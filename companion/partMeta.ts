import fs from 'node:fs/promises';
import path from 'node:path';
import type { SegmentState, SourceTier } from '../shared/types.js';
import { PART_META_SUFFIX } from '../server/utils.js';
import { isStrongEtag, validateResponseValidators } from '../server/validators.js';

export interface PartMetaSegment {
  id: number;
  start: number;
  end: number;
  committedBytes: number;
  status: SegmentState['status'];
  mirrorIndex?: number;
  /**
   * Explicit proof that this span's response reached a clean, length-exact EOF (or an intentional
   * work-steal cutoff) with zero protocol errors. A full byte count alone is NOT proof.
   */
  spanVerified?: boolean;
}

/**
 * Opaque mirror reference persisted in `.part.meta`.
 * Never stores raw URLs, signed query parameters, or credentials.
 */
export interface PartMetaMirrorRef {
  sourceId: string;
  label: string;
  host: string;
  tier: SourceTier;
  provenance?: string;
  etag?: string;
  lastModified?: string;
}

export interface PartMetaFile {
  version: 2;
  jobId: string;
  partPath: string;
  filename: string;
  totalBytes: number | null;
  resourceId?: string;
  expectedMd5?: string;
  expectedSha256?: string;
  pinnedEtag?: string;
  pinnedLastModified?: string;
  mirrors: PartMetaMirrorRef[];
  segments: PartMetaSegment[];
  updatedAt: number;
}

export interface ValidatePartMetaOptions {
  jobId: string;
  partPath: string;
  totalBytes: number | null;
  partFileSize: number;
  resourceId?: string;
  expectedMd5?: string;
  expectedSha256?: string;
  pinnedEtag?: string;
  pinnedLastModified?: string;
}

export interface ValidatePartMetaResult {
  valid: boolean;
  reason?: string;
  segments: SegmentState[];
  committedBySegId: Map<number, number>;
  /** Segment ids whose span completion is proven by a persisted EOF validation record. */
  spanVerifiedSegIds: Set<number>;
  hadUnprovenGaps: boolean;
  pinnedEtag?: string;
  pinnedLastModified?: string;
}

const metaWriteChains = new Map<string, Promise<void>>();

export function getPartMetaPath(partPath: string): string {
  return `${partPath}${PART_META_SUFFIX}`;
}

/**
 * Retires a staging payload and its `.part.meta` sidecar TOGETHER.
 * The sidecar is removed first; if that fails with anything but ENOENT the error propagates and
 * the payload is intentionally left in place, so the pair stays together (and its slot stays
 * occupied) instead of leaving a stale checkpoint that could sit over a newly allocated file.
 */
export async function retireStagingPair(
  partPath: string,
  opts: {
    removeMetaFn?: (partPath: string) => Promise<void>;
    unlinkFn?: typeof fs.unlink;
  } = {}
): Promise<void> {
  if (!partPath) return;
  if (opts.removeMetaFn) {
    await opts.removeMetaFn(partPath);
  } else {
    await removePartMeta(partPath);
  }
  try {
    await (opts.unlinkFn ?? fs.unlink)(partPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
      throw err;
    }
  }
}

/**
 * Atomically persists download chunk progress to `<partPath>.meta` with datasync before rename.
 * Propagates disk write / datasync / rename errors so callers never assume a failed checkpoint succeeded.
 */
export function writePartMeta(partPath: string, meta: PartMetaFile): Promise<void> {
  const metaPath = getPartMetaPath(partPath);
  const prev = metaWriteChains.get(metaPath) ?? Promise.resolve();
  const next = prev.then(async () => {
    const sanitizedMirrors: PartMetaMirrorRef[] = (meta.mirrors ?? []).map((m) => ({
      sourceId: m.sourceId,
      label: m.label,
      host: m.host,
      tier: m.tier,
      provenance: m.provenance,
      etag: m.etag,
      lastModified: m.lastModified,
    }));
    const cleanMeta: PartMetaFile = {
      version: 2,
      jobId: meta.jobId,
      partPath: meta.partPath,
      filename: meta.filename,
      totalBytes: meta.totalBytes,
      resourceId: meta.resourceId,
      expectedMd5: meta.expectedMd5,
      expectedSha256: meta.expectedSha256,
      pinnedEtag: meta.pinnedEtag,
      pinnedLastModified: meta.pinnedLastModified,
      mirrors: sanitizedMirrors,
      segments: meta.segments.map((s) => ({
        id: s.id,
        start: s.start,
        end: s.end,
        committedBytes: s.committedBytes,
        status: s.status,
        mirrorIndex: s.mirrorIndex,
        spanVerified: s.spanVerified === true,
      })),
      updatedAt: meta.updatedAt,
    };

    const payload = Buffer.from(JSON.stringify(cleanMeta, null, 2), 'utf8');
    const tmpPath = `${metaPath}.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2, 6)}.tmp`;
    const fh = await fs.open(tmpPath, 'w');
    try {
      let written = 0;
      while (written < payload.length) {
        const res = await fh.write(payload, written, payload.length - written);
        if (res.bytesWritten <= 0) {
          throw new Error('Zero bytes written while persisting part metadata');
        }
        written += res.bytesWritten;
      }
      await fh.datasync();
    } catch (err) {
      await fh.close().catch(() => undefined);
      await fs.unlink(tmpPath).catch(() => undefined);
      throw err;
    }
    await fh.close();

    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        await fs.rename(tmpPath, metaPath);
        return;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        if ((code === 'EPERM' || code === 'EBUSY') && attempt < 4) {
          await new Promise((r) => setTimeout(r, 25 * (attempt + 1)));
          continue;
        }
        await fs.unlink(tmpPath).catch(() => undefined);
        throw err;
      }
    }
  });
  metaWriteChains.set(
    metaPath,
    next.catch(() => undefined)
  );
  return next;
}

/**
 * Reads `.part.meta` if present and valid v2 metadata; returns null on missing/corrupt/legacy files.
 */
export async function readPartMeta(partPath: string): Promise<PartMetaFile | null> {
  const metaPath = getPartMetaPath(partPath);
  try {
    const raw = await fs.readFile(metaPath, 'utf8');
    const parsed = JSON.parse(raw) as Partial<PartMetaFile>;
    if (
      parsed.version !== 2 ||
      typeof parsed.jobId !== 'string' ||
      typeof parsed.partPath !== 'string' ||
      !Array.isArray(parsed.segments)
    ) {
      return null;
    }
    return parsed as PartMetaFile;
  } catch {
    return null;
  }
}

/**
 * Validates staging file ownership, strong validator/digest identity, same-resource binding,
 * segment geometry, non-overlap, and exact file size ceiling; synthesizes fresh pending segments
 * for any unproven extents.
 */
export function validatePartMetaGeometry(
  meta: PartMetaFile,
  opts: ValidatePartMetaOptions
): ValidatePartMetaResult {
  const invalid = (reason: string): ValidatePartMetaResult => ({
    valid: false,
    reason,
    segments: [],
    committedBySegId: new Map(),
    spanVerifiedSegIds: new Set(),
    hadUnprovenGaps: true,
  });

  if (meta.version !== 2) return invalid('Unsupported part metadata version');
  if (meta.jobId !== opts.jobId) return invalid('Part metadata belongs to a different job');
  if (path.resolve(meta.partPath) !== path.resolve(opts.partPath)) {
    return invalid('Part metadata staging path mismatch');
  }
  if (
    opts.totalBytes === null ||
    !Number.isSafeInteger(opts.totalBytes) ||
    opts.totalBytes <= 0 ||
    meta.totalBytes !== opts.totalBytes
  ) {
    return invalid('Total size missing or mismatched for safe resume');
  }
  if (!Number.isSafeInteger(opts.partFileSize) || opts.partFileSize < 0) {
    return invalid('Invalid staging file size');
  }
  if (opts.partFileSize > opts.totalBytes) {
    return invalid(
      `Oversized staging file (${opts.partFileSize} bytes exceeds expected ${opts.totalBytes} bytes)`
    );
  }
  if (
    opts.expectedMd5 &&
    meta.expectedMd5 &&
    meta.expectedMd5.toLowerCase() !== opts.expectedMd5.toLowerCase()
  ) {
    return invalid('Expected MD5 changed since checkpoint');
  }
  if (
    opts.expectedSha256 &&
    meta.expectedSha256 &&
    meta.expectedSha256.toLowerCase() !== opts.expectedSha256.toLowerCase()
  ) {
    return invalid('Expected SHA-256 changed since checkpoint');
  }

  const hasDigest = Boolean(opts.expectedMd5 || opts.expectedSha256);
  if (!hasDigest) {
    // Require a matching NON-EMPTY same-resource identity (origin + path + query) + matching STRONG
    // ETag validator for digestless resume. A checkpoint missing resourceId proves nothing.
    if (!opts.resourceId || !meta.resourceId) {
      return invalid('Checkpoint is missing source resource identity without trusted digest');
    }
    if (meta.resourceId !== opts.resourceId) {
      return invalid('Checkpoint belongs to a different source resource without trusted digest');
    }
    if (!isStrongEtag(meta.pinnedEtag) || !isStrongEtag(opts.pinnedEtag)) {
      return invalid(
        'Cannot safely resume without a matching strong ETag validator or trusted digest'
      );
    }
    const check = validateResponseValidators(
      { etag: meta.pinnedEtag, lastModified: meta.pinnedLastModified },
      { etag: opts.pinnedEtag, lastModified: opts.pinnedLastModified }
    );
    if (!check.ok) {
      return invalid(check.reason ?? 'Pinned validator mismatch without trusted digest');
    }
  }

  if (meta.segments.length === 0) {
    return invalid('Empty segment table');
  }

  const sorted = [...meta.segments].sort((a, b) => a.start - b.start);
  let cursor = 0;
  let nextSegId = 0;
  let hadUnprovenGaps = false;
  const rebuilt: SegmentState[] = [];
  const committedBySegId = new Map<number, number>();
  const spanVerifiedSegIds = new Set<number>();

  for (let i = 0; i < sorted.length; i++) {
    const seg = sorted[i]!;
    if (
      !Number.isSafeInteger(seg.start) ||
      !Number.isSafeInteger(seg.end) ||
      !Number.isSafeInteger(seg.committedBytes) ||
      seg.start < 0 ||
      seg.end < seg.start ||
      seg.end >= opts.totalBytes ||
      seg.committedBytes < 0 ||
      seg.committedBytes > seg.end - seg.start + 1
    ) {
      return invalid('Corrupt segment bounds or committed byte count');
    }
    if (seg.start < cursor) {
      return invalid('Overlapping segment ranges in metadata');
    }
    if (seg.start > cursor) {
      hadUnprovenGaps = true;
      rebuilt.push({
        id: nextSegId++,
        start: cursor,
        end: seg.start - 1,
        downloaded: 0,
        speedBps: 0,
        status: 'pending',
        retries: 0,
      });
    }

    const segLength = seg.end - seg.start + 1;
    const diskBackedLimit = Math.max(0, opts.partFileSize - seg.start);
    let provenCommitted = Math.min(seg.committedBytes, segLength, diskBackedLimit);
    if (provenCommitted < seg.committedBytes) {
      hadUnprovenGaps = true;
    }

    // A full byte count is NOT completion proof: the response may have been interrupted after the
    // last byte but before a length-exact EOF was observed. Refetch such spans from their start.
    if (provenCommitted === segLength && seg.spanVerified !== true) {
      provenCommitted = 0;
      hadUnprovenGaps = true;
    }

    const id = nextSegId++;
    const done = provenCommitted === segLength;
    rebuilt.push({
      id,
      start: seg.start,
      end: seg.end,
      downloaded: provenCommitted,
      speedBps: 0,
      status: done ? 'done' : 'pending',
      retries: 0,
      mirrorIndex: seg.mirrorIndex,
    });
    committedBySegId.set(id, provenCommitted);
    if (done) spanVerifiedSegIds.add(id);
    cursor = seg.end + 1;
  }

  if (cursor < opts.totalBytes) {
    hadUnprovenGaps = true;
    rebuilt.push({
      id: nextSegId++,
      start: cursor,
      end: opts.totalBytes - 1,
      downloaded: 0,
      speedBps: 0,
      status: 'pending',
      retries: 0,
    });
  }

  return {
    valid: true,
    segments: rebuilt,
    committedBySegId,
    spanVerifiedSegIds,
    hadUnprovenGaps,
    pinnedEtag: meta.pinnedEtag ?? opts.pinnedEtag,
    pinnedLastModified: meta.pinnedLastModified ?? opts.pinnedLastModified,
  };
}

/**
 * Removes `<partPath>.meta` after final assembly, reset, or cancellation.
 * Ignores ONLY `ENOENT`; propagates any other filesystem/unlink error so callers never
 * truncate a staging file underneath a surviving stale checkpoint.
 */
export async function removePartMeta(
  partPath: string,
  opts: { unlinkFn?: typeof fs.unlink } = {}
): Promise<void> {
  const metaPath = getPartMetaPath(partPath);
  const unlinkFn = opts.unlinkFn ?? fs.unlink;
  const pending = metaWriteChains.get(metaPath);
  if (pending) {
    await pending.catch(() => {});
  }
  try {
    await unlinkFn(metaPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
      throw err;
    }
  }
  metaWriteChains.delete(metaPath);
}
