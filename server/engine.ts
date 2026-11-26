import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import type {
  DownloadItem,
  MirrorSourceMeta,
  MirrorTelemetry,
  RoutingLogEntry,
  SegmentState,
  SourceTier,
} from '../shared/types.js';
import {
  assertOutboundUrlSafe,
  redactText,
  redactValidator,
  sanitizeUpstreamError,
} from '../companion/parser.js';
import {
  type PartMetaMirrorRef,
  readPartMeta,
  removePartMeta,
  retireStagingPair,
  validatePartMetaGeometry,
  writePartMeta,
} from '../companion/partMeta.js';
import { OriginRateLimiter } from './rateLimit.js';
import type { TokenBucketThrottle } from './throttle.js';
import {
  captureFileIdentity,
  normalizeHostname,
  publishStagingFileAtomically,
  reserveExclusiveStagingFile,
} from './utils.js';
import {
  canCombineMirrorWithPrimary,
  computeOpaqueSourceId,
  isStrongEtag,
  isTransferIdentityProven,
  validateResponseValidators,
} from './validators.js';
import { verifyFileIntegrity } from './verifier.js';

export interface RunnerFileHandleHooks {
  wrapHandle?: (handle: fs.FileHandle) => fs.FileHandle;
  removeMetaFn?: (partPath: string) => Promise<void>;
  beforeReserveStaging?: () => Promise<void>;
}

export interface RunnerOptions {
  item: DownloadItem;
  throttle: TokenBucketThrottle;
  rateLimiter?: OriginRateLimiter;
  /** Static secret list (tests / one-off runs). Prefer `secretsProvider` for long-lived runners. */
  secrets?: readonly string[];
  /** Live secret set read at EVERY dispatch/redirect/redaction (survives key rotation). */
  secretsProvider?: () => readonly string[];
  /** Stable per-install key for opaque source/resource fingerprints. */
  sourceIdKey?: Buffer;
  minSegmentBytes?: number;
  stallTimeoutMs?: number;
  maxRetries?: number;
  minSpeedFloorBps?: number;
  speedWindowMs?: number;
  evictionGraceMs?: number;
  writeBufferBytes?: number;
  fileHooks?: RunnerFileHandleHooks;
  onUpdate: (item: DownloadItem, immediatePersist?: boolean) => void;
}

class RetryableHttpError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly retryAfterMs: number,
    public readonly hasExplicitRetryAfter: boolean,
    message: string
  ) {
    super(message);
    this.name = 'RetryableHttpError';
  }
}

class ValidatorMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidatorMismatchError';
  }
}

class FatalDiskError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FatalDiskError';
  }
}

interface MirrorMetric {
  sourceId: string;
  url: string;
  label: string;
  host: string;
  tier: SourceTier;
  provenance?: string;
  expectedEtag?: string;
  expectedLastModified?: string;
  observedUrls: Set<string>;
  status: 'active' | 'standby' | 'evicted' | 'cooldown' | 'failed';
  bytes: number;
  speedBps: number;
  lastActiveSpeedBps: number;
  lastSampleBytes: number;
  samples: Array<{ t: number; bytes: number }>;
  firstActiveAt: number | null;
  cooldownUntil: number;
  evictedUntil: number;
  failures: number;
  lastEvent?: string;
}

interface ActiveSegmentHandle {
  req?: http.ClientRequest;
  res?: http.IncomingMessage;
  evicted: boolean;
}

interface WorkerContext {
  seg: SegmentState;
  workerEpoch: number;
}

const DEFAULT_MIN_SEGMENT_BYTES = 128 * 1024;
const DEFAULT_STALL_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_RETRIES = 5;
const DEFAULT_SPEED_FLOOR_BPS = 350 * 1024;
const DEFAULT_SPEED_WINDOW_MS = 5_000;
const DEFAULT_EVICTION_GRACE_MS = 5_000;
const DEFAULT_WRITE_BUFFER_BYTES = 256 * 1024;
const MAX_REDIRECTS = 10;

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 64 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 64 });

export class DownloadRunner {
  public readonly item: DownloadItem;
  private readonly throttle: TokenBucketThrottle;
  private readonly rateLimiter: OriginRateLimiter;
  private readonly staticSecrets: readonly string[];
  private readonly secretsProvider?: () => readonly string[];
  private readonly sourceIdKey?: Buffer;
  private readonly minSegmentBytes: number;
  private readonly stallTimeoutMs: number;
  private readonly maxRetries: number;
  private readonly minSpeedFloorBps: number;
  private readonly speedWindowMs: number;
  private readonly evictionGraceMs: number;
  private readonly writeBufferBytes: number;
  private readonly fileHooks?: RunnerFileHandleHooks;
  private readonly onUpdate: (item: DownloadItem, immediatePersist?: boolean) => void;

  private abortController = new AbortController();
  private epoch = 0;
  private resetGeneration = 0;
  private fileHandle: fs.FileHandle | null = null;
  private inFlightWrites = new Set<Promise<unknown>>();
  private activeWorkers = new Set<Promise<void>>();
  private activeRequests = new Set<http.ClientRequest>();
  private segmentHandles = new Map<number, ActiveSegmentHandle>();
  private stopReason: 'none' | 'paused' | 'cancelled' = 'none';
  private cancelled = false;
  private deleteOnCancel = true;
  private stagingOwned = false;
  private runPromise: Promise<void> | null = null;
  private activeSourceIndex = 0;
  private multiMirrorStripingAllowed = false;
  private switchingSourcePromise: Promise<void> | null = null;
  private finalizePromise: Promise<void> | null = null;
  private fatalDiskError: Error | null = null;
  private frozenExpectedMd5?: string;
  private frozenExpectedSha256?: string;
  private frozenDestinationDir = '';
  private nextSegmentId = 1;
  private telemetryTimer: NodeJS.Timeout | null = null;
  private lastSampleTime = Date.now();
  private lastSampleBytes = 0;
  private lastMetaPersistAt = 0;
  private metaPersistChain: Promise<void> = Promise.resolve();
  private segLastSampleBytes = new Map<number, number>();
  private segCommittedBytes = new Map<number, number>();
  private segSpanCompleted = new Set<number>();
  private emaSpeedBps = 0;
  private diskEmaSpeedBps = 0;
  private diskWindowBytes = 0;
  private throttleConstrainedWindow = false;
  private mirrorMetrics: MirrorMetric[] = [];

  constructor(options: RunnerOptions) {
    this.item = options.item;
    this.throttle = options.throttle;
    this.rateLimiter = options.rateLimiter ?? new OriginRateLimiter();
    this.staticSecrets = options.secrets ?? [];
    this.secretsProvider = options.secretsProvider;
    this.sourceIdKey = options.sourceIdKey;
    this.minSegmentBytes = options.minSegmentBytes ?? DEFAULT_MIN_SEGMENT_BYTES;
    this.stallTimeoutMs = options.stallTimeoutMs ?? DEFAULT_STALL_TIMEOUT_MS;
    this.maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.minSpeedFloorBps = options.minSpeedFloorBps ?? DEFAULT_SPEED_FLOOR_BPS;
    this.speedWindowMs = options.speedWindowMs ?? DEFAULT_SPEED_WINDOW_MS;
    this.evictionGraceMs = options.evictionGraceMs ?? DEFAULT_EVICTION_GRACE_MS;
    this.writeBufferBytes = Math.max(
      64 * 1024,
      Math.min(1024 * 1024, options.writeBufferBytes ?? DEFAULT_WRITE_BUFFER_BYTES)
    );
    this.fileHooks = options.fileHooks;
    this.onUpdate = options.onUpdate;
  }

  /** The live secret set at the moment of use (never a stale snapshot from construction). */
  private get secrets(): readonly string[] {
    if (this.secretsProvider) {
      try {
        return this.secretsProvider();
      } catch {
        return this.staticSecrets;
      }
    }
    return this.staticSecrets;
  }

  private hasTrustedDigest(): boolean {
    return Boolean(
      this.frozenExpectedMd5 ?? this.item.expectedMd5 ?? this.frozenExpectedSha256 ?? this.item.expectedSha256
    );
  }

  /**
   * Identity is proven only by a trusted digest or a strong (RFC 9110) ETag validator.
   * Unproven transfers use ONE uninterrupted stream and restart from offset 0 after interruption.
   */
  private isIdentityProven(mirrorIdx = this.activeSourceIndex): boolean {
    if (this.hasTrustedDigest()) return true;
    const metric = this.mirrorMetrics[mirrorIdx];
    return isTransferIdentityProven({ pinnedEtag: metric?.expectedEtag ?? this.item.pinnedEtag });
  }

  private getActiveResourceId(): string {
    const activeUrl = this.mirrorMetrics[this.activeSourceIndex]?.url ?? this.item.finalUrl;
    return computeOpaqueSourceId(activeUrl, this.sourceIdKey);
  }

  private async removeMetaSafe(partPath: string): Promise<void> {
    if (!partPath) return;
    if (this.fileHooks?.removeMetaFn) {
      await this.fileHooks.removeMetaFn(partPath);
    } else {
      await removePartMeta(partPath);
    }
  }

  /**
   * Retires a staging payload + `.part.meta` pair together. Never silently ignores non-ENOENT
   * failures: they are surfaced in the routing log (and returned) while the pair is left intact,
   * and callers always continue on a freshly reserved exclusive pair.
   */
  private async retireStagingPairLogged(partPath: string, context: string): Promise<Error | null> {
    if (!partPath) return null;
    try {
      await retireStagingPair(partPath, { removeMetaFn: (p) => this.removeMetaSafe(p) });
      return null;
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      this.appendRoutingLog(
        'warn',
        `Could not retire staging pair during ${context} (${sanitizeUpstreamError(e, this.secrets, 160)}); left intact and isolated onto a fresh exclusive staging pair`
      );
      return e;
    }
  }

  private isOwnStagingName(partPath: string): boolean {
    const safeJobId = this.item.id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 16);
    return Boolean(safeJobId) && path.basename(partPath).startsWith(`.boltgate-${safeJobId}`);
  }

  /**
   * Safely prepares staging for an offset-0 reset (non-range retry or range->200 fallback):
   * removes `.part.meta` BEFORE truncating. If sidecar removal fails with any non-ENOENT error,
   * refuses to truncate underneath the surviving sidecar and instead allocates a fresh exclusive
   * staging file + sidecar path.
   */
  private async resetStagingForOffsetZero(totalBytes: number | null): Promise<void> {
    let metaRemoved = false;
    if (this.item.partPath) {
      try {
        await this.removeMetaSafe(this.item.partPath);
        metaRemoved = true;
      } catch (err) {
        metaRemoved = false;
        this.appendRoutingLog(
          'warn',
          `Checkpoint sidecar could not be invalidated before offset-0 reset (${sanitizeUpstreamError(err, this.secrets, 160)}); isolating onto a fresh staging pair`
        );
      }
    } else {
      metaRemoved = true;
    }

    if (metaRemoved && this.fileHandle) {
      await this.fileHandle.truncate(0);
      if (totalBytes && totalBytes > 0) {
        await this.fileHandle.truncate(totalBytes);
      }
      return;
    }

    // Sidecar unlink failed -> NEVER truncate old staging file; isolate onto a brand-new staging file!
    if (this.fileHandle) {
      await this.fileHandle.close().catch(() => undefined);
      this.fileHandle = null;
    }
    const fresh = await reserveExclusiveStagingFile(
      this.frozenDestinationDir || this.item.destinationDir,
      this.item.filename,
      this.item.id
    );
    this.stagingOwned = true;
    this.item.partPath = fresh.partPath;
    this.fileHandle = this.wrapHandle(fresh.handle);
    if (totalBytes && totalBytes > 0) {
      await this.fileHandle.truncate(totalBytes);
    }
  }

  private isMultiMirrorStripingAllowed(): boolean {
    return this.multiMirrorStripingAllowed;
  }

  private wrapHandle(fh: fs.FileHandle): fs.FileHandle {
    return this.fileHooks?.wrapHandle ? this.fileHooks.wrapHandle(fh) : fh;
  }

  private getStopReason(): 'none' | 'paused' | 'cancelled' {
    return this.stopReason;
  }

  private triggerFatalDiskError(err: unknown): FatalDiskError {
    const fatal =
      err instanceof FatalDiskError
        ? err
        : new FatalDiskError(sanitizeUpstreamError(err, this.secrets, 260));
    if (!this.fatalDiskError) {
      this.fatalDiskError = fatal;
    }
    this.epoch += 1;
    this.abortController.abort();
    for (const req of this.activeRequests) {
      req.destroy();
    }
    this.activeRequests.clear();
    return fatal;
  }

  private appendRoutingLog(level: RoutingLogEntry['level'], message: string): void {
    if (!this.item.routingLog) this.item.routingLog = [];
    this.item.routingLog.push({
      timestamp: Date.now(),
      level,
      message: sanitizeUpstreamError(message, this.secrets, 360),
    });
    if (this.item.routingLog.length > 60) {
      this.item.routingLog = this.item.routingLog.slice(-60);
    }
  }

  /**
   * Single lifecycle promise covering staging setup, transfer, verification, publication, AND
   * cancellation cleanup — `cancel()`/`pause()` await exactly this promise.
   */
  run(): Promise<void> {
    if (this.runPromise) return this.runPromise;
    const p = (async () => {
      try {
        await this.runInternal();
      } finally {
        await this.cleanupAfterCancel();
      }
    })().finally(() => {
      if (this.runPromise === p) {
        this.runPromise = null;
      }
    });
    this.runPromise = p;
    return p;
  }

  private async cleanupAfterCancel(): Promise<void> {
    if (this.stopReason !== 'cancelled') return;
    this.stopTelemetryTimer();
    if (this.fileHandle) {
      await this.fileHandle.close().catch(() => undefined);
      this.fileHandle = null;
    }
    if (this.deleteOnCancel && this.stagingOwned && this.item.partPath) {
      const failed = await this.retireStagingPairLogged(this.item.partPath, 'cancellation');
      if (!failed) this.stagingOwned = false;
    }
  }

  /** Centralized terminal transition to `paused` (only after a durable checkpoint). */
  private settlePaused(): void {
    this.item.status = 'paused';
    this.item.speedBps = 0;
    this.item.etaSeconds = null;
    for (const s of this.item.segments) {
      s.speedBps = 0;
      s.downloaded = this.segCommittedBytes.get(s.id) ?? 0;
      if (s.status !== 'done') s.status = 'paused';
    }
    this.recomputeDownloadedTotal();
    this.updateMirrorTelemetrySnapshot();
    this.onUpdate(this.item, true);
  }

  /** Centralized terminal transition to `failed`. */
  private settleFailed(err: unknown): void {
    this.item.status = 'failed';
    this.item.speedBps = 0;
    this.item.etaSeconds = null;
    this.item.error = sanitizeUpstreamError(this.fatalDiskError ?? err, this.secrets, 320);
    for (const s of this.item.segments) {
      s.speedBps = 0;
      s.downloaded = this.segCommittedBytes.get(s.id) ?? 0;
      if (s.status === 'active') s.status = 'error';
    }
    this.recomputeDownloadedTotal();
    this.updateMirrorTelemetrySnapshot();
    this.onUpdate(this.item, true);
  }

  /**
   * Writes the final durable checkpoint and closes the staging handle before reporting `paused`.
   * Any datasync / sidecar write failure propagates (as a fatal disk error), so a job is never
   * reported as durably paused when its checkpoint was not persisted.
   */
  private async checkpointAndCloseForPause(): Promise<void> {
    if (!this.fileHandle) return;
    try {
      await this.persistPartMeta(true);
      if (this.fatalDiskError) throw this.fatalDiskError;
    } catch (err) {
      await this.fileHandle?.close().catch(() => undefined);
      this.fileHandle = null;
      throw this.triggerFatalDiskError(err);
    }
    await this.fileHandle.close();
    this.fileHandle = null;
  }

  private async runInternal(): Promise<void> {
    // Cancellation is sticky: a cancelled runner never starts (or restarts) a transfer.
    if (this.cancelled || this.stopReason === 'cancelled') return;
    this.stopReason = 'none';
    this.deleteOnCancel = true;
    this.stagingOwned = false;
    this.fatalDiskError = null;
    this.segSpanCompleted.clear();
    this.frozenExpectedMd5 = this.item.expectedMd5;
    this.frozenExpectedSha256 = this.item.expectedSha256;
    this.frozenDestinationDir = this.item.destinationDir;
    this.abortController = new AbortController();
    this.epoch += 1;
    this.item.status = 'downloading';
    this.item.error = undefined;
    if (!this.item.startedAt) {
      this.item.startedAt = Date.now();
    }

    try {
      await fs.mkdir(this.frozenDestinationDir, { recursive: true });
      this.initMirrorMetrics();

      if (this.cancelled || this.getStopReason() !== 'none') return;

      const partExists = Boolean(this.item.partPath) && (await fileExists(this.item.partPath));
      const diskMeta = partExists ? await readPartMeta(this.item.partPath) : null;
      let canResumeExisting = false;

      if (
        partExists &&
        diskMeta &&
        this.item.supportsRanges &&
        this.item.totalBytes !== null &&
        this.item.totalBytes > 0
      ) {
        const st = await fs.stat(this.item.partPath).catch(() => null);
        if (st && st.isFile()) {
          const validation = validatePartMetaGeometry(diskMeta, {
            jobId: this.item.id,
            partPath: this.item.partPath,
            totalBytes: this.item.totalBytes,
            partFileSize: st.size,
            resourceId: this.getActiveResourceId(),
            expectedMd5: this.frozenExpectedMd5,
            expectedSha256: this.frozenExpectedSha256,
            pinnedEtag: this.item.pinnedEtag ?? this.item.etag,
            pinnedLastModified: this.item.pinnedLastModified ?? this.item.lastModified,
          });
          if (validation.valid && validation.segments.length > 0) {
            canResumeExisting = true;
            this.stagingOwned = true;
            this.item.segments = validation.segments;
            this.segCommittedBytes = new Map(validation.committedBySegId);
            // Only spans with a persisted EOF/length validation proof count as complete
            for (const id of validation.spanVerifiedSegIds) {
              this.segSpanCompleted.add(id);
            }
            if (validation.pinnedEtag) this.item.pinnedEtag = validation.pinnedEtag;
            if (validation.pinnedLastModified) {
              this.item.pinnedLastModified = validation.pinnedLastModified;
            }
            this.appendRoutingLog(
              'info',
              validation.hadUnprovenGaps
                ? 'Recovered verified .part.meta extents (unproven gaps queued for re-fetch)'
                : 'Recovered byte-range progress from .part.meta'
            );
          } else {
            this.appendRoutingLog(
              'warn',
              `Ignored invalid .part.meta (${validation.reason ?? 'integrity check'}) — starting fresh staging file`
            );
            if (diskMeta.jobId === this.item.id) {
              await this.retireStagingPairLogged(this.item.partPath, 'invalid checkpoint reset');
            }
          }
        }
      }

      if (this.cancelled || this.getStopReason() !== 'none') return;

      if (!canResumeExisting) {
        if (
          partExists &&
          (diskMeta?.jobId === this.item.id || (!diskMeta && this.isOwnStagingName(this.item.partPath)))
        ) {
          // Retire the old payload + sidecar TOGETHER; a failure leaves the pair intact and we
          // always continue on a brand-new exclusively reserved pair below.
          await this.retireStagingPairLogged(this.item.partPath, 'fresh restart');
        }
        if (this.fileHooks?.beforeReserveStaging) {
          await this.fileHooks.beforeReserveStaging();
        }
        if (this.cancelled || this.getStopReason() !== 'none') return;

        const reserved = await reserveExclusiveStagingFile(
          this.frozenDestinationDir,
          sanitizeDerivedName(this.item.filename, this.secrets),
          this.item.id
        );
        this.stagingOwned = true;
        this.item.filename = reserved.filename;
        this.item.savedPath = reserved.savedPath;
        this.item.partPath = reserved.partPath;
        this.fileHandle = this.wrapHandle(reserved.handle);

        // Cancellation during reservation: cleanupAfterCancel() (inside the single run promise)
        // closes the handle and retires the freshly reserved pair.
        if (this.cancelled || this.getStopReason() !== 'none') return;

        this.activeSourceIndex = 0;
        if (!this.hasTrustedDigest()) {
          const primaryMeta = this.mirrorMetrics[0];
          this.item.pinnedEtag = primaryMeta?.expectedEtag ?? this.item.etag;
          this.item.pinnedLastModified = primaryMeta?.expectedLastModified ?? this.item.lastModified;
          this.item.sourceProvenance = primaryMeta?.provenance;
        }
        this.item.segments = this.buildInitialSegments();
        this.item.downloadedBytes = 0;
        this.segCommittedBytes.clear();
        for (const seg of this.item.segments) {
          this.segCommittedBytes.set(seg.id, 0);
        }

        if (this.item.totalBytes === 0) {
          await this.fileHandle.datasync();
          await this.fileHandle.close();
          this.fileHandle = null;
          await this.finalizeCompletedFile();
          return;
        }

        if (this.item.totalBytes && this.item.totalBytes > 0) {
          await this.fileHandle.truncate(this.item.totalBytes);
        }
      } else {
        if (!this.isMultiMirrorStripingAllowed()) {
          const pinnedSourceIdx = this.item.segments.find((s) => s.downloaded > 0)?.mirrorIndex ?? 0;
          this.activeSourceIndex = Math.max(
            0,
            Math.min(pinnedSourceIdx, Math.max(0, this.mirrorMetrics.length - 1))
          );
          for (const seg of this.item.segments) {
            if (seg.status !== 'done') {
              seg.mirrorIndex = this.activeSourceIndex;
            }
          }
          this.item.sourceProvenance = this.mirrorMetrics[this.activeSourceIndex]?.provenance;
        }
        this.recomputeDownloadedTotal();
        this.fileHandle = this.wrapHandle(await fs.open(this.item.partPath, 'r+'));
        if (this.item.totalBytes && this.item.totalBytes > 0) {
          const st = await this.fileHandle.stat();
          if (st.size > this.item.totalBytes) {
            throw new FatalDiskError(
              `Oversized staging file on resume (${st.size} > ${this.item.totalBytes})`
            );
          }
          if (st.size < this.item.totalBytes) {
            await this.fileHandle.truncate(this.item.totalBytes);
          }
        }
      }

      this.nextSegmentId =
        this.item.segments.reduce((max, s) => Math.max(max, s.id), 0) + 1;

      this.lastSampleTime = Date.now();
      this.lastSampleBytes = this.item.downloadedBytes;
      for (const seg of this.item.segments) {
        this.segLastSampleBytes.set(seg.id, seg.downloaded);
        if (!this.segCommittedBytes.has(seg.id)) {
          this.segCommittedBytes.set(seg.id, seg.downloaded);
        }
      }

      await this.persistPartMeta(true);
      this.updateMirrorTelemetrySnapshot();
      this.startTelemetryTimer();
      this.onUpdate(this.item, true);

      const initialEpoch = this.epoch;
      for (const seg of this.item.segments) {
        if (seg.status !== 'done') {
          this.spawnWorker(seg, initialEpoch);
        }
      }

      while (this.activeWorkers.size > 0 || this.switchingSourcePromise !== null) {
        if (this.switchingSourcePromise) {
          await this.switchingSourcePromise.catch(() => undefined);
        }
        if (this.activeWorkers.size > 0) {
          await Promise.allSettled(Array.from(this.activeWorkers));
        }
      }

      await Promise.allSettled(Array.from(this.inFlightWrites));
      await this.metaPersistChain.catch(() => undefined);
      this.stopTelemetryTimer();

      const stopAfterWait = this.getStopReason();
      if (stopAfterWait === 'paused') {
        if (this.fatalDiskError) throw this.fatalDiskError;
        // Datasync / sidecar failure propagates -> reported as failed, never as a durable pause
        await this.checkpointAndCloseForPause();
        this.settlePaused();
        return;
      }

      if (stopAfterWait === 'cancelled') {
        // Handle close + staging pair retirement run in cleanupAfterCancel()
        return;
      }

      if (this.fatalDiskError) {
        throw this.fatalDiskError;
      }

      const failedSeg = this.item.segments.find((s) => s.status === 'error');
      if (failedSeg) {
        throw new Error(failedSeg.lastError || `Segment ${failedSeg.id} failed`);
      }

      // Sync payload durably to disk BEFORE closing handle and verifying completion!
      if (this.fileHandle) {
        try {
          await this.fileHandle.datasync();
        } finally {
          await this.fileHandle.close().catch(() => undefined);
          this.fileHandle = null;
        }
      }

      this.verifyCompleteCommittedCoverage();
      await this.finalizeCompletedFile();
    } catch (err) {
      this.stopTelemetryTimer();
      await Promise.allSettled(Array.from(this.inFlightWrites));
      await this.metaPersistChain.catch(() => undefined);

      const stopOnErr = this.getStopReason();
      if (stopOnErr === 'cancelled') {
        return;
      }

      // Final checkpoint on the error/pause path: a failed write is itself a disk failure
      if (this.fileHandle) {
        const alreadyDiskFailure = Boolean(this.fatalDiskError) || err instanceof FatalDiskError;
        if (!alreadyDiskFailure) {
          await this.persistPartMeta(true).catch((cpErr) => {
            this.triggerFatalDiskError(cpErr);
          });
        }
        await this.fileHandle?.close().catch(() => undefined);
        this.fileHandle = null;
      }

      const isDiskFailure = Boolean(this.fatalDiskError) || err instanceof FatalDiskError;
      if (stopOnErr === 'paused' && !isDiskFailure) {
        this.settlePaused();
        return;
      }

      this.settleFailed(err);
    }
  }

  private verifyCompleteCommittedCoverage(): void {
    if (this.item.segments.length === 0) {
      throw new Error('Incomplete transfer: no segments recorded');
    }

    if (this.item.totalBytes === null) {
      const seg = this.item.segments[0]!;
      const committed = this.segCommittedBytes.get(seg.id) ?? 0;
      if (seg.status !== 'done' || !this.segSpanCompleted.has(seg.id) || committed !== seg.downloaded) {
        throw new Error(
          `Incomplete transfer: committed ${committed} bytes vs received ${seg.downloaded} bytes`
        );
      }
      this.item.downloadedBytes = committed;
      return;
    }

    if (this.item.totalBytes === 0) {
      return;
    }

    const sorted = [...this.item.segments].sort((a, b) => a.start - b.start);
    let cursor = 0;
    let totalCommitted = 0;

    for (const seg of sorted) {
      if (seg.start !== cursor) {
        throw new Error(
          `Incomplete transfer: byte gap or overlap at offset ${cursor} (segment ${seg.id} starts at ${seg.start})`
        );
      }
      if (seg.end < seg.start) {
        throw new Error(`Invalid segment bounds on segment ${seg.id}`);
      }
      const expectedLen = seg.end - seg.start + 1;
      const committed = this.segCommittedBytes.get(seg.id) ?? 0;
      if (seg.status !== 'done' || !this.segSpanCompleted.has(seg.id) || committed !== expectedLen) {
        throw new Error(
          `Incomplete transfer: segment ${seg.id} committed ${committed} of ${expectedLen} bytes`
        );
      }
      totalCommitted += committed;
      cursor = seg.end + 1;
    }

    if (cursor !== this.item.totalBytes || totalCommitted !== this.item.totalBytes) {
      throw new Error(
        `Incomplete transfer: committed ${totalCommitted} of ${this.item.totalBytes} bytes`
      );
    }

    this.item.downloadedBytes = totalCommitted;
  }

  async pause(): Promise<void> {
    if (this.stopReason !== 'none') return;
    if (this.finalizePromise) {
      await this.finalizePromise.catch(() => undefined);
      if (this.item.status === 'completed') return;
    }
    this.stopReason = 'paused';
    this.epoch += 1;
    this.abortController.abort();
    for (const req of this.activeRequests) {
      req.destroy();
    }
    this.activeRequests.clear();
    if (this.runPromise) {
      await this.runPromise.catch(() => undefined);
    }
  }

  async cancel(deletePartFile = true): Promise<void> {
    this.deleteOnCancel = deletePartFile;
    this.stopReason = 'cancelled';
    this.cancelled = true;
    this.epoch += 1;
    this.abortController.abort();
    for (const req of this.activeRequests) {
      req.destroy();
    }
    this.activeRequests.clear();
    // Await the single lifecycle promise covering staging reservation through cleanup
    if (this.runPromise) {
      await this.runPromise.catch(() => undefined);
    } else {
      await this.cleanupAfterCancel();
    }
  }

  private initMirrorMetrics(): void {
    const activeMirrors =
      this.item.mirrorUrls && this.item.mirrorUrls.length > 0
        ? this.item.mirrorUrls
        : [this.item.finalUrl];

    const metaByUrl = new Map<string, MirrorSourceMeta>();
    for (const m of this.item.mirrorMeta ?? []) {
      metaByUrl.set(m.url, m);
    }

    this.mirrorMetrics = activeMirrors.map((url, idx) => {
      const meta = metaByUrl.get(url);
      let host = meta?.host ?? 'mirror';
      if (!meta) {
        try {
          host = normalizeHostname(new URL(url).hostname);
        } catch {
          host = `mirror-${idx + 1}`;
        }
      }
      const tier: SourceTier = meta?.tier ?? 'direct';
      const label =
        meta?.label ?? (activeMirrors.length > 1 ? `Mirror #${idx + 1} (${host})` : host);
      return {
        sourceId: meta?.sourceId ?? computeOpaqueSourceId(url, this.sourceIdKey),
        url,
        label,
        host,
        tier,
        provenance: meta?.provenance,
        expectedEtag: meta?.etag ?? (idx === 0 ? this.item.pinnedEtag ?? this.item.etag : undefined),
        expectedLastModified:
          meta?.lastModified ??
          (idx === 0 ? this.item.pinnedLastModified ?? this.item.lastModified : undefined),
        observedUrls: new Set([url]),
        status: 'standby',
        bytes: 0,
        speedBps: 0,
        lastActiveSpeedBps: 0,
        lastSampleBytes: 0,
        samples: [],
        firstActiveAt: null,
        cooldownUntil: 0,
        evictedUntil: 0,
        failures: 0,
      };
    });

    if (this.mirrorMetrics.length <= 1) {
      this.multiMirrorStripingAllowed = false;
    } else if (this.hasTrustedDigest()) {
      this.multiMirrorStripingAllowed = true;
    } else {
      const primary = this.mirrorMetrics[0]!;
      const primaryInfo = {
        url: primary.url,
        supportsRanges: this.item.supportsRanges,
        totalBytes: this.item.totalBytes,
        etag: primary.expectedEtag,
        lastModified: primary.expectedLastModified,
      };
      this.multiMirrorStripingAllowed = this.mirrorMetrics.slice(1).every((cand) =>
        canCombineMirrorWithPrimary(
          primaryInfo,
          {
            url: cand.url,
            supportsRanges: this.item.supportsRanges,
            totalBytes: this.item.totalBytes,
            etag: cand.expectedEtag,
            lastModified: cand.expectedLastModified,
          },
          false
        ).eligible
      );
    }
  }

  private buildInitialSegments(forcedMirrorIndex?: number): SegmentState[] {
    const total = this.item.totalBytes;
    const requested = Math.max(1, Math.min(16, this.item.connections || 1));
    const singleSourceMode = !this.isMultiMirrorStripingAllowed();
    const fixedMirrorIdx = forcedMirrorIndex ?? this.activeSourceIndex;
    const mirrorCount = Math.max(1, this.mirrorMetrics.length || 1);

    if (
      !this.item.supportsRanges ||
      total === null ||
      total < this.minSegmentBytes * 2 ||
      requested === 1 ||
      // Unproven identity (no digest / strong ETag): ONE uninterrupted stream, never split ranges
      !this.isIdentityProven(fixedMirrorIdx)
    ) {
      return [
        {
          id: 0,
          start: 0,
          end: total !== null ? total - 1 : -1,
          downloaded: 0,
          speedBps: 0,
          status: 'pending',
          retries: 0,
          mirrorIndex: singleSourceMode ? fixedMirrorIdx : 0,
        },
      ];
    }

    const maxBySize = Math.max(1, Math.floor(total / this.minSegmentBytes));
    const count = Math.min(requested, maxBySize);
    const chunkSize = Math.floor(total / count);
    const segments: SegmentState[] = [];

    for (let i = 0; i < count; i++) {
      const start = i * chunkSize;
      const end = i === count - 1 ? total - 1 : (i + 1) * chunkSize - 1;
      segments.push({
        id: i,
        start,
        end,
        downloaded: 0,
        speedBps: 0,
        status: 'pending',
        retries: 0,
        mirrorIndex: singleSourceMode ? fixedMirrorIdx : i % mirrorCount,
      });
    }
    return segments;
  }

  private async restartDownloadOnSingleSource(nextMirrorIdx: number, reason: string): Promise<void> {
    if (this.switchingSourcePromise) {
      return this.switchingSourcePromise;
    }
    const prevMetric = this.mirrorMetrics[this.activeSourceIndex];
    const nextMetric = this.mirrorMetrics[nextMirrorIdx];
    if (!nextMetric) return;

    this.switchingSourcePromise = (async () => {
      const newEpoch = ++this.epoch;
      this.resetGeneration += 1;

      for (const req of this.activeRequests) {
        req.destroy();
      }
      this.activeRequests.clear();
      for (const h of this.segmentHandles.values()) {
        h.evicted = true;
        h.res?.destroy();
        h.req?.destroy();
      }

      await Promise.allSettled(Array.from(this.inFlightWrites));
      await this.metaPersistChain.catch(() => undefined);
      if (this.abortController.signal.aborted || this.stopReason !== 'none' || this.epoch !== newEpoch) {
        return;
      }

      // Isolate staging completely before switching sources:
      // 1. Invalidate old .part.meta first so a crash can never leave stale extents.
      // 2. Close & remove old staging file, then reserve a fresh exclusive staging file.
      const oldPartPath = this.item.partPath;
      if (this.fileHandle) {
        await this.fileHandle.close().catch(() => undefined);
        this.fileHandle = null;
      }
      if (oldPartPath && this.stagingOwned) {
        // Retire old payload + sidecar together; on failure the pair stays intact and the fresh
        // exclusive pair reservation below can never be paired with the stale checkpoint.
        await this.retireStagingPairLogged(oldPartPath, 'single-source restart');
      }

      const fresh = await reserveExclusiveStagingFile(
        this.frozenDestinationDir || this.item.destinationDir,
        this.item.filename,
        this.item.id
      );
      this.stagingOwned = true;
      this.item.partPath = fresh.partPath;
      this.fileHandle = this.wrapHandle(fresh.handle);
      if (this.item.totalBytes && this.item.totalBytes > 0) {
        await this.fileHandle.truncate(this.item.totalBytes);
      }

      this.activeSourceIndex = nextMirrorIdx;
      this.item.pinnedEtag = nextMetric.expectedEtag;
      this.item.pinnedLastModified = nextMetric.expectedLastModified;
      this.item.sourceProvenance = nextMetric.provenance;
      this.item.finalUrl = nextMetric.url;

      this.item.segments = this.buildInitialSegments(nextMirrorIdx);
      this.nextSegmentId = this.item.segments.length;
      this.item.downloadedBytes = 0;
      this.segLastSampleBytes.clear();
      this.segCommittedBytes.clear();
      this.segSpanCompleted.clear();
      for (const seg of this.item.segments) {
        this.segLastSampleBytes.set(seg.id, 0);
        this.segCommittedBytes.set(seg.id, 0);
      }

      this.appendRoutingLog(
        'warn',
        `${prevMetric?.label ?? 'Primary source'} ${reason} -> restarted cleanly from offset 0 on ${nextMetric.label}`
      );
      await this.persistPartMeta(true);
      this.updateMirrorTelemetrySnapshot();

      for (const seg of this.item.segments) {
        this.spawnWorker(seg, newEpoch);
      }
    })();

    try {
      await this.switchingSourcePromise;
    } finally {
      this.switchingSourcePromise = null;
    }
  }

  private spawnWorker(seg: SegmentState, workerEpoch: number): void {
    const p = this.runSegmentWorker(seg, workerEpoch).finally(() => {
      this.activeWorkers.delete(p);
    });
    this.activeWorkers.add(p);
  }

  private async runSegmentWorker(initialSeg: SegmentState, initialWorkerEpoch: number): Promise<void> {
    const ctx: WorkerContext = {
      seg: initialSeg,
      workerEpoch: initialWorkerEpoch,
    };
    let noProgressCount = 0;
    ctx.seg.status = 'active';

    while (!this.abortController.signal.aborted && ctx.workerEpoch === this.epoch) {
      const seg = ctx.seg;
      const committed = this.segCommittedBytes.get(seg.id) ?? 0;
      if (seg.end >= 0 && seg.start + committed > seg.end && this.segSpanCompleted.has(seg.id)) {
        seg.downloaded = committed;
        seg.status = 'done';
        seg.speedBps = 0;
        this.tryStealWork(ctx.workerEpoch);
        return;
      }

      // Ensure cursor starts from verified disk-committed offset
      seg.downloaded = committed;
      const handle: ActiveSegmentHandle = { evicted: false };
      this.segmentHandles.set(seg.id, handle);
      const beforeCommitted = committed;

      try {
        await this.executeSegmentAttempt(ctx, handle);

        if (this.abortController.signal.aborted || ctx.workerEpoch !== this.epoch) {
          return;
        }

        if (handle.evicted) {
          continue;
        }

        const activeSeg = ctx.seg;
        const afterCommitted = this.segCommittedBytes.get(activeSeg.id) ?? 0;
        activeSeg.downloaded = afterCommitted;
        if (
          this.segSpanCompleted.has(activeSeg.id) &&
          (activeSeg.end === -1 || activeSeg.start + afterCommitted > activeSeg.end)
        ) {
          activeSeg.status = 'done';
          activeSeg.speedBps = 0;
          this.tryStealWork(ctx.workerEpoch);
          return;
        }

        throw new Error(
          `Connection closed early at offset ${activeSeg.start + afterCommitted} (expected end ${activeSeg.end})`
        );
      } catch (err) {
        const activeSeg = ctx.seg;
        const afterCommitted = this.segCommittedBytes.get(activeSeg.id) ?? 0;
        activeSeg.downloaded = afterCommitted;
        this.recomputeDownloadedTotal();

        if (err instanceof FatalDiskError || this.fatalDiskError) {
          const fatal = this.triggerFatalDiskError(err);
          activeSeg.lastError = fatal.message;
          activeSeg.status = 'error';
          activeSeg.speedBps = 0;
          return;
        }

        if (
          this.abortController.signal.aborted ||
          ctx.workerEpoch !== this.epoch ||
          isAbortError(err)
        ) {
          return;
        }

        if (handle.evicted) {
          continue;
        }

        if (afterCommitted > beforeCommitted) {
          noProgressCount = 0;
        } else {
          noProgressCount += 1;
        }

        activeSeg.retries += 1;
        activeSeg.lastError = sanitizeUpstreamError(err, this.secrets, 220);

        const failedMirrorIdx = activeSeg.mirrorIndex ?? 0;
        const failedMetric = this.mirrorMetrics[failedMirrorIdx];
        if (failedMetric) {
          failedMetric.failures += 1;
          const retryMs = err instanceof RetryableHttpError ? err.retryAfterMs : 2_000;
          failedMetric.cooldownUntil = Math.max(failedMetric.cooldownUntil, Date.now() + retryMs);
          failedMetric.status = err instanceof ValidatorMismatchError ? 'failed' : 'cooldown';
          failedMetric.lastEvent =
            err instanceof RetryableHttpError
              ? `HTTP ${err.statusCode}`
              : err instanceof ValidatorMismatchError
                ? 'Validator changed'
                : 'Transient error';
        }

        const altIdx = this.pickHealthyAlternateMirror(failedMirrorIdx);
        const maxNoProgress = this.maxRetries + 2;
        if (
          altIdx !== null &&
          noProgressCount <= maxNoProgress &&
          activeSeg.retries <= this.maxRetries + this.mirrorMetrics.length
        ) {
          if (!this.isMultiMirrorStripingAllowed()) {
            await this.restartDownloadOnSingleSource(
              altIdx,
              `returned ${failedMetric?.lastEvent ?? 'error'}`
            );
            return;
          }

          const altMetric = this.mirrorMetrics[altIdx];
          if (failedMetric && altMetric) {
            this.appendRoutingLog(
              'warn',
              `${failedMetric.label} returned ${failedMetric.lastEvent ?? 'error'} -> failed over to ${altMetric.label}`
            );
          }
          activeSeg.mirrorIndex = altIdx;
          await abortableDelay(40, this.abortController.signal).catch(() => {});
          continue;
        }

        if (activeSeg.retries > this.maxRetries || noProgressCount > maxNoProgress) {
          if (failedMetric) failedMetric.status = 'failed';
          activeSeg.status = 'error';
          activeSeg.speedBps = 0;
          this.epoch += 1;
          this.abortController.abort();
          return;
        }

        if (err instanceof RetryableHttpError && err.hasExplicitRetryAfter) {
          // Strictly honor Retry-After deadline without shortening via negative jitter
          await abortableDelay(err.retryAfterMs, this.abortController.signal).catch(() => {});
        } else {
          const rawBackoff =
            err instanceof RetryableHttpError
              ? err.retryAfterMs
              : Math.min(12_000, 500 * Math.pow(2, activeSeg.retries - 1));
          const jitteredBackoff = Math.round(rawBackoff * (1.0 + Math.random() * 0.2));
          await abortableDelay(jitteredBackoff, this.abortController.signal).catch(() => {});
        }
      } finally {
        this.segmentHandles.delete(ctx.seg.id);
      }
    }
  }

  private async executeSegmentAttempt(
    ctx: WorkerContext,
    handle: ActiveSegmentHandle
  ): Promise<void> {
    const seg = ctx.seg;
    const workerEpoch = ctx.workerEpoch;
    const isRanged = this.item.supportsRanges && seg.end >= 0;
    const mirrorIdx = seg.mirrorIndex ?? this.activeSourceIndex;
    const metric = this.mirrorMetrics[mirrorIdx];
    const targetUrl = metric?.url ?? this.item.finalUrl;

    // For non-range retries, safely invalidate checkpoint BEFORE truncating (or allocate fresh staging
    // if sidecar unlink fails with a non-ENOENT error).
    if (!isRanged && (seg.downloaded > 0 || (this.segCommittedBytes.get(seg.id) ?? 0) > 0)) {
      this.resetGeneration += 1;
      await Promise.allSettled(Array.from(this.inFlightWrites));
      await this.metaPersistChain.catch(() => undefined);
      await this.resetStagingForOffsetZero(this.item.totalBytes);
      seg.downloaded = 0;
      this.segCommittedBytes.set(seg.id, 0);
      this.segLastSampleBytes.set(seg.id, 0);
      this.segSpanCompleted.delete(seg.id);
      this.item.downloadedBytes = 0;
    }

    let committedOffset = this.segCommittedBytes.get(seg.id) ?? 0;
    // Never splice unverified validatorless bytes on mid-flight retry without a trusted digest or strong ETag
    if (
      isRanged &&
      committedOffset > 0 &&
      !this.hasTrustedDigest() &&
      !isStrongEtag(metric?.expectedEtag ?? this.item.pinnedEtag)
    ) {
      await this.restartDownloadOnSingleSource(
        mirrorIdx,
        'interrupted without strong ETag validator or digest'
      );
      return;
    }

    // Every byte of the span was written but the response never reached a validated EOF
    // (e.g. interrupted after the last byte): byte count alone is not proof -> refetch the span.
    if (
      isRanged &&
      committedOffset > 0 &&
      seg.start + committedOffset > seg.end &&
      !this.segSpanCompleted.has(seg.id)
    ) {
      this.segCommittedBytes.set(seg.id, 0);
      this.segLastSampleBytes.set(seg.id, 0);
      seg.downloaded = 0;
      committedOffset = 0;
      this.recomputeDownloadedTotal();
      this.appendRoutingLog(
        'warn',
        `Segment ${seg.id} reached its byte count without a validated EOF — refetching the span`
      );
    }

    seg.downloaded = committedOffset;
    const rangeStart = seg.start + committedOffset;
    const requestedEnd = seg.end;
    const headers: Record<string, string> = {
      'User-Agent': 'BoltGate/1.0 (+SafeDownloader)',
      Accept: '*/*',
      'Accept-Encoding': 'identity',
    };

    if (isRanged) {
      headers.Range = `bytes=${rangeStart}-${requestedEnd}`;
      const validator =
        this.item.pinnedEtag ||
        this.item.etag ||
        this.item.pinnedLastModified ||
        this.item.lastModified;
      if (committedOffset > 0 && validator) {
        headers['If-Range'] = validator;
      }
    }

    if (metric) {
      metric.status = 'active';
      if (metric.firstActiveAt === null) {
        metric.firstActiveAt = Date.now();
      }
    }

    const { res, req, finalUrl } = await this.openStreamWithRedirects(
      targetUrl,
      headers,
      workerEpoch,
      handle
    );
    handle.req = req;
    handle.res = res;
    if (metric) {
      metric.observedUrls.add(finalUrl);
    }

    try {
      if (this.abortController.signal.aborted || workerEpoch !== this.epoch || handle.evicted) {
        res.destroy();
        return;
      }

      const status = res.statusCode ?? 0;

      if (status === 429 || status === 503) {
        const currentWorkersOnOrigin = Math.max(
          1,
          this.item.segments.filter((s) => s.status === 'active' && (s.mirrorIndex ?? 0) === mirrorIdx).length
        );
        // Gate against the actual responding origin (important when targetUrl redirected to another host)
        const rl = this.rateLimiter.recordRateLimit(
          finalUrl,
          status,
          res.headers['retry-after'],
          currentWorkersOnOrigin
        );
        if (finalUrl !== targetUrl) {
          this.rateLimiter.recordRateLimit(
            targetUrl,
            status,
            res.headers['retry-after'],
            currentWorkersOnOrigin
          );
        }
        res.destroy();
        throw new RetryableHttpError(
          status,
          rl.delayMs,
          rl.retryAfterMs !== null,
          `Rate limited (HTTP ${status}) on segment ${seg.id}, waiting ${rl.delayMs}ms before retry`
        );
      }

      // Reject compressed representations when exact byte offsets / total bytes are required
      const contentEncoding = firstStr(res.headers['content-encoding'])?.trim().toLowerCase();
      if ((isRanged || this.item.totalBytes !== null) && contentEncoding && contentEncoding !== 'identity') {
        res.destroy();
        throw new Error(`Rejected non-identity Content-Encoding (${contentEncoding}) during transfer`);
      }

      const respEtag = firstStr(res.headers.etag);
      const respLastMod = firstStr(res.headers['last-modified']);

      if (!this.hasTrustedDigest() && status >= 200 && status < 300) {
        const expectedEtag = metric?.expectedEtag ?? this.item.pinnedEtag;
        const expectedLastMod = metric?.expectedLastModified ?? this.item.pinnedLastModified;
        const check = validateResponseValidators(
          { etag: expectedEtag, lastModified: expectedLastMod },
          { etag: respEtag, lastModified: respLastMod }
        );
        if (!check.ok) {
          res.destroy();
          throw new ValidatorMismatchError(
            check.reason ?? 'Upstream validator changed without trusted digest'
          );
        }
        if (respEtag && !this.item.pinnedEtag) {
          this.item.pinnedEtag = respEtag;
          if (metric) metric.expectedEtag = respEtag;
        }
        if (respLastMod && !this.item.pinnedLastModified) {
          this.item.pinnedLastModified = respLastMod;
          if (metric) metric.expectedLastModified = respLastMod;
        }
      }

      // Server ignored Range header and sent full 200 OK body -> clean single-stream generation reset
      if (isRanged && status === 200) {
        const newEpoch = ++this.epoch;
        this.resetGeneration += 1;

        for (const otherReq of this.activeRequests) {
          if (otherReq !== req) {
            otherReq.destroy();
          }
        }

        await Promise.allSettled(Array.from(this.inFlightWrites));
        await this.metaPersistChain.catch(() => undefined);
        if (this.abortController.signal.aborted || this.epoch !== newEpoch) {
          res.destroy();
          return;
        }

        const headerLen = parseStrictContentLength(res.headers['content-length']);
        if (
          this.item.totalBytes !== null &&
          headerLen !== null &&
          headerLen !== this.item.totalBytes
        ) {
          res.destroy();
          throw new Error(
            `Mismatched 200 Content-Length (${headerLen}) vs expected ${this.item.totalBytes} bytes on range fallback`
          );
        }
        const total = headerLen !== null ? headerLen : this.item.totalBytes;

        // Safely invalidate old .part.meta BEFORE truncating (or isolate onto a fresh staging file on unlink error)
        await this.resetStagingForOffsetZero(total);
        this.segSpanCompleted.clear();

        this.item.supportsRanges = false;
        this.item.connections = 1;
        this.item.totalBytes = total;
        this.item.downloadedBytes = 0;
        this.item.mirrorUrls = [targetUrl];
        this.multiMirrorStripingAllowed = false;
        this.mirrorMetrics = [
          {
            sourceId: metric?.sourceId ?? computeOpaqueSourceId(targetUrl, this.sourceIdKey),
            url: targetUrl,
            label: metric?.label ?? 'Single Stream',
            host: metric?.host ?? normalizeHostname(new URL(targetUrl).hostname),
            tier: metric?.tier ?? 'direct',
            provenance: metric?.provenance,
            expectedEtag: respEtag ?? this.item.pinnedEtag,
            expectedLastModified: respLastMod ?? this.item.pinnedLastModified,
            observedUrls: new Set([targetUrl, finalUrl]),
            status: 'active',
            bytes: 0,
            speedBps: 0,
            lastActiveSpeedBps: 0,
            lastSampleBytes: 0,
            samples: [],
            firstActiveAt: Date.now(),
            cooldownUntil: 0,
            evictedUntil: 0,
            failures: 0,
          },
        ];

        const singleSeg: SegmentState = {
          id: 0,
          start: 0,
          end: total !== null ? total - 1 : -1,
          downloaded: 0,
          speedBps: 0,
          status: 'active',
          retries: 0,
          mirrorIndex: 0,
        };
        this.item.segments = [singleSeg];
        this.segLastSampleBytes.clear();
        this.segLastSampleBytes.set(0, 0);
        this.segCommittedBytes.clear();
        this.segCommittedBytes.set(0, 0);

        // Transfer retry ownership to this worker BEFORE streaming so mid-stream interruptions
        // retry cleanly under the new epoch!
        ctx.workerEpoch = newEpoch;
        ctx.seg = singleSeg;
        this.segmentHandles.set(singleSeg.id, handle);

        await this.streamResponseIntoSegment(singleSeg, res, newEpoch, 0, handle, singleSeg.end);
        this.rateLimiter.recordSuccess(finalUrl);
        if (finalUrl !== targetUrl) this.rateLimiter.recordSuccess(targetUrl);
        return;
      }

      if (isRanged) {
        if (status !== 206) {
          res.destroy();
          throw new Error(`Expected HTTP 206 for ranged request on segment ${seg.id}, got HTTP ${status}`);
        }
        const cr = parseStrict206Range(res.headers['content-range']);
        if (!cr || cr.total === null) {
          res.destroy();
          throw new Error(`Missing, wildcard, or malformed 206 Content-Range on segment ${seg.id}`);
        }
        const expectedLen = cr.end - cr.start + 1;
        const headerLen = parseStrictContentLength(res.headers['content-length']);
        if (
          cr.start !== rangeStart ||
          cr.end !== requestedEnd ||
          (this.item.totalBytes !== null && cr.total !== this.item.totalBytes) ||
          (headerLen !== null && headerLen !== expectedLen)
        ) {
          res.destroy();
          throw new Error(
            `Mismatched 206 Content-Range (${cr.start}-${cr.end}/${cr.total} vs expected ${rangeStart}-${requestedEnd})`
          );
        }
      } else {
        // Non-range mode strictly requires HTTP 200 (reject unexpected 206 or other status codes)
        if (status !== 200) {
          res.destroy();
          throw new Error(
            status === 206
              ? `Unexpected HTTP 206 Partial Content in non-range mode on segment ${seg.id}`
              : `HTTP ${status} while fetching segment ${seg.id}`
          );
        }
        const headerLen = parseStrictContentLength(res.headers['content-length']);
        if (this.item.totalBytes !== null && headerLen !== null && headerLen !== this.item.totalBytes) {
          res.destroy();
          throw new Error(
            `Mismatched 200 Content-Length (${headerLen}) vs expected ${this.item.totalBytes} bytes`
          );
        }
        if (this.item.totalBytes === null && headerLen !== null) {
          this.item.totalBytes = headerLen;
          seg.end = headerLen - 1;
        }
      }

      const attemptInitialEnd = seg.end;
      await this.streamResponseIntoSegment(seg, res, workerEpoch, mirrorIdx, handle, attemptInitialEnd);
      this.rateLimiter.recordSuccess(finalUrl);
      if (finalUrl !== targetUrl) this.rateLimiter.recordSuccess(targetUrl);
    } finally {
      this.activeRequests.delete(req);
      if (!res.destroyed) {
        res.destroy();
      }
    }
  }

  private async streamResponseIntoSegment(
    seg: SegmentState,
    res: http.IncomingMessage,
    workerEpoch: number,
    mirrorIdx: number,
    handle: ActiveSegmentHandle,
    attemptInitialEnd: number
  ): Promise<void> {
    const myResetGen = this.resetGeneration;
    const attemptStartCommitted = this.segCommittedBytes.get(seg.id) ?? 0;
    this.segSpanCompleted.delete(seg.id);
    let stallTimer: NodeJS.Timeout | null = null;
    const resetStall = () => {
      if (stallTimer) clearTimeout(stallTimer);
      stallTimer = setTimeout(() => {
        res.destroy(new Error(`Segment ${seg.id} stalled (no data for ${this.stallTimeoutMs}ms)`));
      }, this.stallTimeoutMs);
    };

    const onAbort = () => {
      res.destroy();
    };
    this.abortController.signal.addEventListener('abort', onAbort, { once: true });
    resetStall();

    let pendingChunks: Buffer[] = [];
    let pendingBytes = 0;
    let batchStartOffset = seg.start + seg.downloaded;
    let protocolLengthViolation = false;
    let stoppedByWorkSteal = false;
    let streamReachedCleanEof = false;

    const rollbackUncommitted = () => {
      pendingChunks = [];
      pendingBytes = 0;
      const committed = this.segCommittedBytes.get(seg.id) ?? 0;
      seg.downloaded = committed;
      this.recomputeDownloadedTotal();
    };

    const invalidateAttemptExtents = () => {
      protocolLengthViolation = true;
      pendingChunks = [];
      pendingBytes = 0;
      this.segSpanCompleted.delete(seg.id);
      this.segCommittedBytes.set(seg.id, attemptStartCommitted);
      seg.downloaded = attemptStartCommitted;
      this.recomputeDownloadedTotal();
    };

    const flushPending = async () => {
      if (pendingBytes === 0) return;
      const chunksToWrite = pendingChunks;
      const bytesToWrite = pendingBytes;
      const writeOffset = batchStartOffset;
      pendingChunks = [];
      pendingBytes = 0;
      batchStartOffset = seg.start + seg.downloaded;

      if (myResetGen !== this.resetGeneration || this.stopReason === 'cancelled') {
        rollbackUncommitted();
        return;
      }
      if (!this.fileHandle) {
        rollbackUncommitted();
        throw new FatalDiskError('File handle closed unexpectedly before disk write');
      }

      const combined =
        chunksToWrite.length === 1 ? chunksToWrite[0]! : Buffer.concat(chunksToWrite, bytesToWrite);
      const writePromise = (async () => {
        let written = 0;
        try {
          while (written < combined.length) {
            if (myResetGen !== this.resetGeneration || this.stopReason === 'cancelled') {
              return;
            }
            if (!this.fileHandle) {
              throw new FatalDiskError('File handle closed unexpectedly during write loop');
            }
            const resWrite = await this.fileHandle.write(
              combined,
              written,
              combined.length - written,
              writeOffset + written
            );
            if (!Number.isFinite(resWrite.bytesWritten) || resWrite.bytesWritten <= 0) {
              throw new FatalDiskError('Short or zero-byte disk write to staging file');
            }
            written += resWrite.bytesWritten;
            const committedEnd = writeOffset + written - seg.start;
            this.segCommittedBytes.set(
              seg.id,
              Math.max(this.segCommittedBytes.get(seg.id) ?? 0, committedEnd)
            );
            this.diskWindowBytes += resWrite.bytesWritten;
          }
        } catch (writeErr) {
          rollbackUncommitted();
          throw this.triggerFatalDiskError(writeErr);
        }
      })();
      this.inFlightWrites.add(writePromise);
      try {
        await writePromise;
      } finally {
        this.inFlightWrites.delete(writePromise);
      }
    };

    let streamError: unknown = null;
    try {
      for await (const rawChunk of res) {
        if (this.abortController.signal.aborted || workerEpoch !== this.epoch || handle.evicted) {
          res.destroy();
          break;
        }
        resetStall();

        const buf = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
        if (buf.length === 0) continue;

        let slice = buf;
        const stolenCutoff = attemptInitialEnd >= 0 && seg.end < attemptInitialEnd;
        if (seg.end >= 0) {
          const remaining = seg.end - (seg.start + seg.downloaded) + 1;
          if (remaining <= 0) {
            if (stolenCutoff) {
              stoppedByWorkSteal = true;
              res.destroy();
              break;
            }
            res.destroy();
            invalidateAttemptExtents();
            throw new Error(
              `Upstream response exceeded expected length for segment ${seg.id} (extra ${slice.length} bytes)`
            );
          }
          if (slice.length > remaining) {
            if (stolenCutoff) {
              slice = slice.subarray(0, remaining);
            } else {
              res.destroy();
              invalidateAttemptExtents();
              throw new Error(
                `Upstream response exceeded expected length for segment ${seg.id} (received ${slice.length} bytes with ${remaining} remaining)`
              );
            }
          }
        }

        const tBeforeConsume = Date.now();
        await this.throttle.consume(slice.length, this.abortController.signal);
        if (this.throttle.getLimitKBps() > 0 && Date.now() - tBeforeConsume >= 15) {
          this.throttleConstrainedWindow = true;
        }
        if (this.abortController.signal.aborted || workerEpoch !== this.epoch || handle.evicted) {
          res.destroy();
          break;
        }

        const stolenCutoffAfterThrottle = attemptInitialEnd >= 0 && seg.end < attemptInitialEnd;
        if (seg.end >= 0) {
          const remainingAfterThrottle = seg.end - (seg.start + seg.downloaded) + 1;
          if (remainingAfterThrottle <= 0) {
            if (stolenCutoffAfterThrottle) {
              stoppedByWorkSteal = true;
              res.destroy();
              break;
            }
            res.destroy();
            invalidateAttemptExtents();
            throw new Error(`Upstream response exceeded expected length for segment ${seg.id}`);
          }
          if (slice.length > remainingAfterThrottle) {
            if (stolenCutoffAfterThrottle) {
              slice = slice.subarray(0, remainingAfterThrottle);
            } else {
              res.destroy();
              invalidateAttemptExtents();
              throw new Error(`Upstream response exceeded expected length for segment ${seg.id}`);
            }
          }
        }

        if (pendingBytes === 0) {
          batchStartOffset = seg.start + seg.downloaded;
        }

        seg.downloaded += slice.length;
        this.item.downloadedBytes += slice.length;
        if (this.mirrorMetrics[mirrorIdx]) {
          this.mirrorMetrics[mirrorIdx]!.bytes += slice.length;
        }

        pendingChunks.push(slice);
        pendingBytes += slice.length;

        if (pendingBytes >= this.writeBufferBytes) {
          await flushPending();
        }

        // Only break early when work-stealing intentionally shortened our segment boundary;
        // otherwise keep reading until EOF so any overlong server body is detected and rejected.
        if (stolenCutoffAfterThrottle && seg.end >= 0 && seg.start + seg.downloaded > seg.end) {
          stoppedByWorkSteal = true;
          res.destroy();
          break;
        }
      }
      if (!stoppedByWorkSteal && !this.abortController.signal.aborted && workerEpoch === this.epoch && !handle.evicted) {
        streamReachedCleanEof = true;
      }
    } catch (err) {
      streamError = err;
      throw err;
    } finally {
      if (stallTimer) clearTimeout(stallTimer);
      this.abortController.signal.removeEventListener('abort', onAbort);
      if (protocolLengthViolation) {
        invalidateAttemptExtents();
      } else if (streamError instanceof FatalDiskError || this.fatalDiskError || this.stopReason === 'cancelled') {
        rollbackUncommitted();
      } else {
        try {
          await flushPending();
        } catch (flushErr) {
          rollbackUncommitted();
          if (!streamError) {
            throw flushErr;
          }
        }
      }
      // Guarantee received cursor aligns with verified disk-committed offset on exit
      const committed = this.segCommittedBytes.get(seg.id) ?? 0;
      if (seg.downloaded !== committed) {
        seg.downloaded = committed;
        this.recomputeDownloadedTotal();
      }
      // Explicitly mark span completed ONLY on clean EOF or intentional work-stealing cutoff
      // with zero protocol/length errors and exact committed span coverage.
      if (
        !streamError &&
        !protocolLengthViolation &&
        !this.fatalDiskError &&
        (streamReachedCleanEof || stoppedByWorkSteal) &&
        (seg.end === -1 || seg.start + committed > seg.end)
      ) {
        this.segSpanCompleted.add(seg.id);
      } else {
        this.segSpanCompleted.delete(seg.id);
      }
    }
  }

  private tryStealWork(workerEpoch: number): void {
    if (
      this.abortController.signal.aborted ||
      workerEpoch !== this.epoch ||
      !this.item.supportsRanges ||
      // Never split an unproven-identity transfer into extra ranged requests
      !this.isIdentityProven()
    ) {
      return;
    }

    const singleSource = !this.isMultiMirrorStripingAllowed();
    const activeTargetUrl =
      this.mirrorMetrics[singleSource ? this.activeSourceIndex : this.pickFastestMirrorIndex()]?.url ??
      this.item.finalUrl;
    const currentWorkers = this.item.segments.filter((s) => s.status === 'active').length;
    const allowedWorkers = this.rateLimiter.getRecommendedMaxWorkers(
      activeTargetUrl,
      Math.max(1, Math.min(16, this.item.connections || 1))
    );
    if (currentWorkers >= allowedWorkers) {
      return;
    }

    let bestDonor: SegmentState | null = null;
    let bestRemaining = 0;

    for (const candidate of this.item.segments) {
      if (candidate.status !== 'active' || candidate.end < 0) continue;
      const cursor = candidate.start + candidate.downloaded;
      const remaining = candidate.end - cursor + 1;
      if (remaining > bestRemaining) {
        bestRemaining = remaining;
        bestDonor = candidate;
      }
    }

    if (!bestDonor || bestRemaining < this.minSegmentBytes * 2) {
      return;
    }

    const cursor = bestDonor.start + bestDonor.downloaded;
    const mid = cursor + Math.floor(bestRemaining / 2);
    const oldEnd = bestDonor.end;
    if (mid <= cursor || mid > oldEnd) return;

    bestDonor.end = mid - 1;
    const stolen: SegmentState = {
      id: this.nextSegmentId++,
      start: mid,
      end: oldEnd,
      downloaded: 0,
      speedBps: 0,
      status: 'pending',
      retries: 0,
      mirrorIndex: singleSource
        ? this.activeSourceIndex
        : this.pickFastestMirrorIndex(bestDonor.mirrorIndex),
    };
    this.item.segments.push(stolen);
    this.segLastSampleBytes.set(stolen.id, 0);
    this.segCommittedBytes.set(stolen.id, 0);
    this.spawnWorker(stolen, workerEpoch);
  }

  private isMirrorCoolingDown(m: MirrorMetric, now: number): boolean {
    if (m.cooldownUntil > now) return true;
    for (const observed of m.observedUrls) {
      if (this.rateLimiter.isCoolingDown(observed, now)) return true;
    }
    return false;
  }

  private pickHealthyAlternateMirror(excludeIdx: number): number | null {
    if (this.mirrorMetrics.length <= 1) return null;
    const now = Date.now();
    let bestIdx: number | null = null;
    let bestScore = -Infinity;

    for (let i = 0; i < this.mirrorMetrics.length; i++) {
      if (i === excludeIdx) continue;
      const m = this.mirrorMetrics[i]!;
      if (this.isMirrorCoolingDown(m, now) || m.evictedUntil > now || m.status === 'failed') {
        continue;
      }
      const untriedBonus = m.firstActiveAt === null ? 500_000 : 0;
      const score = untriedBonus + m.speedBps * 10 - m.failures * 100_000;
      if (bestIdx === null || score > bestScore) {
        bestIdx = i;
        bestScore = score;
      }
    }
    return bestIdx;
  }

  private pickFastestMirrorIndex(fallbackIdx = 0): number {
    if (this.mirrorMetrics.length <= 1) return 0;
    const now = Date.now();
    let bestIdx = fallbackIdx;
    let bestSpeed = -1;

    for (let i = 0; i < this.mirrorMetrics.length; i++) {
      const m = this.mirrorMetrics[i]!;
      if (this.isMirrorCoolingDown(m, now) || m.evictedUntil > now || m.status === 'failed') {
        continue;
      }
      const effectiveSpeed = Math.max(m.speedBps, m.lastActiveSpeedBps);
      if (effectiveSpeed > bestSpeed) {
        bestSpeed = effectiveSpeed;
        bestIdx = i;
      }
    }
    return bestIdx;
  }

  private pickSpeedFloorAlternate(slowIdx: number, slowSpeedBps: number): number | null {
    const now = Date.now();
    let bestIdx: number | null = null;
    let bestScore = -Infinity;

    for (let i = 0; i < this.mirrorMetrics.length; i++) {
      if (i === slowIdx) continue;
      const cand = this.mirrorMetrics[i]!;
      if (
        this.isMirrorCoolingDown(cand, now) ||
        cand.evictedUntil > now ||
        cand.status === 'evicted' ||
        cand.status === 'failed'
      ) {
        continue;
      }
      const isUntried = cand.firstActiveAt === null;
      const activeWorkers = this.item.segments.filter(
        (s) => s.status === 'active' && (s.mirrorIndex ?? 0) === i
      ).length;
      const effectiveSpeed =
        activeWorkers > 0 ? cand.speedBps : Math.max(cand.speedBps, cand.lastActiveSpeedBps);
      const isClearlyFaster =
        effectiveSpeed >= this.minSpeedFloorBps ||
        effectiveSpeed > Math.max(slowSpeedBps * 1.5, 64 * 1024);
      if (!isUntried && !isClearlyFaster) continue;

      const score = (isUntried ? 10_000_000 : 0) + effectiveSpeed - cand.failures * 250_000;
      if (bestIdx === null || score > bestScore) {
        bestIdx = i;
        bestScore = score;
      }
    }
    return bestIdx;
  }

  private evaluateSpeedFloor(now: number): void {
    if (
      this.minSpeedFloorBps <= 0 ||
      this.mirrorMetrics.length <= 1 ||
      !this.item.supportsRanges ||
      this.abortController.signal.aborted ||
      this.switchingSourcePromise !== null
    ) {
      return;
    }

    for (let mIdx = 0; mIdx < this.mirrorMetrics.length; mIdx++) {
      const m = this.mirrorMetrics[mIdx]!;
      if (
        m.status !== 'active' ||
        m.firstActiveAt === null ||
        now - m.firstActiveAt < this.evictionGraceMs ||
        m.samples.length < 2
      ) {
        continue;
      }
      if (m.speedBps >= this.minSpeedFloorBps) {
        continue;
      }

      const activeSegsOnMirror = this.item.segments.filter(
        (s) => s.status === 'active' && (s.mirrorIndex ?? 0) === mIdx
      );
      if (activeSegsOnMirror.length === 0) continue;

      const altIdx = this.pickSpeedFloorAlternate(mIdx, m.speedBps);
      if (altIdx === null) continue;

      const alt = this.mirrorMetrics[altIdx]!;
      m.status = 'evicted';
      m.evictedUntil = now + 30_000;
      m.lastEvent = `Evicted at ${formatSpeedShort(m.speedBps)} (< ${formatSpeedShort(this.minSpeedFloorBps)})`;

      if (!this.isMultiMirrorStripingAllowed()) {
        void this.restartDownloadOnSingleSource(
          altIdx,
          `slow at ${formatSpeedShort(m.speedBps)} (< ${formatSpeedShort(this.minSpeedFloorBps)} floor)`
        );
        return;
      }

      for (const seg of activeSegsOnMirror) {
        seg.mirrorIndex = altIdx;
        const handle = this.segmentHandles.get(seg.id);
        if (handle) {
          handle.evicted = true;
          handle.req?.destroy();
          handle.res?.destroy();
        }
      }

      this.appendRoutingLog(
        'warn',
        `${m.label} capped at ${formatSpeedShort(m.speedBps)} (< ${formatSpeedShort(this.minSpeedFloorBps)} floor) -> switched ${activeSegsOnMirror.length} worker(s) to ${alt.label}${alt.speedBps > 0 ? ` (${formatSpeedShort(alt.speedBps)})` : ''}`
      );
    }
  }

  private updateMirrorTelemetrySnapshot(now = Date.now()): void {
    const activeWorkerCounts = new Map<number, number>();
    let totalWorkers = 0;
    let totalCommitted = 0;
    for (const seg of this.item.segments) {
      if (seg.status === 'active') {
        totalWorkers += 1;
        const idx = seg.mirrorIndex ?? 0;
        activeWorkerCounts.set(idx, (activeWorkerCounts.get(idx) ?? 0) + 1);
      }
      totalCommitted += this.segCommittedBytes.get(seg.id) ?? 0;
    }

    const telemetry: MirrorTelemetry[] = this.mirrorMetrics.map((m, idx) => ({
      sourceId: m.sourceId,
      url: m.url,
      label: m.label,
      host: m.host,
      tier: m.tier,
      provenance: m.provenance,
      status: m.status,
      speedBps: m.speedBps,
      downloadedBytes: m.bytes,
      activeWorkers: activeWorkerCounts.get(idx) ?? 0,
      failures: m.failures,
      lastEvent: m.lastEvent,
    }));
    this.item.mirrorTelemetry = telemetry;

    const activeCount = telemetry.filter((m) => m.activeWorkers > 0).length;
    if (activeCount >= 2) {
      this.item.sourceMode = 'swarm';
      this.item.sourceBadge = `Swarming ${activeCount} mirrors`;
    } else if (!this.isMultiMirrorStripingAllowed() && this.mirrorMetrics.length > 1) {
      const activeMirror = this.mirrorMetrics[this.activeSourceIndex];
      this.item.sourceBadge = activeMirror
        ? `Single-source (${activeMirror.host})`
        : this.item.sourceBadge;
    }

    const allObservedUrls: string[] = [];
    for (const m of this.mirrorMetrics) {
      for (const u of m.observedUrls) {
        allObservedUrls.push(u);
      }
    }
    const backingOffHosts = this.rateLimiter.getBackingOffHostsForUrls(allObservedUrls, now);
    const localCapBps = this.throttle.getLimitKBps() * 1024;

    this.item.telemetry = {
      networkSpeedBps: this.item.speedBps,
      diskSpeedBps: Math.round(this.diskEmaSpeedBps),
      committedBytes: totalCommitted,
      receivedBytes: this.item.downloadedBytes,
      throttledByLocalCap: this.throttleConstrainedWindow && localCapBps > 0,
      configuredLocalCapBps: localCapBps,
      localCapBps,
      serverThrottled: backingOffHosts.length > 0,
      backingOffHosts: Array.from(new Set(backingOffHosts)),
      activeWorkers: totalWorkers,
    };
  }

  private async persistPartMeta(force = false): Promise<void> {
    if (!this.item.partPath || this.item.totalBytes === null) return;
    if (this.fatalDiskError || this.stopReason === 'cancelled') return;
    const now = Date.now();
    if (!force && now - this.lastMetaPersistAt < 1500) return;
    this.lastMetaPersistAt = now;

    const myResetGen = this.resetGeneration;
    const targetPartPath = this.item.partPath;

    const run = this.metaPersistChain.then(async () => {
      if (
        !this.item.partPath ||
        this.item.totalBytes === null ||
        myResetGen !== this.resetGeneration ||
        targetPartPath !== this.item.partPath ||
        this.fatalDiskError ||
        this.stopReason === 'cancelled'
      ) {
        return;
      }

      if (force) {
        await Promise.allSettled(Array.from(this.inFlightWrites));
      }

      // Snapshot committed offsets BEFORE datasync so every recorded byte is guaranteed durable
      const segmentsForMeta = this.item.segments.map((seg) => ({
        id: seg.id,
        start: seg.start,
        end: seg.end,
        committedBytes: Math.min(
          seg.end >= 0 ? seg.end - seg.start + 1 : Number.MAX_SAFE_INTEGER,
          this.segCommittedBytes.get(seg.id) ?? 0
        ),
        status: seg.status,
        mirrorIndex: seg.mirrorIndex,
        // Persist explicit EOF/length validation proof (byte count alone never proves completion)
        spanVerified: this.segSpanCompleted.has(seg.id),
      }));

      // Propagate payload datasync() errors BEFORE writing .part.meta!
      if (this.fileHandle) {
        try {
          await this.fileHandle.datasync();
        } catch (syncErr) {
          throw this.triggerFatalDiskError(syncErr);
        }
      }

      if (
        myResetGen !== this.resetGeneration ||
        targetPartPath !== this.item.partPath ||
        this.getStopReason() === 'cancelled'
      ) {
        return;
      }

      // Persist opaque keyed source IDs and sanitized derived fields only — never raw signed or
      // credentialed URLs, and never validators that echo an active credential.
      const secrets = this.secrets;
      const mirrorsForMeta: PartMetaMirrorRef[] = this.mirrorMetrics.map((m) => ({
        sourceId: m.sourceId,
        label: redactText(m.label, secrets),
        host: m.host,
        tier: m.tier,
        provenance: m.provenance ? redactText(m.provenance, secrets) : undefined,
        etag: redactValidator(m.expectedEtag, secrets),
        lastModified: redactValidator(m.expectedLastModified, secrets),
      }));

      await writePartMeta(targetPartPath, {
        version: 2,
        jobId: this.item.id,
        partPath: targetPartPath,
        filename: redactText(this.item.filename, secrets),
        totalBytes: this.item.totalBytes,
        resourceId: this.getActiveResourceId(),
        expectedMd5: this.frozenExpectedMd5,
        expectedSha256: this.frozenExpectedSha256,
        pinnedEtag: redactValidator(this.item.pinnedEtag, secrets),
        pinnedLastModified: redactValidator(this.item.pinnedLastModified, secrets),
        mirrors: mirrorsForMeta,
        segments: segmentsForMeta,
        updatedAt: Date.now(),
      });
    });

    this.metaPersistChain = run.catch(() => undefined);
    try {
      await run;
    } catch (err) {
      // Checkpoint / sidecar write failures are never silently ignored: they are fatal so the job
      // can never be misreported as durably paused or resumable.
      throw err instanceof FatalDiskError ? err : this.triggerFatalDiskError(err);
    }
  }

  private openStreamWithRedirects(
    startUrl: string,
    headers: Record<string, string>,
    workerEpoch: number,
    handle: ActiveSegmentHandle
  ): Promise<{ res: http.IncomingMessage; req: http.ClientRequest; finalUrl: string }> {
    return new Promise((resolve, reject) => {
      const follow = async (target: URL, hop: number) => {
        if (this.abortController.signal.aborted || workerEpoch !== this.epoch || handle.evicted) {
          reject(new DOMException('Aborted', 'AbortError'));
          return;
        }
        if (target.protocol !== 'http:' && target.protocol !== 'https:') {
          reject(new Error(`Blocked unsafe scheme: ${target.protocol}`));
          return;
        }

        const hopUrlStr = target.toString();

        // Gate EVERY request hop against the target origin's shared cooldown,
        // re-checking immediately before dispatch so concurrent Retry-After extensions are honored!
        while (true) {
          const cooldownMs = this.rateLimiter.getCooldownRemainingMs(hopUrlStr);
          if (cooldownMs <= 0) break;
          try {
            await abortableDelay(cooldownMs, this.abortController.signal);
          } catch (delayErr) {
            reject(delayErr);
            return;
          }
          if (this.abortController.signal.aborted || workerEpoch !== this.epoch || handle.evicted) {
            reject(new DOMException('Aborted', 'AbortError'));
            return;
          }
        }

        // Outbound secret leak guard on EVERY initial request and redirect hop, evaluated against
        // the LIVE secret set right before dispatch (after any cooldown wait / key rotation).
        try {
          assertOutboundUrlSafe(hopUrlStr, this.secrets);
        } catch (guardErr) {
          reject(guardErr);
          return;
        }

        const isHttps = target.protocol === 'https:';
        const client = isHttps ? https : http;
        const req = client.request(
          target,
          {
            method: 'GET',
            headers,
            agent: isHttps ? httpsAgent : httpAgent,
            timeout: this.stallTimeoutMs,
            ...(isHttps ? { rejectUnauthorized: true } : {}),
          },
          (res) => {
            const status = res.statusCode ?? 0;
            if (status >= 300 && status < 400 && typeof res.headers.location === 'string') {
              res.destroy();
              this.activeRequests.delete(req);
              if (hop >= MAX_REDIRECTS) {
                reject(new Error(`Too many redirects (>${MAX_REDIRECTS})`));
                return;
              }
              try {
                const nextUrl = new URL(res.headers.location, target);
                if (nextUrl.protocol !== 'http:' && nextUrl.protocol !== 'https:') {
                  throw new Error(`Blocked unsafe redirect scheme: ${nextUrl.protocol}`);
                }
                void follow(nextUrl, hop + 1);
              } catch (err) {
                reject(err);
              }
              return;
            }
            resolve({ res, req, finalUrl: hopUrlStr });
          }
        );

        handle.req = req;
        this.activeRequests.add(req);

        req.on('timeout', () => {
          req.destroy(new Error(`Request timed out after ${this.stallTimeoutMs}ms`));
        });

        req.on('error', (err) => {
          this.activeRequests.delete(req);
          reject(err);
        });

        req.end();
      };

      try {
        void follow(new URL(startUrl), 0);
      } catch (err) {
        reject(err);
      }
    });
  }

  private async finalizeCompletedFile(): Promise<void> {
    if (this.cancelled || this.stopReason !== 'none') return;

    const runFinalize = (async () => {
      this.item.status = 'verifying';
      this.item.speedBps = 0;
      this.item.etaSeconds = 0;
      for (const s of this.item.segments) {
        s.speedBps = 0;
        s.status = 'done';
      }
      this.onUpdate(this.item, false);

      const failAndResetStaging = async (reason: string) => {
        if (this.stagingOwned && this.item.partPath) {
          const retireErr = await this.retireStagingPairLogged(this.item.partPath, 'verification failure');
          if (retireErr) {
            throw new Error(
              `${reason} (staging pair could not be retired: ${sanitizeUpstreamError(retireErr, this.secrets, 120)})`
            );
          }
          this.stagingOwned = false;
        }
        this.item.segments = [];
        this.item.downloadedBytes = 0;
        this.item.pinnedEtag = undefined;
        this.item.pinnedLastModified = undefined;
        throw new Error(reason);
      };

      // Capture the physical identity of the staged file BEFORE hashing; publication is refused
      // if the file is swapped/modified between verification and publish.
      const verifiedIdentity = await captureFileIdentity(this.item.partPath);
      if (this.item.totalBytes !== null && Number(verifiedIdentity.size) !== this.item.totalBytes) {
        await failAndResetStaging(
          `Staged file size mismatch before publish (${verifiedIdentity.size} bytes vs expected ${this.item.totalBytes} bytes)`
        );
      }

      const { sha256, md5 } = await computeFileHashes(this.item.partPath);
      if (this.cancelled || this.stopReason !== 'none') return;

      this.item.sha256 = sha256;
      this.item.md5 = md5;

      if (this.frozenExpectedMd5) {
        const expected = this.frozenExpectedMd5.trim().toLowerCase();
        const match = md5.toLowerCase() === expected;
        this.item.md5Verified = match;
        if (!match) {
          this.appendRoutingLog(
            'danger',
            `MD5 mismatch on assembled .part file (expected ${expected}, got ${md5}) — purged staging before publish`
          );
          await failAndResetStaging(`MD5 verification failed: expected ${expected}, computed ${md5}`);
        }
        this.appendRoutingLog('ok', `MD5 verified (${md5}) before atomic publish`);
      }

      if (this.frozenExpectedSha256) {
        const expectedSha = this.frozenExpectedSha256.trim().toLowerCase();
        const matchSha = sha256.toLowerCase() === expectedSha;
        this.item.verifiedHashMatch = matchSha;
        if (!matchSha) {
          this.appendRoutingLog(
            'danger',
            `SHA-256 mismatch on staged file (expected ${expectedSha.slice(0, 12)}…, got ${sha256.slice(0, 12)}…) — purged staging before publish`
          );
          await failAndResetStaging('SHA-256 verification failed before publish');
        }
        this.appendRoutingLog('ok', 'SHA-256 verified before atomic publish');
      }

      const integrity = await verifyFileIntegrity(this.item.partPath, this.item.filename);
      this.item.integrity = integrity;
      if (integrity.status === 'html_trap' || integrity.status === 'corrupted') {
        this.appendRoutingLog(
          'danger',
          `Format verification rejected staging file (${integrity.status}: ${integrity.summary})`
        );
        await failAndResetStaging(integrity.summary || `File integrity check failed (${integrity.status})`);
      }

      if (this.cancelled || this.stopReason !== 'none') return;

      const publishDir = this.frozenDestinationDir || this.item.destinationDir;
      const published = await publishStagingFileAtomically(
        this.item.partPath,
        publishDir,
        sanitizeDerivedName(this.item.filename, this.secrets),
        { expectedIdentity: verifiedIdentity, physicalRootDir: publishDir }
      );
      this.item.filename = published.filename;
      this.item.savedPath = published.savedPath;
      try {
        await this.removeMetaSafe(this.item.partPath);
      } catch (metaErr) {
        // Payload already published; an orphan sidecar can never be paired with a new staging
        // file (pair reservation), but it must not go unreported.
        this.appendRoutingLog(
          'warn',
          `Published file, but checkpoint sidecar could not be removed (${sanitizeUpstreamError(metaErr, this.secrets, 160)})`
        );
      }

      const stat = await fs.stat(this.item.savedPath);
      this.item.totalBytes = stat.size;
      this.item.downloadedBytes = stat.size;
      this.item.completedAt = Date.now();
      const elapsedSec = Math.max(
        0.05,
        (this.item.completedAt - (this.item.startedAt ?? this.item.createdAt)) / 1000
      );
      this.item.avgSpeedBps = Math.round(stat.size / elapsedSec);
      this.item.speedBps = 0;
      this.item.etaSeconds = 0;
      this.item.status = 'completed';
      this.updateMirrorTelemetrySnapshot();
      this.onUpdate(this.item, true);
    })();

    this.finalizePromise = runFinalize;
    try {
      await runFinalize;
    } finally {
      if (this.finalizePromise === runFinalize) {
        this.finalizePromise = null;
      }
    }
  }

  private recomputeDownloadedTotal(): void {
    let total = 0;
    for (const seg of this.item.segments) {
      total += seg.downloaded;
    }
    this.item.downloadedBytes = total;
  }

  private startTelemetryTimer(): void {
    if (this.telemetryTimer) return;
    this.telemetryTimer = setInterval(() => {
      const now = Date.now();
      const dtSec = Math.max(0.05, (now - this.lastSampleTime) / 1000);
      this.recomputeDownloadedTotal();

      const deltaBytes = Math.max(0, this.item.downloadedBytes - this.lastSampleBytes);
      const instantSpeed = deltaBytes / dtSec;
      this.emaSpeedBps =
        this.emaSpeedBps === 0 ? instantSpeed : this.emaSpeedBps * 0.55 + instantSpeed * 0.45;
      this.item.speedBps = Math.round(this.emaSpeedBps);

      const instantDiskSpeed = this.diskWindowBytes / dtSec;
      this.diskEmaSpeedBps =
        this.diskEmaSpeedBps === 0
          ? instantDiskSpeed
          : this.diskEmaSpeedBps * 0.55 + instantDiskSpeed * 0.45;
      this.diskWindowBytes = 0;

      for (const seg of this.item.segments) {
        const prev = this.segLastSampleBytes.get(seg.id) ?? seg.downloaded;
        const segDelta = Math.max(0, seg.downloaded - prev);
        seg.speedBps = seg.status === 'active' ? Math.round(segDelta / dtSec) : 0;
        this.segLastSampleBytes.set(seg.id, seg.downloaded);
      }

      for (let mIdx = 0; mIdx < this.mirrorMetrics.length; mIdx++) {
        const m = this.mirrorMetrics[mIdx]!;
        const hasWorkers = this.item.segments.some(
          (s) => s.status === 'active' && (s.mirrorIndex ?? 0) === mIdx
        );
        const mDelta = Math.max(0, m.bytes - m.lastSampleBytes);
        if (hasWorkers || mDelta > 0) {
          m.samples.push({ t: now, bytes: m.bytes });
          const cutoff = now - this.speedWindowMs;
          while (m.samples.length > 2 && m.samples[0]!.t < cutoff) {
            m.samples.shift();
          }
          if (m.samples.length >= 2) {
            const oldest = m.samples[0]!;
            const winSec = Math.max(0.1, (now - oldest.t) / 1000);
            m.speedBps = Math.max(0, Math.round((m.bytes - oldest.bytes) / winSec));
          } else {
            m.speedBps = Math.round(mDelta / dtSec);
          }
          if (m.speedBps > 0) {
            m.lastActiveSpeedBps = m.speedBps;
          } else if (m.bytes > 0 && m.lastActiveSpeedBps === 0 && m.firstActiveAt !== null) {
            const totalElapsedSec = Math.max(0.05, (now - m.firstActiveAt) / 1000);
            m.lastActiveSpeedBps = Math.round(m.bytes / totalElapsedSec);
          }
        } else {
          m.speedBps = 0;
        }
        m.lastSampleBytes = m.bytes;
      }

      this.evaluateSpeedFloor(now);
      this.updateMirrorTelemetrySnapshot(now);
      this.throttleConstrainedWindow = false;

      if (this.item.totalBytes !== null && this.item.speedBps > 0) {
        const remaining = Math.max(0, this.item.totalBytes - this.item.downloadedBytes);
        this.item.etaSeconds = Math.ceil(remaining / this.item.speedBps);
      } else {
        this.item.etaSeconds = null;
      }

      this.lastSampleTime = now;
      this.lastSampleBytes = this.item.downloadedBytes;
      void this.persistPartMeta(false).catch(() => {
        // Fatal disk error is already triggered & recorded by persistPartMeta
      });
      this.onUpdate(this.item, false);
    }, 250);
  }

  private stopTelemetryTimer(): void {
    if (this.telemetryTimer) {
      clearInterval(this.telemetryTimer);
      this.telemetryTimer = null;
    }
  }
}

export async function computeFileHandleHashes(
  fh: fs.FileHandle
): Promise<{ sha256: string; md5: string; bytesRead: number }> {
  const sha256 = crypto.createHash('sha256');
  const md5 = crypto.createHash('md5');
  const buf = Buffer.allocUnsafe(256 * 1024);
  let offset = 0;
  while (true) {
    const { bytesRead } = await fh.read(buf, 0, buf.length, offset);
    if (bytesRead <= 0) break;
    const chunk = bytesRead === buf.length ? buf : buf.subarray(0, bytesRead);
    sha256.update(chunk);
    md5.update(chunk);
    offset += bytesRead;
  }
  return {
    sha256: sha256.digest('hex'),
    md5: md5.digest('hex'),
    bytesRead: offset,
  };
}

export async function computeFileHashes(
  filePath: string
): Promise<{ sha256: string; md5: string }> {
  return new Promise((resolve, reject) => {
    const sha256 = crypto.createHash('sha256');
    const md5 = crypto.createHash('md5');
    const stream = createReadStream(filePath, { highWaterMark: 256 * 1024 });
    stream.on('data', (chunk) => {
      sha256.update(chunk);
      md5.update(chunk);
    });
    stream.on('error', reject);
    stream.on('end', () =>
      resolve({
        sha256: sha256.digest('hex'),
        md5: md5.digest('hex'),
      })
    );
  });
}

export async function computeFileSha256(filePath: string): Promise<string> {
  const { sha256 } = await computeFileHashes(filePath);
  return sha256;
}

/** Derived names (filename / staging stem) never carry an active credential. */
function sanitizeDerivedName(name: string, secrets: readonly string[]): string {
  return redactText(name, secrets);
}

function firstStr(val?: string | string[]): string | undefined {
  if (Array.isArray(val)) return val[0];
  return val || undefined;
}

function parseStrictContentLength(header?: string | string[]): number | null {
  const val = firstStr(header);
  if (val === undefined) return null;
  const trimmed = val.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const n = Number(trimmed);
  return Number.isSafeInteger(n) && n >= 0 ? n : null;
}

function parseStrict206Range(
  header?: string | string[]
): { start: number; end: number; total: number | null } | null {
  const val = firstStr(header);
  if (!val) return null;
  const m = val.trim().match(/^bytes\s+(\d+)-(\d+)\/(\d+|\*)$/i);
  if (!m) return null;
  const start = Number(m[1]);
  const end = Number(m[2]);
  const total = m[3] === '*' ? null : Number(m[3]);
  if (
    !Number.isSafeInteger(start) ||
    !Number.isSafeInteger(end) ||
    start < 0 ||
    end < start ||
    (total !== null && (!Number.isSafeInteger(total) || end >= total))
  ) {
    return null;
  }
  return { start, end, total };
}

function formatSpeedShort(bps: number): string {
  if (bps < 1024) return `${Math.round(bps)} B/s`;
  const kbps = bps / 1024;
  if (kbps < 1024) return `${Math.round(kbps)} KB/s`;
  return `${(kbps / 1024).toFixed(1)} MB/s`;
}

async function fileExists(target: string): Promise<boolean> {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

function isAbortError(err: unknown): boolean {
  return (err as Error)?.name === 'AbortError';
}

function abortableDelay(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.reject(new DOMException('Aborted', 'AbortError'));
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException('Aborted', 'AbortError'));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal.addEventListener('abort', onAbort, { once: true });
  });
}
