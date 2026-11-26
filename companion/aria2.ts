import { type ChildProcess, execFile, spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { CURRENT_API_VERSION } from '../shared/compat.js';
import type { CompanionCapabilities, DownloadItem, TorrentFileEntry } from '../shared/types.js';
import { computeFileHashes } from '../server/engine.js';
import type { OriginRateLimiter } from '../server/rateLimit.js';
import {
  type FileIdentity,
  type PublishFsOps,
  assertPhysicalDirInside,
  captureFileIdentity,
  isPathInsideDir,
  publishStagingFileAtomically,
  sanitizeFilename,
} from '../server/utils.js';
import { selectAria2HttpSources } from '../server/validators.js';
import { verifyFileIntegrity } from '../server/verifier.js';
import {
  assertOutboundDestinationsSafe,
  redactSensitiveUrl,
  sanitizeUpstreamError,
} from './parser.js';
import { parseTorrentMetadata } from './torrentParser.js';

export const COMPANION_VERSION = '4.1.0';
export const ARIA2_OWNER_FILENAME = '.boltgate-owner.json';

export function getAria2InstallHint(platform: string = process.platform): {
  command: string;
  label: string;
  platform: string;
} {
  if (platform === 'win32') {
    return {
      command: 'winget install aria2.aria2',
      label: 'Windows (winget)',
      platform,
    };
  }
  if (platform === 'darwin') {
    return {
      command: 'brew install aria2',
      label: 'macOS (Homebrew)',
      platform,
    };
  }
  return {
    command: 'sudo apt install aria2',
    label: 'Linux (apt)',
    platform,
  };
}

/**
 * Safely probes whether `aria2c` is available on PATH without spawning a shell.
 */
export function detectAria2(
  binary = 'aria2c',
  argsPrefix: readonly string[] = []
): Promise<CompanionCapabilities> {
  const hint = getAria2InstallHint();
  const baseFeatures = {
    singleSourceValidatorLock: true,
    splitTelemetry: true,
    writeOnlySecrets: true,
    pairedSessionAuth: true,
  };
  return new Promise((resolve) => {
    execFile(
      binary,
      [...argsPrefix, '--version'],
      { shell: false, timeout: 3000 },
      (err, stdout) => {
        if (err) {
          resolve({
            aria2Available: false,
            platform: process.platform,
            companionVersion: COMPANION_VERSION,
            apiVersion: CURRENT_API_VERSION,
            requiresPairing: true,
            features: baseFeatures,
            installHint: hint,
          });
          return;
        }
        const firstLine = String(stdout ?? '').split(/\r?\n/)[0] ?? '';
        const verMatch = firstLine.match(/aria2 version\s+([^\s]+)/i);
        resolve({
          aria2Available: true,
          aria2Version: verMatch?.[1] ?? firstLine.trim(),
          aria2Path: binary,
          platform: process.platform,
          companionVersion: COMPANION_VERSION,
          apiVersion: CURRENT_API_VERSION,
          requiresPairing: true,
          features: baseFeatures,
          installHint: hint,
        });
      }
    );
  });
}

/**
 * Expands and validates a `selectFile` spec (e.g. `"1,3-4"` or empty for all files)
 * against a pinned torrent manifest.
 */
export function expandSelectFileIndices(
  selectFile: string | undefined,
  manifestFiles: readonly TorrentFileEntry[]
): TorrentFileEntry[] {
  if (manifestFiles.length === 0) {
    throw new Error('Pinned torrent manifest contains no files');
  }
  const trimmed = selectFile?.trim() ?? '';
  if (!trimmed) {
    return [...manifestFiles];
  }
  if (!/^[0-9,-]+$/.test(trimmed)) {
    throw new Error('Invalid selectFile specification (expected digits, commas, or hyphens)');
  }

  const byIndex = new Map<number, TorrentFileEntry>();
  for (const f of manifestFiles) {
    byIndex.set(f.index, f);
  }

  const chosen = new Map<number, TorrentFileEntry>();
  for (const part of trimmed.split(',')) {
    if (!part) throw new Error(`Invalid empty token in selectFile "${trimmed}"`);
    if (part.includes('-')) {
      const [startStr, endStr, extra] = part.split('-');
      if (!startStr || !endStr || extra !== undefined) {
        throw new Error(`Invalid range "${part}" in selectFile`);
      }
      const start = Number(startStr);
      const end = Number(endStr);
      if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end < start) {
        throw new Error(`Invalid index range "${part}" in selectFile`);
      }
      for (let i = start; i <= end; i++) {
        const entry = byIndex.get(i);
        if (!entry) {
          throw new Error(`Selected torrent file index #${i} does not exist in pinned manifest`);
        }
        chosen.set(i, entry);
      }
    } else {
      const idx = Number(part);
      if (!Number.isInteger(idx) || idx < 1) {
        throw new Error(`Invalid file index "${part}" in selectFile`);
      }
      const entry = byIndex.get(idx);
      if (!entry) {
        throw new Error(`Selected torrent file index #${idx} does not exist in pinned manifest`);
      }
      chosen.set(idx, entry);
    }
  }

  if (chosen.size === 0) {
    throw new Error('No torrent files selected');
  }
  return Array.from(chosen.values()).sort((a, b) => a.index - b.index);
}

export interface BuildAria2ArgsOptions {
  uris?: string[];
  torrentFilePath?: string;
  dir: string;
  out?: string;
  maxConnectionsPerServer?: number;
  split?: number;
  selectFile?: string;
  speedLimitKBps?: number;
  isP2P?: boolean;
  /**
   * Unproven HTTP identity (no trusted digest): one uninterrupted stream from offset 0 — no
   * resume of earlier partial bytes, no internal range retries that could mix versions.
   */
  singleUninterruptedStream?: boolean;
}

/**
 * Builds strict, injection-safe argument arrays for `aria2c` (always paired with `shell: false`).
 */
export function buildAria2Args(opts: BuildAria2ArgsOptions): string[] {
  const uris = opts.uris ?? [];
  const hasPinnedTorrent = Boolean(opts.torrentFilePath?.trim());

  if (!hasPinnedTorrent && uris.length === 0) {
    throw new Error('At least one URI or pinned torrent file is required for aria2c');
  }

  for (const uri of uris) {
    const trimmed = uri.trim();
    if (trimmed.startsWith('-')) {
      throw new Error(`Invalid URI rejected by injection guard: ${redactSensitiveUrl(trimmed)}`);
    }
    if (!/^(?:https?:\/\/|magnet:\?)/i.test(trimmed)) {
      throw new Error(`Unsupported URI scheme for aria2c: ${redactSensitiveUrl(trimmed)}`);
    }
  }

  let resolvedTorrentPath: string | undefined;
  if (hasPinnedTorrent) {
    resolvedTorrentPath = path.resolve(opts.torrentFilePath!.trim());
    if (
      path.basename(resolvedTorrentPath).startsWith('-') ||
      !resolvedTorrentPath.toLowerCase().endsWith('.torrent')
    ) {
      throw new Error('Invalid pinned torrent manifest path');
    }
  }

  if (opts.selectFile !== undefined && opts.selectFile.trim() !== '') {
    if (!/^[0-9,-]+$/.test(opts.selectFile.trim())) {
      throw new Error('Invalid selectFile specification (expected digits, commas, or hyphens)');
    }
  }

  const singleStream = Boolean(opts.singleUninterruptedStream) && !opts.isP2P;
  const maxConn = singleStream
    ? 1
    : Math.max(1, Math.min(16, Math.round(opts.maxConnectionsPerServer ?? 16)));
  const split = singleStream ? 1 : Math.max(1, Math.min(16, Math.round(opts.split ?? maxConn)));

  const args: string[] = [
    `--dir=${path.resolve(opts.dir)}`,
    '--summary-interval=1',
    '--console-log-level=notice',
    '--download-result=full',
    '--enable-color=false',
    '--file-allocation=trunc',
    `--continue=${singleStream ? 'false' : 'true'}`,
    '--allow-overwrite=false',
    '--auto-file-renaming=false',
    `--max-connection-per-server=${maxConn}`,
    `--split=${split}`,
    '--min-split-size=1M',
  ];
  if (singleStream) {
    // Never let aria2c silently resume/retry a ranged continuation of an unproven resource
    args.push('--max-tries=1', '--always-resume=false', '--max-resume-failure-tries=0');
  }

  if (opts.speedLimitKBps && opts.speedLimitKBps > 0) {
    args.push(`--max-overall-download-limit=${Math.round(opts.speedLimitKBps)}K`);
  }

  if (!opts.isP2P && opts.out?.trim()) {
    args.push(`--out=${sanitizeFilename(opts.out.trim())}`);
  }

  if (opts.isP2P) {
    args.push('--seed-time=0', '--bt-stop-timeout=120', '--follow-torrent=true');
    if (opts.selectFile?.trim()) {
      args.push(`--select-file=${opts.selectFile.trim()}`);
    }
  }

  if (resolvedTorrentPath) {
    args.push('--', resolvedTorrentPath);
  } else {
    args.push('--', ...uris.map((u) => u.trim()));
  }
  return args;
}

export function parseSizeToken(token: string): number {
  const m = token.trim().match(/^([\d.]+)\s*(GiB|MiB|KiB|GB|MB|KB|B)?$/i);
  if (!m?.[1]) return 0;
  const val = Number(m[1]);
  if (!Number.isFinite(val)) return 0;
  const unit = (m[2] ?? 'B').toLowerCase();
  if (unit === 'gib' || unit === 'gb') return Math.round(val * 1024 * 1024 * 1024);
  if (unit === 'mib' || unit === 'mb') return Math.round(val * 1024 * 1024);
  if (unit === 'kib' || unit === 'kb') return Math.round(val * 1024);
  return Math.round(val);
}

function parseEtaToken(token: string): number | null {
  let total = 0;
  let matched = false;
  const rx = /(\d+)(h|m|s)/gi;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(token)) !== null) {
    matched = true;
    const n = Number(m[1]);
    const u = m[2]?.toLowerCase();
    if (u === 'h') total += n * 3600;
    else if (u === 'm') total += n * 60;
    else total += n;
  }
  return matched ? total : null;
}

export interface Aria2RunnerOptions {
  item: DownloadItem;
  speedLimitKBps?: number;
  binary?: string;
  binaryArgsPrefix?: string[];
  /**
   * Rejected: raw plaintext `.torrent` manifest paths are never handed to aria2c. Supply
   * `readManifestBytes` (decrypting the vault-owned encrypted manifest) instead.
   */
  pinnedTorrentPath?: string;
  readManifestBytes?: () => Promise<Buffer>;
  /**
   * Private directory (inside the companion data dir) where the decrypted manifest is briefly
   * materialized for aria2c — never inside the user's download / staging folder.
   */
  manifestScratchDir?: string;
  publishFsOps?: PublishFsOps;
  /** Static secret list (tests). Prefer `secretsProvider` for long-lived runners. */
  secrets?: readonly string[];
  /** Live secret set read right before dispatch (survives key rotation). */
  secretsProvider?: () => readonly string[];
  /** Shared per-origin cooldowns, re-checked right before dispatching HTTP sources. */
  rateLimiter?: OriginRateLimiter;
  onUpdate: (item: DownloadItem, immediatePersist?: boolean) => void;
}

export interface Aria2ResultRecord {
  gid: string;
  /** aria2c status cell: OK, ERR, RM, INPR, AUTH, … */
  status: string;
  /** Per-file completion from the `%` column; null for `-` (zero-length file / no bitfield). */
  percent: number | null;
  path: string;
}

/**
 * Incremental parser for aria2c `--download-result=full` result tables:
 *
 *   gid   |stat|avg speed  |  %|path/URI
 *   ======+====+===========+===+=========
 *   2089b0|OK  |   1.4MiB/s|100|/dl/pack/a.bin
 *         |    |           |100|/dl/pack/b.bin      <- continuation row (inherits gid/status)
 *
 * Handles the `%` column, continuation rows, ANSI colors, and the default (no `%`) layout.
 */
export class Aria2ResultTableParser {
  private hasPercentColumn: boolean | null = null;
  private current: { gid: string; status: string } | null = null;
  readonly records: Aria2ResultRecord[] = [];

  feedLine(rawLine: string): void {
    const line = rawLine.replace(/\x1b\[[0-9;]*m/g, '').replace(/\r$/, '');
    const trimmed = line.trim();
    if (!trimmed) return;
    if (/^gid\s*\|\s*stat\s*\|/i.test(trimmed)) {
      this.hasPercentColumn = /\|\s*%\s*\|/.test(trimmed);
      this.current = null;
      return;
    }
    if (/^[=+]+$/.test(trimmed) || /^Status Legend:/i.test(trimmed) || /^\([A-Z]+\):/.test(trimmed)) {
      if (/^Status Legend:/i.test(trimmed)) this.current = null;
      return;
    }
    const cells = line.split('|');
    if (cells.length < 4) return;
    const gidCell = cells[0]!.trim();
    const statCell = cells[1]!.trim();

    let percentLayout = this.hasPercentColumn;
    if (percentLayout === null) {
      percentLayout = cells.length >= 5 && /^(?:\d{1,3}|-)$/.test(cells[3]!.trim());
    }
    const pathIdx = percentLayout ? 4 : 3;
    if (cells.length <= pathIdx) return;

    let gid = gidCell;
    let status = statCell;
    if (!gidCell && !statCell) {
      // Continuation row: inherits the head row's download
      if (!this.current) return;
      gid = this.current.gid;
      status = this.current.status;
    } else {
      if (!/^[0-9a-f]{1,16}$/i.test(gidCell) || !/^[A-Z]{2,4}$/.test(statCell)) return;
      this.current = { gid, status };
    }

    let percent: number | null = null;
    if (percentLayout) {
      const pc = cells[3]!.trim();
      if (pc !== '-') {
        if (!/^\d{1,3}$/.test(pc)) return;
        percent = Number(pc);
      }
    } else if (status === 'OK') {
      percent = 100;
    }
    const reportedPath = cells.slice(pathIdx).join('|').trim();
    if (!reportedPath || reportedPath === 'n/a') return;
    this.records.push({ gid, status, percent, path: reportedPath });
  }

  /** Paths aria2c reported as fully completed (status OK and 100% or zero-length `-`). */
  completedPaths(): string[] {
    const out: string[] = [];
    for (const r of this.records) {
      if (r.status !== 'OK') continue;
      if (r.percent !== null && r.percent !== 100) continue;
      if (r.path.startsWith('[MEMORY]') || /^[a-z][a-z0-9+.-]*:/i.test(r.path) && !/^[a-z]:[\\/]/i.test(r.path)) {
        continue;
      }
      if (!out.includes(r.path)) out.push(r.path);
    }
    return out;
  }
}

interface ResolvedTarget {
  stagedPath: string;
  desiredFilename: string;
  relativePath: string;
  /** 1-based manifest index when resolved from a pinned manifest. */
  manifestIndex?: number;
}

interface PublishJournalEntry {
  relativePath: string;
  targetDir: string;
  stagedPath: string;
  state: 'pending' | 'published';
  savedPath?: string;
  /** Physical identity of the published file (decimal strings; bigint-safe). */
  dev?: string;
  ino?: string;
  size?: string;
}

interface PublishJournal {
  version: 1;
  jobId: string;
  createdDirs: string[];
  entries: PublishJournalEntry[];
}

const PUBLISH_JOURNAL_FILENAME = '.boltgate-publish-journal.json';

class StopSignal extends Error {
  constructor() {
    super('stopped');
    this.name = 'StopSignal';
  }
}

/**
 * Manages an isolated `aria2c` staging job with serialized lifecycle, single completion promise,
 * verified encrypted torrent manifests, live outbound credential guard (top-level + embedded
 * trackers / web seeds), digest-to-file identity binding, journaled multi-file publication with
 * verified rollback, strict completed-file resolution, and single-source HTTP identity enforcement.
 */
export class Aria2Runner {
  public readonly item: DownloadItem;
  private readonly speedLimitKBps: number;
  private readonly binary: string;
  private readonly binaryArgsPrefix: string[];
  private readonly rejectedPlaintextManifestPath?: string;
  private readonly readManifestBytes?: () => Promise<Buffer>;
  private readonly manifestScratchDir?: string;
  private readonly publishFsOps?: PublishFsOps;
  private readonly staticSecrets: readonly string[];
  private readonly secretsProvider?: () => readonly string[];
  private readonly rateLimiter?: OriginRateLimiter;
  private readonly onUpdate: (item: DownloadItem, immediatePersist?: boolean) => void;
  private child: ChildProcess | null = null;
  private stopReason: 'none' | 'paused' | 'cancelled' = 'none';
  private cancelled = false;
  private phase: 'idle' | 'setup' | 'transfer' | 'verify' = 'idle';
  private abortController = new AbortController();
  private stagingDir: string | null = null;
  private runPromise: Promise<void> | null = null;
  private resultParser = new Aria2ResultTableParser();
  private authoritativeTotalBytes: number | null = null;
  private tempManifestPath: string | null = null;

  constructor(options: Aria2RunnerOptions) {
    this.item = options.item;
    this.speedLimitKBps = options.speedLimitKBps ?? 0;
    this.binary = options.binary ?? 'aria2c';
    this.binaryArgsPrefix = options.binaryArgsPrefix ?? [];
    this.rejectedPlaintextManifestPath = options.pinnedTorrentPath;
    this.readManifestBytes = options.readManifestBytes;
    this.manifestScratchDir = options.manifestScratchDir;
    this.publishFsOps = options.publishFsOps;
    this.staticSecrets = options.secrets ?? [];
    this.secretsProvider = options.secretsProvider;
    this.rateLimiter = options.rateLimiter;
    this.onUpdate = options.onUpdate;
  }

  /** The live secret set at the moment of use. */
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

  private getStopReason(): 'none' | 'paused' | 'cancelled' {
    return this.stopReason;
  }

  private throwIfStopped(): void {
    if (this.cancelled || this.stopReason !== 'none') throw new StopSignal();
  }

  private log(level: 'info' | 'ok' | 'warn' | 'danger', message: string): void {
    this.item.routingLog = this.item.routingLog ?? [];
    this.item.routingLog.push({
      timestamp: Date.now(),
      level,
      message: sanitizeUpstreamError(message, this.secrets, 360),
    });
    if (this.item.routingLog.length > 60) this.item.routingLog = this.item.routingLog.slice(-60);
  }

  private async ensureOwnedStagingDir(destDir: string): Promise<string> {
    if (this.stagingDir) return this.stagingDir;
    await fs.mkdir(destDir, { recursive: true });

    if (this.item.partPath && path.basename(this.item.partPath).startsWith('.boltgate-aria2-')) {
      const ownerPath = path.join(this.item.partPath, ARIA2_OWNER_FILENAME);
      try {
        const raw = JSON.parse(await fs.readFile(ownerPath, 'utf8')) as { jobId?: string };
        if (raw.jobId === this.item.id) {
          this.stagingDir = this.item.partPath;
          return this.stagingDir;
        }
      } catch {
        // Not owned by this job -> allocate fresh isolated staging dir
      }
    }

    const safeJobId = this.item.id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 16) || 'job';
    for (let i = 0; i < 100; i++) {
      const suffix = i === 0 ? '' : `-${i}`;
      const candidate = path.join(destDir, `.boltgate-aria2-${safeJobId}${suffix}`);
      try {
        await fs.mkdir(candidate);
        await fs.writeFile(
          path.join(candidate, ARIA2_OWNER_FILENAME),
          JSON.stringify({ jobId: this.item.id, createdAt: Date.now() }),
          'utf8'
        );
        this.stagingDir = candidate;
        this.item.partPath = candidate;
        return candidate;
      } catch (err) {
        if ((err as NodeJS.ErrnoException)?.code === 'EEXIST') continue;
        throw err;
      }
    }
    throw new Error('Could not reserve isolated aria2c staging directory');
  }

  run(): Promise<void> {
    if (this.runPromise) return this.runPromise;
    const p = (async () => {
      try {
        await this.runInternal();
      } finally {
        await this.removeTempManifest();
        if (this.stopReason === 'cancelled') {
          await this.cleanupAfterCancel();
        }
      }
    })().finally(() => {
      if (this.runPromise === p) {
        this.runPromise = null;
      }
    });
    this.runPromise = p;
    return p;
  }

  private deleteOnCancel = true;

  private async cleanupAfterCancel(): Promise<void> {
    if (this.deleteOnCancel && this.stagingDir) {
      await fs.rm(this.stagingDir, { recursive: true, force: true }).catch(() => undefined);
      this.stagingDir = null;
    }
  }

  private async removeTempManifest(): Promise<void> {
    const p = this.tempManifestPath;
    if (!p) return;
    this.tempManifestPath = null;
    await fs.unlink(p).catch((err: NodeJS.ErrnoException) => {
      if (err?.code !== 'ENOENT') {
        this.log('warn', 'Temporary decrypted manifest could not be removed immediately; retrying');
        return new Promise<void>((resolve) =>
          setTimeout(() => {
            void fs.unlink(p).catch(() => undefined).finally(resolve);
          }, 200)
        );
      }
      return undefined;
    });
  }

  /** Centralized terminal transition to `paused`. */
  private settlePaused(): void {
    this.item.status = 'paused';
    this.item.speedBps = 0;
    this.item.etaSeconds = null;
    this.onUpdate(this.item, true);
  }

  /** Centralized terminal transition to `failed`. */
  private settleFailed(err: unknown): void {
    this.item.status = 'failed';
    this.item.speedBps = 0;
    this.item.etaSeconds = null;
    this.item.error = sanitizeUpstreamError(err, this.secrets, 320);
    this.onUpdate(this.item, true);
  }

  private async purgeStagingForRetry(): Promise<void> {
    if (this.stagingDir) {
      await fs.rm(this.stagingDir, { recursive: true, force: true }).catch(() => undefined);
      this.stagingDir = null;
    }
    this.item.downloadedBytes = 0;
    this.item.segments = [];
  }

  private async runInternal(): Promise<void> {
    // Cancellation is sticky: a cancelled runner never (re)starts.
    if (this.cancelled || this.stopReason === 'cancelled') return;
    this.stopReason = 'none';
    this.phase = 'setup';
    this.abortController = new AbortController();
    this.resultParser = new Aria2ResultTableParser();
    this.authoritativeTotalBytes = this.item.totalBytes;
    // Freeze approval inputs at execution start so concurrent updates cannot mutate verification contract
    const frozenExpectedMd5 = this.item.expectedMd5;
    const frozenExpectedSha256 = this.item.expectedSha256;
    const frozenDestDir = this.item.destinationDir;
    const frozenSelectFile = this.item.selectFile;

    this.item.status = 'downloading';
    this.item.error = undefined;
    if (!this.item.startedAt) this.item.startedAt = Date.now();
    this.item.routingLog = this.item.routingLog ?? [];

    const isTorrent = Boolean(this.item.torrentUrl);
    const isMagnet = Boolean(this.item.magnetUri);
    const isP2P = isTorrent || isMagnet;
    const requestedConnections = Math.max(1, Math.min(16, Math.round(this.item.connections || 4)));
    const hasTrustedDigest = Boolean(frozenExpectedMd5 || frozenExpectedSha256);

    try {
      let selectedManifestFiles: TorrentFileEntry[] | null = null;
      let manifestRootName = this.item.torrentRootName;
      let manifestBytes: Buffer | null = null;
      let embeddedDestinations: string[] = [];

      if (isTorrent) {
        if (this.rejectedPlaintextManifestPath && !this.readManifestBytes) {
          throw new Error(
            'Refusing raw plaintext .torrent manifest path; only encrypted vault manifests are accepted — re-inspect the torrent'
          );
        }
        if (!this.readManifestBytes || !this.item.torrentInfoHash) {
          throw new Error(
            'Pinned .torrent manifest is missing — re-inspect the torrent in Safety Gate before downloading'
          );
        }
        manifestBytes = await this.readManifestBytes();
        const parsed = parseTorrentMetadata(manifestBytes);
        if (parsed.infoHash.toLowerCase() !== this.item.torrentInfoHash.toLowerCase()) {
          throw new Error(
            `Pinned .torrent infoHash mismatch (expected ${this.item.torrentInfoHash}, got ${parsed.infoHash})`
          );
        }
        manifestRootName = parsed.name;
        this.item.torrentRootName = parsed.name;
        this.item.torrentFiles = parsed.files;
        embeddedDestinations = parsed.outboundUrls;
        selectedManifestFiles = expandSelectFileIndices(frozenSelectFile, parsed.files);
      } else if (this.item.torrentFiles && this.item.torrentFiles.length > 0) {
        selectedManifestFiles = expandSelectFileIndices(frozenSelectFile, this.item.torrentFiles);
      }

      this.throwIfStopped();

      const stagingDir = await this.ensureOwnedStagingDir(frozenDestDir);
      this.throwIfStopped();

      // Recover (roll back) any interrupted earlier publication before touching staging
      await this.recoverPublishJournal(stagingDir);

      const uris = isTorrent
        ? undefined
        : isMagnet
          ? [this.item.magnetUri!]
          : selectAria2HttpSources({
              finalUrl: this.item.finalUrl,
              mirrorUrls: this.item.mirrorUrls,
              expectedMd5: frozenExpectedMd5,
              expectedSha256: frozenExpectedSha256,
            });

      // Unproven HTTP identity (aria2c cannot enforce ETags per range): single uninterrupted
      // stream from offset 0 — purge any earlier partial output so nothing is resumed.
      const singleUninterruptedStream = !isP2P && !hasTrustedDigest;
      if (singleUninterruptedStream) {
        const outName = sanitizeFilename(this.item.filename);
        await fs.rm(path.join(stagingDir, outName), { force: true }).catch(() => undefined);
        await fs.rm(path.join(stagingDir, `${outName}.aria2`), { force: true }).catch(() => undefined);
      }

      const buildArgs = (torrentFilePath?: string) =>
        buildAria2Args({
          uris,
          torrentFilePath,
          dir: stagingDir,
          out: isP2P ? undefined : this.item.filename,
          maxConnectionsPerServer: requestedConnections,
          split: requestedConnections,
          selectFile: frozenSelectFile,
          speedLimitKBps: this.speedLimitKBps,
          isP2P,
          singleUninterruptedStream,
        });
      // Validate argument safety up-front (before any manifest is materialized)
      buildArgs(isTorrent ? path.join(stagingDir, 'validate-only.torrent') : undefined);

      this.item.sourceMode = isP2P ? 'aria2_p2p' : 'aria2_http';
      this.item.sourceBadge = isP2P
        ? 'aria2c P2P'
        : `aria2c (${uris!.length} source${uris!.length > 1 ? 's' : ''})`;
      this.log(
        'info',
        isTorrent
          ? `Handed pinned .torrent (infoHash ${this.item.torrentInfoHash!.slice(0, 12)}…, ${selectedManifestFiles?.length ?? 1} file(s)) to aria2c`
          : isMagnet
            ? `Handed magnet transfer to aria2c (${requestedConnections} connections, isolated staging)`
            : singleUninterruptedStream
              ? 'Handed 1 HTTP source to aria2c as a single uninterrupted stream (identity unproven: no resume / split)'
              : `Handed ${uris!.length} HTTP source(s) to aria2c (${requestedConnections} connection(s)/server, isolated staging)`
      );
      this.onUpdate(this.item, true);

      // Re-check shared origin cooldowns RIGHT before dispatch (honors concurrent Retry-After)
      if (uris && !isP2P && this.rateLimiter) {
        await this.rateLimiter.waitForCooldowns(uris, this.abortController.signal);
      }
      this.throwIfStopped();

      // Outbound credential guard against the LIVE secret set, immediately before spawn: top-level
      // URIs AND every embedded tracker / web-seed destination aria2c would contact on its own.
      assertOutboundDestinationsSafe(uris ?? [], embeddedDestinations, this.secrets);

      // Materialize the decrypted manifest as late as possible (private scratch dir, 0600)
      const args = buildArgs(
        isTorrent && manifestBytes ? await this.materializeManifest(manifestBytes, stagingDir) : undefined
      );
      this.throwIfStopped();

      this.phase = 'transfer';
      await this.spawnAndMonitor(args);
      await this.removeTempManifest();

      this.throwIfStopped();

      this.phase = 'verify';
      this.item.status = 'verifying';
      this.item.speedBps = 0;
      this.onUpdate(this.item, false);

      // Resolve ONLY verified manifest entries or aria2c's explicitly reported OK selected files
      const resolvedFiles = await this.resolveExactTargetFiles(
        stagingDir,
        isP2P,
        selectedManifestFiles,
        manifestRootName
      );
      if (resolvedFiles.length === 0) {
        throw new Error('aria2c finished, but no expected output files were found in staging directory');
      }

      // Verify digests AND format integrity across ALL resolved files BEFORE publishing ANY file!
      const singleFileMode = resolvedFiles.length === 1;
      const expectedMd5Norm = frozenExpectedMd5?.trim().toLowerCase();
      const expectedShaNorm = frozenExpectedSha256?.trim().toLowerCase();
      const verified: Array<{
        target: ResolvedTarget;
        identity: FileIdentity;
        sha256: string;
        md5: string;
        integrity: Awaited<ReturnType<typeof verifyFileIntegrity>>;
      }> = [];
      let matchedDigestIdx = -1;

      for (const target of resolvedFiles) {
        this.throwIfStopped();
        const identity = await captureFileIdentity(target.stagedPath);
        const { sha256, md5 } = await computeFileHashes(target.stagedPath);
        const integrity = await verifyFileIntegrity(target.stagedPath, target.desiredFilename);
        verified.push({ target, identity, sha256, md5, integrity });

        const md5Ok = !expectedMd5Norm || md5.toLowerCase() === expectedMd5Norm;
        const shaOk = !expectedShaNorm || sha256.toLowerCase() === expectedShaNorm;
        if ((expectedMd5Norm || expectedShaNorm) && md5Ok && shaOk && matchedDigestIdx === -1) {
          matchedDigestIdx = verified.length - 1;
        }

        if (integrity.status === 'html_trap' || integrity.status === 'corrupted') {
          this.item.integrity = integrity;
          await this.purgeStagingForRetry();
          throw new Error(
            integrity.summary || `File integrity check failed on ${target.desiredFilename} (${integrity.status})`
          );
        }
      }

      // A job-level digest is applied ONLY to a resolved file that actually matched it, and that
      // exact file (manifest index / relative path) becomes the job's displayed/opened/re-verified file.
      if (expectedMd5Norm || expectedShaNorm) {
        if (matchedDigestIdx === -1) {
          if (expectedMd5Norm) this.item.md5Verified = false;
          if (expectedShaNorm) this.item.verifiedHashMatch = false;
          await this.purgeStagingForRetry();
          throw new Error(
            singleFileMode
              ? expectedMd5Norm
                ? `MD5 verification failed (expected ${expectedMd5Norm}, got ${verified[0]!.md5})`
                : 'SHA-256 verification failed before publish'
              : 'Multi-file P2P digest check failed: none of the selected files matched the expected checksum'
          );
        }
      }
      const boundIdx = matchedDigestIdx !== -1 ? matchedDigestIdx : 0;
      const bound = verified[boundIdx]!;

      this.throwIfStopped();

      // Publish EVERY requested file with a durable journal + verified rollback, retaining
      // stagingDir until the whole batch succeeded.
      const multiRoot = singleFileMode
        ? null
        : path.join(frozenDestDir, sanitizeFilename(manifestRootName || this.item.filename || 'torrent-files'));
      const published = await this.publishBatch(stagingDir, frozenDestDir, multiRoot, verified);

      // Only remove stagingDir AFTER EVERY requested file has been verified and published!
      await fs.rm(stagingDir, { recursive: true, force: true }).catch(() => undefined);
      this.stagingDir = null;

      const boundPublished = published[boundIdx]!;
      this.item.publishedFiles = published.map((p) => p.savedPath);
      this.item.savedPath = boundPublished.savedPath;
      if (singleFileMode) this.item.filename = boundPublished.filename;
      this.item.verifiedFilePath = bound.target.relativePath;
      this.item.verifiedFileIndex = bound.target.manifestIndex;
      this.item.sha256 = bound.sha256;
      this.item.md5 = bound.md5;
      this.item.integrity = bound.integrity;
      if (expectedMd5Norm) this.item.md5Verified = true;
      if (expectedShaNorm) this.item.verifiedHashMatch = true;
      const totalPublishedBytes = published.reduce((sum, p) => sum + p.size, 0);
      this.item.totalBytes = totalPublishedBytes;
      this.item.downloadedBytes = totalPublishedBytes;
      this.item.completedAt = Date.now();
      const elapsedSec = Math.max(
        0.05,
        (this.item.completedAt - (this.item.startedAt ?? this.item.createdAt)) / 1000
      );
      this.item.avgSpeedBps = Math.round(totalPublishedBytes / elapsedSec);
      this.item.etaSeconds = 0;
      this.item.status = 'completed';
      this.phase = 'idle';
      this.onUpdate(this.item, true);
    } catch (err) {
      await this.removeTempManifest();
      this.phase = 'idle';
      const stopOnErr = this.getStopReason();
      if (stopOnErr === 'cancelled' || this.cancelled) return;
      if (stopOnErr === 'paused' && (err instanceof StopSignal || isAbortError(err))) {
        this.settlePaused();
        return;
      }
      if (err instanceof StopSignal) {
        this.settlePaused();
        return;
      }
      this.settleFailed(err);
    }
  }

  /**
   * Materializes the decrypted manifest for aria2c in a private data-dir scratch location
   * (0600, exclusive create) — never in the user's download folder. It is removed as soon as
   * aria2c has parsed it (first output) and unconditionally in the lifecycle `finally`.
   */
  private async materializeManifest(bytes: Buffer, stagingDir: string): Promise<string> {
    const dir = this.manifestScratchDir ?? stagingDir;
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    const safeId = this.item.id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 16) || 'job';
    const target = path.join(
      dir,
      `.boltgate-pinned-${safeId}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.torrent`
    );
    this.tempManifestPath = target;
    await fs.writeFile(target, bytes, { mode: 0o600, flag: 'wx' });
    return target;
  }

  async pause(): Promise<void> {
    if (this.stopReason !== 'none') return;
    if (this.phase === 'verify') {
      // Verification/publication is not interruptible mid-batch: wait for its terminal state
      if (this.runPromise) await this.runPromise.catch(() => undefined);
      return;
    }
    this.stopReason = 'paused';
    this.abortController.abort();
    this.child?.kill('SIGTERM');
    if (this.runPromise) {
      await this.runPromise.catch(() => undefined);
    }
  }

  async cancel(deletePartFile = true): Promise<void> {
    this.cancelled = true;
    this.stopReason = 'cancelled';
    this.deleteOnCancel = deletePartFile;
    this.abortController.abort();
    this.child?.kill('SIGKILL');
    if (this.runPromise) {
      await this.runPromise.catch(() => undefined);
    } else {
      await this.cleanupAfterCancel();
    }
  }

  private spawnAndMonitor(args: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.cancelled || this.stopReason !== 'none') {
        resolve();
        return;
      }
      const child = spawn(this.binary, [...this.binaryArgsPrefix, ...args], {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      this.child = child;
      let lastStderr = '';
      let sawOutput = false;
      const pending: Record<'out' | 'err', string> = { out: '', err: '' };

      const handleText = (stream: 'out' | 'err', text: string, flush = false) => {
        if (!sawOutput) {
          sawOutput = true;
          // aria2c has parsed its inputs: drop the decrypted manifest from disk right away
          void this.removeTempManifest();
        }
        const combined = pending[stream] + text;
        const lines = combined.split(/\r?\n/);
        pending[stream] = flush ? '' : (lines.pop() ?? '');
        for (const line of lines) {
          if (!line.trim()) continue;
          this.parseProgressLine(line);
        }
      };

      child.stdout?.on('data', (chunk: Buffer) => handleText('out', chunk.toString('utf8')));
      child.stderr?.on('data', (chunk: Buffer) => {
        const text = chunk.toString('utf8');
        lastStderr = text.trim() || lastStderr;
        handleText('err', text);
      });

      child.on('error', (err) => {
        this.child = null;
        reject(new Error(`Failed to launch aria2c: ${sanitizeUpstreamError(err, this.secrets)}`));
      });

      child.on('close', (code) => {
        this.child = null;
        handleText('out', '\n', true);
        handleText('err', '\n', true);
        if (this.stopReason !== 'none' || code === 0) {
          resolve();
        } else {
          reject(
            new Error(
              lastStderr
                ? sanitizeUpstreamError(lastStderr, this.secrets)
                : `aria2c exited with code ${code}`
            )
          );
        }
      });
    });
  }

  private parseProgressLine(line: string): void {
    const progMatch = line.match(
      /\[#[^\s]+\s+([\d.]+[KMGT]?i?B)\/([\d.]+[KMGT]?i?B)\((\d+)%\)(?:.*?CN:(\d+))?(?:.*?SD:(\d+))?.*?DL:([\d.]+[KMGT]?i?B)(?:.*?ETA:([^\]]+))?\]/i
    );
    if (progMatch) {
      const displayDownloaded = parseSizeToken(progMatch[1]!);
      const displayTotal = parseSizeToken(progMatch[2]!);
      const cn = progMatch[4] ? Number(progMatch[4]) : 0;
      const sd = progMatch[5] ? Number(progMatch[5]) : 0;
      const speedBps = parseSizeToken(progMatch[6]!);
      const etaSeconds = progMatch[7] ? parseEtaToken(progMatch[7]) : null;

      // Rounded CLI tokens are DISPLAY-ONLY: never mutate authoritative totalBytes, and never let
      // the displayed progress exceed the authoritative size.
      const authoritative = this.authoritativeTotalBytes;
      this.item.downloadedBytes =
        authoritative !== null ? Math.min(displayDownloaded, authoritative) : displayDownloaded;
      this.item.speedBps = speedBps;
      this.item.etaSeconds = etaSeconds;
      const workers = Math.max(1, cn);
      const configuredCapBps = this.speedLimitKBps * 1024;
      const observedLocalThrottle = configuredCapBps > 0 && speedBps >= configuredCapBps * 0.9;
      this.item.telemetry = {
        networkSpeedBps: speedBps,
        diskSpeedBps: 0,
        committedBytes: this.item.downloadedBytes,
        receivedBytes: displayDownloaded,
        throttledByLocalCap: observedLocalThrottle,
        configuredLocalCapBps: configuredCapBps,
        localCapBps: configuredCapBps,
        serverThrottled: false,
        backingOffHosts: [],
        activeWorkers: workers,
        displayTotalBytes: displayTotal,
      };
      this.item.mirrorTelemetry = [
        {
          url: redactSensitiveUrl(
            this.item.magnetUri ?? this.item.torrentUrl ?? this.item.finalUrl,
            this.secrets
          ),
          label: sd > 0 ? `aria2c P2P (${sd} seeds)` : 'aria2c Engine',
          host: 'aria2c',
          tier: this.item.magnetUri || this.item.torrentUrl ? 'p2p' : 'mirror',
          status: 'active',
          speedBps,
          downloadedBytes: this.item.downloadedBytes,
          activeWorkers: workers,
          failures: 0,
        },
      ];
      this.onUpdate(this.item, false);
      return;
    }

    // `--download-result=full` table rows (incl. `%` column and continuation rows)
    this.resultParser.feedLine(line);
  }

  /** Exposed for diagnostics/tests: completed paths parsed from aria2c's result table. */
  getReportedCompletedPaths(): string[] {
    return this.resultParser.completedPaths();
  }

  private async resolveExactTargetFiles(
    stagingDir: string,
    isP2P: boolean,
    selectedManifestFiles: TorrentFileEntry[] | null,
    manifestRootName?: string
  ): Promise<ResolvedTarget[]> {
    const resolvedStaging = path.resolve(stagingDir);

    // 1. Pinned torrent manifest: resolve EVERY selected file strictly by manifest path & EXACT length
    if (selectedManifestFiles && selectedManifestFiles.length > 0) {
      const results: ResolvedTarget[] = [];
      const isMultiFile = (this.item.torrentFiles?.length ?? 0) > 1;
      for (const entry of selectedManifestFiles) {
        const candidates: string[] = [];
        if (isMultiFile && manifestRootName) {
          candidates.push(path.resolve(resolvedStaging, manifestRootName, entry.path));
        }
        candidates.push(path.resolve(resolvedStaging, entry.path));

        let matchedPath: string | null = null;
        for (const cand of candidates) {
          if (!isPathInsideDir(cand, resolvedStaging)) continue;
          try {
            const st = await fs.lstat(cand);
            if (st.isSymbolicLink() || !st.isFile()) continue;
            // Exact size check for EVERY entry, including zero-byte manifest entries
            if (st.size !== entry.length) {
              throw new Error(
                `Staged torrent file "${entry.path}" size mismatch (${st.size} vs expected ${entry.length} bytes)`
              );
            }
            matchedPath = cand;
            break;
          } catch (err) {
            if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') continue;
            throw err;
          }
        }

        if (!matchedPath && entry.length === 0) {
          // aria2c may not materialize empty files: synthesize the exact (empty) manifest entry
          const synthPath = candidates.find((c) => isPathInsideDir(c, resolvedStaging));
          if (synthPath) {
            await fs.mkdir(path.dirname(synthPath), { recursive: true });
            await fs.writeFile(synthPath, Buffer.alloc(0), { flag: 'wx' }).catch((err) => {
              if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') throw err;
            });
            const st = await fs.lstat(synthPath);
            if (st.isFile() && !st.isSymbolicLink() && st.size === 0) matchedPath = synthPath;
          }
        }

        if (!matchedPath) {
          throw new Error(
            `Expected selected torrent file #${entry.index} ("${entry.path}") was not produced by aria2c`
          );
        }

        results.push({
          stagedPath: matchedPath,
          desiredFilename: sanitizeFilename(path.basename(entry.path)),
          relativePath: entry.path,
          manifestIndex: entry.index,
        });
      }
      return results;
    }

    // 2. Non-P2P HTTP download: resolve exact expected --out filename only (no blind fallback!)
    if (!isP2P) {
      const expectedName = sanitizeFilename(this.item.filename);
      const directOut = path.resolve(resolvedStaging, expectedName);
      if (!isPathInsideDir(directOut, resolvedStaging)) {
        throw new Error('Invalid staged HTTP output path');
      }
      const stat = await fs.lstat(directOut).catch(() => null);
      if (!stat || !stat.isFile() || stat.isSymbolicLink()) {
        throw new Error(`Expected staged output file "${expectedName}" was not produced by aria2c`);
      }
      // Compare ONLY against authoritative probed totalBytes (never rounded CLI display tokens)
      if (this.authoritativeTotalBytes !== null && stat.size !== this.authoritativeTotalBytes) {
        throw new Error(
          `Staged aria2c HTTP file size mismatch (${stat.size} vs expected ${this.authoritativeTotalBytes} bytes)`
        );
      }
      return [{ stagedPath: directOut, desiredFilename: expectedName, relativePath: expectedName }];
    }

    // 3. Unmanifested magnet link: publish ONLY files aria2c's result table reported as fully
    // completed (status OK, 100% / zero-length) inside stagingDir — never scan arbitrary files.
    const verifiedReported: ResolvedTarget[] = [];
    const seenPaths = new Set<string>();
    for (const reported of this.resultParser.completedPaths()) {
      const candidate = path.isAbsolute(reported)
        ? path.resolve(reported)
        : path.resolve(resolvedStaging, reported);
      if (!isPathInsideDir(candidate, resolvedStaging)) continue;
      if (seenPaths.has(candidate)) continue;
      const base = path.basename(candidate);
      const lower = base.toLowerCase();
      if (
        base === ARIA2_OWNER_FILENAME ||
        base === PUBLISH_JOURNAL_FILENAME ||
        lower.endsWith('.aria2') ||
        lower.endsWith('.torrent') ||
        lower.startsWith('.boltgate-')
      ) {
        continue;
      }
      const st = await fs.lstat(candidate).catch(() => null);
      if (!st || !st.isFile() || st.isSymbolicLink()) continue;
      seenPaths.add(candidate);
      const rel = path.relative(resolvedStaging, candidate).replace(/\\/g, '/');
      verifiedReported.push({
        stagedPath: candidate,
        desiredFilename: sanitizeFilename(base),
        relativePath: rel,
      });
    }

    if (verifiedReported.length === 0) {
      throw new Error(
        'aria2c magnet transfer did not report any verified completed payload files in staging'
      );
    }
    return verifiedReported;
  }

  private journalPath(stagingDir: string): string {
    return path.join(stagingDir, PUBLISH_JOURNAL_FILENAME);
  }

  private async writeJournal(stagingDir: string, journal: PublishJournal): Promise<void> {
    const target = this.journalPath(stagingDir);
    const tmp = `${target}.${process.pid}.${Date.now()}.tmp`;
    const fh = await fs.open(tmp, 'w', 0o600);
    try {
      await fh.writeFile(JSON.stringify(journal), 'utf8');
      await fh.datasync();
    } finally {
      await fh.close().catch(() => undefined);
    }
    await fs.rename(tmp, target);
  }

  /**
   * Publishes every verified file with a durable journal entry written BEFORE each link and
   * updated after it. On any failure, every already-published file (and every directory this
   * batch created, deepest first) is rolled back — but only when its physical identity still
   * matches what we published. Any rollback failure is surfaced, the journal + staging are kept
   * for recovery, and leftover outputs stay tracked in `publishedFiles`.
   */
  private async publishBatch(
    stagingDir: string,
    destRoot: string,
    multiRoot: string | null,
    verified: Array<{ target: ResolvedTarget; identity: FileIdentity }>
  ): Promise<Array<{ savedPath: string; filename: string; size: number }>> {
    const journal: PublishJournal = { version: 1, jobId: this.item.id, createdDirs: [], entries: [] };
    await this.writeJournal(stagingDir, journal);
    const results: Array<{ savedPath: string; filename: string; size: number }> = [];

    try {
      for (const { target, identity } of verified) {
        const relDir = multiRoot ? path.dirname(target.relativePath) : '.';
        const targetDir = multiRoot
          ? relDir && relDir !== '.'
            ? path.resolve(multiRoot, relDir)
            : multiRoot
          : destRoot;
        if (!isPathInsideDir(targetDir, destRoot)) {
          throw new Error(`Unsafe destination subpath rejected: ${target.relativePath}`);
        }
        // Physically validate existing components, then create (and journal) missing ones
        await assertPhysicalDirInside(targetDir, destRoot);
        await this.createDirsTracked(destRoot, targetDir, journal, stagingDir);

        const entry: PublishJournalEntry = {
          relativePath: target.relativePath,
          targetDir,
          stagedPath: target.stagedPath,
          state: 'pending',
        };
        journal.entries.push(entry);
        await this.writeJournal(stagingDir, journal);

        const pub = await publishStagingFileAtomically(target.stagedPath, targetDir, target.desiredFilename, {
          ...this.publishFsOps,
          preserveStaging: true,
          expectedIdentity: identity,
          physicalRootDir: destRoot,
        });
        const pubIdentity = await captureFileIdentity(pub.savedPath);
        entry.state = 'published';
        entry.savedPath = pub.savedPath;
        entry.dev = pubIdentity.dev.toString();
        entry.ino = pubIdentity.ino.toString();
        entry.size = pubIdentity.size.toString();
        await this.writeJournal(stagingDir, journal);
        results.push({ savedPath: pub.savedPath, filename: pub.filename, size: Number(pubIdentity.size) });
      }
    } catch (pubErr) {
      const failures = await this.rollbackJournal(journal);
      if (failures.length > 0) {
        // Keep journal + staging for recovery; keep leftovers tracked (never untracked outputs)
        this.item.publishedFiles = journal.entries
          .filter((e) => e.state === 'published' && e.savedPath)
          .map((e) => e.savedPath!);
        await this.writeJournal(stagingDir, journal).catch(() => undefined);
        throw new Error(
          `${sanitizeUpstreamError(pubErr, this.secrets, 160)}; batch rollback INCOMPLETE (${failures.length} item(s) could not be removed: ${failures
            .map((f) => sanitizeUpstreamError(f, this.secrets, 80))
            .join('; ')}) — staging and publish journal preserved for recovery`
        );
      }
      await fs.unlink(this.journalPath(stagingDir)).catch(() => undefined);
      this.item.publishedFiles = undefined;
      throw pubErr;
    }

    await fs.unlink(this.journalPath(stagingDir)).catch(() => undefined);
    return results;
  }

  private async createDirsTracked(
    destRoot: string,
    targetDir: string,
    journal: PublishJournal,
    stagingDir: string
  ): Promise<void> {
    const rel = path.relative(path.resolve(destRoot), path.resolve(targetDir));
    if (!rel) {
      await fs.mkdir(destRoot, { recursive: true });
      return;
    }
    let cursor = path.resolve(destRoot);
    for (const part of rel.split(path.sep)) {
      cursor = path.join(cursor, part);
      try {
        await fs.mkdir(cursor);
        journal.createdDirs.push(cursor);
        await this.writeJournal(stagingDir, journal);
      } catch (err) {
        if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') throw err;
        const st = await fs.lstat(cursor);
        if (st.isSymbolicLink() || !st.isDirectory()) {
          throw new Error(`Refusing to publish through symlink/junction or non-directory "${part}"`);
        }
      }
    }
  }

  /** Rolls back a publish journal; returns the list of failures (empty when fully rolled back). */
  private async rollbackJournal(journal: PublishJournal): Promise<string[]> {
    const failures: string[] = [];
    for (const entry of [...journal.entries].reverse()) {
      if (entry.state !== 'published' || !entry.savedPath) continue;
      try {
        const st = await fs.lstat(entry.savedPath, { bigint: true });
        if (
          st.isSymbolicLink() ||
          st.dev.toString() !== entry.dev ||
          st.ino.toString() !== entry.ino ||
          st.size.toString() !== entry.size
        ) {
          failures.push(`${path.basename(entry.savedPath)} was replaced after publication`);
          continue;
        }
        await (this.publishFsOps?.unlink ?? fs.unlink)(entry.savedPath);
        entry.state = 'pending';
        entry.savedPath = undefined;
      } catch (err) {
        if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') {
          entry.state = 'pending';
          entry.savedPath = undefined;
          continue;
        }
        failures.push(`${path.basename(entry.savedPath!)}: ${(err as Error)?.message ?? 'unlink failed'}`);
      }
    }
    // Remove directories this batch created, deepest first (only if now empty)
    for (const dir of [...journal.createdDirs].sort((a, b) => b.length - a.length)) {
      try {
        await fs.rmdir(dir);
        journal.createdDirs = journal.createdDirs.filter((d) => d !== dir);
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        if (code === 'ENOENT') {
          journal.createdDirs = journal.createdDirs.filter((d) => d !== dir);
          continue;
        }
        if (code === 'ENOTEMPTY' || code === 'EEXIST') {
          // Holds files we do not own (or a rolled-back failure) — leave it, it is not ours alone
          if (journal.entries.some((e) => e.state === 'published' && e.savedPath?.startsWith(dir))) {
            failures.push(`${path.basename(dir)}/ still contains published output`);
          }
          continue;
        }
        failures.push(`${path.basename(dir)}/: ${(err as Error)?.message ?? 'rmdir failed'}`);
      }
    }
    return failures;
  }

  /** Recovers a publish journal left by an interrupted earlier run (rolls the partial batch back). */
  private async recoverPublishJournal(stagingDir: string): Promise<void> {
    let journal: PublishJournal;
    try {
      journal = JSON.parse(await fs.readFile(this.journalPath(stagingDir), 'utf8')) as PublishJournal;
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') return;
      throw new Error('Publish journal from an earlier run is unreadable; refusing to continue');
    }
    if (journal.jobId !== this.item.id || !Array.isArray(journal.entries)) {
      throw new Error('Publish journal in staging does not belong to this job');
    }
    journal.createdDirs = Array.isArray(journal.createdDirs) ? journal.createdDirs : [];
    const failures = await this.rollbackJournal(journal);
    if (failures.length > 0) {
      await this.writeJournal(stagingDir, journal).catch(() => undefined);
      throw new Error(`Could not recover interrupted batch publication: ${failures.join('; ')}`);
    }
    await fs.unlink(this.journalPath(stagingDir)).catch(() => undefined);
    this.log('warn', 'Rolled back an interrupted multi-file publication from an earlier run');
  }
}

function isAbortError(err: unknown): boolean {
  return (err as Error)?.name === 'AbortError';
}
