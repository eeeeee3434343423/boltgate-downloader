import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import type http from 'node:http';
import path from 'node:path';
import type {
  AppSettings,
  AppStateSnapshot,
  AppStats,
  DiskSpaceInfo,
  DownloadItem,
  FileIntegrityReport,
  MirrorProbeSummary,
  RiskLevel,
  SSEEvent,
  SpeedPreset,
  TrustRule,
} from '../shared/types.js';
import { DownloadRunner, computeFileSha256 } from './engine.js';
import { probeUrl } from './inspector.js';
import { StateStore } from './store.js';
import { TokenBucketThrottle } from './throttle.js';
import {
  classifyFile,
  extractUrlsFromText,
  normalizeDomainRuleInput,
  normalizeHostname,
  resolveUniquePath,
  sanitizeFilename,
} from './utils.js';
import { verifyFileIntegrity } from './verifier.js';

export interface ManagerOptions {
  dataDir?: string;
  minSegmentBytes?: number;
  stallTimeoutMs?: number;
}

const SPEED_PRESETS: Record<
  Exclude<SpeedPreset, 'custom'>,
  Pick<
    AppSettings,
    'maxConcurrentDownloads' | 'maxConcurrentPerHost' | 'segmentsPerDownload' | 'speedLimitKBps'
  >
> = {
  balanced: {
    maxConcurrentDownloads: 3,
    maxConcurrentPerHost: 2,
    segmentsPerDownload: 8,
    speedLimitKBps: 0,
  },
  turbo: {
    maxConcurrentDownloads: 4,
    maxConcurrentPerHost: 4,
    segmentsPerDownload: 16,
    speedLimitKBps: 0,
  },
  books: {
    maxConcurrentDownloads: 3,
    maxConcurrentPerHost: 1,
    segmentsPerDownload: 4,
    speedLimitKBps: 0,
  },
  background: {
    maxConcurrentDownloads: 2,
    maxConcurrentPerHost: 1,
    segmentsPerDownload: 4,
    speedLimitKBps: 2048,
  },
};

export class DownloadManager {
  public readonly store: StateStore;
  public readonly throttle: TokenBucketThrottle;
  private readonly minSegmentBytes?: number;
  private readonly stallTimeoutMs?: number;

  private downloads: DownloadItem[] = [];
  private settings!: AppSettings;
  private trustRules: TrustRule[] = [];
  private diskSpace: DiskSpaceInfo = { path: '', freeBytes: 0, totalBytes: 0 };
  private speedHistory: number[] = Array(60).fill(0);

  private runners = new Map<string, DownloadRunner>();
  private sseClients = new Set<http.ServerResponse>();
  private telemetryTick: NodeJS.Timeout | null = null;
  private lastPersistAt = 0;

  constructor(options: ManagerOptions = {}) {
    this.store = new StateStore(options.dataDir);
    this.throttle = new TokenBucketThrottle(0);
    this.minSegmentBytes = options.minSegmentBytes;
    this.stallTimeoutMs = options.stallTimeoutMs;
  }

  async init(): Promise<void> {
    const loaded = await this.store.load();
    this.downloads = loaded.downloads;
    this.settings = loaded.settings;
    this.trustRules = loaded.trustRules;
    this.throttle.setLimitKBps(this.settings.speedLimitKBps);
    await this.refreshDiskSpace();
  }

  async shutdown(): Promise<void> {
    if (this.telemetryTick) {
      clearInterval(this.telemetryTick);
      this.telemetryTick = null;
    }
    const pausePromises = Array.from(this.runners.values()).map((r) => r.pause());
    await Promise.allSettled(pausePromises);
    // Wait briefly for active run loops to settle into paused state
    for (let i = 0; i < 20 && this.runners.size > 0; i++) {
      await new Promise((r) => setTimeout(r, 50));
    }
    this.persistImmediate();
    await this.store.flush();
    for (const res of this.sseClients) {
      res.end();
    }
    this.sseClients.clear();
  }

  getSnapshot(): AppStateSnapshot {
    return {
      downloads: this.downloads,
      settings: this.settings,
      trustRules: this.trustRules,
      speedHistory: this.speedHistory,
      stats: this.computeStats(),
      diskSpace: this.diskSpace,
    };
  }

  addSseClient(res: http.ServerResponse): void {
    this.sseClients.add(res);
    this.sendEvent(res, { type: 'snapshot', data: this.getSnapshot() });
    res.on('close', () => {
      this.sseClients.delete(res);
    });
  }

  async refreshDiskSpace(): Promise<DiskSpaceInfo> {
    const target = this.settings.downloadDir;
    try {
      await fs.mkdir(target, { recursive: true });
      const stats = await fs.statfs(target);
      this.diskSpace = {
        path: target,
        freeBytes: Number(stats.bavail) * Number(stats.bsize),
        totalBytes: Number(stats.blocks) * Number(stats.bsize),
      };
    } catch {
      this.diskSpace = { path: target, freeBytes: 0, totalBytes: 0 };
    }
    return this.diskSpace;
  }

  async inspectRawText(
    rawText: string,
    destinationDir?: string
  ): Promise<{ items: DownloadItem[]; rejectedTokens: string[] }> {
    const { urls, rejectedTokens } = extractUrlsFromText(rawText);
    if (urls.length === 0) {
      return { items: [], rejectedTokens };
    }

    const baseDest = destinationDir?.trim()
      ? path.resolve(destinationDir.trim())
      : this.settings.downloadDir;

    const created: DownloadItem[] = [];
    for (const url of urls) {
      const parsed = new URL(url);
      const roughName = sanitizeFilename(
        decodeURIComponentSafe(parsed.pathname.split('/').filter(Boolean).pop() ?? '') ||
          parsed.hostname ||
          'download'
      );
      const id = crypto.randomUUID();
      const item: DownloadItem = {
        id,
        originalUrl: url,
        finalUrl: url,
        filename: roughName,
        destinationDir: baseDest,
        savedPath: path.join(baseDest, roughName),
        partPath: path.join(baseDest, `${roughName}.boltpart`),
        category: classifyFile(roughName).category,
        status: 'probing',
        priority: this.nextPriority(),
        totalBytes: null,
        downloadedBytes: 0,
        speedBps: 0,
        avgSpeedBps: 0,
        etaSeconds: null,
        connections: this.settings.segmentsPerDownload,
        supportsRanges: false,
        segments: [],
        safety: null,
        createdAt: Date.now(),
        userDeemedSafe: false,
      };
      this.downloads.unshift(item);
      created.push(item);
      this.broadcast({ type: 'download_updated', data: item });
    }

    this.persistImmediate();

    // Launch probes concurrently without blocking API response if desired,
    // OR await them for deterministic REST callers. Wait: inspecting 1-5 URLs in parallel is very fast locally!
    // Wait: let's kick off probes and await if <= 10 URLs? Actually, returning immediately while SSE updates
    // makes bulk paste feel instant, AND we can expose awaitProbe or let tests wait on status/SSE —
    // wait: if inspectRawText returns after kicking off, UI immediately shows geometry-matched probing skeletons!
    // Let's launch probes immediately in background AND return the probing items.
    for (const item of created) {
      void this.runProbeForItem(item, destinationDir);
    }

    return { items: created, rejectedTokens };
  }

  async inspectMirrorGroup(
    rawText: string,
    destinationDir?: string
  ): Promise<{ items: DownloadItem[]; rejectedTokens: string[] }> {
    const { urls, rejectedTokens } = extractUrlsFromText(rawText);
    if (urls.length < 2) {
      return this.inspectRawText(rawText, destinationDir);
    }

    const baseDest = destinationDir?.trim()
      ? path.resolve(destinationDir.trim())
      : this.settings.downloadDir;

    const primaryUrl = urls[0]!;
    const parsed = new URL(primaryUrl);
    const roughName = sanitizeFilename(
      decodeURIComponentSafe(parsed.pathname.split('/').filter(Boolean).pop() ?? '') ||
        parsed.hostname ||
        'download'
    );

    const item: DownloadItem = {
      id: crypto.randomUUID(),
      originalUrl: primaryUrl,
      finalUrl: primaryUrl,
      mirrorUrls: urls,
      filename: roughName,
      destinationDir: baseDest,
      savedPath: path.join(baseDest, roughName),
      partPath: path.join(baseDest, `${roughName}.boltpart`),
      category: classifyFile(roughName).category,
      status: 'probing',
      priority: this.nextPriority(),
      totalBytes: null,
      downloadedBytes: 0,
      speedBps: 0,
      avgSpeedBps: 0,
      etaSeconds: null,
      connections: Math.min(16, Math.max(this.settings.segmentsPerDownload, urls.length * 4)),
      supportsRanges: false,
      segments: [],
      safety: null,
      createdAt: Date.now(),
      userDeemedSafe: false,
    };

    this.downloads.unshift(item);
    this.broadcast({ type: 'download_updated', data: item });
    this.persistImmediate();

    void this.runMirrorGroupProbe(item, urls, destinationDir);
    return { items: [item], rejectedTokens };
  }

  private async runMirrorGroupProbe(
    item: DownloadItem,
    mirrorUrls: string[],
    customDest?: string
  ): Promise<void> {
    await this.refreshDiskSpace();
    const existing = this.downloads.filter((d) => d.id !== item.id);
    const reports = await Promise.all(
      mirrorUrls.map((u) =>
        probeUrl(u, {
          trustRules: this.trustRules,
          existingDownloads: existing,
          freeBytes: this.diskSpace.freeBytes || undefined,
        })
      )
    );

    const current = this.downloads.find((d) => d.id === item.id);
    if (!current) return;

    const primary =
      reports.find(
        (r) =>
          !r.probeError &&
          (r.statusCode ?? 500) < 400 &&
          r.supportsRanges &&
          r.totalBytes !== null &&
          r.domainTrust !== 'blocked'
      ) ??
      reports.find((r) => !r.probeError && (r.statusCode ?? 500) < 400) ??
      reports[0]!;

    const mirrorReports: MirrorProbeSummary[] = [];
    const includedUrls: string[] = [];
    const seenFinal = new Set<string>();
    const includedReports = [primary];

    for (let i = 0; i < reports.length; i++) {
      const r = reports[i]!;
      const rawUrl = mirrorUrls[i]!;
      let included = true;
      let excludeReason: string | undefined;

      if (r.probeError || (r.statusCode ?? 500) >= 400) {
        included = false;
        excludeReason = r.probeError ?? `HTTP ${r.statusCode}`;
      } else if (r.domainTrust === 'blocked') {
        included = false;
        excludeReason = 'Blocked domain';
      } else if (!primary.supportsRanges || primary.totalBytes === null) {
        included = r === primary;
        if (!included) excludeReason = 'Primary mirror does not support byte ranges or size';
      } else if (!r.supportsRanges) {
        included = false;
        excludeReason = 'No byte-range support';
      } else if (r.totalBytes === null || r.totalBytes !== primary.totalBytes) {
        included = false;
        excludeReason = `Size mismatch (${r.totalBytes ?? 'unknown'} vs ${primary.totalBytes} bytes)`;
      } else if (seenFinal.has(r.finalUrl)) {
        included = false;
        excludeReason = 'Duplicate mirror endpoint';
      }

      if (included) {
        seenFinal.add(r.finalUrl);
        includedUrls.push(r.finalUrl);
        if (r !== primary) includedReports.push(r);
      }

      mirrorReports.push({
        url: rawUrl,
        finalUrl: r.finalUrl,
        host: r.finalHost,
        statusCode: r.statusCode,
        totalBytes: r.totalBytes,
        supportsRanges: r.supportsRanges,
        riskLevel: r.riskLevel,
        included,
        excludeReason,
      });
    }

    const signals = [...primary.signals];
    if (includedUrls.length >= 2) {
      signals.unshift({
        id: 'multi_mirror',
        level: 'ok',
        title: `Multi-Mirror Striped Ready (${includedUrls.length} mirrors)`,
        detail: `Verified identical ${primary.totalBytes?.toLocaleString()} byte size and Range support across ${includedUrls.length} mirrors.`,
      });
    }
    const excludedMirrors = mirrorReports.filter((m) => !m.included);
    if (excludedMirrors.length > 0) {
      signals.push({
        id: 'mirror_excluded',
        level: 'warn',
        title: `${excludedMirrors.length} Mirror(s) Excluded`,
        detail: excludedMirrors
          .map((m) => `${m.host}: ${m.excludeReason ?? 'incompatible'}`)
          .join('; '),
      });
    }

    const riskOrder: Record<RiskLevel, number> = {
      safe: 0,
      caution: 1,
      high_risk: 2,
      error: 3,
    };
    let worstRisk = primary.riskLevel;
    for (const ir of includedReports) {
      if (riskOrder[ir.riskLevel] > riskOrder[worstRisk]) {
        worstRisk = ir.riskLevel;
      }
    }

    current.safety = {
      ...primary,
      riskLevel: worstRisk,
      signals,
      mirrorReports,
    };
    current.finalUrl = primary.finalUrl;
    current.mirrorUrls = includedUrls.length > 0 ? includedUrls : [primary.finalUrl];
    current.filename = primary.suggestedFilename;
    current.category = primary.category;
    current.totalBytes = primary.totalBytes;
    current.supportsRanges = primary.supportsRanges;
    current.etag = primary.etag;
    current.lastModified = primary.lastModified;
    current.connections =
      current.mirrorUrls.length >= 2
        ? Math.min(16, Math.max(this.settings.segmentsPerDownload, current.mirrorUrls.length * 4))
        : this.settings.segmentsPerDownload;

    const effectiveDest = customDest?.trim()
      ? path.resolve(customDest.trim())
      : this.settings.organizeByCategory
        ? path.join(this.settings.downloadDir, primary.category)
        : this.settings.downloadDir;

    current.destinationDir = effectiveDest;
    const unique = await resolveUniquePath(effectiveDest, current.filename);
    current.filename = unique.filename;
    current.savedPath = unique.savedPath;
    current.partPath = unique.partPath;
    current.status = 'pending_review';

    this.broadcast({ type: 'download_updated', data: current });
    this.persistImmediate();
  }

  private async runProbeForItem(item: DownloadItem, customDest?: string): Promise<void> {
    await this.refreshDiskSpace();
    const report = await probeUrl(item.originalUrl, {
      trustRules: this.trustRules,
      existingDownloads: this.downloads.filter((d) => d.id !== item.id),
      freeBytes: this.diskSpace.freeBytes || undefined,
    });

    // Item might have been removed while probing
    const current = this.downloads.find((d) => d.id === item.id);
    if (!current) return;

    current.safety = report;
    current.finalUrl = report.finalUrl;
    current.filename = report.suggestedFilename;
    current.category = report.category;
    current.totalBytes = report.totalBytes;
    current.supportsRanges = report.supportsRanges;
    current.etag = report.etag;
    current.lastModified = report.lastModified;

    const effectiveDest = customDest?.trim()
      ? path.resolve(customDest.trim())
      : this.settings.organizeByCategory
        ? path.join(this.settings.downloadDir, report.category)
        : this.settings.downloadDir;

    current.destinationDir = effectiveDest;
    const unique = await resolveUniquePath(effectiveDest, current.filename);
    current.filename = unique.filename;
    current.savedPath = unique.savedPath;
    current.partPath = unique.partPath;

    if (
      this.settings.autoApproveTrusted &&
      report.domainTrust === 'trusted' &&
      report.riskLevel === 'safe'
    ) {
      current.userDeemedSafe = true;
      current.approvedAt = Date.now();
      current.status = 'queued';
      this.broadcast({ type: 'download_updated', data: current });
      this.persistImmediate();
      this.scheduleQueue();
      return;
    }

    current.status = 'pending_review';
    this.broadcast({ type: 'download_updated', data: current });
    this.persistImmediate();
  }

  async reprobeDownload(id: string): Promise<DownloadItem> {
    const item = this.requireItem(id);
    if (this.runners.has(id)) {
      throw new Error('Cannot re-inspect an actively running download');
    }
    item.status = 'probing';
    item.error = undefined;
    this.broadcast({ type: 'download_updated', data: item });
    await this.runProbeForItem(item, item.destinationDir);
    return item;
  }

  async approveDownload(
    id: string,
    opts: {
      filename?: string;
      destinationDir?: string;
      connections?: number;
      trustDomain?: boolean;
      startNow?: boolean;
    } = {}
  ): Promise<DownloadItem> {
    const item = this.requireItem(id);
    if (item.status === 'completed' || item.status === 'downloading') {
      return item;
    }

    if (opts.destinationDir?.trim()) {
      item.destinationDir = path.resolve(opts.destinationDir.trim());
    }
    if (opts.filename?.trim()) {
      item.filename = sanitizeFilename(opts.filename.trim(), item.safety?.extension);
      item.category = classifyFile(item.filename, item.safety?.contentType).category;
    }
    if (typeof opts.connections === 'number' && Number.isFinite(opts.connections)) {
      item.connections = Math.max(1, Math.min(16, Math.round(opts.connections)));
    }

    const unique = await resolveUniquePath(item.destinationDir, item.filename);
    item.filename = unique.filename;
    item.savedPath = unique.savedPath;
    item.partPath = unique.partPath;

    if (opts.trustDomain && item.safety?.finalHost) {
      await this.upsertTrustRule({
        domain: item.safety.finalHost,
        status: 'trusted',
        note: 'Trusted from Safety Gate',
      });
    }

    item.userDeemedSafe = true;
    item.approvedAt = Date.now();
    item.error = undefined;
    item.status = 'queued';

    if (opts.startNow) {
      const minPrio = this.downloads.reduce((m, d) => Math.min(m, d.priority), 0);
      item.priority = minPrio - 1;
      this.broadcast({ type: 'download_updated', data: item });
      this.persistImmediate();
      this.startRunner(item);
      return item;
    }

    this.broadcast({ type: 'download_updated', data: item });
    this.persistImmediate();
    this.scheduleQueue();
    return item;
  }

  async approveBatch(
    ids: string[],
    trustDomains = false
  ): Promise<DownloadItem[]> {
    const approved: DownloadItem[] = [];
    for (const id of ids) {
      const item = this.downloads.find((d) => d.id === id);
      if (!item || item.status !== 'pending_review') continue;
      approved.push(await this.approveDownload(id, { trustDomain: trustDomains }));
    }
    return approved;
  }

  async rejectDownload(id: string, blockDomain = false): Promise<{ id: string }> {
    const item = this.requireItem(id);
    if (blockDomain && item.safety?.finalHost) {
      await this.upsertTrustRule({
        domain: item.safety.finalHost,
        status: 'blocked',
        note: 'Blocked from Safety Gate',
      });
    }
    return this.removeDownload(id, true);
  }

  async pauseDownload(id: string): Promise<DownloadItem> {
    const item = this.requireItem(id);
    const runner = this.runners.get(id);
    if (runner) {
      await runner.pause();
      // Wait for runner loop to settle into paused
      for (let i = 0; i < 40 && this.runners.has(id); i++) {
        await new Promise((r) => setTimeout(r, 25));
      }
    } else if (item.status === 'queued') {
      item.status = 'paused';
      item.speedBps = 0;
      item.etaSeconds = null;
      this.broadcast({ type: 'download_updated', data: item });
      this.persistImmediate();
    }
    this.scheduleQueue();
    return item;
  }

  async resumeDownload(id: string, startNow = false): Promise<DownloadItem> {
    const item = this.requireItem(id);
    if (!item.userDeemedSafe) {
      throw new Error('Download must be reviewed and deemed safe before starting');
    }
    if (item.status === 'downloading' || item.status === 'completed') {
      return item;
    }

    if (item.status === 'failed' && !item.supportsRanges) {
      item.segments = [];
      item.downloadedBytes = 0;
    }
    item.error = undefined;
    item.status = 'queued';

    if (startNow) {
      const minPrio = this.downloads.reduce((m, d) => Math.min(m, d.priority), 0);
      item.priority = minPrio - 1;
      this.broadcast({ type: 'download_updated', data: item });
      this.persistImmediate();
      this.startRunner(item);
      return item;
    }

    this.broadcast({ type: 'download_updated', data: item });
    this.persistImmediate();
    this.scheduleQueue();
    return item;
  }

  reorderPriority(id: string, action: 'top' | 'up' | 'down'): DownloadItem {
    const item = this.requireItem(id);
    const ordered = this.downloads
      .filter((d) => d.status === 'queued' || d.status === 'paused')
      .sort((a, b) => a.priority - b.priority);

    const idx = ordered.findIndex((d) => d.id === id);
    if (idx === -1) return item;

    if (action === 'top') {
      const min = ordered[0]?.priority ?? 0;
      item.priority = min - 1;
    } else if (action === 'up' && idx > 0) {
      const prev = ordered[idx - 1]!;
      const tmp = prev.priority;
      prev.priority = item.priority;
      item.priority = tmp;
      if (prev.priority === item.priority) {
        item.priority -= 1;
      }
      this.broadcast({ type: 'download_updated', data: prev });
    } else if (action === 'down' && idx < ordered.length - 1) {
      const next = ordered[idx + 1]!;
      const tmp = next.priority;
      next.priority = item.priority;
      item.priority = tmp;
      if (next.priority === item.priority) {
        item.priority += 1;
      }
      this.broadcast({ type: 'download_updated', data: next });
    }

    this.broadcast({ type: 'download_updated', data: item });
    this.persistImmediate();
    return item;
  }

  async removeDownload(id: string, deleteFile = false): Promise<{ id: string; undoable: boolean }> {
    const idx = this.downloads.findIndex((d) => d.id === id);
    if (idx === -1) {
      throw new Error('Download not found');
    }
    const item = this.downloads[idx]!;
    const runner = this.runners.get(id);
    if (runner) {
      await runner.cancel(deleteFile);
      this.runners.delete(id);
    }

    if (deleteFile) {
      await fs.unlink(item.partPath).catch(() => {});
      if (item.status === 'completed') {
        await fs.unlink(item.savedPath).catch(() => {});
      }
    } else {
      this.store.stashDeletedItem(item);
    }

    this.downloads.splice(idx, 1);
    this.broadcast({ type: 'download_removed', data: { id } });
    this.persistImmediate();
    this.scheduleQueue();
    return { id, undoable: !deleteFile };
  }

  restoreDownload(id: string): DownloadItem {
    const restored = this.store.takeDeletedItem(id);
    if (!restored) {
      throw new Error('Undo window expired or item not found');
    }
    if (restored.status === 'downloading' || restored.status === 'verifying') {
      restored.status = 'paused';
      restored.speedBps = 0;
    }
    this.downloads.unshift(restored);
    this.broadcast({ type: 'download_updated', data: restored });
    this.persistImmediate();
    return restored;
  }

  async bulkAction(
    action: 'pauseAll' | 'resumeAll' | 'retryFailed' | 'clearCompleted'
  ): Promise<{ count: number; undoToken?: string }> {
    if (action === 'pauseAll') {
      const targets = this.downloads.filter(
        (d) => d.status === 'downloading' || d.status === 'queued'
      );
      for (const item of targets) {
        await this.pauseDownload(item.id);
      }
      return { count: targets.length };
    }

    if (action === 'resumeAll') {
      const targets = this.downloads.filter((d) => d.status === 'paused' && d.userDeemedSafe);
      for (const item of targets) {
        item.status = 'queued';
        item.error = undefined;
        this.broadcast({ type: 'download_updated', data: item });
      }
      this.persistImmediate();
      this.scheduleQueue();
      return { count: targets.length };
    }

    if (action === 'retryFailed') {
      const targets = this.downloads.filter((d) => d.status === 'failed' && d.userDeemedSafe);
      for (const item of targets) {
        if (!item.supportsRanges) {
          item.segments = [];
          item.downloadedBytes = 0;
        }
        item.error = undefined;
        item.status = 'queued';
        this.broadcast({ type: 'download_updated', data: item });
      }
      this.persistImmediate();
      this.scheduleQueue();
      return { count: targets.length };
    }

    // clearCompleted
    const completed = this.downloads.filter((d) => d.status === 'completed');
    if (completed.length === 0) return { count: 0 };

    const undoToken = crypto.randomUUID();
    this.store.stashDeletedBatch(undoToken, completed);
    const removeIds = new Set(completed.map((d) => d.id));
    this.downloads = this.downloads.filter((d) => !removeIds.has(d.id));
    for (const id of removeIds) {
      this.broadcast({ type: 'download_removed', data: { id } });
    }
    this.persistImmediate();
    return { count: completed.length, undoToken };
  }

  restoreBatch(token: string): DownloadItem[] {
    const restored = this.store.takeDeletedBatch(token);
    if (!restored) {
      throw new Error('Undo window expired');
    }
    this.downloads = [...restored, ...this.downloads];
    for (const item of restored) {
      this.broadcast({ type: 'download_updated', data: item });
    }
    this.persistImmediate();
    return restored;
  }

  async verifyHash(
    id: string,
    expectedSha256: string
  ): Promise<{ match: boolean; actual: string; expected: string }> {
    const item = this.requireItem(id);
    if (item.status !== 'completed') {
      throw new Error('Hash verification is available only after download completes');
    }
    const normalized = expectedSha256.trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(normalized)) {
      throw new Error('Expected SHA-256 must be a 64-character hexadecimal digest');
    }

    const actual = item.sha256 ?? (await computeFileSha256(item.savedPath));
    item.sha256 = actual;
    const match = actual.toLowerCase() === normalized;
    item.verifiedHashMatch = match;
    this.broadcast({ type: 'download_updated', data: item });
    this.persistImmediate();
    return { match, actual, expected: normalized };
  }

  async verifyIntegrity(id: string): Promise<FileIntegrityReport> {
    const item = this.requireItem(id);
    if (item.status !== 'completed') {
      throw new Error('Integrity verification is available only after download completes');
    }
    const integrity = await verifyFileIntegrity(item.savedPath, item.filename);
    item.integrity = integrity;
    this.broadcast({ type: 'download_updated', data: item });
    this.persistImmediate();
    return integrity;
  }

  async openInFolder(id: string): Promise<void> {
    const item = this.requireItem(id);
    const targetPath =
      item.status === 'completed'
        ? item.savedPath
        : (await fileExists(item.partPath))
          ? item.partPath
          : item.destinationDir;

    const resolved = path.resolve(targetPath);
    if (process.platform === 'win32') {
      const exists = await fileExists(resolved);
      const args = exists && targetPath !== item.destinationDir ? [`/select,${resolved}`] : [item.destinationDir];
      const child = spawn('explorer.exe', args, {
        detached: true,
        stdio: 'ignore',
        shell: false,
      });
      child.unref();
      return;
    }
    const cmd = process.platform === 'darwin' ? 'open' : 'xdg-open';
    const child = spawn(cmd, [path.dirname(resolved)], {
      detached: true,
      stdio: 'ignore',
      shell: false,
    });
    child.unref();
  }

  async openFile(id: string): Promise<void> {
    const item = this.requireItem(id);
    if (item.status !== 'completed') {
      throw new Error('File can only be opened after completion');
    }
    const check = classifyFile(item.savedPath);
    if (check.isExecutable || item.safety?.isExecutable) {
      throw new Error(
        'For your protection, BoltGate never launches executable files directly. Use "Show in Folder" instead.'
      );
    }
    const resolved = path.resolve(item.savedPath);
    if (!(await fileExists(resolved))) {
      throw new Error('File no longer exists at its saved location');
    }
    if (process.platform === 'win32') {
      const child = spawn('rundll32.exe', ['url.dll,FileProtocolHandler', resolved], {
        detached: true,
        stdio: 'ignore',
        shell: false,
      });
      child.unref();
      return;
    }
    const cmd = process.platform === 'darwin' ? 'open' : 'xdg-open';
    const child = spawn(cmd, [resolved], {
      detached: true,
      stdio: 'ignore',
      shell: false,
    });
    child.unref();
  }

  async upsertTrustRule(input: {
    domain: string;
    status: 'trusted' | 'blocked';
    note?: string;
  }): Promise<TrustRule[]> {
    const domain = normalizeDomainRuleInput(input.domain);
    if (!domain) {
      throw new Error('Invalid domain name');
    }
    const existing = this.trustRules.find((r) => r.domain === domain);
    if (existing) {
      existing.status = input.status;
      if (input.note !== undefined) existing.note = input.note.trim();
    } else {
      this.trustRules.unshift({
        domain,
        status: input.status,
        note: (input.note ?? '').trim(),
        createdAt: Date.now(),
      });
    }
    this.broadcast({ type: 'trust_updated', data: this.trustRules });
    this.persistImmediate();
    return this.trustRules;
  }

  async deleteTrustRule(domainInput: string): Promise<TrustRule[]> {
    const domain = normalizeDomainRuleInput(domainInput) ?? domainInput.toLowerCase();
    this.trustRules = this.trustRules.filter((r) => r.domain !== domain);
    this.broadcast({ type: 'trust_updated', data: this.trustRules });
    this.persistImmediate();
    return this.trustRules;
  }

  async updateSettings(patch: Partial<AppSettings>): Promise<{
    settings: AppSettings;
    diskSpace: DiskSpaceInfo;
  }> {
    const next: AppSettings = { ...this.settings };

    if (patch.speedPreset && patch.speedPreset !== 'custom') {
      const preset = SPEED_PRESETS[patch.speedPreset];
      if (preset) {
        next.speedPreset = patch.speedPreset;
        next.maxConcurrentDownloads = preset.maxConcurrentDownloads;
        next.maxConcurrentPerHost = preset.maxConcurrentPerHost;
        next.segmentsPerDownload = preset.segmentsPerDownload;
        next.speedLimitKBps = preset.speedLimitKBps;
      }
    } else if (patch.speedPreset === 'custom') {
      next.speedPreset = 'custom';
    }

    if (typeof patch.downloadDir === 'string' && patch.downloadDir.trim()) {
      next.downloadDir = path.resolve(patch.downloadDir.trim());
    }
    if (typeof patch.organizeByCategory === 'boolean') {
      next.organizeByCategory = patch.organizeByCategory;
    }
    if (typeof patch.autoApproveTrusted === 'boolean') {
      next.autoApproveTrusted = patch.autoApproveTrusted;
    }
    if (patch.theme === 'light' || patch.theme === 'dark') {
      next.theme = patch.theme;
    }

    if (typeof patch.maxConcurrentDownloads === 'number' && Number.isFinite(patch.maxConcurrentDownloads)) {
      next.maxConcurrentDownloads = Math.max(1, Math.min(8, Math.round(patch.maxConcurrentDownloads)));
      if (!patch.speedPreset) next.speedPreset = 'custom';
    }
    if (typeof patch.maxConcurrentPerHost === 'number' && Number.isFinite(patch.maxConcurrentPerHost)) {
      next.maxConcurrentPerHost = Math.max(1, Math.min(8, Math.round(patch.maxConcurrentPerHost)));
      if (!patch.speedPreset) next.speedPreset = 'custom';
    }
    if (typeof patch.segmentsPerDownload === 'number' && Number.isFinite(patch.segmentsPerDownload)) {
      next.segmentsPerDownload = Math.max(1, Math.min(16, Math.round(patch.segmentsPerDownload)));
      if (!patch.speedPreset) next.speedPreset = 'custom';
    }
    if (typeof patch.speedLimitKBps === 'number' && Number.isFinite(patch.speedLimitKBps)) {
      next.speedLimitKBps = Math.max(0, Math.round(patch.speedLimitKBps));
      if (!patch.speedPreset) next.speedPreset = 'custom';
    }

    this.settings = next;
    this.throttle.setLimitKBps(next.speedLimitKBps);
    await this.refreshDiskSpace();
    this.broadcast({
      type: 'settings_updated',
      data: { settings: this.settings, diskSpace: this.diskSpace },
    });
    this.persistImmediate();
    this.scheduleQueue();
    return { settings: this.settings, diskSpace: this.diskSpace };
  }

  private scheduleQueue(): void {
    const activeCount = this.runners.size;
    const slots = this.settings.maxConcurrentDownloads - activeCount;
    if (slots <= 0) return;

    const perHostCap = Math.max(1, this.settings.maxConcurrentPerHost || 2);
    const activeByHost = new Map<string, number>();
    for (const runner of this.runners.values()) {
      const host = getItemHost(runner.item);
      activeByHost.set(host, (activeByHost.get(host) ?? 0) + 1);
    }

    const queued = this.downloads
      .filter((d) => d.status === 'queued' && d.userDeemedSafe && !this.runners.has(d.id))
      .sort((a, b) => a.priority - b.priority);

    let started = 0;
    for (const item of queued) {
      if (started >= slots) break;
      const host = getItemHost(item);
      const hostActive = activeByHost.get(host) ?? 0;
      if (hostActive >= perHostCap) continue;

      activeByHost.set(host, hostActive + 1);
      started++;
      this.startRunner(item);
    }
  }

  private startRunner(item: DownloadItem): void {
    if (this.runners.has(item.id)) return;
    const runner = new DownloadRunner({
      item,
      throttle: this.throttle,
      minSegmentBytes: this.minSegmentBytes,
      stallTimeoutMs: this.stallTimeoutMs,
      onUpdate: (updated, immediatePersist) => {
        this.broadcast({ type: 'download_updated', data: updated });
        if (immediatePersist || Date.now() - this.lastPersistAt > 2000) {
          this.persistImmediate();
        }
      },
    });
    this.runners.set(item.id, runner);
    this.ensureTelemetryLoop();

    void runner.run().finally(() => {
      this.runners.delete(item.id);
      if (item.status === 'completed') {
        void this.refreshDiskSpace().then(() => {
          this.broadcast({
            type: 'settings_updated',
            data: { settings: this.settings, diskSpace: this.diskSpace },
          });
        });
      }
      this.persistImmediate();
      this.scheduleQueue();
    });
  }

  private ensureTelemetryLoop(): void {
    if (this.telemetryTick) return;
    this.telemetryTick = setInterval(() => {
      const stats = this.computeStats();
      this.speedHistory = [...this.speedHistory.slice(1), stats.totalSpeedBps];

      const activeItems = this.downloads.filter(
        (d) => d.status === 'downloading' || d.status === 'verifying'
      );

      this.broadcast({
        type: 'telemetry',
        data: {
          downloads: activeItems,
          speedHistory: this.speedHistory,
          stats,
        },
      });

      if (this.runners.size === 0 && stats.totalSpeedBps === 0) {
        if (this.telemetryTick) {
          clearInterval(this.telemetryTick);
          this.telemetryTick = null;
        }
      }
    }, 300);
  }

  private computeStats(): AppStats {
    let pendingReviewCount = 0;
    let probingCount = 0;
    let activeCount = 0;
    let queuedCount = 0;
    let pausedCount = 0;
    let failedCount = 0;
    let completedCount = 0;
    let totalSpeedBps = 0;
    let activeStreamsCount = 0;
    let totalDownloadedBytes = 0;

    for (const d of this.downloads) {
      totalDownloadedBytes += d.downloadedBytes;
      switch (d.status) {
        case 'pending_review':
          pendingReviewCount++;
          break;
        case 'probing':
          probingCount++;
          break;
        case 'downloading':
        case 'verifying':
          activeCount++;
          totalSpeedBps += d.speedBps;
          activeStreamsCount += d.segments.filter((s) => s.status === 'active').length;
          break;
        case 'queued':
          queuedCount++;
          break;
        case 'paused':
          pausedCount++;
          break;
        case 'failed':
          failedCount++;
          break;
        case 'completed':
          completedCount++;
          break;
      }
    }

    return {
      pendingReviewCount,
      probingCount,
      activeCount,
      queuedCount,
      pausedCount,
      failedCount,
      completedCount,
      totalSpeedBps,
      activeStreamsCount,
      totalDownloadedBytes,
    };
  }

  private nextPriority(): number {
    if (this.downloads.length === 0) return 0;
    return this.downloads.reduce((m, d) => Math.max(m, d.priority), 0) + 1;
  }

  private requireItem(id: string): DownloadItem {
    const item = this.downloads.find((d) => d.id === id);
    if (!item) {
      throw new Error('Download not found');
    }
    return item;
  }

  private persistImmediate(): void {
    this.lastPersistAt = Date.now();
    void this.store.save({
      version: 1,
      downloads: this.downloads,
      settings: this.settings,
      trustRules: this.trustRules,
    });
  }

  private broadcast(event: SSEEvent): void {
    const payload = `data: ${JSON.stringify(event)}\n\n`;
    for (const res of this.sseClients) {
      if (!res.writableEnded) {
        res.write(payload);
      }
    }
  }

  private sendEvent(res: http.ServerResponse, event: SSEEvent): void {
    if (!res.writableEnded) {
      res.write(`data: ${JSON.stringify(event)}\n\n`);
    }
  }
}

function getItemHost(item: DownloadItem): string {
  if (item.safety?.finalHost) {
    return normalizeHostname(item.safety.finalHost);
  }
  try {
    return normalizeHostname(new URL(item.finalUrl || item.originalUrl).hostname);
  } catch {
    return 'unknown';
  }
}

async function fileExists(target: string): Promise<boolean> {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
