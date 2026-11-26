import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import type {
  AppSettings,
  AppStateSnapshot,
  AppStats,
  CompanionCapabilities,
  DiskSpaceInfo,
  DownloadEngine,
  DownloadItem,
  FileIntegrityReport,
  MirrorProbeSummary,
  MirrorSourceMeta,
  RiskLevel,
  RoutingLogEntry,
  SafetyReport,
  SafetySignal,
  SSEEvent,
  SettingsPatch,
  SpeedPreset,
  TorrentFileEntry,
  TrustRule,
} from '../shared/types.js';
import {
  CURRENT_API_VERSION,
  DEFAULT_PUBLIC_IPFS_GATEWAYS,
  normalizeSettings,
} from '../shared/compat.js';
import { type ParsedInputEntry, parseSmartInput } from '../shared/inputParser.js';
import {
  ARIA2_OWNER_FILENAME,
  Aria2Runner,
  detectAria2,
  expandSelectFileIndices,
} from '../companion/aria2.js';
import {
  type CandidateBenchmarkResult,
  type CandidateSource,
  benchmarkCandidates,
} from '../companion/benchmarker.js';
import {
  assertOutboundUrlSafe,
  containsActiveSecret,
  redactSensitiveUrl,
  redactText,
  redactValidator,
  sanitizeUpstreamError,
  summarizeRejectedToken,
} from '../companion/parser.js';
import { readPartMeta, removePartMeta } from '../companion/partMeta.js';
import {
  expandIpfsCidToCandidates,
  resolveApprovedProviderOrigin,
  resolveBookSources,
} from '../companion/resolver.js';
import { parseTorrentMetadata } from '../companion/torrentParser.js';
import { DownloadRunner, computeFileHandleHashes } from './engine.js';
import { probeUrl } from './inspector.js';
import { OriginRateLimiter } from './rateLimit.js';
import { type OperationalSourceRef, SecretStore } from './secretStore.js';
import { StateStore } from './store.js';
import { TokenBucketThrottle } from './throttle.js';
import {
  checkMimeExtensionMismatch,
  classifyFile,
  isPathInsideDir,
  isPrivateOrIpHost,
  matchDomainTrust,
  normalizeDomainRuleInput,
  normalizeHostname,
  resolveUniquePath,
  sanitizeFilename,
} from './utils.js';
import { canCombineMirrorWithPrimary, computeOpaqueSourceId } from './validators.js';
import { verifyFileIntegrity } from './verifier.js';

export interface ManagerOptions {
  dataDir?: string;
  minSegmentBytes?: number;
  stallTimeoutMs?: number;
  sessionToken?: string;
  allowInsecureLoopbackProvider?: boolean;
  /** Test-only: aria2c binary + args prefix (deterministic mock aria2c). */
  aria2Binary?: string;
  aria2BinaryArgsPrefix?: string[];
  testHooks?: {
    onDuringVerifyHash?: () => Promise<void>;
    /** Awaited mid-approval, after validation and before the approval is committed. */
    onDuringApproval?: (id: string) => Promise<void>;
  };
}

/** Per-row bulk approval entry (each row's own edits travel with it). */
export interface ApprovalEntry {
  id: string;
  filename?: string;
  destinationDir?: string;
  connections?: number;
  engine?: DownloadEngine;
  selectFile?: string;
  expectedSha256?: string;
}

/** Template entry in a settings PATCH: plaintext, or a stable stored-template reference. */
type TemplateEntryInput = string | { ref?: unknown };

interface SseClientState {
  res: http.ServerResponse;
  draining: boolean;
  queue: string[];
  pendingTelemetry: string | null;
}

interface ActiveRunner {
  item: DownloadItem;
  run(): Promise<void>;
  pause(): Promise<void>;
  cancel(deletePartFile?: boolean): Promise<void>;
}

/**
 * One registered runner instance plus the SINGLE promise covering its whole lifecycle
 * (runner setup -> transfer -> verification -> manager-side cleanup). All map/state mutations
 * are guarded by exact handle identity so a late, stale runner can never clobber a newer one.
 */
interface RunnerHandle {
  runner: ActiveRunner;
  done: Promise<void>;
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
  public readonly secretStore: SecretStore;
  public readonly rateLimiter = new OriginRateLimiter();
  private readonly minSegmentBytes?: number;
  private readonly stallTimeoutMs?: number;
  private readonly allowInsecureLoopbackProvider: boolean;
  private readonly testHooks?: ManagerOptions['testHooks'];
  private readonly aria2Binary?: string;
  private readonly aria2BinaryArgsPrefix?: string[];
  /** Process-local key for stable opaque private-template identities (never derived from masks). */
  private readonly templateIdKey = crypto.randomBytes(32);
  /** Stable per-install key for opaque source / resource fingerprints (set in init()). */
  private sourceIdKey: Buffer | undefined;

  private downloads: DownloadItem[] = [];
  private settings!: AppSettings;
  private trustRules: TrustRule[] = [];
  /**
   * Live secret set. Mutated IN PLACE (never reassigned) so every runner / guard holding this
   * array—or reading it via `secretsProvider`—sees key rotations immediately. Retired keys stay
   * in the set for the process lifetime because they may still be valid at the provider.
   */
  private readonly cachedSecrets: string[] = [];
  private approvalLocks = new Set<string>();
  private sessionToken = '';
  private diskSpace: DiskSpaceInfo = { path: '', freeBytes: 0, totalBytes: 0 };
  private capabilities: CompanionCapabilities = {
    aria2Available: false,
    platform: process.platform,
    companionVersion: '4.1.0',
    apiVersion: CURRENT_API_VERSION,
    requiresPairing: true,
    features: {
      singleSourceValidatorLock: true,
      splitTelemetry: true,
      writeOnlySecrets: true,
      pairedSessionAuth: true,
    },
    installHint: {
      command: process.platform === 'win32' ? 'winget install aria2.aria2' : 'brew install aria2',
      label: process.platform === 'win32' ? 'Windows (winget)' : 'macOS (Homebrew)',
      platform: process.platform,
    },
  };
  private speedHistory: number[] = Array(60).fill(0);

  private runners = new Map<string, RunnerHandle>();
  private removingIds = new Set<string>();
  private inFlightRemovals = new Map<string, Promise<{ id: string; undoable: boolean }>>();
  private pinnedTorrentPaths = new Map<string, string>();
  private sseClients = new Map<http.ServerResponse, SseClientState>();
  private telemetryTick: NodeJS.Timeout | null = null;
  private lastPersistAt = 0;

  constructor(options: ManagerOptions = {}) {
    this.store = new StateStore(options.dataDir);
    this.secretStore = new SecretStore(this.store.dataDir, options.sessionToken);
    this.throttle = new TokenBucketThrottle(0);
    this.minSegmentBytes = options.minSegmentBytes;
    this.stallTimeoutMs = options.stallTimeoutMs;
    this.allowInsecureLoopbackProvider = Boolean(options.allowInsecureLoopbackProvider);
    this.testHooks = options.testHooks;
    this.aria2Binary = options.aria2Binary;
    this.aria2BinaryArgsPrefix = options.aria2BinaryArgsPrefix;
  }

  /** Refreshes the live secret set in place (union with previously active secrets). */
  private async refreshCachedSecrets(): Promise<void> {
    const fresh = await this.secretStore.getActiveSecretsForRedaction();
    const merged = Array.from(new Set([...fresh, ...this.cachedSecrets])).filter(Boolean);
    this.cachedSecrets.splice(0, this.cachedSecrets.length, ...merged);
  }

  private readonly secretsProvider = (): readonly string[] => this.cachedSecrets;

  private templateId(raw: string): string {
    return `tpl_${crypto.createHmac('sha256', this.templateIdKey).update(raw).digest('hex').slice(0, 24)}`;
  }

  async init(): Promise<void> {
    this.sessionToken = await this.secretStore.getOrCreateSessionToken();
    // Malformed / unreadable state.json throws StateLoadError (never overwritten with defaults)
    const loaded = await this.store.load();
    this.downloads = loaded.downloads;
    this.settings = loaded.settings;
    this.trustRules = loaded.trustRules;
    this.sourceIdKey = await this.secretStore.deriveSubkey('source-id/v1');

    // Every migration step below propagates its failure (vault write, verification, scrub).

    // 1. Migrate legacy plaintext API key & verify persisted encrypted vault BEFORE scrubbing state.json.
    if (loaded.migratedAnnasApiKey) {
      await this.secretStore.setAnnasArchiveApiKey(loaded.migratedAnnasApiKey);
      const verified = await this.secretStore.verifyPersistedAnnasArchiveApiKey(
        loaded.migratedAnnasApiKey
      );
      if (!verified) {
        throw new Error(
          'Failed to verify encrypted API key persistence before scrubbing legacy state.json'
        );
      }
    }

    // 2. Load or migrate private mirror/gateway templates into encrypted vault BEFORE rewriting state.json
    const vaultedTemplates = await this.secretStore.getPrivateTemplates();
    const templatesToVault: { customMirrorUrls?: string[]; ipfsGateways?: string[] } = {};
    if (vaultedTemplates.customMirrorUrls) {
      this.settings.customMirrorUrls = vaultedTemplates.customMirrorUrls;
    } else if (
      this.settings.customMirrorUrls.length > 0 &&
      !this.settings.customMirrorUrls.some((u) => u.includes('***'))
    ) {
      templatesToVault.customMirrorUrls = [...this.settings.customMirrorUrls];
    }
    if (vaultedTemplates.ipfsGateways) {
      this.settings.ipfsGateways = vaultedTemplates.ipfsGateways;
    } else if (
      this.settings.ipfsGateways.length > 0 &&
      !this.settings.ipfsGateways.some((u) => u.includes('***'))
    ) {
      templatesToVault.ipfsGateways = [...this.settings.ipfsGateways];
    }
    if (templatesToVault.customMirrorUrls || templatesToVault.ipfsGateways) {
      await this.secretStore.setPrivateTemplates(templatesToVault);
    }

    // 3. Vault any legacy unredacted job operational URLs into encrypted store BEFORE rewriting state.json!
    const storedSources = await this.secretStore.getOperationalSources();
    const legacySourcesToVault: Record<string, OperationalSourceRef> = {};
    for (const item of this.downloads) {
      const existingRef = storedSources[item.id];
      if (existingRef) {
        this.applyOperationalSourceRef(item, existingRef);
      } else {
        const hasLiveUrls =
          Boolean(item.originalUrl && !item.originalUrl.includes('***')) ||
          Boolean(item.finalUrl && !item.finalUrl.includes('***')) ||
          Boolean(item.magnetUri && !item.magnetUri.includes('***')) ||
          Boolean(item.torrentUrl && !item.torrentUrl.includes('***'));
        if (hasLiveUrls) {
          legacySourcesToVault[item.id] = {
            originalUrl: item.originalUrl,
            finalUrl: item.finalUrl,
            mirrorUrls: item.mirrorUrls ? [...item.mirrorUrls] : undefined,
            mirrorMeta: item.mirrorMeta ? item.mirrorMeta.map((m) => ({ ...m })) : undefined,
            magnetUri: item.magnetUri,
            torrentUrl: item.torrentUrl,
            torrentInfoHash: item.torrentInfoHash,
          };
        }
      }
    }
    if (Object.keys(legacySourcesToVault).length > 0) {
      await this.secretStore.setOperationalSourcesBatch(legacySourcesToVault);
    }

    const hasKey = await this.secretStore.hasAnnasArchiveApiKey();
    this.settings.hasAnnasArchiveApiKey = hasKey;
    await this.refreshCachedSecrets();

    // 4. Migrate legacy plaintext .torrent manifests into encrypted envelopes; drop any pinned
    // manifest path that cannot be migrated (the job must be re-inspected).
    await this.migrateLegacyPinnedManifests();

    this.throttle.setLimitKBps(this.settings.speedLimitKBps);
    await Promise.all([this.refreshDiskSpace(), this.refreshCapabilities()]);

    // 5. Scrub decision is based on the ACTUAL bytes still on disk (not on which migration branch
    // ran): if state.json differs in any way from the sanitized state we would write — e.g. a
    // previous run vaulted secrets but crashed before scrubbing — rewrite it now, propagating
    // any write failure.
    const sanitizedText = this.store.serialize(this.buildPersistedState());
    const diskText = await this.store.readDiskText();
    if (diskText !== sanitizedText) {
      await this.store.saveStrict(this.buildPersistedState());
      const verifyText = await this.store.readDiskText();
      if (verifyText !== null && this.diskTextHasPlaintextSecrets(verifyText)) {
        throw new Error('state.json still contains plaintext credentials after migration scrub');
      }
    }
  }

  private buildPersistedState() {
    return {
      version: 1,
      downloads: this.downloads.map((d) => this.sanitizeItemForExport(d)),
      // Template identities are process-local display handles; never persisted.
      settings: this.sanitizeSettingsForExport(false),
      trustRules: this.trustRules,
    };
  }

  /** Detects any vaulted plaintext credential (API key, template, operational URL) in raw text. */
  private diskTextHasPlaintextSecrets(text: string): boolean {
    if (containsActiveSecret(text, this.cachedSecrets)) return true;
    const rawTemplates = [...this.settings.customMirrorUrls, ...this.settings.ipfsGateways];
    for (const raw of rawTemplates) {
      if (raw && redactSensitiveUrl(raw, this.cachedSecrets) !== raw && text.includes(raw)) return true;
    }
    for (const item of this.downloads) {
      for (const u of [item.originalUrl, item.finalUrl, item.magnetUri, item.torrentUrl, ...(item.mirrorUrls ?? [])]) {
        if (u && redactSensitiveUrl(u, this.cachedSecrets) !== u && text.includes(JSON.stringify(u).slice(1, -1))) {
          return true;
        }
      }
    }
    return false;
  }

  private async migrateLegacyPinnedManifests(): Promise<void> {
    for (const [jobId, manifestPath] of Array.from(this.pinnedTorrentPaths.entries())) {
      if (this.secretStore.isEncryptedManifestPath(manifestPath)) continue;
      const item = this.downloads.find((d) => d.id === jobId);
      try {
        const migrated = await this.secretStore.migrateLegacyPlaintextManifest(jobId, manifestPath);
        const parsed = parseTorrentMetadata(migrated.bytes);
        if (
          item?.torrentInfoHash &&
          parsed.infoHash.toLowerCase() !== item.torrentInfoHash.toLowerCase()
        ) {
          await this.secretStore.deleteEncryptedManifest(migrated.encryptedPath).catch(() => undefined);
          throw new Error('legacy manifest infoHash does not match the inspected torrent');
        }
        this.pinnedTorrentPaths.set(jobId, migrated.encryptedPath);
      } catch (err) {
        // Reject the unmigrated/raw plaintext manifest path outright; job must be re-inspected.
        this.pinnedTorrentPaths.delete(jobId);
        if (item) {
          item.routingLog = [
            ...(item.routingLog ?? []),
            {
              timestamp: Date.now(),
              level: 'warn',
              message: sanitizeUpstreamError(
                `Legacy plaintext .torrent manifest could not be migrated (${err instanceof Error ? err.message : 'error'}); re-inspect before downloading`,
                this.cachedSecrets,
                300
              ),
            },
          ];
        }
      }
      if (item) await this.syncOperationalSource(item);
    }
  }

  getSessionToken(): string {
    return this.sessionToken;
  }

  issuePairingCode(ttlMs?: number): { code: string; expiresAt: number } {
    return this.secretStore.issuePairingCode(ttlMs);
  }

  redeemPairingCredential(candidate: string | undefined | null): string | null {
    const token = this.secretStore.redeemPairingCredential(candidate);
    if (token && !this.cachedSecrets.includes(token)) {
      // In-place push: every live runner/guard observes the new session token immediately
      this.cachedSecrets.push(token);
    }
    return token;
  }

  verifySessionToken(candidate: string | undefined | null): boolean {
    return this.secretStore.verifySessionToken(candidate);
  }

  getActiveSecrets(): string[] {
    return this.cachedSecrets;
  }

  private applyOperationalSourceRef(item: DownloadItem, ref: OperationalSourceRef): void {
    item.originalUrl = ref.originalUrl;
    item.finalUrl = ref.finalUrl;
    if (ref.mirrorUrls) item.mirrorUrls = [...ref.mirrorUrls];
    if (ref.mirrorMeta) item.mirrorMeta = ref.mirrorMeta.map((m) => ({ ...m }));
    if (ref.magnetUri !== undefined) item.magnetUri = ref.magnetUri;
    if (ref.torrentUrl !== undefined) item.torrentUrl = ref.torrentUrl;
    if (ref.torrentInfoHash) item.torrentInfoHash = ref.torrentInfoHash;
    if (ref.pinnedTorrentPath) {
      this.pinnedTorrentPaths.set(item.id, ref.pinnedTorrentPath);
    }
  }

  private async syncOperationalSource(item: DownloadItem): Promise<void> {
    const ref: OperationalSourceRef = {
      originalUrl: item.originalUrl,
      finalUrl: item.finalUrl,
      mirrorUrls: item.mirrorUrls ? [...item.mirrorUrls] : undefined,
      mirrorMeta: item.mirrorMeta ? item.mirrorMeta.map((m) => ({ ...m })) : undefined,
      magnetUri: item.magnetUri,
      torrentUrl: item.torrentUrl,
      pinnedTorrentPath: this.pinnedTorrentPaths.get(item.id),
      torrentInfoHash: item.torrentInfoHash,
    };
    await this.secretStore.setOperationalSource(item.id, ref);
  }

  private async isVerifiedStagingOwnedByJob(item: DownloadItem): Promise<boolean> {
    if (!item.partPath || !item.destinationDir) return false;
    const resolvedPart = path.resolve(item.partPath);
    if (!isPathInsideDir(resolvedPart, item.destinationDir)) return false;
    if (resolvedPart === path.resolve(item.destinationDir)) return false;

    const st = await fs.stat(resolvedPart).catch(() => null);
    if (!st) return false;

    if (st.isDirectory()) {
      const ownerPath = path.join(resolvedPart, ARIA2_OWNER_FILENAME);
      try {
        const owner = JSON.parse(await fs.readFile(ownerPath, 'utf8')) as { jobId?: string };
        return owner.jobId === item.id;
      } catch {
        return false;
      }
    }

    if (st.isFile()) {
      const meta = await readPartMeta(resolvedPart);
      if (meta) {
        return meta.jobId === item.id;
      }
      const safeJobId = item.id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 16);
      return Boolean(safeJobId) && path.basename(resolvedPart).startsWith(`.boltgate-${safeJobId}`);
    }

    return false;
  }

  getCapabilities(): CompanionCapabilities {
    return this.capabilities;
  }

  async refreshCapabilities(): Promise<CompanionCapabilities> {
    this.capabilities = await detectAria2(this.aria2Binary ?? 'aria2c', this.aria2BinaryArgsPrefix ?? []);
    return this.capabilities;
  }

  async shutdown(): Promise<void> {
    if (this.telemetryTick) {
      clearInterval(this.telemetryTick);
      this.telemetryTick = null;
    }
    const handles = Array.from(this.runners.values());
    await Promise.allSettled(handles.map((h) => h.runner.pause()));
    await Promise.allSettled(handles.map((h) => h.done));
    this.persistImmediate();
    await this.store.flush();
    for (const res of this.sseClients.keys()) {
      res.end();
    }
    this.sseClients.clear();
  }

  private sanitizeSettingsForExport(includeTemplateRefs = true): AppSettings {
    const secrets = this.cachedSecrets;
    const normalized = normalizeSettings({
      ...this.settings,
      templateRefs: undefined,
      hasAnnasArchiveApiKey: this.settings.hasAnnasArchiveApiKey,
    });
    const exported: AppSettings = {
      downloadDir: normalized.downloadDir,
      organizeByCategory: normalized.organizeByCategory,
      maxConcurrentDownloads: normalized.maxConcurrentDownloads,
      maxConcurrentPerHost: normalized.maxConcurrentPerHost,
      segmentsPerDownload: normalized.segmentsPerDownload,
      speedLimitKBps: normalized.speedLimitKBps,
      speedPreset: normalized.speedPreset,
      autoApproveTrusted: normalized.autoApproveTrusted,
      theme: normalized.theme,
      hasAnnasArchiveApiKey: normalized.hasAnnasArchiveApiKey,
      annasArchiveBaseUrl: redactSensitiveUrl(normalized.annasArchiveBaseUrl, secrets),
      customMirrorUrls: normalized.customMirrorUrls.map((u) => redactSensitiveUrl(u, secrets)),
      ipfsGateways: normalized.ipfsGateways.map((u) => redactSensitiveUrl(u, secrets)),
      minSpeedFloorKBps: normalized.minSpeedFloorKBps,
      preferAria2: normalized.preferAria2,
    };
    if (includeTemplateRefs) {
      // Stable opaque identity per stored template (index-aligned with the masked display list)
      exported.templateRefs = {
        customMirrorUrls: normalized.customMirrorUrls.map((u) => this.templateId(u)),
        ipfsGateways: normalized.ipfsGateways.map((u) => this.templateId(u)),
      };
    }
    return exported;
  }

  private sanitizeItemForExport(item: DownloadItem): DownloadItem {
    const secrets = this.cachedSecrets;
    const redactedSafety: SafetyReport | null = item.safety
      ? {
          riskLevel: item.safety.riskLevel,
          signals: item.safety.signals.map((sig) => ({
            id: sig.id,
            level: sig.level,
            title: redactText(sig.title, secrets),
            detail: redactText(sig.detail, secrets),
          })),
          finalUrl: redactSensitiveUrl(item.safety.finalUrl, secrets),
          finalHost: item.safety.finalHost,
          initialHost: item.safety.initialHost,
          redirectChain: item.safety.redirectChain.map((hop) => ({
            url: redactSensitiveUrl(hop.url, secrets),
            host: hop.host,
            statusCode: hop.statusCode,
          })),
          statusCode: item.safety.statusCode,
          contentType: item.safety.contentType,
          etag: redactValidator(item.safety.etag, secrets),
          lastModified: redactValidator(item.safety.lastModified, secrets),
          supportsRanges: item.safety.supportsRanges,
          totalBytes: item.safety.totalBytes,
          suggestedFilename: redactText(item.safety.suggestedFilename, secrets),
          extension: item.safety.extension,
          category: item.safety.category,
          isExecutable: item.safety.isExecutable,
          domainTrust: item.safety.domainTrust,
          tls: item.safety.tls
            ? {
                authorized: item.safety.tls.authorized,
                issuer: item.safety.tls.issuer,
                subjectCN: item.safety.tls.subjectCN,
                validTo: item.safety.tls.validTo,
                error: item.safety.tls.error
                  ? redactText(item.safety.tls.error, secrets)
                  : undefined,
              }
            : undefined,
          duplicateOfId: item.safety.duplicateOfId,
          mirrorReports: item.safety.mirrorReports?.map((mr) => ({
            url: redactSensitiveUrl(mr.url, secrets),
            finalUrl: redactSensitiveUrl(mr.finalUrl, secrets),
            host: mr.host,
            statusCode: mr.statusCode,
            totalBytes: mr.totalBytes,
            supportsRanges: mr.supportsRanges,
            riskLevel: mr.riskLevel,
            included: mr.included,
            excludeReason: mr.excludeReason ? redactText(mr.excludeReason, secrets) : undefined,
            label: mr.label ? redactText(mr.label, secrets) : undefined,
            tier: mr.tier,
            probeSpeedBps: mr.probeSpeedBps,
            latencyMs: mr.latencyMs,
            isSlowPartner: mr.isSlowPartner,
            etag: redactValidator(mr.etag, secrets),
            lastModified: redactValidator(mr.lastModified, secrets),
            isHtmlTrap: mr.isHtmlTrap,
            contentType: mr.contentType,
            provenance: mr.provenance ? redactText(mr.provenance, secrets) : undefined,
          })),
          expectedMd5: item.safety.expectedMd5,
          expectedSha256: item.safety.expectedSha256,
          resolvedCids: item.safety.resolvedCids ? [...item.safety.resolvedCids] : undefined,
          torrentFiles: item.safety.torrentFiles?.map((f) => ({
            index: f.index,
            path: redactText(f.path, secrets),
            length: f.length,
          })),
          torrentInfoHash: item.safety.torrentInfoHash,
          sourceMode: item.safety.sourceMode,
          isP2P: item.safety.isP2P,
          probedAt: item.safety.probedAt,
          probeError: item.safety.probeError
            ? redactText(item.safety.probeError, secrets)
            : undefined,
        }
      : null;

    return {
      id: item.id,
      originalUrl: redactSensitiveUrl(item.originalUrl, secrets),
      finalUrl: redactSensitiveUrl(item.finalUrl, secrets),
      mirrorUrls: item.mirrorUrls?.map((u) => redactSensitiveUrl(u, secrets)),
      mirrorMeta: item.mirrorMeta?.map((m) => ({
        // Keyed fingerprint: never an unsalted hash of a credential-bearing URL
        sourceId: m.sourceId ?? computeOpaqueSourceId(m.url, this.sourceIdKey),
        url: redactSensitiveUrl(m.url, secrets),
        label: redactText(m.label, secrets),
        host: m.host,
        tier: m.tier,
        isSlowPartner: m.isSlowPartner,
        etag: redactValidator(m.etag, secrets),
        lastModified: redactValidator(m.lastModified, secrets),
        provenance: m.provenance ? redactText(m.provenance, secrets) : undefined,
      })),
      mirrorTelemetry: item.mirrorTelemetry?.map((mt) => ({
        sourceId: mt.sourceId,
        url: redactSensitiveUrl(mt.url, secrets),
        label: redactText(mt.label, secrets),
        host: mt.host,
        tier: mt.tier,
        status: mt.status,
        speedBps: mt.speedBps,
        downloadedBytes: mt.downloadedBytes,
        activeWorkers: mt.activeWorkers,
        failures: mt.failures,
        lastEvent: mt.lastEvent ? redactText(mt.lastEvent, secrets) : undefined,
        provenance: mt.provenance ? redactText(mt.provenance, secrets) : undefined,
      })),
      routingLog: item.routingLog?.map((entry) => ({
        timestamp: entry.timestamp,
        level: entry.level,
        message: redactText(entry.message, secrets),
      })),
      filename: redactText(item.filename, secrets),
      destinationDir: item.destinationDir,
      savedPath: redactText(item.savedPath, secrets),
      partPath: redactText(item.partPath, secrets),
      category: item.category,
      status: item.status,
      priority: item.priority,
      totalBytes: item.totalBytes,
      downloadedBytes: item.downloadedBytes,
      speedBps: item.speedBps,
      avgSpeedBps: item.avgSpeedBps,
      etaSeconds: item.etaSeconds,
      connections: item.connections,
      supportsRanges: item.supportsRanges,
      etag: redactValidator(item.etag, secrets),
      lastModified: redactValidator(item.lastModified, secrets),
      pinnedEtag: redactValidator(item.pinnedEtag, secrets),
      pinnedLastModified: redactValidator(item.pinnedLastModified, secrets),
      sourceProvenance: item.sourceProvenance
        ? redactText(item.sourceProvenance, secrets)
        : undefined,
      telemetry: item.telemetry ? { ...item.telemetry, backingOffHosts: [...item.telemetry.backingOffHosts] } : undefined,
      segments: item.segments.map((seg) => ({
        id: seg.id,
        start: seg.start,
        end: seg.end,
        downloaded: seg.downloaded,
        speedBps: seg.speedBps,
        status: seg.status,
        retries: seg.retries,
        mirrorIndex: seg.mirrorIndex,
        lastError: seg.lastError ? redactText(seg.lastError, secrets) : undefined,
      })),
      safety: redactedSafety,
      expectedSha256: item.expectedSha256,
      sha256: item.sha256,
      verifiedHashMatch: item.verifiedHashMatch,
      expectedMd5: item.expectedMd5,
      md5: item.md5,
      md5Verified: item.md5Verified,
      sourceMode: item.sourceMode,
      sourceBadge: item.sourceBadge ? redactText(item.sourceBadge, secrets) : undefined,
      engine: item.engine,
      magnetUri: item.magnetUri ? redactSensitiveUrl(item.magnetUri, secrets) : undefined,
      torrentUrl: item.torrentUrl ? redactSensitiveUrl(item.torrentUrl, secrets) : undefined,
      torrentInfoHash: item.torrentInfoHash,
      torrentRootName: item.torrentRootName ? redactText(item.torrentRootName, secrets) : undefined,
      selectFile: item.selectFile,
      selectFileInfoHash: item.selectFileInfoHash,
      torrentFiles: item.torrentFiles?.map((f) => ({
        index: f.index,
        path: redactText(f.path, secrets),
        length: f.length,
      })),
      publishedFiles: item.publishedFiles?.map((p) => redactText(p, secrets)),
      verifiedFileIndex: item.verifiedFileIndex,
      verifiedFilePath: item.verifiedFilePath ? redactText(item.verifiedFilePath, secrets) : undefined,
      integrity: item.integrity
        ? {
            status: item.integrity.status,
            format: item.integrity.format,
            summary: redactText(item.integrity.summary, secrets),
            checks: item.integrity.checks.map((c) => redactText(c, secrets)),
            verifiedAt: item.integrity.verifiedAt,
          }
        : undefined,
      createdAt: item.createdAt,
      approvedAt: item.approvedAt,
      startedAt: item.startedAt,
      completedAt: item.completedAt,
      error: item.error ? redactText(item.error, secrets) : undefined,
      userDeemedSafe: item.userDeemedSafe,
    };
  }

  getSnapshot(): AppStateSnapshot {
    return {
      downloads: this.downloads.map((d) => this.sanitizeItemForExport(d)),
      settings: this.sanitizeSettingsForExport(),
      trustRules: this.trustRules,
      speedHistory: this.speedHistory,
      stats: this.computeStats(),
      diskSpace: this.diskSpace,
      capabilities: this.capabilities,
    };
  }

  addSseClient(res: http.ServerResponse): void {
    const client: SseClientState = {
      res,
      draining: false,
      queue: [],
      pendingTelemetry: null,
    };
    this.sseClients.set(res, client);
    this.sendEventToClient(client, { type: 'snapshot', data: this.getSnapshot() });
    res.on('close', () => {
      this.sseClients.delete(res);
    });
    res.on('error', () => {
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

  private getApprovedProviderHosts(): string[] {
    const check = resolveApprovedProviderOrigin(
      this.settings.annasArchiveBaseUrl,
      this.allowInsecureLoopbackProvider
    );
    if (!check.origin) return [];
    try {
      return [normalizeHostname(new URL(check.origin).hostname)];
    } catch {
      return [];
    }
  }

  async inspectRawText(
    rawText: string,
    destinationDir?: string,
    opts: {
      mode?: 'auto' | 'separate' | 'mirrors';
      /** Verification contract carried over from a history item (re-download). */
      inherit?: {
        expectedMd5?: string;
        expectedSha256?: string;
        selectFile?: string;
        torrentInfoHash?: string;
      };
    } = {}
  ): Promise<{ items: DownloadItem[]; rejectedTokens: string[] }> {
    const parsed = parseSmartInput(rawText, {
      approvedProviderHosts: this.getApprovedProviderHosts(),
    });
    if (parsed.entries.length === 0) {
      return { items: [], rejectedTokens: parsed.rejectedTokens.map(summarizeRejectedToken) };
    }

    if (opts.mode === 'mirrors' && parsed.directUrls.length >= 2) {
      return this.inspectMirrorGroup(parsed.directUrls.join('\n'), destinationDir, opts.inherit);
    }

    const baseDest = destinationDir?.trim()
      ? path.resolve(destinationDir.trim())
      : this.settings.downloadDir;

    const created: DownloadItem[] = [];
    const launchTasks: Array<() => Promise<void>> = [];

    for (const entry of parsed.entries) {
      const id = crypto.randomUUID();
      let roughName = 'download';
      let originalUrl = '';
      let expectedMd5: string | undefined;
      let engine: DownloadEngine = 'node';
      let sourceMode: DownloadItem['sourceMode'] = 'direct';
      let sourceBadge: string | undefined;
      let magnetUri: string | undefined;
      let torrentUrl: string | undefined;

      if (entry.kind === 'annas_md5') {
        originalUrl = entry.sourcePageUrl;
        expectedMd5 = entry.md5;
        roughName = `book-${entry.md5.slice(0, 8)}`;
        sourceBadge = 'Resolving Mirrors';
      } else if (entry.kind === 'raw_md5') {
        originalUrl = `md5:${entry.md5}`;
        expectedMd5 = entry.md5;
        roughName = `book-${entry.md5.slice(0, 8)}`;
        sourceBadge = 'Resolving Mirrors';
      } else if (entry.kind === 'ipfs_uri') {
        originalUrl = entry.raw;
        roughName = sanitizeFilename(
          redactText(entry.filename || `ipfs-${entry.cid.slice(0, 10)}`, this.cachedSecrets)
        );
        sourceMode = 'ipfs_race';
        sourceBadge = 'IPFS Race';
      } else if (entry.kind === 'magnet') {
        originalUrl = entry.magnetUri;
        magnetUri = entry.magnetUri;
        roughName = sanitizeFilename(
          redactText(
            entry.displayName ||
              (entry.infoHash ? `torrent-${entry.infoHash.slice(0, 10)}` : 'magnet-download'),
            this.cachedSecrets
          )
        );
        engine = 'aria2';
        sourceMode = 'aria2_p2p';
        sourceBadge = 'aria2c P2P';
      } else if (entry.kind === 'torrent_url') {
        originalUrl = entry.url;
        torrentUrl = entry.url;
        roughName = sanitizeFilename(
          extractRedactedUrlFilename(entry.url, this.cachedSecrets) || 'torrent-download'
        );
        engine = 'aria2';
        sourceMode = 'aria2_p2p';
        sourceBadge = 'aria2c P2P';
      } else {
        originalUrl = entry.url;
        const u = new URL(entry.url);
        roughName = sanitizeFilename(
          extractRedactedUrlFilename(entry.url, this.cachedSecrets) || u.hostname || 'download'
        );
      }

      const item: DownloadItem = {
        id,
        originalUrl,
        finalUrl: originalUrl,
        filename: roughName,
        destinationDir: baseDest,
        savedPath: path.join(baseDest, roughName),
        partPath: '',
        category: expectedMd5 ? 'ebook' : classifyFile(roughName).category,
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
        expectedMd5,
        sourceMode,
        sourceBadge,
        engine,
        magnetUri,
        torrentUrl,
        routingLog: [],
        createdAt: Date.now(),
        userDeemedSafe: false,
      };

      // Re-download from history: carry the original verification contract (digests + the
      // exact torrent file selection) instead of silently dropping it for defaults.
      if (opts.inherit && parsed.entries.length === 1) {
        applyInheritedContract(item, opts.inherit);
      }

      this.downloads.unshift(item);
      created.push(item);
      await this.syncOperationalSource(item);
      this.broadcast({ type: 'download_updated', data: item });

      if (entry.kind === 'annas_md5' || entry.kind === 'raw_md5') {
        launchTasks.push(() => this.runSmartBookResolution(item, entry, destinationDir));
      } else if (entry.kind === 'ipfs_uri') {
        launchTasks.push(() => this.runIpfsResolution(item, entry, destinationDir));
      } else if (entry.kind === 'magnet' || entry.kind === 'torrent_url') {
        launchTasks.push(() => this.runP2PProbe(item, entry, destinationDir));
      } else {
        launchTasks.push(() => this.runProbeForItem(item, destinationDir));
      }
    }

    this.persistImmediate();
    for (const task of launchTasks) {
      void task();
    }

    return {
      items: created.map((c) => this.sanitizeItemForExport(c)),
      rejectedTokens: parsed.rejectedTokens.map(summarizeRejectedToken),
    };
  }

  async inspectMirrorGroup(
    rawText: string,
    destinationDir?: string,
    inherit?: { expectedMd5?: string; expectedSha256?: string }
  ): Promise<{ items: DownloadItem[]; rejectedTokens: string[] }> {
    const parsed = parseSmartInput(rawText);
    const urls = parsed.directUrls;
    if (urls.length < 2) {
      return this.inspectRawText(rawText, destinationDir);
    }

    const baseDest = destinationDir?.trim()
      ? path.resolve(destinationDir.trim())
      : this.settings.downloadDir;

    const primaryUrl = urls[0]!;
    const parsedUrl = new URL(primaryUrl);
    const roughName = sanitizeFilename(
      extractRedactedUrlFilename(primaryUrl, this.cachedSecrets) ||
        parsedUrl.hostname ||
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
      partPath: '',
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
      sourceMode: 'swarm',
      sourceBadge: `Swarming ${urls.length} mirrors`,
      engine: 'node',
      routingLog: [],
      createdAt: Date.now(),
      userDeemedSafe: false,
    };
    if (inherit) {
      applyInheritedContract(item, inherit);
    }

    this.downloads.unshift(item);
    await this.syncOperationalSource(item);
    this.broadcast({ type: 'download_updated', data: item });
    this.persistImmediate();

    void this.runMirrorGroupProbe(item, urls, destinationDir);
    return {
      items: [this.sanitizeItemForExport(item)],
      rejectedTokens: parsed.rejectedTokens.map(summarizeRejectedToken),
    };
  }

  private async runMirrorGroupProbe(
    item: DownloadItem,
    mirrorUrls: string[],
    customDest?: string
  ): Promise<void> {
    await this.refreshDiskSpace();
    const existing = this.downloads.filter((d) => d.id !== item.id);

    const candidates: CandidateSource[] = mirrorUrls.map((u, idx) => {
      let host = 'mirror';
      try {
        host = normalizeHostname(new URL(u).hostname);
      } catch {
        host = 'mirror';
      }
      return {
        url: u,
        label: `Mirror #${idx + 1} (${host})`,
        tier: 'mirror',
        host,
        priority: 70 - idx,
        provenance: `user_mirror:${host}`,
      };
    });

    const [reports, benchResults] = await Promise.all([
      Promise.all(
        mirrorUrls.map((u) =>
          probeUrl(u, {
            trustRules: this.trustRules,
            existingDownloads: existing,
            freeBytes: this.diskSpace.freeBytes || undefined,
            secrets: this.cachedSecrets,
          })
        )
      ),
      benchmarkCandidates(candidates, { concurrency: 5, secrets: this.cachedSecrets }),
    ]);

    const current = this.downloads.find((d) => d.id === item.id);
    if (!current || this.removingIds.has(item.id)) return;

    const isReportAndBenchHealthy = (idx: number): boolean => {
      const r = reports[idx]!;
      const b = benchResults[idx];
      if (r.probeError || (r.statusCode ?? 500) >= 400 || r.domainTrust === 'blocked') {
        return false;
      }
      if (b && (!b.ok || b.isHtmlTrap || (b.statusCode ?? 500) >= 400)) {
        return false;
      }
      return true;
    };

    const primaryIdx = (() => {
      const ranged = reports.findIndex(
        (r, i) => isReportAndBenchHealthy(i) && r.supportsRanges && r.totalBytes !== null
      );
      if (ranged !== -1) return ranged;
      const anyHealthy = reports.findIndex((_, i) => isReportAndBenchHealthy(i));
      if (anyHealthy !== -1) return anyHealthy;
      return 0;
    })();
    const primary = reports[primaryIdx]!;
    const primaryBench = benchResults[primaryIdx];
    const hasTrustedDigest = Boolean(current.expectedMd5 || current.expectedSha256);

    const mirrorReports: MirrorProbeSummary[] = [];
    const includedEntries: Array<{ url: string; meta: MirrorSourceMeta; speed: number }> = [];
    const seenFinal = new Set<string>();
    const includedReports = [primary];

    for (let i = 0; i < reports.length; i++) {
      const r = reports[i]!;
      const bench = benchResults[i];
      const rawUrl = mirrorUrls[i]!;
      const primaryOk =
        !primary.probeError &&
        (primary.statusCode ?? 500) < 400 &&
        (!primaryBench || (primaryBench.ok && !primaryBench.isHtmlTrap));

      let included = true;
      let excludeReason: string | undefined;

      if (r.probeError || (r.statusCode ?? 500) >= 400) {
        included = false;
        excludeReason = r.probeError ?? `HTTP ${r.statusCode}`;
      } else if (bench && (!bench.ok || bench.isHtmlTrap || (bench.statusCode ?? 500) >= 400)) {
        included = false;
        excludeReason = bench.isHtmlTrap
          ? 'Returned HTML page instead of binary file'
          : bench.error ?? `HTTP ${bench.statusCode ?? 'error'}`;
      } else if (r.domainTrust === 'blocked') {
        included = false;
        excludeReason = 'Blocked domain';
      } else if (i !== primaryIdx) {
        if (!primaryOk) {
          included = false;
          excludeReason = 'Primary mirror failed safety/benchmark check';
        } else {
          const check = canCombineMirrorWithPrimary(
            {
              url: primary.finalUrl,
              supportsRanges: primary.supportsRanges,
              totalBytes: primary.totalBytes,
              etag: primary.etag ?? primaryBench?.etag,
              lastModified: primary.lastModified ?? primaryBench?.lastModified,
            },
            {
              url: r.finalUrl,
              supportsRanges: r.supportsRanges,
              totalBytes: r.totalBytes,
              etag: r.etag ?? bench?.etag,
              lastModified: r.lastModified ?? bench?.lastModified,
            },
            hasTrustedDigest
          );
          if (!check.eligible) {
            included = false;
            excludeReason = check.reason ?? 'Incompatible mirror validator';
          }
        }
      }

      if (included && seenFinal.has(r.finalUrl)) {
        included = false;
        excludeReason = 'Duplicate mirror endpoint';
      }

      if (included) {
        seenFinal.add(r.finalUrl);
        includedEntries.push({
          url: r.finalUrl,
          meta: {
            url: r.finalUrl,
            label: `Mirror #${i + 1} (${r.finalHost})`,
            host: r.finalHost,
            tier: 'mirror',
            etag: r.etag ?? bench?.etag,
            lastModified: r.lastModified ?? bench?.lastModified,
            provenance: candidates[i]?.provenance ?? `user_mirror:${r.finalHost}`,
          },
          speed: bench?.probeSpeedBps ?? 0,
        });
        if (r !== primary) includedReports.push(r);
      }

      mirrorReports.push({
        url: rawUrl,
        finalUrl: r.finalUrl,
        host: r.finalHost,
        statusCode: r.statusCode,
        totalBytes: r.totalBytes,
        supportsRanges: r.supportsRanges,
        riskLevel: bench?.isHtmlTrap ? 'high_risk' : r.riskLevel,
        included,
        excludeReason,
        label: `Mirror #${i + 1}`,
        tier: 'mirror',
        probeSpeedBps: bench?.probeSpeedBps,
        latencyMs: bench?.latencyMs,
        etag: r.etag ?? bench?.etag,
        lastModified: r.lastModified ?? bench?.lastModified,
        isHtmlTrap: bench?.isHtmlTrap,
        contentType: r.contentType ?? bench?.contentType,
        provenance: candidates[i]?.provenance,
      });
    }

    // Order included mirrors fastest-first based on concurrent Range benchmark
    includedEntries.sort((a, b) => b.speed - a.speed);
    const includedUrls = includedEntries.map((e) => e.url);
    const includedMeta = includedEntries.map((e) => e.meta);

    const signals = [...primary.signals];
    if (includedUrls.length >= 2) {
      signals.unshift({
        id: 'multi_mirror',
        level: 'ok',
        title: `Multi-Mirror Swarm Ready (${includedUrls.length} mirrors)`,
        detail: `Verified identical ${primary.totalBytes?.toLocaleString()} byte size, Range support, and matching strong validators across ${includedUrls.length} mirrors.`,
      });
    } else if (mirrorUrls.length >= 2 && !hasTrustedDigest) {
      signals.unshift({
        id: 'single_source_validator',
        level: 'info',
        title: 'Single-Source Validator Lock',
        detail:
          'Without a verified MD5/SHA-256 or matching strong ETags across mirrors, BoltGate restricts transfer to one validated source at a time.',
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
    if (primaryBench && (!primaryBench.ok || primaryBench.isHtmlTrap)) {
      worstRisk = 'error';
    }

    current.safety = {
      ...primary,
      riskLevel: worstRisk,
      signals,
      mirrorReports,
      sourceMode: includedUrls.length >= 2 ? 'swarm' : 'direct',
    };
    current.finalUrl = includedUrls[0] ?? primary.finalUrl;
    current.mirrorUrls = includedUrls.length > 0 ? includedUrls : [primary.finalUrl];
    current.mirrorMeta =
      includedMeta.length > 0
        ? includedMeta
        : [
            {
              url: primary.finalUrl,
              label: primary.finalHost,
              host: primary.finalHost,
              tier: 'direct',
              etag: primary.etag,
              lastModified: primary.lastModified,
              provenance: candidates[primaryIdx]?.provenance,
            },
          ];
    current.sourceMode = includedUrls.length >= 2 ? 'swarm' : 'direct';
    current.sourceBadge =
      includedUrls.length >= 2
        ? `Swarming ${includedUrls.length} mirrors`
        : `Single-source (${primary.finalHost})`;
    current.sourceProvenance = includedMeta[0]?.provenance ?? candidates[primaryIdx]?.provenance;
    current.filename = primary.suggestedFilename;
    current.category = primary.category;
    current.totalBytes = primary.totalBytes;
    current.supportsRanges = primary.supportsRanges;
    current.etag = primary.etag;
    current.lastModified = primary.lastModified;
    current.pinnedEtag = primary.etag;
    current.pinnedLastModified = primary.lastModified;

    const topSpeed = includedEntries[0]?.speed ?? 0;
    current.connections =
      current.mirrorUrls.length >= 2
        ? Math.min(16, Math.max(this.settings.segmentsPerDownload, current.mirrorUrls.length * 4))
        : current.supportsRanges && topSpeed >= 2 * 1024 * 1024
          ? Math.min(16, Math.max(8, this.settings.segmentsPerDownload))
          : this.settings.segmentsPerDownload;

    if (includedUrls.length >= 2) {
      current.routingLog = [
        {
          timestamp: Date.now(),
          level: 'ok',
          message: `Benchmarked ${mirrorUrls.length} mirrors -> swarming ${includedUrls.length} verified equal-validator sources`,
        },
      ];
    } else if (excludedMirrors.length > 0) {
      current.routingLog = [
        {
          timestamp: Date.now(),
          level: 'info',
          message: `Pinned single source (${primary.finalHost}); excluded ${excludedMirrors.length} mirror(s) (${excludedMirrors.map((e) => e.excludeReason).join('; ')})`,
        },
      ];
    }

    const effectiveDest = customDest?.trim()
      ? path.resolve(customDest.trim())
      : this.settings.organizeByCategory
        ? path.join(this.settings.downloadDir, primary.category)
        : this.settings.downloadDir;

    current.destinationDir = effectiveDest;
    const unique = await resolveUniquePath(effectiveDest, current.filename);
    current.filename = unique.filename;
    current.savedPath = unique.savedPath;
    // Keep partPath unset until exclusive staging reservation succeeds at download time
    current.partPath = '';
    current.status = 'pending_review';

    await this.syncOperationalSource(current);
    this.broadcast({ type: 'download_updated', data: current });
    this.persistImmediate();
  }

  private async runSmartBookResolution(
    item: DownloadItem,
    entry: Extract<ParsedInputEntry, { kind: 'annas_md5' | 'raw_md5' }>,
    customDest?: string
  ): Promise<void> {
    await this.refreshDiskSpace();
    const md5 = entry.md5;
    const sourcePageUrl = entry.kind === 'annas_md5' ? entry.sourcePageUrl : undefined;
    const apiKey = await this.secretStore.getAnnasArchiveApiKey();
    const resolved = await resolveBookSources({ md5, sourcePageUrl }, this.settings, {
      apiKey,
      allowInsecureLoopbackForTests: this.allowInsecureLoopbackProvider,
    });

    const current = this.downloads.find((d) => d.id === item.id);
    if (!current || this.removingIds.has(item.id)) return;

    const routingLog: RoutingLogEntry[] = [...resolved.routingLog];
    const filenameHint = resolved.filenameHint || `book-${md5.slice(0, 8)}`;

    const benchResults =
      resolved.candidates.length > 0
        ? await benchmarkCandidates(resolved.candidates, {
            concurrency: 5,
            filenameHint,
            secrets: this.cachedSecrets,
          })
        : [];

    const validHealthy = benchResults.filter((b) => {
      if (!b.ok || b.isHtmlTrap || (b.statusCode ?? 500) >= 400) return false;
      const trust = matchDomainTrust(b.finalHost, this.trustRules);
      return trust !== 'blocked';
    });

    // If zero HTTP/IPFS candidates worked but P2P sources were found, fall back to P2P
    if (validHealthy.length === 0 && (resolved.magnetLinks.length > 0 || resolved.torrentUrls.length > 0)) {
      current.routingLog = routingLog;
      if (resolved.magnetLinks[0]) {
        current.magnetUri = resolved.magnetLinks[0];
        await this.runP2PProbe(
          current,
          { kind: 'magnet', raw: resolved.magnetLinks[0], magnetUri: resolved.magnetLinks[0] },
          customDest
        );
        return;
      }
      if (resolved.torrentUrls[0]) {
        current.torrentUrl = resolved.torrentUrls[0];
        await this.runP2PProbe(
          current,
          {
            kind: 'torrent_url',
            raw: resolved.torrentUrls[0],
            url: resolved.torrentUrls[0],
            host: normalizeHostname(new URL(resolved.torrentUrls[0]).hostname),
          },
          customDest
        );
        return;
      }
    }

    if (validHealthy.length === 0) {
      const mirrorReports: MirrorProbeSummary[] = benchResults.map((b) => ({
        url: b.candidate.url,
        finalUrl: b.finalUrl,
        host: b.finalHost,
        statusCode: b.statusCode,
        totalBytes: b.totalBytes,
        supportsRanges: b.supportsRanges,
        riskLevel: b.isHtmlTrap ? 'high_risk' : 'error',
        included: false,
        excludeReason: b.error ?? 'Probe failed',
        label: b.candidate.label,
        tier: b.candidate.tier,
        probeSpeedBps: b.probeSpeedBps,
        latencyMs: b.latencyMs,
        isSlowPartner: b.candidate.isSlowPartner,
        etag: b.etag,
        lastModified: b.lastModified,
        isHtmlTrap: b.isHtmlTrap,
        contentType: b.contentType,
        provenance: b.candidate.provenance,
      }));

      const fallbackHost = sourcePageUrl
        ? normalizeHostname(new URL(sourcePageUrl).hostname)
        : 'md5-lookup';
      routingLog.push({
        timestamp: Date.now(),
        level: 'danger',
        message:
          benchResults.length > 0
            ? `All ${benchResults.length} candidate mirror(s) failed or returned HTML traps.`
            : 'No direct mirrors or IPFS CIDs resolved. Configure Fast Download API key or custom external mirror templates in Settings.',
      });

      current.routingLog = routingLog;
      current.expectedMd5 = md5;
      current.sourceBadge = 'No Fast Mirror';
      current.safety = {
        riskLevel: 'error',
        signals: [
          {
            id: 'resolution_failed',
            level: 'danger',
            title: 'No Working Download Mirrors Found',
            detail:
              benchResults.length > 0
                ? 'Candidate mirrors were rate-limited, unreachable, or returned HTML pages.'
                : 'No unthrottled mirrors or IPFS CIDs were discovered. Add your Fast Download API key or custom external mirror templates in Settings.',
          },
        ],
        finalUrl: current.originalUrl,
        finalHost: fallbackHost,
        initialHost: fallbackHost,
        redirectChain: [],
        supportsRanges: false,
        totalBytes: null,
        suggestedFilename: filenameHint,
        extension: path.extname(filenameHint).toLowerCase(),
        category: 'ebook',
        isExecutable: false,
        domainTrust: 'unknown',
        mirrorReports,
        expectedMd5: md5,
        resolvedCids: resolved.resolvedCids,
        probedAt: Date.now(),
        probeError: 'No working download source resolved for MD5',
      };
      current.status = 'pending_review';
      this.broadcast({ type: 'download_updated', data: current });
      this.persistImmediate();
      return;
    }

    const tierScore = (b: CandidateBenchmarkResult): number => {
      if (b.candidate.isSlowPartner) return 0;
      if (b.candidate.tier === 'fast_api') return 4;
      if (b.candidate.tier === 'ipfs' && (b.finalHost === '127.0.0.1' || b.finalHost === 'localhost'))
        return 3.5;
      if (b.candidate.tier === 'mirror') return 3;
      if (b.candidate.tier === 'ipfs') return 2;
      return 1;
    };

    validHealthy.sort((a, b) => {
      const slowDiff = (a.candidate.isSlowPartner ? 1 : 0) - (b.candidate.isSlowPartner ? 1 : 0);
      if (slowDiff !== 0) return slowDiff;
      const tierDiff = tierScore(b) - tierScore(a);
      if (tierDiff !== 0 && (tierScore(b) === 4 || tierScore(a) === 4)) return tierDiff;
      const rangeDiff = (b.supportsRanges ? 1 : 0) - (a.supportsRanges ? 1 : 0);
      if (rangeDiff !== 0) return rangeDiff;
      return b.probeSpeedBps - a.probeSpeedBps;
    });

    const primary = validHealthy[0]!;
    const includedUrls: string[] = [];
    const includedMeta: MirrorSourceMeta[] = [];
    const seenFinalUrls = new Set<string>();
    const includedBenchSet = new Set<CandidateBenchmarkResult>();

    const hasFastOrExternalPrimary =
      primary.candidate.tier === 'fast_api' ||
      (!primary.candidate.isSlowPartner && primary.probeSpeedBps >= 512 * 1024);

    for (const b of validHealthy) {
      if (seenFinalUrls.has(b.finalUrl)) continue;
      if (b !== primary) {
        if (!primary.supportsRanges || primary.totalBytes === null) continue;
        if (!b.supportsRanges || b.totalBytes !== primary.totalBytes) continue;
        if (b.candidate.isSlowPartner && hasFastOrExternalPrimary) continue;
      }
      seenFinalUrls.add(b.finalUrl);
      includedUrls.push(b.finalUrl);
      includedMeta.push({
        url: b.finalUrl,
        label: b.candidate.label,
        host: b.finalHost,
        tier: b.candidate.tier,
        isSlowPartner: b.candidate.isSlowPartner,
        etag: b.etag,
        lastModified: b.lastModified,
        provenance: b.candidate.provenance,
      });
      includedBenchSet.add(b);
    }

    const mirrorReports: MirrorProbeSummary[] = benchResults.map((b) => {
      const isIncluded = includedBenchSet.has(b);
      let excludeReason: string | undefined;
      if (!isIncluded) {
        if (!b.ok || b.isHtmlTrap || (b.statusCode ?? 500) >= 400) {
          excludeReason = b.error ?? `HTTP ${b.statusCode}`;
        } else if (matchDomainTrust(b.finalHost, this.trustRules) === 'blocked') {
          excludeReason = 'Blocked domain';
        } else if (b.candidate.isSlowPartner && hasFastOrExternalPrimary) {
          excludeReason = 'Deprioritized slow partner';
        } else if (!b.supportsRanges) {
          excludeReason = 'No byte-range support';
        } else if (primary.totalBytes !== null && b.totalBytes !== primary.totalBytes) {
          excludeReason = 'Size mismatch';
        } else {
          excludeReason = 'Duplicate endpoint';
        }
      }
      return {
        url: b.candidate.url,
        finalUrl: b.finalUrl,
        host: b.finalHost,
        statusCode: b.statusCode,
        totalBytes: b.totalBytes,
        supportsRanges: b.supportsRanges,
        riskLevel: b.isHtmlTrap ? 'high_risk' : b.ok ? 'safe' : 'error',
        included: isIncluded,
        excludeReason,
        label: b.candidate.label,
        tier: b.candidate.tier,
        probeSpeedBps: b.probeSpeedBps,
        latencyMs: b.latencyMs,
        isSlowPartner: b.candidate.isSlowPartner,
        etag: b.etag,
        lastModified: b.lastModified,
        isHtmlTrap: b.isHtmlTrap,
        contentType: b.contentType,
        provenance: b.candidate.provenance,
      };
    });

    const sourceMode: DownloadItem['sourceMode'] =
      includedUrls.length >= 2
        ? 'swarm'
        : primary.candidate.tier === 'fast_api'
          ? 'fast_api'
          : primary.candidate.tier === 'ipfs'
            ? 'ipfs_race'
            : 'direct';

    const sourceBadge =
      includedUrls.length >= 2
        ? `Swarming ${includedUrls.length} mirrors`
        : primary.candidate.tier === 'fast_api'
          ? 'Fast Download API'
          : primary.candidate.tier === 'ipfs'
            ? 'IPFS Race Winner'
            : primary.candidate.label;

    routingLog.push({
      timestamp: Date.now(),
      level: 'ok',
      message: `Selected ${sourceBadge}: primary ${primary.candidate.label} (${formatSpeedInline(primary.probeSpeedBps)} probe)`,
    });

    const safety = this.buildSafetyReportFromBenchmark(primary, {
      trustRules: this.trustRules,
      existingDownloads: this.downloads.filter((d) => d.id !== current.id),
      freeBytes: this.diskSpace.freeBytes || undefined,
      mirrorReports,
      expectedMd5: md5,
      resolvedCids: resolved.resolvedCids,
      sourceMode,
      sourceBadge,
      includedCount: includedUrls.length,
    });

    current.safety = safety;
    current.finalUrl = primary.finalUrl;
    current.mirrorUrls = includedUrls;
    current.mirrorMeta = includedMeta;
    current.expectedMd5 = md5;
    current.sourceMode = sourceMode;
    current.sourceBadge = sourceBadge;
    current.sourceProvenance = primary.candidate.provenance;
    current.routingLog = routingLog;
    current.filename = safety.suggestedFilename;
    current.category = safety.category;
    current.totalBytes = safety.totalBytes;
    current.supportsRanges = safety.supportsRanges;
    current.etag = safety.etag;
    current.lastModified = safety.lastModified;

    current.connections =
      includedUrls.length >= 2
        ? Math.min(16, Math.max(this.settings.segmentsPerDownload, includedUrls.length * 4))
        : primary.supportsRanges && primary.probeSpeedBps >= 2 * 1024 * 1024
          ? Math.min(16, Math.max(8, this.settings.segmentsPerDownload))
          : this.settings.segmentsPerDownload;

    await this.finalizeProbedItemDestination(current, customDest);
  }

  private async runIpfsResolution(
    item: DownloadItem,
    entry: Extract<ParsedInputEntry, { kind: 'ipfs_uri' }>,
    customDest?: string
  ): Promise<void> {
    await this.refreshDiskSpace();
    const gateways =
      this.settings.ipfsGateways.length > 0
        ? this.settings.ipfsGateways
        : [...DEFAULT_PUBLIC_IPFS_GATEWAYS];
    const candidates = expandIpfsCidToCandidates(entry.cid, gateways, entry.subPath);
    if (/^https?:\/\//i.test(entry.raw)) {
      const parsed = new URL(entry.raw);
      const host = normalizeHostname(parsed.hostname);
      if (!candidates.some((c) => c.url === entry.raw)) {
        candidates.unshift({
          url: entry.raw,
          label: `IPFS (${host})`,
          tier: 'ipfs',
          host,
          priority: 90,
          cid: entry.cid,
          subPath: entry.subPath,
          provenance: `ipfs:${host}`,
        });
      }
    }

    const benchResults = await benchmarkCandidates(candidates, {
      concurrency: 6,
      filenameHint: entry.filename,
      secrets: this.cachedSecrets,
    });

    const current = this.downloads.find((d) => d.id === item.id);
    if (!current || this.removingIds.has(item.id)) return;

    const healthy = benchResults
      .filter(
        (b) =>
          b.ok &&
          !b.isHtmlTrap &&
          (b.statusCode ?? 500) < 400 &&
          matchDomainTrust(b.finalHost, this.trustRules) !== 'blocked'
      )
      .sort((a, b) => b.probeSpeedBps - a.probeSpeedBps);

    const cidDisplay = entry.subPath ? `${entry.cid}/${entry.subPath}` : entry.cid;

    if (healthy.length === 0) {
      current.routingLog = [
        {
          timestamp: Date.now(),
          level: 'danger',
          message: `All ${candidates.length} IPFS gateways timed out or failed for CID ${cidDisplay.slice(0, 24)}…`,
        },
      ];
      current.safety = {
        riskLevel: 'error',
        signals: [
          {
            id: 'ipfs_failed',
            level: 'danger',
            title: 'No Responsive IPFS Gateways',
            detail: `Tested ${candidates.length} gateways for ${cidDisplay}; none returned a valid binary stream.`,
          },
        ],
        finalUrl: current.originalUrl,
        finalHost: 'ipfs',
        initialHost: 'ipfs',
        redirectChain: [],
        supportsRanges: false,
        totalBytes: null,
        suggestedFilename: entry.filename || `ipfs-${entry.cid.slice(0, 10)}`,
        extension: path.extname(entry.filename ?? '').toLowerCase(),
        category: classifyFile(entry.filename ?? '').category,
        isExecutable: false,
        domainTrust: 'unknown',
        resolvedCids: [cidDisplay],
        mirrorReports: benchResults.map((b) => ({
          url: b.candidate.url,
          finalUrl: b.finalUrl,
          host: b.finalHost,
          statusCode: b.statusCode,
          totalBytes: b.totalBytes,
          supportsRanges: b.supportsRanges,
          riskLevel: b.isHtmlTrap ? 'high_risk' : 'error',
          included: false,
          excludeReason: b.error ?? 'Failed',
          label: b.candidate.label,
          tier: 'ipfs',
          probeSpeedBps: b.probeSpeedBps,
          latencyMs: b.latencyMs,
          etag: b.etag,
          lastModified: b.lastModified,
          isHtmlTrap: b.isHtmlTrap,
          contentType: b.contentType,
          provenance: b.candidate.provenance,
        })),
        probedAt: Date.now(),
        probeError: 'IPFS race found no healthy gateway',
      };
      current.status = 'pending_review';
      this.broadcast({ type: 'download_updated', data: current });
      this.persistImmediate();
      return;
    }

    const primary = healthy[0]!;
    const hasTrustedDigest = Boolean(current.expectedMd5 || current.expectedSha256);
    const excludeReasonByBench = new Map<CandidateBenchmarkResult, string>();
    const included = healthy.filter((b) => {
      if (b === primary) return true;
      const check = canCombineMirrorWithPrimary(
        {
          url: primary.finalUrl,
          supportsRanges: primary.supportsRanges,
          totalBytes: primary.totalBytes,
          etag: primary.etag,
          lastModified: primary.lastModified,
        },
        {
          url: b.finalUrl,
          supportsRanges: b.supportsRanges,
          totalBytes: b.totalBytes,
          etag: b.etag,
          lastModified: b.lastModified,
        },
        hasTrustedDigest
      );
      if (!check.eligible) {
        excludeReasonByBench.set(b, check.reason ?? 'Incompatible validator');
        return false;
      }
      return true;
    });
    const includedSet = new Set(included);
    const sourceMode: DownloadItem['sourceMode'] = included.length >= 2 ? 'swarm' : 'ipfs_race';
    const sourceBadge =
      included.length >= 2 ? `Swarming ${included.length} IPFS gateways` : 'IPFS Race Winner';

    current.routingLog = [
      {
        timestamp: Date.now(),
        level: 'ok',
        message: `IPFS gateway race winner: ${primary.candidate.label} (${formatSpeedInline(primary.probeSpeedBps)})`,
      },
    ];
    current.finalUrl = primary.finalUrl;
    current.mirrorUrls = included.map((b) => b.finalUrl);
    current.mirrorMeta = included.map((b) => ({
      url: b.finalUrl,
      label: b.candidate.label,
      host: b.finalHost,
      tier: 'ipfs',
      etag: b.etag,
      lastModified: b.lastModified,
      provenance: b.candidate.provenance,
    }));
    current.sourceMode = sourceMode;
    current.sourceBadge = sourceBadge;
    current.sourceProvenance = primary.candidate.provenance;
    current.etag = primary.etag;
    current.lastModified = primary.lastModified;
    current.pinnedEtag = primary.etag;
    current.pinnedLastModified = primary.lastModified;
    current.safety = this.buildSafetyReportFromBenchmark(primary, {
      trustRules: this.trustRules,
      existingDownloads: this.downloads.filter((d) => d.id !== current.id),
      freeBytes: this.diskSpace.freeBytes || undefined,
      mirrorReports: benchResults.map((b) => ({
        url: b.candidate.url,
        finalUrl: b.finalUrl,
        host: b.finalHost,
        statusCode: b.statusCode,
        totalBytes: b.totalBytes,
        supportsRanges: b.supportsRanges,
        riskLevel: b.isHtmlTrap ? 'high_risk' : b.ok ? 'safe' : 'error',
        included: includedSet.has(b),
        excludeReason: includedSet.has(b)
          ? undefined
          : excludeReasonByBench.get(b) ?? b.error ?? 'Not selected',
        label: b.candidate.label,
        tier: 'ipfs',
        probeSpeedBps: b.probeSpeedBps,
        latencyMs: b.latencyMs,
        etag: b.etag,
        lastModified: b.lastModified,
        isHtmlTrap: b.isHtmlTrap,
        contentType: b.contentType,
        provenance: b.candidate.provenance,
      })),
      resolvedCids: [cidDisplay],
      sourceMode,
      sourceBadge,
      includedCount: included.length,
    });
    current.filename = current.safety.suggestedFilename;
    current.category = current.safety.category;
    current.totalBytes = current.safety.totalBytes;
    current.supportsRanges = current.safety.supportsRanges;
    current.connections =
      included.length >= 2
        ? Math.min(16, Math.max(this.settings.segmentsPerDownload, included.length * 4))
        : Math.min(16, Math.max(8, this.settings.segmentsPerDownload));

    await this.finalizeProbedItemDestination(current, customDest);
  }

  private async runP2PProbe(
    item: DownloadItem,
    entry: Extract<ParsedInputEntry, { kind: 'magnet' | 'torrent_url' }>,
    customDest?: string
  ): Promise<void> {
    await Promise.all([this.refreshDiskSpace(), this.refreshCapabilities()]);

    let torrentFiles: TorrentFileEntry[] | undefined;
    let torrentInfoHash: string | undefined;
    let torrentRootName: string | undefined;
    let pinnedManifestPath: string | undefined;
    let totalBytes: number | null = null;
    let suggestedFilename = item.filename;
    let probeError: string | undefined;
    let embeddedCredentialLeak = false;

    if (entry.kind === 'torrent_url') {
      try {
        const buf = await fetchSmallBuffer(entry.url, 10_000, 5 * 1024 * 1024, this.cachedSecrets);
        const meta = parseTorrentMetadata(buf);
        torrentFiles = meta.files;
        torrentInfoHash = meta.infoHash;
        torrentRootName = meta.name;
        totalBytes = meta.totalBytes;
        suggestedFilename = redactText(meta.name, this.cachedSecrets);
        embeddedCredentialLeak = meta.outboundUrls.some((u) => containsActiveSecret(u, this.cachedSecrets));

        // Encrypt raw .torrent bytes at rest so tracker passkeys/tokens never sit in plaintext on disk
        pinnedManifestPath = await this.secretStore.writeEncryptedManifest(item.id, buf);
      } catch (err) {
        probeError = sanitizeUpstreamError(err, this.cachedSecrets, 260);
      }
    }

    const current = this.downloads.find((d) => d.id === item.id);
    if (!current || this.removingIds.has(item.id)) {
      if (pinnedManifestPath) {
        await this.secretStore.deleteEncryptedManifest(pinnedManifestPath).catch(() => undefined);
      }
      return;
    }

    if (pinnedManifestPath) {
      this.pinnedTorrentPaths.set(current.id, pinnedManifestPath);
    }

    // Re-downloaded selection is bound to the original manifest identity: only keep it when the
    // re-inspected manifest is provably the same (infoHash) and every index still exists.
    let selectionNotice: string | undefined;
    if (current.selectFile) {
      const boundHash = current.selectFileInfoHash?.toLowerCase();
      const observedHash = (
        torrentInfoHash ?? (entry.kind === 'magnet' ? entry.infoHash : undefined)
      )?.toLowerCase();
      let keep = !(boundHash && observedHash && boundHash !== observedHash);
      if (keep && torrentFiles) {
        try {
          expandSelectFileIndices(current.selectFile, torrentFiles);
        } catch {
          keep = false;
        }
      }
      if (!keep) {
        selectionNotice = `Previous file selection (${current.selectFile}) was dropped: the re-inspected torrent manifest does not match the original`;
        current.selectFile = undefined;
        current.selectFileInfoHash = undefined;
      } else if (observedHash) {
        current.selectFileInfoHash = observedHash;
      }
    }

    const host = entry.kind === 'torrent_url' ? entry.host : 'bittorrent-dht';
    const domainTrust =
      entry.kind === 'torrent_url' ? matchDomainTrust(host, this.trustRules) : 'unknown';

    const fileClass = classifyFile(suggestedFilename);
    const hasExecInsideTorrent = Boolean(
      torrentFiles?.some((f) => classifyFile(path.basename(f.path)).isExecutable)
    );

    const signals: SafetySignal[] = [
      {
        id: 'p2p_source',
        level: this.capabilities.aria2Available ? 'info' : 'warn',
        title: this.capabilities.aria2Available
          ? `aria2c P2P Ready (v${this.capabilities.aria2Version})`
          : 'aria2c Required for P2P',
        detail: this.capabilities.aria2Available
          ? 'Companion detected aria2c for magnet/torrent transfers with zero-seed exit.'
          : `Install aria2c (${this.capabilities.installHint.command}) and restart/re-check to run magnet or .torrent downloads.`,
      },
    ];

    if (domainTrust === 'blocked') {
      signals.push({
        id: 'domain_trust',
        level: 'danger',
        title: 'Blocked Domain',
        detail: `${host} is on your Blocked Domains list.`,
      });
    }

    if (fileClass.isExecutable || hasExecInsideTorrent) {
      signals.push({
        id: 'filename_type',
        level: 'danger',
        title: 'Executable File in P2P Payload',
        detail: 'Torrent contains executable files. Only proceed if you trust the exact release.',
      });
    }

    if (probeError) {
      signals.push({
        id: 'torrent_probe',
        level: 'danger',
        title: 'Failed to Fetch .torrent Metadata',
        detail: probeError,
      });
    }

    if (embeddedCredentialLeak) {
      signals.push({
        id: 'embedded_credential',
        level: 'danger',
        title: 'Tracker / Web Seed Carries Your Credential',
        detail:
          'An embedded tracker or web-seed URL contains an active BoltGate credential. aria2c will refuse to dispatch it.',
      });
    }

    if (selectionNotice) {
      signals.push({
        id: 'selection_rebind',
        level: 'warn',
        title: 'File Selection Reset',
        detail: selectionNotice,
      });
    }

    if (totalBytes !== null && this.diskSpace.freeBytes > 0 && totalBytes > this.diskSpace.freeBytes * 0.98) {
      signals.push({
        id: 'disk_space',
        level: 'danger',
        title: 'Insufficient Disk Space',
        detail: 'Torrent size exceeds available disk space.',
      });
    }

    const riskLevel: RiskLevel = probeError
      ? 'error'
      : signals.some((s) => s.level === 'danger')
        ? 'high_risk'
        : signals.some((s) => s.level === 'warn')
          ? 'caution'
          : 'safe';

    current.filename = suggestedFilename;
    current.totalBytes = totalBytes;
    current.torrentFiles = torrentFiles;
    current.torrentInfoHash = torrentInfoHash;
    current.torrentRootName = torrentRootName;
    current.category = fileClass.category;
    current.engine = 'aria2';
    current.sourceMode = 'aria2_p2p';
    current.sourceBadge = 'aria2c P2P';
    current.supportsRanges = true;
    current.safety = {
      riskLevel,
      signals,
      finalUrl: current.originalUrl,
      finalHost: host,
      initialHost: host,
      redirectChain: [],
      supportsRanges: true,
      totalBytes,
      suggestedFilename,
      extension: fileClass.extension,
      category: fileClass.category,
      isExecutable: fileClass.isExecutable || hasExecInsideTorrent,
      domainTrust,
      torrentFiles,
      torrentInfoHash,
      sourceMode: 'aria2_p2p',
      isP2P: true,
      probedAt: Date.now(),
      probeError,
    };

    await this.finalizeProbedItemDestination(current, customDest, true);
  }

  private buildSafetyReportFromBenchmark(
    primary: CandidateBenchmarkResult,
    opts: {
      trustRules: TrustRule[];
      existingDownloads: DownloadItem[];
      freeBytes?: number;
      mirrorReports: MirrorProbeSummary[];
      expectedMd5?: string;
      resolvedCids?: string[];
      sourceMode: DownloadItem['sourceMode'];
      sourceBadge: string;
      includedCount: number;
    }
  ): SafetyReport {
    const fileClass = classifyFile(primary.suggestedFilename, primary.contentType);
    const mimeCheck = checkMimeExtensionMismatch(fileClass.extension, primary.contentType);
    const initialUrl = new URL(primary.candidate.url);
    const finalUrl = new URL(primary.finalUrl);
    const initialHost = normalizeHostname(initialUrl.hostname);
    const finalHost = primary.finalHost;
    const domainTrust = matchDomainTrust(finalHost, opts.trustRules);

    const signals: SafetySignal[] = [];

    if (opts.includedCount >= 2) {
      signals.push({
        id: 'multi_mirror',
        level: 'ok',
        title: `Swarming ${opts.includedCount} Verified Mirrors`,
        detail: `Verified identical ${primary.totalBytes?.toLocaleString() ?? 'matching'} byte size across ${opts.includedCount} fast sources.`,
      });
    } else {
      signals.push({
        id: 'resolved_source',
        level: 'ok',
        title: `${opts.sourceBadge}`,
        detail: `Benchmarked ${primary.candidate.label} at ${formatSpeedInline(primary.probeSpeedBps)} (${primary.latencyMs}ms).`,
      });
    }

    if (domainTrust === 'trusted') {
      signals.push({
        id: 'domain_trust',
        level: 'ok',
        title: 'Trusted Domain',
        detail: `${finalHost} is on your Trusted Domains list.`,
      });
    } else {
      signals.push({
        id: 'domain_trust',
        level: 'info',
        title: 'Unlisted Domain',
        detail: `${finalHost} is not yet in your Trust List — review signals below before approving.`,
      });
    }

    if (finalUrl.protocol === 'https:') {
      signals.push({
        id: 'transport',
        level: 'ok',
        title: 'Encrypted HTTPS',
        detail: primary.tls?.issuer ? `Issued by ${primary.tls.issuer}` : 'Verified TLS certificate.',
      });
    } else if (finalHost === '127.0.0.1' || finalHost === 'localhost') {
      signals.push({
        id: 'transport',
        level: 'info',
        title: 'Localhost HTTP',
        detail: 'Served directly from local machine (e.g., local IPFS gateway or test server).',
      });
    } else {
      signals.push({
        id: 'transport',
        level: 'warn',
        title: 'Unencrypted HTTP',
        detail: 'Transfer uses plain HTTP without TLS encryption.',
      });
    }

    if (fileClass.hasDoubleExtension || fileClass.isExecutable) {
      signals.push({
        id: 'filename_type',
        level: 'danger',
        title: fileClass.hasDoubleExtension
          ? 'Double-Extension Disguise'
          : `Executable / Script (${fileClass.extension})`,
        detail: 'Executable file detected; verify publisher before proceeding.',
      });
    } else {
      signals.push({
        id: 'filename_type',
        level: 'ok',
        title: `Non-Executable (${fileClass.extension || fileClass.category})`,
        detail: `Classified as ${fileClass.category}.`,
      });
    }

    if (mimeCheck.mismatch && mimeCheck.reason) {
      signals.push({
        id: 'mime_check',
        level: mimeCheck.severity ?? 'warn',
        title: 'Content-Type Mismatch',
        detail: mimeCheck.reason,
      });
    }

    if (isPrivateOrIpHost(finalHost) && finalHost !== '127.0.0.1' && finalHost !== 'localhost') {
      signals.push({
        id: 'private_ip',
        level: 'warn',
        title: 'Direct IP / Local Host',
        detail: `Hosted on ${finalHost}.`,
      });
    }

    signals.push({
      id: 'acceleration',
      level: primary.supportsRanges ? 'ok' : 'info',
      title: primary.supportsRanges ? 'Multi-Stream Acceleration Ready' : 'Single-Stream Server',
      detail: primary.supportsRanges
        ? 'Supports HTTP Range — adaptive multi-worker swarming and crash-safe resume enabled.'
        : 'Server does not advertise Range support; downloading as a single stream.',
    });

    if (primary.totalBytes !== null && opts.freeBytes !== undefined && primary.totalBytes > opts.freeBytes * 0.98) {
      signals.push({
        id: 'disk_space',
        level: 'danger',
        title: 'Insufficient Disk Space',
        detail: 'File size exceeds free disk space.',
      });
    }

    const riskLevel: RiskLevel = signals.some((s) => s.level === 'danger')
      ? 'high_risk'
      : signals.some((s) => s.level === 'warn')
        ? 'caution'
        : 'safe';

    return {
      riskLevel,
      signals,
      finalUrl: primary.finalUrl,
      finalHost,
      initialHost,
      redirectChain: primary.redirectChain,
      statusCode: primary.statusCode,
      contentType: primary.contentType,
      etag: primary.etag,
      lastModified: primary.lastModified,
      supportsRanges: primary.supportsRanges,
      totalBytes: primary.totalBytes,
      suggestedFilename: primary.suggestedFilename,
      extension: fileClass.extension,
      category: fileClass.category,
      isExecutable: fileClass.isExecutable,
      domainTrust,
      tls: primary.tls,
      mirrorReports: opts.mirrorReports,
      expectedMd5: opts.expectedMd5,
      resolvedCids: opts.resolvedCids,
      sourceMode: opts.sourceMode,
      probedAt: Date.now(),
    };
  }

  private async finalizeProbedItemDestination(
    current: DownloadItem,
    customDest?: string,
    skipAutoApprove = false
  ): Promise<void> {
    const effectiveDest = customDest?.trim()
      ? path.resolve(customDest.trim())
      : this.settings.organizeByCategory
        ? path.join(this.settings.downloadDir, current.category)
        : this.settings.downloadDir;

    if (this.removingIds.has(current.id)) return;
    current.destinationDir = effectiveDest;
    const unique = await resolveUniquePath(effectiveDest, current.filename);
    current.filename = unique.filename;
    current.savedPath = unique.savedPath;
    // Leave partPath unset until exclusive staging reservation succeeds
    if (!this.runners.has(current.id) && current.downloadedBytes === 0) {
      current.partPath = '';
    }
    await this.syncOperationalSource(current);

    if (
      !skipAutoApprove &&
      this.settings.autoApproveTrusted &&
      current.safety?.domainTrust === 'trusted' &&
      current.safety?.riskLevel === 'safe'
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

  private async runProbeForItem(item: DownloadItem, customDest?: string): Promise<void> {
    await this.refreshDiskSpace();
    const report = await probeUrl(item.originalUrl, {
      trustRules: this.trustRules,
      existingDownloads: this.downloads.filter((d) => d.id !== item.id),
      freeBytes: this.diskSpace.freeBytes || undefined,
      secrets: this.cachedSecrets,
    });

    const current = this.downloads.find((d) => d.id === item.id);
    if (!current || this.removingIds.has(item.id)) return;

    current.safety = report;
    current.finalUrl = report.finalUrl;
    current.filename = report.suggestedFilename;
    current.category = report.category;
    current.totalBytes = report.totalBytes;
    current.supportsRanges = report.supportsRanges;
    current.etag = report.etag;
    current.lastModified = report.lastModified;

    await this.finalizeProbedItemDestination(current, customDest);
  }

  async reprobeDownload(id: string): Promise<DownloadItem> {
    if (this.removingIds.has(id)) {
      throw new Error('Download is being removed');
    }
    const item = this.requireItem(id);
    if (this.runners.has(id)) {
      throw new Error('Cannot re-inspect an actively running download');
    }
    item.status = 'probing';
    item.error = undefined;
    this.broadcast({ type: 'download_updated', data: item });
    if (item.expectedMd5) {
      await this.runSmartBookResolution(
        item,
        item.originalUrl.startsWith('http')
          ? {
              kind: 'annas_md5',
              raw: item.originalUrl,
              md5: item.expectedMd5,
              sourcePageUrl: item.originalUrl,
              host: normalizeHostname(new URL(item.originalUrl).hostname),
            }
          : { kind: 'raw_md5', raw: item.expectedMd5, md5: item.expectedMd5 },
        item.destinationDir
      );
    } else if (item.torrentUrl) {
      await this.runP2PProbe(
        item,
        {
          kind: 'torrent_url',
          raw: item.torrentUrl,
          url: item.torrentUrl,
          host: normalizeHostname(new URL(item.torrentUrl).hostname),
        },
        item.destinationDir
      );
    } else {
      await this.runProbeForItem(item, item.destinationDir);
    }
    return this.sanitizeItemForExport(item);
  }

  async redownloadFromHistory(
    id: string
  ): Promise<{ items: DownloadItem[]; rejectedTokens: string[] }> {
    const item = this.requireItem(id);
    const ref = await this.secretStore.getOperationalSource(id);
    let sourceText = '';
    let mode: 'auto' | 'mirrors' = 'auto';

    if (ref?.torrentUrl) {
      sourceText = ref.torrentUrl;
    } else if (ref?.magnetUri) {
      sourceText = ref.magnetUri;
    } else if (ref?.mirrorUrls && ref.mirrorUrls.length >= 2) {
      sourceText = ref.mirrorUrls.join('\n');
      mode = 'mirrors';
    } else if (ref?.originalUrl) {
      sourceText = ref.originalUrl;
    } else if (item.expectedMd5) {
      sourceText = item.expectedMd5;
    } else {
      sourceText = item.originalUrl;
    }

    if (!sourceText || sourceText.includes('***')) {
      throw Object.assign(
        new Error(
          'Original source credentials are no longer available in the local vault; please paste the link again.'
        ),
        { status: 409 }
      );
    }

    return this.inspectRawText(sourceText, item.destinationDir, {
      mode,
      inherit: {
        expectedMd5: item.expectedMd5,
        expectedSha256: item.expectedSha256,
        selectFile: item.selectFile,
        torrentInfoHash: item.torrentInfoHash ?? ref?.torrentInfoHash,
      },
    });
  }

  async approveDownload(
    id: string,
    opts: {
      filename?: string;
      destinationDir?: string;
      connections?: number;
      trustDomain?: boolean;
      startNow?: boolean;
      engine?: DownloadEngine;
      selectFile?: string;
      expectedSha256?: string;
    } = {}
  ): Promise<DownloadItem> {
    if (this.removingIds.has(id)) {
      throw new Error('Download is being removed');
    }
    const item = this.requireItem(id);
    if (item.status === 'completed') {
      return this.sanitizeItemForExport(item);
    }
    const assertNotLocked = () => {
      if (item.status === 'downloading' || item.status === 'verifying' || this.runners.has(id)) {
        throw Object.assign(
          new Error('Cannot modify approval settings while download is active or verifying'),
          { status: 409 }
        );
      }
    };
    assertNotLocked();
    if (this.approvalLocks.has(id)) {
      throw Object.assign(new Error('Another approval for this download is already in progress'), {
        status: 409,
      });
    }

    this.approvalLocks.add(id);
    try {
      // Compute every approval parameter into locals FIRST; the live item is only mutated in one
      // synchronous commit after re-checking live job state (no half-applied approval can ever
      // change expectedSha256 / destination / selection of a job that started verifying meanwhile).
      let nextExpectedSha256 = item.expectedSha256;
      if (opts.expectedSha256 !== undefined) {
        const normalizedSha = opts.expectedSha256.trim().toLowerCase();
        if (normalizedSha && !/^[a-f0-9]{64}$/.test(normalizedSha)) {
          throw Object.assign(
            new Error('Expected SHA-256 must be a 64-character hexadecimal digest'),
            { status: 400 }
          );
        }
        nextExpectedSha256 = normalizedSha || undefined;
      }

      let nextEngine = item.engine;
      if (opts.engine === 'aria2' || opts.engine === 'node') {
        nextEngine = opts.engine;
      } else if (!item.magnetUri && !item.torrentUrl) {
        // HTTP(S) always stays on the guarded native transport (aria2c follows redirects that the
        // outbound credential guard cannot verify, and cannot enforce validators per range).
        nextEngine = 'node';
      }
      if ((nextEngine === 'aria2' || item.magnetUri || item.torrentUrl) && !this.settings.preferAria2 && opts.engine !== 'aria2') {
        throw new Error('aria2c delegation is disabled in Settings (preferAria2 is off).');
      }
      if ((nextEngine === 'aria2' || item.magnetUri || item.torrentUrl) && !this.capabilities.aria2Available) {
        throw new Error(
          `aria2c is required for P2P or aria2-mode downloads (${this.capabilities.installHint.command}).`
        );
      }

      const nextSelectFile =
        opts.selectFile !== undefined ? opts.selectFile.trim() || undefined : item.selectFile;
      let nextTotalBytes = item.totalBytes;
      let nextFilename = item.filename;
      let nextCategory = item.category;
      if (item.torrentFiles && item.torrentFiles.length > 0) {
        const selectedEntries = expandSelectFileIndices(nextSelectFile, item.torrentFiles);
        nextTotalBytes = selectedEntries.reduce((sum, entry) => sum + entry.length, 0);
        if (selectedEntries.length === 1 && !opts.filename?.trim()) {
          nextFilename = sanitizeFilename(path.basename(selectedEntries[0]!.path));
        }
      }
      const nextDestinationDir = opts.destinationDir?.trim()
        ? path.resolve(opts.destinationDir.trim())
        : item.destinationDir;
      if (opts.filename?.trim()) {
        nextFilename = sanitizeFilename(opts.filename.trim(), item.safety?.extension);
        nextCategory = classifyFile(nextFilename, item.safety?.contentType).category;
      }
      let nextConnections = item.connections;
      if (typeof opts.connections === 'number' && Number.isFinite(opts.connections)) {
        nextConnections = Math.max(1, Math.min(16, Math.round(opts.connections)));
      }

      const unique = await resolveUniquePath(nextDestinationDir, nextFilename);

      if (opts.trustDomain && item.safety?.finalHost) {
        await this.upsertTrustRule({
          domain: item.safety.finalHost,
          status: 'trusted',
          note: 'Trusted from Safety Gate',
        });
      }

      if (this.testHooks?.onDuringApproval) {
        await this.testHooks.onDuringApproval(id);
      }

      // Re-check LIVE job state immediately before committing / queueing / startNow
      // (status may have changed across the awaits above)
      if (this.removingIds.has(id) || !this.downloads.includes(item)) {
        throw new Error('Download was removed during approval');
      }
      if (liveStatus(item) === 'completed') {
        return this.sanitizeItemForExport(item);
      }
      assertNotLocked();

      // Single synchronous commit of the frozen approval contract
      item.expectedSha256 = nextExpectedSha256;
      item.engine = nextEngine;
      item.selectFile = nextSelectFile;
      if (nextSelectFile && item.torrentInfoHash) {
        item.selectFileInfoHash = item.torrentInfoHash.toLowerCase();
      }
      item.totalBytes = nextTotalBytes;
      item.destinationDir = nextDestinationDir;
      item.filename = unique.filename;
      item.savedPath = unique.savedPath;
      item.category = nextCategory;
      item.connections = nextConnections;
      // Leave partPath unset until runner exclusively reserves staging
      if (item.downloadedBytes === 0) {
        item.partPath = '';
      }
      item.userDeemedSafe = true;
      item.approvedAt = Date.now();
      item.error = undefined;
      item.status = 'queued';

      if (opts.startNow) {
        const minPrio = this.downloads.reduce((m, d) => Math.min(m, d.priority), 0);
        item.priority = minPrio - 1;
      }
      this.broadcast({ type: 'download_updated', data: item });
      this.persistImmediate();
      await this.syncOperationalSource(item);

      if (opts.startNow) {
        this.startRunner(item);
      } else {
        this.scheduleQueue();
      }
      return this.sanitizeItemForExport(item);
    } finally {
      this.approvalLocks.delete(id);
    }
  }

  /**
   * Bulk approval that preserves each row's own edits (SHA-256, torrent file selection, filename,
   * connections, engine). Every entry is validated BEFORE any row is approved, so one invalid
   * edited row never results in other rows being approved with silently dropped edits.
   */
  async approveBatch(
    input: Array<string | ApprovalEntry>,
    trustDomains = false
  ): Promise<DownloadItem[]> {
    const entries: ApprovalEntry[] = input
      .map((e) => (typeof e === 'string' ? { id: e } : e))
      .filter((e): e is ApprovalEntry => Boolean(e && typeof e.id === 'string' && e.id));

    for (const entry of entries) {
      const item = this.downloads.find((d) => d.id === entry.id);
      if (!item || item.status !== 'pending_review') continue;
      if (entry.expectedSha256 !== undefined) {
        const sha = String(entry.expectedSha256).trim().toLowerCase();
        if (sha && !/^[a-f0-9]{64}$/.test(sha)) {
          throw Object.assign(
            new Error(`Row "${item.filename}": expected SHA-256 must be a 64-character hexadecimal digest`),
            { status: 400 }
          );
        }
      }
      if (entry.selectFile !== undefined && item.torrentFiles && item.torrentFiles.length > 0) {
        try {
          expandSelectFileIndices(String(entry.selectFile).trim() || undefined, item.torrentFiles);
        } catch (err) {
          throw Object.assign(
            new Error(`Row "${item.filename}": ${err instanceof Error ? err.message : 'invalid file selection'}`),
            { status: 400 }
          );
        }
      }
    }

    const approved: DownloadItem[] = [];
    for (const entry of entries) {
      const item = this.downloads.find((d) => d.id === entry.id);
      if (!item || item.status !== 'pending_review') continue;
      approved.push(
        await this.approveDownload(entry.id, {
          trustDomain: trustDomains,
          filename: typeof entry.filename === 'string' ? entry.filename : undefined,
          destinationDir: typeof entry.destinationDir === 'string' ? entry.destinationDir : undefined,
          connections: typeof entry.connections === 'number' ? entry.connections : undefined,
          engine: entry.engine === 'aria2' || entry.engine === 'node' ? entry.engine : undefined,
          selectFile: typeof entry.selectFile === 'string' ? entry.selectFile : undefined,
          expectedSha256: typeof entry.expectedSha256 === 'string' ? entry.expectedSha256 : undefined,
        })
      );
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
    const handle = this.runners.get(id);
    if (handle) {
      await handle.runner.pause();
      // Await the single lifecycle promise (runner run + manager cleanup), never a polling loop
      await handle.done.catch(() => undefined);
    } else if (item.status === 'queued') {
      item.status = 'paused';
      item.speedBps = 0;
      item.etaSeconds = null;
      this.broadcast({ type: 'download_updated', data: item });
      this.persistImmediate();
    }
    this.scheduleQueue();
    return this.sanitizeItemForExport(item);
  }

  private async prepareRetryState(item: DownloadItem): Promise<void> {
    const failedDigestOrFormat =
      item.md5Verified === false ||
      item.verifiedHashMatch === false ||
      item.integrity?.status === 'corrupted' ||
      item.integrity?.status === 'html_trap';

    if (failedDigestOrFormat || (item.status === 'failed' && !item.supportsRanges)) {
      if (item.partPath && (await this.isVerifiedStagingOwnedByJob(item))) {
        await removePartMeta(item.partPath);
        await fs.rm(item.partPath, { recursive: true, force: true }).catch(() => undefined);
        item.partPath = '';
      }
      item.segments = [];
      item.downloadedBytes = 0;
      item.pinnedEtag = undefined;
      item.pinnedLastModified = undefined;
      item.md5 = undefined;
      item.sha256 = undefined;
      item.md5Verified = undefined;
      item.verifiedHashMatch = undefined;
      item.integrity = undefined;
    }
  }

  async resumeDownload(id: string, startNow = false): Promise<DownloadItem> {
    if (this.removingIds.has(id)) {
      throw new Error('Download is being removed');
    }
    const item = this.requireItem(id);
    if (!item.userDeemedSafe) {
      throw new Error('Download must be reviewed and deemed safe before starting');
    }
    if (item.status === 'downloading' || item.status === 'completed') {
      return this.sanitizeItemForExport(item);
    }

    // Rehydrate encrypted operational source if present so restored/restarted jobs never use `***` URLs
    const storedRef = await this.secretStore.getOperationalSource(item.id);
    if (storedRef) {
      this.applyOperationalSourceRef(item, storedRef);
    }

    await this.prepareRetryState(item);
    if (this.removingIds.has(id) || !this.downloads.includes(item)) {
      throw new Error('Download is being removed');
    }
    // Re-check live job state after the awaits above before queueing / startNow
    const statusNow = liveStatus(item);
    if (
      this.runners.has(id) ||
      statusNow === 'downloading' ||
      statusNow === 'verifying' ||
      statusNow === 'completed'
    ) {
      return this.sanitizeItemForExport(item);
    }
    item.error = undefined;
    item.status = 'queued';

    if (startNow) {
      const minPrio = this.downloads.reduce((m, d) => Math.min(m, d.priority), 0);
      item.priority = minPrio - 1;
      this.broadcast({ type: 'download_updated', data: item });
      this.persistImmediate();
      this.startRunner(item);
      return this.sanitizeItemForExport(item);
    }

    this.broadcast({ type: 'download_updated', data: item });
    this.persistImmediate();
    this.scheduleQueue();
    return this.sanitizeItemForExport(item);
  }

  reorderPriority(id: string, action: 'top' | 'up' | 'down'): DownloadItem {
    const item = this.requireItem(id);
    const ordered = this.downloads
      .filter((d) => d.status === 'queued' || d.status === 'paused')
      .sort((a, b) => a.priority - b.priority);

    const idx = ordered.findIndex((d) => d.id === id);
    if (idx === -1) return this.sanitizeItemForExport(item);

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
    return this.sanitizeItemForExport(item);
  }

  async removeDownload(id: string, deleteFile = false): Promise<{ id: string; undoable: boolean }> {
    const existingRemoval = this.inFlightRemovals.get(id);
    if (existingRemoval) {
      return existingRemoval;
    }

    const item = this.downloads.find((d) => d.id === id);
    if (!item) {
      throw new Error('Download not found');
    }

    this.removingIds.add(id);

    const removalPromise = (async () => {
      try {
        const handle = this.runners.get(id);
        if (handle) {
          await handle.runner.cancel(deleteFile);
          // Await the runner's whole lifecycle (including manager-side cleanup) before mutating
          await handle.done.catch(() => undefined);
          if (this.runners.get(id) === handle) {
            this.runners.delete(id);
          }
        }

        if (deleteFile) {
          // Require verified job ownership before deleting ANY staging artifact
          if (item.partPath && (await this.isVerifiedStagingOwnedByJob(item))) {
            await removePartMeta(item.partPath);
            await fs.rm(item.partPath, { recursive: true, force: true }).catch(() => {});
          }
          // Only delete published output files for genuinely completed jobs owned inside destinationDir
          if (item.status === 'completed' && item.completedAt) {
            const toDelete =
              item.publishedFiles && item.publishedFiles.length > 0
                ? item.publishedFiles
                : item.savedPath
                  ? [item.savedPath]
                  : [];
            for (const filePath of toDelete) {
              const resolved = path.resolve(filePath);
              if (!isPathInsideDir(resolved, item.destinationDir)) continue;
              const st = await fs.stat(resolved).catch(() => null);
              if (st?.isFile()) {
                await fs.unlink(resolved).catch(() => {});
              }
            }
          }
          const manifestPath = this.pinnedTorrentPaths.get(id);
          if (manifestPath) {
            await this.secretStore.deleteEncryptedManifest(manifestPath).catch(() => undefined);
            this.pinnedTorrentPaths.delete(id);
          }
          await this.secretStore.deleteOperationalSource(id);
        } else {
          // Keep encrypted operational source ref in secretStore so Undo restores live URLs
          // without storing unredacted URLs in memory trash or state.json!
          await this.syncOperationalSource(item);
          this.store.stashDeletedItem(this.sanitizeItemForExport(item));
        }

        // Remove by job ID *after* awaiting cancellation (never by pre-await index!)
        const liveIdx = this.downloads.findIndex((d) => d.id === id);
        if (liveIdx !== -1) {
          this.downloads.splice(liveIdx, 1);
        }
        this.broadcast({ type: 'download_removed', data: { id } });
        this.persistImmediate();
        this.scheduleQueue();
        return { id, undoable: !deleteFile };
      } finally {
        this.removingIds.delete(id);
        this.inFlightRemovals.delete(id);
      }
    })();

    this.inFlightRemovals.set(id, removalPromise);
    return removalPromise;
  }

  async restoreDownload(id: string): Promise<DownloadItem> {
    const restored = this.store.takeDeletedItem(id);
    if (!restored) {
      throw new Error('Undo window expired or item not found');
    }
    const storedRef = await this.secretStore.getOperationalSource(restored.id);
    if (storedRef) {
      this.applyOperationalSourceRef(restored, storedRef);
    }
    if (restored.status === 'downloading' || restored.status === 'verifying') {
      restored.status = 'paused';
      restored.speedBps = 0;
    }
    this.downloads.unshift(restored);
    this.broadcast({ type: 'download_updated', data: restored });
    this.persistImmediate();
    return this.sanitizeItemForExport(restored);
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
        await this.prepareRetryState(item);
        item.error = undefined;
        item.status = 'queued';
        this.broadcast({ type: 'download_updated', data: item });
      }
      this.persistImmediate();
      this.scheduleQueue();
      return { count: targets.length };
    }

    const completed = this.downloads.filter((d) => d.status === 'completed');
    if (completed.length === 0) return { count: 0 };

    const undoToken = crypto.randomUUID();
    for (const item of completed) {
      await this.syncOperationalSource(item);
    }
    this.store.stashDeletedBatch(
      undoToken,
      completed.map((c) => this.sanitizeItemForExport(c))
    );
    const removeIds = new Set(completed.map((d) => d.id));
    this.downloads = this.downloads.filter((d) => !removeIds.has(d.id));
    for (const id of removeIds) {
      this.broadcast({ type: 'download_removed', data: { id } });
    }
    this.persistImmediate();
    return { count: completed.length, undoToken };
  }

  async restoreBatch(token: string): Promise<DownloadItem[]> {
    const restored = this.store.takeDeletedBatch(token);
    if (!restored) {
      throw new Error('Undo window expired');
    }
    for (const item of restored) {
      const storedRef = await this.secretStore.getOperationalSource(item.id);
      if (storedRef) {
        this.applyOperationalSourceRef(item, storedRef);
      }
    }
    this.downloads = [...restored, ...this.downloads];
    for (const item of restored) {
      this.broadcast({ type: 'download_updated', data: item });
    }
    this.persistImmediate();
    return restored.map((item) => this.sanitizeItemForExport(item));
  }

  async verifyHash(
    id: string,
    expectedHash: string
  ): Promise<{ match: boolean; actual: string; expected: string; algorithm: 'sha256' | 'md5' }> {
    const item = this.requireItem(id);
    if (item.status !== 'completed') {
      throw new Error('Hash verification is available only after download completes');
    }
    const normalized = expectedHash.trim().toLowerCase();
    const isSha256 = /^[a-f0-9]{64}$/.test(normalized);
    const isMd5 = /^[a-f0-9]{32}$/.test(normalized);
    if (!isSha256 && !isMd5) {
      throw new Error('Expected checksum must be a 64-character SHA-256 or 32-character MD5 hex digest');
    }

    const expectedPath = item.savedPath;
    const prevCompletedAt = item.completedAt;
    const prevSha256 = item.sha256;

    // Open-handle hashing + live inode/stat comparison so file swaps during verification are detected
    const fh = await fs.open(expectedPath, 'r');
    let beforeStat: Awaited<ReturnType<typeof fh.stat>>;
    let diskHashes: { sha256: string; md5: string };
    let afterHandleStat: Awaited<ReturnType<typeof fh.stat>>;
    try {
      beforeStat = await fh.stat();
      diskHashes = await computeFileHandleHashes(fh);
      if (this.testHooks?.onDuringVerifyHash) {
        await this.testHooks.onDuringVerifyHash();
      }
      afterHandleStat = await fh.stat();
    } finally {
      await fh.close().catch(() => undefined);
    }

    const liveStat = await fs.stat(expectedPath).catch(() => null);
    if (
      !liveStat ||
      liveStat.dev !== beforeStat.dev ||
      liveStat.ino !== beforeStat.ino ||
      liveStat.size !== beforeStat.size ||
      liveStat.mtimeMs !== beforeStat.mtimeMs ||
      liveStat.ctimeMs !== beforeStat.ctimeMs ||
      afterHandleStat.size !== beforeStat.size ||
      afterHandleStat.mtimeMs !== beforeStat.mtimeMs
    ) {
      throw new Error('File at saved destination changed during checksum verification');
    }

    // Recheck job & file identity before applying late verification updates
    const live = this.downloads.find((d) => d.id === id);
    if (
      !live ||
      this.removingIds.has(id) ||
      live.status !== 'completed' ||
      live.savedPath !== expectedPath ||
      live.completedAt !== prevCompletedAt
    ) {
      throw new Error('Download changed or was removed while verifying checksum');
    }

    const fileMutated = Boolean(prevSha256 && diskHashes.sha256 !== prevSha256);
    live.sha256 = diskHashes.sha256;
    live.md5 = diskHashes.md5;

    if (isMd5) {
      const actual = diskHashes.md5;
      const match = actual.toLowerCase() === normalized;
      live.md5Verified = match;
      if (fileMutated) {
        live.verifiedHashMatch = undefined;
      }
      if (fileMutated || !match) {
        // Invalidate stale format verification badge when file changes or manual check fails
        live.integrity = undefined;
      }
      this.broadcast({ type: 'download_updated', data: live });
      this.persistImmediate();
      return { match, actual, expected: normalized, algorithm: 'md5' };
    }

    const actual = diskHashes.sha256;
    const match = actual.toLowerCase() === normalized;
    live.verifiedHashMatch = match;
    if (fileMutated) {
      live.md5Verified = undefined;
    }
    if (fileMutated || !match) {
      // Invalidate stale format verification badge when file changes or manual check fails
      live.integrity = undefined;
    }
    this.broadcast({ type: 'download_updated', data: live });
    this.persistImmediate();
    return { match, actual, expected: normalized, algorithm: 'sha256' };
  }

  async verifyIntegrity(id: string): Promise<FileIntegrityReport> {
    const item = this.requireItem(id);
    if (item.status !== 'completed') {
      throw new Error('Integrity verification is available only after download completes');
    }
    const expectedPath = item.savedPath;
    const prevCompletedAt = item.completedAt;
    const beforeStat = await fs.stat(expectedPath);
    const integrity = await verifyFileIntegrity(expectedPath, item.filename);
    const afterStat = await fs.stat(expectedPath).catch(() => null);
    if (
      !afterStat ||
      afterStat.dev !== beforeStat.dev ||
      afterStat.ino !== beforeStat.ino ||
      afterStat.size !== beforeStat.size ||
      afterStat.mtimeMs !== beforeStat.mtimeMs ||
      afterStat.ctimeMs !== beforeStat.ctimeMs
    ) {
      throw new Error('File at saved destination changed during integrity verification');
    }

    const live = this.downloads.find((d) => d.id === id);
    if (
      !live ||
      this.removingIds.has(id) ||
      live.status !== 'completed' ||
      live.savedPath !== expectedPath ||
      live.completedAt !== prevCompletedAt
    ) {
      throw new Error('Download changed or was removed while verifying integrity');
    }

    live.integrity = integrity;
    this.broadcast({ type: 'download_updated', data: live });
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

  async updateSettings(patch: SettingsPatch): Promise<{
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

    if (typeof patch.annasArchiveBaseUrl === 'string' && patch.annasArchiveBaseUrl.trim()) {
      const check = resolveApprovedProviderOrigin(
        patch.annasArchiveBaseUrl.trim(),
        this.allowInsecureLoopbackProvider
      );
      if (!check.origin) {
        throw new Error(check.reason ?? 'Invalid Anna’s Archive provider origin');
      }
      next.annasArchiveBaseUrl = check.origin;
    }
    // Resolve private templates BEFORE any write so an unresolvable/ambiguous masked entry
    // rejects the whole patch instead of overwriting another stored credential.
    const privateTemplatesPatch: { customMirrorUrls?: string[]; ipfsGateways?: string[] } = {};
    if (Array.isArray(patch.customMirrorUrls)) {
      next.customMirrorUrls = this.resolveTemplateEntries(
        patch.customMirrorUrls as TemplateEntryInput[],
        this.settings.customMirrorUrls,
        'custom mirror'
      );
      privateTemplatesPatch.customMirrorUrls = [...next.customMirrorUrls];
    }
    if (Array.isArray(patch.ipfsGateways)) {
      const resolvedGws = this.resolveTemplateEntries(
        patch.ipfsGateways as TemplateEntryInput[],
        this.settings.ipfsGateways,
        'IPFS gateway'
      );
      next.ipfsGateways = resolvedGws.length > 0 ? resolvedGws : [...DEFAULT_PUBLIC_IPFS_GATEWAYS];
      privateTemplatesPatch.ipfsGateways = [...next.ipfsGateways];
    }

    if (patch.annasArchiveApiKey !== undefined) {
      const hasKey = await this.secretStore.setAnnasArchiveApiKey(patch.annasArchiveApiKey);
      next.hasAnnasArchiveApiKey = hasKey;
      // In-place refresh: running runners/guards immediately see the rotated key
      await this.refreshCachedSecrets();
    }
    if (privateTemplatesPatch.customMirrorUrls || privateTemplatesPatch.ipfsGateways) {
      await this.secretStore.setPrivateTemplates(privateTemplatesPatch);
    }
    if (typeof patch.minSpeedFloorKBps === 'number' && Number.isFinite(patch.minSpeedFloorKBps)) {
      next.minSpeedFloorKBps = Math.max(0, Math.min(50_000, Math.round(patch.minSpeedFloorKBps)));
    }
    if (typeof patch.preferAria2 === 'boolean') {
      next.preferAria2 = patch.preferAria2;
    }

    this.settings = next;
    this.throttle.setLimitKBps(next.speedLimitKBps);
    await this.refreshDiskSpace();
    const safeSettings = this.sanitizeSettingsForExport();
    this.broadcast({
      type: 'settings_updated',
      data: { settings: safeSettings, diskSpace: this.diskSpace },
    });
    this.persistImmediate();
    this.scheduleQueue();
    return { settings: safeSettings, diskSpace: this.diskSpace };
  }

  /**
   * Resolves a template list from a settings PATCH using stable stored-template identities:
   * - `{ ref }` resolves ONLY to the exact stored template with that opaque identity;
   * - a plaintext line is taken as-is;
   * - a legacy masked line (`***`, no ref) resolves only when exactly ONE stored template masks to
   *   it — an ambiguous or unknown masked line is rejected (409), never guessed, so saving unchanged
   *   or adjacent templates can never overwrite another credential.
   */
  private resolveTemplateEntries(
    incoming: TemplateEntryInput[],
    existing: string[],
    label: string
  ): string[] {
    const byId = new Map<string, string>();
    for (const raw of existing) byId.set(this.templateId(raw), raw);
    const out: string[] = [];
    for (const entry of incoming) {
      if (entry && typeof entry === 'object') {
        const ref = typeof entry.ref === 'string' ? entry.ref : '';
        const raw = byId.get(ref);
        if (!raw) {
          throw Object.assign(
            new Error(`Stored ${label} template reference is stale or unknown; reload Settings and try again`),
            { status: 409 }
          );
        }
        out.push(raw);
        continue;
      }
      const line = String(entry ?? '').trim();
      if (!/^https?:\/\//i.test(line)) continue;
      if (line.includes('***')) {
        const matches = Array.from(
          new Set(existing.filter((raw) => redactSensitiveUrl(raw, this.cachedSecrets) === line))
        );
        if (matches.length !== 1) {
          throw Object.assign(
            new Error(
              `Masked ${label} template "${line}" is ${matches.length === 0 ? 'unknown' : 'ambiguous'}; re-enter the full template URL`
            ),
            { status: 409 }
          );
        }
        out.push(matches[0]!);
        continue;
      }
      out.push(line);
    }
    return out;
  }

  private scheduleQueue(): void {
    const activeCount = this.runners.size;
    const slots = this.settings.maxConcurrentDownloads - activeCount;
    if (slots <= 0) return;

    const perHostCap = Math.max(1, this.settings.maxConcurrentPerHost || 2);
    const activeByHost = new Map<string, number>();
    for (const handle of this.runners.values()) {
      const host = getItemHost(handle.runner.item);
      activeByHost.set(host, (activeByHost.get(host) ?? 0) + 1);
    }

    const queued = this.downloads
      .filter(
        (d) =>
          d.status === 'queued' &&
          d.userDeemedSafe &&
          !this.runners.has(d.id) &&
          !this.removingIds.has(d.id)
      )
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
    if (this.runners.has(item.id) || this.removingIds.has(item.id)) return;
    // Recheck live state right before dispatch: never start a removed / completed / unapproved job
    if (!this.downloads.includes(item) || !item.userDeemedSafe || item.status !== 'queued') return;

    let handle!: RunnerHandle;
    const isCurrent = () => this.runners.get(item.id) === handle;
    const onUpdate = (updated: DownloadItem, immediatePersist?: boolean) => {
      // Guard by exact runner-instance identity: a stale runner never broadcasts/persists
      if (this.removingIds.has(updated.id) || !isCurrent()) return;
      this.broadcast({ type: 'download_updated', data: updated });
      if (immediatePersist || Date.now() - this.lastPersistAt > 2000) {
        this.persistImmediate();
      }
    };

    const isP2P = Boolean(item.magnetUri || item.torrentUrl);
    // aria2c is used ONLY for P2P (embedded trackers / web seeds are validated before spawn).
    // HTTP(S) always stays on the guarded native transport: aria2c follows redirects the outbound
    // credential guard cannot verify, and cannot enforce per-range validators.
    const useAria2 =
      this.capabilities.aria2Available &&
      isP2P &&
      (item.engine === 'aria2' || this.settings.preferAria2);
    if (!isP2P && item.engine === 'aria2') {
      item.routingLog = [
        ...(item.routingLog ?? []),
        {
          timestamp: Date.now(),
          level: 'info',
          message:
            'HTTP transfer kept on the guarded native engine (aria2c redirects cannot be verified by the credential guard)',
        },
      ];
    }

    const manifestPath = this.pinnedTorrentPaths.get(item.id);

    const runner: ActiveRunner = useAria2
      ? new Aria2Runner({
          item,
          speedLimitKBps: this.settings.speedLimitKBps,
          binary: this.aria2Binary,
          binaryArgsPrefix: this.aria2BinaryArgsPrefix,
          // Only encrypted, vault-owned manifests are accepted (raw plaintext paths are rejected)
          readManifestBytes: manifestPath
            ? () => this.secretStore.readEncryptedManifest(manifestPath)
            : undefined,
          manifestScratchDir: this.secretStore.getManifestScratchDir(),
          secretsProvider: this.secretsProvider,
          rateLimiter: this.rateLimiter,
          onUpdate,
        })
      : new DownloadRunner({
          item,
          throttle: this.throttle,
          rateLimiter: this.rateLimiter,
          secretsProvider: this.secretsProvider,
          sourceIdKey: this.sourceIdKey,
          minSegmentBytes: this.minSegmentBytes,
          stallTimeoutMs: this.stallTimeoutMs,
          minSpeedFloorBps: this.settings.minSpeedFloorKBps * 1024,
          onUpdate,
        });

    // Register the handle BEFORE starting so identity guards are valid from the first callback
    handle = { runner, done: Promise.resolve() };
    this.runners.set(item.id, handle);
    this.ensureTelemetryLoop();

    // ONE promise covering runner setup -> transfer -> verification -> manager cleanup
    handle.done = (async () => {
      try {
        await runner.run();
      } catch {
        // Runners settle their own terminal state; never let a rejection escape the lifecycle
      } finally {
        // Only our own handle may clear the map entry / trigger follow-up (post-Undo race safe)
        if (isCurrent()) {
          this.runners.delete(item.id);
          if (item.status === 'completed') {
            void this.refreshDiskSpace().then(() => {
              this.broadcast({
                type: 'settings_updated',
                data: { settings: this.sanitizeSettingsForExport(), diskSpace: this.diskSpace },
              });
            });
          }
          this.persistImmediate();
          this.scheduleQueue();
        }
      }
    })();
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
          activeStreamsCount +=
            d.segments.filter((s) => s.status === 'active').length ||
            d.mirrorTelemetry?.reduce((sum, m) => sum + m.activeWorkers, 0) ||
            0;
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
    void this.store.save(this.buildPersistedState());
  }

  private sanitizeEvent(event: SSEEvent): SSEEvent {
    switch (event.type) {
      case 'download_updated':
        return { type: 'download_updated', data: this.sanitizeItemForExport(event.data) };
      case 'telemetry':
        return {
          type: 'telemetry',
          data: {
            ...event.data,
            downloads: event.data.downloads.map((d) => this.sanitizeItemForExport(d)),
          },
        };
      case 'settings_updated':
        return {
          type: 'settings_updated',
          data: {
            ...event.data,
            settings: this.sanitizeSettingsForExport(),
          },
        };
      default:
        return event;
    }
  }

  private broadcast(event: SSEEvent): void {
    const sanitized = this.sanitizeEvent(event);
    const payload = `data: ${JSON.stringify(sanitized)}\n\n`;
    const isTelemetry = sanitized.type === 'telemetry';
    for (const client of Array.from(this.sseClients.values())) {
      this.enqueueSsePayload(client, payload, isTelemetry);
    }
  }

  private sendEventToClient(client: SseClientState, event: SSEEvent): void {
    const sanitized = this.sanitizeEvent(event);
    const payload = `data: ${JSON.stringify(sanitized)}\n\n`;
    this.enqueueSsePayload(client, payload, sanitized.type === 'telemetry');
  }

  private enqueueSsePayload(client: SseClientState, payload: string, isTelemetry: boolean): void {
    if (client.res.writableEnded || client.res.destroyed) {
      this.sseClients.delete(client.res);
      return;
    }

    if (!client.draining && client.queue.length === 0 && !client.pendingTelemetry) {
      try {
        const ok = client.res.write(payload);
        if (!ok) {
          client.draining = true;
          client.res.once('drain', () => this.flushSseClient(client));
        }
      } catch {
        this.sseClients.delete(client.res);
      }
      return;
    }

    if (isTelemetry) {
      client.pendingTelemetry = payload;
      return;
    }

    client.queue.push(payload);
    if (client.queue.length > 100) {
      // Drop overwhelmed/stalled SSE consumer cleanly rather than buffering unboundedly
      this.sseClients.delete(client.res);
      client.res.end();
    }
  }

  private flushSseClient(client: SseClientState): void {
    if (client.res.writableEnded || client.res.destroyed) {
      this.sseClients.delete(client.res);
      return;
    }
    client.draining = false;

    while (client.queue.length > 0) {
      const next = client.queue.shift()!;
      try {
        if (!client.res.write(next)) {
          client.draining = true;
          client.res.once('drain', () => this.flushSseClient(client));
          return;
        }
      } catch {
        this.sseClients.delete(client.res);
        return;
      }
    }

    if (client.pendingTelemetry) {
      const tel = client.pendingTelemetry;
      client.pendingTelemetry = null;
      try {
        if (!client.res.write(tel)) {
          client.draining = true;
          client.res.once('drain', () => this.flushSseClient(client));
        }
      } catch {
        this.sseClients.delete(client.res);
      }
    }
  }
}

function fetchSmallBuffer(
  rawUrl: string,
  timeoutMs: number,
  maxBytes: number,
  secrets: readonly string[] = []
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const step = (target: URL, hop: number) => {
      try {
        assertOutboundUrlSafe(target.toString(), secrets);
      } catch (guardErr) {
        reject(guardErr);
        return;
      }
      const isHttps = target.protocol === 'https:';
      const client = isHttps ? https : http;
      let settled = false;

      const req = client.request(
        target,
        {
          method: 'GET',
          headers: { 'User-Agent': 'BoltGate/1.0 (+SafeDownloader)', Accept: '*/*' },
          timeout: timeoutMs,
          ...(isHttps ? { rejectUnauthorized: true } : {}),
        },
        (res) => {
          const status = res.statusCode ?? 0;
          if (status >= 300 && status < 400 && typeof res.headers.location === 'string') {
            res.destroy();
            if (hop >= 5) {
              if (!settled) {
                settled = true;
                reject(new Error('Too many redirects'));
              }
              return;
            }
            try {
              const nextUrl = new URL(res.headers.location, target);
              if (nextUrl.protocol !== 'http:' && nextUrl.protocol !== 'https:') {
                throw new Error(`Blocked unsafe redirect scheme: ${nextUrl.protocol}`);
              }
              assertOutboundUrlSafe(nextUrl.toString(), secrets);
              step(nextUrl, hop + 1);
            } catch (err) {
              if (!settled) {
                settled = true;
                reject(err);
              }
            }
            return;
          }
          if (status >= 400) {
            res.destroy();
            if (!settled) {
              settled = true;
              reject(new Error(`HTTP ${status}`));
            }
            return;
          }
          const chunks: Buffer[] = [];
          let total = 0;
          res.on('data', (chunk: Buffer) => {
            const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            total += buf.length;
            if (total > maxBytes) {
              res.destroy();
              if (!settled) {
                settled = true;
                reject(new Error('Metadata file too large'));
              }
              return;
            }
            chunks.push(buf);
          });
          res.on('end', () => {
            if (!settled) {
              settled = true;
              resolve(Buffer.concat(chunks));
            }
          });
          res.on('error', (err) => {
            if (!settled) {
              settled = true;
              reject(err);
            }
          });
        }
      );

      req.on('timeout', () => {
        if (!settled) {
          settled = true;
          const err = new Error(`Timed out after ${timeoutMs}ms`);
          req.destroy(err);
          reject(err);
        }
      });
      req.on('error', (err) => {
        if (!settled) {
          settled = true;
          reject(err);
        }
      });
      req.end();
    };
    step(new URL(rawUrl), 0);
  });
}

/** Reads an item's CURRENT status (defeats stale control-flow narrowing across awaits). */
function liveStatus(item: DownloadItem): DownloadItem['status'] {
  return item.status;
}

/**
 * Applies a history item's verification contract to a freshly inspected re-download item.
 * A torrent file selection is bound to the original manifest identity (infoHash): it is only
 * re-applied after re-inspection proves the same manifest (see runP2PProbe).
 */
function applyInheritedContract(
  item: DownloadItem,
  inherit: { expectedMd5?: string; expectedSha256?: string; selectFile?: string; torrentInfoHash?: string }
): void {
  const md5 = inherit.expectedMd5?.trim().toLowerCase();
  if (md5 && /^[a-f0-9]{32}$/.test(md5) && !item.expectedMd5) {
    item.expectedMd5 = md5;
  }
  const sha = inherit.expectedSha256?.trim().toLowerCase();
  if (sha && /^[a-f0-9]{64}$/.test(sha)) {
    item.expectedSha256 = sha;
  }
  if (inherit.selectFile?.trim() && (item.torrentUrl || item.magnetUri)) {
    item.selectFile = inherit.selectFile.trim();
    item.selectFileInfoHash = inherit.torrentInfoHash?.toLowerCase();
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

function formatSpeedInline(bps: number): string {
  if (!bps || bps <= 0) return '0 KB/s';
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

function extractRedactedUrlFilename(rawUrl: string, secrets: readonly string[]): string {
  try {
    const redacted = new URL(redactSensitiveUrl(rawUrl, secrets));
    const last = decodeURIComponentSafe(redacted.pathname.split('/').filter(Boolean).pop() ?? '');
    if (!last || last === '***') return '';
    return redactText(last, secrets);
  } catch {
    return '';
  }
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
