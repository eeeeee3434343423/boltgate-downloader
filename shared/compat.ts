import type {
  AppSettings,
  AppStateSnapshot,
  AppStats,
  CompanionCapabilities,
  CompanionFeatureFlags,
  DiskSpaceInfo,
  DownloadItem,
  SpeedPreset,
  TemplatePatchEntryValue,
  TrustRule,
} from './types.js';

export const CURRENT_API_VERSION = 4;
export const DEFAULT_LOCAL_ENGINE = 'http://127.0.0.1:3847';

/**
 * Validates and normalizes a local Companion engine URL.
 * Only loopback http(s) origins without credentials or paths are accepted.
 */
export function validateLoopbackOrigin(rawUrl: string): string | null {
  const trimmed = rawUrl.trim();
  if (!trimmed) return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    if (parsed.username || parsed.password) return null;
    if (parsed.pathname && parsed.pathname !== '/' && parsed.pathname !== '') return null;
    if (parsed.search || parsed.hash) return null;
    const host = parsed.hostname.toLowerCase();
    if (host !== '127.0.0.1' && host !== 'localhost' && host !== '[::1]' && host !== '::1') {
      return null;
    }
    return parsed.origin;
  } catch {
    return null;
  }
}

/**
 * Formats a loopback listener origin, bracketing IPv6 literals (`http://[::1]:3847`).
 */
export function formatLoopbackOrigin(host: string, port: number | string, protocol = 'http'): string {
  const trimmed = host.trim().replace(/^\[|\]$/g, '');
  const hostPart = trimmed.includes(':') ? `[${trimmed}]` : trimmed;
  return `${protocol}://${hostPart}:${port}`;
}

/**
 * The engine origin and paired session a capability snapshot was actually fetched from.
 * A capability flag is only meaningful for the exact origin + session that reported it.
 */
export interface CapabilityBinding {
  origin: string;
  sessionToken: string;
}

export interface PinnedSecretWriteContext {
  engineOrigin: string;
  sessionToken: string;
  writeOnlySecrets: boolean;
  /** Origin the `writeOnlySecrets` capability was observed on. */
  capabilityOrigin: string;
  /** Session token used for the request that observed the capability. */
  capabilitySessionToken: string;
}

/**
 * Validates that a credential-bearing write (API key, private mirror / gateway templates) is
 * strictly pinned to the paired loopback origin, carries its bound session token, that the
 * `writeOnlySecrets` capability is literally `true` AND was observed on that same origin and
 * session, and that the engine has not silently drifted to a different origin in shared storage.
 */
export function assertPinnedSecretWriteContext(
  pinned: PinnedSecretWriteContext,
  currentStorageOrigin: string
): { engineOrigin: string; sessionToken: string } {
  if (!pinned || pinned.writeOnlySecrets !== true) {
    throw new Error('Secret write blocked: Companion does not advertise writeOnlySecrets support');
  }
  const normalizedPinned = validateLoopbackOrigin(String(pinned.engineOrigin ?? ''));
  if (!normalizedPinned) {
    throw new Error('Secret write blocked: invalid loopback engine origin');
  }
  const normalizedCapabilityOrigin = validateLoopbackOrigin(String(pinned.capabilityOrigin ?? ''));
  if (!normalizedCapabilityOrigin || normalizedCapabilityOrigin !== normalizedPinned) {
    throw new Error(
      'Secret write blocked: writeOnlySecrets capability was not reported by the pinned engine origin'
    );
  }
  const normalizedStorage = validateLoopbackOrigin(currentStorageOrigin);
  if (normalizedStorage && normalizedStorage !== normalizedPinned) {
    throw new Error(
      'Engine origin changed in another tab; re-pair with the active engine before saving API keys'
    );
  }
  const token = typeof pinned.sessionToken === 'string' ? pinned.sessionToken.trim() : '';
  if (!token) {
    throw new Error('Secret write blocked: missing active paired session token for this origin');
  }
  const capabilityToken =
    typeof pinned.capabilitySessionToken === 'string' ? pinned.capabilitySessionToken.trim() : '';
  if (!capabilityToken || capabilityToken !== token) {
    throw new Error(
      'Secret write blocked: writeOnlySecrets capability was not observed on the active paired session'
    );
  }
  return { engineOrigin: normalizedPinned, sessionToken: token };
}

/**
 * Validates that a non-secret but engine-specific request (e.g. bulk approval of reviewed rows)
 * still targets the origin + session the rows were loaded from.
 */
export function assertPinnedEngineBinding(
  binding: CapabilityBinding,
  currentStorageOrigin: string
): { engineOrigin: string; sessionToken: string } {
  const normalized = validateLoopbackOrigin(String(binding?.origin ?? ''));
  if (!normalized) {
    throw new Error('Request blocked: invalid loopback engine origin');
  }
  const normalizedStorage = validateLoopbackOrigin(currentStorageOrigin);
  if (normalizedStorage && normalizedStorage !== normalized) {
    throw new Error(
      'Engine origin changed in another tab; reload the Safety Gate from the active engine before approving'
    );
  }
  const token = typeof binding.sessionToken === 'string' ? binding.sessionToken.trim() : '';
  if (!token) {
    throw new Error('Request blocked: missing active paired session token for this origin');
  }
  return { engineOrigin: normalized, sessionToken: token };
}

/** A private template entry sent back to the engine: plaintext, or a stable stored-template reference. */
export type TemplatePatchEntry = TemplatePatchEntryValue;

/**
 * Maps edited template lines back to stable server-side template identities.
 * Lines that still equal a masked (`***`) display string are sent as `{ ref }` using a distinct
 * stored identity (preferring the same position), so unchanged or adjacent masked templates that
 * share an identical display string can never be resolved to another credential.
 */
export function buildTemplatePatchEntries(
  lines: readonly string[],
  savedDisplay: readonly string[],
  savedIds: readonly string[] | undefined
): TemplatePatchEntry[] {
  const ids = savedIds ?? [];
  const used = new Set<number>();
  return lines.map((line, lineIdx) => {
    if (!line.includes('***')) return line;
    const candidates: number[] = [];
    if (savedDisplay[lineIdx] === line && ids[lineIdx]) candidates.push(lineIdx);
    for (let i = 0; i < savedDisplay.length; i++) {
      if (i !== lineIdx && savedDisplay[i] === line && ids[i]) candidates.push(i);
    }
    const pick = candidates.find((i) => !used.has(i));
    if (pick === undefined) {
      // Unresolvable masked line: send as-is so the engine rejects it instead of guessing.
      return line;
    }
    used.add(pick);
    return { ref: ids[pick]! };
  });
}

export interface BulkApprovalRowEdits {
  filename?: string;
  connections?: number;
  engine?: 'node' | 'aria2';
  selectFile?: string;
  expectedSha256?: string;
}

export interface BulkApprovalEntry extends BulkApprovalRowEdits {
  id: string;
}

/**
 * Builds per-row bulk approval entries that carry every user edit (SHA-256, torrent file
 * selection, filename, connections, engine) instead of approving rows with defaults.
 */
export function buildBulkApprovalEntries(
  ids: readonly string[],
  edits: {
    names?: Record<string, string>;
    connections?: Record<string, number>;
    engines?: Record<string, 'node' | 'aria2'>;
    selectFiles?: Record<string, string>;
    expectedSha256?: Record<string, string>;
  }
): BulkApprovalEntry[] {
  return ids.map((id) => {
    const entry: BulkApprovalEntry = { id };
    const name = edits.names?.[id];
    if (typeof name === 'string' && name.trim()) entry.filename = name;
    const conns = edits.connections?.[id];
    if (typeof conns === 'number' && Number.isFinite(conns)) entry.connections = conns;
    const engine = edits.engines?.[id];
    if (engine === 'node' || engine === 'aria2') entry.engine = engine;
    const sel = edits.selectFiles?.[id];
    if (typeof sel === 'string') entry.selectFile = sel;
    const sha = edits.expectedSha256?.[id];
    if (typeof sha === 'string') entry.expectedSha256 = sha;
    return entry;
  });
}

export interface SettingsDraftSnapshot {
  downloadDir: string;
  speedInputKBps: string;
  annasBaseInput: string;
  customMirrorsText: string;
  ipfsGatewaysText: string;
  speedFloorInput: string;
}

export function buildSettingsDraftSnapshot(settings: AppSettings): SettingsDraftSnapshot {
  return {
    downloadDir: settings.downloadDir,
    speedInputKBps: String(settings.speedLimitKBps),
    annasBaseInput: settings.annasArchiveBaseUrl,
    customMirrorsText: (settings.customMirrorUrls ?? []).join('\n'),
    ipfsGatewaysText: (settings.ipfsGateways ?? DEFAULT_PUBLIC_IPFS_GATEWAYS).join('\n'),
    speedFloorInput: String(settings.minSpeedFloorKBps ?? 350),
  };
}

/**
 * Merges incoming saved settings into local form drafts, updating only fields
 * whose persisted server value actually changed since the previous snapshot.
 */
export function mergeSettingsDrafts(
  currentDraft: SettingsDraftSnapshot,
  prevSaved: SettingsDraftSnapshot,
  nextSaved: SettingsDraftSnapshot
): SettingsDraftSnapshot {
  return {
    downloadDir:
      nextSaved.downloadDir !== prevSaved.downloadDir ? nextSaved.downloadDir : currentDraft.downloadDir,
    speedInputKBps:
      nextSaved.speedInputKBps !== prevSaved.speedInputKBps
        ? nextSaved.speedInputKBps
        : currentDraft.speedInputKBps,
    annasBaseInput:
      nextSaved.annasBaseInput !== prevSaved.annasBaseInput
        ? nextSaved.annasBaseInput
        : currentDraft.annasBaseInput,
    customMirrorsText:
      nextSaved.customMirrorsText !== prevSaved.customMirrorsText
        ? nextSaved.customMirrorsText
        : currentDraft.customMirrorsText,
    ipfsGatewaysText:
      nextSaved.ipfsGatewaysText !== prevSaved.ipfsGatewaysText
        ? nextSaved.ipfsGatewaysText
        : currentDraft.ipfsGatewaysText,
    speedFloorInput:
      nextSaved.speedFloorInput !== prevSaved.speedFloorInput
        ? nextSaved.speedFloorInput
        : currentDraft.speedFloorInput,
  };
}

export const DEFAULT_PUBLIC_IPFS_GATEWAYS: readonly string[] = [
  'http://127.0.0.1:8080/ipfs/{cid}',
  'https://dweb.link/ipfs/{cid}',
  'https://ipfs.io/ipfs/{cid}',
  'https://cloudflare-ipfs.com/ipfs/{cid}',
  'https://w3s.link/ipfs/{cid}',
  'https://gateway.pinata.cloud/ipfs/{cid}',
];

export const DEFAULT_FEATURE_FLAGS: CompanionFeatureFlags = {
  singleSourceValidatorLock: false,
  splitTelemetry: false,
  writeOnlySecrets: false,
  pairedSessionAuth: false,
};

export function normalizeCapabilities(raw: unknown): CompanionCapabilities {
  const obj = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const hintObj =
    obj.installHint && typeof obj.installHint === 'object'
      ? (obj.installHint as Record<string, unknown>)
      : {};
  const featuresObj =
    obj.features && typeof obj.features === 'object'
      ? (obj.features as Record<string, unknown>)
      : {};

  const platform = typeof obj.platform === 'string' && obj.platform ? obj.platform : 'unknown';

  return {
    aria2Available: Boolean(obj.aria2Available),
    aria2Version: typeof obj.aria2Version === 'string' ? obj.aria2Version : undefined,
    aria2Path: typeof obj.aria2Path === 'string' ? obj.aria2Path : undefined,
    platform,
    companionVersion:
      typeof obj.companionVersion === 'string' && obj.companionVersion
        ? obj.companionVersion
        : 'legacy',
    apiVersion: typeof obj.apiVersion === 'number' && Number.isFinite(obj.apiVersion) ? obj.apiVersion : 1,
    buildId: typeof obj.buildId === 'string' ? obj.buildId : undefined,
    requiresPairing: typeof obj.requiresPairing === 'boolean' ? obj.requiresPairing : false,
    // Feature flags require a literal boolean `true` (never `Boolean("false")`-style coercion).
    features: {
      singleSourceValidatorLock: featuresObj.singleSourceValidatorLock === true,
      splitTelemetry: featuresObj.splitTelemetry === true,
      writeOnlySecrets: featuresObj.writeOnlySecrets === true,
      pairedSessionAuth: featuresObj.pairedSessionAuth === true,
    },
    installHint: {
      command:
        typeof hintObj.command === 'string' && hintObj.command
          ? hintObj.command
          : 'winget install aria2.aria2',
      label:
        typeof hintObj.label === 'string' && hintObj.label
          ? hintObj.label
          : 'Install aria2 CLI',
      platform:
        typeof hintObj.platform === 'string' && hintObj.platform
          ? hintObj.platform
          : platform,
    },
  };
}

const VALID_PRESETS = new Set<SpeedPreset>(['balanced', 'turbo', 'books', 'background', 'custom']);

export function normalizeSettings(raw: unknown, fallbackDownloadDir = ''): AppSettings {
  const obj = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const legacyKeyPresent =
    typeof obj.annasArchiveApiKey === 'string' && obj.annasArchiveApiKey.trim().length > 0;
  const preset =
    typeof obj.speedPreset === 'string' && VALID_PRESETS.has(obj.speedPreset as SpeedPreset)
      ? (obj.speedPreset as SpeedPreset)
      : 'balanced';

  const toFinite = (val: unknown, fallback: number): number =>
    typeof val === 'number' && Number.isFinite(val) ? val : fallback;

  const toStringList = (val: unknown, fallback: string[]): string[] =>
    Array.isArray(val)
      ? val.filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0)
      : fallback;

  return {
    downloadDir:
      typeof obj.downloadDir === 'string' ? obj.downloadDir : fallbackDownloadDir,
    organizeByCategory: typeof obj.organizeByCategory === 'boolean' ? obj.organizeByCategory : true,
    maxConcurrentDownloads: Math.max(1, toFinite(obj.maxConcurrentDownloads, 4)),
    maxConcurrentPerHost: Math.max(1, toFinite(obj.maxConcurrentPerHost, 2)),
    segmentsPerDownload: Math.max(1, toFinite(obj.segmentsPerDownload, 8)),
    speedLimitKBps: Math.max(0, toFinite(obj.speedLimitKBps, 0)),
    speedPreset: preset,
    autoApproveTrusted: Boolean(obj.autoApproveTrusted),
    theme: obj.theme === 'dark' ? 'dark' : 'light',
    hasAnnasArchiveApiKey: Boolean(obj.hasAnnasArchiveApiKey) || legacyKeyPresent,
    annasArchiveBaseUrl:
      typeof obj.annasArchiveBaseUrl === 'string' && obj.annasArchiveBaseUrl.trim()
        ? obj.annasArchiveBaseUrl.trim()
        : 'https://annas-archive.org',
    customMirrorUrls: toStringList(obj.customMirrorUrls, [
      'https://annas-archive.org/md5/{md5}',
      'https://libgen.li/ads.php?md5={md5}',
    ]),
    ipfsGateways: toStringList(obj.ipfsGateways, [...DEFAULT_PUBLIC_IPFS_GATEWAYS]),
    minSpeedFloorKBps: Math.max(0, toFinite(obj.minSpeedFloorKBps, 350)),
    preferAria2: typeof obj.preferAria2 === 'boolean' ? obj.preferAria2 : true,
    templateRefs: normalizeTemplateRefs(obj.templateRefs),
  };
}

function normalizeTemplateRefs(raw: unknown): AppSettings['templateRefs'] {
  if (!raw || typeof raw !== 'object') return undefined;
  const obj = raw as Record<string, unknown>;
  const ids = (val: unknown): string[] =>
    Array.isArray(val) ? val.map((v) => (typeof v === 'string' ? v : '')) : [];
  return {
    customMirrorUrls: ids(obj.customMirrorUrls),
    ipfsGateways: ids(obj.ipfsGateways),
  };
}

export function normalizeSnapshot(raw: unknown): AppStateSnapshot {
  const obj = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const statsObj =
    obj.stats && typeof obj.stats === 'object' ? (obj.stats as Record<string, unknown>) : {};
  const diskObj =
    obj.diskSpace && typeof obj.diskSpace === 'object'
      ? (obj.diskSpace as Record<string, unknown>)
      : {};

  const num = (v: unknown, fb = 0): number =>
    typeof v === 'number' && Number.isFinite(v) ? v : fb;

  const settings = normalizeSettings(obj.settings);
  const stats: AppStats = {
    pendingReviewCount: num(statsObj.pendingReviewCount),
    probingCount: num(statsObj.probingCount),
    activeCount: num(statsObj.activeCount),
    queuedCount: num(statsObj.queuedCount),
    pausedCount: num(statsObj.pausedCount),
    failedCount: num(statsObj.failedCount),
    completedCount: num(statsObj.completedCount),
    totalSpeedBps: num(statsObj.totalSpeedBps),
    activeStreamsCount: num(statsObj.activeStreamsCount),
    totalDownloadedBytes: num(statsObj.totalDownloadedBytes),
  };

  const diskSpace: DiskSpaceInfo = {
    path: typeof diskObj.path === 'string' ? diskObj.path : settings.downloadDir,
    freeBytes: num(diskObj.freeBytes),
    totalBytes: num(diskObj.totalBytes),
  };

  return {
    downloads: Array.isArray(obj.downloads) ? (obj.downloads as DownloadItem[]) : [],
    settings,
    trustRules: Array.isArray(obj.trustRules) ? (obj.trustRules as TrustRule[]) : [],
    speedHistory: Array.isArray(obj.speedHistory)
      ? obj.speedHistory.filter((n): n is number => typeof n === 'number' && Number.isFinite(n))
      : [],
    stats,
    diskSpace,
    capabilities: normalizeCapabilities(obj.capabilities),
  };
}

export function isCapabilitiesVersionCurrent(capabilities: CompanionCapabilities): boolean {
  return (capabilities.apiVersion ?? 1) >= CURRENT_API_VERSION;
}
