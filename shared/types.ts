export type DownloadStatus =
  | 'probing'
  | 'pending_review'
  | 'queued'
  | 'downloading'
  | 'paused'
  | 'verifying'
  | 'completed'
  | 'failed'
  | 'rejected';

export type RiskLevel = 'safe' | 'caution' | 'high_risk' | 'error';

export type FileCategory =
  | 'ebook'
  | 'video'
  | 'audio'
  | 'archive'
  | 'software'
  | 'document'
  | 'image'
  | 'disk'
  | 'other';

export type IntegrityStatus = 'valid' | 'corrupted' | 'html_trap' | 'unchecked';

export interface FileIntegrityReport {
  status: IntegrityStatus;
  format: string;
  summary: string;
  checks: string[];
  verifiedAt: number;
}

export interface SafetySignal {
  id: string;
  level: 'ok' | 'info' | 'warn' | 'danger';
  title: string;
  detail: string;
}

export interface RedirectHop {
  url: string;
  host: string;
  statusCode: number;
}

export interface TlsInfo {
  authorized: boolean;
  issuer?: string;
  subjectCN?: string;
  validTo?: string;
  error?: string;
}

export type SourceTier = 'fast_api' | 'mirror' | 'ipfs' | 'p2p' | 'direct';

export type SourceMode =
  | 'fast_api'
  | 'swarm'
  | 'ipfs_race'
  | 'aria2_p2p'
  | 'aria2_http'
  | 'direct';

export type DownloadEngine = 'node' | 'aria2';

export interface RoutingLogEntry {
  timestamp: number;
  level: 'info' | 'ok' | 'warn' | 'danger';
  message: string;
}

export interface MirrorSourceMeta {
  sourceId?: string;
  url: string;
  label: string;
  host: string;
  tier: SourceTier;
  isSlowPartner?: boolean;
  etag?: string;
  lastModified?: string;
  provenance?: string;
}

export interface MirrorTelemetry {
  sourceId?: string;
  url: string;
  label: string;
  host: string;
  tier: SourceTier;
  status: 'active' | 'standby' | 'evicted' | 'cooldown' | 'failed';
  speedBps: number;
  downloadedBytes: number;
  activeWorkers: number;
  failures: number;
  lastEvent?: string;
  provenance?: string;
}

export interface TorrentFileEntry {
  index: number;
  path: string;
  length: number;
}

export interface CompanionFeatureFlags {
  singleSourceValidatorLock: boolean;
  splitTelemetry: boolean;
  writeOnlySecrets: boolean;
  pairedSessionAuth: boolean;
}

export interface CompanionCapabilities {
  aria2Available: boolean;
  aria2Version?: string;
  aria2Path?: string;
  platform: string;
  companionVersion: string;
  apiVersion?: number;
  buildId?: string;
  requiresPairing?: boolean;
  features?: CompanionFeatureFlags;
  installHint: {
    command: string;
    label: string;
    platform: string;
  };
}

export interface MirrorProbeSummary {
  url: string;
  finalUrl: string;
  host: string;
  statusCode?: number;
  totalBytes: number | null;
  supportsRanges: boolean;
  riskLevel: RiskLevel;
  included: boolean;
  excludeReason?: string;
  label?: string;
  tier?: SourceTier;
  probeSpeedBps?: number;
  latencyMs?: number;
  isSlowPartner?: boolean;
  etag?: string;
  lastModified?: string;
  isHtmlTrap?: boolean;
  contentType?: string;
  provenance?: string;
}

export interface SafetyReport {
  riskLevel: RiskLevel;
  signals: SafetySignal[];
  finalUrl: string;
  finalHost: string;
  initialHost: string;
  redirectChain: RedirectHop[];
  statusCode?: number;
  contentType?: string;
  etag?: string;
  lastModified?: string;
  supportsRanges: boolean;
  totalBytes: number | null;
  suggestedFilename: string;
  extension: string;
  category: FileCategory;
  isExecutable: boolean;
  domainTrust: 'trusted' | 'blocked' | 'unknown';
  tls?: TlsInfo;
  duplicateOfId?: string;
  mirrorReports?: MirrorProbeSummary[];
  expectedMd5?: string;
  expectedSha256?: string;
  resolvedCids?: string[];
  torrentFiles?: TorrentFileEntry[];
  torrentInfoHash?: string;
  sourceMode?: SourceMode;
  isP2P?: boolean;
  probedAt: number;
  probeError?: string;
}

export interface SegmentState {
  id: number;
  start: number;
  end: number; // inclusive byte index; -1 for unknown total size single-stream
  downloaded: number;
  speedBps: number;
  status: 'pending' | 'active' | 'done' | 'paused' | 'error';
  retries: number;
  mirrorIndex?: number;
  lastError?: string;
}

export interface DownloadTelemetry {
  networkSpeedBps: number;
  diskSpeedBps: number;
  committedBytes: number;
  receivedBytes: number;
  throttledByLocalCap: boolean;
  configuredLocalCapBps?: number;
  localCapBps: number;
  serverThrottled?: boolean;
  backingOffHosts: string[];
  activeWorkers: number;
  /** Display-only total reported by an external engine's rounded progress line (never authoritative). */
  displayTotalBytes?: number;
}

export interface DownloadItem {
  id: string;
  originalUrl: string;
  finalUrl: string;
  mirrorUrls?: string[];
  mirrorMeta?: MirrorSourceMeta[];
  mirrorTelemetry?: MirrorTelemetry[];
  routingLog?: RoutingLogEntry[];
  filename: string;
  destinationDir: string;
  savedPath: string;
  partPath: string;
  category: FileCategory;
  status: DownloadStatus;
  priority: number;
  totalBytes: number | null;
  downloadedBytes: number;
  speedBps: number;
  avgSpeedBps: number;
  etaSeconds: number | null;
  connections: number;
  supportsRanges: boolean;
  etag?: string;
  lastModified?: string;
  pinnedEtag?: string;
  pinnedLastModified?: string;
  sourceProvenance?: string;
  telemetry?: DownloadTelemetry;
  segments: SegmentState[];
  safety: SafetyReport | null;
  expectedSha256?: string;
  sha256?: string;
  verifiedHashMatch?: boolean | null;
  expectedMd5?: string;
  md5?: string;
  md5Verified?: boolean | null;
  sourceMode?: SourceMode;
  sourceBadge?: string;
  engine?: DownloadEngine;
  magnetUri?: string;
  torrentUrl?: string;
  torrentInfoHash?: string;
  torrentRootName?: string;
  selectFile?: string;
  /** infoHash of the manifest `selectFile` indices refer to (selection identity binding). */
  selectFileInfoHash?: string;
  torrentFiles?: TorrentFileEntry[];
  publishedFiles?: string[];
  /**
   * Multi-file P2P: the manifest index / relative path of the ONE file a job-level MD5/SHA-256 was
   * verified against. `savedPath`, Open, and re-verification are bound to this same file.
   */
  verifiedFileIndex?: number;
  verifiedFilePath?: string;
  integrity?: FileIntegrityReport;
  createdAt: number;
  approvedAt?: number;
  startedAt?: number;
  completedAt?: number;
  error?: string;
  userDeemedSafe: boolean;
}

export type SpeedPreset = 'balanced' | 'turbo' | 'books' | 'background' | 'custom';

export interface AppSettings {
  downloadDir: string;
  organizeByCategory: boolean;
  maxConcurrentDownloads: number;
  maxConcurrentPerHost: number;
  segmentsPerDownload: number;
  speedLimitKBps: number; // 0 = unlimited
  speedPreset: SpeedPreset;
  autoApproveTrusted: boolean;
  theme: 'light' | 'dark';
  hasAnnasArchiveApiKey: boolean;
  annasArchiveBaseUrl: string;
  customMirrorUrls: string[];
  ipfsGateways: string[];
  minSpeedFloorKBps: number; // 0 = disabled; default 350
  preferAria2: boolean;
  /**
   * Stable opaque identities for each exported (possibly masked) private template entry,
   * index-aligned with `customMirrorUrls` / `ipfsGateways`.
   */
  templateRefs?: {
    customMirrorUrls: string[];
    ipfsGateways: string[];
  };
}

/** A private template entry sent back to the engine: plaintext, or a stable stored-template reference. */
export type TemplatePatchEntryValue = string | { ref: string };

export type SettingsPatch = Partial<
  Omit<AppSettings, 'hasAnnasArchiveApiKey' | 'templateRefs' | 'customMirrorUrls' | 'ipfsGateways'>
> & {
  annasArchiveApiKey?: string | null;
  customMirrorUrls?: TemplatePatchEntryValue[];
  ipfsGateways?: TemplatePatchEntryValue[];
};

export interface TrustRule {
  domain: string;
  status: 'trusted' | 'blocked';
  note: string;
  createdAt: number;
}

export interface DiskSpaceInfo {
  path: string;
  freeBytes: number;
  totalBytes: number;
}

export interface AppStats {
  pendingReviewCount: number;
  probingCount: number;
  activeCount: number;
  queuedCount: number;
  pausedCount: number;
  failedCount: number;
  completedCount: number;
  totalSpeedBps: number;
  activeStreamsCount: number;
  totalDownloadedBytes: number;
}

export interface AppStateSnapshot {
  downloads: DownloadItem[];
  settings: AppSettings;
  trustRules: TrustRule[];
  speedHistory: number[];
  stats: AppStats;
  diskSpace: DiskSpaceInfo;
  capabilities: CompanionCapabilities;
}

export type SSEEvent =
  | { type: 'snapshot'; data: AppStateSnapshot }
  | { type: 'telemetry'; data: { downloads: DownloadItem[]; speedHistory: number[]; stats: AppStats } }
  | { type: 'download_updated'; data: DownloadItem }
  | { type: 'download_removed'; data: { id: string } }
  | { type: 'settings_updated'; data: { settings: AppSettings; diskSpace: DiskSpaceInfo } }
  | { type: 'trust_updated'; data: TrustRule[] };
