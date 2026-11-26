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

export interface DownloadItem {
  id: string;
  originalUrl: string;
  finalUrl: string;
  mirrorUrls?: string[];
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
  segments: SegmentState[];
  safety: SafetyReport | null;
  sha256?: string;
  verifiedHashMatch?: boolean | null;
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
}

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
}

export type SSEEvent =
  | { type: 'snapshot'; data: AppStateSnapshot }
  | { type: 'telemetry'; data: { downloads: DownloadItem[]; speedHistory: number[]; stats: AppStats } }
  | { type: 'download_updated'; data: DownloadItem }
  | { type: 'download_removed'; data: { id: string } }
  | { type: 'settings_updated'; data: { settings: AppSettings; diskSpace: DiskSpaceInfo } }
  | { type: 'trust_updated'; data: TrustRule[] };
