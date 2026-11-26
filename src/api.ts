import type {
  AppSettings,
  AppStateSnapshot,
  DiskSpaceInfo,
  DownloadItem,
  FileIntegrityReport,
  SSEEvent,
  TrustRule,
} from '../shared/types';

const STORAGE_KEY = 'boltgate_engine_url';
const DEFAULT_LOCAL_ENGINE = 'http://127.0.0.1:3847';

export function isRemoteHosted(): boolean {
  if (typeof window === 'undefined') return false;
  const host = window.location.hostname;
  return host !== '127.0.0.1' && host !== 'localhost';
}

export function getEngineBaseUrl(): string {
  if (!isRemoteHosted()) return '';
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY)?.trim();
    if (saved) return saved.replace(/\/+$/, '');
  } catch {
    // Ignore storage errors
  }
  return DEFAULT_LOCAL_ENGINE;
}

export function setEngineBaseUrl(nextUrl: string): string {
  const cleaned = nextUrl.trim().replace(/\/+$/, '') || DEFAULT_LOCAL_ENGINE;
  try {
    window.localStorage.setItem(STORAGE_KEY, cleaned);
  } catch {
    // Ignore storage errors
  }
  return cleaned;
}

function apiUrl(path: string): string {
  const base = getEngineBaseUrl();
  return `${base}${path}`;
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(apiUrl(path), {
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  });
  const text = await res.text();
  let data: Record<string, unknown> = {};
  if (text) {
    try {
      data = JSON.parse(text) as Record<string, unknown>;
    } catch {
      data = {};
    }
  }
  if (!res.ok) {
    const message = typeof data.error === 'string' ? data.error : res.statusText || 'Request failed';
    throw new Error(message);
  }
  return data as T;
}

export const api = {
  getEngineBaseUrl,
  setEngineBaseUrl,
  isRemoteHosted,

  getState: () => requestJson<AppStateSnapshot>('/api/state'),

  inspectLinks: (text: string, destinationDir?: string) =>
    requestJson<{ items: DownloadItem[]; rejectedTokens: string[] }>('/api/inspect', {
      method: 'POST',
      body: JSON.stringify({ text, destinationDir }),
    }),

  approveDownload: (
    id: string,
    opts: {
      filename?: string;
      destinationDir?: string;
      connections?: number;
      trustDomain?: boolean;
      startNow?: boolean;
    } = {}
  ) =>
    requestJson<{ item: DownloadItem }>(`/api/downloads/${encodeURIComponent(id)}/approve`, {
      method: 'POST',
      body: JSON.stringify(opts),
    }),

  approveBatch: (ids: string[], trustDomains = false) =>
    requestJson<{ items: DownloadItem[] }>('/api/downloads/approve-batch', {
      method: 'POST',
      body: JSON.stringify({ ids, trustDomains }),
    }),

  rejectDownload: (id: string, blockDomain = false) =>
    requestJson<{ id: string }>(`/api/downloads/${encodeURIComponent(id)}/reject`, {
      method: 'POST',
      body: JSON.stringify({ blockDomain }),
    }),

  pauseDownload: (id: string) =>
    requestJson<{ item: DownloadItem }>(`/api/downloads/${encodeURIComponent(id)}/pause`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  resumeDownload: (id: string, startNow = false) =>
    requestJson<{ item: DownloadItem }>(`/api/downloads/${encodeURIComponent(id)}/resume`, {
      method: 'POST',
      body: JSON.stringify({ startNow }),
    }),

  reprobeDownload: (id: string) =>
    requestJson<{ item: DownloadItem }>(`/api/downloads/${encodeURIComponent(id)}/reprobe`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  reorderPriority: (id: string, action: 'top' | 'up' | 'down') =>
    requestJson<{ item: DownloadItem }>(`/api/downloads/${encodeURIComponent(id)}/priority`, {
      method: 'POST',
      body: JSON.stringify({ action }),
    }),

  removeDownload: (id: string, deleteFile = false) =>
    requestJson<{ id: string; undoable: boolean }>(
      `/api/downloads/${encodeURIComponent(id)}?deleteFile=${deleteFile ? 'true' : 'false'}`,
      { method: 'DELETE' }
    ),

  restoreDownload: (id: string) =>
    requestJson<{ item: DownloadItem }>(`/api/downloads/${encodeURIComponent(id)}/restore`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  bulkAction: (action: 'pauseAll' | 'resumeAll' | 'retryFailed' | 'clearCompleted') =>
    requestJson<{ count: number; undoToken?: string }>('/api/downloads/bulk', {
      method: 'POST',
      body: JSON.stringify({ action }),
    }),

  restoreBatch: (token: string) =>
    requestJson<{ items: DownloadItem[] }>('/api/downloads/restore-batch', {
      method: 'POST',
      body: JSON.stringify({ token }),
    }),

  verifyHash: (id: string, expectedSha256: string) =>
    requestJson<{ match: boolean; actual: string; expected: string }>(
      `/api/downloads/${encodeURIComponent(id)}/verify-hash`,
      {
        method: 'POST',
        body: JSON.stringify({ expectedSha256 }),
      }
    ),

  verifyIntegrity: (id: string) =>
    requestJson<{ integrity: FileIntegrityReport }>(
      `/api/downloads/${encodeURIComponent(id)}/verify-integrity`,
      {
        method: 'POST',
        body: JSON.stringify({}),
      }
    ),

  openInFolder: (id: string) =>
    requestJson<{ ok: boolean }>(`/api/downloads/${encodeURIComponent(id)}/open-folder`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  openFile: (id: string) =>
    requestJson<{ ok: boolean }>(`/api/downloads/${encodeURIComponent(id)}/open-file`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  upsertTrustRule: (domain: string, status: 'trusted' | 'blocked', note = '') =>
    requestJson<{ trustRules: TrustRule[] }>('/api/trust', {
      method: 'POST',
      body: JSON.stringify({ domain, status, note }),
    }),

  deleteTrustRule: (domain: string) =>
    requestJson<{ trustRules: TrustRule[] }>(`/api/trust/${encodeURIComponent(domain)}`, {
      method: 'DELETE',
    }),

  updateSettings: (patch: Partial<AppSettings>) =>
    requestJson<{ settings: AppSettings; diskSpace: DiskSpaceInfo }>('/api/settings', {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),

  connectEvents: (onEvent: (ev: SSEEvent) => void, onStatusChange?: (connected: boolean) => void) => {
    const source = new EventSource(apiUrl('/api/events'));
    source.onopen = () => onStatusChange?.(true);
    source.onerror = () => onStatusChange?.(false);
    source.onmessage = (msg) => {
      try {
        const parsed = JSON.parse(msg.data) as SSEEvent;
        onEvent(parsed);
      } catch {
        // Ignore malformed ping
      }
    };
    return () => {
      source.close();
    };
  },
};
