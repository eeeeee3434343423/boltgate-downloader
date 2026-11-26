import {
  type BulkApprovalEntry,
  type CapabilityBinding,
  DEFAULT_LOCAL_ENGINE,
  type PinnedSecretWriteContext,
  assertPinnedEngineBinding,
  assertPinnedSecretWriteContext,
  normalizeCapabilities,
  normalizeSettings,
  normalizeSnapshot,
  validateLoopbackOrigin,
} from '../shared/compat';
import type {
  AppSettings,
  AppStateSnapshot,
  CompanionCapabilities,
  DiskSpaceInfo,
  DownloadEngine,
  DownloadItem,
  FileIntegrityReport,
  SSEEvent,
  SettingsPatch,
  TrustRule,
} from '../shared/types';

const STORAGE_KEY = 'boltgate_engine_url';
const LEGACY_SESSION_STORAGE_KEY = 'boltgate_session_token';
const SESSION_KEY_PREFIX = 'boltgate_session_v2::';

// Active session tokens are kept in-memory keyed by exact engine origin
// (and mirrored only into origin-scoped sessionStorage, never shared localStorage).
const memorySessionTokens = new Map<string, string>();
let activePairedOrigin: string | null = null;

export class PairingRequiredError extends Error {
  constructor(message = 'Companion pairing required') {
    super(message);
    this.name = 'PairingRequiredError';
  }
}

export { validateLoopbackOrigin };

export function isRemoteHosted(): boolean {
  if (typeof window === 'undefined') return false;
  const host = window.location.hostname;
  return host !== '127.0.0.1' && host !== 'localhost' && host !== '[::1]' && host !== '::1';
}

function purgeLegacyLocalStorageSession(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(LEGACY_SESSION_STORAGE_KEY);
  } catch {
    // Ignore storage errors
  }
}

export function getEngineBaseUrl(): string {
  if (!isRemoteHosted()) return '';
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY)?.trim();
    if (saved) {
      const validated = validateLoopbackOrigin(saved);
      if (validated) return validated;
      // Purge invalid/non-loopback stored origin
      window.localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore storage errors
  }
  return DEFAULT_LOCAL_ENGINE;
}

export function getEffectiveEngineOrigin(): string {
  if (isRemoteHosted()) {
    return getEngineBaseUrl();
  }
  if (typeof window !== 'undefined' && window.location?.origin) {
    return validateLoopbackOrigin(window.location.origin) ?? DEFAULT_LOCAL_ENGINE;
  }
  return DEFAULT_LOCAL_ENGINE;
}

export function setEngineBaseUrl(nextUrl: string): string {
  const trimmed = nextUrl.trim();
  const validated = trimmed ? validateLoopbackOrigin(trimmed) : DEFAULT_LOCAL_ENGINE;
  if (!validated) {
    throw new Error(
      'Engine address must be a valid loopback origin (e.g., http://127.0.0.1:3847 or http://localhost:3847)'
    );
  }

  const prevOrigin = getEffectiveEngineOrigin();
  try {
    window.localStorage.setItem(STORAGE_KEY, validated);
  } catch {
    // Ignore storage errors
  }

  // Whenever the engine origin changes, clear bound tokens so fresh pairing is required
  if (prevOrigin !== validated) {
    clearSessionToken(prevOrigin);
    clearSessionToken(validated);
    activePairedOrigin = null;
  }

  return validated;
}

function sessionKeyForOrigin(origin: string): string {
  return `${SESSION_KEY_PREFIX}${origin}`;
}

export function getSessionToken(originOverride?: string): string {
  purgeLegacyLocalStorageSession();
  const origin = originOverride ? validateLoopbackOrigin(originOverride) : getEffectiveEngineOrigin();
  if (!origin) return '';

  // Require the token to be bound to the active engine origin
  if (activePairedOrigin && activePairedOrigin !== origin) {
    return '';
  }

  const memToken = memorySessionTokens.get(origin);
  if (memToken) return memToken;

  if (typeof window !== 'undefined') {
    try {
      const stored = window.sessionStorage.getItem(sessionKeyForOrigin(origin))?.trim() ?? '';
      if (stored) {
        memorySessionTokens.set(origin, stored);
        activePairedOrigin = origin;
        return stored;
      }
    } catch {
      return '';
    }
  }
  return '';
}

export function setSessionToken(token: string, originOverride?: string): string {
  purgeLegacyLocalStorageSession();
  const origin = originOverride ? validateLoopbackOrigin(originOverride) : getEffectiveEngineOrigin();
  if (!origin) return '';
  const trimmed = token.trim();

  if (trimmed) {
    memorySessionTokens.set(origin, trimmed);
    activePairedOrigin = origin;
  } else {
    memorySessionTokens.delete(origin);
    if (activePairedOrigin === origin) {
      activePairedOrigin = null;
    }
  }

  if (typeof window !== 'undefined') {
    try {
      const key = sessionKeyForOrigin(origin);
      if (trimmed) {
        window.sessionStorage.setItem(key, trimmed);
      } else {
        window.sessionStorage.removeItem(key);
      }
    } catch {
      // Ignore storage errors
    }
  }
  return trimmed;
}

export function clearSessionToken(originOverride?: string): void {
  setSessionToken('', originOverride);
}

/**
 * Reads and immediately removes any one-time pairing code injected into same-origin local HTML.
 */
export function consumeInlinePairingCode(): string {
  if (typeof document === 'undefined' || isRemoteHosted()) return '';
  const meta = document.querySelector('meta[name="boltgate-pairing-code"]');
  const code = meta?.getAttribute('content')?.trim() ?? '';
  meta?.remove();
  return code;
}

function apiUrl(path: string): string {
  const base = getEngineBaseUrl();
  return `${base}${path}`;
}

function pinnedUrl(origin: string, path: string): string {
  const validated = validateLoopbackOrigin(origin);
  if (!validated) {
    throw new Error('Blocked request to invalid non-loopback engine origin');
  }
  return !isRemoteHosted() && typeof window !== 'undefined' && window.location.origin === validated
    ? path
    : `${validated}${path}`;
}

/**
 * Captures the engine origin + session token BEFORE a request so the response (and any
 * capability flags it carries) is bound to exactly where it came from.
 */
function captureBinding(): CapabilityBinding {
  return { origin: getEffectiveEngineOrigin(), sessionToken: getSessionToken() };
}

interface RequestJsonOptions extends RequestInit {
  pinnedOrigin?: string;
  pinnedToken?: string;
}

async function requestJson<T>(path: string, init?: RequestJsonOptions): Promise<T> {
  const { pinnedOrigin, pinnedToken, ...fetchInit } = init ?? {};
  const token = pinnedToken !== undefined ? pinnedToken : getSessionToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((fetchInit.headers as Record<string, string> | undefined) ?? {}),
  };
  if (token && !headers['X-BoltGate-Session']) {
    headers['X-BoltGate-Session'] = token;
  }

  const targetUrl = pinnedOrigin ? pinnedUrl(pinnedOrigin, path) : apiUrl(path);

  const res = await fetch(targetUrl, {
    ...fetchInit,
    headers,
    // Reject HTTP redirects on all credential-bearing companion API requests
    redirect: 'error',
  });

  if (res.redirected || (res.status >= 300 && res.status < 400)) {
    throw new Error('Blocked unexpected redirect on companion API request');
  }

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
    if (res.status === 401 || data.requiresPairing === true) {
      throw new PairingRequiredError(message);
    }
    throw new Error(message);
  }
  return data as T;
}

export const api = {
  getEngineBaseUrl,
  getEffectiveEngineOrigin,
  setEngineBaseUrl,
  getSessionToken,
  setSessionToken,
  clearSessionToken,
  consumeInlinePairingCode,
  isRemoteHosted,

  fetchHealth: () =>
    requestJson<{
      ok: boolean;
      apiVersion?: number;
      companionVersion?: string;
      requiresPairing?: boolean;
    }>('/api/health'),

  pairSession: async (codeOrToken: string) => {
    const trimmed = codeOrToken.trim();
    const targetOrigin = getEffectiveEngineOrigin();
    const res = await requestJson<{
      paired: boolean;
      sessionToken?: string;
      apiVersion?: number;
      capabilities?: CompanionCapabilities;
    }>('/api/session/pair', {
      method: 'POST',
      headers: { 'X-BoltGate-Session': trimmed },
      body: JSON.stringify({ code: trimmed, token: trimmed }),
    });
    if (res.paired) {
      setSessionToken(res.sessionToken ?? trimmed, targetOrigin);
    }
    return {
      paired: Boolean(res.paired),
      apiVersion: res.apiVersion ?? 4,
      capabilities: normalizeCapabilities(res.capabilities),
    };
  },

  bootstrapLocalSession: async (): Promise<boolean> => {
    if (getSessionToken()) return true;
    const inlineCode = consumeInlinePairingCode();
    if (!inlineCode) return false;
    try {
      const res = await api.pairSession(inlineCode);
      return res.paired;
    } catch {
      return false;
    }
  },

  issuePairingCode: () =>
    requestJson<{ code: string; expiresAt: number }>('/api/session/pairing-code', {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  getState: async (): Promise<AppStateSnapshot> => {
    const { snapshot } = await api.getStateBound();
    return snapshot;
  },

  /**
   * Loads state pinned to the origin + session captured before the request, returning that
   * binding so capability flags are only ever trusted for the engine that reported them.
   */
  getStateBound: async (): Promise<{ snapshot: AppStateSnapshot; binding: CapabilityBinding }> => {
    await api.bootstrapLocalSession();
    const binding = captureBinding();
    const raw = await requestJson<unknown>('/api/state', {
      pinnedOrigin: binding.origin,
      pinnedToken: binding.sessionToken,
    });
    return { snapshot: normalizeSnapshot(raw), binding };
  },

  getCapabilities: async (): Promise<CompanionCapabilities> => {
    const { capabilities } = await api.getCapabilitiesBound();
    return capabilities;
  },

  getCapabilitiesBound: async (): Promise<{
    capabilities: CompanionCapabilities;
    binding: CapabilityBinding;
  }> => {
    const binding = captureBinding();
    const raw = await requestJson<unknown>('/api/capabilities', {
      pinnedOrigin: binding.origin,
      pinnedToken: binding.sessionToken,
    });
    return { capabilities: normalizeCapabilities(raw), binding };
  },

  inspectLinks: (
    text: string,
    destinationDir?: string,
    mode?: 'auto' | 'separate' | 'mirrors'
  ) =>
    requestJson<{ items: DownloadItem[]; rejectedTokens: string[] }>('/api/inspect', {
      method: 'POST',
      body: JSON.stringify({ text, destinationDir, mode }),
    }),

  inspectMirrors: (text: string, destinationDir?: string) =>
    requestJson<{ items: DownloadItem[]; rejectedTokens: string[] }>('/api/inspect-mirrors', {
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
      engine?: DownloadEngine;
      selectFile?: string;
      expectedSha256?: string;
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

  /**
   * Bulk approval carrying each row's edits (SHA-256, torrent file selection, …), pinned to the
   * engine origin + session the reviewed rows were loaded from.
   */
  approveBatchEntries: (
    entries: BulkApprovalEntry[],
    binding: CapabilityBinding,
    trustDomains = false
  ) => {
    const verified = assertPinnedEngineBinding(binding, getEffectiveEngineOrigin());
    return requestJson<{ items: DownloadItem[] }>('/api/downloads/approve-batch', {
      method: 'POST',
      pinnedOrigin: verified.engineOrigin,
      pinnedToken: verified.sessionToken,
      body: JSON.stringify({ entries, trustDomains }),
    });
  },

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

  redownloadFromHistory: (id: string) =>
    requestJson<{ items: DownloadItem[]; rejectedTokens: string[] }>(
      `/api/downloads/${encodeURIComponent(id)}/redownload`,
      {
        method: 'POST',
        body: JSON.stringify({}),
      }
    ),

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

  verifyHash: (id: string, expectedHash: string) =>
    requestJson<{ match: boolean; actual: string; expected: string; algorithm?: 'sha256' | 'md5' }>(
      `/api/downloads/${encodeURIComponent(id)}/verify-hash`,
      {
        method: 'POST',
        body: JSON.stringify({ expectedHash }),
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

  updateSettings: async (patch: SettingsPatch) => {
    const res = await requestJson<{ settings: AppSettings; diskSpace: DiskSpaceInfo }>(
      '/api/settings',
      {
        method: 'PATCH',
        body: JSON.stringify(patch),
      }
    );
    return {
      settings: normalizeSettings(res.settings),
      diskSpace: res.diskSpace,
    };
  },

  /**
   * Credential-bearing writes (Save Key / Clear Key, private mirror & gateway templates) are
   * strictly pinned to the captured paired origin, active session token, and an explicit
   * `writeOnlySecrets === true` capability observed on that same origin + session—never
   * re-reading a drifted engine URL from shared localStorage mid-operation.
   */
  updateSecretSettings: async (patch: SettingsPatch, pinned: PinnedSecretWriteContext) => {
    const currentStorageOrigin = getEffectiveEngineOrigin();
    const verified = assertPinnedSecretWriteContext(pinned, currentStorageOrigin);
    const boundToken = getSessionToken(verified.engineOrigin);
    if (!boundToken || boundToken !== verified.sessionToken) {
      throw new PairingRequiredError(
        'Active session no longer matches the paired engine origin; please re-pair before saving secrets'
      );
    }
    const res = await requestJson<{ settings: AppSettings; diskSpace: DiskSpaceInfo }>(
      '/api/settings',
      {
        method: 'PATCH',
        pinnedOrigin: verified.engineOrigin,
        pinnedToken: verified.sessionToken,
        body: JSON.stringify(patch),
      }
    );
    return {
      settings: normalizeSettings(res.settings),
      diskSpace: res.diskSpace,
    };
  },

  connectEvents: (
    onEvent: (ev: SSEEvent) => void,
    onStatusChange?: (connected: boolean) => void,
    binding?: CapabilityBinding
  ) => {
    const token = binding ? binding.sessionToken : getSessionToken();
    const eventsPath = token ? `/api/events?session=${encodeURIComponent(token)}` : '/api/events';
    const eventsUrl = binding ? pinnedUrl(binding.origin, eventsPath) : apiUrl(eventsPath);
    const source = new EventSource(eventsUrl);
    source.onopen = () => onStatusChange?.(true);
    source.onerror = () => onStatusChange?.(false);
    source.onmessage = (msg) => {
      try {
        const parsed = JSON.parse(msg.data) as SSEEvent;
        if (parsed.type === 'snapshot') {
          onEvent({ type: 'snapshot', data: normalizeSnapshot(parsed.data) });
        } else if (parsed.type === 'settings_updated') {
          onEvent({
            type: 'settings_updated',
            data: {
              ...parsed.data,
              settings: normalizeSettings(parsed.data.settings),
            },
          });
        } else {
          onEvent(parsed);
        }
      } catch {
        // Ignore malformed ping
      }
    };
    return () => {
      source.close();
    };
  },
};
