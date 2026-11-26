import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { AppSettings, DownloadItem, TrustRule } from '../shared/types.js';
import { DEFAULT_PUBLIC_IPFS_GATEWAYS } from '../shared/compat.js';

export interface PersistedState {
  version: number;
  downloads: DownloadItem[];
  settings: AppSettings;
  trustRules: TrustRule[];
}

export interface LoadedState extends PersistedState {
  migratedAnnasApiKey?: string;
  /** Exact bytes of `state.json` as found on disk (null when freshly initialized). */
  diskText: string | null;
}

export class StateLoadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StateLoadError';
  }
}

export interface TrashBatchEntry {
  token: string;
  items: DownloadItem[];
  expiresAt: number;
}

export function getDefaultSettings(): AppSettings {
  return {
    downloadDir: path.join(os.homedir(), 'Downloads'),
    organizeByCategory: false,
    maxConcurrentDownloads: 3,
    maxConcurrentPerHost: 2,
    segmentsPerDownload: 8,
    speedLimitKBps: 0,
    speedPreset: 'balanced',
    autoApproveTrusted: false,
    theme: 'light',
    hasAnnasArchiveApiKey: false,
    annasArchiveBaseUrl: 'https://annas-archive.org',
    customMirrorUrls: [],
    ipfsGateways: [...DEFAULT_PUBLIC_IPFS_GATEWAYS],
    minSpeedFloorKBps: 350,
    preferAria2: true,
  };
}

export class StateStore {
  public readonly dataDir: string;
  public readonly statePath: string;
  private writeChain: Promise<void> = Promise.resolve();
  private trashSingles = new Map<string, { item: DownloadItem; expiresAt: number }>();
  private trashBatches = new Map<string, TrashBatchEntry>();

  constructor(dataDir?: string) {
    this.dataDir = dataDir ?? process.env.BOLTGATE_DATA_DIR ?? path.join(process.cwd(), 'data');
    this.statePath = path.join(this.dataDir, 'state.json');
  }

  async load(): Promise<LoadedState> {
    await fs.mkdir(this.dataDir, { recursive: true });
    const defaults = getDefaultSettings();

    // Initialize fresh state ONLY when state.json genuinely does not exist. A malformed or
    // unreadable state.json (which may still hold legacy secrets/history) is never overwritten.
    let raw: string;
    try {
      raw = await fs.readFile(this.statePath, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
        throw new StateLoadError(
          `Could not read state.json (${(err as NodeJS.ErrnoException)?.code ?? 'error'}); refusing to overwrite it`
        );
      }
      const initial: PersistedState = {
        version: 1,
        downloads: [],
        settings: defaults,
        trustRules: [],
      };
      await this.saveStrict(initial);
      return { ...initial, diskText: null };
    }

    let parsed: Partial<PersistedState> & {
      settings?: Partial<AppSettings> & { annasArchiveApiKey?: unknown };
    };
    try {
      parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('state root is not an object');
      }
    } catch (err) {
      throw new StateLoadError(
        `state.json is malformed (${err instanceof Error ? err.message : 'parse error'}); refusing to overwrite it — repair or move the file and restart`
      );
    }

    {

      const legacyApiKey =
        typeof parsed.settings?.annasArchiveApiKey === 'string' &&
        parsed.settings.annasArchiveApiKey.trim().length > 0
          ? parsed.settings.annasArchiveApiKey.trim()
          : undefined;

      const rawSettings = { ...(parsed.settings ?? {}) } as Partial<AppSettings> & {
        annasArchiveApiKey?: unknown;
      };
      delete rawSettings.annasArchiveApiKey;

      const settings: AppSettings = {
        ...defaults,
        ...rawSettings,
        hasAnnasArchiveApiKey: Boolean(parsed.settings?.hasAnnasArchiveApiKey || legacyApiKey),
        customMirrorUrls: Array.isArray(parsed.settings?.customMirrorUrls)
          ? parsed.settings.customMirrorUrls
          : defaults.customMirrorUrls,
        ipfsGateways:
          Array.isArray(parsed.settings?.ipfsGateways) && parsed.settings.ipfsGateways.length > 0
            ? parsed.settings.ipfsGateways
            : [...DEFAULT_PUBLIC_IPFS_GATEWAYS],
        annasArchiveBaseUrl:
          typeof parsed.settings?.annasArchiveBaseUrl === 'string' &&
          parsed.settings.annasArchiveBaseUrl.trim()
            ? parsed.settings.annasArchiveBaseUrl
            : defaults.annasArchiveBaseUrl,
        minSpeedFloorKBps:
          typeof parsed.settings?.minSpeedFloorKBps === 'number' &&
          Number.isFinite(parsed.settings.minSpeedFloorKBps)
            ? Math.max(0, parsed.settings.minSpeedFloorKBps)
            : defaults.minSpeedFloorKBps,
        preferAria2:
          typeof parsed.settings?.preferAria2 === 'boolean'
            ? parsed.settings.preferAria2
            : defaults.preferAria2,
      };

      const downloads: DownloadItem[] = Array.isArray(parsed.downloads)
        ? parsed.downloads.map((item) => {
            if (item.status === 'downloading' || item.status === 'verifying') {
              return {
                ...item,
                status: 'paused',
                speedBps: 0,
                etaSeconds: null,
                segments: Array.isArray(item.segments)
                  ? item.segments.map((seg) => ({
                      ...seg,
                      speedBps: 0,
                      status: seg.status === 'done' ? 'done' : 'paused',
                    }))
                  : [],
              };
            }
            if (item.status === 'probing') {
              return {
                ...item,
                status: 'pending_review',
              };
            }
            return {
              ...item,
              speedBps: 0,
              etaSeconds: null,
            };
          })
        : [];

      const trustRules: TrustRule[] = Array.isArray(parsed.trustRules) ? parsed.trustRules : [];

      const loaded: LoadedState = {
        version: 1,
        downloads,
        settings,
        trustRules,
        migratedAnnasApiKey: legacyApiKey,
        diskText: raw,
      };

      // Do NOT scrub legacyApiKey from state.json here!
      // DownloadManager.init() must write and verify the encrypted secret in secrets.enc.json first.
      return loaded;
    }
  }

  /** Serializes exactly what `save()` would write (used to compare against on-disk bytes). */
  serialize(state: PersistedState): string {
    const cleanSettings = { ...state.settings } as AppSettings & { annasArchiveApiKey?: unknown };
    delete cleanSettings.annasArchiveApiKey;
    const cleanState: PersistedState = {
      version: state.version,
      downloads: state.downloads,
      settings: cleanSettings,
      trustRules: state.trustRules,
    };
    return JSON.stringify(cleanState, null, 2);
  }

  save(state: PersistedState): Promise<void> {
    const payload = this.serialize(state);
    this.writeChain = this.writeChain
      .then(() => this.atomicWrite(payload))
      .catch((err) => {
        console.error('[BoltGate] Failed to persist state:', err);
      });
    return this.writeChain;
  }

  /**
   * Like `save()`, but the returned promise REJECTS if this write fails (used for migration
   * scrubs, where a silent failure would leave legacy plaintext on disk). The shared write chain
   * stays alive for later writes either way.
   */
  saveStrict(state: PersistedState): Promise<void> {
    const payload = this.serialize(state);
    const task = this.writeChain.then(() => this.atomicWrite(payload));
    this.writeChain = task.catch((err) => {
      console.error('[BoltGate] Failed to persist state:', err);
    });
    return task;
  }

  /** Reads the exact current bytes of `state.json` (null if missing). */
  async readDiskText(): Promise<string | null> {
    try {
      return await fs.readFile(this.statePath, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') return null;
      throw err;
    }
  }

  async flush(): Promise<void> {
    await this.writeChain;
  }

  private async atomicWrite(payload: string): Promise<void> {
    await fs.mkdir(this.dataDir, { recursive: true });
    const tmpPath = `${this.statePath}.${process.pid}.${Date.now()}.tmp`;
    await fs.writeFile(tmpPath, payload, 'utf8');

    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        await fs.rename(tmpPath, this.statePath);
        return;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        if ((code === 'EPERM' || code === 'EBUSY') && attempt < 4) {
          await new Promise((r) => setTimeout(r, 25 * (attempt + 1)));
          continue;
        }
        await fs.unlink(tmpPath).catch(() => {});
        throw err;
      }
    }
  }

  stashDeletedItem(item: DownloadItem, ttlMs = 60_000): void {
    this.pruneTrash();
    this.trashSingles.set(item.id, {
      item: structuredClone(item),
      expiresAt: Date.now() + ttlMs,
    });
  }

  takeDeletedItem(id: string): DownloadItem | null {
    this.pruneTrash();
    const entry = this.trashSingles.get(id);
    if (!entry) return null;
    this.trashSingles.delete(id);
    return entry.item;
  }

  stashDeletedBatch(token: string, items: DownloadItem[], ttlMs = 60_000): void {
    this.pruneTrash();
    this.trashBatches.set(token, {
      token,
      items: items.map((i) => structuredClone(i)),
      expiresAt: Date.now() + ttlMs,
    });
  }

  takeDeletedBatch(token: string): DownloadItem[] | null {
    this.pruneTrash();
    const entry = this.trashBatches.get(token);
    if (!entry) return null;
    this.trashBatches.delete(token);
    return entry.items;
  }

  private pruneTrash(): void {
    const now = Date.now();
    for (const [k, v] of this.trashSingles) {
      if (v.expiresAt <= now) this.trashSingles.delete(k);
    }
    for (const [k, v] of this.trashBatches) {
      if (v.expiresAt <= now) this.trashBatches.delete(k);
    }
  }
}
