import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { AppSettings, DownloadItem, TrustRule } from '../shared/types.js';

export interface PersistedState {
  version: number;
  downloads: DownloadItem[];
  settings: AppSettings;
  trustRules: TrustRule[];
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

  async load(): Promise<PersistedState> {
    await fs.mkdir(this.dataDir, { recursive: true });
    const defaults = getDefaultSettings();

    try {
      const raw = await fs.readFile(this.statePath, 'utf8');
      const parsed = JSON.parse(raw) as Partial<PersistedState>;

      const settings: AppSettings = {
        ...defaults,
        ...(parsed.settings ?? {}),
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

      return {
        version: 1,
        downloads,
        settings,
        trustRules,
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
        console.warn('[BoltGate] Could not parse state.json, starting fresh:', err);
      }
      const initial: PersistedState = {
        version: 1,
        downloads: [],
        settings: defaults,
        trustRules: [],
      };
      await this.save(initial);
      return initial;
    }
  }

  save(state: PersistedState): Promise<void> {
    const payload = JSON.stringify(state, null, 2);
    this.writeChain = this.writeChain
      .then(() => this.atomicWrite(payload))
      .catch((err) => {
        console.error('[BoltGate] Failed to persist state:', err);
      });
    return this.writeChain;
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
