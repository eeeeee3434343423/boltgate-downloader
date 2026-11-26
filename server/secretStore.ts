import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import type { MirrorSourceMeta } from '../shared/types.js';

interface EncryptedSecretEnvelope {
  v: 1;
  iv: string;
  tag: string;
  ciphertext: string;
}

export class VaultCorruptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultCorruptionError';
  }
}

export interface OperationalSourceRef {
  originalUrl: string;
  finalUrl: string;
  mirrorUrls?: string[];
  mirrorMeta?: MirrorSourceMeta[];
  magnetUri?: string;
  torrentUrl?: string;
  pinnedTorrentPath?: string;
  torrentInfoHash?: string;
}

interface SecretPayload {
  annasArchiveApiKey?: string;
  operationalSources?: Record<string, OperationalSourceRef>;
  privateCustomMirrorUrls?: string[];
  privateIpfsGateways?: string[];
}

interface PairingCodeEntry {
  code: string;
  expiresAt: number;
  used: boolean;
}

const DEFAULT_PAIRING_TTL_MS = 5 * 60_000;
const MAX_ACTIVE_PAIRING_CODES = 64;
const MAX_ACTIVE_SESSION_TOKENS = 64;
const VAULT_LOCK_STALE_MS = 30_000;
const VAULT_LOCK_TIMEOUT_MS = 15_000;

/** On-disk generation signature of `secrets.enc.json` (detects writes by other processes). */
interface VaultGeneration {
  exists: boolean;
  size: number;
  mtimeMs: number;
  ino: number;
}

function sameGeneration(a: VaultGeneration | null, b: VaultGeneration | null): boolean {
  if (!a || !b) return false;
  return a.exists === b.exists && a.size === b.size && a.mtimeMs === b.mtimeMs && a.ino === b.ino;
}

function isProcessAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'EPERM';
  }
}

export class SecretStore {
  private readonly keyPath: string;
  private readonly secretsPath: string;
  private readonly lockPath: string;
  private readonly tokenPath: string;
  private readonly manifestsDir: string;
  private masterKey: Buffer | null = null;
  private cachedSecrets: SecretPayload | null = null;
  private cachedGeneration: VaultGeneration | null = null;
  private cachedSessionToken: string | null = null;
  private issuedSessionTokens = new Set<string>();
  private pairingCodes = new Map<string, PairingCodeEntry>();
  private opChain: Promise<void> = Promise.resolve();

  constructor(private readonly dataDir: string, explicitSessionToken?: string) {
    this.keyPath = path.join(dataDir, '.boltgate.key');
    this.secretsPath = path.join(dataDir, 'secrets.enc.json');
    this.lockPath = path.join(dataDir, 'secrets.enc.json.lock');
    this.tokenPath = path.join(dataDir, '.companion-token');
    this.manifestsDir = path.join(dataDir, 'manifests');
    if (explicitSessionToken && explicitSessionToken.trim()) {
      this.cachedSessionToken = explicitSessionToken.trim();
    }
  }

  /** Private, data-dir-scoped directory for short-lived decrypted manifest materialization. */
  getManifestScratchDir(): string {
    return path.join(this.manifestsDir, '.scratch');
  }

  /** Derives a stable per-install subkey (e.g. for keyed source fingerprints). */
  async deriveSubkey(label: string): Promise<Buffer> {
    const key = await this.getMasterKey();
    return crypto.createHmac('sha256', key).update(`boltgate-subkey:${label}`).digest();
  }

  private async readGeneration(): Promise<VaultGeneration> {
    try {
      const st = await fs.stat(this.secretsPath);
      return { exists: true, size: st.size, mtimeMs: st.mtimeMs, ino: st.ino };
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') {
        return { exists: false, size: 0, mtimeMs: 0, ino: 0 };
      }
      throw err;
    }
  }

  /**
   * Cross-process exclusive vault lock (`secrets.enc.json.lock`, created with O_EXCL).
   * Stale locks (dead owner pid or older than 30s) are broken; otherwise waits up to 15s.
   */
  private async withVaultFileLock<T>(fn: () => Promise<T>): Promise<T> {
    await this.ensureDataDir();
    const deadline = Date.now() + VAULT_LOCK_TIMEOUT_MS;
    const token = `${process.pid}:${crypto.randomBytes(8).toString('hex')}`;
    for (;;) {
      try {
        const fh = await fs.open(this.lockPath, 'wx', 0o600);
        try {
          await fh.writeFile(JSON.stringify({ pid: process.pid, token, at: Date.now() }), 'utf8');
        } finally {
          await fh.close().catch(() => undefined);
        }
        break;
      } catch (err) {
        if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') throw err;
        let stale = false;
        try {
          const raw = JSON.parse(await fs.readFile(this.lockPath, 'utf8')) as { pid?: number; at?: number };
          const ageMs = Date.now() - Number(raw.at ?? 0);
          stale = !isProcessAlive(Number(raw.pid)) || ageMs > VAULT_LOCK_STALE_MS;
        } catch {
          const st = await fs.stat(this.lockPath).catch(() => null);
          stale = !st || Date.now() - st.mtimeMs > VAULT_LOCK_STALE_MS;
        }
        if (stale) {
          await fs.unlink(this.lockPath).catch(() => undefined);
          continue;
        }
        if (Date.now() > deadline) {
          throw new Error('Timed out waiting for the encrypted vault lock held by another BoltGate process');
        }
        await new Promise((r) => setTimeout(r, 15 + Math.floor(Math.random() * 20)));
      }
    }
    try {
      return await fn();
    } finally {
      try {
        const raw = JSON.parse(await fs.readFile(this.lockPath, 'utf8')) as { token?: string };
        if (raw.token === token) await fs.unlink(this.lockPath).catch(() => undefined);
      } catch {
        // Lock already gone
      }
    }
  }

  private async ensureDataDir(): Promise<void> {
    await fs.mkdir(this.dataDir, { recursive: true, mode: 0o700 });
  }

  private async getMasterKey(): Promise<Buffer> {
    if (this.masterKey) return this.masterKey;
    await this.ensureDataDir();

    try {
      const existing = await fs.readFile(this.keyPath);
      if (existing.length === 32) {
        this.masterKey = existing;
        return existing;
      }
      const hexDecoded = Buffer.from(existing.toString('utf8').trim(), 'hex');
      if (hexDecoded.length === 32) {
        this.masterKey = hexDecoded;
        return hexDecoded;
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
        throw err;
      }
    }

    const generated = crypto.randomBytes(32);
    const tmpPath = `${this.keyPath}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    await fs.writeFile(tmpPath, generated, { mode: 0o600 });
    try {
      await fs.chmod(tmpPath, 0o600);
    } catch {
      // Windows NTFS ignores POSIX chmod bits
    }
    try {
      await fs.link(tmpPath, this.keyPath);
      await fs.unlink(tmpPath).catch(() => undefined);
    } catch {
      await fs.unlink(tmpPath).catch(() => undefined);
      const raceExisting = await fs.readFile(this.keyPath);
      const raceKey =
        raceExisting.length === 32
          ? raceExisting
          : Buffer.from(raceExisting.toString('utf8').trim(), 'hex');
      this.masterKey = raceKey;
      return raceKey;
    }

    this.masterKey = generated;
    return generated;
  }

  private async encryptEnvelope(plaintext: Buffer): Promise<EncryptedSecretEnvelope> {
    const key = await this.getMasterKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      v: 1,
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    };
  }

  private async decryptEnvelope(rawJson: string): Promise<Buffer> {
    let env: EncryptedSecretEnvelope;
    try {
      env = JSON.parse(rawJson) as EncryptedSecretEnvelope;
    } catch {
      throw new VaultCorruptionError('Encrypted vault JSON is malformed; refusing to overwrite');
    }
    if (!env || env.v !== 1 || !env.iv || !env.tag || !env.ciphertext) {
      throw new VaultCorruptionError('Encrypted vault envelope is invalid; refusing to overwrite');
    }
    try {
      const key = await this.getMasterKey();
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(env.iv, 'base64')
      );
      decipher.setAuthTag(Buffer.from(env.tag, 'base64'));
      return Buffer.concat([
        decipher.update(Buffer.from(env.ciphertext, 'base64')),
        decipher.final(),
      ]);
    } catch {
      throw new VaultCorruptionError(
        'Encrypted vault failed authentication/decryption; preserving existing secrets.enc.json without overwriting'
      );
    }
  }

  private async atomicWriteSecretFile(targetPath: string, payload: Buffer): Promise<void> {
    await fs.mkdir(path.dirname(targetPath), { recursive: true, mode: 0o700 });
    const tmpPath = `${targetPath}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const fh = await fs.open(tmpPath, 'w', 0o600);
    try {
      let written = 0;
      while (written < payload.length) {
        const res = await fh.write(payload, written, payload.length - written);
        if (res.bytesWritten <= 0) {
          throw new Error('Zero bytes written while persisting encrypted vault file');
        }
        written += res.bytesWritten;
      }
      await fh.datasync();
    } catch (err) {
      await fh.close().catch(() => undefined);
      await fs.unlink(tmpPath).catch(() => undefined);
      throw err;
    }
    await fh.close();
    try {
      await fs.chmod(tmpPath, 0o600);
    } catch {
      // Ignore on Windows
    }
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        await fs.rename(tmpPath, targetPath);
        return;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        if ((code === 'EPERM' || code === 'EBUSY') && attempt < 4) {
          await new Promise((r) => setTimeout(r, 25 * (attempt + 1)));
          continue;
        }
        await fs.unlink(tmpPath).catch(() => undefined);
        throw err;
      }
    }
  }

  /**
   * Serializes the full read-modify-write cycle inside the vault so concurrent key updates,
   * operational source writes, and deletions never clobber each other.
   */
  private runSerialized<T>(fn: () => Promise<T>): Promise<T> {
    const task = this.opChain.then(fn, fn);
    this.opChain = task.then(
      () => undefined,
      () => undefined
    );
    return task;
  }

  async getOrCreateSessionToken(): Promise<string> {
    if (this.cachedSessionToken) return this.cachedSessionToken;
    await this.ensureDataDir();

    try {
      const existing = (await fs.readFile(this.tokenPath, 'utf8')).trim();
      if (existing.length >= 24) {
        this.cachedSessionToken = existing;
        return existing;
      }
    } catch {
      // Generate fresh token
    }

    const token = crypto.randomBytes(24).toString('base64url');
    await this.atomicWriteSecretFile(this.tokenPath, Buffer.from(`${token}\n`, 'utf8'));
    this.cachedSessionToken = token;
    return token;
  }

  private constantTimeEqual(a: string, b: string): boolean {
    const aBuf = Buffer.from(a, 'utf8');
    const bBuf = Buffer.from(b, 'utf8');
    if (aBuf.length !== bBuf.length) return false;
    return crypto.timingSafeEqual(aBuf, bBuf);
  }

  /**
   * Prunes ONLY expired or already-used pairing codes (never evicts valid unexpired codes).
   */
  private pruneExpiredPairingCodes(now = Date.now()): void {
    for (const [k, entry] of this.pairingCodes) {
      if (entry.used || entry.expiresAt <= now) {
        this.pairingCodes.delete(k);
      }
    }
  }

  /**
   * Issues a short-lived, single-use interactive pairing code (not a reusable bearer token).
   * Capacity eviction runs ONLY here when issuing a new code, never during redemption.
   */
  issuePairingCode(ttlMs = DEFAULT_PAIRING_TTL_MS): { code: string; expiresAt: number } {
    const now = Date.now();
    this.pruneExpiredPairingCodes(now);
    while (this.pairingCodes.size >= MAX_ACTIVE_PAIRING_CODES) {
      const oldestKey = this.pairingCodes.keys().next().value;
      if (oldestKey === undefined) break;
      this.pairingCodes.delete(oldestKey);
    }
    const raw = crypto.randomBytes(12).toString('base64url');
    const code = `bgc_${raw}`;
    const expiresAt = now + Math.max(1_000, Math.min(15 * 60_000, ttlMs));
    this.pairingCodes.set(code, { code, expiresAt, used: false });
    return { code, expiresAt };
  }

  /**
   * Redeems either a short-lived single-use pairing code (minting a fresh session bearer token)
   * or an already-valid session token.
   */
  redeemPairingCredential(candidate: string | undefined | null): string | null {
    if (!candidate) return null;
    const trimmed = candidate.trim();
    if (!trimmed) return null;

    const now = Date.now();
    this.pruneExpiredPairingCodes(now);

    for (const [key, entry] of this.pairingCodes) {
      if (!entry.used && entry.expiresAt > now && this.constantTimeEqual(entry.code, trimmed)) {
        entry.used = true;
        this.pairingCodes.delete(key);
        const sessionToken = crypto.randomBytes(24).toString('base64url');
        this.issuedSessionTokens.add(sessionToken);
        if (this.issuedSessionTokens.size > MAX_ACTIVE_SESSION_TOKENS) {
          const oldest = this.issuedSessionTokens.values().next().value;
          if (oldest) this.issuedSessionTokens.delete(oldest);
        }
        return sessionToken;
      }
    }

    if (this.verifySessionToken(trimmed)) {
      return trimmed;
    }

    return null;
  }

  verifySessionToken(candidate: string | undefined | null): boolean {
    if (!candidate) return false;
    const trimmed = candidate.trim();
    if (!trimmed) return false;

    if (this.cachedSessionToken && this.constantTimeEqual(this.cachedSessionToken, trimmed)) {
      return true;
    }

    for (const issued of this.issuedSessionTokens) {
      if (this.constantTimeEqual(issued, trimmed)) {
        return true;
      }
    }

    return false;
  }

  private async decryptSecretsFromDisk(): Promise<SecretPayload> {
    let raw: string;
    try {
      raw = await fs.readFile(this.secretsPath, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') {
        return {};
      }
      throw err;
    }

    const plaintext = (await this.decryptEnvelope(raw)).toString('utf8');
    let parsed: SecretPayload;
    try {
      parsed = JSON.parse(plaintext) as SecretPayload;
    } catch {
      throw new VaultCorruptionError('Decrypted secret vault payload is malformed JSON');
    }

    return {
      annasArchiveApiKey:
        typeof parsed.annasArchiveApiKey === 'string' && parsed.annasArchiveApiKey.trim()
          ? parsed.annasArchiveApiKey.trim()
          : undefined,
      operationalSources:
        parsed.operationalSources && typeof parsed.operationalSources === 'object'
          ? parsed.operationalSources
          : undefined,
      privateCustomMirrorUrls: Array.isArray(parsed.privateCustomMirrorUrls)
        ? parsed.privateCustomMirrorUrls.filter((s): s is string => typeof s === 'string')
        : undefined,
      privateIpfsGateways: Array.isArray(parsed.privateIpfsGateways)
        ? parsed.privateIpfsGateways.filter((s): s is string => typeof s === 'string')
        : undefined,
    };
  }

  /**
   * Returns the current vault contents, reloading from disk whenever the on-disk generation
   * changed (e.g. another process wrote it). A vault corrupted after load surfaces as
   * VaultCorruptionError instead of being silently served from (or overwritten by) a stale cache.
   */
  private async loadSecretsUnlocked(forceReload = false): Promise<SecretPayload> {
    const generation = await this.readGeneration();
    if (!forceReload && this.cachedSecrets && sameGeneration(generation, this.cachedGeneration)) {
      return structuredClone(this.cachedSecrets);
    }
    const parsed = await this.decryptSecretsFromDisk();
    this.cachedSecrets = structuredClone(parsed);
    this.cachedGeneration = generation;
    return parsed;
  }

  private async writeSecretsUnlocked(payload: SecretPayload): Promise<void> {
    const cleanedSources =
      payload.operationalSources && Object.keys(payload.operationalSources).length > 0
        ? payload.operationalSources
        : undefined;
    const cleanedCustomMirrors =
      payload.privateCustomMirrorUrls && payload.privateCustomMirrorUrls.length > 0
        ? payload.privateCustomMirrorUrls
        : undefined;
    const cleanedGateways =
      payload.privateIpfsGateways && payload.privateIpfsGateways.length > 0
        ? payload.privateIpfsGateways
        : undefined;

    const nextPayload: SecretPayload = {
      annasArchiveApiKey: payload.annasArchiveApiKey,
      operationalSources: cleanedSources,
      privateCustomMirrorUrls: cleanedCustomMirrors,
      privateIpfsGateways: cleanedGateways,
    };

    await this.ensureDataDir();
    if (
      !nextPayload.annasArchiveApiKey &&
      !nextPayload.operationalSources &&
      !nextPayload.privateCustomMirrorUrls &&
      !nextPayload.privateIpfsGateways
    ) {
      await fs.unlink(this.secretsPath).catch((err) => {
        if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') throw err;
      });
      this.cachedSecrets = {};
      this.cachedGeneration = await this.readGeneration();
      return;
    }

    const envelope = await this.encryptEnvelope(Buffer.from(JSON.stringify(nextPayload), 'utf8'));
    await this.atomicWriteSecretFile(
      this.secretsPath,
      Buffer.from(JSON.stringify(envelope, null, 2), 'utf8')
    );
    this.cachedSecrets = structuredClone(nextPayload);
    this.cachedGeneration = await this.readGeneration();
  }

  /**
   * Read-modify-write under BOTH the in-process serializer and the cross-process vault file lock,
   * always reloading the CURRENT on-disk vault generation under the lock before mutating, so a
   * concurrent store/process (or post-load corruption) can never be clobbered by stale state.
   */
  private mutateSecrets<T>(mutator: (draft: SecretPayload) => T): Promise<T> {
    return this.runSerialized(() =>
      this.withVaultFileLock(async () => {
        const current = await this.loadSecretsUnlocked(true);
        const result = mutator(current);
        await this.writeSecretsUnlocked(current);
        return result;
      })
    );
  }

  async getAnnasArchiveApiKey(): Promise<string> {
    return this.runSerialized(async () => {
      const data = await this.loadSecretsUnlocked();
      return data.annasArchiveApiKey ?? '';
    });
  }

  async hasAnnasArchiveApiKey(): Promise<boolean> {
    const key = await this.getAnnasArchiveApiKey();
    return key.length > 0;
  }

  async setAnnasArchiveApiKey(rawKey: string | null | undefined): Promise<boolean> {
    const trimmed = typeof rawKey === 'string' ? rawKey.trim() : '';
    return this.mutateSecrets((draft) => {
      draft.annasArchiveApiKey = trimmed || undefined;
      return Boolean(trimmed);
    });
  }

  /**
   * Re-reads and decrypts secrets.enc.json directly from disk to verify a migrated key
   * is durably persisted before scrubbing any legacy plaintext file.
   */
  async verifyPersistedAnnasArchiveApiKey(expectedKey: string): Promise<boolean> {
    return this.runSerialized(async () => {
      const onDisk = await this.decryptSecretsFromDisk();
      return Boolean(
        onDisk.annasArchiveApiKey && this.constantTimeEqual(onDisk.annasArchiveApiKey, expectedKey)
      );
    });
  }

  async getOperationalSources(): Promise<Record<string, OperationalSourceRef>> {
    return this.runSerialized(async () => {
      const data = await this.loadSecretsUnlocked();
      return data.operationalSources ? structuredClone(data.operationalSources) : {};
    });
  }

  async getOperationalSource(jobId: string): Promise<OperationalSourceRef | null> {
    return this.runSerialized(async () => {
      const data = await this.loadSecretsUnlocked();
      const entry = data.operationalSources?.[jobId];
      return entry ? structuredClone(entry) : null;
    });
  }

  async setOperationalSource(jobId: string, ref: OperationalSourceRef): Promise<void> {
    await this.mutateSecrets((draft) => {
      draft.operationalSources = {
        ...(draft.operationalSources ?? {}),
        [jobId]: structuredClone(ref),
      };
    });
  }

  async setOperationalSourcesBatch(entries: Record<string, OperationalSourceRef>): Promise<void> {
    if (Object.keys(entries).length === 0) return;
    await this.mutateSecrets((draft) => {
      draft.operationalSources = {
        ...(draft.operationalSources ?? {}),
        ...structuredClone(entries),
      };
    });
  }

  async deleteOperationalSource(jobId: string): Promise<void> {
    await this.mutateSecrets((draft) => {
      if (!draft.operationalSources || !(jobId in draft.operationalSources)) return;
      delete draft.operationalSources[jobId];
      if (Object.keys(draft.operationalSources).length === 0) {
        draft.operationalSources = undefined;
      }
    });
  }

  async getPrivateTemplates(): Promise<{
    customMirrorUrls?: string[];
    ipfsGateways?: string[];
  }> {
    return this.runSerialized(async () => {
      const data = await this.loadSecretsUnlocked();
      return {
        customMirrorUrls: data.privateCustomMirrorUrls
          ? [...data.privateCustomMirrorUrls]
          : undefined,
        ipfsGateways: data.privateIpfsGateways ? [...data.privateIpfsGateways] : undefined,
      };
    });
  }

  async setPrivateTemplates(patch: {
    customMirrorUrls?: string[];
    ipfsGateways?: string[];
  }): Promise<void> {
    await this.mutateSecrets((draft) => {
      if (patch.customMirrorUrls !== undefined) {
        draft.privateCustomMirrorUrls = [...patch.customMirrorUrls];
      }
      if (patch.ipfsGateways !== undefined) {
        draft.privateIpfsGateways = [...patch.ipfsGateways];
      }
    });
  }

  /**
   * Encrypts raw `.torrent` manifest bytes at rest in `data/manifests/<id>.torrent.enc`
   * so private tracker passkeys inside `.torrent` files are never stored in plaintext.
   */
  async writeEncryptedManifest(jobId: string, rawTorrentBytes: Buffer): Promise<string> {
    const safeId = jobId.replace(/[^a-zA-Z0-9_-]/g, '') || 'manifest';
    const manifestPath = path.join(this.manifestsDir, `${safeId}.torrent.enc`);
    const envelope = await this.encryptEnvelope(rawTorrentBytes);
    await this.atomicWriteSecretFile(
      manifestPath,
      Buffer.from(JSON.stringify(envelope, null, 2), 'utf8')
    );
    return manifestPath;
  }

  /** True only for an encrypted manifest envelope stored inside this vault's manifests dir. */
  isEncryptedManifestPath(manifestPath: string | undefined): boolean {
    if (!manifestPath || !manifestPath.endsWith('.torrent.enc')) return false;
    const resolved = path.resolve(manifestPath);
    const rel = path.relative(path.resolve(this.manifestsDir), resolved);
    return Boolean(rel) && !rel.startsWith('..') && !path.isAbsolute(rel) && !rel.includes(path.sep);
  }

  async readEncryptedManifest(manifestPath: string): Promise<Buffer> {
    if (!this.isEncryptedManifestPath(manifestPath)) {
      throw new Error('Refusing unmigrated or raw plaintext .torrent manifest path; re-inspect the torrent');
    }
    const raw = await fs.readFile(manifestPath, 'utf8');
    return this.decryptEnvelope(raw);
  }

  /**
   * Migrates a legacy plaintext `.torrent` manifest into an encrypted envelope, verifies the
   * encrypted copy decrypts byte-for-byte BEFORE scrubbing, then removes the plaintext file
   * (only when it lives inside the data directory — never deletes user files elsewhere).
   */
  async migrateLegacyPlaintextManifest(
    jobId: string,
    legacyPath: string
  ): Promise<{ encryptedPath: string; plaintextRemoved: boolean; bytes: Buffer }> {
    const bytes = await fs.readFile(legacyPath);
    const encryptedPath = await this.writeEncryptedManifest(jobId, bytes);
    const roundTrip = await this.readEncryptedManifest(encryptedPath);
    if (!roundTrip.equals(bytes)) {
      throw new VaultCorruptionError('Encrypted manifest verification failed during legacy migration');
    }
    const resolvedLegacy = path.resolve(legacyPath);
    const relToData = path.relative(path.resolve(this.dataDir), resolvedLegacy);
    const insideDataDir = Boolean(relToData) && !relToData.startsWith('..') && !path.isAbsolute(relToData);
    let plaintextRemoved = false;
    if (insideDataDir) {
      await fs.unlink(resolvedLegacy).catch((err) => {
        if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') throw err;
      });
      plaintextRemoved = true;
    }
    return { encryptedPath, plaintextRemoved, bytes };
  }

  async deleteEncryptedManifest(manifestPath: string): Promise<void> {
    await fs.unlink(manifestPath).catch((err) => {
      if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') throw err;
    });
  }

  async getActiveSecretsForRedaction(): Promise<string[]> {
    const secrets: string[] = [];
    const key = await this.getAnnasArchiveApiKey();
    if (key) secrets.push(key);
    if (this.cachedSessionToken) secrets.push(this.cachedSessionToken);
    for (const tok of this.issuedSessionTokens) {
      secrets.push(tok);
    }
    return secrets;
  }
}
