import crypto from 'node:crypto';
import type { DownloadItem } from '../shared/types.js';

export interface ValidatorValues {
  etag?: string;
  lastModified?: string;
}

export interface MirrorValidatorCandidate {
  url?: string;
  supportsRanges: boolean;
  totalBytes: number | null;
  etag?: string;
  lastModified?: string;
}

/**
 * RFC 9110 §8.8.3 strong entity-tag: a non-weak `opaque-tag` that is exactly one DQUOTE-delimited
 * run of `etagc` characters (%x21 / %x23-7E / obs-text). Unquoted, weak (`W/`), empty (`""`), or
 * otherwise malformed values are NOT strong validators.
 */
export function isStrongEtag(etag?: string): boolean {
  if (typeof etag !== 'string') return false;
  const trimmed = etag.trim();
  if (/^W\//i.test(trimmed)) return false;
  return /^"[\x21\x23-\x7E\x80-\xFF]+"$/.test(trimmed);
}

function normValidator(v?: string): string | undefined {
  const t = v?.trim();
  return t ? t : undefined;
}

/**
 * Full resource identity: origin + path + query. Query parameters routinely select a different
 * file on the same path (`/get.php?id=1` vs `/get.php?id=2`), so they are part of identity.
 */
export function isSameResourceEndpoint(urlA?: string, urlB?: string): boolean {
  if (!urlA || !urlB) return false;
  try {
    const a = new URL(urlA);
    const b = new URL(urlB);
    return a.origin === b.origin && a.pathname === b.pathname && a.search === b.search;
  } catch {
    return false;
  }
}

/**
 * Unified validator enforcement for untrusted (no digest) HTTP transfers:
 * - If an ETag is pinned, the response MUST include an exact matching ETag (missing ETag is rejected).
 * - If a Last-Modified is pinned, any conflicting response Last-Modified is rejected even when ETags match.
 * - If only Last-Modified is pinned (no pinned ETag), missing response Last-Modified is rejected.
 */
export function validateResponseValidators(
  expected: ValidatorValues,
  actual: ValidatorValues
): { ok: boolean; reason?: string } {
  const expEtag = normValidator(expected.etag);
  const actEtag = normValidator(actual.etag);
  const expLm = normValidator(expected.lastModified);
  const actLm = normValidator(actual.lastModified);

  if (expEtag) {
    if (!actEtag) {
      return {
        ok: false,
        reason: `Missing ETag on response when pinned ETag (${expEtag}) is required`,
      };
    }
    if (actEtag !== expEtag) {
      return {
        ok: false,
        reason: `Upstream ETag changed (${actEtag} !== ${expEtag}) without trusted digest`,
      };
    }
  }

  if (expLm) {
    if (actLm && actLm !== expLm) {
      return {
        ok: false,
        reason: `Upstream Last-Modified changed (${actLm} !== ${expLm}) without trusted digest`,
      };
    }
    if (!expEtag && !actLm) {
      return {
        ok: false,
        reason: `Missing Last-Modified on response when pinned Last-Modified (${expLm}) is required`,
      };
    }
  }

  return { ok: true };
}

/**
 * Unified multi-mirror eligibility check used across mirror groups, IPFS gateway selection,
 * native runner dispatch, and aria2c delegation.
 *
 * Across independent resources (different origin, path, OR query), a trusted cryptographic digest
 * (expectedMd5 / expectedSha256) or verified manifest is ALWAYS required—even when ETags match,
 * because HTTP ETags are only scoped to a single resource.
 */
export function canCombineMirrorWithPrimary(
  primary: MirrorValidatorCandidate,
  candidate: MirrorValidatorCandidate,
  hasTrustedDigest: boolean
): { eligible: boolean; reason?: string } {
  if (!primary.supportsRanges || primary.totalBytes === null) {
    return { eligible: false, reason: 'Primary mirror does not support byte ranges or size' };
  }
  if (!candidate.supportsRanges) {
    return { eligible: false, reason: 'No byte-range support' };
  }
  if (candidate.totalBytes === null || candidate.totalBytes !== primary.totalBytes) {
    return {
      eligible: false,
      reason: `Size mismatch (${candidate.totalBytes ?? 'unknown'} vs ${primary.totalBytes} bytes)`,
    };
  }

  if (hasTrustedDigest) {
    return { eligible: true };
  }

  const pEtag = normValidator(primary.etag);
  const cEtag = normValidator(candidate.etag);
  const pLm = normValidator(primary.lastModified);
  const cLm = normValidator(candidate.lastModified);

  if (!isStrongEtag(pEtag) || !isStrongEtag(cEtag)) {
    return {
      eligible: false,
      reason: 'Missing matching strong ETag for untrusted multi-mirror striping',
    };
  }
  if (cEtag !== pEtag) {
    return {
      eligible: false,
      reason: `Validator mismatch without trusted digest (${cEtag} vs ${pEtag})`,
    };
  }
  if (pLm && cLm && cLm !== pLm) {
    return {
      eligible: false,
      reason: 'Last-Modified mismatch without trusted digest',
    };
  }
  if (pLm && !cLm) {
    return {
      eligible: false,
      reason: 'Missing Last-Modified on mirror when primary pinned Last-Modified',
    };
  }

  // Without a trusted digest, independent resources cannot be combined even if their ETags match,
  // because HTTP ETags are only scoped to a single resource (origin + path + query).
  if (!isSameResourceEndpoint(primary.url, candidate.url)) {
    return {
      eligible: false,
      reason:
        'Independent mirrors require a trusted MD5/SHA-256 digest or verified manifest (matching ETags across separate resources are not trusted)',
    };
  }

  return { eligible: true };
}

/**
 * Returns true when a transfer's identity is proven by a trusted digest or a strong validator.
 * Unproven transfers must use a single uninterrupted stream and restart from offset 0.
 */
export function isTransferIdentityProven(opts: {
  expectedMd5?: string;
  expectedSha256?: string;
  pinnedEtag?: string;
}): boolean {
  return Boolean(opts.expectedMd5 || opts.expectedSha256) || isStrongEtag(opts.pinnedEtag);
}

/**
 * Selects HTTP URLs allowed for `aria2c` dispatch.
 * Because `aria2c` cannot enforce pinned HTTP ETag/Last-Modified validators per segment across
 * multiple URLs, multi-source HTTP delegation to `aria2c` is allowed ONLY when a trusted digest
 * (expectedMd5 or expectedSha256) will verify the assembled payload before publication.
 */
export function selectAria2HttpSources(item: Pick<
  DownloadItem,
  'finalUrl' | 'mirrorUrls' | 'expectedMd5' | 'expectedSha256'
>): string[] {
  const hasTrustedDigest = Boolean(item.expectedMd5 || item.expectedSha256);
  const rawList =
    item.mirrorUrls && item.mirrorUrls.length > 0 ? item.mirrorUrls : [item.finalUrl];
  const clean = rawList.filter((u) => typeof u === 'string' && u.trim().length > 0);
  if (clean.length === 0) return [item.finalUrl];
  if (hasTrustedDigest) return clean;
  return [clean[0]!];
}

// Process-local fallback key; managers pass a stable per-install key derived from the vault.
const FALLBACK_SOURCE_ID_KEY = crypto.randomBytes(32);

/**
 * Generates an opaque, deterministic, keyed (HMAC) source identifier for `.part.meta` and exported
 * state, so raw signed URLs or credentials are never written to staging checkpoint files and the
 * fingerprint cannot be brute-forced offline to recover a low-entropy credential.
 */
export function computeOpaqueSourceId(rawUrl: string, key?: Buffer): string {
  const digest = crypto
    .createHmac('sha256', key && key.length > 0 ? key : FALLBACK_SOURCE_ID_KEY)
    .update(rawUrl)
    .digest('hex')
    .slice(0, 24);
  return `src_${digest}`;
}
