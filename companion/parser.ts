export {
  APPROVED_ANNAS_HOST_REGEX,
  isApprovedAnnasHostname,
  parseSmartInput,
  sanitizeIpfsSubPath,
  type ParsedInputEntry,
  type ParsedInputKind,
  type SmartParseOptions,
  type SmartParseResult,
} from '../shared/inputParser.js';

// Path segments carrying credentials, tokens, tickets, or signed payloads
const SENSITIVE_PATH_TOKEN_PATTERN =
  /(\/(?:passkey|pass|token|access_token|auth|authkey|auth_key|key|api_key|apikey|secret|sig|signature|ticket|session|jwt|credential|dl_token|download_token)\/)[^/?#\s"'<>]+/gi;

// Inline `k=v` credential segments embedded inside URL paths (e.g. `/ticket=abc/file.epub`)
const SENSITIVE_PATH_KV_PATTERN =
  /(\/[^/?#\s"'<>]*?(?:key|token|auth|pass|secret|sig|ticket|session|jwt|credential)=)[^/?#\s"'<>]+/gi;

// Tracker endpoint segments (`/announce`, `/scrape`, `/announce.php`)
const TRACKER_ENDPOINT_SEGMENT = /^(?:announce|scrape)(?:\.php)?$/i;
// Content-address labels whose following segment is a public hash/CID, not a credential
const CONTENT_ADDRESS_LABELS = new Set(['md5', 'sha1', 'sha256', 'ipfs', 'ipns', 'btih']);

function decodeSegmentSafe(seg: string): string {
  try {
    return decodeURIComponent(seg);
  } catch {
    return seg;
  }
}

/**
 * Opaque high-entropy path tokens (signed path tokens, passkeys, session ids): 16+ URL-safe
 * characters mixing letters and digits, with no dots (so real filenames like `book.epub` survive).
 */
function isOpaquePathToken(seg: string): boolean {
  const decoded = decodeSegmentSafe(seg);
  if (!/^[A-Za-z0-9_~-]{16,}$/.test(decoded)) return false;
  return /\d/.test(decoded) && /[A-Za-z]/.test(decoded);
}

/**
 * Hides opaque path segments by default, and—inside private-tracker announce/scrape URLs—every
 * passkey-like segment (e.g. `/0123abcd…/announce`, `/announce/PASSKEY`, `/a/PASSKEY/announce`).
 */
function redactOpaquePathSegments(pathname: string): string {
  if (!pathname || pathname === '/') return pathname;
  const segs = pathname.split('/');
  const isTracker = segs.some((s) => TRACKER_ENDPOINT_SEGMENT.test(decodeSegmentSafe(s)));
  return segs
    .map((seg, i) => {
      if (!seg || seg === '***' || /[{}]/.test(seg)) return seg;
      const prev = decodeSegmentSafe(segs[i - 1] ?? '').toLowerCase();
      if (CONTENT_ADDRESS_LABELS.has(prev)) return seg;
      const decoded = decodeSegmentSafe(seg);
      if (isTracker) {
        if (TRACKER_ENDPOINT_SEGMENT.test(decoded)) return seg;
        if (decoded.length >= 16 || (decoded.length >= 6 && /\d/.test(decoded))) return '***';
        return seg;
      }
      return isOpaquePathToken(seg) ? '***' : seg;
    })
    .join('/');
}

function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function redactExplicitSecrets(input: string, secrets: readonly string[]): string {
  let out = input;
  for (const secret of secrets) {
    const trimmed = secret.trim();
    if (!trimmed) continue;
    for (const variant of new Set([
      trimmed,
      encodeURIComponent(trimmed),
      encodeURIComponent(encodeURIComponent(trimmed)),
    ])) {
      if (!variant) continue;
      out = out.replace(new RegExp(escapeRegExp(variant), 'g'), '***');
    }
  }
  return out;
}

/**
 * Strips ALL query parameter values by default (preserving parameter names for diagnostics)
 * so arbitrary signed params like `?ticket=`, `?t=`, `?p=`, `?X-Amz-*`, etc. never leak.
 */
function stripAllQueryValues(queryString: string): string {
  if (!queryString) return '';
  const hasPrefix = queryString.startsWith('?');
  const raw = hasPrefix ? queryString.slice(1) : queryString;
  if (!raw) return '';
  const parts = raw.split('&').map((pair) => {
    if (!pair) return '';
    const eqIdx = pair.indexOf('=');
    if (eqIdx === -1) return '***';
    const key = pair.slice(0, eqIdx);
    return `${key}=***`;
  });
  return `${hasPrefix ? '?' : ''}${parts.join('&')}`;
}

function redactMagnetUri(raw: string, secrets: readonly string[]): string {
  const qIdx = raw.indexOf('?');
  if (qIdx === -1) return redactExplicitSecrets(raw, secrets);
  const query = raw.slice(qIdx + 1);
  const parts = query.split('&').map((pair) => {
    if (!pair) return '';
    const eqIdx = pair.indexOf('=');
    if (eqIdx === -1) return '***';
    const key = pair.slice(0, eqIdx);
    const val = pair.slice(eqIdx + 1);
    const lowerKey = key.toLowerCase();
    // Preserve btih/btmh infoHash (`xt`) and sanitized display name (`dn`)
    if (lowerKey === 'xt') {
      return `${key}=${redactExplicitSecrets(val, secrets)}`;
    }
    if (lowerKey === 'dn') {
      return `${key}=${redactExplicitSecrets(val, secrets)}`;
    }
    // For tracker / webseed URLs (`tr`, `ws`, `xs`), decode -> full URL redaction -> re-encode
    if (lowerKey === 'tr' || lowerKey === 'ws' || lowerKey === 'xs') {
      try {
        const decoded = decodeURIComponent(val);
        const cleaned = redactSensitiveUrl(decoded, secrets);
        return `${key}=${encodeURIComponent(cleaned)}`;
      } catch {
        return `${key}=***`;
      }
    }
    return `${key}=***`;
  });
  return `magnet:?${parts.join('&')}`;
}

/**
 * Redacts all query parameter values by default, embedded URL credentials, path-embedded
 * tokens/tickets/passkeys, fragments, magnet tracker params, and explicit secret values
 * before persisting or displaying URLs.
 */
export function redactSensitiveUrl(raw: string, secrets: readonly string[] = []): string {
  if (!raw) return raw;
  let out = redactExplicitSecrets(raw, secrets);

  if (/^magnet:\?/i.test(out)) {
    return redactMagnetUri(out, secrets);
  }

  // Handle full URLs (including templates with `{md5}` / `{cid}`) by parsing or regex fallback
  const urlPattern = /([a-z][a-z0-9+.-]*:\/\/)([^\s"'<>]+)/gi;
  out = out.replace(urlPattern, (fullMatch, schemePrefix: string, rest: string) => {
    // Separate authority, path, query, fragment safely (even if template contains `{md5}`/`{cid}`)
    let working = rest;
    let fragment = '';
    const hashIdx = working.indexOf('#');
    if (hashIdx !== -1) {
      const rawFrag = working.slice(hashIdx + 1);
      fragment = rawFrag ? '#***' : '';
      working = working.slice(0, hashIdx);
    }

    let query = '';
    const qIdx = working.indexOf('?');
    if (qIdx !== -1) {
      query = stripAllQueryValues(working.slice(qIdx));
      working = working.slice(0, qIdx);
    }

    const slashIdx = working.indexOf('/');
    let authority = slashIdx === -1 ? working : working.slice(0, slashIdx);
    let pathname = slashIdx === -1 ? '' : working.slice(slashIdx);

    // Strip embedded userinfo `user:pass@host`
    const atIdx = authority.lastIndexOf('@');
    if (atIdx !== -1) {
      authority = `***@${authority.slice(atIdx + 1)}`;
    }

    // Strip path-embedded credentials (e.g. `/token/SECRET/`, `/ticket/ABC/`, `/passkey=XYZ/`)
    pathname = pathname.replace(SENSITIVE_PATH_TOKEN_PATTERN, '$1***');
    pathname = pathname.replace(SENSITIVE_PATH_KV_PATTERN, '$1***');
    // Hide opaque private-tracker passkeys / signed path tokens by default
    pathname = redactOpaquePathSegments(pathname);

    return `${schemePrefix}${authority}${pathname}${query}${fragment}` || fullMatch;
  });

  // Catch any standalone query values or userinfo left in non-URL strings
  out = out.replace(SENSITIVE_PATH_TOKEN_PATTERN, '$1***');
  out = out.replace(SENSITIVE_PATH_KV_PATTERN, '$1***');
  return out;
}

/**
 * Redacts any URLs, query secrets, path credentials, auth headers, or explicit secrets
 * embedded inside log lines, filenames, paths, or error messages.
 */
export function redactText(text: string, secrets: readonly string[] = []): string {
  if (!text) return text;
  let out = redactSensitiveUrl(text, secrets);
  out = out.replace(/magnet:\?[^\s"'<>]+/gi, (mag) => redactMagnetUri(mag, secrets));
  // Also redact standalone query fragments like `?ticket=abc` or `&key=xyz` in prose/errors
  out = out.replace(/([?&][A-Za-z0-9._-]+=)[^&#\s"'<>]+/g, '$1***');
  out = out.replace(/\b(Bearer\s+|Basic\s+)[A-Za-z0-9._~+/-]+=*/gi, '$1***');
  out = out.replace(/\b(X-BoltGate-Session\s*:\s*)\S+/gi, '$1***');
  return out;
}

/**
 * Checks whether a URL or string contains any active secret (raw, single-, or double-encoded).
 */
export function containsActiveSecret(input: string, secrets: readonly string[]): boolean {
  if (!input || secrets.length === 0) return false;
  let decoded = input;
  try {
    decoded = decodeURIComponent(input);
  } catch {
    // keep raw
  }
  let doubleDecoded = decoded;
  try {
    doubleDecoded = decodeURIComponent(decoded);
  } catch {
    // keep single decoded
  }
  for (const secret of secrets) {
    const trimmed = secret.trim();
    if (!trimmed) continue;
    const encoded = encodeURIComponent(trimmed);
    if (
      input.includes(trimmed) ||
      decoded.includes(trimmed) ||
      doubleDecoded.includes(trimmed) ||
      (encoded && input.includes(encoded))
    ) {
      return true;
    }
  }
  return false;
}

export interface OutboundUrlGuardOptions {
  allowCredentialedOrigin?: string;
  allowCredentialedPathPrefix?: string;
}

/**
 * Unified outbound secret leak guard enforced before EVERY initial request and redirect
 * across resolver, benchmarker, inspector, engine, and torrent/metadata fetches.
 * Only the explicitly approved Tier-1 credentialed provider endpoint may carry the provider secret.
 */
export function assertOutboundUrlSafe(
  rawUrl: string,
  secrets: readonly string[],
  opts: OutboundUrlGuardOptions = {}
): void {
  if (!rawUrl || secrets.length === 0) return;
  if (!containsActiveSecret(rawUrl, secrets)) return;

  if (opts.allowCredentialedOrigin) {
    try {
      const parsed = new URL(rawUrl);
      const allowedOrigin = new URL(opts.allowCredentialedOrigin).origin;
      const prefix = opts.allowCredentialedPathPrefix ?? '/dyn/api/fast_download.json';
      if (parsed.origin === allowedOrigin && parsed.pathname.startsWith(prefix)) {
        return;
      }
    } catch {
      // Fall through to block
    }
  }

  throw new Error('Blocked outbound request URL containing active provider credential');
}

/**
 * Extracts every embedded destination a P2P client will contact on its own from a magnet URI
 * (`tr` trackers, `ws` web seeds, `xs` exact sources, `as` acceptable sources).
 */
export function extractMagnetEmbeddedUrls(magnetUri: string): string[] {
  const qIdx = magnetUri.indexOf('?');
  if (qIdx === -1) return [];
  const out: string[] = [];
  for (const pair of magnetUri.slice(qIdx + 1).split('&')) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx === -1) continue;
    const key = pair.slice(0, eqIdx).toLowerCase().replace(/\.\d+$/, '');
    if (key !== 'tr' && key !== 'ws' && key !== 'xs' && key !== 'as') continue;
    let val = pair.slice(eqIdx + 1).replace(/\+/g, '%20');
    try {
      val = decodeURIComponent(val);
    } catch {
      // keep raw value; the guard still inspects it
    }
    if (val.trim()) out.push(val.trim());
  }
  return out;
}

/**
 * Applies the outbound credential guard to a top-level URI AND every embedded destination it
 * would cause a child process to contact (magnet trackers / web seeds, `.torrent` announce and
 * url-list entries), using the live secret set at dispatch time.
 */
export function assertOutboundDestinationsSafe(
  topLevel: readonly string[],
  embedded: readonly string[],
  secrets: readonly string[]
): void {
  for (const u of topLevel) {
    assertOutboundUrlSafe(u, secrets);
    if (/^magnet:\?/i.test(u)) {
      for (const inner of extractMagnetEmbeddedUrls(u)) {
        assertOutboundUrlSafe(inner, secrets);
      }
    }
  }
  for (const u of embedded) {
    assertOutboundUrlSafe(u, secrets);
  }
}

/**
 * Upstream validators (ETag / Last-Modified) are server-controlled strings; never expose one
 * that echoes an active credential.
 */
export function redactValidator(value: string | undefined, secrets: readonly string[]): string | undefined {
  if (!value) return value;
  return containsActiveSecret(value, secrets) ? '***' : value;
}

/**
 * Converts a rejected raw paste token into a safe, non-secret summary so raw credentials
 * or malformed secret-bearing tokens are never echoed back in API responses.
 */
export function summarizeRejectedToken(rawToken: string): string {
  const trimmed = rawToken.trim();
  const schemeMatch = trimmed.match(/^([a-z][a-z0-9+.-]*):/i);
  if (schemeMatch?.[1]) {
    return `[unsupported ${schemeMatch[1].toLowerCase()}: token]`;
  }
  return '[invalid token]';
}

/**
 * Normalizes and redacts an upstream error before surfacing it in UI state or logs.
 */
export function sanitizeUpstreamError(
  err: unknown,
  secrets: readonly string[] = [],
  maxLength = 260
): string {
  const raw = err instanceof Error ? err.message : String(err ?? 'Unknown upstream error');
  const redacted = redactText(raw, secrets).replace(/\s+/g, ' ').trim();
  if (redacted.length <= maxLength) return redacted;
  return `${redacted.slice(0, maxLength - 1)}…`;
}
