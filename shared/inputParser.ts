export type ParsedInputKind =
  | 'direct_url'
  | 'annas_md5'
  | 'raw_md5'
  | 'magnet'
  | 'torrent_url'
  | 'ipfs_uri';

export type ParsedInputEntry =
  | { kind: 'direct_url'; raw: string; url: string; host: string }
  | { kind: 'annas_md5'; raw: string; md5: string; sourcePageUrl: string; host: string }
  | { kind: 'raw_md5'; raw: string; md5: string }
  | { kind: 'magnet'; raw: string; magnetUri: string; infoHash?: string; displayName?: string }
  | { kind: 'torrent_url'; raw: string; url: string; host: string }
  | { kind: 'ipfs_uri'; raw: string; cid: string; subPath?: string; filename?: string };

export interface SmartParseOptions {
  approvedProviderHosts?: readonly string[];
}

export const APPROVED_ANNAS_HOST_REGEX =
  /^(?:[a-z0-9-]+\.)*annas-archive\.(?:org|li|se|gs|pm|in|gl)$/i;

export function isApprovedAnnasHostname(
  hostname: string,
  extraApprovedHosts: readonly string[] = []
): boolean {
  const normalized = hostname.trim().toLowerCase().replace(/\.+$/, '');
  if (!normalized) return false;
  if (APPROVED_ANNAS_HOST_REGEX.test(normalized)) {
    return true;
  }
  return extraApprovedHosts.some(
    (entry) => entry.trim().toLowerCase().replace(/\.+$/, '') === normalized
  );
}

export function sanitizeIpfsSubPath(rawSubPath?: string): string | undefined {
  if (!rawSubPath) return undefined;
  const cleaned = cleanTrailingPunctuation(rawSubPath).replace(/^\/+|\/+$/g, '');
  if (!cleaned) return undefined;
  const parts = cleaned.split('/').filter(Boolean);
  if (parts.length === 0) return undefined;
  const safeParts: string[] = [];
  for (const part of parts) {
    let decoded = part;
    try {
      decoded = decodeURIComponent(part);
    } catch {
      return undefined;
    }
    if (!part || part === '.' || part === '..' || decoded === '.' || decoded === '..' || decoded.includes('/') || decoded.includes('\\')) {
      return undefined;
    }
    safeParts.push(decoded);
  }
  return safeParts.join('/');
}

export interface SmartParseResult {
  entries: ParsedInputEntry[];
  rejectedTokens: string[];
  directUrls: string[];
  hasMultiMirrors: boolean;
  summaryLabel: string;
}

function cleanTrailingPunctuation(raw: string): string {
  let cleaned = raw.trim();
  while (cleaned.length > 0 && /[.,;!?"'>\]]$/.test(cleaned)) {
    cleaned = cleaned.slice(0, -1);
  }
  while (cleaned.endsWith(')')) {
    const openCount = (cleaned.match(/\(/g) ?? []).length;
    const closeCount = (cleaned.match(/\)/g) ?? []).length;
    if (closeCount > openCount) {
      cleaned = cleaned.slice(0, -1);
    } else {
      break;
    }
  }
  return cleaned;
}

function parseMagnetDetails(magnetUri: string): { infoHash?: string; displayName?: string } {
  const queryIndex = magnetUri.indexOf('?');
  if (queryIndex === -1) return {};
  const params = new URLSearchParams(magnetUri.slice(queryIndex + 1));
  const xtList = params.getAll('xt');
  let infoHash: string | undefined;
  for (const xt of xtList) {
    const m = xt.match(/^urn:btih:([a-zA-Z0-9]{32,40})$/i);
    if (m?.[1]) {
      infoHash = m[1].toLowerCase();
      break;
    }
  }
  const dn = params.get('dn')?.trim();
  return {
    infoHash,
    displayName: dn || undefined,
  };
}

/**
 * Parses arbitrary pasted text into structured BoltGate download entries:
 * direct HTTP(S) URLs, Anna's Archive /md5/<hash> URLs, raw 32-char MD5 hashes,
 * multi-line mirror lists, magnet:? links, .torrent URLs, and ipfs:// URIs.
 */
export function parseSmartInput(
  rawText: string,
  options: SmartParseOptions = {}
): SmartParseResult {
  const entries: ParsedInputEntry[] = [];
  const rejectedTokens: string[] = [];
  const seenRejected = new Set<string>();
  const seenUrls = new Set<string>();
  const seenMd5s = new Set<string>();
  const seenMagnets = new Set<string>();
  const seenIpfsKeys = new Set<string>();
  const directUrls: string[] = [];
  const approvedHosts = options.approvedProviderHosts ?? [];

  let remainingText = rawText;

  // 1. Magnet links
  const magnetRegex = /magnet:\?[^\s<>"'`]+/gi;
  const magnetMatches = rawText.match(magnetRegex) ?? [];
  for (const raw of magnetMatches) {
    const cleaned = cleanTrailingPunctuation(raw);
    const details = parseMagnetDetails(cleaned);
    const dedupKey = details.infoHash ? `btih:${details.infoHash}` : cleaned.toLowerCase();
    if (!seenMagnets.has(dedupKey)) {
      seenMagnets.add(dedupKey);
      entries.push({
        kind: 'magnet',
        raw: cleaned,
        magnetUri: cleaned,
        infoHash: details.infoHash,
        displayName: details.displayName,
      });
    }
  }
  remainingText = remainingText.replace(magnetRegex, ' ');

  // 2. ipfs://<cid>/... URIs
  const ipfsRegex = /ipfs:\/\/([a-zA-Z0-9]+)(?:\/([^\s<>"'`?#]+))?/gi;
  const ipfsMatches = Array.from(remainingText.matchAll(ipfsRegex));
  for (const match of ipfsMatches) {
    const full = cleanTrailingPunctuation(match[0]);
    const cid = match[1] ?? '';
    const subPath = sanitizeIpfsSubPath(match[2]);
    const dedupKey = `${cid}/${subPath ?? ''}`;
    if (cid && !seenIpfsKeys.has(dedupKey)) {
      seenIpfsKeys.add(dedupKey);
      const filename = subPath ? subPath.split('/').filter(Boolean).pop() : undefined;
      entries.push({
        kind: 'ipfs_uri',
        raw: full,
        cid,
        subPath,
        filename,
      });
    }
  }
  remainingText = remainingText.replace(ipfsRegex, ' ');

  // 3. HTTP/HTTPS URLs
  const httpRegex = /https?:\/\/[^\s<>"'`]+/gi;
  const httpMatches = remainingText.match(httpRegex) ?? [];
  for (const match of httpMatches) {
    const cleaned = cleanTrailingPunctuation(match);
    try {
      const parsed = new URL(cleaned);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') continue;
      const canonical = parsed.toString();
      const host = parsed.hostname.toLowerCase();

      const md5Match = parsed.pathname.match(/\/md5\/([a-f0-9]{32})(?:[/?#]|$)/i);
      if (md5Match?.[1] && isApprovedAnnasHostname(host, approvedHosts)) {
        const md5 = md5Match[1].toLowerCase();
        if (!seenMd5s.has(md5)) {
          seenMd5s.add(md5);
          entries.push({
            kind: 'annas_md5',
            raw: canonical,
            md5,
            sourcePageUrl: canonical,
            host,
          });
        }
        continue;
      }

      const ipfsGatewayMatch = parsed.pathname.match(
        /\/ipfs\/(Qm[1-9A-HJ-NP-Za-km-z]{44}|baf[a-z2-7]{50,})(?:\/([^?#]+))?/i
      );
      if (ipfsGatewayMatch?.[1]) {
        const cid = ipfsGatewayMatch[1];
        const subPath = sanitizeIpfsSubPath(ipfsGatewayMatch[2]);
        const dedupKey = `${cid}/${subPath ?? ''}`;
        if (!seenIpfsKeys.has(dedupKey)) {
          seenIpfsKeys.add(dedupKey);
          const filename =
            (subPath ? subPath.split('/').filter(Boolean).pop() : undefined) ??
            (parsed.searchParams.get('filename') || undefined);
          entries.push({
            kind: 'ipfs_uri',
            raw: canonical,
            cid,
            subPath,
            filename,
          });
        }
        continue;
      }

      if (parsed.pathname.toLowerCase().endsWith('.torrent')) {
        if (!seenUrls.has(canonical)) {
          seenUrls.add(canonical);
          entries.push({
            kind: 'torrent_url',
            raw: canonical,
            url: canonical,
            host,
          });
        }
        continue;
      }

      if (!seenUrls.has(canonical)) {
        seenUrls.add(canonical);
        directUrls.push(canonical);
        entries.push({
          kind: 'direct_url',
          raw: canonical,
          url: canonical,
          host,
        });
      }
    } catch {
      if (!seenRejected.has(cleaned)) {
        seenRejected.add(cleaned);
        rejectedTokens.push(cleaned);
      }
    }
  }
  remainingText = remainingText.replace(httpRegex, ' ');

  // 4. Flag explicit unsafe schemes (note: magnet: and ipfs: are now supported!)
  const unsafeSchemeRegex = /(?:javascript|file|data|vbscript|ftp):[^\s<>"'`]*/gi;
  const unsafeMatches = remainingText.match(unsafeSchemeRegex) ?? [];
  for (const token of unsafeMatches) {
    if (!seenRejected.has(token)) {
      seenRejected.add(token);
      rejectedTokens.push(token);
    }
  }
  remainingText = remainingText.replace(unsafeSchemeRegex, ' ');

  // 5. Standalone 32-char MD5 hashes (must NOT match 64-char SHA-256 tokens)
  const rawTokens = remainingText.split(/[\s,;]+/).filter(Boolean);
  for (const rawToken of rawTokens) {
    const trimmed = rawToken.replace(/^[("'[\]]+|[)"'\].,;!?]+$/g, '');
    if (/^[a-f0-9]{32}$/i.test(trimmed)) {
      const md5 = trimmed.toLowerCase();
      if (!seenMd5s.has(md5)) {
        seenMd5s.add(md5);
        entries.push({
          kind: 'raw_md5',
          raw: trimmed,
          md5,
        });
      }
    }
  }

  const hasMultiMirrors =
    directUrls.length >= 2 && entries.every((e) => e.kind === 'direct_url');

  let summaryLabel = '';
  if (entries.length === 1) {
    const only = entries[0]!;
    switch (only.kind) {
      case 'annas_md5':
        summaryLabel = `Anna's Archive MD5 (${only.md5.slice(0, 8)}…)`;
        break;
      case 'raw_md5':
        summaryLabel = `Book MD5 Hash (${only.md5.slice(0, 8)}…)`;
        break;
      case 'magnet':
        summaryLabel = `Magnet P2P${only.displayName ? ` (${only.displayName})` : ''}`;
        break;
      case 'torrent_url':
        summaryLabel = `Torrent File (${only.host})`;
        break;
      case 'ipfs_uri':
        summaryLabel = `IPFS CID (${only.cid.slice(0, 10)}…)`;
        break;
      case 'direct_url':
        summaryLabel = `Direct URL (${only.host})`;
        break;
    }
  } else if (entries.length > 1) {
    summaryLabel = hasMultiMirrors
      ? `${directUrls.length} Mirror URLs detected`
      : `${entries.length} sources detected`;
  }

  return {
    entries,
    rejectedTokens,
    directUrls,
    hasMultiMirrors,
    summaryLabel,
  };
}
