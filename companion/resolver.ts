import http from 'node:http';
import https from 'node:https';
import type { AppSettings, RoutingLogEntry } from '../shared/types.js';
import { DEFAULT_PUBLIC_IPFS_GATEWAYS } from '../shared/compat.js';
import { isApprovedAnnasHostname, sanitizeIpfsSubPath } from '../shared/inputParser.js';
import { normalizeHostname, sanitizeFilename } from '../server/utils.js';
import type { CandidateSource } from './benchmarker.js';
import { assertOutboundUrlSafe, containsActiveSecret, sanitizeUpstreamError } from './parser.js';

export const DEFAULT_IPFS_GATEWAYS = [...DEFAULT_PUBLIC_IPFS_GATEWAYS];

export interface SourceResolutionResult {
  md5: string;
  filenameHint?: string;
  candidates: CandidateSource[];
  resolvedCids: string[];
  magnetLinks: string[];
  torrentUrls: string[];
  routingLog: RoutingLogEntry[];
}

export interface ResolveBookSourcesOptions {
  timeoutMs?: number;
  apiKey?: string;
  allowInsecureLoopbackForTests?: boolean;
}

const ANTI_BOT_PATTERNS = [
  /cf-browser-verification/i,
  /challenge-platform/i,
  /just a moment\.\.\./i,
  /ddos-guard/i,
  /cf-turnstile/i,
  /challenges\.cloudflare\.com/i,
  /hcaptcha/i,
  /g-recaptcha/i,
  /verify you are human/i,
];

const IGNORED_EXTERNAL_HOSTS = new Set([
  'twitter.com',
  'x.com',
  't.me',
  'discord.gg',
  'discord.com',
  'reddit.com',
  'www.reddit.com',
  'en.wikipedia.org',
  'creativecommons.org',
  'goodreads.com',
  'www.goodreads.com',
  'amazon.com',
  'www.amazon.com',
  'worldcat.org',
  'www.worldcat.org',
]);

const STATIC_EXTS = /\.(?:css|js|mjs|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp|map)$/i;
const BOOK_EXTS = /\.(?:epub|pdf|mobi|azw3?|kfx|djvu|cbz|cbr|fb2|zip|rar|7z)$/i;

export function isAntiBotChallenge(statusCode: number, body: string): boolean {
  if (statusCode === 403 || statusCode === 429 || statusCode === 503) {
    return true;
  }
  const sample = body.slice(0, 64 * 1024);
  return ANTI_BOT_PATTERNS.some((rx) => rx.test(sample));
}

export function expandIpfsCidToCandidates(
  cid: string,
  gateways: string[] = DEFAULT_IPFS_GATEWAYS,
  subPath?: string
): CandidateSource[] {
  const list = gateways.length > 0 ? gateways : DEFAULT_IPFS_GATEWAYS;
  const out: CandidateSource[] = [];
  const seen = new Set<string>();
  const safeSubPath = sanitizeIpfsSubPath(subPath);
  const encodedSubPath = safeSubPath
    ? '/' + safeSubPath.split('/').map((part) => encodeURIComponent(part)).join('/')
    : '';

  for (const template of list) {
    const trimmed = template.trim();
    if (!trimmed) continue;
    let expanded: string;
    if (/\{cid\}/i.test(trimmed)) {
      expanded = trimmed.replace(/\{cid\}/gi, encodeURIComponent(cid)) + encodedSubPath;
    } else {
      const base = trimmed.replace(/\/+$/, '');
      expanded = base.endsWith('/ipfs')
        ? `${base}/${encodeURIComponent(cid)}${encodedSubPath}`
        : `${base}/ipfs/${encodeURIComponent(cid)}${encodedSubPath}`;
    }
    try {
      const parsed = new URL(expanded);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') continue;
      const canonical = parsed.toString();
      if (seen.has(canonical)) continue;
      seen.add(canonical);
      const host = normalizeHostname(parsed.hostname);
      const isLocal = host === '127.0.0.1' || host === 'localhost';
      out.push({
        url: canonical,
        label: isLocal ? 'Local IPFS (127.0.0.1:8080)' : `IPFS (${host})`,
        tier: 'ipfs',
        host,
        priority: isLocal ? 85 : 65,
        cid,
        subPath: safeSubPath,
        provenance: isLocal ? 'ipfs:local' : `ipfs:${host}`,
      });
    } catch {
      // Ignore malformed gateway template
    }
  }
  return out;
}

export function expandCustomMirrors(md5: string, templates: string[]): CandidateSource[] {
  const out: CandidateSource[] = [];
  const seen = new Set<string>();
  const cleanMd5 = md5.trim().toLowerCase();

  for (let i = 0; i < templates.length; i++) {
    const raw = templates[i]?.trim() ?? '';
    if (!raw) continue;
    let expanded: string;
    if (/\{md5\}/i.test(raw)) {
      expanded = raw.replace(/\{md5\}/gi, cleanMd5);
    } else {
      expanded = `${raw.replace(/\/+$/, '')}/${cleanMd5}`;
    }
    try {
      const parsed = new URL(expanded);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') continue;
      const canonical = parsed.toString();
      if (seen.has(canonical)) continue;
      seen.add(canonical);
      const host = normalizeHostname(parsed.hostname);
      out.push({
        url: canonical,
        label: `Custom Mirror #${out.length + 1} (${host})`,
        tier: 'mirror',
        host,
        priority: 80,
        provenance: `custom_mirror:${host}`,
      });
    } catch {
      // Ignore malformed template
    }
  }
  return out;
}

function fetchSmallText(
  rawUrl: string,
  timeoutMs: number,
  maxBytes = 2 * 1024 * 1024,
  opts: {
    sameOriginOnly?: boolean;
    secrets?: readonly string[];
    allowCredentialedOrigin?: string;
  } = {}
): Promise<{ finalUrl: string; statusCode: number; body: string }> {
  const secrets = opts.secrets ?? [];
  return new Promise((resolve, reject) => {
    let settled = false;
    let activeReq: http.ClientRequest | null = null;
    let activeRes: http.IncomingMessage | null = null;

    const fail = (err: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      activeRes?.destroy();
      activeReq?.destroy();
      const safeErr =
        err instanceof Error
          ? new Error(sanitizeUpstreamError(err, secrets))
          : new Error(sanitizeUpstreamError(err, secrets));
      reject(safeErr);
    };

    const succeed = (val: { finalUrl: string; statusCode: number; body: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      resolve(val);
    };

    const hardTimer = setTimeout(() => {
      fail(new Error(`Request timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    const step = (target: URL, hop: number) => {
      if (settled) return;
      try {
        // Unified outbound secret guard: only hop 0 on the explicit approved Tier-1 endpoint may carry the provider key
        assertOutboundUrlSafe(
          target.toString(),
          secrets,
          hop === 0 && opts.allowCredentialedOrigin
            ? {
                allowCredentialedOrigin: opts.allowCredentialedOrigin,
                allowCredentialedPathPrefix: '/dyn/api/fast_download.json',
              }
            : {}
        );
      } catch (guardErr) {
        fail(guardErr);
        return;
      }
      const isHttps = target.protocol === 'https:';
      const client = isHttps ? https : http;

      const req = client.request(
        target,
        {
          method: 'GET',
          headers: {
            'User-Agent': 'BoltGate/1.0 (+SafeDownloader)',
            Accept: 'text/html,application/json;q=0.9,*/*;q=0.8',
            'Accept-Encoding': 'identity',
          },
          timeout: timeoutMs,
          ...(isHttps ? { rejectUnauthorized: true } : {}),
        },
        (res) => {
          activeRes = res;
          const status = res.statusCode ?? 0;
          if (status >= 300 && status < 400 && typeof res.headers.location === 'string') {
            res.destroy();
            if (hop >= 5) {
              fail(new Error('Too many redirects fetching metadata'));
              return;
            }
            try {
              const nextUrl = new URL(res.headers.location, target);
              if (nextUrl.protocol !== 'http:' && nextUrl.protocol !== 'https:') {
                throw new Error(`Unsafe redirect scheme: ${nextUrl.protocol}`);
              }
              assertOutboundUrlSafe(nextUrl.toString(), secrets);
              if (opts.sameOriginOnly && nextUrl.origin !== target.origin) {
                throw new Error(
                  `Blocked cross-origin redirect on credentialed provider request (${nextUrl.origin})`
                );
              }
              step(nextUrl, hop + 1);
            } catch (err) {
              fail(err);
            }
            return;
          }

          const chunks: Buffer[] = [];
          let bytes = 0;

          const finish = () => {
            if (!res.destroyed) res.destroy();
            succeed({
              finalUrl: target.toString(),
              statusCode: status,
              body: Buffer.concat(chunks).toString('utf8'),
            });
          };

          res.on('data', (chunk: Buffer) => {
            if (settled) return;
            const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            const rem = maxBytes - bytes;
            if (rem <= 0) {
              finish();
              return;
            }
            const slice = buf.length > rem ? buf.subarray(0, rem) : buf;
            chunks.push(slice);
            bytes += slice.length;
            if (bytes >= maxBytes) finish();
          });
          res.on('end', finish);
          res.on('close', finish);
          res.on('error', (err) => {
            fail(err);
          });
        }
      );

      activeReq = req;
      req.on('timeout', () => {
        fail(new Error(`Request timed out after ${timeoutMs}ms`));
      });
      req.on('error', (err) => {
        fail(err);
      });
      req.end();
    };

    try {
      step(new URL(rawUrl), 0);
    } catch (err) {
      fail(err);
    }
  });
}

function extractFilenameHint(html: string, md5: string): string | undefined {
  const h1Match = html.match(/<h1[^>]*>([\s\S]{2,180}?)<\/h1>/i);
  const ogMatch = html.match(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']{2,180})["']/i);
  const titleMatch = html.match(/<title[^>]*>([^<]{2,180})<\/title>/i);
  const rawTitle = (h1Match?.[1] ?? ogMatch?.[1] ?? titleMatch?.[1] ?? '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  const extMatch = html.match(/([A-Za-z0-9_.\- ]+\.(?:epub|pdf|mobi|azw3|djvu|cbz|cbr|fb2))/i);
  const extFromHtml = extMatch?.[1] ? extMatch[1].slice(extMatch[1].lastIndexOf('.')).toLowerCase() : '';

  if (rawTitle && !/anna'?s archive/i.test(rawTitle)) {
    return sanitizeFilename(rawTitle, extFromHtml);
  }
  if (extFromHtml) {
    return `${md5}${extFromHtml}`;
  }
  return undefined;
}

export function resolveApprovedProviderOrigin(
  configuredBaseUrl: string | undefined,
  allowInsecureLoopback = false
): { origin: string | null; reason?: string } {
  const raw = (configuredBaseUrl ?? '').trim() || 'https://annas-archive.org';
  try {
    const parsed = new URL(raw);
    const host = normalizeHostname(parsed.hostname);
    if (
      allowInsecureLoopback &&
      (host === '127.0.0.1' || host === 'localhost') &&
      (parsed.protocol === 'http:' || parsed.protocol === 'https:')
    ) {
      return { origin: parsed.origin };
    }
    if (parsed.protocol !== 'https:') {
      return {
        origin: null,
        reason: `Provider origin must use HTTPS (${parsed.protocol}//${host})`,
      };
    }
    if (!isApprovedAnnasHostname(host)) {
      return {
        origin: null,
        reason: `Configured provider host (${host}) is not an approved Anna's Archive HTTPS origin`,
      };
    }
    return { origin: parsed.origin };
  } catch {
    return { origin: null, reason: 'Invalid configured provider base URL' };
  }
}

/**
 * 4-Tier Book Source Resolver for Anna's Archive MD5 hashes / URLs:
 * Tier 1: Official Fast Download API (strictly bound to approved configured HTTPS origin)
 * Tier 2: Custom external mirror templates + clean HTML metadata/mirror extraction (bails immediately on anti-bot gates)
 * Tier 3: Concurrent IPFS gateway expansion for any discovered CIDs (with full subpath preservation)
 * Tier 4: Magnet / .torrent URL extraction for P2P delegation
 */
export async function resolveBookSources(
  params: { md5: string; sourcePageUrl?: string },
  settings: AppSettings,
  options: ResolveBookSourcesOptions = {}
): Promise<SourceResolutionResult> {
  const timeoutMs = options.timeoutMs ?? 8_000;
  const apiKey = (options.apiKey ?? '').trim();
  const secrets = apiKey ? [apiKey] : [];
  const md5 = params.md5.trim().toLowerCase();
  const routingLog: RoutingLogEntry[] = [];
  const candidates: CandidateSource[] = [];
  const seenUrls = new Set<string>();
  const resolvedIpfs = new Map<string, { cid: string; subPath?: string }>();
  const magnetLinks: string[] = [];
  const seenMagnets = new Set<string>();
  const torrentUrls: string[] = [];
  const seenTorrents = new Set<string>();
  let filenameHint: string | undefined;

  const pushCandidate = (cand: CandidateSource) => {
    if (secrets.length > 0 && containsActiveSecret(cand.url, secrets)) {
      routingLog.push({
        timestamp: Date.now(),
        level: 'warn',
        message: `Rejected candidate URL on ${cand.host} containing active provider credential before downstream request`,
      });
      return;
    }
    if (seenUrls.has(cand.url)) return;
    seenUrls.add(cand.url);
    candidates.push(cand);
  };

  const addIpfsTarget = (cid: string, rawSubPath?: string) => {
    const cleanCid = cid.trim();
    if (!cleanCid) return;
    const subPath = sanitizeIpfsSubPath(rawSubPath);
    const key = `${cleanCid}/${subPath ?? ''}`;
    if (!resolvedIpfs.has(key)) {
      resolvedIpfs.set(key, { cid: cleanCid, subPath });
    }
  };

  const providerCheck = resolveApprovedProviderOrigin(
    settings.annasArchiveBaseUrl,
    Boolean(options.allowInsecureLoopbackForTests)
  );
  const configuredOrigin = providerCheck.origin;

  // Tier 1: Official Fast Download API (strictly bound to configured approved HTTPS origin)
  if (apiKey) {
    if (!configuredOrigin) {
      routingLog.push({
        timestamp: Date.now(),
        level: 'warn',
        message: `Tier 1 Fast API blocked: ${providerCheck.reason ?? 'unapproved provider origin'}`,
      });
    } else {
      try {
        const apiEndpoint = `${configuredOrigin}/dyn/api/fast_download.json?md5=${encodeURIComponent(md5)}&key=${encodeURIComponent(apiKey)}`;
        const apiResp = await fetchSmallText(apiEndpoint, timeoutMs, 512 * 1024, {
          sameOriginOnly: true,
          secrets,
          allowCredentialedOrigin: configuredOrigin,
        });
        if (apiResp.statusCode >= 200 && apiResp.statusCode < 300) {
          const parsed = JSON.parse(apiResp.body) as { download_url?: string | null; error?: string };
          if (parsed.download_url) {
            const dlUrl = new URL(parsed.download_url, configuredOrigin);
            if (dlUrl.protocol === 'http:' || dlUrl.protocol === 'https:') {
              const host = normalizeHostname(dlUrl.hostname);
              pushCandidate({
                url: dlUrl.toString(),
                label: `Fast Download API (${host})`,
                tier: 'fast_api',
                host,
                priority: 100,
                provenance: `fast_api:${new URL(configuredOrigin).hostname}`,
              });
              routingLog.push({
                timestamp: Date.now(),
                level: 'ok',
                message: `Tier 1 Fast Download API resolved direct link on ${host}`,
              });
            }
          } else if (parsed.error) {
            routingLog.push({
              timestamp: Date.now(),
              level: 'warn',
              message: `Tier 1 Fast API reported: ${sanitizeUpstreamError(parsed.error, secrets)}`,
            });
          }
        } else {
          routingLog.push({
            timestamp: Date.now(),
            level: 'warn',
            message: `Tier 1 Fast API returned HTTP ${apiResp.statusCode} — falling back to mirrors & IPFS`,
          });
        }
      } catch (err) {
        routingLog.push({
          timestamp: Date.now(),
          level: 'warn',
          message: `Tier 1 Fast API lookup failed: ${sanitizeUpstreamError(err, secrets)}`,
        });
      }
    }
  }

  // Tier 2A: User-configured custom external mirror templates
  const customMirrors = expandCustomMirrors(md5, settings.customMirrorUrls);
  for (const m of customMirrors) {
    pushCandidate(m);
  }
  if (customMirrors.length > 0) {
    routingLog.push({
      timestamp: Date.now(),
      level: 'info',
      message: `Expanded ${customMirrors.length} configured custom mirror URL(s) for MD5 ${md5.slice(0, 8)}…`,
    });
  }

  // Tier 2B: Metadata page inspection (respects anti-bot gates strictly & never scrapes unapproved sourcePageUrl origins)
  let pageUrl = `${configuredOrigin ?? 'https://annas-archive.org'}/md5/${md5}`;
  if (params.sourcePageUrl) {
    try {
      const candidatePageUrl = new URL(params.sourcePageUrl);
      const pageHost = normalizeHostname(candidatePageUrl.hostname);
      const allowLoopback =
        Boolean(options.allowInsecureLoopbackForTests) &&
        (pageHost === '127.0.0.1' || pageHost === 'localhost');
      if (
        (candidatePageUrl.protocol === 'https:' && isApprovedAnnasHostname(pageHost)) ||
        allowLoopback ||
        (configuredOrigin && candidatePageUrl.origin === configuredOrigin)
      ) {
        pageUrl = candidatePageUrl.toString();
      }
    } catch {
      // Keep default configured page URL
    }
  }

  try {
    const pageResp = await fetchSmallText(pageUrl, timeoutMs, 2 * 1024 * 1024, { secrets });
    if (isAntiBotChallenge(pageResp.statusCode, pageResp.body)) {
      routingLog.push({
        timestamp: Date.now(),
        level: 'warn',
        message: `Metadata page (${new URL(pageUrl).hostname}) returned HTTP ${pageResp.statusCode} / anti-bot check — skipping page scrape and relying on Fast API / custom mirrors / IPFS`,
      });
    } else if (pageResp.statusCode >= 200 && pageResp.statusCode < 300) {
      filenameHint = extractFilenameHint(pageResp.body, md5);
      const pageHost = normalizeHostname(new URL(pageResp.finalUrl).hostname);

      // Extract IPFS CIDs including optional nested subpath
      const cidMatches =
        pageResp.body.matchAll(
          /(?:\/ipfs\/|ipfs:\/\/)(Qm[1-9A-HJ-NP-Za-km-z]{44}|baf[a-z2-7]{50,})(?:\/([^\s"'<>?#]+))?/g
        ) ?? [];
      for (const m of cidMatches) {
        if (m[1]) addIpfsTarget(m[1], m[2]);
      }

      // Extract magnet links
      const magMatches = pageResp.body.match(/magnet:\?[^\s"'<>]+/gi) ?? [];
      for (const mag of magMatches) {
        const cleanMag = mag.replace(/&amp;/g, '&');
        if (secrets.length > 0 && containsActiveSecret(cleanMag, secrets)) continue;
        if (!seenMagnets.has(cleanMag)) {
          seenMagnets.add(cleanMag);
          magnetLinks.push(cleanMag);
        }
      }

      // Extract href links
      const hrefRegex = /href\s*=\s*["']([^"'#]+)["']/gi;
      let hrefMatch: RegExpExecArray | null;
      while ((hrefMatch = hrefRegex.exec(pageResp.body)) !== null) {
        const rawHref = hrefMatch[1]?.trim().replace(/&amp;/g, '&');
        if (!rawHref) continue;
        if (rawHref.startsWith('magnet:')) {
          if (secrets.length > 0 && containsActiveSecret(rawHref, secrets)) continue;
          if (!seenMagnets.has(rawHref)) {
            seenMagnets.add(rawHref);
            magnetLinks.push(rawHref);
          }
          continue;
        }
        try {
          const resolved = new URL(rawHref, pageResp.finalUrl);
          if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') continue;
          const hrefHost = normalizeHostname(resolved.hostname);
          const pathLower = resolved.pathname.toLowerCase();

          if (STATIC_EXTS.test(pathLower)) continue;
          if (IGNORED_EXTERNAL_HOSTS.has(hrefHost)) continue;

          if (pathLower.endsWith('.torrent')) {
            const tUrl = resolved.toString();
            if (secrets.length > 0 && containsActiveSecret(tUrl, secrets)) continue;
            if (!seenTorrents.has(tUrl)) {
              seenTorrents.add(tUrl);
              torrentUrls.push(tUrl);
            }
            continue;
          }

          const ipfsMatch = resolved.pathname.match(
            /\/ipfs\/(Qm[1-9A-HJ-NP-Za-km-z]{44}|baf[a-z2-7]{50,})(?:\/([^?#]+))?/
          );
          if (ipfsMatch?.[1]) {
            addIpfsTarget(ipfsMatch[1], ipfsMatch[2]);
            continue;
          }

          const isSlowPartner = /\/slow_download\//i.test(pathLower);
          const isFastEndpoint = /\/fast_download\//i.test(pathLower);
          const looksLikeFileLink =
            isSlowPartner ||
            isFastEndpoint ||
            BOOK_EXTS.test(pathLower) ||
            /\/(?:download|get\.php|main|ads\.php|d\/)/i.test(pathLower) ||
            (hrefHost !== pageHost && resolved.search.includes(md5));

          if (!looksLikeFileLink) continue;

          pushCandidate({
            url: resolved.toString(),
            label: isSlowPartner
              ? `Slow Partner (${hrefHost})`
              : isFastEndpoint
                ? `Fast Endpoint (${hrefHost})`
                : `External Mirror (${hrefHost})`,
            tier: isFastEndpoint ? 'fast_api' : 'mirror',
            host: hrefHost,
            priority: isSlowPartner ? 10 : isFastEndpoint ? 95 : 70,
            isSlowPartner,
            provenance: isSlowPartner
              ? `slow_partner:${hrefHost}`
              : `metadata_scrape:${hrefHost}`,
          });
        } catch {
          // Ignore malformed href
        }
      }

      routingLog.push({
        timestamp: Date.now(),
        level: 'info',
        message: `Metadata scan found ${candidates.filter((c) => !c.isSlowPartner).length} mirror(s), ${resolvedIpfs.size} IPFS target(s), ${magnetLinks.length + torrentUrls.length} P2P source(s)`,
      });
    } else {
      routingLog.push({
        timestamp: Date.now(),
        level: 'warn',
        message: `Metadata page returned HTTP ${pageResp.statusCode} — continuing with custom mirrors & IPFS`,
      });
    }
  } catch (err) {
    routingLog.push({
      timestamp: Date.now(),
      level: 'warn',
      message: `Metadata lookup skipped: ${sanitizeUpstreamError(err, secrets)}`,
    });
  }

  // Tier 3: Expand discovered IPFS CIDs into gateway race candidates
  if (resolvedIpfs.size > 0) {
    for (const target of resolvedIpfs.values()) {
      const gwCandidates = expandIpfsCidToCandidates(
        target.cid,
        settings.ipfsGateways,
        target.subPath
      );
      for (const gw of gwCandidates) {
        pushCandidate(gw);
      }
    }
    routingLog.push({
      timestamp: Date.now(),
      level: 'info',
      message: `Queued ${resolvedIpfs.size} IPFS target(s) across ${settings.ipfsGateways.length || DEFAULT_IPFS_GATEWAYS.length} gateways for concurrent racing`,
    });
  }

  // Sort: fast/external/IPFS mirrors first, slow partner links strictly last
  candidates.sort((a, b) => {
    const aSlow = a.isSlowPartner ? 1 : 0;
    const bSlow = b.isSlowPartner ? 1 : 0;
    if (aSlow !== bSlow) return aSlow - bSlow;
    return b.priority - a.priority;
  });

  return {
    md5,
    filenameHint,
    candidates,
    resolvedCids: Array.from(resolvedIpfs.values()).map((t) =>
      t.subPath ? `${t.cid}/${t.subPath}` : t.cid
    ),
    magnetLinks,
    torrentUrls,
    routingLog,
  };
}
