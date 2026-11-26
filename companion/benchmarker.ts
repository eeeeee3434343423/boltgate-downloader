import http from 'node:http';
import https from 'node:https';
import type { TLSSocket } from 'node:tls';
import type { RedirectHop, SourceTier, TlsInfo } from '../shared/types.js';
import {
  extensionFromMime,
  normalizeHostname,
  parseContentDispositionFilename,
  sanitizeFilename,
} from '../server/utils.js';
import {
  assertOutboundUrlSafe,
  redactSensitiveUrl,
  redactText,
  sanitizeUpstreamError,
} from './parser.js';

export interface CandidateSource {
  url: string;
  label: string;
  tier: SourceTier;
  host: string;
  priority: number;
  isSlowPartner?: boolean;
  cid?: string;
  subPath?: string;
  provenance?: string;
}

export interface CandidateBenchmarkResult {
  candidate: CandidateSource;
  ok: boolean;
  finalUrl: string;
  finalHost: string;
  statusCode?: number;
  totalBytes: number | null;
  supportsRanges: boolean;
  contentType?: string;
  etag?: string;
  lastModified?: string;
  suggestedFilename: string;
  probeSpeedBps: number;
  latencyMs: number;
  isHtmlTrap: boolean;
  error?: string;
  redirectChain: RedirectHop[];
  tls?: TlsInfo;
}

export interface BenchmarkOptions {
  concurrency?: number;
  timeoutMs?: number;
  localIpfsTimeoutMs?: number;
  sampleBytes?: number;
  filenameHint?: string;
  secrets?: readonly string[];
}

interface RawHeadResponse {
  url: URL;
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  tls?: TlsInfo;
}

interface RawRangeSample {
  url: URL;
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  tls?: TlsInfo;
  sampleBuf: Buffer;
  exceededSampleLimit: boolean;
  endedNaturally: boolean;
  elapsedMs: number;
}

const MAX_REDIRECTS = 10;

function firstStr(value?: string | string[]): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value || undefined;
}

function parseContentLength(header?: string | string[]): number | null {
  const val = Array.isArray(header) ? header[0] : header;
  if (!val) return null;
  const n = Number(val.trim());
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function extractTls(sock: TLSSocket | null | undefined): TlsInfo | undefined {
  if (!sock) return undefined;
  try {
    const cert = sock.getPeerCertificate?.();
    const subjCN = Array.isArray(cert?.subject?.CN) ? cert.subject.CN[0] : cert?.subject?.CN;
    const issuerO = Array.isArray(cert?.issuer?.O) ? cert.issuer.O[0] : cert?.issuer?.O;
    const issuerCN = Array.isArray(cert?.issuer?.CN) ? cert.issuer.CN[0] : cert?.issuer?.CN;
    return {
      authorized: Boolean(sock.authorized),
      issuer: issuerO || issuerCN,
      subjectCN: subjCN,
      validTo: cert?.valid_to || undefined,
    };
  } catch {
    return { authorized: Boolean(sock.authorized) };
  }
}

function detectHtmlSnippet(buf: Buffer, contentType?: string, filename?: string): boolean {
  const mime = (contentType ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
  const lowerName = (filename ?? '').toLowerCase();
  const expectsHtml =
    lowerName.endsWith('.html') || lowerName.endsWith('.htm') || lowerName.endsWith('.xhtml');
  if (expectsHtml) return false;
  if (mime === 'text/html' || mime === 'application/xhtml+xml') {
    return true;
  }
  if (buf.length === 0) return false;
  const head = buf.subarray(0, Math.min(512, buf.length)).toString('utf8').trimStart().toLowerCase();
  return (
    head.startsWith('<!doctype html') ||
    head.startsWith('<html') ||
    head.startsWith('<head') ||
    head.startsWith('<script')
  );
}

function requestWithRedirects(
  startUrl: URL,
  method: 'HEAD' | 'GET',
  headers: Record<string, string>,
  timeoutMs: number,
  maxBytes: number,
  redirectChain: RedirectHop[],
  secrets: readonly string[] = []
): Promise<RawRangeSample> {
  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    let overallSettled = false;
    let activeReq: http.ClientRequest | null = null;
    let activeRes: http.IncomingMessage | null = null;

    const fail = (err: unknown) => {
      if (overallSettled) return;
      overallSettled = true;
      clearTimeout(hardTimer);
      activeRes?.destroy();
      activeReq?.destroy();
      reject(err);
    };

    const succeed = (sample: RawRangeSample) => {
      if (overallSettled) return;
      overallSettled = true;
      clearTimeout(hardTimer);
      resolve(sample);
    };

    const hardTimer = setTimeout(() => {
      fail(new Error(`Benchmark timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    const step = (target: URL, hop: number) => {
      if (overallSettled) return;
      try {
        assertOutboundUrlSafe(target.toString(), secrets);
      } catch (guardErr) {
        fail(guardErr);
        return;
      }
      const isHttps = target.protocol === 'https:';
      const client = isHttps ? https : http;

      const req = client.request(
        target,
        {
          method,
          headers: {
            'User-Agent': 'BoltGate/1.0 (+SafeDownloader)',
            Accept: '*/*',
            'Accept-Encoding': 'identity',
            ...headers,
          },
          timeout: timeoutMs,
          ...(isHttps ? { rejectUnauthorized: true } : {}),
        },
        (res) => {
          activeRes = res;
          const status = res.statusCode ?? 0;
          if (status >= 300 && status < 400 && typeof res.headers.location === 'string') {
            res.destroy();
            if (hop >= MAX_REDIRECTS) {
              fail(new Error(`Too many redirects (>${MAX_REDIRECTS})`));
              return;
            }
            redirectChain.push({
              url: target.toString(),
              host: normalizeHostname(target.hostname),
              statusCode: status,
            });
            try {
              const nextUrl = new URL(res.headers.location, target);
              if (nextUrl.protocol !== 'http:' && nextUrl.protocol !== 'https:') {
                throw new Error(`Blocked unsafe redirect scheme: ${nextUrl.protocol}`);
              }
              assertOutboundUrlSafe(nextUrl.toString(), secrets);
              step(nextUrl, hop + 1);
            } catch (err) {
              fail(err);
            }
            return;
          }

          const tls = isHttps ? extractTls(res.socket as TLSSocket) : undefined;

          if (method === 'HEAD' || maxBytes <= 0) {
            res.destroy();
            succeed({
              url: target,
              statusCode: status,
              headers: res.headers,
              tls,
              sampleBuf: Buffer.alloc(0),
              exceededSampleLimit: false,
              endedNaturally: true,
              elapsedMs: Date.now() - startedAt,
            });
            return;
          }

          const chunks: Buffer[] = [];
          let totalRead = 0;
          let exceededSampleLimit = false;
          let endedNaturally = false;
          const is206 = status === 206;

          const finish = (natural = false) => {
            if (natural) endedNaturally = true;
            if (!res.destroyed) res.destroy();
            succeed({
              url: target,
              statusCode: status,
              headers: res.headers,
              tls,
              sampleBuf: Buffer.concat(chunks),
              exceededSampleLimit,
              endedNaturally,
              elapsedMs: Date.now() - startedAt,
            });
          };

          res.on('data', (chunk: Buffer) => {
            if (overallSettled) return;
            const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            const remaining = maxBytes - totalRead;
            if (remaining <= 0) {
              exceededSampleLimit = true;
              finish(false);
              return;
            }
            if (buf.length > remaining) {
              exceededSampleLimit = true;
              chunks.push(buf.subarray(0, remaining));
              totalRead += remaining;
              finish(false);
              return;
            }
            chunks.push(buf);
            totalRead += buf.length;
            // For 200 OK full bodies, stop early once sampleBytes reached;
            // for 206 ranged responses of exact sampleBytes, keep reading until EOF (or +1 overflow byte)
            if (!is206 && totalRead >= maxBytes) {
              finish(false);
            }
          });

          res.on('end', () => finish(true));
          res.on('close', () => finish(false));
          res.on('error', (err) => {
            if (overallSettled) return;
            fail(err);
          });
        }
      );

      activeReq = req;

      req.on('timeout', () => {
        fail(new Error(`Benchmark timed out after ${timeoutMs}ms`));
      });

      req.on('error', (err) => {
        fail(err);
      });

      req.end();
    };

    step(startUrl, 0);
  });
}

async function benchmarkSingleCandidate(
  candidate: CandidateSource,
  options: Required<BenchmarkOptions>
): Promise<CandidateBenchmarkResult> {
  const isLocalIpfs =
    candidate.tier === 'ipfs' &&
    (candidate.host === '127.0.0.1' || candidate.host === 'localhost');
  const timeoutMs = isLocalIpfs ? options.localIpfsTimeoutMs : options.timeoutMs;
  const redirectChain: RedirectHop[] = [];
  const startUrl = new URL(candidate.url);

  let headResp: RawHeadResponse | null = null;
  let rangeResp: RawRangeSample | null = null;

  try {
    try {
      const head = await requestWithRedirects(
        startUrl,
        'HEAD',
        {},
        timeoutMs,
        0,
        redirectChain,
        options.secrets
      );
      headResp = {
        url: head.url,
        statusCode: head.statusCode,
        headers: head.headers,
        tls: head.tls,
      };
    } catch (headErr) {
      // If the outbound secret leak guard blocked the URL/redirect, abort immediately!
      if (headErr instanceof Error && headErr.message.includes('active provider credential')) {
        throw headErr;
      }
      // Fall through to GET range probe
    }

    const headSucceeded =
      headResp !== null && headResp.statusCode >= 200 && headResp.statusCode < 300;
    if (!headSucceeded) {
      redirectChain.length = 0;
    }
    const probeStart = headSucceeded ? headResp!.url : startUrl;

    rangeResp = await requestWithRedirects(
      probeStart,
      'GET',
      { Range: `bytes=0-${options.sampleBytes - 1}` },
      timeoutMs,
      options.sampleBytes,
      redirectChain,
      options.secrets
    );

    const statusCode = rangeResp.statusCode;
    const headers = rangeResp.headers;
    const headSameValidator =
      headSucceeded &&
      !(
        headResp!.headers.etag &&
        headers.etag &&
        firstStr(headResp!.headers.etag) !== firstStr(headers.etag)
      );
    const validHeadHeaders = headSameValidator ? headResp!.headers : undefined;
    const finalUrl = rangeResp.url.toString();
    const finalHost = normalizeHostname(rangeResp.url.hostname);

    const rawEncoding = firstStr(headers['content-encoding'])?.trim().toLowerCase();
    const isIdentityEncoding = !rawEncoding || rawEncoding === 'identity';

    const contentType =
      firstStr(headers['content-type']) ?? firstStr(validHeadHeaders?.['content-type']);
    const etag = firstStr(headers.etag) ?? firstStr(validHeadHeaders?.etag);
    const lastModified =
      firstStr(headers['last-modified']) ?? firstStr(validHeadHeaders?.['last-modified']);
    const contentDisposition =
      firstStr(headers['content-disposition']) ?? firstStr(validHeadHeaders?.['content-disposition']);
    const acceptRanges =
      firstStr(headers['accept-ranges']) ?? firstStr(validHeadHeaders?.['accept-ranges']);

    let totalBytes: number | null = null;
    let valid206 = false;
    let rangeValidationError: string | undefined;
    if (statusCode === 206) {
      const crHeader = firstStr(headers['content-range']);
      const crMatch = crHeader?.match(/^bytes\s+(\d+)-(\d+)\/(\d+|\*)$/i);
      const declaredLen = parseContentLength(headers['content-length']);
      if (crMatch) {
        const crStart = Number(crMatch[1]);
        const crEnd = Number(crMatch[2]);
        const crTotal = crMatch[3] === '*' ? null : Number(crMatch[3]);
        const expectedEnd =
          crTotal !== null && Number.isSafeInteger(crTotal) && crTotal > 0
            ? Math.min(options.sampleBytes - 1, crTotal - 1)
            : -1;
        const expectedSpanLen = crEnd - crStart + 1;
        if (
          !isIdentityEncoding ||
          !Number.isSafeInteger(crStart) ||
          !Number.isSafeInteger(crEnd) ||
          crTotal === null ||
          !Number.isSafeInteger(crTotal) ||
          crTotal <= 0 ||
          crStart !== 0 ||
          crEnd !== expectedEnd
        ) {
          rangeValidationError = 'Invalid or out-of-bounds 206 Content-Range on benchmark sample';
        } else if (declaredLen !== null && declaredLen !== expectedSpanLen) {
          rangeValidationError = `206 Content-Length (${declaredLen}) mismatched Content-Range length (${expectedSpanLen})`;
        } else if (rangeResp.exceededSampleLimit || rangeResp.sampleBuf.length !== expectedSpanLen) {
          rangeValidationError = `206 response body length (${rangeResp.sampleBuf.length}${rangeResp.exceededSampleLimit ? '+' : ''}) mismatched expected range span (${expectedSpanLen})`;
        } else {
          valid206 = true;
          totalBytes = crTotal;
        }
      } else {
        rangeValidationError = 'Missing or malformed 206 Content-Range header';
      }
      if (!valid206) {
        return {
          candidate,
          ok: false,
          finalUrl,
          finalHost,
          statusCode,
          totalBytes: null,
          supportsRanges: false,
          contentType,
          etag,
          lastModified,
          suggestedFilename: options.filenameHint || 'download',
          probeSpeedBps: 0,
          latencyMs: rangeResp.elapsedMs,
          isHtmlTrap: false,
          error: rangeValidationError ?? 'Invalid 206 Content-Range or compressed ranged response',
          redirectChain,
          tls: rangeResp.tls ?? (headSucceeded ? headResp?.tls : undefined),
        };
      }
    } else if (statusCode >= 200 && statusCode < 300) {
      totalBytes = isIdentityEncoding
        ? parseContentLength(headers['content-length']) ??
          parseContentLength(validHeadHeaders?.['content-length'])
        : null;
      const declared200Len = isIdentityEncoding ? parseContentLength(headers['content-length']) : null;
      if (declared200Len !== null) {
        const expectedSampleLen = Math.min(options.sampleBytes, declared200Len);
        if (rangeResp.sampleBuf.length < expectedSampleLen) {
          return {
            candidate,
            ok: false,
            finalUrl,
            finalHost,
            statusCode,
            totalBytes,
            supportsRanges: false,
            contentType,
            etag,
            lastModified,
            suggestedFilename: options.filenameHint || 'download',
            probeSpeedBps: 0,
            latencyMs: rangeResp.elapsedMs,
            isHtmlTrap: false,
            error: `Truncated 200 sample body (${rangeResp.sampleBuf.length} of ${expectedSampleLen} bytes)`,
            redirectChain,
            tls: rangeResp.tls ?? (headSucceeded ? headResp?.tls : undefined),
          };
        }
        if (declared200Len <= options.sampleBytes && rangeResp.sampleBuf.length > declared200Len) {
          return {
            candidate,
            ok: false,
            finalUrl,
            finalHost,
            statusCode,
            totalBytes,
            supportsRanges: false,
            contentType,
            etag,
            lastModified,
            suggestedFilename: options.filenameHint || 'download',
            probeSpeedBps: 0,
            latencyMs: rangeResp.elapsedMs,
            isHtmlTrap: false,
            error: `Overlong 200 sample body exceeded declared Content-Length (${declared200Len})`,
            redirectChain,
            tls: rangeResp.tls ?? (headSucceeded ? headResp?.tls : undefined),
          };
        }
      }
    }

    const supportsRanges =
      valid206 ||
      (isIdentityEncoding && Boolean(acceptRanges && acceptRanges.toLowerCase().includes('bytes')));

    const cdName = parseContentDispositionFilename(contentDisposition);
    const safePathPart = (() => {
      try {
        const redacted = new URL(redactSensitiveUrl(rangeResp.url.toString(), options.secrets));
        const last = decodeURIComponentSafe(
          redacted.pathname.split('/').filter(Boolean).pop() ?? ''
        );
        return last === '***' ? '' : last;
      } catch {
        return '';
      }
    })();
    const subPathTail = candidate.subPath?.split('/').filter(Boolean).pop();
    const rawCandidate = redactText(
      cdName ||
        subPathTail ||
        (safePathPart && safePathPart !== candidate.cid ? safePathPart : '') ||
        options.filenameHint ||
        safePathPart ||
        'download',
      options.secrets
    );
    const fallbackExt = extensionFromMime(contentType);
    const suggestedFilename = sanitizeFilename(rawCandidate, fallbackExt);

    const isHtmlTrap = detectHtmlSnippet(rangeResp.sampleBuf, contentType, suggestedFilename);
    const elapsedSec = Math.max(0.005, rangeResp.elapsedMs / 1000);
    const probeSpeedBps =
      rangeResp.sampleBuf.length > 0 ? Math.round(rangeResp.sampleBuf.length / elapsedSec) : 0;

    if (statusCode >= 400 || (totalBytes !== null && totalBytes === 0 && statusCode !== 206)) {
      return {
        candidate,
        ok: false,
        finalUrl,
        finalHost,
        statusCode,
        totalBytes: totalBytes === 0 ? null : totalBytes,
        supportsRanges: false,
        contentType,
        etag,
        lastModified,
        suggestedFilename,
        probeSpeedBps: 0,
        latencyMs: rangeResp.elapsedMs,
        isHtmlTrap,
        error: statusCode >= 400 ? `HTTP ${statusCode}` : 'Upstream returned 0-byte Content-Length',
        redirectChain,
        tls: rangeResp.tls ?? (headSucceeded ? headResp?.tls : undefined),
      };
    }

    if (isHtmlTrap) {
      return {
        candidate,
        ok: false,
        finalUrl,
        finalHost,
        statusCode,
        totalBytes,
        supportsRanges: false,
        contentType,
        etag,
        lastModified,
        suggestedFilename,
        probeSpeedBps: 0,
        latencyMs: rangeResp.elapsedMs,
        isHtmlTrap: true,
        error: 'Returned HTML page instead of binary file',
        redirectChain,
        tls: rangeResp.tls ?? (headSucceeded ? headResp?.tls : undefined),
      };
    }

    return {
      candidate,
      ok: true,
      finalUrl,
      finalHost,
      statusCode,
      totalBytes,
      supportsRanges,
      contentType,
      etag,
      lastModified,
      suggestedFilename,
      probeSpeedBps,
      latencyMs: rangeResp.elapsedMs,
      isHtmlTrap: false,
      redirectChain,
      tls: rangeResp.tls ?? (headSucceeded ? headResp?.tls : undefined),
    };
  } catch (err) {
    const message = sanitizeUpstreamError(err, options.secrets, 260);
    return {
      candidate,
      ok: false,
      finalUrl: candidate.url,
      finalHost: normalizeHostname(startUrl.hostname),
      totalBytes: null,
      supportsRanges: false,
      suggestedFilename: options.filenameHint || 'download',
      probeSpeedBps: 0,
      latencyMs: timeoutMs,
      isHtmlTrap: false,
      error: message,
      redirectChain,
    };
  }
}

/**
 * Concurrently probes up to `concurrency` (default 5) candidate mirrors with HEAD +
 * short 64 KiB byte-range requests to measure real throughput, Range support, and HTML traps.
 */
export async function benchmarkCandidates(
  candidates: CandidateSource[],
  options: BenchmarkOptions = {}
): Promise<CandidateBenchmarkResult[]> {
  if (candidates.length === 0) return [];
  const resolvedOpts: Required<BenchmarkOptions> = {
    concurrency: Math.max(1, Math.min(8, options.concurrency ?? 5)),
    timeoutMs: options.timeoutMs ?? 6_000,
    localIpfsTimeoutMs: options.localIpfsTimeoutMs ?? 1_500,
    sampleBytes: options.sampleBytes ?? 64 * 1024,
    filenameHint: options.filenameHint ?? '',
    secrets: options.secrets ?? [],
  };

  const results: CandidateBenchmarkResult[] = new Array(candidates.length);
  let cursor = 0;

  const workers = Array.from(
    { length: Math.min(resolvedOpts.concurrency, candidates.length) },
    async () => {
      while (cursor < candidates.length) {
        const idx = cursor++;
        const cand = candidates[idx]!;
        results[idx] = await benchmarkSingleCandidate(cand, resolvedOpts);
      }
    }
  );

  await Promise.all(workers);
  return results;
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
