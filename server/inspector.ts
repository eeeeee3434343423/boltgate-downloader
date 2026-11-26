import http from 'node:http';
import https from 'node:https';
import type { TLSSocket } from 'node:tls';
import type {
  DownloadItem,
  RedirectHop,
  RiskLevel,
  SafetyReport,
  SafetySignal,
  TlsInfo,
  TrustRule,
} from '../shared/types.js';
import {
  assertOutboundUrlSafe,
  redactSensitiveUrl,
  redactText,
  sanitizeUpstreamError,
} from '../companion/parser.js';
import {
  checkMimeExtensionMismatch,
  classifyFile,
  extensionFromMime,
  isPrivateOrIpHost,
  matchDomainTrust,
  normalizeHostname,
  parseContentDispositionFilename,
  sanitizeFilename,
} from './utils.js';

export interface ProbeOptions {
  trustRules: TrustRule[];
  existingDownloads: DownloadItem[];
  freeBytes?: number;
  timeoutMs?: number;
  secrets?: readonly string[];
}

interface RawProbeResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  tls?: TlsInfo;
}

const MAX_REDIRECTS = 10;

function singleRequest(
  targetUrl: URL,
  method: 'HEAD' | 'GET',
  headers: Record<string, string>,
  timeoutMs: number
): Promise<RawProbeResponse> {
  return new Promise((resolve, reject) => {
    const isHttps = targetUrl.protocol === 'https:';
    const client = isHttps ? https : http;
    let settled = false;

    const reqOptions: https.RequestOptions = {
      method,
      headers: {
        'User-Agent': 'BoltGate/1.0 (+SafeDownloader)',
        Accept: '*/*',
        'Accept-Encoding': 'identity',
        ...headers,
      },
      timeout: timeoutMs,
      ...(isHttps ? { rejectUnauthorized: true } : {}),
    };

    const req = client.request(targetUrl, reqOptions, (res) => {
      if (settled) {
        res.destroy();
        return;
      }
      settled = true;

      let tls: TlsInfo | undefined;
      if (isHttps) {
        const sock = res.socket as TLSSocket;
        try {
          const cert = sock.getPeerCertificate?.();
          tls = {
            authorized: Boolean(sock.authorized),
            issuer: firstStr(cert?.issuer?.O) || firstStr(cert?.issuer?.CN),
            subjectCN: firstStr(cert?.subject?.CN),
            validTo: cert?.valid_to || undefined,
          };
        } catch {
          tls = { authorized: Boolean((sock as TLSSocket)?.authorized) };
        }
      }

      // Immediately close stream without buffering payload
      res.destroy();
      resolve({
        statusCode: res.statusCode ?? 0,
        headers: res.headers,
        tls,
      });
    });

    req.on('timeout', () => {
      if (settled) return;
      settled = true;
      const err = new Error(`Connection timed out after ${timeoutMs}ms`);
      req.destroy(err);
      reject(err);
    });

    req.on('error', (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });

    req.end();
  });
}

function isTlsError(err: unknown): boolean {
  const code = String((err as NodeJS.ErrnoException)?.code ?? '');
  const msg = String((err as Error)?.message ?? '').toLowerCase();
  return (
    code.startsWith('ERR_TLS') ||
    code.includes('CERT') ||
    code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
    code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
    code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
    msg.includes('certificate') ||
    msg.includes('tls') ||
    msg.includes('ssl')
  );
}

function parseStrictZeroRangeHeader(
  header?: string | string[],
  contentLengthHeader?: string | string[]
): { valid: boolean; total: number | null } {
  const val = Array.isArray(header) ? header[0] : header;
  if (!val) return { valid: false, total: null };
  const match = val.trim().match(/^bytes\s+(\d+)-(\d+)\/(\d+|\*)$/i);
  if (!match) return { valid: false, total: null };
  const start = Number(match[1]);
  const end = Number(match[2]);
  const total = match[3] === '*' ? null : Number(match[3]);
  // For `Range: bytes=0-0`, require exact 0-0 span and a concrete positive total length
  if (
    !Number.isSafeInteger(start) ||
    !Number.isSafeInteger(end) ||
    start !== 0 ||
    end !== 0 ||
    total === null ||
    !Number.isSafeInteger(total) ||
    total <= 0
  ) {
    return { valid: false, total: null };
  }
  const declaredLen = parseContentLength(contentLengthHeader);
  if (declaredLen !== null && declaredLen !== end - start + 1) {
    return { valid: false, total: null };
  }
  return { valid: true, total };
}

function parseContentLength(header?: string | string[]): number | null {
  const val = Array.isArray(header) ? header[0] : header;
  if (!val) return null;
  const n = Number(val.trim());
  return Number.isFinite(n) && n >= 0 ? n : null;
}

export async function probeUrl(rawUrl: string, options: ProbeOptions): Promise<SafetyReport> {
  const timeoutMs = options.timeoutMs ?? 12_000;
  const initialUrl = new URL(rawUrl);
  const initialHost = normalizeHostname(initialUrl.hostname);

  const redirectChain: RedirectHop[] = [];
  let currentUrl = initialUrl;
  let finalResponse: RawProbeResponse | null = null;
  let probeError: string | undefined;
  let tlsFailure: TlsInfo | undefined;

  const secrets = options.secrets ?? [];

  const follow = async (startUrl: URL, method: 'HEAD' | 'GET', extraHeaders: Record<string, string>) => {
    const hops: RedirectHop[] = [];
    let url = startUrl;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      assertOutboundUrlSafe(url.toString(), secrets);
      const resp = await singleRequest(url, method, extraHeaders, timeoutMs);
      const isRedirect =
        resp.statusCode >= 300 && resp.statusCode < 400 && typeof resp.headers.location === 'string';
      if (isRedirect) {
        if (hop === MAX_REDIRECTS) {
          throw new Error(`Too many redirects (>${MAX_REDIRECTS})`);
        }
        hops.push({
          url: url.toString(),
          host: normalizeHostname(url.hostname),
          statusCode: resp.statusCode,
        });
        url = new URL(resp.headers.location as string, url);
        if (url.protocol !== 'http:' && url.protocol !== 'https:') {
          throw new Error(`Blocked unsafe redirect scheme: ${url.protocol}`);
        }
        assertOutboundUrlSafe(url.toString(), secrets);
        continue;
      }
      return { url, resp, hops };
    }
    throw new Error('Redirect limit exceeded');
  };

  let headSucceeded = false;
  let headRespHeaders: http.IncomingHttpHeaders | undefined;
  let headRespTls: TlsInfo | undefined;

  try {
    const headResult = await follow(initialUrl, 'HEAD', {});
    headSucceeded = headResult.resp.statusCode >= 200 && headResult.resp.statusCode < 300;
    if (headSucceeded) {
      currentUrl = headResult.url;
      finalResponse = headResult.resp;
      headRespHeaders = headResult.resp.headers;
      headRespTls = headResult.resp.tls;
      redirectChain.push(...headResult.hops);
    }

    const headAcceptRanges = String(headResult.resp.headers['accept-ranges'] ?? '').toLowerCase();
    const needsRangeProbe =
      !headSucceeded ||
      (!headAcceptRanges.includes('bytes') && headAcceptRanges !== 'none');

    if (needsRangeProbe) {
      try {
        const rangeStartUrl = headSucceeded ? currentUrl : initialUrl;
        const rangeResult = await follow(rangeStartUrl, 'GET', { Range: 'bytes=0-0' });
        if (rangeResult.resp.statusCode < 400 || !headSucceeded) {
          if (!headSucceeded) {
            redirectChain.length = 0;
            redirectChain.push(...rangeResult.hops);
          } else {
            redirectChain.push(...rangeResult.hops);
          }
          currentUrl = rangeResult.url;
          finalResponse = rangeResult.resp;
        }
      } catch (rangeErr) {
        // Keep HEAD result ONLY if HEAD succeeded; never restore failed HEAD metadata on fallback GET failure!
        if (!headSucceeded) {
          throw rangeErr;
        }
      }
    }
  } catch (err) {
    const message = sanitizeUpstreamError(err, secrets, 260);
    probeError = message;
    if (isTlsError(err)) {
      tlsFailure = { authorized: false, error: message };
    }
  }

  const finalUrlStr = currentUrl.toString();
  const finalHost = normalizeHostname(currentUrl.hostname);

  const headers = finalResponse?.headers ?? {};
  const statusCode = finalResponse?.statusCode;
  const rawEncoding = firstStr(headers['content-encoding'])?.trim().toLowerCase();
  const isIdentityEncoding = !rawEncoding || rawEncoding === 'identity';

  const headSameValidator =
    headSucceeded &&
    !(
      headRespHeaders?.etag &&
      headers.etag &&
      firstStr(headRespHeaders.etag) !== firstStr(headers.etag)
    );
  const validHeadHeaders = headSameValidator ? headRespHeaders : undefined;
  if (finalResponse && !finalResponse.tls && headSameValidator && headRespTls) {
    finalResponse = { ...finalResponse, tls: headRespTls };
  }

  const contentType = firstStr(headers['content-type']) ?? firstStr(validHeadHeaders?.['content-type']);
  const etag = firstStr(headers.etag) ?? firstStr(validHeadHeaders?.etag);
  const lastModified =
    firstStr(headers['last-modified']) ?? firstStr(validHeadHeaders?.['last-modified']);
  const contentDisposition =
    firstStr(headers['content-disposition']) ?? firstStr(validHeadHeaders?.['content-disposition']);
  const acceptRanges =
    firstStr(headers['accept-ranges']) ?? firstStr(validHeadHeaders?.['accept-ranges']);

  let totalBytes: number | null = null;
  let valid206 = false;
  if (statusCode === 206) {
    const cr = parseStrictZeroRangeHeader(headers['content-range'], headers['content-length']);
    if (cr.valid && isIdentityEncoding) {
      valid206 = true;
      totalBytes = cr.total;
    }
  } else if (statusCode && statusCode >= 200 && statusCode < 300) {
    totalBytes = isIdentityEncoding
      ? parseContentLength(headers['content-length']) ??
        parseContentLength(validHeadHeaders?.['content-length'])
      : null;
  }

  const supportsRanges =
    valid206 ||
    (isIdentityEncoding &&
      Boolean(acceptRanges && acceptRanges.toLowerCase().includes('bytes')));

  const cdName = parseContentDispositionFilename(contentDisposition);
  const safePathLast = (u: URL): string => {
    try {
      const redacted = new URL(redactSensitiveUrl(u.toString(), secrets));
      const last = decodeURIComponentSafe(redacted.pathname.split('/').filter(Boolean).pop() ?? '');
      return last === '***' ? '' : last;
    } catch {
      return '';
    }
  };
  const urlPathName = safePathLast(currentUrl);
  const initialPathName = safePathLast(initialUrl);
  const rawCandidate = redactText(cdName || urlPathName || initialPathName || 'download', secrets);
  const fallbackExt = extensionFromMime(contentType);
  const suggestedFilename = sanitizeFilename(rawCandidate, fallbackExt);

  const fileClass = classifyFile(suggestedFilename, contentType);
  const mimeCheck = checkMimeExtensionMismatch(fileClass.extension, contentType);

  // Domain trust evaluation (blocked on either initial or final host takes precedence)
  const initialTrust = matchDomainTrust(initialHost, options.trustRules);
  const finalTrust = matchDomainTrust(finalHost, options.trustRules);
  const domainTrust: 'trusted' | 'blocked' | 'unknown' =
    initialTrust === 'blocked' || finalTrust === 'blocked'
      ? 'blocked'
      : finalTrust === 'trusted'
        ? 'trusted'
        : 'unknown';

  // Duplicate check
  const dup = options.existingDownloads.find(
    (d) =>
      d.status !== 'rejected' &&
      (d.originalUrl === rawUrl || d.finalUrl === finalUrlStr)
  );

  // Build concrete inspectable safety signals
  const signals: SafetySignal[] = [];

  if (domainTrust === 'blocked') {
    signals.push({
      id: 'domain_trust',
      level: 'danger',
      title: 'Blocked Domain',
      detail: `${finalHost} matches a domain on your Blocked list.`,
    });
  } else if (domainTrust === 'trusted') {
    signals.push({
      id: 'domain_trust',
      level: 'ok',
      title: 'Trusted Domain',
      detail: `${finalHost} is on your Trusted Domains list.`,
    });
  } else {
    signals.push({
      id: 'domain_trust',
      level: 'info',
      title: 'Unlisted Domain',
      detail: `${finalHost} is not yet in your Trust List — inspect evidence below before approving.`,
    });
  }

  if (tlsFailure) {
    signals.push({
      id: 'transport',
      level: 'danger',
      title: 'TLS Certificate Error',
      detail: tlsFailure.error || 'Server certificate could not be verified.',
    });
  } else if (currentUrl.protocol === 'https:') {
    const tls = finalResponse?.tls;
    const issuerPart = tls?.issuer ? `Issued by ${tls.issuer}` : 'Verified certificate';
    signals.push({
      id: 'transport',
      level: 'ok',
      title: 'Encrypted HTTPS',
      detail: `${issuerPart}${tls?.validTo ? ` (valid until ${tls.validTo})` : ''}.`,
    });
  } else {
    signals.push({
      id: 'transport',
      level: 'warn',
      title: 'Unencrypted HTTP',
      detail: 'Transfer uses plain HTTP without TLS encryption or server identity verification.',
    });
  }

  if (redirectChain.length > 0) {
    const distinctHosts = new Set([initialHost, ...redirectChain.map((r) => r.host), finalHost]);
    if (distinctHosts.size > 1) {
      signals.push({
        id: 'redirects',
        level: 'warn',
        title: `Cross-Domain Redirect (${redirectChain.length} hop${redirectChain.length > 1 ? 's' : ''})`,
        detail: `Started on ${initialHost} and redirected to ${finalHost}. Verify you trust the final host.`,
      });
    } else {
      signals.push({
        id: 'redirects',
        level: 'info',
        title: `${redirectChain.length} Same-Domain Redirect${redirectChain.length > 1 ? 's' : ''}`,
        detail: `Redirected within ${finalHost}.`,
      });
    }
  }

  if (fileClass.hasDoubleExtension) {
    signals.push({
      id: 'filename_type',
      level: 'danger',
      title: 'Double-Extension Disguise',
      detail: `"${suggestedFilename}" hides an executable extension behind a document/media name.`,
    });
  } else if (fileClass.isExecutable) {
    signals.push({
      id: 'filename_type',
      level: 'danger',
      title: `Executable / Script (${fileClass.extension})`,
      detail: 'Executable code can modify your system. Only deem safe if you trust the exact publisher.',
    });
  } else if (fileClass.riskTier === 'medium') {
    signals.push({
      id: 'filename_type',
      level: 'info',
      title: `${fileClass.category === 'disk' ? 'Disk Image' : 'Archive'} (${fileClass.extension || 'file'})`,
      detail: 'Verify archive/image contents after extracting.',
    });
  } else {
    signals.push({
      id: 'filename_type',
      level: 'ok',
      title: `Non-Executable (${fileClass.extension || fileClass.category})`,
      detail: `Classified as ${fileClass.category}; cannot execute directly as a program.`,
    });
  }

  if (mimeCheck.mismatch && mimeCheck.reason) {
    signals.push({
      id: 'mime_check',
      level: mimeCheck.severity ?? 'warn',
      title: 'Content-Type Mismatch',
      detail: mimeCheck.reason,
    });
  } else if (contentType) {
    signals.push({
      id: 'mime_check',
      level: 'ok',
      title: 'Content-Type Consistent',
      detail: `Server reports ${contentType.split(';')[0]?.trim()}.`,
    });
  }

  if (initialUrl.username || initialUrl.password || currentUrl.username || currentUrl.password) {
    signals.push({
      id: 'url_creds',
      level: 'danger',
      title: 'Embedded URL Credentials',
      detail: 'Link contains username/password syntax, often used in spoofing URLs.',
    });
  }

  if (initialHost.includes('xn--') || finalHost.includes('xn--')) {
    signals.push({
      id: 'punycode',
      level: 'danger',
      title: 'Punycode / Lookalike Domain',
      detail: `Host "${finalHost}" uses Punycode (xn--) encoding — double-check for lookalike characters.`,
    });
  }

  if (isPrivateOrIpHost(finalHost)) {
    signals.push({
      id: 'private_ip',
      level: 'warn',
      title: 'Direct IP / Local Network Host',
      detail: `Hosted on ${finalHost} instead of a public domain. Normal for local NAS or benchmark tests.`,
    });
  }

  if (statusCode !== undefined && statusCode >= 400) {
    signals.push({
      id: 'http_status',
      level: 'danger',
      title: `Server Returned HTTP ${statusCode}`,
      detail: 'The remote server rejected the metadata probe or could not find the file.',
    });
  } else if (probeError && !tlsFailure) {
    signals.push({
      id: 'network_error',
      level: 'danger',
      title: 'Probe Failed',
      detail: probeError,
    });
  }

  if (!probeError && statusCode !== undefined && statusCode < 400) {
    signals.push({
      id: 'acceleration',
      level: supportsRanges ? 'ok' : 'info',
      title: supportsRanges ? 'Multi-Stream Acceleration Ready' : 'Single-Stream Server',
      detail: supportsRanges
        ? 'Server supports HTTP byte ranges — BoltGate can split into parallel streams and pause/resume.'
        : 'Server does not advertise Accept-Ranges; will download as a single reliable stream.',
    });
  }

  if (totalBytes !== null && options.freeBytes !== undefined) {
    if (totalBytes > options.freeBytes * 0.98) {
      signals.push({
        id: 'disk_space',
        level: 'danger',
        title: 'Insufficient Disk Space',
        detail: 'File size exceeds available space on the target download drive.',
      });
    }
  }

  if (dup) {
    signals.push({
      id: 'duplicate',
      level: 'info',
      title: 'Duplicate Link Detected',
      detail: `Matches existing item "${dup.filename}" (${dup.status}).`,
    });
  }

  let riskLevel: RiskLevel = 'safe';
  if ((probeError && !tlsFailure) || (statusCode !== undefined && statusCode >= 400)) {
    riskLevel = 'error';
  } else if (signals.some((s) => s.level === 'danger')) {
    riskLevel = 'high_risk';
  } else if (signals.some((s) => s.level === 'warn')) {
    riskLevel = 'caution';
  }

  return {
    riskLevel,
    signals,
    finalUrl: finalUrlStr,
    finalHost,
    initialHost,
    redirectChain,
    statusCode,
    contentType,
    etag,
    lastModified,
    supportsRanges,
    totalBytes,
    suggestedFilename,
    extension: fileClass.extension,
    category: fileClass.category,
    isExecutable: fileClass.isExecutable,
    domainTrust,
    tls: tlsFailure ?? finalResponse?.tls,
    duplicateOfId: dup?.id,
    probedAt: Date.now(),
    probeError,
  };
}

function firstStr(value?: string | string[]): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value || undefined;
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
