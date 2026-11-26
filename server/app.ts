import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import type { DownloadManager } from './manager.js';
import { isPathInsideDir } from './utils.js';

export interface AppServerOptions {
  manager: DownloadManager;
  distDir?: string;
}

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

export function createAppServer(options: AppServerOptions): http.Server {
  const { manager } = options;
  const distDir = options.distDir ?? path.resolve(process.cwd(), 'dist');

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`);
      const method = (req.method ?? 'GET').toUpperCase();

      if (url.pathname.startsWith('/api/')) {
        await handleApiRequest(req, res, url, method, manager);
        return;
      }

      if (method !== 'GET' && method !== 'HEAD') {
        sendJson(res, 405, { error: 'Method not allowed' });
        return;
      }

      await serveStaticFile(res, url.pathname, distDir, method === 'HEAD');
    } catch (err) {
      const status = (err as { status?: number })?.status ?? 500;
      const message = err instanceof Error ? err.message : 'Internal server error';
      if (!res.headersSent) {
        sendJson(res, status, { error: message });
      } else {
        res.end();
      }
    }
  });

  return server;
}

async function handleApiRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  url: URL,
  method: string,
  manager: DownloadManager
): Promise<void> {
  const origin = req.headers.origin;
  if (origin) {
    const allowedOrigin = getAllowedCorsOrigin(origin);
    if (!allowedOrigin) {
      if (
        method === 'OPTIONS' ||
        method === 'POST' ||
        method === 'PATCH' ||
        method === 'DELETE'
      ) {
        sendJson(res, 403, { error: 'Origin not allowed' });
        return;
      }
    } else {
      res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Access-Control-Allow-Private-Network', 'true');
      if (method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }
    }
  }

  const p = url.pathname;

  // Built-in deterministic benchmark file supporting HTTP Range / 206 Partial Content
  if (p === '/api/local-benchmark' && (method === 'GET' || method === 'HEAD')) {
    await serveLocalBenchmark(req, res, url, method === 'HEAD');
    return;
  }

  if (p === '/api/state' && method === 'GET') {
    sendJson(res, 200, manager.getSnapshot());
    return;
  }

  if (p === '/api/events' && method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
    });
    manager.addSseClient(res);
    return;
  }

  if (p === '/api/inspect' && method === 'POST') {
    const body = await readJsonBody<{ text?: string; url?: string; destinationDir?: string }>(req);
    const rawText = body.text ?? body.url ?? '';
    if (!rawText.trim()) {
      sendJson(res, 400, { error: 'Paste one or more http(s) links to inspect' });
      return;
    }
    const result = await manager.inspectRawText(rawText, body.destinationDir);
    if (result.items.length === 0) {
      sendJson(res, 400, {
        error: 'No valid http:// or https:// URLs detected',
        rejectedTokens: result.rejectedTokens,
      });
      return;
    }
    sendJson(res, 200, result);
    return;
  }

  if (p === '/api/downloads/approve-batch' && method === 'POST') {
    const body = await readJsonBody<{ ids?: string[]; trustDomains?: boolean }>(req);
    const items = await manager.approveBatch(body.ids ?? [], Boolean(body.trustDomains));
    sendJson(res, 200, { items });
    return;
  }

  if (p === '/api/downloads/bulk' && method === 'POST') {
    const body = await readJsonBody<{
      action?: 'pauseAll' | 'resumeAll' | 'retryFailed' | 'clearCompleted';
    }>(req);
    if (!body.action) {
      sendJson(res, 400, { error: 'Missing bulk action' });
      return;
    }
    const result = await manager.bulkAction(body.action);
    sendJson(res, 200, result);
    return;
  }

  if (p === '/api/downloads/restore-batch' && method === 'POST') {
    const body = await readJsonBody<{ token?: string }>(req);
    if (!body.token) {
      sendJson(res, 400, { error: 'Missing restore token' });
      return;
    }
    const items = manager.restoreBatch(body.token);
    sendJson(res, 200, { items });
    return;
  }

  // Dynamic /api/downloads/:id routes
  const dlMatch = p.match(/^\/api\/downloads\/([^/]+)(?:\/([^/]+))?$/);
  if (dlMatch) {
    const id = decodeURIComponent(dlMatch[1]!);
    const action = dlMatch[2];

    if (!action && method === 'DELETE') {
      const deleteFile = url.searchParams.get('deleteFile') === 'true';
      const result = await manager.removeDownload(id, deleteFile);
      sendJson(res, 200, result);
      return;
    }

    if (action === 'approve' && method === 'POST') {
      const body = await readJsonBody<{
        filename?: string;
        destinationDir?: string;
        connections?: number;
        trustDomain?: boolean;
        startNow?: boolean;
      }>(req);
      const item = await manager.approveDownload(id, body);
      sendJson(res, 200, { item });
      return;
    }

    if (action === 'reject' && method === 'POST') {
      const body = await readJsonBody<{ blockDomain?: boolean }>(req);
      const result = await manager.rejectDownload(id, Boolean(body.blockDomain));
      sendJson(res, 200, result);
      return;
    }

    if (action === 'pause' && method === 'POST') {
      const item = await manager.pauseDownload(id);
      sendJson(res, 200, { item });
      return;
    }

    if (action === 'resume' && method === 'POST') {
      const body = await readJsonBody<{ startNow?: boolean }>(req);
      const item = await manager.resumeDownload(id, Boolean(body.startNow));
      sendJson(res, 200, { item });
      return;
    }

    if (action === 'reprobe' && method === 'POST') {
      const item = await manager.reprobeDownload(id);
      sendJson(res, 200, { item });
      return;
    }

    if (action === 'priority' && method === 'POST') {
      const body = await readJsonBody<{ action?: 'top' | 'up' | 'down' }>(req);
      if (!body.action) {
        sendJson(res, 400, { error: 'Missing priority action' });
        return;
      }
      const item = manager.reorderPriority(id, body.action);
      sendJson(res, 200, { item });
      return;
    }

    if (action === 'verify-hash' && method === 'POST') {
      const body = await readJsonBody<{ expectedSha256?: string }>(req);
      const result = await manager.verifyHash(id, body.expectedSha256 ?? '');
      sendJson(res, 200, result);
      return;
    }

    if (action === 'verify-integrity' && method === 'POST') {
      const integrity = await manager.verifyIntegrity(id);
      sendJson(res, 200, { integrity });
      return;
    }

    if (action === 'open-folder' && method === 'POST') {
      await manager.openInFolder(id);
      sendJson(res, 200, { ok: true });
      return;
    }

    if (action === 'open-file' && method === 'POST') {
      try {
        await manager.openFile(id);
        sendJson(res, 200, { ok: true });
      } catch (err) {
        sendJson(res, 403, { error: err instanceof Error ? err.message : String(err) });
      }
      return;
    }

    if (action === 'restore' && method === 'POST') {
      const item = manager.restoreDownload(id);
      sendJson(res, 200, { item });
      return;
    }
  }

  if (p === '/api/trust') {
    if (method === 'GET') {
      sendJson(res, 200, { trustRules: manager.getSnapshot().trustRules });
      return;
    }
    if (method === 'POST') {
      const body = await readJsonBody<{
        domain?: string;
        status?: 'trusted' | 'blocked';
        note?: string;
      }>(req);
      if (!body.domain || (body.status !== 'trusted' && body.status !== 'blocked')) {
        sendJson(res, 400, { error: 'Provide domain and status ("trusted" or "blocked")' });
        return;
      }
      const trustRules = await manager.upsertTrustRule({
        domain: body.domain,
        status: body.status,
        note: body.note,
      });
      sendJson(res, 200, { trustRules });
      return;
    }
  }

  const trustDeleteMatch = p.match(/^\/api\/trust\/([^/]+)$/);
  if (trustDeleteMatch && method === 'DELETE') {
    const domain = decodeURIComponent(trustDeleteMatch[1]!);
    const trustRules = await manager.deleteTrustRule(domain);
    sendJson(res, 200, { trustRules });
    return;
  }

  if (p === '/api/settings' && method === 'PATCH') {
    const body = await readJsonBody<Record<string, unknown>>(req);
    const result = await manager.updateSettings(body);
    sendJson(res, 200, result);
    return;
  }

  if (p === '/api/disk-space' && method === 'GET') {
    const diskSpace = await manager.refreshDiskSpace();
    sendJson(res, 200, diskSpace);
    return;
  }

  sendJson(res, 404, { error: `Unknown API route: ${method} ${p}` });
}

async function serveLocalBenchmark(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  url: URL,
  headOnly: boolean
): Promise<void> {
  const sizeMBParam = Number(url.searchParams.get('sizeMB') ?? '20');
  const sizeMB = Number.isFinite(sizeMBParam)
    ? Math.max(1, Math.min(256, Math.round(sizeMBParam)))
    : 20;
  const totalBytes = sizeMB * 1024 * 1024;

  const baseHeaders: Record<string, string | number> = {
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': `attachment; filename="boltgate-benchmark-${sizeMB}MB.bin"`,
    'Accept-Ranges': 'bytes',
    ETag: `"boltgate-bench-${sizeMB}mb-v1"`,
    'Cache-Control': 'no-store',
  };

  let start = 0;
  let end = totalBytes - 1;
  let statusCode = 200;

  const rangeHeader = req.headers.range;
  if (typeof rangeHeader === 'string' && rangeHeader.startsWith('bytes=')) {
    const match = rangeHeader.match(/^bytes=(\d+)-(\d*)$/);
    if (!match) {
      res.writeHead(416, { 'Content-Range': `bytes */${totalBytes}` });
      res.end();
      return;
    }
    start = Number(match[1]);
    end = match[2] ? Math.min(totalBytes - 1, Number(match[2])) : totalBytes - 1;
    if (start > end || start >= totalBytes) {
      res.writeHead(416, { 'Content-Range': `bytes */${totalBytes}` });
      res.end();
      return;
    }
    statusCode = 206;
    baseHeaders['Content-Range'] = `bytes ${start}-${end}/${totalBytes}`;
  }

  const length = end - start + 1;
  baseHeaders['Content-Length'] = length;
  res.writeHead(statusCode, baseHeaders);

  if (headOnly) {
    res.end();
    return;
  }

  // Stream deterministic chunks cleanly with backpressure
  const chunkSize = 64 * 1024;
  let pos = start;

  while (pos <= end && !res.destroyed) {
    const toWrite = Math.min(chunkSize, end - pos + 1);
    const buf = Buffer.allocUnsafe(toWrite);
    for (let i = 0; i < toWrite; i++) {
      const idx = pos + i;
      buf[i] = (idx * 31 + (idx >>> 8) * 17 + (idx >>> 16) * 13) & 0xff;
    }
    pos += toWrite;
    const canContinue = res.write(buf);
    if (!canContinue) {
      await new Promise<void>((resolve) => {
        const cleanup = () => {
          res.off('drain', onDone);
          res.off('close', onDone);
          resolve();
        };
        const onDone = () => cleanup();
        res.once('drain', onDone);
        res.once('close', onDone);
      });
    }
  }
  if (!res.destroyed) {
    res.end();
  }
}

async function serveStaticFile(
  res: http.ServerResponse,
  requestPath: string,
  distDir: string,
  headOnly: boolean
): Promise<void> {
  const cleanPath = requestPath === '/' ? '/index.html' : requestPath;
  const candidate = path.resolve(distDir, `.${cleanPath}`);
  if (!isPathInsideDir(candidate, distDir)) {
    sendJson(res, 403, { error: 'Forbidden' });
    return;
  }

  let filePath = candidate;
  try {
    const stat = await fs.stat(filePath);
    if (stat.isDirectory()) {
      filePath = path.join(distDir, 'index.html');
    }
  } catch {
    filePath = path.join(distDir, 'index.html');
  }

  try {
    const data = await fs.readFile(filePath);
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME_TYPES[ext] ?? 'application/octet-stream',
      'Content-Length': data.length,
    });
    if (headOnly) {
      res.end();
    } else {
      res.end(data);
    }
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Frontend build not found. Run `npm run build` first.');
  }
}

async function readJsonBody<T>(req: http.IncomingMessage): Promise<T> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buf.length;
    if (size > 2 * 1024 * 1024) {
      throw Object.assign(new Error('Request payload too large'), { status: 413 });
    }
    chunks.push(buf);
  }
  if (chunks.length === 0) return {} as T;
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) return {} as T;
  try {
    return JSON.parse(raw) as T;
  } catch {
    throw Object.assign(new Error('Invalid JSON payload'), { status: 400 });
  }
}

function getAllowedCorsOrigin(origin: string): string | null {
  const trimmed = origin.trim();
  if (trimmed === 'https://eeeeee3434343423.github.io') {
    return trimmed;
  }

  const extra = (process.env.BOLTGATE_ALLOWED_ORIGIN ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (extra.includes(trimmed)) {
    return trimmed;
  }

  try {
    const parsed = new URL(trimmed);
    if (
      (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
      (parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost')
    ) {
      return parsed.origin;
    }
  } catch {
    return null;
  }

  return null;
}

function sendJson(res: http.ServerResponse, statusCode: number, data: unknown): void {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}
