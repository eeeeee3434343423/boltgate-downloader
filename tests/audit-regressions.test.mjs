import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { gzipSync } from 'node:zlib';
import { Aria2Runner, buildAria2Args } from '../dist-server/companion/aria2.js';
import { benchmarkCandidates } from '../dist-server/companion/benchmarker.js';
import {
  assertOutboundUrlSafe,
  extractMagnetEmbeddedUrls,
  redactSensitiveUrl,
  sanitizeUpstreamError,
} from '../dist-server/companion/parser.js';
import {
  readPartMeta,
  retireStagingPair,
  validatePartMetaGeometry,
  writePartMeta,
} from '../dist-server/companion/partMeta.js';
import { parseTorrentMetadata } from '../dist-server/companion/torrentParser.js';
import { expandIpfsCidToCandidates, resolveBookSources } from '../dist-server/companion/resolver.js';
import { assertLoopbackBindHost, createAppServer } from '../dist-server/server/app.js';
import { DownloadRunner } from '../dist-server/server/engine.js';
import { probeUrl } from '../dist-server/server/inspector.js';
import { DownloadManager } from '../dist-server/server/manager.js';
import { OriginRateLimiter } from '../dist-server/server/rateLimit.js';
import { SecretStore, VaultCorruptionError } from '../dist-server/server/secretStore.js';
import { StateLoadError, StateStore, getDefaultSettings } from '../dist-server/server/store.js';
import { TokenBucketThrottle } from '../dist-server/server/throttle.js';
import {
  assertPhysicalDirInside,
  captureFileIdentity,
  publishStagingFileAtomically,
  reserveExclusiveStagingFile,
} from '../dist-server/server/utils.js';
import {
  canCombineMirrorWithPrimary,
  computeOpaqueSourceId,
  isSameResourceEndpoint,
  isStrongEtag,
  selectAria2HttpSources,
} from '../dist-server/server/validators.js';
import {
  assertPinnedEngineBinding,
  assertPinnedSecretWriteContext,
  buildBulkApprovalEntries,
  buildSettingsDraftSnapshot,
  buildTemplatePatchEntries,
  formatLoopbackOrigin,
  mergeSettingsDrafts,
  normalizeCapabilities,
  normalizeSettings,
  normalizeSnapshot,
  validateLoopbackOrigin,
} from '../dist-server/shared/compat.js';
import { parseSmartInput } from '../dist-server/shared/inputParser.js';

function listenServer(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        port: addr.port,
        close: () => {
          server.closeAllConnections?.();
          return new Promise((r) => server.close(r));
        },
      });
    });
  });
}

function makePayload(sizeBytes, seedBias = 0) {
  const buf = Buffer.allocUnsafe(sizeBytes);
  for (let i = 0; i < sizeBytes; i++) {
    buf[i] = ((i + seedBias) * 31 + (i >>> 8) * 17 + (i >>> 16) * 13) & 0xff;
  }
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  const md5 = crypto.createHash('md5').update(buf).digest('hex');
  return { buf, sha256, md5 };
}

function makeItem(url, destDir, filename, opts = {}) {
  const savedPath = path.join(destDir, filename);
  return {
    id: opts.id ?? crypto.randomUUID(),
    originalUrl: url,
    finalUrl: url,
    mirrorUrls: opts.mirrorUrls,
    mirrorMeta: opts.mirrorMeta,
    filename,
    destinationDir: destDir,
    savedPath,
    partPath: opts.partPath ?? '',
    category: 'archive',
    status: 'queued',
    priority: 0,
    totalBytes: opts.totalBytes ?? null,
    downloadedBytes: 0,
    speedBps: 0,
    avgSpeedBps: 0,
    etaSeconds: null,
    connections: opts.connections ?? 4,
    supportsRanges: opts.supportsRanges ?? true,
    etag: opts.etag,
    lastModified: opts.lastModified,
    expectedMd5: opts.expectedMd5,
    expectedSha256: opts.expectedSha256,
    segments: [],
    safety: null,
    routingLog: [],
    createdAt: Date.now(),
    userDeemedSafe: true,
  };
}

async function waitFor(predicate, timeoutMs = 8000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const val = await predicate();
    if (val) return val;
    await new Promise((r) => setTimeout(r, 35));
  }
  throw new Error('Timed out waiting for condition');
}

function sendRawHttpHost(port, hostHeader, reqPath = '/api/health') {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => {
      sock.write(`GET ${reqPath} HTTP/1.1\r\nHost: ${hostHeader}\r\nConnection: close\r\n\r\n`);
    });
    const chunks = [];
    sock.on('data', (c) => chunks.push(c));
    sock.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    sock.on('error', reject);
  });
}

test('Audit 1: Credential origin binding, cross-origin redirect block, legacy migration, and secret redaction', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit1-data-'));
  const md5 = 'aabbccddeeff00112233445566778899';
  const apiKey = 'super_secret_annas_key_xyz';
  let evilHits = 0;

  // Attacker host that pasted URL or cross-origin redirect targets
  const evilServer = http.createServer((req, res) => {
    evilHits++;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ download_url: `http://127.0.0.1:${evilPort}/loot` }));
  });

  // Legitimate loopback provider that redirects credentialed Tier 1 request cross-origin to attacker
  const redirectProvider = http.createServer((req, res) => {
    if (req.url?.startsWith('/dyn/api/fast_download.json')) {
      res.writeHead(302, {
        Location: `http://127.0.0.1:${evilPort}/steal?md5=${md5}&key=victim`,
      });
      res.end();
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const evil = await listenServer(evilServer);
  const evilPort = evil.port;
  const prov = await listenServer(redirectProvider);

  try {
    // 1. Pasted unapproved host with /md5/<hash> must NOT parse as annas_md5
    const evilParse = parseSmartInput(`https://evil.example/md5/${md5}`);
    assert.equal(evilParse.entries[0].kind, 'direct_url');

    // 2. Non-HTTPS provider baseUrl and unapproved HTTPS domain must NOT receive API key
    const nonHttpsRes = await resolveBookSources(
      { md5, sourcePageUrl: `http://127.0.0.1:${evilPort}/md5/${md5}` },
      { ...getDefaultSettings(), annasArchiveBaseUrl: 'http://annas-archive.org' },
      { apiKey }
    );
    assert.equal(evilHits, 0);
    assert.ok(nonHttpsRes.routingLog.some((l) => l.message.includes('HTTPS')));

    const unapprovedHttps = await resolveBookSources(
      { md5 },
      { ...getDefaultSettings(), annasArchiveBaseUrl: 'https://not-annas-evil.example' },
      { apiKey }
    );
    assert.ok(
      unapprovedHttps.routingLog.some((l) => l.message.includes('not an approved'))
    );

    // 3. Cross-origin 302 redirect on credentialed Tier 1 API fetch must abort before contacting second origin
    const redirRes = await resolveBookSources(
      { md5 },
      { ...getDefaultSettings(), annasArchiveBaseUrl: `http://127.0.0.1:${prov.port}` },
      { apiKey, allowInsecureLoopbackForTests: true }
    );
    assert.equal(evilHits, 0);
    assert.ok(redirRes.routingLog.some((l) => l.message.includes('cross-origin')));

    // 4. Redact signed URL params, bearer auth, userinfo, and explicit secret values
    const dirty = `https://user:pass@cdn.example/dl?X-Amz-Signature=deadbeef&token=tok1&key=${encodeURIComponent(apiKey)}`;
    const redacted = redactSensitiveUrl(dirty, [apiKey]);
    assert.equal(redacted.includes(apiKey), false);
    assert.equal(redacted.includes('deadbeef'), false);
    assert.equal(redacted.includes('tok1'), false);
    assert.equal(redacted.includes('user:pass'), false);

    const errMsg = sanitizeUpstreamError(
      new Error(`Authorization: Bearer tokABC999 failed with key=${apiKey}`),
      [apiKey]
    );
    assert.equal(errMsg.includes(apiKey), false);
    assert.equal(errMsg.includes('tokABC999'), false);

    // 5. Legacy plaintext key in state.json migrates into encrypted secrets.enc.json and disappears from state.json & API snapshot
    const legacyKey = 'legacy_plaintext_key_to_migrate_42';
    await fs.writeFile(
      path.join(tmpDataDir, 'state.json'),
      JSON.stringify({
        version: 1,
        downloads: [],
        trustRules: [],
        settings: {
          ...getDefaultSettings(),
          annasArchiveApiKey: legacyKey,
        },
      }),
      'utf8'
    );

    const manager = new DownloadManager({ dataDir: tmpDataDir });
    await manager.init();

    const snap = manager.getSnapshot();
    assert.equal(snap.settings.hasAnnasArchiveApiKey, true);
    assert.equal('annasArchiveApiKey' in snap.settings, false);
    assert.equal(JSON.stringify(snap).includes(legacyKey), false);

    const newStateRaw = await fs.readFile(path.join(tmpDataDir, 'state.json'), 'utf8');
    const encRaw = await fs.readFile(path.join(tmpDataDir, 'secrets.enc.json'), 'utf8');
    assert.equal(newStateRaw.includes(legacyKey), false);
    assert.equal(encRaw.includes(legacyKey), false);
    assert.equal(await manager.secretStore.getAnnasArchiveApiKey(), legacyKey);

    await manager.shutdown();
  } finally {
    await evil.close();
    await prov.close();
    await fs.rm(tmpDataDir, { recursive: true, force: true });
  }
});

test('Audit 2: Mismatched mirror ETags & HTML traps are excluded without digest, and single-source switch restarts cleanly from 0', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit2-data-'));
  const tmpDlDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit2-dl-'));
  const fileA = makePayload(600 * 1024, 1);
  const fileB = makePayload(600 * 1024, 99);

  // Server A: ETag "v1", slow bytes
  const srvA = http.createServer(async (req, res) => {
    if (req.method === 'HEAD') {
      res.writeHead(200, {
        'Content-Length': fileA.buf.length,
        'Accept-Ranges': 'bytes',
        ETag: '"v1"',
        'Content-Type': 'application/octet-stream',
      });
      res.end();
      return;
    }
    const range = req.headers.range ?? 'bytes=0-';
    const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
    const start = Number(s);
    const end = e ? Number(e) : fileA.buf.length - 1;
    const slice = fileA.buf.subarray(start, end + 1);
    res.writeHead(206, {
      'Content-Range': `bytes ${start}-${end}/${fileA.buf.length}`,
      'Content-Length': slice.length,
      'Accept-Ranges': 'bytes',
      ETag: '"v1"',
    });
    // Throttle slowly so speed floor switches cleanly unless small probe
    if (slice.length > 65536) {
      for (let pos = 0; pos < slice.length && !res.destroyed; pos += 8192) {
        res.write(slice.subarray(pos, Math.min(slice.length, pos + 8192)));
        await new Promise((r) => setTimeout(r, 120));
      }
      if (!res.destroyed) res.end();
      return;
    }
    res.end(slice);
  });

  // Server B: different ETag "v2", different content, fast
  const srvB = http.createServer((req, res) => {
    if (req.method === 'HEAD') {
      res.writeHead(200, {
        'Content-Length': fileB.buf.length,
        'Accept-Ranges': 'bytes',
        ETag: '"v2"',
        'Content-Type': 'application/octet-stream',
      });
      res.end();
      return;
    }
    const range = req.headers.range ?? 'bytes=0-';
    const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
    const start = Number(s);
    const end = e ? Number(e) : fileB.buf.length - 1;
    const slice = fileB.buf.subarray(start, end + 1);
    res.writeHead(206, {
      'Content-Range': `bytes ${start}-${end}/${fileB.buf.length}`,
      'Content-Length': slice.length,
      'Accept-Ranges': 'bytes',
      ETag: '"v2"',
    });
    res.end(slice);
  });

  // Server C: HTML trap pretending to be binary size in HEAD
  const srvTrap = http.createServer((req, res) => {
    const html = '<!DOCTYPE html><html><body>Queue challenge</body></html>';
    if (req.method === 'HEAD') {
      res.writeHead(200, {
        'Content-Length': fileA.buf.length,
        'Accept-Ranges': 'bytes',
        ETag: '"v1"',
        'Content-Type': 'application/octet-stream',
      });
      res.end();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': Buffer.byteLength(html) });
    res.end(html);
  });

  const a = await listenServer(srvA);
  const b = await listenServer(srvB);
  const trap = await listenServer(srvTrap);
  const manager = new DownloadManager({ dataDir: tmpDataDir });
  await manager.init();
  await manager.updateSettings({ downloadDir: tmpDlDir });
  const appServer = createAppServer({ manager });
  await new Promise((r) => appServer.listen(0, '127.0.0.1', r));
  const baseUrl = `http://127.0.0.1:${appServer.address().port}`;
  const token = manager.getSessionToken();

  try {
    // 1. inspect-mirrors without digest must reject conflicting ETags AND HTML traps
    const inspectRes = await fetch(`${baseUrl}/api/inspect-mirrors`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-BoltGate-Session': token },
      body: JSON.stringify({
        text: [
          `http://127.0.0.1:${a.port}/book.bin`,
          `http://127.0.0.1:${b.port}/book.bin`,
          `http://127.0.0.1:${trap.port}/book.bin`,
        ].join('\n'),
      }),
    });
    const { items } = await inspectRes.json();
    const id = items[0].id;

    const reviewed = await waitFor(async () => {
      const st = manager.getSnapshot().downloads.find((d) => d.id === id);
      return st?.status === 'pending_review' ? st : null;
    });

    assert.equal(reviewed.mirrorUrls.length, 1);
    assert.equal(reviewed.sourceMode, 'direct');
    const bReport = reviewed.safety.mirrorReports.find((m) => m.host === '127.0.0.1' && m.url.includes(`:${b.port}`));
    const trapReport = reviewed.safety.mirrorReports.find((m) => m.url.includes(`:${trap.port}`));
    assert.equal(bReport.included, false);
    assert.ok(bReport.excludeReason.includes('Validator mismatch'));
    assert.equal(trapReport.included, false);
    assert.equal(trapReport.isHtmlTrap, true);

    // 2. Direct runner without trusted digest switches cleanly from slow A to B by restarting from offset 0
    const singleSwitchItem = makeItem(`http://127.0.0.1:${a.port}/switch.bin`, tmpDlDir, 'switch.bin', {
      totalBytes: fileA.buf.length,
      connections: 2,
      supportsRanges: true,
      mirrorUrls: [
        `http://127.0.0.1:${a.port}/switch.bin`,
        `http://127.0.0.1:${b.port}/switch.bin`,
      ],
    });
    await new DownloadRunner({
      item: singleSwitchItem,
      throttle: new TokenBucketThrottle(0),
      minSegmentBytes: 128 * 1024,
      minSpeedFloorBps: 250 * 1024,
      speedWindowMs: 250,
      evictionGraceMs: 220,
      onUpdate: () => {},
    }).run();

    assert.equal(singleSwitchItem.status, 'completed');
    // Restarted cleanly from offset 0 on Mirror B -> 100% fileB, 0 mixed bytes from fileA!
    assert.equal(singleSwitchItem.sha256, fileB.sha256);
    assert.ok(
      singleSwitchItem.routingLog.some((r) => r.message.includes('restarted cleanly from offset 0'))
    );
  } finally {
    await manager.shutdown().catch(() => {});
    await new Promise((r) => appServer.close(() => r()));
    await a.close();
    await b.close();
    await trap.close();
    await fs.rm(tmpDataDir, { recursive: true, force: true });
    await fs.rm(tmpDlDir, { recursive: true, force: true });
  }
});

test('Audit 3: Failed 405 HEAD discard, identity Accept-Encoding enforcement, invalid 206 rejection, and clean 200 OK retry reset', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit3-'));
  const payload = makePayload(256 * 1024, 5);
  let retryAttempt = 0;

  const server = http.createServer((req, res) => {
    if (req.url === '/head405.bin') {
      if (req.method === 'HEAD') {
        res.writeHead(405, {
          'Content-Type': 'text/html',
          'Content-Length': 0,
        });
        res.end();
        return;
      }
      if (req.headers.range === 'bytes=0-0') {
        res.writeHead(206, {
          'Content-Type': 'application/octet-stream',
          'Content-Range': `bytes 0-0/${payload.buf.length}`,
          'Content-Length': 1,
          'Accept-Ranges': 'bytes',
        });
        res.end(payload.buf.subarray(0, 1));
        return;
      }
    }

    if (req.url === '/gzip-ranged.bin') {
      assert.equal(req.headers['accept-encoding'], 'identity');
      const gz = gzipSync(payload.buf);
      res.writeHead(206, {
        'Content-Encoding': 'gzip',
        'Content-Range': `bytes 0-${payload.buf.length - 1}/${payload.buf.length}`,
        'Content-Length': gz.length,
      });
      res.end(gz);
      return;
    }

    if (req.url === '/wrong-206.bin') {
      res.writeHead(206, {
        'Content-Range': `bytes 50-100/${payload.buf.length}`,
        'Content-Length': payload.buf.length,
      });
      res.end(payload.buf);
      return;
    }

    if (req.url === '/interrupted-200.bin') {
      retryAttempt++;
      res.writeHead(200, {
        'Content-Length': payload.buf.length,
        'Accept-Ranges': 'none',
      });
      if (retryAttempt === 1) {
        // Send first 64 KiB cleanly then drop socket abruptly
        res.write(payload.buf.subarray(0, 64 * 1024));
        setTimeout(() => res.destroy(), 20);
        return;
      }
      res.end(payload.buf);
      return;
    }

    res.writeHead(404);
    res.end();
  });

  const srv = await listenServer(server);

  try {
    // 1. HEAD 405 with Content-Length: 0 & text/html must be discarded cleanly
    const report = await probeUrl(`http://127.0.0.1:${srv.port}/head405.bin`, {
      trustRules: [],
      existingDownloads: [],
    });
    assert.equal(report.statusCode, 206);
    assert.equal(report.totalBytes, payload.buf.length);
    assert.equal(report.supportsRanges, true);
    assert.equal(report.contentType, 'application/octet-stream');

    // 2. Non-identity gzip encoding on ranged transfer is rejected
    const gzipItem = makeItem(`http://127.0.0.1:${srv.port}/gzip-ranged.bin`, tmpDir, 'gz.bin', {
      totalBytes: payload.buf.length,
      connections: 1,
      supportsRanges: true,
    });
    await new DownloadRunner({
      item: gzipItem,
      throttle: new TokenBucketThrottle(0),
      maxRetries: 1,
      onUpdate: () => {},
    }).run();
    assert.equal(gzipItem.status, 'failed');
    assert.ok(gzipItem.error?.includes('Content-Encoding'));

    // 3. Mismatched 206 Content-Range is rejected
    const wrong206Item = makeItem(`http://127.0.0.1:${srv.port}/wrong-206.bin`, tmpDir, 'bad206.bin', {
      totalBytes: payload.buf.length,
      connections: 1,
      supportsRanges: true,
    });
    await new DownloadRunner({
      item: wrong206Item,
      throttle: new TokenBucketThrottle(0),
      maxRetries: 1,
      onUpdate: () => {},
    }).run();
    assert.equal(wrong206Item.status, 'failed');
    assert.ok(wrong206Item.error?.includes('Content-Range'));

    // 4. Interrupted 200 OK stream restarts cleanly from offset 0 without duplicating prefix bytes
    const retry200Item = makeItem(
      `http://127.0.0.1:${srv.port}/interrupted-200.bin`,
      tmpDir,
      'retry200.bin',
      {
        totalBytes: payload.buf.length,
        connections: 1,
        supportsRanges: false,
      }
    );
    await new DownloadRunner({
      item: retry200Item,
      throttle: new TokenBucketThrottle(0),
      onUpdate: () => {},
    }).run();
    assert.equal(retry200Item.status, 'completed');
    assert.equal(retry200Item.sha256, payload.sha256);
    assert.equal(retryAttempt, 2);
  } finally {
    await srv.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('Audit 4: Exclusive wx+ staging, EEXIST publish collision avoidance, .part.meta gap re-fetch, MD5 mismatch fresh retry, verifyHash disk re-hash, and soft-remove checkpoint retention', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit4-data-'));
  const tmpDlDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit4-dl-'));
  const good = makePayload(300 * 1024, 11);
  const second = makePayload(300 * 1024, 22);
  const bad = makePayload(300 * 1024, 77);
  let serveBad = true;

  const server = http.createServer((req, res) => {
    const active = req.url === '/second.bin'
      ? second.buf
      : req.url === '/flaky-md5.bin' && serveBad
        ? bad.buf
        : good.buf;

    if (req.method === 'HEAD') {
      res.writeHead(200, {
        'Content-Length': active.length,
        'Accept-Ranges': 'bytes',
        'Content-Type': 'application/octet-stream',
      });
      res.end();
      return;
    }
    const range = req.headers.range;
    if (range && range.startsWith('bytes=')) {
      const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
      const start = Number(s);
      const end = e ? Number(e) : active.length - 1;
      const slice = active.subarray(start, end + 1);
      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${active.length}`,
        'Content-Length': slice.length,
        'Accept-Ranges': 'bytes',
      });
      res.end(slice);
      return;
    }
    res.writeHead(200, { 'Content-Length': active.length, 'Accept-Ranges': 'bytes' });
    res.end(active);
  });

  const srv = await listenServer(server);
  const manager = new DownloadManager({ dataDir: tmpDataDir, minSegmentBytes: 128 * 1024 });
  await manager.init();
  await manager.updateSettings({ downloadDir: tmpDlDir, maxConcurrentPerHost: 4 });
  const appServer = createAppServer({ manager });
  await new Promise((r) => appServer.listen(0, '127.0.0.1', r));
  const baseUrl = `http://127.0.0.1:${appServer.address().port}`;
  const token = manager.getSessionToken();

  try {
    // 1. Pre-existing target file + two concurrent same-filename jobs -> never overwrite EXISTING
    const preExistingPath = path.join(tmpDlDir, 'collide.bin');
    await fs.writeFile(preExistingPath, 'KEEP_EXISTING_CONTENT');

    const j1 = makeItem(`http://127.0.0.1:${srv.port}/first.bin`, tmpDlDir, 'collide.bin', {
      totalBytes: good.buf.length,
      connections: 2,
      supportsRanges: true,
      expectedSha256: good.sha256,
    });
    const j2 = makeItem(`http://127.0.0.1:${srv.port}/second.bin`, tmpDlDir, 'collide.bin', {
      totalBytes: second.buf.length,
      connections: 2,
      supportsRanges: true,
      expectedSha256: second.sha256,
    });

    await Promise.all([
      new DownloadRunner({ item: j1, throttle: new TokenBucketThrottle(0), onUpdate: () => {} }).run(),
      new DownloadRunner({ item: j2, throttle: new TokenBucketThrottle(0), onUpdate: () => {} }).run(),
    ]);
    assert.equal(j1.status, 'completed');
    assert.equal(j2.status, 'completed');
    assert.notEqual(j1.savedPath, preExistingPath);
    assert.notEqual(j2.savedPath, preExistingPath);
    assert.notEqual(j1.savedPath, j2.savedPath);
    assert.equal(await fs.readFile(preExistingPath, 'utf8'), 'KEEP_EXISTING_CONTENT');

    // 2. .part.meta truncated file size check -> re-fetch unproven extent
    const gapItem = makeItem(`http://127.0.0.1:${srv.port}/first.bin`, tmpDlDir, 'gap.bin', {
      id: 'job-gap-test',
      totalBytes: good.buf.length,
      connections: 2,
      supportsRanges: true,
      expectedMd5: good.md5,
      partPath: path.join(tmpDlDir, '.boltgate-job-gap-test-gap.bin.part'),
    });
    await fs.writeFile(gapItem.partPath, good.buf.subarray(0, 16384)); // truncated below claimed 153600!
    await writePartMeta(gapItem.partPath, {
      version: 2,
      jobId: gapItem.id,
      partPath: gapItem.partPath,
      filename: gapItem.filename,
      totalBytes: good.buf.length,
      expectedMd5: good.md5,
      mirrors: [],
      segments: [
        { id: 0, start: 0, end: 153599, committedBytes: 153600, status: 'done' },
        { id: 1, start: 153600, end: good.buf.length - 1, committedBytes: 0, status: 'pending' },
      ],
      updatedAt: Date.now(),
    });
    const geomCheck = validatePartMetaGeometry(
      {
        version: 2,
        jobId: gapItem.id,
        partPath: gapItem.partPath,
        filename: gapItem.filename,
        totalBytes: good.buf.length,
        expectedMd5: good.md5,
        mirrors: [],
        segments: [
          { id: 0, start: 0, end: 153599, committedBytes: 153600, status: 'done' },
          { id: 1, start: 153600, end: good.buf.length - 1, committedBytes: 0, status: 'pending' },
        ],
        updatedAt: Date.now(),
      },
      {
        jobId: gapItem.id,
        partPath: gapItem.partPath,
        totalBytes: good.buf.length,
        partFileSize: 16384,
        expectedMd5: good.md5,
      }
    );
    assert.equal(geomCheck.hadUnprovenGaps, true);
    assert.equal(geomCheck.committedBySegId.get(0), 16384);

    await new DownloadRunner({
      item: gapItem,
      throttle: new TokenBucketThrottle(0),
      minSegmentBytes: 128 * 1024,
      onUpdate: () => {},
    }).run();
    assert.equal(gapItem.status, 'completed');
    assert.equal(gapItem.sha256, good.sha256);

    // 3. MD5 mismatch purges staging, fails, and retry after fixing upstream starts fresh and completes
    const inspRes = await fetch(`${baseUrl}/api/inspect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-BoltGate-Session': token },
      body: JSON.stringify({ text: `http://127.0.0.1:${srv.port}/flaky-md5.bin` }),
    });
    const { items } = await inspRes.json();
    const retryId = items[0].id;
    await waitFor(() => manager.getSnapshot().downloads.find((d) => d.id === retryId)?.status === 'pending_review');
    // Seed expectedMd5 BEFORE approval/execution (approval inputs are frozen once execution starts)
    const liveItem = manager['downloads'].find((d) => d.id === retryId);
    liveItem.expectedMd5 = good.md5;
    const rawRetryItem = await manager.approveDownload(retryId, { trustDomain: true, startNow: true });

    const failedItem = await waitFor(() => {
      const it = manager.getSnapshot().downloads.find((d) => d.id === retryId);
      return it?.status === 'failed' ? it : null;
    });
    assert.equal(failedItem.md5Verified, false);
    assert.ok(rawRetryItem);

    // Fix upstream & retry -> must start fresh and verify MD5!
    serveBad = false;
    await manager.resumeDownload(retryId, true);
    const doneRetryItem = await waitFor(() => {
      const it = manager.getSnapshot().downloads.find((d) => d.id === retryId);
      return it?.status === 'completed' ? it : null;
    });
    assert.equal(doneRetryItem.md5Verified, true);
    assert.equal(doneRetryItem.sha256, good.sha256);

    // 4. Manual verifyHash MUST re-hash current file on disk (mutating file invalidates match!)
    await fs.writeFile(doneRetryItem.savedPath, Buffer.alloc(good.buf.length, 0xee));
    const rehashRes = await fetch(`${baseUrl}/api/downloads/${retryId}/verify-hash`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-BoltGate-Session': token },
      body: JSON.stringify({ expectedHash: good.sha256 }),
    });
    const rehashJson = await rehashRes.json();
    assert.equal(rehashRes.status, 200);
    assert.equal(rehashJson.match, false);

    // 5. Soft remove retains checkpoint .part & .part.meta for Undo restore
    const softItem = makeItem(`http://127.0.0.1:${srv.port}/first.bin`, tmpDlDir, 'soft-keep.bin', {
      totalBytes: good.buf.length,
      partPath: path.join(tmpDlDir, '.boltgate-softkeep-soft-keep.bin.part'),
    });
    await fs.writeFile(softItem.partPath, 'PART_DATA');
    await writePartMeta(softItem.partPath, {
      version: 2,
      jobId: softItem.id,
      partPath: softItem.partPath,
      filename: softItem.filename,
      totalBytes: good.buf.length,
      mirrors: [],
      segments: [{ id: 0, start: 0, end: good.buf.length - 1, committedBytes: 9, status: 'paused' }],
      updatedAt: Date.now(),
    });
    manager['downloads'].push(softItem);
    await manager.removeDownload(softItem.id, false);
    await fs.access(softItem.partPath);
    await fs.access(`${softItem.partPath}.meta`);
  } finally {
    await manager.shutdown().catch(() => {});
    await new Promise((r) => appServer.close(() => r()));
    await srv.close();
    await fs.rm(tmpDataDir, { recursive: true, force: true });
    await fs.rm(tmpDlDir, { recursive: true, force: true });
  }
});

test('Audit 5: Companion Host/Origin/Session auth, HTML injection, RateLimiter telemetry, IPFS subpath, aria2 connections & legacy compat', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit5-data-'));
  const tmpDistDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit5-dist-'));
  const tmpDlDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit5-dl-'));

  await fs.writeFile(
    path.join(tmpDistDir, 'index.html'),
    '<!doctype html><html><head><title>BoltGate</title></head><body>ok</body></html>',
    'utf8'
  );

  const manager = new DownloadManager({ dataDir: tmpDataDir });
  await manager.init();
  await manager.updateSettings({ downloadDir: tmpDlDir, preferAria2: false });
  const appServer = createAppServer({ manager, distDir: tmpDistDir });
  await new Promise((r) => appServer.listen(0, '127.0.0.1', r));
  const port = appServer.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  const validToken = manager.getSessionToken();

  try {
    // 1. Untrusted Host header blocked (403)
    const badHostRaw = await sendRawHttpHost(port, 'evil.example:3847', '/api/health');
    assert.ok(badHostRaw.startsWith('HTTP/1.1 403'));

    // 2. Untrusted Origin on GET blocked (403, not only POST!)
    const evilGet = await fetch(`${baseUrl}/api/state`, {
      method: 'GET',
      headers: { Origin: 'https://evil.example' },
    });
    assert.equal(evilGet.status, 403);

    // 3. Unauthenticated access returns 401 on state/events/actions; /api/health & /api/session/pair work
    const unauthState = await fetch(`${baseUrl}/api/state`);
    assert.equal(unauthState.status, 401);
    const unauthEvents = await fetch(`${baseUrl}/api/events`);
    assert.equal(unauthEvents.status, 401);

    const healthRes = await fetch(`${baseUrl}/api/health`);
    assert.equal(healthRes.status, 200);
    const healthData = await healthRes.json();
    assert.equal(healthData.requiresPairing, true);
    assert.equal(healthData.apiVersion, 4);

    const badPair = await fetch(`${baseUrl}/api/session/pair`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'wrong-token' }),
    });
    assert.equal(badPair.status, 401);

    const goodPair = await fetch(`${baseUrl}/api/session/pair`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: validToken }),
    });
    assert.equal(goodPair.status, 200);
    const pairJson = await goodPair.json();
    assert.equal(pairJson.paired, true);

    // 4. Local same-origin navigate GET / and SPA fallback inject short-lived one-time pairing code (NEVER raw bearer token!)
    const rawHttpGet = (reqPath, headers = {}) =>
      new Promise((resolve, reject) => {
        const req = http.request(
          { hostname: '127.0.0.1', port, path: reqPath, method: 'GET', headers },
          (res) => {
            const chunks = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () =>
              resolve({
                status: res.statusCode,
                headers: res.headers,
                body: Buffer.concat(chunks).toString('utf8'),
              })
            );
          }
        );
        req.on('error', reject);
        req.end();
      });

    const htmlRes = await rawHttpGet('/', {
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
    });
    assert.equal(htmlRes.status, 200);
    const htmlText = htmlRes.body;
    assert.equal(htmlText.includes(validToken), false, 'Reusable bearer token must never appear in HTML');
    const codeMatch = htmlText.match(/<meta name="boltgate-pairing-code" content="([^"]+)"/);
    assert.ok(codeMatch?.[1], 'Expected short-lived pairing code meta tag on same-origin navigate HTML');

    // Non-navigate fetch (Sec-Fetch-Mode: cors) must NOT receive pairing code injection
    const nonNavRes = await rawHttpGet('/', { 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Site': 'same-origin' });
    assert.equal(nonNavRes.status, 200);
    assert.equal(nonNavRes.body.includes('boltgate-pairing-code'), false);
    assert.equal(nonNavRes.body.includes(validToken), false);

    // Cross-origin / cross-site requests to / and SPA fallback MUST be rejected (403) with NO CORS headers and NO code/token
    const crossHtmlRoot = await rawHttpGet('/', {
      Origin: 'https://eeeeee3434343423.github.io',
      'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Site': 'cross-site',
    });
    assert.equal(crossHtmlRoot.status, 403);
    assert.equal(crossHtmlRoot.headers['access-control-allow-origin'], undefined);
    const crossSpa = await rawHttpGet('/downloads', {
      Origin: 'https://evil.example',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'cross-site',
    });
    assert.equal(crossSpa.status, 403);
    assert.equal(crossSpa.headers['access-control-allow-origin'], undefined);

    // Redeeming one-time pairing code works once and mints a working session token; second use fails with 401
    const redeemRes = await fetch(`${baseUrl}/api/session/pair`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: codeMatch[1] }),
    });
    assert.equal(redeemRes.status, 200);
    const redeemJson = await redeemRes.json();
    assert.equal(redeemJson.paired, true);
    assert.ok(redeemJson.sessionToken && redeemJson.sessionToken !== codeMatch[1]);

    const authState = await fetch(`${baseUrl}/api/state`, {
      headers: { 'X-BoltGate-Session': redeemJson.sessionToken },
    });
    assert.equal(authState.status, 200);

    const replayCode = await fetch(`${baseUrl}/api/session/pair`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: codeMatch[1] }),
    });
    assert.equal(replayCode.status, 401);

    // Loopback origin validation
    assert.equal(validateLoopbackOrigin('http://127.0.0.1:3847/'), 'http://127.0.0.1:3847');
    assert.equal(validateLoopbackOrigin('http://localhost:3847'), 'http://localhost:3847');
    assert.equal(validateLoopbackOrigin('http://[::1]:3847'), 'http://[::1]:3847');
    assert.equal(validateLoopbackOrigin('https://evil.example:3847'), null);
    assert.equal(validateLoopbackOrigin('http://user:pass@127.0.0.1:3847'), null);
    assert.equal(validateLoopbackOrigin('http://127.0.0.1:3847/api'), null);

    // 5. OriginRateLimiter Retry-After + worker step-down (never shortened below Retry-After!)
    const rl = new OriginRateLimiter();
    const rec = rl.recordRateLimit('https://mirror.example.com/a.bin', 429, '2', 8);
    assert.ok(rec.delayMs >= 2000, `Expected Retry-After >= 2000ms without negative jitter, got ${rec.delayMs}`);
    assert.equal(rec.newMaxWorkers, 4);
    assert.equal(rl.getRecommendedMaxWorkers('https://mirror.example.com/b.bin', 8), 4);
    assert.ok(rl.getBackingOffHostsForUrls(['https://mirror.example.com/a.bin']).includes('mirror.example.com'));

    // 6. IPFS full subPath preservation without double encoding + path traversal rejection
    const cid = 'QmYwAPJzv5CZsnAzt8auVZRn3b7Q9s7d5y8i3v7o2x9p1q';
    const ipfsParsed = parseSmartInput(
      `https://ipfs.io/ipfs/${cid}/folder%20one/My%20Book.epub ipfs://${cid}/../etc/passwd`
    );
    assert.equal(ipfsParsed.entries.length, 2);
    const validIpfs = ipfsParsed.entries.find((e) => e.raw.includes('folder%20one'));
    const traversalIpfs = ipfsParsed.entries.find((e) => e.raw.includes('..'));
    assert.ok(validIpfs && traversalIpfs);
    assert.equal(validIpfs.subPath, 'folder one/My Book.epub');
    assert.equal(traversalIpfs.subPath, undefined);
    const gwCands = expandIpfsCidToCandidates(
      cid,
      ['https://ipfs.io/ipfs/{cid}'],
      validIpfs.subPath
    );
    assert.equal(gwCands[0].url, `https://ipfs.io/ipfs/${cid}/folder%20one/My%20Book.epub`);
    assert.equal(gwCands[0].url.includes('%2520'), false);

    // 7. buildAria2Args honors low requested connections
    const lowConnArgs = buildAria2Args({
      uris: ['https://example.org/file.epub'],
      dir: tmpDlDir,
      maxConnectionsPerServer: 2,
      split: 2,
    });
    assert.ok(lowConnArgs.includes('--max-connection-per-server=2'));
    assert.ok(lowConnArgs.includes('--split=2'));

    // 8. normalizeSnapshot handles legacy companion payload safely
    const legacyNormalized = normalizeSnapshot({
      downloads: [],
      settings: { annasArchiveApiKey: 'legacy_key', downloadDir: tmpDlDir },
      trustRules: [],
    });
    assert.equal(legacyNormalized.capabilities.apiVersion, 1);
    assert.equal(legacyNormalized.settings.hasAnnasArchiveApiKey, true);
    assert.equal('annasArchiveApiKey' in legacyNormalized.settings, false);
  } finally {
    await manager.shutdown().catch(() => {});
    await new Promise((r) => appServer.close(() => r()));
    await fs.rm(tmpDataDir, { recursive: true, force: true });
    await fs.rm(tmpDistDir, { recursive: true, force: true });
    await fs.rm(tmpDlDir, { recursive: true, force: true });
  }
});

test('Audit 6: Complete redaction across REST/SSE/reprobe/errors/state.json/.part.meta, resolver secret rejection, and atomic legacy key migration', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit6-data-'));
  const tmpDlDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit6-dl-'));
  const apiKey = 'ACTIVE_PROVIDER_KEY_987654';
  const signedToken = 'SIGNED_MIRROR_TOK_555';
  const trackerPasskey = 'TRACKER_PASSKEY_777';
  const payload = makePayload(256 * 1024, 3);
  let leakedHits = 0;

  const mockSrv = http.createServer((req, res) => {
    const u = new URL(req.url, `http://127.0.0.1:${srv.port}`);
    if (u.pathname === '/leaked-downstream') {
      leakedHits++;
      res.writeHead(200);
      res.end('should not be reached');
      return;
    }
    if (u.pathname === '/dyn/api/fast_download.json') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      // Malicious/misconfigured response returning a candidate URL containing the active API key
      res.end(
        JSON.stringify({
          download_url: `http://127.0.0.1:${srv.port}/leaked-downstream?key=${apiKey}`,
        })
      );
      return;
    }
    if (u.pathname.startsWith('/md5/')) {
      res.writeHead(302, {
        Location: `http://127.0.0.1:${srv.port}/leaked-downstream?secret=${apiKey}`,
      });
      res.end();
      return;
    }
    if (u.pathname === '/signed.bin') {
      if (u.searchParams.get('token') !== signedToken) {
        res.writeHead(403);
        res.end('forbidden');
        return;
      }
      if (req.method === 'HEAD') {
        res.writeHead(200, {
          'Content-Length': payload.buf.length,
          'Accept-Ranges': 'bytes',
          ETag: '"sig1"',
        });
        res.end();
        return;
      }
      const range = req.headers.range;
      if (range && range.startsWith('bytes=')) {
        const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
        const start = Number(s);
        const end = e ? Number(e) : payload.buf.length - 1;
        const slice = payload.buf.subarray(start, end + 1);
        res.writeHead(206, {
          'Content-Range': `bytes ${start}-${end}/${payload.buf.length}`,
          'Content-Length': slice.length,
          'Accept-Ranges': 'bytes',
          ETag: '"sig1"',
        });
        res.end(slice);
        return;
      }
      res.writeHead(200, { 'Content-Length': payload.buf.length, ETag: '"sig1"' });
      res.end(payload.buf);
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const srv = await listenServer(mockSrv);
  const manager = new DownloadManager({ dataDir: tmpDataDir, allowInsecureLoopbackProvider: true });
  await manager.init();
  await manager.updateSettings({
    downloadDir: tmpDlDir,
    annasArchiveApiKey: apiKey,
    annasArchiveBaseUrl: `http://127.0.0.1:${srv.port}`,
    customMirrorUrls: [`https://user:mirrorpass@mirror.example/dl/{md5}?token=MIRROR_TMPL_SECRET`],
    ipfsGateways: [`https://gwuser:gwpass@gw.example/ipfs/{cid}?api_key=GW_SECRET_123`],
  });

  const appServer = createAppServer({ manager });
  await new Promise((r) => appServer.listen(0, '127.0.0.1', r));
  const baseUrl = `http://127.0.0.1:${appServer.address().port}`;
  const token = manager.getSessionToken();

  try {
    // 1. Resolver rejects candidate & redirect URLs carrying the active provider API key
    const resolved = await resolveBookSources(
      { md5: '0123456789abcdef0123456789abcdef' },
      { ...getDefaultSettings(), annasArchiveBaseUrl: `http://127.0.0.1:${srv.port}`, customMirrorUrls: [] },
      { apiKey, allowInsecureLoopbackForTests: true }
    );
    assert.equal(leakedHits, 0);
    assert.equal(resolved.candidates.length, 0);
    assert.equal(JSON.stringify(resolved).includes(apiKey), false);

    // 2. Settings templates redact credentials in REST snapshot & state.json
    const snap = manager.getSnapshot();
    const snapStr = JSON.stringify(snap);
    assert.equal(snapStr.includes('mirrorpass'), false);
    assert.equal(snapStr.includes('MIRROR_TMPL_SECRET'), false);
    assert.equal(snapStr.includes('gwpass'), false);
    assert.equal(snapStr.includes('GW_SECRET_123'), false);

    // 3. Magnet tracker passkey & torrentUrl token redacted in REST, SSE, reprobe, and state.json
    const sseChunks = [];
    const sseAbort = new AbortController();
    const sseReq = fetch(`${baseUrl}/api/events?session=${encodeURIComponent(token)}`, {
      signal: sseAbort.signal,
    }).then(async (r) => {
      const reader = r.body.getReader();
      const dec = new TextDecoder();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        sseChunks.push(dec.decode(value, { stream: true }));
      }
    }).catch(() => {});

    const magnetUrl = `magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&tr=${encodeURIComponent(`https://tracker.example/announce?passkey=${trackerPasskey}`)}`;
    const torrentUrl = `http://127.0.0.1:${srv.port}/book.torrent?token=${signedToken}`;
    const inspRes = await fetch(`${baseUrl}/api/inspect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-BoltGate-Session': token },
      body: JSON.stringify({ text: `${magnetUrl}\n${torrentUrl}` }),
    });
    const inspJson = await inspRes.json();
    assert.equal(JSON.stringify(inspJson).includes(trackerPasskey), false);
    assert.equal(JSON.stringify(inspJson).includes(signedToken), false);

    const torrentId = inspJson.items.find((i) => i.torrentUrl)?.id;
    await waitFor(() => manager.getSnapshot().downloads.find((d) => d.id === torrentId)?.status === 'pending_review');
    const reprobeRes = await fetch(`${baseUrl}/api/downloads/${torrentId}/reprobe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-BoltGate-Session': token },
      body: JSON.stringify({}),
    });
    const reprobeJson = await reprobeRes.json();
    assert.equal(JSON.stringify(reprobeJson).includes(signedToken), false);

    await new Promise((r) => setTimeout(r, 120));
    sseAbort.abort();
    await sseReq;
    const allSse = sseChunks.join('');
    assert.equal(allSse.includes(trackerPasskey), false);
    assert.equal(allSse.includes(signedToken), false);
    assert.equal(allSse.includes(apiKey), false);

    // 4. .part.meta stores opaque sourceIds (ZERO raw signed URLs!)
    const partItem = makeItem(
      `http://127.0.0.1:${srv.port}/signed.bin?token=${signedToken}`,
      tmpDlDir,
      'meta-redact.bin',
      { totalBytes: payload.buf.length, connections: 2, supportsRanges: true, etag: '"sig1"' }
    );
    const runner = new DownloadRunner({
      item: partItem,
      throttle: new TokenBucketThrottle(64),
      secrets: [signedToken],
      onUpdate: () => {},
    });
    const runP = runner.run();
    await new Promise((r) => setTimeout(r, 120));
    await runner.pause();
    await runP;
    const rawMetaText = await fs.readFile(`${partItem.partPath}.meta`, 'utf8');
    assert.equal(rawMetaText.includes(signedToken), false, '.part.meta must not contain signed tokens');
    assert.equal(rawMetaText.includes('http://127.0.0.1'), false, '.part.meta must store opaque sourceIds instead of raw URLs');
    const parsedMeta = await readPartMeta(partItem.partPath);
    assert.ok(parsedMeta.mirrors[0].sourceId.startsWith('src_'));

    // 5. StateStore.load() preserves legacy plaintext key in state.json until encrypted migration verifies it
    const migDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-mig-'));
    try {
      const legacySecret = 'legacy_do_not_scrub_early_42';
      await fs.writeFile(
        path.join(migDir, 'state.json'),
        JSON.stringify({
          version: 1,
          downloads: [],
          trustRules: [],
          settings: { ...getDefaultSettings(), annasArchiveApiKey: legacySecret },
        }),
        'utf8'
      );
      const storeOnly = new StateStore(migDir);
      const loaded = await storeOnly.load();
      assert.equal(loaded.migratedAnnasApiKey, legacySecret);
      const stillOnDisk = await fs.readFile(path.join(migDir, 'state.json'), 'utf8');
      assert.equal(
        stillOnDisk.includes(legacySecret),
        true,
        'StateStore.load() must not scrub legacy key before SecretStore encrypts and verifies it'
      );
    } finally {
      await fs.rm(migDir, { recursive: true, force: true });
    }
  } finally {
    await manager.shutdown().catch(() => {});
    await new Promise((r) => appServer.close(() => r()));
    await srv.close();
    await fs.rm(tmpDataDir, { recursive: true, force: true });
    await fs.rm(tmpDlDir, { recursive: true, force: true });
  }
});

test('Audit 7: Validator strictness (missing ETag, conflicting Last-Modified), wildcard/unsolicited 206, overlong 200, interrupted range->200 fallback, and inspector/benchmarker bounds', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit7-'));
  const payload = makePayload(256 * 1024, 17);
  let fallbackHits = 0;

  const srv = await listenServer(
    http.createServer((req, res) => {
      if (req.url === '/missing-etag.bin') {
        const range = req.headers.range ?? 'bytes=0-';
        const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
        const start = Number(s);
        const end = e ? Number(e) : payload.buf.length - 1;
        const slice = payload.buf.subarray(start, end + 1);
        // Pinned ETag omitted on response!
        res.writeHead(206, {
          'Content-Range': `bytes ${start}-${end}/${payload.buf.length}`,
          'Content-Length': slice.length,
        });
        res.end(slice);
        return;
      }

      if (req.url === '/conflicting-lm.bin') {
        const range = req.headers.range ?? 'bytes=0-';
        const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
        const start = Number(s);
        const end = e ? Number(e) : payload.buf.length - 1;
        const slice = payload.buf.subarray(start, end + 1);
        // Same ETag but conflicting Last-Modified!
        res.writeHead(206, {
          'Content-Range': `bytes ${start}-${end}/${payload.buf.length}`,
          'Content-Length': slice.length,
          ETag: '"same-etag"',
          'Last-Modified': 'Tue, 02 Jan 2024 00:00:00 GMT',
        });
        res.end(slice);
        return;
      }

      if (req.url === '/wildcard-206.bin') {
        res.writeHead(206, {
          'Content-Range': `bytes 0-${payload.buf.length - 1}/*`,
          'Content-Length': payload.buf.length,
        });
        res.end(payload.buf);
        return;
      }

      if (req.url === '/unsolicited-206.bin') {
        res.writeHead(206, {
          'Content-Range': `bytes 0-${payload.buf.length - 1}/${payload.buf.length}`,
          'Content-Length': payload.buf.length,
        });
        res.end(payload.buf);
        return;
      }

      if (req.url === '/overlong-200.bin') {
        // Chunked 200 OK sending MORE bytes than probed totalBytes!
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
        res.write(payload.buf);
        res.end(Buffer.alloc(4096, 0xaa));
        return;
      }

      if (req.url === '/range-to-200-flaky.bin') {
        fallbackHits++;
        // Ignore Range header, return 200 OK; drop first attempt mid-flight, succeed on retry!
        res.writeHead(200, { 'Content-Length': payload.buf.length });
        if (fallbackHits === 1) {
          res.write(payload.buf.subarray(0, 64 * 1024));
          setTimeout(() => res.destroy(), 20);
          return;
        }
        res.end(payload.buf);
        return;
      }

      if (req.url === '/head-fail-get-drop.bin') {
        if (req.method === 'HEAD') {
          res.writeHead(405, { 'Content-Type': 'text/html', 'Content-Length': 1234 });
          res.end();
          return;
        }
        // Abruptly reset socket on fallback GET
        req.socket.destroy();
        return;
      }

      if (req.url === '/bad-bench-range.bin') {
        if (req.method === 'HEAD') {
          res.writeHead(200, { 'Content-Length': payload.buf.length, 'Accept-Ranges': 'bytes' });
          res.end();
          return;
        }
        // Requested bytes=0-65535, server lies and returns bytes 0-99999/262144
        res.writeHead(206, {
          'Content-Range': `bytes 0-99999/${payload.buf.length}`,
          'Content-Length': 100000,
        });
        res.end(payload.buf.subarray(0, 100000));
        return;
      }

      res.writeHead(404);
      res.end();
    })
  );

  try {
    // 1. Missing ETag when pinned -> rejected
    const missingEtag = makeItem(`http://127.0.0.1:${srv.port}/missing-etag.bin`, tmpDir, 'm-etag.bin', {
      totalBytes: payload.buf.length,
      connections: 1,
      supportsRanges: true,
      etag: '"pinned-v1"',
    });
    await new DownloadRunner({ item: missingEtag, throttle: new TokenBucketThrottle(0), maxRetries: 1, onUpdate: () => {} }).run();
    assert.equal(missingEtag.status, 'failed');
    assert.ok(missingEtag.error?.includes('Missing ETag'));

    // 2. Conflicting Last-Modified even on equal ETag -> rejected
    const conflictLm = makeItem(`http://127.0.0.1:${srv.port}/conflicting-lm.bin`, tmpDir, 'c-lm.bin', {
      totalBytes: payload.buf.length,
      connections: 1,
      supportsRanges: true,
      etag: '"same-etag"',
      lastModified: 'Mon, 01 Jan 2024 00:00:00 GMT',
    });
    await new DownloadRunner({ item: conflictLm, throttle: new TokenBucketThrottle(0), maxRetries: 1, onUpdate: () => {} }).run();
    assert.equal(conflictLm.status, 'failed');
    assert.ok(conflictLm.error?.includes('Last-Modified'));

    // 3. Wildcard 206 total (`/*`) -> rejected
    const wild206 = makeItem(`http://127.0.0.1:${srv.port}/wildcard-206.bin`, tmpDir, 'wild.bin', {
      totalBytes: payload.buf.length,
      connections: 1,
      supportsRanges: true,
    });
    await new DownloadRunner({ item: wild206, throttle: new TokenBucketThrottle(0), maxRetries: 1, onUpdate: () => {} }).run();
    assert.equal(wild206.status, 'failed');
    assert.ok(wild206.error?.includes('Content-Range'));

    // 4. Unsolicited 206 in non-range mode -> rejected
    const unsol206 = makeItem(`http://127.0.0.1:${srv.port}/unsolicited-206.bin`, tmpDir, 'unsol.bin', {
      totalBytes: payload.buf.length,
      connections: 1,
      supportsRanges: false,
    });
    await new DownloadRunner({ item: unsol206, throttle: new TokenBucketThrottle(0), maxRetries: 1, onUpdate: () => {} }).run();
    assert.equal(unsol206.status, 'failed');
    assert.ok(unsol206.error?.includes('206'));

    // 5. Overlong 200 body exceeding known totalBytes -> rejected (NOT silently clipped)
    const overlong200 = makeItem(`http://127.0.0.1:${srv.port}/overlong-200.bin`, tmpDir, 'overlong.bin', {
      totalBytes: payload.buf.length,
      connections: 1,
      supportsRanges: false,
    });
    await new DownloadRunner({ item: overlong200, throttle: new TokenBucketThrottle(0), maxRetries: 1, onUpdate: () => {} }).run();
    assert.equal(overlong200.status, 'failed');
    assert.ok(overlong200.error?.includes('exceeded expected length'));

    // 6. Interrupted range->200 fallback retains retry ownership and completes with exact SHA-256
    const fallbackItem = makeItem(`http://127.0.0.1:${srv.port}/range-to-200-flaky.bin`, tmpDir, 'fallback200.bin', {
      totalBytes: payload.buf.length,
      connections: 2,
      supportsRanges: true,
    });
    await new DownloadRunner({ item: fallbackItem, throttle: new TokenBucketThrottle(0), onUpdate: () => {} }).run();
    assert.equal(fallbackItem.status, 'completed');
    assert.equal(fallbackItem.sha256, payload.sha256);
    assert.ok(fallbackHits >= 2);

    // 7. aria2c single-source HTTP identity enforcement without trusted digest vs with digest
    const singleOnly = selectAria2HttpSources({
      finalUrl: 'https://a.example/f.epub',
      mirrorUrls: ['https://a.example/f.epub', 'https://b.example/f.epub'],
    });
    assert.deepEqual(singleOnly, ['https://a.example/f.epub']);
    const multiWithDigest = selectAria2HttpSources({
      finalUrl: 'https://a.example/f.epub',
      mirrorUrls: ['https://a.example/f.epub', 'https://b.example/f.epub'],
      expectedSha256: payload.sha256,
    });
    assert.equal(multiWithDigest.length, 2);

    // 8. probeUrl must NOT restore failed HEAD metadata when fallback GET fails
    const failedProbe = await probeUrl(`http://127.0.0.1:${srv.port}/head-fail-get-drop.bin`, {
      trustRules: [],
      existingDownloads: [],
    });
    assert.equal(failedProbe.riskLevel, 'error');
    assert.equal(failedProbe.statusCode, undefined);
    assert.equal(failedProbe.totalBytes, null);
    assert.ok(failedProbe.probeError);

    // 9. benchmarkCandidates rejects out-of-bounds 206 sample range
    const [bench] = await benchmarkCandidates([
      {
        url: `http://127.0.0.1:${srv.port}/bad-bench-range.bin`,
        label: 'BadRange',
        tier: 'mirror',
        host: '127.0.0.1',
        priority: 50,
      },
    ]);
    assert.equal(bench.ok, false);
    assert.ok(bench.error?.includes('206'));
  } finally {
    await srv.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('Audit 8: Failed/short disk writes, failed datasync(), truncate-before-checkpoint isolation, oversized .part resume, and atomic publication fallbacks', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit8-'));
  const payload = makePayload(256 * 1024, 29);
  let retryDropOnce = false;

  const srv = await listenServer(
    http.createServer((req, res) => {
      if (req.url === '/flaky-nonrange.bin') {
        res.writeHead(200, { 'Content-Length': payload.buf.length });
        if (!retryDropOnce) {
          retryDropOnce = true;
          res.write(payload.buf.subarray(0, 64 * 1024));
          setTimeout(() => res.destroy(), 20);
          return;
        }
        res.end(payload.buf);
        return;
      }
      const range = req.headers.range;
      if (range && range.startsWith('bytes=')) {
        const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
        const start = Number(s);
        const end = e ? Number(e) : payload.buf.length - 1;
        const slice = payload.buf.subarray(start, end + 1);
        res.writeHead(206, {
          'Content-Range': `bytes ${start}-${end}/${payload.buf.length}`,
          'Content-Length': slice.length,
          'Accept-Ranges': 'bytes',
        });
        res.end(slice);
        return;
      }
      res.writeHead(200, { 'Content-Length': payload.buf.length });
      res.end(payload.buf);
    })
  );

  try {
    // 1. Short / ENOSPC write fails terminally, never marks segment done with 0 committed bytes, never publishes
    const enospcItem = makeItem(`http://127.0.0.1:${srv.port}/ok.bin`, tmpDir, 'enospc.bin', {
      totalBytes: payload.buf.length,
      connections: 1,
      supportsRanges: true,
    });
    await new DownloadRunner({
      item: enospcItem,
      throttle: new TokenBucketThrottle(0),
      fileHooks: {
        wrapHandle: (fh) =>
          new Proxy(fh, {
            get(target, prop, recv) {
              if (prop === 'write') {
                return async () => {
                  throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' });
                };
              }
              const v = Reflect.get(target, prop, recv);
              return typeof v === 'function' ? v.bind(target) : v;
            },
          }),
      },
      onUpdate: () => {},
    }).run();
    assert.equal(enospcItem.status, 'failed');
    assert.equal(enospcItem.downloadedBytes, 0);
    assert.ok(enospcItem.error?.includes('ENOSPC'));
    await assert.rejects(fs.access(path.join(tmpDir, 'enospc.bin')));

    // 2. Failed datasync() propagates error and prevents .part.meta creation & publication
    const datasyncItem = makeItem(`http://127.0.0.1:${srv.port}/ok.bin`, tmpDir, 'bad-sync.bin', {
      totalBytes: payload.buf.length,
      connections: 1,
      supportsRanges: true,
    });
    await new DownloadRunner({
      item: datasyncItem,
      throttle: new TokenBucketThrottle(0),
      fileHooks: {
        wrapHandle: (fh) =>
          new Proxy(fh, {
            get(target, prop, recv) {
              if (prop === 'datasync') {
                return async () => {
                  throw Object.assign(new Error('EIO: datasync failed'), { code: 'EIO' });
                };
              }
              const v = Reflect.get(target, prop, recv);
              return typeof v === 'function' ? v.bind(target) : v;
            },
          }),
      },
      onUpdate: () => {},
    }).run();
    assert.equal(datasyncItem.status, 'failed');
    assert.ok(datasyncItem.error?.includes('datasync failed'));
    // The sidecar slot is reserved together with the payload (empty placeholder), but NO valid
    // checkpoint may ever be written when the payload datasync failed.
    assert.equal(await readPartMeta(datasyncItem.partPath), null);
    const placeholder = await fs.readFile(`${datasyncItem.partPath}.meta`, 'utf8').catch(() => '');
    assert.equal(placeholder, '', 'Sidecar must remain an empty (invalid) reservation placeholder');
    await assert.rejects(fs.access(path.join(tmpDir, 'bad-sync.bin')));

    // 3. Checkpoint (.part.meta) is invalidated BEFORE truncate(0) during non-range retry reset
    let metaExistedDuringTruncate0 = null;
    const truncItem = makeItem(`http://127.0.0.1:${srv.port}/flaky-nonrange.bin`, tmpDir, 'trunc-iso.bin', {
      totalBytes: payload.buf.length,
      connections: 1,
      supportsRanges: false,
    });
    await new DownloadRunner({
      item: truncItem,
      throttle: new TokenBucketThrottle(0),
      fileHooks: {
        wrapHandle: (fh) =>
          new Proxy(fh, {
            get(target, prop, recv) {
              if (prop === 'truncate') {
                return async (len) => {
                  if (len === 0) {
                    metaExistedDuringTruncate0 = await fs
                      .access(`${truncItem.partPath}.meta`)
                      .then(() => true)
                      .catch(() => false);
                  }
                  return target.truncate(len);
                };
              }
              const v = Reflect.get(target, prop, recv);
              return typeof v === 'function' ? v.bind(target) : v;
            },
          }),
      },
      onUpdate: () => {},
    }).run();
    assert.equal(truncItem.status, 'completed');
    assert.equal(truncItem.sha256, payload.sha256);
    assert.equal(metaExistedDuringTruncate0, false, '.part.meta must be removed BEFORE truncate(0)');

    // 4. Oversized .part file on resume is rejected by validatePartMetaGeometry and replaced cleanly
    const overPartPath = path.join(tmpDir, '.boltgate-oversized-over.bin.part');
    await fs.writeFile(overPartPath, Buffer.alloc(payload.buf.length + 8192, 0xcc));
    const overMeta = {
      version: 2,
      jobId: 'oversized',
      partPath: overPartPath,
      filename: 'over.bin',
      totalBytes: payload.buf.length,
      mirrors: [],
      segments: [{ id: 0, start: 0, end: payload.buf.length - 1, committedBytes: 65536, status: 'paused' }],
      updatedAt: Date.now(),
    };
    await writePartMeta(overPartPath, overMeta);
    const geom = validatePartMetaGeometry(overMeta, {
      jobId: 'oversized',
      partPath: overPartPath,
      totalBytes: payload.buf.length,
      partFileSize: payload.buf.length + 8192,
    });
    assert.equal(geom.valid, false);
    assert.ok(geom.reason?.includes('Oversized'));

    const overItem = makeItem(`http://127.0.0.1:${srv.port}/ok.bin`, tmpDir, 'over.bin', {
      id: 'oversized',
      totalBytes: payload.buf.length,
      connections: 2,
      supportsRanges: true,
      partPath: overPartPath,
    });
    await new DownloadRunner({ item: overItem, throttle: new TokenBucketThrottle(0), onUpdate: () => {} }).run();
    assert.equal(overItem.status, 'completed');
    assert.equal(overItem.sha256, payload.sha256);

    // 5. publishStagingFileAtomically: EXDEV uses hidden temp + atomic link; EPERM preserves staging & exposes NO partial target
    const pubDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-pub-'));
    try {
      const stageExdev = path.join(pubDir, '.stage-exdev.part');
      await fs.writeFile(stageExdev, 'VERIFIED_EXDEV_DATA');
      let firstLink = true;
      const exdevRes = await publishStagingFileAtomically(stageExdev, pubDir, 'final-exdev.bin', {
        link: async (src, dst) => {
          if (firstLink) {
            firstLink = false;
            throw Object.assign(new Error('cross-device link not permitted'), { code: 'EXDEV' });
          }
          return fs.link(src, dst);
        },
      });
      assert.equal(await fs.readFile(exdevRes.savedPath, 'utf8'), 'VERIFIED_EXDEV_DATA');

      const stageEperm = path.join(pubDir, '.stage-eperm.part');
      await fs.writeFile(stageEperm, 'VERIFIED_EPERM_DATA');
      await assert.rejects(
        publishStagingFileAtomically(stageEperm, pubDir, 'final-eperm.bin', {
          link: async () => {
            throw Object.assign(new Error('hard links unsupported'), { code: 'ENOTSUP' });
          },
        }),
        /Atomic no-replace publication is unavailable/
      );
      // Destination must NOT have any partial file, and verified staging must be preserved!
      await assert.rejects(fs.access(path.join(pubDir, 'final-eperm.bin')));
      assert.equal(await fs.readFile(stageEperm, 'utf8'), 'VERIFIED_EPERM_DATA');
    } finally {
      await fs.rm(pubDir, { recursive: true, force: true });
    }
  } finally {
    await srv.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('Audit 9: Safe cancel during probing, concurrent insert+remove, Undo->resume signed URL, hash re-check invalidating integrity badge, pre-publish expectedSha256, Retry-After redirect gating, and Settings draft stability', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit9-data-'));
  const tmpDlDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit9-dl-'));

  // Minimal valid EPUB payload
  const zipHeader = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]);
  const zipEocd = Buffer.alloc(22);
  Buffer.from([0x50, 0x4b, 0x05, 0x06]).copy(zipEocd, 0);
  const epubBuf = Buffer.concat([zipHeader, Buffer.alloc(128 * 1024, 0x42), zipEocd]);
  const epubSha256 = crypto.createHash('sha256').update(epubBuf).digest('hex');
  const signedSecret = 'LIVE_SIGNED_SECRET_789';
  let slowProbeRelease;
  let redirect429Count = 0;

  // Separate CDN server to test responding-origin Retry-After gating on redirect
  const cdnSrv = await listenServer(
    http.createServer((req, res) => {
      if (req.url === '/cdn-rate-limited.bin') {
        redirect429Count++;
        if (redirect429Count === 1) {
          res.writeHead(429, { 'Retry-After': '1' });
          res.end('slow down');
          return;
        }
        res.writeHead(200, { 'Content-Length': epubBuf.length });
        res.end(epubBuf);
        return;
      }
      res.writeHead(404);
      res.end();
    })
  );

  const mainSrv = await listenServer(
    http.createServer(async (req, res) => {
      const u = new URL(req.url, `http://127.0.0.1:${mainSrv.port}`);
      if (u.pathname === '/slow-probe.epub') {
        await new Promise((r) => {
          slowProbeRelease = r;
          setTimeout(r, 1500);
        });
        res.writeHead(200, { 'Content-Length': epubBuf.length, 'Content-Type': 'application/epub+zip' });
        res.end(req.method === 'HEAD' ? undefined : epubBuf);
        return;
      }
      if (u.pathname === '/signed-book.epub') {
        if (u.searchParams.get('token') !== signedSecret) {
          res.writeHead(403);
          res.end('bad token');
          return;
        }
        if (req.method === 'HEAD') {
          res.writeHead(200, {
            'Content-Length': epubBuf.length,
            'Accept-Ranges': 'bytes',
            'Content-Type': 'application/epub+zip',
          });
          res.end();
          return;
        }
        const range = req.headers.range;
        if (range && range.startsWith('bytes=')) {
          const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
          const start = Number(s);
          const end = e ? Number(e) : epubBuf.length - 1;
          const slice = epubBuf.subarray(start, end + 1);
          res.writeHead(206, {
            'Content-Range': `bytes ${start}-${end}/${epubBuf.length}`,
            'Content-Length': slice.length,
            'Accept-Ranges': 'bytes',
            'Content-Type': 'application/epub+zip',
          });
          res.end(slice);
          return;
        }
        res.writeHead(200, { 'Content-Length': epubBuf.length, 'Content-Type': 'application/epub+zip' });
        res.end(epubBuf);
        return;
      }
      if (u.pathname === '/redir-to-429.bin') {
        res.writeHead(302, { Location: `http://127.0.0.1:${cdnSrv.port}/cdn-rate-limited.bin` });
        res.end();
        return;
      }
      res.writeHead(404);
      res.end();
    })
  );

  const manager = new DownloadManager({ dataDir: tmpDataDir });
  await manager.init();
  await manager.updateSettings({ downloadDir: tmpDlDir });

  try {
    // 1. Safe cancel during probing next to an unrelated .part file
    const unrelatedPart = path.join(tmpDlDir, 'slow-probe.epub.part');
    await fs.writeFile(unrelatedPart, 'UNRELATED_USER_PART_FILE');
    const probeRes = await manager.inspectRawText(`http://127.0.0.1:${mainSrv.port}/slow-probe.epub`);
    const probeId = probeRes.items[0].id;
    assert.equal(probeRes.items[0].partPath, '', 'partPath must remain unset during probing');
    await manager.rejectDownload(probeId, false);
    slowProbeRelease?.();
    assert.equal(await fs.readFile(unrelatedPart, 'utf8'), 'UNRELATED_USER_PART_FILE');

    // 2. Concurrent queue insert + remove while runner.cancel() is awaiting (must remove by job ID, never shifted index!)
    const fakeCancelItem = makeItem(`http://127.0.0.1:${mainSrv.port}/signed-book.epub?token=${signedSecret}`, tmpDlDir, 'cancel-race.bin', {
      totalBytes: epubBuf.length,
    });
    manager['downloads'].unshift(fakeCancelItem);
    let releaseCancel;
    manager['runners'].set(fakeCancelItem.id, {
      runner: {
        item: fakeCancelItem,
        run: async () => {},
        pause: async () => {},
        cancel: () => new Promise((r) => { releaseCancel = r; }),
      },
      done: Promise.resolve(),
    });
    const removePromise = manager.removeDownload(fakeCancelItem.id, false);
    // Concurrently insert a brand-new job at index 0 via unshift while removal is awaiting!
    const insertedRes = await manager.inspectRawText(`http://127.0.0.1:${mainSrv.port}/signed-book.epub?token=${signedSecret}`);
    const insertedId = insertedRes.items[0].id;
    releaseCancel();
    await removePromise;
    const idsAfter = manager.getSnapshot().downloads.map((d) => d.id);
    assert.equal(idsAfter.includes(fakeCancelItem.id), false);
    assert.equal(idsAfter.includes(insertedId), true, 'Newly inserted job must not be spliced by shifted index');

    // 3. Soft-remove -> Undo -> resume with signed URL (state.json stays redacted, operational URL restored from encrypted vault!)
    await waitFor(() => manager.getSnapshot().downloads.find((d) => d.id === insertedId)?.status === 'pending_review');
    await manager.removeDownload(insertedId, false);
    const diskState = await fs.readFile(path.join(tmpDataDir, 'state.json'), 'utf8');
    assert.equal(diskState.includes(signedSecret), false);
    await manager.restoreDownload(insertedId);

    // 4. Pre-publish expectedSha256 on approval: mismatch fails before publish; matching hash completes & verifies EPUB!
    await manager.approveDownload(insertedId, {
      expectedSha256: '0'.repeat(64),
      startNow: true,
    });
    const failedSha = await waitFor(() => {
      const d = manager.getSnapshot().downloads.find((x) => x.id === insertedId);
      return d?.status === 'failed' ? d : null;
    });
    assert.equal(failedSha.verifiedHashMatch, false);

    // Update expectedSha256 to real hash via re-approval and complete
    await manager.approveDownload(insertedId, {
      expectedSha256: epubSha256,
      startNow: true,
    });
    const completedEpub = await waitFor(() => {
      const d = manager.getSnapshot().downloads.find((x) => x.id === insertedId);
      return d?.status === 'completed' ? d : null;
    });
    assert.equal(completedEpub.verifiedHashMatch, true);
    assert.equal(completedEpub.integrity?.status, 'valid');

    // 5. Mutate EPUB on disk & run manual verifyHash -> match: false AND stale integrity badge invalidated!
    await fs.writeFile(completedEpub.savedPath, Buffer.concat([epubBuf.subarray(0, 64), Buffer.from('CORRUPT')]));
    const verifyRes = await manager.verifyHash(insertedId, epubSha256);
    assert.equal(verifyRes.match, false);
    const afterVerify = manager.getSnapshot().downloads.find((x) => x.id === insertedId);
    assert.equal(afterVerify.integrity, undefined, 'Stale format verification badge must be invalidated when file mutates / hash fails');

    // 6. Responding-origin Retry-After gating on 302 -> 429 (honors full >= 1000ms Retry-After without shortening!)
    const limiter = new OriginRateLimiter();
    const redir429Item = makeItem(`http://127.0.0.1:${mainSrv.port}/redir-to-429.bin`, tmpDlDir, 'redir429.epub', {
      totalBytes: epubBuf.length,
      connections: 1,
      supportsRanges: false,
    });
    const t0 = Date.now();
    await new DownloadRunner({
      item: redir429Item,
      throttle: new TokenBucketThrottle(0),
      rateLimiter: limiter,
      onUpdate: () => {},
    }).run();
    const elapsed = Date.now() - t0;
    assert.equal(redir429Item.status, 'completed');
    assert.equal(redir429Item.sha256, epubSha256);
    assert.ok(elapsed >= 950, `Expected full Retry-After (>= ~1000ms) on responding origin, got ${elapsed}ms`);

    // 7. Settings draft stability across repeated re-renders with fresh normalizeSettings() calls
    const baseSettings = normalizeSettings({ ...getDefaultSettings(), downloadDir: tmpDlDir });
    const prevSaved = buildSettingsDraftSnapshot(baseSettings);
    const userTypingDraft = {
      ...prevSaved,
      downloadDir: 'C:\\Users\\typing-unsaved-path',
      customMirrorsText: 'https://typing-mirror.example/{md5}',
    };
    // Simulate SSE telemetry tick passing a fresh normalizeSettings() object with unchanged values
    const rerenderedSettings = normalizeSettings({ ...baseSettings });
    const nextSavedUnchanged = buildSettingsDraftSnapshot(rerenderedSettings);
    const afterTick = mergeSettingsDrafts(userTypingDraft, prevSaved, nextSavedUnchanged);
    assert.equal(afterTick.downloadDir, 'C:\\Users\\typing-unsaved-path');
    assert.equal(afterTick.customMirrorsText, 'https://typing-mirror.example/{md5}');

    // When ONLY speedLimitKBps changes on server, only speedInputKBps syncs while other unsaved drafts stay intact
    const nextSavedPartial = buildSettingsDraftSnapshot(
      normalizeSettings({ ...baseSettings, speedLimitKBps: 1024 })
    );
    const afterPartial = mergeSettingsDrafts(afterTick, nextSavedUnchanged, nextSavedPartial);
    assert.equal(afterPartial.speedInputKBps, '1024');
    assert.equal(afterPartial.downloadDir, 'C:\\Users\\typing-unsaved-path');
    assert.equal(afterPartial.customMirrorsText, 'https://typing-mirror.example/{md5}');
  } finally {
    await manager.shutdown().catch(() => {});
    await mainSrv.close();
    await cdnSrv.close();
    await fs.rm(tmpDataDir, { recursive: true, force: true });
    await fs.rm(tmpDlDir, { recursive: true, force: true });
  }
});


test('Audit 10: Strict Sec-Fetch pairing guard, loopback bind enforcement, pairing capacity/expiry, and two-tab origin-pinned secret writes', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit10-data-'));
  const tmpDistDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit10-dist-'));

  await fs.writeFile(
    path.join(tmpDistDir, 'index.html'),
    '<!doctype html><html><head><title>BoltGate</title></head><body>ok</body></html>',
    'utf8'
  );

  const manager = new DownloadManager({ dataDir: tmpDataDir });
  await manager.init();
  const appServer = createAppServer({ manager, distDir: tmpDistDir });
  await new Promise((r) => appServer.listen(0, '127.0.0.1', r));
  const port = appServer.address().port;

  const rawHttpGet = (reqPath, headers = {}) =>
    new Promise((resolve, reject) => {
      const req = http.request(
        { hostname: '127.0.0.1', port, path: reqPath, method: 'GET', headers },
        (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () =>
            resolve({
              status: res.statusCode,
              headers: res.headers,
              body: Buffer.concat(chunks).toString('utf8'),
            })
          );
        }
      );
      req.on('error', reject);
      req.end();
    });

  try {
    // 1. Missing Sec-Fetch-* headers MUST NOT inject pairing code
    const missingFetchMeta = await rawHttpGet('/');
    assert.equal(missingFetchMeta.status, 200);
    assert.equal(missingFetchMeta.body.includes('boltgate-pairing-code'), false);

    // Sec-Fetch-Mode: navigate WITHOUT Sec-Fetch-Site MUST NOT inject pairing code
    const navWithoutSite = await rawHttpGet('/', { 'Sec-Fetch-Mode': 'navigate' });
    assert.equal(navWithoutSite.status, 200);
    assert.equal(navWithoutSite.body.includes('boltgate-pairing-code'), false);

    // Explicit Sec-Fetch-Mode: navigate + Sec-Fetch-Site: same-origin DOES inject pairing code
    const validSameOriginNav = await rawHttpGet('/', {
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'same-origin',
    });
    assert.equal(validSameOriginNav.status, 200);
    assert.ok(validSameOriginNav.body.includes('boltgate-pairing-code'));

    // 2. Non-loopback bind host enforcement
    assert.equal(assertLoopbackBindHost('127.0.0.1'), '127.0.0.1');
    assert.equal(assertLoopbackBindHost('localhost'), 'localhost');
    assert.equal(assertLoopbackBindHost('::1'), '::1');
    assert.throws(() => assertLoopbackBindHost('0.0.0.0'), /loopback/i);
    assert.throws(() => assertLoopbackBindHost('192.168.1.50'), /loopback/i);
    assert.throws(() => assertLoopbackBindHost('::'), /loopback/i);

    // 3. Pairing code capacity & expiry: redeeming 1st code at 64-code capacity succeeds (no eviction on redeem!)
    const storeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit10-pair-'));
    try {
      const store = new SecretStore(storeDir);
      const issued = [];
      for (let i = 0; i < 64; i++) {
        issued.push(store.issuePairingCode(60_000));
      }
      const redeemedFirst = store.redeemPairingCredential(issued[0].code);
      assert.ok(redeemedFirst, 'First issued valid pairing code must redeem even when table is at capacity');
      assert.equal(store.redeemPairingCredential(issued[0].code), null, 'One-time code must not replay');

      // Expired code fails redemption
      const expiring = store.issuePairingCode(15_000);
      store['pairingCodes'].get(expiring.code).expiresAt = Date.now() - 1;
      assert.equal(store.redeemPairingCredential(expiring.code), null);
    } finally {
      await fs.rm(storeDir, { recursive: true, force: true });
    }

    // 4. Two-tab engine switching during secret key entry (origin-pinned secret write validation)
    const validPin = {
      engineOrigin: 'http://127.0.0.1:3847',
      sessionToken: 'tok_3847_abc',
      writeOnlySecrets: true,
      capabilityOrigin: 'http://127.0.0.1:3847',
      capabilitySessionToken: 'tok_3847_abc',
    };
    assert.deepEqual(assertPinnedSecretWriteContext(validPin, 'http://127.0.0.1:3847'), {
      engineOrigin: 'http://127.0.0.1:3847',
      sessionToken: 'tok_3847_abc',
    });
    assert.throws(
      () => assertPinnedSecretWriteContext(validPin, 'http://127.0.0.1:3848'),
      /changed in another tab/i
    );
    assert.throws(
      () => assertPinnedSecretWriteContext({ ...validPin, writeOnlySecrets: false }, 'http://127.0.0.1:3847'),
      /writeOnlySecrets/i
    );
    assert.throws(
      () => assertPinnedSecretWriteContext({ ...validPin, sessionToken: '' }, 'http://127.0.0.1:3847'),
      /session|paired/i
    );
    // Capability must be literally `true` (never truthy coercion like "false" / 1 / "true")
    for (const coerced of ['true', 'false', 1, {}, null, undefined]) {
      assert.throws(
        () => assertPinnedSecretWriteContext({ ...validPin, writeOnlySecrets: coerced }, 'http://127.0.0.1:3847'),
        /writeOnlySecrets/i,
        `writeOnlySecrets=${JSON.stringify(coerced)} must not enable secret writes`
      );
    }
    // Capability observed on ANOTHER engine (other tab switched engines) cannot authorize this write
    assert.throws(
      () =>
        assertPinnedSecretWriteContext(
          { ...validPin, capabilityOrigin: 'http://127.0.0.1:3848' },
          'http://127.0.0.1:3847'
        ),
      /not reported by the pinned engine origin/i
    );
    // Capability observed on a different (stale) session cannot authorize this write
    assert.throws(
      () =>
        assertPinnedSecretWriteContext(
          { ...validPin, capabilitySessionToken: 'tok_other_session' },
          'http://127.0.0.1:3847'
        ),
      /active paired session/i
    );
    assert.equal(
      normalizeCapabilities({ features: { writeOnlySecrets: 'false' } }).features.writeOnlySecrets,
      false,
      'String "false" must never parse as an enabled capability'
    );
    assert.equal(
      normalizeCapabilities({ features: { writeOnlySecrets: 1 } }).features.writeOnlySecrets,
      false
    );
    assert.equal(
      normalizeCapabilities({ features: { writeOnlySecrets: true } }).features.writeOnlySecrets,
      true
    );
  } finally {
    await manager.shutdown().catch(() => {});
    await new Promise((r) => appServer.close(() => r()));
    await fs.rm(tmpDataDir, { recursive: true, force: true });
    await fs.rm(tmpDistDir, { recursive: true, force: true });
  }
});

test('Audit 11: Outbound secret leak guard across benchmark/probe/engine/torrent, default query+path redaction, and safe rejected paste tokens', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit11-data-'));
  const tmpDlDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit11-dl-'));
  const activeSecret = 'ACTIVE_PROVIDER_SECRET_XYZ987';
  let leakHits = 0;

  const mockSrv = await listenServer(
    http.createServer((req, res) => {
      const u = new URL(req.url, `http://127.0.0.1:${mockSrv.port}`);
      if (u.pathname === '/leak-dest') {
        leakHits++;
        res.writeHead(200);
        res.end('LEAKED');
        return;
      }
      if (u.pathname === '/redir-leak.bin' || u.pathname === '/redir-leak.torrent') {
        res.writeHead(302, {
          Location: `http://127.0.0.1:${mockSrv.port}/leak-dest?leaked=${activeSecret}`,
        });
        res.end();
        return;
      }
      if (u.pathname.startsWith('/ticket/')) {
        res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': 12 });
        res.end(req.method === 'HEAD' ? undefined : 'HELLO_WORLD!');
        return;
      }
      res.writeHead(404);
      res.end();
    })
  );

  const manager = new DownloadManager({ dataDir: tmpDataDir, allowInsecureLoopbackProvider: true });
  await manager.init();
  await manager.updateSettings({
    downloadDir: tmpDlDir,
    annasArchiveApiKey: activeSecret,
  });
  const appServer = createAppServer({ manager });
  await new Promise((r) => appServer.listen(0, '127.0.0.1', r));
  const baseUrl = `http://127.0.0.1:${appServer.address().port}`;
  const token = manager.getSessionToken();

  try {
    // 1. Outbound leak guard helper blocks active secret in query or path
    assert.throws(
      () => assertOutboundUrlSafe(`http://127.0.0.1:${mockSrv.port}/dl?k=${activeSecret}`, [activeSecret]),
      /active provider credential/i
    );

    // 2. benchmarkCandidates blocks initial secret URL AND 302 redirect containing secret
    const benchRes = await benchmarkCandidates(
      [
        {
          url: `http://127.0.0.1:${mockSrv.port}/leak-dest?k=${activeSecret}`,
          label: 'Direct Leak',
          tier: 'mirror',
          host: '127.0.0.1',
          priority: 50,
        },
        {
          url: `http://127.0.0.1:${mockSrv.port}/redir-leak.bin`,
          label: 'Redir Leak',
          tier: 'mirror',
          host: '127.0.0.1',
          priority: 50,
        },
      ],
      { secrets: [activeSecret] }
    );
    assert.equal(benchRes[0].ok, false);
    assert.equal(benchRes[1].ok, false);
    assert.equal(leakHits, 0);

    // 3. probeUrl blocks initial secret URL AND 302 redirect containing secret
    const probeDirect = await probeUrl(`http://127.0.0.1:${mockSrv.port}/leak-dest?k=${activeSecret}`, {
      trustRules: [],
      existingDownloads: [],
      secrets: [activeSecret],
    });
    assert.ok(probeDirect.probeError?.includes('active provider credential'));
    const probeRedir = await probeUrl(`http://127.0.0.1:${mockSrv.port}/redir-leak.bin`, {
      trustRules: [],
      existingDownloads: [],
      secrets: [activeSecret],
    });
    assert.ok(probeRedir.probeError?.includes('active provider credential'));
    assert.equal(leakHits, 0);

    // 4. DownloadRunner blocks initial secret URL AND 302 redirect containing secret
    const engItem = makeItem(`http://127.0.0.1:${mockSrv.port}/redir-leak.bin`, tmpDlDir, 'no-leak.bin', {
      totalBytes: 12,
      connections: 1,
      supportsRanges: false,
    });
    await new DownloadRunner({
      item: engItem,
      throttle: new TokenBucketThrottle(0),
      secrets: [activeSecret],
      maxRetries: 1,
      onUpdate: () => {},
    }).run();
    assert.equal(engItem.status, 'failed');
    assert.equal(leakHits, 0);

    // 5. .torrent metadata fetch (runP2PProbe) blocks 302 redirect carrying active secret
    const torInspect = await manager.inspectRawText(`http://127.0.0.1:${mockSrv.port}/redir-leak.torrent`);
    const torId = torInspect.items[0].id;
    const torReviewed = await waitFor(() => {
      const it = manager.getSnapshot().downloads.find((d) => d.id === torId);
      return it?.status === 'pending_review' ? it : null;
    });
    assert.ok(torReviewed.safety?.probeError?.includes('active provider credential'));
    assert.equal(leakHits, 0);

    // 6. Default query-param stripping & path-credential redaction (including derived filename/savedPath)
    const stripped = redactSensitiveUrl('https://cdn.example/ticket/PATH_SECRET_77/book.epub?custom_sig=UNLISTED_VAL&foo=BAR');
    assert.equal(stripped.includes('PATH_SECRET_77'), false);
    assert.equal(stripped.includes('UNLISTED_VAL'), false);
    assert.equal(stripped.includes('BAR'), false);

    const pathCredInsp = await manager.inspectRawText(`http://127.0.0.1:${mockSrv.port}/ticket/SECRET_FILENAME_88`);
    const pathCredId = pathCredInsp.items[0].id;
    assert.equal(JSON.stringify(pathCredInsp).includes('SECRET_FILENAME_88'), false);
    const pathCredDone = await waitFor(() => {
      const it = manager.getSnapshot().downloads.find((d) => d.id === pathCredId);
      return it?.status === 'pending_review' ? it : null;
    });
    assert.equal(JSON.stringify(pathCredDone).includes('SECRET_FILENAME_88'), false);

    // 7. Rejected paste tokens NEVER echo raw credentials in 400 or 200 API responses
    const rejRes = await fetch(`${baseUrl}/api/inspect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-BoltGate-Session': token },
      body: JSON.stringify({ text: 'ftp://alice:SUPER_FTP_PASS_99@host.example/file?key=RAW_REJECT_TOK' }),
    });
    assert.equal(rejRes.status, 400);
    const rejText = await rejRes.text();
    assert.equal(rejText.includes('SUPER_FTP_PASS_99'), false);
    assert.equal(rejText.includes('RAW_REJECT_TOK'), false);
  } finally {
    await manager.shutdown().catch(() => {});
    await new Promise((r) => appServer.close(() => r()));
    await mockSrv.close();
    await fs.rm(tmpDataDir, { recursive: true, force: true });
    await fs.rm(tmpDlDir, { recursive: true, force: true });
  }
});

test('Audit 12: Serialized SecretStore RMW, legacy vault-before-scrub upgrade, VaultCorruptionError preservation, encrypted .torrent manifests, history redownload, and private templates', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit12-data-'));
  const tmpDlDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit12-dl-'));
  const payload = makePayload(64 * 1024, 13);
  const signedParam = 'HISTORY_VAULT_SECRET_555';
  const trackerPasskey = 'ENCRYPTED_MANIFEST_PASSKEY_888';

  const bencode = (val) => {
    if (typeof val === 'number') return Buffer.from(`i${val}e`, 'ascii');
    if (Buffer.isBuffer(val)) return Buffer.concat([Buffer.from(`${val.length}:`, 'ascii'), val]);
    if (typeof val === 'string') {
      const b = Buffer.from(val, 'utf8');
      return Buffer.concat([Buffer.from(`${b.length}:`, 'ascii'), b]);
    }
    if (Array.isArray(val)) return Buffer.concat([Buffer.from('l'), ...val.map(bencode), Buffer.from('e')]);
    const keys = Object.keys(val).sort();
    const parts = [Buffer.from('d')];
    for (const k of keys) parts.push(bencode(k), bencode(val[k]));
    parts.push(Buffer.from('e'));
    return Buffer.concat(parts);
  };

  const privateTorrentBuf = bencode({
    announce: `https://tracker.private.example/announce?passkey=${trackerPasskey}`,
    info: {
      name: 'PrivateBook.epub',
      length: 4096,
      'piece length': 16384,
      pieces: Buffer.alloc(20, 0xab),
    },
  });

  const srv = await listenServer(
    http.createServer((req, res) => {
      const u = new URL(req.url, `http://127.0.0.1:${srv.port}`);
      if (u.pathname === '/vaulted-history.bin') {
        if (u.searchParams.get('sig') !== signedParam) {
          res.writeHead(403);
          res.end('invalid signature');
          return;
        }
        res.writeHead(200, {
          'Content-Length': payload.buf.length,
          'Accept-Ranges': 'bytes',
          'Content-Type': 'application/octet-stream',
        });
        res.end(req.method === 'HEAD' ? undefined : payload.buf);
        return;
      }
      if (u.pathname === '/private.torrent') {
        res.writeHead(200, { 'Content-Type': 'application/x-bittorrent', 'Content-Length': privateTorrentBuf.length });
        res.end(privateTorrentBuf);
        return;
      }
      res.writeHead(404);
      res.end();
    })
  );

  try {
    // 1. Concurrent SecretStore read-modify-write preserves ALL parallel writes without clobbering
    const rmwDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit12-rmw-'));
    try {
      const store = new SecretStore(rmwDir);
      await Promise.all([
        store.setAnnasArchiveApiKey('CONCURRENT_KEY_77'),
        store.setPrivateTemplates({ customMirrorUrls: ['https://m.example/{md5}?tok=TMPL_CONC'] }),
        ...Array.from({ length: 12 }, (_, idx) =>
          store.setOperationalSource(`job-${idx}`, {
            originalUrl: `https://cdn.example/${idx}?sig=S${idx}`,
            finalUrl: `https://cdn.example/${idx}?sig=S${idx}`,
          })
        ),
      ]);
      const freshStore = new SecretStore(rmwDir);
      assert.equal(await freshStore.getAnnasArchiveApiKey(), 'CONCURRENT_KEY_77');
      const tmpl = await freshStore.getPrivateTemplates();
      assert.deepEqual(tmpl.customMirrorUrls, ['https://m.example/{md5}?tok=TMPL_CONC']);
      const sources = await freshStore.getOperationalSources();
      assert.equal(Object.keys(sources).length, 12);
      assert.equal(sources['job-11'].originalUrl, 'https://cdn.example/11?sig=S11');
    } finally {
      await fs.rm(rmwDir, { recursive: true, force: true });
    }

    // 2. Legacy state.json upgrade vaults job URLs & private templates BEFORE rewriting state.json redacted
    const legacyJobId = 'legacy-completed-job-1';
    const legacySignedUrl = `http://127.0.0.1:${srv.port}/vaulted-history.bin?sig=${signedParam}`;
    const privateTemplate = `https://user:pass@private-mirror.example/{md5}?key=PRIV_TMPL_44`;
    await fs.writeFile(
      path.join(tmpDataDir, 'state.json'),
      JSON.stringify({
        version: 1,
        trustRules: [],
        settings: {
          ...getDefaultSettings(),
          downloadDir: tmpDlDir,
          customMirrorUrls: [privateTemplate],
        },
        downloads: [
          {
            ...makeItem(legacySignedUrl, tmpDlDir, 'vaulted-history.bin', {
              id: legacyJobId,
              totalBytes: payload.buf.length,
            }),
            status: 'completed',
            completedAt: Date.now() - 1000,
          },
        ],
      }),
      'utf8'
    );

    const manager = new DownloadManager({ dataDir: tmpDataDir });
    await manager.init();

    // state.json must now be scrubbed of legacy secrets
    const scrubbedState = await fs.readFile(path.join(tmpDataDir, 'state.json'), 'utf8');
    assert.equal(scrubbedState.includes(signedParam), false);
    assert.equal(scrubbedState.includes('PRIV_TMPL_44'), false);

    // Public snapshot shows masked URL, yet POST /api/downloads/:id/redownload uses vaulted real signed URL!
    const snapJob = manager.getSnapshot().downloads.find((d) => d.id === legacyJobId);
    assert.ok(snapJob.originalUrl.includes('***'));
    const appServer = createAppServer({ manager });
    await new Promise((r) => appServer.listen(0, '127.0.0.1', r));
    const baseUrl = `http://127.0.0.1:${appServer.address().port}`;
    const token = manager.getSessionToken();

    try {
      const redlRes = await fetch(`${baseUrl}/api/downloads/${legacyJobId}/redownload`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-BoltGate-Session': token },
        body: JSON.stringify({}),
      });
      assert.equal(redlRes.status, 200);
      const redlJson = await redlRes.json();
      const newId = redlJson.items[0].id;
      const probedRedl = await waitFor(() => {
        const d = manager.getSnapshot().downloads.find((x) => x.id === newId);
        return d?.status === 'pending_review' ? d : null;
      });
      assert.equal(probedRedl.safety?.statusCode, 200, 'Re-download must authenticate using vaulted signed URL');
      assert.equal(probedRedl.totalBytes, payload.buf.length);

      // Updating settings while echoing back unchanged masked template preserves vaulted private template!
      const maskedTmpl = manager.getSnapshot().settings.customMirrorUrls[0];
      assert.ok(maskedTmpl.includes('***'));
      await manager.updateSettings({ customMirrorUrls: [maskedTmpl] });
      const storedTemplates = await manager.secretStore.getPrivateTemplates();
      assert.equal(storedTemplates.customMirrorUrls?.[0], privateTemplate);

      // 3. Encrypted .torrent manifests at rest: passkey never appears in plaintext on disk
      const torRes = await manager.inspectRawText(`http://127.0.0.1:${srv.port}/private.torrent`);
      const torId = torRes.items[0].id;
      await waitFor(() => {
        const d = manager.getSnapshot().downloads.find((x) => x.id === torId);
        return d?.status === 'pending_review' ? d : null;
      });
      const manifestsDir = path.join(tmpDataDir, 'manifests');
      const manifestFiles = await fs.readdir(manifestsDir);
      const encFile = manifestFiles.find((f) => f.endsWith('.torrent.enc'));
      assert.ok(encFile, 'Expected encrypted .torrent.enc manifest on disk');
      const rawEncDisk = await fs.readFile(path.join(manifestsDir, encFile), 'utf8');
      assert.equal(rawEncDisk.includes(trackerPasskey), false);
      assert.equal(rawEncDisk.includes('tracker.private.example'), false);
      const decrypted = await manager.secretStore.readEncryptedManifest(path.join(manifestsDir, encFile));
      assert.equal(Buffer.compare(decrypted, privateTorrentBuf), 0);
    } finally {
      await manager.shutdown().catch(() => {});
      await new Promise((r) => appServer.close(() => r()));
    }

    // 4. Unreadable/corrupted secrets.enc.json throws VaultCorruptionError AND preserves file untouched
    const corruptDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit12-corrupt-'));
    try {
      const corruptBytes = JSON.stringify({ v: 1, iv: '00'.repeat(12), tag: '11'.repeat(16), ciphertext: 'deadbeef' });
      await fs.writeFile(path.join(corruptDir, 'secrets.enc.json'), corruptBytes, 'utf8');
      const corruptMgr = new DownloadManager({ dataDir: corruptDir });
      await assert.rejects(corruptMgr.init(), (err) => err instanceof VaultCorruptionError);
      // Original corrupted vault file must remain preserved verbatim (never overwritten!)
      assert.equal(await fs.readFile(path.join(corruptDir, 'secrets.enc.json'), 'utf8'), corruptBytes);
    } finally {
      await fs.rm(corruptDir, { recursive: true, force: true });
    }
  } finally {
    await srv.close();
    await fs.rm(tmpDataDir, { recursive: true, force: true });
    await fs.rm(tmpDlDir, { recursive: true, force: true });
  }
});

test('Audit 13: Equal-ETag independent mirrors blocked, validatorless changed resume blocked, trailing 206 bytes invalidated, EPERM sidecar isolation, cancel before staging, post-Undo runner race, approval freeze, verifyHash live swap, and concurrent Retry-After extension', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit13-data-'));
  const tmpDlDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit13-dl-'));
  const payloadA = makePayload(256 * 1024, 1);
  const payloadB = makePayload(256 * 1024, 55);
  let serveSwapped = false;
  let epermRetryAttempt = 0;

  // Two independent hosts (different ports) serving DIFFERENT bytes with IDENTICAL strong ETag "same-v1"!
  const makeMirrorServer = (buf) =>
    listenServer(
      http.createServer((req, res) => {
        if (req.method === 'HEAD') {
          res.writeHead(200, {
            'Content-Length': buf.length,
            'Accept-Ranges': 'bytes',
            ETag: '"same-v1"',
            'Content-Type': 'application/octet-stream',
          });
          res.end();
          return;
        }
        const range = req.headers.range ?? 'bytes=0-';
        const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
        const start = Number(s);
        const end = e ? Number(e) : buf.length - 1;
        const slice = buf.subarray(start, end + 1);
        res.writeHead(206, {
          'Content-Range': `bytes ${start}-${end}/${buf.length}`,
          'Content-Length': slice.length,
          'Accept-Ranges': 'bytes',
          ETag: '"same-v1"',
        });
        res.end(slice);
      })
    );

  const mirror1 = await makeMirrorServer(payloadA.buf);
  const mirror2 = await makeMirrorServer(payloadB.buf);

  const edgeSrv = await listenServer(
    http.createServer(async (req, res) => {
      if (req.url === '/validatorless.bin') {
        const active = serveSwapped ? payloadB.buf : payloadA.buf;
        const range = req.headers.range ?? 'bytes=0-';
        const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
        const start = Number(s);
        const end = e ? Number(e) : active.length - 1;
        const slice = active.subarray(start, end + 1);
        // Deliberately NO ETag and NO Last-Modified!
        res.writeHead(206, {
          'Content-Range': `bytes ${start}-${end}/${active.length}`,
          'Content-Length': slice.length,
          'Accept-Ranges': 'bytes',
        });
        if (!serveSwapped) {
          for (let pos = 0; pos < slice.length && !res.destroyed; pos += 16384) {
            res.write(slice.subarray(pos, Math.min(slice.length, pos + 16384)));
            await new Promise((r) => setTimeout(r, 80));
          }
          if (!res.destroyed) res.end();
          return;
        }
        res.end(slice);
        return;
      }

      if (req.url === '/trailing-206.bin') {
        // Chunked 206 response (no Content-Length) that sends 16 trailing bytes past exact range end!
        const range = req.headers.range ?? 'bytes=0-131071';
        const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
        const start = Number(s);
        const end = e ? Number(e) : payloadA.buf.length - 1;
        const slice = payloadA.buf.subarray(start, end + 1);
        res.writeHead(206, {
          'Content-Range': `bytes ${start}-${end}/${payloadA.buf.length}`,
          'Accept-Ranges': 'bytes',
        });
        res.write(slice);
        res.end(Buffer.alloc(16, 0xff));
        return;
      }

      if (req.url === '/eperm-reset.bin') {
        epermRetryAttempt++;
        res.writeHead(200, { 'Content-Length': payloadA.buf.length, 'Accept-Ranges': 'none' });
        if (epermRetryAttempt === 1) {
          res.write(payloadA.buf.subarray(0, 32768));
          setTimeout(() => res.destroy(), 20);
          return;
        }
        res.end(payloadA.buf);
        return;
      }

      if (req.url === '/ok-static.bin') {
        res.writeHead(200, { 'Content-Length': payloadA.buf.length, 'Accept-Ranges': 'none' });
        res.end(req.method === 'HEAD' ? undefined : payloadA.buf);
        return;
      }

      res.writeHead(404);
      res.end();
    })
  );

  let duringVerifyHook = null;
  const manager = new DownloadManager({
    dataDir: tmpDataDir,
    testHooks: {
      onDuringVerifyHash: async () => {
        if (duringVerifyHook) await duringVerifyHook();
      },
    },
  });
  await manager.init();
  await manager.updateSettings({ downloadDir: tmpDlDir });

  try {
    // 1. Independent mirrors with EQUAL strong ETag "same-v1" MUST NOT be combined without a trusted digest
    const mirRes = await manager.inspectMirrorGroup(
      `http://127.0.0.1:${mirror1.port}/same.bin\nhttp://127.0.0.1:${mirror2.port}/same.bin`
    );
    const mirId = mirRes.items[0].id;
    const mirReviewed = await waitFor(() => {
      const d = manager.getSnapshot().downloads.find((x) => x.id === mirId);
      return d?.status === 'pending_review' ? d : null;
    });
    assert.equal(mirReviewed.mirrorUrls.length, 1, 'Independent mirrors must not stripe without digest even when ETags match');
    assert.equal(mirReviewed.sourceMode, 'direct');

    // 2. Validatorless source that changes while paused MUST NOT resume old unverified .part.meta bytes
    const valLessItem = makeItem(
      `http://127.0.0.1:${edgeSrv.port}/validatorless.bin`,
      tmpDlDir,
      'validatorless.bin',
      { totalBytes: payloadA.buf.length, connections: 2, supportsRanges: true }
    );
    const rPause = new DownloadRunner({
      item: valLessItem,
      throttle: new TokenBucketThrottle(0),
      minSegmentBytes: 128 * 1024,
      onUpdate: () => {},
    });
    const runP = rPause.run();
    await new Promise((r) => setTimeout(r, 180));
    await rPause.pause();
    await runP;
    assert.equal(valLessItem.status, 'paused');
    assert.ok(valLessItem.downloadedBytes > 0);

    // Upstream swaps file content while paused!
    serveSwapped = true;
    await new DownloadRunner({
      item: valLessItem,
      throttle: new TokenBucketThrottle(0),
      minSegmentBytes: 128 * 1024,
      onUpdate: () => {},
    }).run();
    assert.equal(valLessItem.status, 'completed');
    assert.equal(
      valLessItem.sha256,
      payloadB.sha256,
      'Validatorless source must restart cleanly from offset 0 rather than mixing stale bytes'
    );

    // 3. Trailing bytes after exact 206 span invalidate attempt extents and fail download
    const trailingItem = makeItem(
      `http://127.0.0.1:${edgeSrv.port}/trailing-206.bin`,
      tmpDlDir,
      'trailing.bin',
      { totalBytes: payloadA.buf.length, connections: 2, supportsRanges: true }
    );
    await new DownloadRunner({
      item: trailingItem,
      throttle: new TokenBucketThrottle(0),
      minSegmentBytes: 128 * 1024,
      maxRetries: 1,
      onUpdate: () => {},
    }).run();
    assert.equal(trailingItem.status, 'failed');
    assert.ok(trailingItem.error?.includes('exceeded') || trailingItem.error?.includes('overflow') || trailingItem.error?.includes('mismatched'));

    // 4. Non-ENOENT sidecar unlink failure (EPERM) isolates onto a fresh staging file without truncating old .part
    const epermItem = makeItem(
      `http://127.0.0.1:${edgeSrv.port}/eperm-reset.bin`,
      tmpDlDir,
      'eperm-reset.bin',
      { totalBytes: payloadA.buf.length, connections: 1, supportsRanges: false }
    );
    let oldPartPathCaptured = '';
    await new DownloadRunner({
      item: epermItem,
      throttle: new TokenBucketThrottle(0),
      fileHooks: {
        removeMetaFn: async (partPath) => {
          if (!oldPartPathCaptured) {
            oldPartPathCaptured = partPath;
            throw Object.assign(new Error('EPERM: sidecar locked'), { code: 'EPERM' });
          }
          await fs.unlink(`${partPath}.meta`).catch(() => undefined);
        },
      },
      onUpdate: () => {},
    }).run();
    assert.equal(epermItem.status, 'completed');
    assert.equal(epermItem.sha256, payloadA.sha256);
    assert.ok(oldPartPathCaptured);
    assert.notEqual(epermItem.partPath, oldPartPathCaptured, 'Must allocate fresh staging file when old sidecar unlink fails with EPERM');
    const oldPartStat = await fs.stat(oldPartPathCaptured);
    assert.ok(oldPartStat.size > 0, 'Old .part file must NOT be truncated underneath locked sidecar');

    // 5. Native DownloadRunner.cancel(true) during beforeReserveStaging awaits full lifecycle & leaves zero stray staging
    let releaseReserve;
    const cancelPreItem = makeItem(
      `http://127.0.0.1:${edgeSrv.port}/ok-static.bin`,
      tmpDlDir,
      'cancel-pre.bin',
      { totalBytes: payloadA.buf.length, connections: 1, supportsRanges: false }
    );
    const cancelRunner = new DownloadRunner({
      item: cancelPreItem,
      throttle: new TokenBucketThrottle(0),
      fileHooks: {
        beforeReserveStaging: () =>
          new Promise((r) => {
            releaseReserve = r;
          }),
      },
      onUpdate: () => {},
    });
    const preRunP = cancelRunner.run();
    await waitFor(() => Boolean(releaseReserve));
    const cancelP = cancelRunner.cancel(true);
    releaseReserve();
    await Promise.all([cancelP, preRunP]);
    assert.equal(cancelPreItem.partPath, '', 'No staging file should remain after cancel before reservation');

    // 6. Post-Undo runner race: old runner's finally must NOT clear a newer runner registered for same id
    const raceItem = makeItem(`http://127.0.0.1:${edgeSrv.port}/ok-static.bin`, tmpDlDir, 'undo-race.bin', {
      totalBytes: payloadA.buf.length,
    });
    manager['downloads'].unshift(raceItem);
    const replacementRunner = { item: raceItem, run: async () => {}, pause: async () => {}, cancel: async () => {} };
    manager['runners'].set(raceItem.id, replacementRunner);
    // Simulate stale runner completing and running the guarded cleanup check
    const staleRunner = { item: raceItem, run: async () => {}, pause: async () => {}, cancel: async () => {} };
    if (manager['runners'].get(raceItem.id) === staleRunner) {
      manager['runners'].delete(raceItem.id);
    }
    assert.equal(manager['runners'].get(raceItem.id), replacementRunner);
    manager['runners'].delete(raceItem.id);

    // 7. Approval inputs are frozen while downloading/verifying (409 rejection)
    raceItem.status = 'verifying';
    await assert.rejects(
      manager.approveDownload(raceItem.id, { expectedSha256: payloadA.sha256 }),
      (err) => err?.status === 409
    );

    // 8. Live-file replacement during verifyHash is detected via open-handle + inode/stat check
    const verifyInsp = await manager.inspectRawText(`http://127.0.0.1:${edgeSrv.port}/ok-static.bin`);
    const verifyId = verifyInsp.items[0].id;
    await waitFor(() => manager.getSnapshot().downloads.find((d) => d.id === verifyId)?.status === 'pending_review');
    await manager.approveDownload(verifyId, { startNow: true });
    const doneVerify = await waitFor(() => {
      const d = manager.getSnapshot().downloads.find((x) => x.id === verifyId);
      return d?.status === 'completed' ? d : null;
    });

    duringVerifyHook = async () => {
      // Mutate live savedPath while verifyHash is in progress
      await fs.writeFile(doneVerify.savedPath, Buffer.concat([payloadA.buf, Buffer.from('SWAP_EXTRA')]));
    };
    await assert.rejects(
      manager.verifyHash(verifyId, payloadA.sha256),
      /changed during checksum verification/i
    );
    duringVerifyHook = null;
    assert.equal(
      manager.getSnapshot().downloads.find((x) => x.id === verifyId)?.verifiedHashMatch,
      undefined,
      'Badges must not be updated when live file changed mid-verification'
    );

    // 9. Concurrent Retry-After extension: sleeping worker re-checks extended deadline before dispatching
    const rl = new OriginRateLimiter();
    const targetUrl = `http://127.0.0.1:${edgeSrv.port}/ok-static.bin`;
    // Seed initial 250ms cooldown, start waiter, then extend via second recordRateLimit('1')
    const originKey = new URL(targetUrl).origin.toLowerCase();
    rl['origins'].set(originKey, {
      origin: originKey,
      cooldownUntil: Date.now() + 250,
      consecutiveRateLimits: 1,
      maxWorkersCap: 2,
    });
    const tStart = Date.now();
    const waitPromise = (async () => {
      while (true) {
        const rem = rl.getCooldownRemainingMs(targetUrl);
        if (rem <= 0) break;
        await new Promise((r) => setTimeout(r, rem));
      }
      return Date.now() - tStart;
    })();
    await new Promise((r) => setTimeout(r, 80));
    rl.recordRateLimit(targetUrl, 429, '1', 4); // extends to >= +1000ms from now
    const waitedMs = await waitPromise;
    assert.ok(waitedMs >= 950, `Expected waiter to re-check extended Retry-After (>= ~1000ms), waited ${waitedMs}ms`);
  } finally {
    await manager.shutdown().catch(() => {});
    await mirror1.close();
    await mirror2.close();
    await edgeSrv.close();
    await fs.rm(tmpDataDir, { recursive: true, force: true });
    await fs.rm(tmpDlDir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Audit 14 (Codex review round 14) helpers
// ---------------------------------------------------------------------------

function bencodeValue(val) {
  if (typeof val === 'number') return Buffer.from(`i${val}e`, 'ascii');
  if (Buffer.isBuffer(val)) return Buffer.concat([Buffer.from(`${val.length}:`, 'ascii'), val]);
  if (typeof val === 'string') {
    const b = Buffer.from(val, 'utf8');
    return Buffer.concat([Buffer.from(`${b.length}:`, 'ascii'), b]);
  }
  if (Array.isArray(val)) return Buffer.concat([Buffer.from('l'), ...val.map(bencodeValue), Buffer.from('e')]);
  const keys = Object.keys(val).sort();
  const parts = [Buffer.from('d')];
  for (const k of keys) parts.push(bencodeValue(k), bencodeValue(val[k]));
  parts.push(Buffer.from('e'));
  return Buffer.concat(parts);
}

/** Raw HTTP/1.1 request with EXACT headers (fetch() would inject Sec-Fetch-* on its own). */
function rawRequest(port, { method = 'GET', reqPath = '/', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => {
      const lines = [`${method} ${reqPath} HTTP/1.1`, `Host: ${headers.Host ?? `127.0.0.1:${port}`}`];
      for (const [k, v] of Object.entries(headers)) {
        if (k === 'Host') continue;
        lines.push(`${k}: ${v}`);
      }
      lines.push('Connection: close', '', '');
      sock.write(lines.join('\r\n'));
    });
    const chunks = [];
    sock.on('data', (c) => chunks.push(c));
    sock.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      const status = Number(text.match(/^HTTP\/1\.1 (\d{3})/)?.[1] ?? 0);
      const body = text.slice(text.indexOf('\r\n\r\n') + 4);
      resolve({ status, body });
    });
    sock.on('error', reject);
  });
}

async function writeMockAria2(dir, name, source) {
  const p = path.join(dir, name);
  await fs.writeFile(p, source, 'utf8');
  return p;
}

test('Audit 14A: strict capability parsing, origin+session pinned secret/bulk writes, stable template identities, missing Sec-Fetch headers, non-loopback bind/Host rejection, generic unknown-route errors, IPv6 [::1] formatting', async () => {
  // --- IPv6 loopback formatting & loopback-only binding ---
  assert.equal(formatLoopbackOrigin('::1', 3847), 'http://[::1]:3847');
  assert.equal(formatLoopbackOrigin('[::1]', 3847), 'http://[::1]:3847');
  assert.equal(formatLoopbackOrigin('127.0.0.1', 3847), 'http://127.0.0.1:3847');
  assert.equal(formatLoopbackOrigin('localhost', '3847'), 'http://localhost:3847');
  assert.equal(validateLoopbackOrigin(formatLoopbackOrigin('::1', 3847)), 'http://[::1]:3847');
  assert.equal(assertLoopbackBindHost('[::1]'), '::1');
  for (const bad of ['0.0.0.0', '::', '[::]', '192.168.1.20', '10.0.0.5', 'example.com', '127.0.0.1.nip.io', '::ffff:10.0.0.1']) {
    assert.throws(() => assertLoopbackBindHost(bad), /non-loopback/i, `bind host ${bad} must be rejected`);
  }

  // --- Two-tab engine switching during BULK APPROVAL: rows are pinned to their engine ---
  const binding = { origin: 'http://127.0.0.1:3847', sessionToken: 'tok_tab_a' };
  assert.deepEqual(assertPinnedEngineBinding(binding, 'http://127.0.0.1:3847'), {
    engineOrigin: 'http://127.0.0.1:3847',
    sessionToken: 'tok_tab_a',
  });
  assert.throws(() => assertPinnedEngineBinding(binding, 'http://127.0.0.1:3848'), /changed in another tab/i);
  assert.throws(() => assertPinnedEngineBinding({ ...binding, origin: 'https://evil.example' }, 'http://127.0.0.1:3847'), /loopback/i);
  assert.throws(() => assertPinnedEngineBinding({ ...binding, sessionToken: '' }, 'http://127.0.0.1:3847'), /session/i);

  // Each row's own edits travel with it (never dropped for defaults)
  const sha = 'a'.repeat(64);
  assert.deepEqual(
    buildBulkApprovalEntries(['r1', 'r2', 'r3'], {
      expectedSha256: { r1: sha },
      selectFiles: { r2: '2,3' },
      names: { r3: 'renamed.pdf', r1: '   ' },
      connections: { r3: 2 },
      engines: { r2: 'aria2' },
    }),
    [
      { id: 'r1', expectedSha256: sha },
      { id: 'r2', selectFile: '2,3', engine: 'aria2' },
      { id: 'r3', filename: 'renamed.pdf', connections: 2 },
    ]
  );

  // --- Stable template identity on the client: identical masks map to DISTINCT identities ---
  const display = ['https://m.example/{md5}?key=***', 'https://m.example/{md5}?key=***', 'https://open.example/{md5}'];
  const ids = ['tpl_one', 'tpl_two', 'tpl_three'];
  assert.deepEqual(buildTemplatePatchEntries(display, display, ids), [
    { ref: 'tpl_one' },
    { ref: 'tpl_two' },
    'https://open.example/{md5}',
  ]);
  // Adjacent plaintext edit keeps both masked identities intact and distinct
  assert.deepEqual(
    buildTemplatePatchEntries([display[0], display[1], 'https://edited.example/{md5}'], display, ids),
    [{ ref: 'tpl_one' }, { ref: 'tpl_two' }, 'https://edited.example/{md5}']
  );

  // --- Server-side stable identities: masked strings are never resolved by display text ---
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit14a-data-'));
  const tmpDistDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit14a-dist-'));
  await fs.writeFile(path.join(tmpDistDir, 'index.html'), '<html><head><title>BG</title></head><body></body></html>');
  const manager = new DownloadManager({ dataDir: tmpDataDir });
  await manager.init();
  const appServer = createAppServer({ manager, distDir: tmpDistDir });
  await new Promise((r) => appServer.listen(0, '127.0.0.1', r));
  const port = appServer.address().port;
  const token = manager.getSessionToken();
  try {
    const K1 = 'https://m.example/{md5}?key=TEMPLATE_KEY_ONE_111';
    const K2 = 'https://m.example/{md5}?key=TEMPLATE_KEY_TWO_222';
    await manager.updateSettings({ customMirrorUrls: [K1, K2] });
    let settings = manager.getSnapshot().settings;
    assert.equal(settings.customMirrorUrls[0], settings.customMirrorUrls[1], 'Both templates mask identically');
    const refs = settings.templateRefs.customMirrorUrls;
    assert.equal(refs.length, 2);
    assert.notEqual(refs[0], refs[1], 'Identical masks must still carry distinct stable identities');
    assert.equal(JSON.stringify(settings).includes('TEMPLATE_KEY'), false);

    // Saving unchanged (refs) preserves both credentials in place
    await manager.updateSettings({
      customMirrorUrls: buildTemplatePatchEntries(settings.customMirrorUrls, settings.customMirrorUrls, refs),
    });
    assert.deepEqual((await manager.secretStore.getPrivateTemplates()).customMirrorUrls, [K1, K2]);

    // Reordering by identity never swaps credentials across entries
    await manager.updateSettings({ customMirrorUrls: [{ ref: refs[1] }, { ref: refs[0] }] });
    assert.deepEqual((await manager.secretStore.getPrivateTemplates()).customMirrorUrls, [K2, K1]);

    // Legacy masked string (no ref) that matches TWO credentials is ambiguous -> 409, vault untouched
    settings = manager.getSnapshot().settings;
    await assert.rejects(
      manager.updateSettings({ customMirrorUrls: [settings.customMirrorUrls[0]] }),
      (err) => err?.status === 409 && /ambiguous/i.test(err.message)
    );
    assert.deepEqual((await manager.secretStore.getPrivateTemplates()).customMirrorUrls, [K2, K1]);
    // Stale / foreign ref -> 409, vault untouched
    await assert.rejects(
      manager.updateSettings({ customMirrorUrls: [{ ref: 'tpl_not_a_real_identity' }] }),
      (err) => err?.status === 409
    );
    assert.deepEqual((await manager.secretStore.getPrivateTemplates()).customMirrorUrls, [K2, K1]);
    // templateRefs are process-local handles: never persisted to state.json
    await manager.store.flush();
    const disk = await fs.readFile(path.join(tmpDataDir, 'state.json'), 'utf8');
    assert.equal(disk.includes('templateRefs'), false);
    assert.equal(disk.includes('TEMPLATE_KEY'), false);

    // --- Missing / partial Sec-Fetch-* metadata NEVER receives a redeemable pairing code ---
    const pairingMeta = /boltgate-pairing-code/;
    const noMeta = await rawRequest(port, { reqPath: '/' });
    assert.equal(noMeta.status, 200);
    assert.equal(pairingMeta.test(noMeta.body), false, 'No Sec-Fetch headers -> no pairing code');
    const modeOnly = await rawRequest(port, { reqPath: '/', headers: { 'Sec-Fetch-Mode': 'navigate' } });
    assert.equal(pairingMeta.test(modeOnly.body), false, 'Sec-Fetch-Mode without Sec-Fetch-Site -> no pairing code');
    const siteOnly = await rawRequest(port, { reqPath: '/', headers: { 'Sec-Fetch-Site': 'same-origin' } });
    assert.equal(pairingMeta.test(siteOnly.body), false, 'Sec-Fetch-Site without Sec-Fetch-Mode -> no pairing code');
    const corsMode = await rawRequest(port, {
      reqPath: '/',
      headers: { 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Site': 'same-origin' },
    });
    assert.equal(pairingMeta.test(corsMode.body), false, 'Non-navigation fetch -> no pairing code');
    const crossSite = await rawRequest(port, {
      reqPath: '/',
      headers: { 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Site': 'cross-site' },
    });
    assert.equal(crossSite.status, 403);
    const realNav = await rawRequest(port, {
      reqPath: '/',
      headers: { 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Site': 'none' },
    });
    assert.equal(pairingMeta.test(realNav.body), true, 'Genuine top-level navigation gets the pairing code');

    // --- Non-loopback Host headers are rejected; bracketed IPv6 loopback Host is accepted ---
    for (const evilHost of ['evil.example', `evil.example:${port}`, `127.0.0.1.evil.example:${port}`, `localhost.attacker.test:${port}`]) {
      const r = await rawRequest(port, { reqPath: '/api/health', headers: { Host: evilHost } });
      assert.equal(r.status, 403, `Host ${evilHost} must be rejected`);
    }
    const v6Host = await rawRequest(port, { reqPath: '/api/health', headers: { Host: `[::1]:${port}` } });
    assert.equal(v6Host.status, 200);

    // --- Unknown API routes never echo the raw request pathname ---
    const unknown = await rawRequest(port, {
      reqPath: '/api/not-a-route/PATHNAME_SECRET_TOKEN_9?sig=QUERY_SECRET_4',
      headers: { 'X-BoltGate-Session': token },
    });
    assert.equal(unknown.status, 404);
    assert.equal(unknown.body.includes('PATHNAME_SECRET_TOKEN_9'), false);
    assert.equal(unknown.body.includes('QUERY_SECRET_4'), false);
    assert.equal(unknown.body.includes('not-a-route'), false);
    const unknownDl = await rawRequest(port, {
      method: 'POST',
      reqPath: '/api/downloads/some-id/LEAKY_ACTION_SEGMENT',
      headers: { 'X-BoltGate-Session': token, 'Content-Length': '0' },
    });
    assert.equal(unknownDl.status, 404);
    assert.equal(unknownDl.body.includes('LEAKY_ACTION_SEGMENT'), false);
  } finally {
    await manager.shutdown().catch(() => {});
    await new Promise((r) => appServer.close(() => r()));
    await fs.rm(tmpDataDir, { recursive: true, force: true });
    await fs.rm(tmpDistDir, { recursive: true, force: true });
  }
});

test('Audit 14B: outbound guard uses the LIVE secret set at dispatch and blocks credential-bearing redirects across benchmark/inspection/transfer/torrent paths, embedded tracker & web-seed destinations, and hides private-tracker path passkeys', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit14b-'));
  const dlDir = path.join(tmpDir, 'dl');
  await fs.mkdir(dlDir, { recursive: true });
  const SECRET = 'LIVE_PROVIDER_KEY_14B_ALPHA';
  const ROTATED = 'ROTATED_PROVIDER_KEY_14B_BETA';
  const payload = makePayload(96 * 1024, 41);
  let leakHits = 0;
  const leakSrv = await listenServer(
    http.createServer((req, res) => {
      leakHits += 1;
      res.writeHead(200, { 'Content-Length': payload.buf.length });
      res.end(payload.buf);
    })
  );
  const leakBase = `http://127.0.0.1:${leakSrv.port}`;
  const srv = await listenServer(
    http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x');
      if (u.pathname === '/redir-query-leak') {
        res.writeHead(302, { Location: `${leakBase}/collect?k=${SECRET}` });
        res.end();
        return;
      }
      if (u.pathname === '/redir-rotated-leak') {
        res.writeHead(302, { Location: `${leakBase}/collect/${encodeURIComponent(ROTATED)}/file.bin` });
        res.end();
        return;
      }
      if (u.pathname === '/leaky.torrent') {
        res.writeHead(302, { Location: `${leakBase}/t.torrent?passkey=${SECRET}` });
        res.end();
        return;
      }
      if (u.pathname === '/etag-echo.bin') {
        res.writeHead(200, {
          'Content-Length': payload.buf.length,
          'Accept-Ranges': 'bytes',
          ETag: `"v-${SECRET}"`,
          'Content-Disposition': `attachment; filename="report-${SECRET}.pdf"`,
        });
        res.end(req.method === 'HEAD' ? undefined : payload.buf);
        return;
      }
      res.writeHead(404);
      res.end();
    })
  );
  const base = `http://127.0.0.1:${srv.port}`;

  try {
    // 1. Inspection (probeUrl) blocks the credential-bearing redirect hop
    const report = await probeUrl(`${base}/redir-query-leak`, {
      trustRules: [],
      existingDownloads: [],
      secrets: [SECRET],
    });
    assert.ok(report.probeError?.includes('Blocked outbound'), `probe must be blocked, got ${report.probeError}`);

    // 2. Benchmark path blocks it too
    const bench = await benchmarkCandidates(
      [{ url: `${base}/redir-query-leak`, label: 'leak', tier: 'mirror', host: '127.0.0.1', priority: 1 }],
      { concurrency: 1, secrets: [SECRET] }
    );
    assert.equal(bench[0].ok, false);
    assert.ok(bench[0].error?.includes('Blocked outbound'));

    // 3. Transfer path: a runner constructed BEFORE key rotation still enforces the LIVE secret set
    const liveSecrets = [SECRET];
    const rotItem = makeItem(`${base}/redir-rotated-leak`, dlDir, 'rotated.bin', {
      totalBytes: payload.buf.length,
      supportsRanges: false,
      connections: 1,
    });
    const rotRunner = new DownloadRunner({
      item: rotItem,
      throttle: new TokenBucketThrottle(0),
      secretsProvider: () => liveSecrets,
      maxRetries: 0,
      onUpdate: () => {},
    });
    liveSecrets.push(ROTATED); // key rotation AFTER the runner exists
    await rotRunner.run();
    assert.equal(rotItem.status, 'failed');
    assert.ok(rotItem.error?.includes('Blocked outbound'), `transfer must be blocked, got ${rotItem.error}`);

    // 4. Manager: the live secret array is refreshed IN PLACE on key rotation (runners hold it)
    const dataDir = path.join(tmpDir, 'data');
    const manager = new DownloadManager({ dataDir });
    await manager.init();
    await manager.updateSettings({ downloadDir: dlDir });
    try {
      const liveRef = manager.getActiveSecrets();
      await manager.updateSettings({ annasArchiveApiKey: SECRET });
      assert.equal(manager.getActiveSecrets(), liveRef, 'Secret set must be the same live array');
      assert.ok(liveRef.includes(SECRET));
      await manager.updateSettings({ annasArchiveApiKey: ROTATED });
      assert.ok(liveRef.includes(ROTATED), 'Rotated key is visible to existing holders');
      assert.ok(liveRef.includes(SECRET), 'Retired key stays guarded (it may still be valid upstream)');

      // 5. Torrent metadata fetch path blocks the credential-bearing redirect
      const torRes = await manager.inspectRawText(`${base}/leaky.torrent`);
      const torItem = await waitFor(() => {
        const d = manager.getSnapshot().downloads.find((x) => x.id === torRes.items[0].id);
        return d?.status === 'pending_review' ? d : null;
      });
      assert.ok(torItem.safety.probeError?.includes('Blocked outbound'));

      // 6. Derived fields & upstream validators never expose an echoed credential
      const echoRes = await manager.inspectRawText(`${base}/etag-echo.bin`);
      const echoItem = await waitFor(() => {
        const d = manager.getSnapshot().downloads.find((x) => x.id === echoRes.items[0].id);
        return d?.status === 'pending_review' ? d : null;
      });
      const exported = JSON.stringify(echoItem);
      assert.equal(exported.includes(SECRET), false, 'filename/savedPath/etag/suggestedFilename must be sanitized');
      assert.equal(echoItem.etag, '***');
      await manager.store.flush();
      assert.equal((await fs.readFile(path.join(dataDir, 'state.json'), 'utf8')).includes(SECRET), false);
      assert.equal(leakHits, 0, 'No credential-bearing request may ever reach the redirect target');
    } finally {
      await manager.shutdown().catch(() => {});
    }

    // 7. Embedded tracker / web-seed destinations are validated before aria2c is ever spawned
    const invokedMarker = path.join(tmpDir, 'aria2-invoked.txt');
    const mockAria2 = await writeMockAria2(
      tmpDir,
      'mock-aria2-14b.mjs',
      `import fs from 'node:fs/promises';\nawait fs.writeFile(${JSON.stringify(invokedMarker)}, 'spawned');\nprocess.exit(0);\n`
    );
    const leakyTorrent = bencodeValue({
      announce: 'https://tracker.example/announce',
      'announce-list': [[`https://backup-tracker.example/announce?pk=${SECRET}`]],
      'url-list': [`https://webseed.example/files/${SECRET}/`],
      info: { name: 'Leaky.epub', length: 10, 'piece length': 16384, pieces: Buffer.alloc(20, 0x11) },
    });
    const parsedLeaky = parseTorrentMetadata(leakyTorrent);
    assert.ok(parsedLeaky.outboundUrls.some((u) => u.includes('backup-tracker')));
    assert.ok(parsedLeaky.outboundUrls.some((u) => u.includes('webseed.example')));
    const torrentItem = {
      ...makeItem('https://tracker.example/leaky.torrent', dlDir, 'Leaky.epub', { totalBytes: 10 }),
      torrentUrl: 'https://tracker.example/leaky.torrent',
      torrentInfoHash: parsedLeaky.infoHash,
    };
    await new Aria2Runner({
      item: torrentItem,
      binary: process.execPath,
      binaryArgsPrefix: [mockAria2],
      readManifestBytes: async () => leakyTorrent,
      manifestScratchDir: path.join(tmpDir, 'scratch'),
      secretsProvider: () => [SECRET],
      onUpdate: () => {},
    }).run();
    assert.equal(torrentItem.status, 'failed');
    assert.ok(torrentItem.error?.includes('Blocked outbound'));
    await assert.rejects(fs.access(invokedMarker), 'aria2c must never be spawned');
    assert.deepEqual(await fs.readdir(path.join(tmpDir, 'scratch')).catch(() => []), []);

    const magnet = `magnet:?xt=urn:btih:${'ab'.repeat(20)}&tr=${encodeURIComponent(`udp://tracker.example:80/${SECRET}/announce`)}`;
    assert.ok(extractMagnetEmbeddedUrls(magnet)[0].includes(SECRET));
    const magnetItem = { ...makeItem(magnet, dlDir, 'mag', {}), magnetUri: magnet };
    await new Aria2Runner({
      item: magnetItem,
      binary: process.execPath,
      binaryArgsPrefix: [mockAria2],
      secretsProvider: () => [SECRET],
      onUpdate: () => {},
    }).run();
    assert.equal(magnetItem.status, 'failed');
    assert.ok(magnetItem.error?.includes('Blocked outbound'));
    await assert.rejects(fs.access(invokedMarker));

    // 8. Private-tracker path passkeys & opaque signed path tokens are hidden by default
    const cases = [
      ['https://tracker.example.org/0123456789abcdef0123456789abcdef/announce', '0123456789abcdef0123456789abcdef'],
      ['http://tracker.example:2710/a/pk9f8e7d6c5b/announce', 'pk9f8e7d6c5b'],
      ['https://tracker.example/announce/ABCDEF123456', 'ABCDEF123456'],
      ['https://tracker.example/scrape.php/u42secretpass', 'u42secretpass'],
      ['https://cdn.example/dl/bFYrSzIGeCP_pRh2Tip9uw/Book%20Title.pdf', 'bFYrSzIGeCP_pRh2Tip9uw'],
    ];
    for (const [raw, hidden] of cases) {
      const red = redactSensitiveUrl(raw);
      assert.equal(red.includes(hidden), false, `${raw} must hide ${hidden} (got ${red})`);
    }
    assert.ok(redactSensitiveUrl(cases[0][0]).endsWith('/announce'));
    assert.ok(redactSensitiveUrl(cases[4][0]).endsWith('/Book%20Title.pdf'), 'real filenames survive');
    assert.equal(
      redactSensitiveUrl('https://annas-archive.org/md5/c942aa9892d0601d44120fe062c46006'),
      'https://annas-archive.org/md5/c942aa9892d0601d44120fe062c46006',
      'public content hashes are not credentials'
    );
    const magRed = redactSensitiveUrl(
      `magnet:?xt=urn:btih:${'cd'.repeat(20)}&tr=${encodeURIComponent('https://tracker.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0/announce')}`
    );
    assert.equal(magRed.includes('0f1e2d3c4b5a69788796a5b4c3d2e1f0'), false);
    assert.ok(magRed.includes(`btih:${'cd'.repeat(20)}`));
    assert.equal(redactSensitiveUrl(redactSensitiveUrl(cases[1][0])), redactSensitiveUrl(cases[1][0]), 'idempotent');
  } finally {
    await srv.close();
    await leakSrv.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('Audit 14C: cross-store vault serialization, post-load corruption, interrupted legacy migration scrub, malformed state.json preservation, strict save propagation, and legacy plaintext .torrent migration', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit14c-'));
  try {
    // 1. Two independent SecretStore instances (≈ two processes) on ONE data dir never clobber
    const sharedDir = path.join(root, 'shared');
    const storeA = new SecretStore(sharedDir);
    const storeB = new SecretStore(sharedDir);
    await storeA.getOperationalSources(); // A caches the (empty) generation up-front
    await storeB.getOperationalSources();
    await Promise.all([
      storeA.setAnnasArchiveApiKey('CROSS_STORE_KEY_A'),
      storeB.setPrivateTemplates({ customMirrorUrls: ['https://m.example/{md5}?t=CROSS_B'] }),
      ...Array.from({ length: 8 }, (_, i) =>
        storeA.setOperationalSource(`a-${i}`, { originalUrl: `https://a.example/${i}`, finalUrl: `https://a.example/${i}` })
      ),
      ...Array.from({ length: 8 }, (_, i) =>
        storeB.setOperationalSource(`b-${i}`, { originalUrl: `https://b.example/${i}`, finalUrl: `https://b.example/${i}` })
      ),
    ]);
    const verifier = new SecretStore(sharedDir);
    assert.equal(await verifier.getAnnasArchiveApiKey(), 'CROSS_STORE_KEY_A');
    assert.deepEqual((await verifier.getPrivateTemplates()).customMirrorUrls, ['https://m.example/{md5}?t=CROSS_B']);
    assert.equal(Object.keys(await verifier.getOperationalSources()).length, 16);
    // A stale in-memory view in A reloads the newer generation written by B
    assert.deepEqual((await storeA.getPrivateTemplates()).customMirrorUrls, ['https://m.example/{md5}?t=CROSS_B']);
    await assert.rejects(fs.access(path.join(sharedDir, 'secrets.enc.json.lock')), 'Vault lock released');

    // 2. Post-load corruption: a loaded store must NOT overwrite a vault corrupted on disk afterwards
    const corruptAfterLoad = JSON.stringify({ v: 1, iv: 'AAAA', tag: 'BBBB', ciphertext: 'CCCC' });
    await fs.writeFile(path.join(sharedDir, 'secrets.enc.json'), corruptAfterLoad, 'utf8');
    await assert.rejects(
      storeA.setOperationalSource('late-write', { originalUrl: 'https://x', finalUrl: 'https://x' }),
      (err) => err instanceof VaultCorruptionError
    );
    assert.equal(await fs.readFile(path.join(sharedDir, 'secrets.enc.json'), 'utf8'), corruptAfterLoad);

    // 3. Interrupted legacy migration: vault already holds the secrets (previous run) but the scrub
    //    of state.json never happened -> init MUST scrub based on what is actually on disk.
    const migDir = path.join(root, 'interrupted');
    const migDl = path.join(root, 'interrupted-dl');
    await fs.mkdir(migDl, { recursive: true });
    const jobId = 'interrupted-job-1';
    const signedUrl = 'https://cdn.example/book.epub?sig=INTERRUPTED_SIG_SECRET_77';
    const privTemplate = 'https://priv.example/{md5}?key=INTERRUPTED_TMPL_KEY_88';
    const preVault = new SecretStore(migDir);
    await preVault.setOperationalSource(jobId, { originalUrl: signedUrl, finalUrl: signedUrl });
    await preVault.setPrivateTemplates({ customMirrorUrls: [privTemplate] });
    await fs.writeFile(
      path.join(migDir, 'state.json'),
      JSON.stringify({
        version: 1,
        trustRules: [],
        settings: { ...getDefaultSettings(), downloadDir: migDl, customMirrorUrls: [privTemplate] },
        downloads: [{ ...makeItem(signedUrl, migDl, 'book.epub', { id: jobId }), status: 'completed', completedAt: Date.now() }],
      }),
      'utf8'
    );
    const migMgr = new DownloadManager({ dataDir: migDir });
    await migMgr.init();
    const scrubbed = await fs.readFile(path.join(migDir, 'state.json'), 'utf8');
    assert.equal(scrubbed.includes('INTERRUPTED_SIG_SECRET_77'), false, 'plaintext signed URL must be scrubbed');
    assert.equal(scrubbed.includes('INTERRUPTED_TMPL_KEY_88'), false, 'plaintext template must be scrubbed');
    assert.equal((await migMgr.secretStore.getOperationalSource(jobId)).originalUrl, signedUrl);
    await migMgr.shutdown();

    // 4. Malformed or unreadable state.json is NEVER overwritten with fresh defaults
    const badDir = path.join(root, 'malformed');
    await fs.mkdir(badDir, { recursive: true });
    const truncated = '{"version":1,"downloads":[{"id":"keep-me","originalUrl":"https://x/?sig=LEGACY';
    await fs.writeFile(path.join(badDir, 'state.json'), truncated, 'utf8');
    await assert.rejects(new DownloadManager({ dataDir: badDir }).init(), (err) => err instanceof StateLoadError);
    assert.equal(await fs.readFile(path.join(badDir, 'state.json'), 'utf8'), truncated, 'malformed state preserved byte-for-byte');
    const dirStateDir = path.join(root, 'unreadable');
    await fs.mkdir(path.join(dirStateDir, 'state.json'), { recursive: true });
    await assert.rejects(new DownloadManager({ dataDir: dirStateDir }).init(), (err) => err instanceof StateLoadError);
    assert.ok((await fs.stat(path.join(dirStateDir, 'state.json'))).isDirectory());
    // Fresh state is created ONLY when state.json is genuinely absent
    const freshDir = path.join(root, 'fresh');
    const freshMgr = new DownloadManager({ dataDir: freshDir });
    await freshMgr.init();
    await fs.access(path.join(freshDir, 'state.json'));
    await freshMgr.shutdown();

    // 5. Migration/scrub saves propagate failures (strict save) instead of being swallowed
    const strictDir = path.join(root, 'strict');
    await fs.mkdir(path.join(strictDir, 'state.json', 'blocker'), { recursive: true });
    const strictStore = new StateStore(strictDir);
    const st = { version: 1, downloads: [], settings: getDefaultSettings(), trustRules: [] };
    await assert.rejects(strictStore.saveStrict(st));
    await strictStore.save(st); // non-strict variant still never throws (logged)

    // 6. Legacy plaintext .torrent manifests are migrated into encrypted envelopes and scrubbed
    const torDir = path.join(root, 'legacy-torrent');
    const passkey = 'LEGACY_PLAINTEXT_PASSKEY_99';
    const legacyTorrent = bencodeValue({
      announce: `https://tracker.private.example/announce?passkey=${passkey}`,
      info: { name: 'Legacy.epub', length: 2048, 'piece length': 16384, pieces: Buffer.alloc(20, 0x42) },
    });
    const legacyParsed = parseTorrentMetadata(legacyTorrent);
    const legacyPath = path.join(torDir, 'manifests', 'legacy-job.torrent');
    const mismatchPath = path.join(torDir, 'manifests', 'mismatch-job.torrent');
    await fs.mkdir(path.dirname(legacyPath), { recursive: true });
    await fs.writeFile(legacyPath, legacyTorrent);
    await fs.writeFile(mismatchPath, legacyTorrent);
    const torVault = new SecretStore(torDir);
    await torVault.setOperationalSource('legacy-job', {
      originalUrl: 'https://tracker.private.example/l.torrent',
      finalUrl: 'https://tracker.private.example/l.torrent',
      torrentUrl: 'https://tracker.private.example/l.torrent',
      pinnedTorrentPath: legacyPath,
      torrentInfoHash: legacyParsed.infoHash,
    });
    await torVault.setOperationalSource('mismatch-job', {
      originalUrl: 'https://tracker.private.example/m.torrent',
      finalUrl: 'https://tracker.private.example/m.torrent',
      torrentUrl: 'https://tracker.private.example/m.torrent',
      pinnedTorrentPath: mismatchPath,
      torrentInfoHash: '0'.repeat(40),
    });
    await fs.writeFile(
      path.join(torDir, 'state.json'),
      JSON.stringify({
        version: 1,
        trustRules: [],
        settings: getDefaultSettings(),
        downloads: [
          { ...makeItem('https://tracker.private.example/l.torrent', root, 'Legacy.epub', { id: 'legacy-job' }), status: 'paused', userDeemedSafe: true, torrentUrl: 'https://tracker.private.example/l.torrent', torrentInfoHash: legacyParsed.infoHash },
          { ...makeItem('https://tracker.private.example/m.torrent', root, 'Mismatch.epub', { id: 'mismatch-job' }), status: 'paused', userDeemedSafe: true, torrentUrl: 'https://tracker.private.example/m.torrent', torrentInfoHash: '0'.repeat(40) },
        ],
      }),
      'utf8'
    );
    const torMgr = new DownloadManager({ dataDir: torDir });
    await torMgr.init();
    try {
      await assert.rejects(fs.access(legacyPath), 'plaintext legacy manifest removed after verified migration');
      const migratedPath = torMgr['pinnedTorrentPaths'].get('legacy-job');
      assert.ok(migratedPath.endsWith('.torrent.enc'));
      assert.equal(Buffer.compare(await torMgr.secretStore.readEncryptedManifest(migratedPath), legacyTorrent), 0);
      assert.equal((await fs.readFile(migratedPath, 'utf8')).includes(passkey), false);
      assert.equal(torMgr['pinnedTorrentPaths'].has('mismatch-job'), false, 'unverifiable manifest path is rejected');
      assert.ok(
        torMgr.getSnapshot().downloads.find((d) => d.id === 'mismatch-job').routingLog.some((e) => /could not be migrated/i.test(e.message))
      );
      // Raw plaintext manifest paths are refused by the vault reader
      await fs.writeFile(path.join(root, 'raw.torrent'), legacyTorrent);
      await assert.rejects(torMgr.secretStore.readEncryptedManifest(path.join(root, 'raw.torrent')), /plaintext/i);
    } finally {
      await torMgr.shutdown();
    }
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('Audit 14D: full resource identity (query), strict RFC 9110 strong ETags, digestless resourceId requirement, span EOF proof across restart, unproven-identity single stream, paired staging with locked orphan sidecar, and checkpoint failures never reported as paused', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit14d-'));
  const payload = makePayload(512 * 1024, 57);
  const rangeStarts = [];
  let unprovenRequests = 0;
  let dropFirstUnproven = true;
  let slowMode = false;
  const srv = await listenServer(
    http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x');
      const range = req.headers.range;
      const m = range?.match(/^bytes=(\d+)-(\d*)$/);
      const start = m ? Number(m[1]) : 0;
      const end = m && m[2] ? Number(m[2]) : payload.buf.length - 1;
      if (u.pathname === '/strong.bin') {
        rangeStarts.push(start);
        const slice = payload.buf.subarray(start, end + 1);
        res.writeHead(m ? 206 : 200, {
          ETag: '"strong-v1"',
          'Accept-Ranges': 'bytes',
          'Content-Length': slice.length,
          ...(m ? { 'Content-Range': `bytes ${start}-${end}/${payload.buf.length}` } : {}),
        });
        if (slowMode) {
          res.write(slice.subarray(0, 32 * 1024));
          setTimeout(() => res.end(slice.subarray(32 * 1024)), 1500);
          return;
        }
        res.end(slice);
        return;
      }
      if (u.pathname === '/unproven.bin') {
        unprovenRequests += 1;
        rangeStarts.push(start);
        const slice = payload.buf.subarray(start, end + 1);
        res.writeHead(m ? 206 : 200, {
          'Accept-Ranges': 'bytes',
          'Content-Length': slice.length,
          ...(m ? { 'Content-Range': `bytes ${start}-${end}/${payload.buf.length}` } : {}),
        });
        if (dropFirstUnproven) {
          dropFirstUnproven = false;
          res.write(slice.subarray(0, 100 * 1024));
          setTimeout(() => res.destroy(), 30);
          return;
        }
        res.end(slice);
        return;
      }
      res.writeHead(404);
      res.end();
    })
  );
  const base = `http://127.0.0.1:${srv.port}`;
  try {
    // 1. Strict RFC 9110 strong ETags
    assert.equal(isStrongEtag('"abc"'), true);
    assert.equal(isStrongEtag('abc'), false, 'unquoted is not a valid entity-tag');
    assert.equal(isStrongEtag('W/"abc"'), false);
    assert.equal(isStrongEtag('""'), false, 'empty opaque-tag carries no identity');
    assert.equal(isStrongEtag('"ab"c"'), false);
    assert.equal(isStrongEtag('"abc'), false);

    // 2. Full resource identity includes the query string
    assert.equal(isSameResourceEndpoint('https://h.example/get.php?id=1', 'https://h.example/get.php?id=1'), true);
    assert.equal(isSameResourceEndpoint('https://h.example/get.php?id=1', 'https://h.example/get.php?id=2'), false);
    const primary = { url: 'https://h.example/get.php?id=1', supportsRanges: true, totalBytes: 100, etag: '"same"' };
    assert.equal(canCombineMirrorWithPrimary(primary, { ...primary, url: 'https://h.example/get.php?id=2' }, false).eligible, false);
    // Equal ETags on DIFFERENT files of the same host never prove identity
    assert.equal(canCombineMirrorWithPrimary(primary, { ...primary, url: 'https://h.example/other.bin' }, false).eligible, false);
    assert.equal(canCombineMirrorWithPrimary(primary, { ...primary }, false).eligible, true);
    assert.equal(canCombineMirrorWithPrimary(primary, { ...primary, url: 'https://h.example/get.php?id=2' }, true).eligible, true);

    // 3. Digestless checkpoints REQUIRE a matching non-empty resourceId
    const baseMeta = {
      version: 2,
      jobId: 'rid-job',
      partPath: path.join(tmpDir, 'rid.part'),
      filename: 'rid.bin',
      totalBytes: 1000,
      pinnedEtag: '"strong-v1"',
      mirrors: [],
      segments: [{ id: 0, start: 0, end: 999, committedBytes: 500, status: 'paused' }],
      updatedAt: Date.now(),
    };
    const baseOpts = { jobId: 'rid-job', partPath: baseMeta.partPath, totalBytes: 1000, partFileSize: 1000, pinnedEtag: '"strong-v1"' };
    assert.equal(validatePartMetaGeometry(baseMeta, { ...baseOpts, resourceId: 'src_x' }).valid, false, 'missing meta resourceId');
    assert.equal(validatePartMetaGeometry({ ...baseMeta, resourceId: 'src_x' }, baseOpts).valid, false, 'missing current resourceId');
    assert.equal(validatePartMetaGeometry({ ...baseMeta, resourceId: 'src_x' }, { ...baseOpts, resourceId: 'src_y' }).valid, false);
    assert.equal(validatePartMetaGeometry({ ...baseMeta, resourceId: 'src_x' }, { ...baseOpts, resourceId: 'src_x' }).valid, true);
    assert.notEqual(
      computeOpaqueSourceId('https://h.example/f?sig=a'),
      computeOpaqueSourceId('https://h.example/f?sig=b'),
      'query is part of the keyed resource fingerprint'
    );
    assert.notEqual(
      computeOpaqueSourceId('https://h.example/f', Buffer.alloc(32, 1)),
      computeOpaqueSourceId('https://h.example/f', Buffer.alloc(32, 2)),
      'fingerprint is keyed (not an unsalted hash of the credential-bearing URL)'
    );

    // 4. Span completion proof: full byte count WITHOUT persisted EOF proof is refetched on restart
    const unproofed = validatePartMetaGeometry(
      { ...baseMeta, resourceId: 'r', segments: [{ id: 0, start: 0, end: 499, committedBytes: 500, status: 'done' }, { id: 1, start: 500, end: 999, committedBytes: 0, status: 'pending' }] },
      { ...baseOpts, resourceId: 'r' }
    );
    assert.equal(unproofed.segments[0].status, 'pending');
    assert.equal(unproofed.segments[0].downloaded, 0);
    assert.equal(unproofed.spanVerifiedSegIds.size, 0);
    const proofed = validatePartMetaGeometry(
      { ...baseMeta, resourceId: 'r', segments: [{ id: 0, start: 0, end: 499, committedBytes: 500, status: 'done', spanVerified: true }, { id: 1, start: 500, end: 999, committedBytes: 0, status: 'pending' }] },
      { ...baseOpts, resourceId: 'r' }
    );
    assert.equal(proofed.segments[0].status, 'done');
    assert.ok(proofed.spanVerifiedSegIds.has(proofed.segments[0].id));

    //    End-to-end restart after the last byte of span 0 was written but before EOF was validated
    const half = payload.buf.length / 2;
    const restartItem = makeItem(`${base}/strong.bin`, tmpDir, 'restart-eof.bin', {
      id: 'restart-eof-job',
      totalBytes: payload.buf.length,
      connections: 2,
      etag: '"strong-v1"',
    });
    restartItem.pinnedEtag = '"strong-v1"';
    restartItem.partPath = path.join(tmpDir, '.boltgate-restart-eof-job-restart-eof.bin.part');
    const partBytes = Buffer.alloc(payload.buf.length);
    payload.buf.copy(partBytes, 0, 0, half); // span 0 fully written...
    await fs.writeFile(restartItem.partPath, partBytes);
    await writePartMeta(restartItem.partPath, {
      version: 2,
      jobId: restartItem.id,
      partPath: restartItem.partPath,
      filename: restartItem.filename,
      totalBytes: payload.buf.length,
      resourceId: computeOpaqueSourceId(restartItem.finalUrl),
      pinnedEtag: '"strong-v1"',
      mirrors: [],
      segments: [
        { id: 0, start: 0, end: half - 1, committedBytes: half, status: 'active' }, // ...but no EOF proof
        { id: 1, start: half, end: payload.buf.length - 1, committedBytes: 0, status: 'pending' },
      ],
      updatedAt: Date.now(),
    });
    rangeStarts.length = 0;
    await new DownloadRunner({ item: restartItem, throttle: new TokenBucketThrottle(0), minSegmentBytes: 64 * 1024, onUpdate: () => {} }).run();
    assert.equal(restartItem.status, 'completed');
    assert.equal(restartItem.sha256, payload.sha256);
    assert.ok(rangeStarts.includes(0), 'Unproven full span 0 must be refetched from its start');

    // 5. Unproven identity (no digest, no strong ETag): ONE uninterrupted stream, restart from 0
    rangeStarts.length = 0;
    const unprovenItem = makeItem(`${base}/unproven.bin`, tmpDir, 'unproven.bin', {
      totalBytes: payload.buf.length,
      connections: 8,
      supportsRanges: true,
    });
    await new DownloadRunner({ item: unprovenItem, throttle: new TokenBucketThrottle(0), minSegmentBytes: 16 * 1024, onUpdate: () => {} }).run();
    assert.equal(unprovenItem.status, 'completed');
    assert.equal(unprovenItem.sha256, payload.sha256);
    assert.equal(unprovenItem.segments.length, 1, 'never split into ranged segments');
    assert.equal(unprovenRequests, 2, 'one interrupted stream + one clean restart');
    assert.deepEqual(rangeStarts, [0, 0], 'interruption restarts from offset 0, never resumes mid-file');
    const unprovenArgs = buildAria2Args({ uris: ['https://h.example/a.bin'], dir: tmpDir, maxConnectionsPerServer: 8, singleUninterruptedStream: true });
    for (const flag of ['--split=1', '--max-connection-per-server=1', '--continue=false', '--max-tries=1']) {
      assert.ok(unprovenArgs.includes(flag), `aria2c unproven-identity args must include ${flag}`);
    }

    // 6. Paired staging reservation never pairs a new payload with an orphan (or locked) sidecar
    const pairDir = path.join(tmpDir, 'pairs');
    await fs.mkdir(pairDir, { recursive: true });
    const orphanSidecar = path.join(pairDir, '.boltgate-orphanjob-file.bin.part.meta');
    await fs.writeFile(orphanSidecar, JSON.stringify({ version: 2, jobId: 'orphanjob', stale: true }));
    const reserved = await reserveExclusiveStagingFile(pairDir, 'file.bin', 'orphanjob');
    await reserved.handle.close();
    assert.notEqual(reserved.partPath, orphanSidecar.replace(/\.meta$/, ''), 'slot with orphan sidecar is skipped');
    assert.equal(await fs.readFile(`${reserved.partPath}.meta`, 'utf8'), '', 'own sidecar reserved as empty placeholder');
    assert.ok((await fs.readFile(orphanSidecar, 'utf8')).includes('stale'), 'orphan sidecar untouched');
    // A LOCKED sidecar (EPERM) keeps the pair intact and its slot occupied
    const lockedErr = Object.assign(new Error('EPERM: locked sidecar'), { code: 'EPERM' });
    await assert.rejects(retireStagingPair(reserved.partPath, { removeMetaFn: async () => { throw lockedErr; } }), /EPERM/);
    await fs.access(reserved.partPath);
    await fs.access(`${reserved.partPath}.meta`);
    const reservedAgain = await reserveExclusiveStagingFile(pairDir, 'file.bin', 'orphanjob');
    await reservedAgain.handle.close();
    assert.notEqual(reservedAgain.partPath, reserved.partPath);
    // Engine level: an invalid checkpoint whose sidecar is locked is isolated, never reused
    const lockItem = makeItem(`${base}/strong.bin`, pairDir, 'lock.bin', {
      id: 'lockedjob',
      totalBytes: payload.buf.length,
      connections: 1,
      etag: '"strong-v1"',
    });
    lockItem.partPath = path.join(pairDir, '.boltgate-lockedjob-lock.bin.part');
    await fs.writeFile(lockItem.partPath, Buffer.alloc(10));
    await fs.writeFile(`${lockItem.partPath}.meta`, JSON.stringify({ version: 2, jobId: 'lockedjob', partPath: lockItem.partPath, segments: [], totalBytes: 1 }));
    await new DownloadRunner({
      item: lockItem,
      throttle: new TokenBucketThrottle(0),
      fileHooks: {
        removeMetaFn: async (p) => {
          if (p.endsWith('.boltgate-lockedjob-lock.bin.part')) throw lockedErr;
          await fs.unlink(`${p}.meta`).catch(() => undefined);
        },
      },
      onUpdate: () => {},
    }).run();
    assert.equal(lockItem.status, 'completed');
    assert.equal(lockItem.sha256, payload.sha256);
    assert.notEqual(lockItem.partPath, path.join(pairDir, '.boltgate-lockedjob-lock.bin.part'));
    await fs.access(path.join(pairDir, '.boltgate-lockedjob-lock.bin.part.meta'));
    assert.ok(lockItem.routingLog.some((e) => /Could not retire staging pair/i.test(e.message)), 'failure surfaced, not ignored');

    // 7. A checkpoint (sidecar) write failure is NEVER reported as a durable pause
    slowMode = true;
    const cpItem = makeItem(`${base}/strong.bin`, tmpDir, 'checkpoint-fail.bin', {
      totalBytes: payload.buf.length,
      connections: 1,
      etag: '"strong-v1"',
    });
    const cpRunner = new DownloadRunner({ item: cpItem, throttle: new TokenBucketThrottle(0), onUpdate: () => {} });
    const cpRun = cpRunner.run();
    await waitFor(() => cpItem.partPath && cpItem.downloadedBytes > 0);
    await fs.rm(`${cpItem.partPath}.meta`, { force: true });
    await fs.mkdir(`${cpItem.partPath}.meta`, { recursive: true });
    await fs.writeFile(path.join(`${cpItem.partPath}.meta`, 'occupied'), 'x');
    await cpRunner.pause();
    await cpRun;
    slowMode = false;
    assert.equal(cpItem.status, 'failed', 'failed checkpoint must not be misreported as paused');
    assert.ok(cpItem.error);
  } finally {
    await srv.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('Audit 14E: native cancel during reservation, real post-Undo runner race, approval locked during verification, file replacement before publish, symlinked publication dirs, bulk approval preserving per-row edits, and history re-download preserving digests & torrent selections', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit14e-data-'));
  const tmpDlDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit14e-dl-'));
  const payload = makePayload(160 * 1024, 71);
  const selTorrent = bencodeValue({
    announce: 'https://tracker.example/announce',
    info: {
      name: 'SelPack',
      'piece length': 16384,
      pieces: Buffer.alloc(20, 0x33),
      files: [
        { length: 10, path: ['one.txt'] },
        { length: 20, path: ['two.txt'] },
        { length: 30, path: ['three.txt'] },
      ],
    },
  });
  const otherTorrent = bencodeValue({
    announce: 'https://tracker.example/announce',
    info: { name: 'Different', 'piece length': 16384, pieces: Buffer.alloc(20, 0x44), files: [{ length: 5, path: ['x.txt'] }] },
  });
  let serveOtherTorrent = false;
  let slowStream = false;
  const srv = await listenServer(
    http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x');
      if (u.pathname === '/sel.torrent') {
        const body = serveOtherTorrent ? otherTorrent : selTorrent;
        res.writeHead(200, { 'Content-Type': 'application/x-bittorrent', 'Content-Length': body.length });
        res.end(body);
        return;
      }
      if (u.pathname.startsWith('/file')) {
        res.writeHead(200, { 'Content-Length': payload.buf.length, 'Accept-Ranges': 'bytes', ETag: '"e-v1"' });
        if (req.method === 'HEAD') return res.end();
        if (slowStream) {
          res.write(payload.buf.subarray(0, 16 * 1024));
          setTimeout(() => res.end(payload.buf.subarray(16 * 1024)), 700);
          return;
        }
        res.end(payload.buf);
        return;
      }
      res.writeHead(404);
      res.end();
    })
  );
  const base = `http://127.0.0.1:${srv.port}`;

  let approvalGate = null;
  let duringApproval = null;
  const manager = new DownloadManager({
    dataDir: tmpDataDir,
    testHooks: {
      onDuringApproval: async (id) => {
        if (duringApproval) await duringApproval(id);
        if (approvalGate) await approvalGate;
      },
    },
  });
  await manager.init();
  await manager.updateSettings({ downloadDir: tmpDlDir });
  const appServer = createAppServer({ manager });
  await new Promise((r) => appServer.listen(0, '127.0.0.1', r));
  const apiBase = `http://127.0.0.1:${appServer.address().port}`;
  const token = manager.getSessionToken();
  const inspectAndReview = async (url) => {
    const res = await manager.inspectRawText(url);
    const id = res.items[0].id;
    await waitFor(() => manager.getSnapshot().downloads.find((d) => d.id === id)?.status === 'pending_review');
    return id;
  };

  try {
    // 1. Native cancel DURING reservation: freshly reserved pair is retired by the lifecycle promise
    const cancelDir = path.join(tmpDlDir, 'cancel-during');
    await fs.mkdir(cancelDir, { recursive: true });
    const cancelItem = makeItem(`${base}/file-cancel.bin`, cancelDir, 'cancel.bin', { totalBytes: payload.buf.length, connections: 1, etag: '"e-v1"' });
    let cancelRunner;
    cancelRunner = new DownloadRunner({
      item: cancelItem,
      throttle: new TokenBucketThrottle(0),
      fileHooks: {
        wrapHandle: (fh) => {
          void cancelRunner.cancel(true); // cancellation arrives while reservation completes
          return fh;
        },
      },
      onUpdate: () => {},
    });
    await cancelRunner.run();
    await cancelRunner.cancel(true);
    assert.deepEqual(
      (await fs.readdir(cancelDir)).filter((n) => n.startsWith('.boltgate-')),
      [],
      'no stray staging payload or sidecar after cancel during reservation'
    );
    assert.notEqual(cancelItem.status, 'completed');

    // 2. Real post-Undo runner race: soft remove -> Undo -> resume; the old runner lifecycle can
    //    never clear or broadcast over the new runner registered for the same id.
    slowStream = true;
    const raceId = await inspectAndReview(`${base}/file-race.bin`);
    await manager.approveDownload(raceId, { startNow: true });
    const oldHandle = manager['runners'].get(raceId);
    assert.ok(oldHandle?.runner);
    await manager.removeDownload(raceId, false);
    assert.equal(manager['runners'].has(raceId), false);
    await manager.restoreDownload(raceId);
    await manager.resumeDownload(raceId, true);
    const newHandle = manager['runners'].get(raceId);
    assert.ok(newHandle && newHandle !== oldHandle && newHandle.runner !== oldHandle.runner);
    await oldHandle.done; // stale lifecycle fully settled
    assert.equal(manager['runners'].get(raceId), newHandle, 'stale runner must not clear the newer runner');
    slowStream = false;
    const raceDone = await waitFor(() => {
      const d = manager.getSnapshot().downloads.find((x) => x.id === raceId);
      return d?.status === 'completed' ? d : null;
    });
    assert.equal(raceDone.sha256, payload.sha256);
    assert.equal(manager['runners'].has(raceId), false);

    // 3. Approval parameters are locked once verification starts (re-checked after awaits)
    const lockId = await inspectAndReview(`${base}/file-lock.bin`);
    const lockLive = manager['downloads'].find((d) => d.id === lockId);
    const destBefore = lockLive.destinationDir;
    duringApproval = async () => {
      lockLive.status = 'verifying'; // verification began while approval was mid-flight
    };
    await assert.rejects(
      manager.approveDownload(lockId, { expectedSha256: 'b'.repeat(64), destinationDir: path.join(tmpDlDir, 'elsewhere'), startNow: true }),
      (err) => err?.status === 409
    );
    duringApproval = null;
    assert.equal(lockLive.expectedSha256, undefined, 'expectedSha256 must not change once verification started');
    assert.equal(lockLive.destinationDir, destBefore, 'destination must not change once verification started');
    assert.equal(manager['runners'].has(lockId), false, 'no runner started by the rejected approval');
    lockLive.status = 'pending_review';
    // Concurrent approval of the same row is rejected while the first is in flight
    let releaseGate;
    approvalGate = new Promise((r) => (releaseGate = r));
    const firstApproval = manager.approveDownload(lockId, { expectedSha256: payload.sha256 });
    await assert.rejects(manager.approveDownload(lockId, { expectedSha256: 'c'.repeat(64) }), (err) => err?.status === 409);
    releaseGate();
    approvalGate = null;
    await firstApproval;
    assert.equal(lockLive.expectedSha256, payload.sha256);
    await waitFor(() => manager.getSnapshot().downloads.find((d) => d.id === lockId)?.status === 'completed');

    // 4. File replacement between verification and publication is refused
    const pubDir = path.join(tmpDlDir, 'pub');
    await fs.mkdir(pubDir, { recursive: true });
    const stage = path.join(pubDir, '.stage-verify.part');
    await fs.writeFile(stage, 'VERIFIED_BYTES_0001');
    const verifiedId = await captureFileIdentity(stage);
    await new Promise((r) => setTimeout(r, 20));
    await fs.writeFile(stage, 'SWAPPED_BYTES_00002');
    await assert.rejects(
      publishStagingFileAtomically(stage, pubDir, 'final.bin', { expectedIdentity: verifiedId }),
      /replaced or modified/i
    );
    await assert.rejects(fs.access(path.join(pubDir, 'final.bin')));
    // Publication through a symlink/junction inside the destination is refused
    const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-audit14e-outside-'));
    try {
      const linkDir = path.join(pubDir, 'linked');
      await fs.symlink(outside, linkDir, process.platform === 'win32' ? 'junction' : 'dir');
      await assert.rejects(assertPhysicalDirInside(path.join(linkDir, 'sub'), pubDir), /symlink|junction|outside/i);
      const stage2 = path.join(pubDir, '.stage-2.part');
      await fs.writeFile(stage2, 'DATA');
      await assert.rejects(
        publishStagingFileAtomically(stage2, linkDir, 'escape.bin', { physicalRootDir: pubDir }),
        /symlink|junction|outside/i
      );
      assert.deepEqual(await fs.readdir(outside), []);
    } finally {
      await fs.rm(outside, { recursive: true, force: true });
    }

    // 5. Bulk approval preserves each row's edits; one invalid row approves NOTHING
    const rowA = await inspectAndReview(`${base}/file-row-a.bin`);
    const rowB = await inspectAndReview(`${base}/file-row-b.bin`);
    const badBulk = await fetch(`${apiBase}/api/downloads/approve-batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-BoltGate-Session': token },
      body: JSON.stringify({ entries: [{ id: rowA, expectedSha256: payload.sha256 }, { id: rowB, expectedSha256: 'not-hex' }] }),
    });
    assert.equal(badBulk.status, 400);
    assert.equal(manager.getSnapshot().downloads.find((d) => d.id === rowA).status, 'pending_review');
    const okBulk = await fetch(`${apiBase}/api/downloads/approve-batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-BoltGate-Session': token },
      body: JSON.stringify({
        entries: buildBulkApprovalEntries([rowA, rowB], {
          expectedSha256: { rowA: 'ignored', [rowA]: payload.sha256 },
          names: { [rowB]: 'renamed-row-b.bin' },
        }),
      }),
    });
    assert.equal(okBulk.status, 200);
    const approvedRows = (await okBulk.json()).items;
    assert.equal(approvedRows.find((d) => d.id === rowA).expectedSha256, payload.sha256);
    assert.ok(approvedRows.find((d) => d.id === rowB).filename.startsWith('renamed-row-b'));
    const doneA = await waitFor(() => {
      const d = manager.getSnapshot().downloads.find((x) => x.id === rowA);
      return d?.status === 'completed' ? d : null;
    });
    assert.equal(doneA.verifiedHashMatch, true, 'bulk-approved row verified against ITS edited SHA-256');

    // 6. Re-download from history preserves expected digests ...
    const histDirect = await manager.redownloadFromHistory(rowA);
    const histDirectItem = manager['downloads'].find((d) => d.id === histDirect.items[0].id);
    assert.equal(histDirectItem.expectedSha256, payload.sha256);

    // ... and the exact torrent file selection when the re-inspected manifest is identical
    const torId = await inspectAndReview(`${base}/sel.torrent`);
    const torLive = manager['downloads'].find((d) => d.id === torId);
    torLive.selectFile = '2,3';
    torLive.selectFileInfoHash = torLive.torrentInfoHash;
    torLive.expectedMd5 = 'd'.repeat(32);
    torLive.status = 'completed';
    torLive.completedAt = Date.now();
    const histTor = await manager.redownloadFromHistory(torId);
    const histTorId = histTor.items[0].id;
    const histTorReviewed = await waitFor(() => {
      const d = manager.getSnapshot().downloads.find((x) => x.id === histTorId);
      return d?.status === 'pending_review' ? d : null;
    });
    assert.equal(histTorReviewed.selectFile, '2,3');
    assert.equal(histTorReviewed.selectFileInfoHash, torLive.torrentInfoHash.toLowerCase());
    assert.equal(histTorReviewed.expectedMd5, 'd'.repeat(32));
    // A DIFFERENT manifest behind the same URL drops the selection (with a visible warning)
    serveOtherTorrent = true;
    const histOther = await manager.redownloadFromHistory(torId);
    const histOtherReviewed = await waitFor(() => {
      const d = manager.getSnapshot().downloads.find((x) => x.id === histOther.items[0].id);
      return d?.status === 'pending_review' ? d : null;
    });
    assert.equal(histOtherReviewed.selectFile, undefined);
    assert.ok(histOtherReviewed.safety.signals.some((s) => s.id === 'selection_rebind'));
  } finally {
    await manager.shutdown().catch(() => {});
    await new Promise((r) => appServer.close(() => r()));
    await srv.close();
    await fs.rm(tmpDataDir, { recursive: true, force: true });
    await fs.rm(tmpDlDir, { recursive: true, force: true });
  }
});
