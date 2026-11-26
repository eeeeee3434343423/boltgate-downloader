import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import net from 'node:net';
import {
  Aria2ResultTableParser,
  Aria2Runner,
  buildAria2Args,
  expandSelectFileIndices,
} from '../dist-server/companion/aria2.js';
import { OriginRateLimiter } from '../dist-server/server/rateLimit.js';
import { benchmarkCandidates } from '../dist-server/companion/benchmarker.js';
import { redactText } from '../dist-server/companion/parser.js';
import { resolveBookSources } from '../dist-server/companion/resolver.js';
import { parseTorrentMetadata } from '../dist-server/companion/torrentParser.js';
import { createAppServer } from '../dist-server/server/app.js';
import { DownloadRunner } from '../dist-server/server/engine.js';
import { DownloadManager } from '../dist-server/server/manager.js';
import { getDefaultSettings } from '../dist-server/server/store.js';
import { TokenBucketThrottle } from '../dist-server/server/throttle.js';

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

function makeDeterministicPayload(sizeBytes) {
  const buf = Buffer.allocUnsafe(sizeBytes);
  for (let i = 0; i < sizeBytes; i++) {
    buf[i] = (i * 31 + (i >>> 8) * 17 + (i >>> 16) * 13) & 0xff;
  }
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  const md5 = crypto.createHash('md5').update(buf).digest('hex');
  return { buf, sha256, md5 };
}

function makeMinimalEpubPayload(padBytes = 256 * 1024) {
  // Minimal valid ZIP with PK\x03\x04 header + padding + PK\x05\x06 EOCD trailer
  const header = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]);
  const eocd = Buffer.alloc(22);
  Buffer.from([0x50, 0x4b, 0x05, 0x06]).copy(eocd, 0);
  const middle = Buffer.alloc(padBytes, 0x41);
  const buf = Buffer.concat([header, middle, eocd]);
  const md5 = crypto.createHash('md5').update(buf).digest('hex');
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  return { buf, md5, sha256 };
}

function bencode(val) {
  if (typeof val === 'number') return Buffer.from(`i${val}e`, 'ascii');
  if (Buffer.isBuffer(val)) return Buffer.concat([Buffer.from(`${val.length}:`, 'ascii'), val]);
  if (typeof val === 'string') {
    const b = Buffer.from(val, 'utf8');
    return Buffer.concat([Buffer.from(`${b.length}:`, 'ascii'), b]);
  }
  if (Array.isArray(val)) {
    return Buffer.concat([Buffer.from('l'), ...val.map(bencode), Buffer.from('e')]);
  }
  const keys = Object.keys(val).sort();
  const parts = [Buffer.from('d')];
  for (const k of keys) {
    parts.push(bencode(k), bencode(val[k]));
  }
  parts.push(Buffer.from('e'));
  return Buffer.concat(parts);
}

test('resolveBookSources resolves Tier 1 Fast API, custom mirrors, IPFS CIDs, redacts key, and stops cleanly on anti-bot gate', async () => {
  const md5 = '11223344556677889900aabbccddeeff';
  const cfMd5 = 'ffeeddccbbaa00998877665544332211';
  const cid = 'QmYwAPJzv5CZsnAzt8auVZRn3b7Q9s7d5y8i3v7o2x9p1q';
  const secretKey = 'secret_fast_key_999';

  const server = http.createServer((req, res) => {
    const u = new URL(req.url, `http://127.0.0.1:${port}`);
    if (u.pathname === '/dyn/api/fast_download.json') {
      if (u.searchParams.get('key') !== secretKey) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid key' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ download_url: `http://127.0.0.1:${port}/fast-cdn/book.epub` }));
      return;
    }

    if (u.pathname === `/md5/${md5}`) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`
        <html><head><title>Distributed Systems Book.epub</title></head>
        <body>
          <h1>Distributed Systems Book.epub</h1>
          <a href="/slow_download/${md5}/0">Slow Partner</a>
          <a href="http://127.0.0.1:${port}/external-mirror/${md5}.epub">Fast Mirror</a>
          <a href="https://dweb.link/ipfs/${cid}">IPFS Copy</a>
        </body></html>
      `);
      return;
    }

    if (u.pathname === `/md5/${cfMd5}`) {
      res.writeHead(403, { 'Content-Type': 'text/html' });
      res.end('<html><title>Just a moment...</title><div class="cf-browser-verification">Checking</div></html>');
      return;
    }

    res.writeHead(404);
    res.end();
  });

  const { port, close } = await listenServer(server);
  try {
    const settings = {
      ...getDefaultSettings(),
      annasArchiveBaseUrl: `http://127.0.0.1:${port}`,
      customMirrorUrls: [`http://127.0.0.1:${port}/custom/{md5}.epub`],
      ipfsGateways: [`http://127.0.0.1:${port}/ipfs/{cid}`],
    };

    const res = await resolveBookSources(
      { md5, sourcePageUrl: `http://127.0.0.1:${port}/md5/${md5}` },
      settings,
      { apiKey: secretKey, allowInsecureLoopbackForTests: true }
    );

    assert.equal(res.candidates[0].tier, 'fast_api');
    assert.ok(res.resolvedCids.includes(cid));
    assert.ok(res.candidates.some((c) => c.url.endsWith(`/custom/${md5}.epub`)));
    assert.ok(res.candidates[res.candidates.length - 1].isSlowPartner === true);

    // Ensure API key never leaks into candidate URLs or routing logs
    assert.equal(JSON.stringify(res).includes(secretKey), false);
    assert.equal(redactText(`https://a.org/api?md5=1&key=${secretKey}`).includes(secretKey), false);

    // Anti-bot challenge page stops cleanly without bypass and still expands custom mirrors
    const blockedRes = await resolveBookSources(
      { md5: cfMd5, sourcePageUrl: `http://127.0.0.1:${port}/md5/${cfMd5}` },
      settings,
      { allowInsecureLoopbackForTests: true }
    );
    assert.ok(blockedRes.routingLog.some((l) => l.message.includes('anti-bot')));
    assert.ok(blockedRes.candidates.some((c) => c.url.endsWith(`/custom/${cfMd5}.epub`)));
  } finally {
    await close();
  }
});

test('benchmarkCandidates races gateways concurrently, measures Range throughput, and rejects HTML traps', async () => {
  const { buf } = makeDeterministicPayload(256 * 1024);

  const server = http.createServer(async (req, res) => {
    if (req.url === '/err503') {
      res.writeHead(503);
      res.end('Busy');
      return;
    }
    if (req.url === '/html-trap.epub') {
      const htmlBody = '<!DOCTYPE html><html><body>Wait 30 seconds</body></html>';
      res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': Buffer.byteLength(htmlBody) });
      res.end(htmlBody);
      return;
    }
    if (req.url === '/slow.epub' || req.url === '/fast.epub') {
      if (req.url === '/slow.epub') await new Promise((r) => setTimeout(r, 120));
      const range = req.headers.range;
      if (range && range.startsWith('bytes=')) {
        const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
        const start = Number(s);
        const end = Math.min(buf.length - 1, e ? Number(e) : buf.length - 1);
        const slice = buf.subarray(start, end + 1);
        res.writeHead(206, {
          'Content-Type': 'application/epub+zip',
          'Content-Range': `bytes ${start}-${end}/${buf.length}`,
          'Content-Length': slice.length,
          'Accept-Ranges': 'bytes',
        });
        res.end(slice);
        return;
      }
      res.writeHead(200, { 'Content-Length': buf.length, 'Accept-Ranges': 'bytes' });
      res.end();
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const { port, close } = await listenServer(server);
  try {
    const results = await benchmarkCandidates([
      { url: `http://127.0.0.1:${port}/err503`, label: 'Dead GW', tier: 'ipfs', host: '127.0.0.1', priority: 50 },
      { url: `http://127.0.0.1:${port}/html-trap.epub`, label: 'Trap', tier: 'mirror', host: '127.0.0.1', priority: 60 },
      { url: `http://127.0.0.1:${port}/slow.epub`, label: 'Slow GW', tier: 'ipfs', host: '127.0.0.1', priority: 65 },
      { url: `http://127.0.0.1:${port}/fast.epub`, label: 'Fast GW', tier: 'ipfs', host: '127.0.0.1', priority: 65 },
    ]);

    assert.equal(results[0].ok, false);
    assert.equal(results[1].ok, false);
    assert.equal(results[1].isHtmlTrap, true);
    assert.equal(results[2].ok, true);
    assert.equal(results[3].ok, true);
    assert.equal(results[3].supportsRanges, true);
    assert.equal(results[3].totalBytes, buf.length);
    assert.ok(results[3].probeSpeedBps > results[2].probeSpeedBps);
  } finally {
    await close();
  }
});

test('DownloadRunner evicts slow mirror below speed floor, supports .part.meta resume, and aborts before rename on MD5 mismatch', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-evict-'));
  const { buf: payload, sha256: expectedSha256, md5: expectedMd5 } = makeDeterministicPayload(1536 * 1024);

  // Mirror A: throttled ~32 KB/s (16 KB every 500ms) -> triggers speed-floor eviction
  const slowServer = http.createServer(async (req, res) => {
    const range = req.headers.range ?? 'bytes=0-';
    const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
    const start = Number(s);
    const end = e ? Number(e) : payload.length - 1;
    const slice = payload.subarray(start, end + 1);
    res.writeHead(206, {
      'Content-Range': `bytes ${start}-${end}/${payload.length}`,
      'Content-Length': slice.length,
      'Accept-Ranges': 'bytes',
    });
    const chunk = 8 * 1024;
    let clientClosed = false;
    req.on('close', () => {
      clientClosed = true;
    });
    for (let pos = 0; pos < slice.length && !res.destroyed && !clientClosed; pos += chunk) {
      res.write(slice.subarray(pos, Math.min(slice.length, pos + chunk)));
      await new Promise((r) => setTimeout(r, 250));
    }
    if (!res.destroyed && !clientClosed) res.end();
  });

  // Mirror B: full local speed
  const fastServer = http.createServer((req, res) => {
    const range = req.headers.range ?? 'bytes=0-';
    const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
    const start = Number(s);
    const end = e ? Number(e) : payload.length - 1;
    const slice = payload.subarray(start, end + 1);
    res.writeHead(206, {
      'Content-Range': `bytes ${start}-${end}/${payload.length}`,
      'Content-Length': slice.length,
      'Accept-Ranges': 'bytes',
    });
    res.end(slice);
  });

  const slow = await listenServer(slowServer);
  const fast = await listenServer(fastServer);

  try {
    // 1. Live speed-floor eviction + pre-rename MD5 verification
    const savedPath1 = path.join(tmpDir, 'evicted-book.bin');
    const item1 = {
      id: crypto.randomUUID(),
      originalUrl: `http://127.0.0.1:${slow.port}/book.bin`,
      finalUrl: `http://127.0.0.1:${slow.port}/book.bin`,
      mirrorUrls: [
        `http://127.0.0.1:${slow.port}/book.bin`,
        `http://127.0.0.1:${fast.port}/book.bin`,
      ],
      filename: 'evicted-book.bin',
      destinationDir: tmpDir,
      savedPath: savedPath1,
      partPath: `${savedPath1}.part`,
      category: 'archive',
      status: 'queued',
      priority: 0,
      totalBytes: payload.length,
      downloadedBytes: 0,
      speedBps: 0,
      avgSpeedBps: 0,
      etaSeconds: null,
      connections: 4,
      supportsRanges: true,
      expectedMd5,
      segments: [],
      safety: null,
      routingLog: [],
      createdAt: Date.now(),
      userDeemedSafe: true,
    };

    await new DownloadRunner({
      item: item1,
      throttle: new TokenBucketThrottle(0),
      minSegmentBytes: 128 * 1024,
      minSpeedFloorBps: 250 * 1024,
      speedWindowMs: 400,
      evictionGraceMs: 350,
      onUpdate: () => {},
    }).run();

    assert.equal(item1.status, 'completed');
    assert.equal(item1.md5, expectedMd5);
    assert.equal(item1.md5Verified, true);
    assert.equal(item1.sha256, expectedSha256);
    assert.ok(
      item1.routingLog.some((r) => r.message.includes('switched')),
      'Expected routingLog to record speed-floor switch to fast mirror'
    );

    // 2. MD5 mismatch aborts BEFORE atomic rename (savedPath must not exist!)
    const savedPathBad = path.join(tmpDir, 'bad-md5.bin');
    const itemBad = {
      ...item1,
      id: crypto.randomUUID(),
      mirrorUrls: [`http://127.0.0.1:${fast.port}/book.bin`],
      filename: 'bad-md5.bin',
      savedPath: savedPathBad,
      partPath: `${savedPathBad}.part`,
      expectedMd5: 'f'.repeat(32),
      md5: undefined,
      md5Verified: undefined,
      segments: [],
      routingLog: [],
      status: 'queued',
    };

    await new DownloadRunner({
      item: itemBad,
      throttle: new TokenBucketThrottle(0),
      onUpdate: () => {},
    }).run();

    assert.equal(itemBad.status, 'failed');
    assert.equal(itemBad.md5Verified, false);
    await assert.rejects(fs.access(savedPathBad));

    // 3. .part.meta crash-safe resume (wipe in-memory segments to simulate crash)
    const savedPathMeta = path.join(tmpDir, 'crash-resume.bin');
    const itemResume = {
      ...item1,
      id: crypto.randomUUID(),
      mirrorUrls: [`http://127.0.0.1:${slow.port}/book.bin`],
      filename: 'crash-resume.bin',
      savedPath: savedPathMeta,
      partPath: `${savedPathMeta}.part`,
      expectedMd5,
      md5: undefined,
      md5Verified: undefined,
      segments: [],
      routingLog: [],
      status: 'queued',
    };
    const runnerA = new DownloadRunner({
      item: itemResume,
      throttle: new TokenBucketThrottle(0),
      minSegmentBytes: 128 * 1024,
      onUpdate: () => {},
    });
    const runA = runnerA.run();
    await new Promise((r) => setTimeout(r, 500));
    await runnerA.pause();
    await runA;

    assert.equal(itemResume.status, 'paused');
    // Simulate crash losing state.json segments while .part and .part.meta survived
    itemResume.segments = [];
    itemResume.downloadedBytes = 0;
    itemResume.mirrorUrls = [`http://127.0.0.1:${fast.port}/book.bin`];

    await new DownloadRunner({
      item: itemResume,
      throttle: new TokenBucketThrottle(0),
      minSegmentBytes: 128 * 1024,
      onUpdate: () => {},
    }).run();

    assert.equal(itemResume.status, 'completed');
    assert.equal(itemResume.md5Verified, true);
    assert.equal(itemResume.sha256, expectedSha256);
    assert.ok(
      itemResume.routingLog.some((r) => r.message.includes('.part.meta')),
      'Expected recovery log from .part.meta'
    );
  } finally {
    await slow.close();
    await fast.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('parseTorrentMetadata decodes single & multi-file torrents and buildAria2Args enforces injection safety', () => {
  const singleBuf = bencode({
    announce: 'https://tracker.example.org/announce',
    info: {
      name: 'CleanBook.epub',
      length: 123456,
      'piece length': 16384,
      pieces: Buffer.alloc(20, 0xaa),
    },
  });
  const singleMeta = parseTorrentMetadata(singleBuf);
  assert.equal(singleMeta.name, 'CleanBook.epub');
  assert.equal(singleMeta.totalBytes, 123456);
  assert.equal(singleMeta.files.length, 1);
  assert.equal(singleMeta.infoHash.length, 40);

  const multiBuf = bencode({
    info: {
      name: 'BookCollection',
      'piece length': 16384,
      pieces: Buffer.alloc(20, 0xbb),
      files: [
        { length: 1000, path: ['folder', 'first.pdf'] },
        { length: 2000, path: ['folder', 'second.epub'] },
      ],
    },
  });
  const multiMeta = parseTorrentMetadata(multiBuf);
  assert.equal(multiMeta.totalBytes, 3000);
  assert.equal(multiMeta.files.length, 2);
  assert.equal(multiMeta.files[1].index, 2);
  assert.equal(multiMeta.files[1].path, 'folder/second.epub');

  const args = buildAria2Args({
    uris: ['magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567'],
    dir: os.tmpdir(),
    selectFile: '2',
    isP2P: true,
  });
  assert.ok(args.includes('--select-file=2'));
  assert.ok(args.includes('--seed-time=0'));
  assert.ok(args.includes('--max-connection-per-server=16'));

  assert.throws(() =>
    buildAria2Args({ uris: ['--rpc-listen-all=true'], dir: os.tmpdir() })
  );
  assert.throws(() =>
    buildAria2Args({ uris: ['https://example.com/a.bin'], dir: os.tmpdir(), selectFile: '1;rm -rf' })
  );
});

test('End-to-end API flow: Anna MD5 URL -> Tier 1 Fast API -> Safety Gate -> Approve -> MD5 Verified & EPUB Valid', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-e2e-data-'));
  const tmpDownloadDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-e2e-dl-'));
  const { buf: epubBuf, md5: epubMd5, sha256: epubSha256 } = makeMinimalEpubPayload();
  const apiKey = 'e2e_secret_api_key_123';

  const mockOrigin = http.createServer((req, res) => {
    const u = new URL(req.url, `http://127.0.0.1:${originServer.port}`);
    if (u.pathname === '/dyn/api/fast_download.json') {
      assert.equal(u.searchParams.get('key'), apiKey);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          download_url: `http://127.0.0.1:${originServer.port}/cdn/clean-book.epub`,
        })
      );
      return;
    }
    if (u.pathname === `/md5/${epubMd5}`) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><title>Clean_Book.epub</title><body></body></html>');
      return;
    }
    if (u.pathname === '/cdn/clean-book.epub') {
      if (req.method === 'HEAD') {
        res.writeHead(200, {
          'Content-Type': 'application/epub+zip',
          'Content-Disposition': 'attachment; filename="Clean_Book.epub"',
          'Content-Length': epubBuf.length,
          'Accept-Ranges': 'bytes',
        });
        res.end();
        return;
      }
      const range = req.headers.range;
      if (range && range.startsWith('bytes=')) {
        const [, s, e] = range.match(/^bytes=(\d+)-(\d*)$/);
        const start = Number(s);
        const end = Math.min(epubBuf.length - 1, e ? Number(e) : epubBuf.length - 1);
        const slice = epubBuf.subarray(start, end + 1);
        res.writeHead(206, {
          'Content-Type': 'application/epub+zip',
          'Content-Disposition': 'attachment; filename="Clean_Book.epub"',
          'Content-Range': `bytes ${start}-${end}/${epubBuf.length}`,
          'Content-Length': slice.length,
          'Accept-Ranges': 'bytes',
        });
        res.end(slice);
        return;
      }
      res.writeHead(200, { 'Content-Length': epubBuf.length });
      res.end(epubBuf);
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const originServer = await listenServer(mockOrigin);
  const manager = new DownloadManager({
    dataDir: tmpDataDir,
    allowInsecureLoopbackProvider: true,
  });
  await manager.init();
  await manager.updateSettings({
    downloadDir: tmpDownloadDir,
    annasArchiveApiKey: apiKey,
    annasArchiveBaseUrl: `http://127.0.0.1:${originServer.port}`,
  });

  const appServer = createAppServer({ manager });
  await new Promise((resolve) => appServer.listen(0, '127.0.0.1', resolve));
  const appBase = `http://127.0.0.1:${appServer.address().port}`;
  const token = manager.getSessionToken();

  try {
    const inspectRes = await fetch(`${appBase}/api/inspect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-BoltGate-Session': token,
      },
      body: JSON.stringify({
        text: `http://127.0.0.1:${originServer.port}/md5/${epubMd5}`,
      }),
    });
    assert.equal(inspectRes.status, 200);
    const { items } = await inspectRes.json();
    const id = items[0].id;

    let reviewed;
    let latestState;
    for (let i = 0; i < 100; i++) {
      const stRes = await fetch(`${appBase}/api/state`, {
        headers: { 'X-BoltGate-Session': token },
      });
      const st = await stRes.json();
      latestState = st;
      const found = st.downloads.find((d) => d.id === id);
      if (found?.status === 'pending_review') {
        reviewed = found;
        break;
      }
      await new Promise((r) => setTimeout(r, 40));
    }

    assert.ok(reviewed, 'Item should finish resolving to pending_review');
    assert.equal(reviewed.expectedMd5, epubMd5);
    assert.equal(reviewed.sourceMode, 'fast_api');
    assert.equal(reviewed.sourceBadge, 'Fast Download API');
    assert.equal(latestState.settings.hasAnnasArchiveApiKey, true);
    assert.equal('annasArchiveApiKey' in latestState.settings, false);
    assert.equal(JSON.stringify(latestState).includes(apiKey), false);

    const diskStateRaw = await fs.readFile(path.join(tmpDataDir, 'state.json'), 'utf8');
    assert.equal(diskStateRaw.includes(apiKey), false);

    await fetch(`${appBase}/api/downloads/${id}/approve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-BoltGate-Session': token,
      },
      body: JSON.stringify({}),
    });

    let completed;
    for (let i = 0; i < 100; i++) {
      const stRes = await fetch(`${appBase}/api/state`, {
        headers: { 'X-BoltGate-Session': token },
      });
      const st = await stRes.json();
      const found = st.downloads.find((d) => d.id === id);
      if (found?.status === 'completed') {
        completed = found;
        break;
      }
      await new Promise((r) => setTimeout(r, 40));
    }

    assert.ok(completed, 'Item should complete');
    assert.equal(completed.md5, epubMd5);
    assert.equal(completed.md5Verified, true);
    assert.equal(completed.sha256, epubSha256);
    assert.equal(completed.integrity?.status, 'valid');
  } finally {
    await manager.shutdown().catch(() => {});
    await new Promise((r) => appServer.close(() => r()));
    await originServer.close();
    await fs.rm(tmpDataDir, { recursive: true, force: true });
    await fs.rm(tmpDownloadDir, { recursive: true, force: true });
  }
});

test('Aria2Runner enforces pinned torrent manifest/infoHash, multi-file selection & publication, single-source HTTP identity, serialized cancel, and observed throttle separation', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-aria2-test-'));
  const dlDir = path.join(tmpDir, 'downloads');
  await fs.mkdir(dlDir, { recursive: true });

  // Build deterministic multi-file torrent
  const file1Data = Buffer.from('FILE_ONE_TEXT_CONTENT_001');
  const file2Data = Buffer.from('FILE_TWO_TEXT_CONTENT_002_LONGER');
  const file3Data = Buffer.from('FILE_THREE_SKIPPED');
  const multiTorrentBuf = bencode({
    announce: 'https://tracker.example/announce',
    info: {
      name: 'BookPack',
      'piece length': 16384,
      pieces: Buffer.alloc(20, 0xaa),
      files: [
        { length: file1Data.length, path: ['sub', 'one.txt'] },
        { length: file2Data.length, path: ['sub', 'two.txt'] },
        { length: file3Data.length, path: ['sub', 'three.txt'] },
      ],
    },
  });
  const parsedMulti = parseTorrentMetadata(multiTorrentBuf);
  const pinnedTorrentPath = path.join(tmpDir, 'pinned.torrent');
  await fs.writeFile(pinnedTorrentPath, multiTorrentBuf);

  // Deterministic Node mock aria2c script (records invoked args & produces files or sleeps for cancel test)
  const argsLogPath = path.join(tmpDir, 'aria2-args.json');
  const mockAria2Script = path.join(tmpDir, 'mock-aria2.mjs');
  await fs.writeFile(
    mockAria2Script,
    `
import fs from 'node:fs/promises';
import path from 'node:path';

const args = process.argv.slice(2);
const dirArg = args.find((a) => a.startsWith('--dir=')).slice('--dir='.length);
const outArg = args.find((a) => a.startsWith('--out='))?.slice('--out='.length);
const selectArg = args.find((a) => a.startsWith('--select-file='))?.slice('--select-file='.length);
const sepIdx = args.indexOf('--');
const targets = sepIdx >= 0 ? args.slice(sepIdx + 1) : [];
await fs.writeFile(${JSON.stringify(argsLogPath)}, JSON.stringify({ args, targets, selectArg, outArg }), 'utf8');

if (process.env.MOCK_ARIA2_MODE === 'hang') {
  console.log('[#abc123 10KiB/1MiB(1%) CN:2 DL:10KiB ETA:1m]');
  setInterval(() => {}, 1000);
} else if (process.env.MOCK_ARIA2_MODE === 'missing_second') {
  const root = path.join(dirArg, 'BookPack', 'sub');
  await fs.mkdir(root, { recursive: true });
  await fs.writeFile(path.join(root, 'one.txt'), ${JSON.stringify(file1Data.toString('utf8'))});
  await fs.writeFile(path.join(dirArg, 'decoy.aria2'), 'control');
  process.exit(0);
} else if (process.env.MOCK_ARIA2_MODE === 'http') {
  console.log('[#http1 50KiB/100KiB(50%) CN:2 DL:50KiB ETA:1s]');
  await fs.writeFile(path.join(dirArg, outArg), 'HTTP_SINGLE_SOURCE_OK');
  process.exit(0);
} else {
  const root = path.join(dirArg, 'BookPack', 'sub');
  await fs.mkdir(root, { recursive: true });
  await fs.writeFile(path.join(root, 'one.txt'), ${JSON.stringify(file1Data.toString('utf8'))});
  await fs.writeFile(path.join(root, 'two.txt'), ${JSON.stringify(file2Data.toString('utf8'))});
  process.exit(0);
}
`,
    'utf8'
  );

  try {
    // 1. expandSelectFileIndices validates indices & ranges
    const selected12 = expandSelectFileIndices('1,2', parsedMulti.files);
    assert.deepEqual(selected12.map((f) => f.index), [1, 2]);
    assert.throws(() => expandSelectFileIndices('1,99', parsedMulti.files));

    // 2. Multi-file torrent publishes EVERY selected file (and uses pinned local .torrent file, not remote URL!)
    const multiItem = {
      id: 'aria2-multi-1',
      originalUrl: 'https://tracker.example/bookpack.torrent?token=SECRET_T',
      finalUrl: 'https://tracker.example/bookpack.torrent?token=SECRET_T',
      torrentUrl: 'https://tracker.example/bookpack.torrent?token=SECRET_T',
      torrentInfoHash: parsedMulti.infoHash,
      torrentRootName: parsedMulti.name,
      torrentFiles: parsedMulti.files,
      selectFile: '1,2',
      filename: 'BookPack',
      destinationDir: dlDir,
      savedPath: path.join(dlDir, 'BookPack'),
      partPath: '',
      category: 'document',
      status: 'queued',
      priority: 0,
      totalBytes: file1Data.length + file2Data.length,
      downloadedBytes: 0,
      speedBps: 0,
      avgSpeedBps: 0,
      etaSeconds: null,
      connections: 4,
      supportsRanges: true,
      segments: [],
      safety: null,
      routingLog: [],
      createdAt: Date.now(),
      userDeemedSafe: true,
    };

    // 2a. A raw plaintext manifest path is REJECTED outright (only decrypted vault bytes accepted)
    const plaintextPathItem = { ...multiItem, id: 'aria2-plaintext-rejected', status: 'queued', partPath: '', routingLog: [] };
    await new Aria2Runner({
      item: plaintextPathItem,
      binary: process.execPath,
      binaryArgsPrefix: [mockAria2Script],
      pinnedTorrentPath,
      onUpdate: () => {},
    }).run();
    assert.equal(plaintextPathItem.status, 'failed');
    assert.match(plaintextPathItem.error ?? '', /plaintext \.torrent manifest/i);

    const manifestScratchDir = path.join(tmpDir, 'vault-scratch');
    await new Aria2Runner({
      item: multiItem,
      binary: process.execPath,
      binaryArgsPrefix: [mockAria2Script],
      readManifestBytes: async () => multiTorrentBuf,
      manifestScratchDir,
      onUpdate: () => {},
    }).run();

    assert.equal(multiItem.status, 'completed');
    assert.equal(multiItem.publishedFiles?.length, 2);
    const invoked = JSON.parse(await fs.readFile(argsLogPath, 'utf8'));
    // Decrypted manifest is materialized ONLY in the private scratch dir (never in staging/downloads)
    assert.equal(invoked.targets.length, 1);
    assert.equal(path.dirname(invoked.targets[0]), path.resolve(manifestScratchDir));
    assert.equal(invoked.targets[0].startsWith(path.resolve(dlDir)), false);
    // ...and it is gone once the run settles
    await assert.rejects(fs.access(invoked.targets[0]));
    assert.deepEqual(await fs.readdir(manifestScratchDir), []);
    assert.equal(await fs.readFile(multiItem.publishedFiles[0], 'utf8'), file1Data.toString('utf8'));
    assert.equal(await fs.readFile(multiItem.publishedFiles[1], 'utf8'), file2Data.toString('utf8'));

    // 3. Missing second selected file MUST FAIL (never report success after publishing only 1 file or .aria2 sibling!)
    process.env.MOCK_ARIA2_MODE = 'missing_second';
    const partialItem = {
      ...multiItem,
      id: 'aria2-partial-fail',
      status: 'queued',
      partPath: '',
      publishedFiles: undefined,
      routingLog: [],
    };
    await new Aria2Runner({
      item: partialItem,
      binary: process.execPath,
      binaryArgsPrefix: [mockAria2Script],
      readManifestBytes: async () => multiTorrentBuf,
      manifestScratchDir,
      onUpdate: () => {},
    }).run();
    delete process.env.MOCK_ARIA2_MODE;
    assert.equal(partialItem.status, 'failed');
    assert.ok(partialItem.error?.includes('two.txt'));

    // 4. Tampered pinned torrent infoHash MUST FAIL before spawning aria2c
    const tamperedItem = {
      ...multiItem,
      id: 'aria2-bad-hash',
      torrentInfoHash: '0'.repeat(40),
      status: 'queued',
      partPath: '',
      routingLog: [],
    };
    await new Aria2Runner({
      item: tamperedItem,
      binary: process.execPath,
      binaryArgsPrefix: [mockAria2Script],
      readManifestBytes: async () => multiTorrentBuf,
      manifestScratchDir,
      onUpdate: () => {},
    }).run();
    assert.equal(tamperedItem.status, 'failed');
    assert.ok(tamperedItem.error?.includes('infoHash mismatch'));

    // 5. HTTP aria2c without trusted digest passes ONLY 1 HTTP source, and separates configured cap from observed throttling
    process.env.MOCK_ARIA2_MODE = 'http';
    let lastObservedTelemetry = null;
    const httpItem = {
      id: 'aria2-http-1',
      originalUrl: 'https://mirror-a.example/file.bin',
      finalUrl: 'https://mirror-a.example/file.bin',
      mirrorUrls: ['https://mirror-a.example/file.bin', 'https://mirror-b.example/file.bin'],
      filename: 'single-http.txt',
      destinationDir: dlDir,
      savedPath: path.join(dlDir, 'single-http.txt'),
      partPath: '',
      category: 'document',
      status: 'queued',
      priority: 0,
      totalBytes: Buffer.byteLength('HTTP_SINGLE_SOURCE_OK'),
      downloadedBytes: 0,
      speedBps: 0,
      avgSpeedBps: 0,
      etaSeconds: null,
      connections: 4,
      supportsRanges: true,
      segments: [],
      safety: null,
      routingLog: [],
      createdAt: Date.now(),
      userDeemedSafe: true,
    };
    await new Aria2Runner({
      item: httpItem,
      speedLimitKBps: 2048, // configured cap is 2 MB/s, mock reports 50 KiB/s -> NOT locally throttled!
      binary: process.execPath,
      binaryArgsPrefix: [mockAria2Script],
      onUpdate: (it) => {
        if (it.telemetry) lastObservedTelemetry = { ...it.telemetry };
      },
    }).run();
    delete process.env.MOCK_ARIA2_MODE;
    assert.equal(httpItem.status, 'completed');
    const httpInvoked = JSON.parse(await fs.readFile(argsLogPath, 'utf8'));
    assert.deepEqual(httpInvoked.targets, ['https://mirror-a.example/file.bin']);
    assert.equal(lastObservedTelemetry?.configuredLocalCapBps, 2048 * 1024);
    assert.equal(lastObservedTelemetry?.throttledByLocalCap, false);

    // 6. Serialized cancellation waits for full run lifecycle & removes owned staging directory
    process.env.MOCK_ARIA2_MODE = 'hang';
    const hangItem = {
      ...httpItem,
      id: 'aria2-cancel-1',
      filename: 'cancel-hang.txt',
      status: 'queued',
      partPath: '',
      routingLog: [],
    };
    const cancelRunner = new Aria2Runner({
      item: hangItem,
      binary: process.execPath,
      binaryArgsPrefix: [mockAria2Script],
      onUpdate: () => {},
    });
    const runPromise = cancelRunner.run();
    await new Promise((r) => setTimeout(r, 150));
    const stagingPathBeforeCancel = hangItem.partPath;
    assert.ok(stagingPathBeforeCancel);
    await cancelRunner.cancel(true);
    await runPromise;
    delete process.env.MOCK_ARIA2_MODE;
    await assert.rejects(fs.access(stagingPathBeforeCancel));
  } finally {
    delete process.env.MOCK_ARIA2_MODE;
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('Companion CLI prints one-time pairing code (not raw bearer token) and fails explicitly on EADDRINUSE port collision', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-cli-test-'));
  const entryPath = path.resolve(process.cwd(), 'dist-server', 'companion', 'index.js');

  // Bind a blocker server on an ephemeral port to trigger EADDRINUSE
  const blocker = await listenServer(http.createServer((_req, res) => res.end('busy')));

  try {
    // 1. Port collision exits non-zero with explicit stderr message
    const collisionRes = await new Promise((resolve) => {
      const child = spawn(process.execPath, [entryPath], {
        env: {
          ...process.env,
          HOST: '127.0.0.1',
          PORT: String(blocker.port),
          BOLTGATE_DATA_DIR: tmpDataDir,
          BOLTGATE_OPEN_BROWSER: '0',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stderr = '';
      child.stderr.on('data', (c) => {
        stderr += c.toString('utf8');
      });
      child.on('close', (code) => resolve({ code, stderr }));
    });
    assert.notEqual(collisionRes.code, 0);
    assert.ok(
      collisionRes.stderr.includes('already in use'),
      `Expected explicit port collision error, got: ${collisionRes.stderr}`
    );

    // 2. Clean startup prints one-time pairing code (`bgc_...`) and NEVER prints raw `.companion-token`
    const freeProbe = await listenServer(http.createServer());
    const freePort = freeProbe.port;
    await freeProbe.close();

    const startStdout = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [entryPath], {
        env: {
          ...process.env,
          HOST: '127.0.0.1',
          PORT: String(freePort),
          BOLTGATE_DATA_DIR: tmpDataDir,
          BOLTGATE_OPEN_BROWSER: '0',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let out = '';
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error(`Timed out waiting for companion startup. Output: ${out}`));
      }, 6000);
      child.stdout.on('data', (c) => {
        out += c.toString('utf8');
        if (out.includes('One-Time Pairing Code')) {
          clearTimeout(timer);
          child.kill('SIGTERM');
          setTimeout(() => child.kill('SIGKILL'), 800).unref();
        }
      });
      child.on('close', () => resolve(out));
    });

    const rawToken = (await fs.readFile(path.join(tmpDataDir, '.companion-token'), 'utf8')).trim();
    assert.ok(startStdout.includes('bgc_'), 'Expected one-time pairing code in stdout');
    assert.equal(
      startStdout.includes(rawToken),
      false,
      'Raw reusable bearer token must NEVER be printed to stdout'
    );

    // 3. Non-loopback HOST=0.0.0.0 MUST exit non-zero and refuse to bind
    const nonLoopbackRes = await new Promise((resolve) => {
      const child = spawn(process.execPath, [entryPath], {
        env: {
          ...process.env,
          HOST: '0.0.0.0',
          PORT: String(freePort),
          BOLTGATE_DATA_DIR: tmpDataDir,
          BOLTGATE_OPEN_BROWSER: '0',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stderr = '';
      child.stderr.on('data', (c) => {
        stderr += c.toString('utf8');
      });
      child.on('close', (code) => resolve({ code, stderr }));
    });
    assert.notEqual(nonLoopbackRes.code, 0);
    assert.ok(
      nonLoopbackRes.stderr.includes('loopback'),
      `Expected loopback bind rejection error, got: ${nonLoopbackRes.stderr}`
    );
  } finally {
    await blocker.close();
    await fs.rm(tmpDataDir, { recursive: true, force: true });
  }
});

test('Aria2Runner Pass 2: encrypted manifests, multi-file P2P digest check, magnet |OK| allowlist, batch rollback, and unknown-length HTTP stream', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-aria2-p2-'));
  const dlDir = path.join(tmpDir, 'downloads');
  await fs.mkdir(dlDir, { recursive: true });

  const file1Data = Buffer.from('MULTI_FILE_ONE_PAYLOAD_AAA');
  const file2Data = Buffer.from('MULTI_FILE_TWO_PAYLOAD_BBB_TARGET');
  const file2Md5 = crypto.createHash('md5').update(file2Data).digest('hex');

  const multiTorrentBuf = bencode({
    announce: 'https://private-tracker.example/announce?passkey=SECRET_TRACKER_KEY_99',
    info: {
      name: 'DigestPack',
      'piece length': 16384,
      pieces: Buffer.alloc(20, 0xcc),
      files: [
        { length: file1Data.length, path: ['docs', 'alpha.txt'] },
        { length: file2Data.length, path: ['docs', 'beta.txt'] },
      ],
    },
  });
  const parsedMulti = parseTorrentMetadata(multiTorrentBuf);

  const mockScript = path.join(tmpDir, 'mock-aria2-p2.mjs');
  await fs.writeFile(
    mockScript,
    `
import fs from 'node:fs/promises';
import path from 'node:path';

const args = process.argv.slice(2);
const dirArg = args.find((a) => a.startsWith('--dir=')).slice('--dir='.length);
const outArg = args.find((a) => a.startsWith('--out='))?.slice('--out='.length);
const sepIdx = args.indexOf('--');
const targets = sepIdx >= 0 ? args.slice(sepIdx + 1) : [];

if (process.env.MOCK_P2_MODE === 'magnet_extra') {
  const okFile = path.join(dirArg, 'selected.txt');
  const extraFile = path.join(dirArg, 'unselected_decoy.txt');
  await fs.writeFile(okFile, 'SELECTED_MAGNET_BOOK');
  await fs.writeFile(extraFile, 'UNSELECTED_DECOY_BOOK');
  console.log(\`123456|OK  | 1.2MiB/s|\${okFile}\`);
  process.exit(0);
} else if (process.env.MOCK_P2_MODE === 'http_unknown_len') {
  // Emit rounded progress line larger/different than actual exact stream length
  console.log('[#u1 50KiB/100KiB(50%) CN:1 DL:50KiB ETA:1s]');
  await fs.writeFile(path.join(dirArg, outArg), 'EXACT_UNKNOWN_LEN_STREAM');
  process.exit(0);
} else {
  // Verify decrypted manifest target exists during run
  await fs.access(targets[0]);
  const root = path.join(dirArg, 'DigestPack', 'docs');
  await fs.mkdir(root, { recursive: true });
  await fs.writeFile(path.join(root, 'alpha.txt'), ${JSON.stringify(file1Data.toString('utf8'))});
  await fs.writeFile(path.join(root, 'beta.txt'), ${JSON.stringify(file2Data.toString('utf8'))});
  process.exit(0);
}
`,
    'utf8'
  );

  try {
    // 1. Multi-file torrent with mismatched job-level expectedMd5 MUST fail and purge staging
    const badDigestItem = {
      id: 'p2-bad-digest',
      originalUrl: 'https://tracker.example/pack.torrent',
      finalUrl: 'https://tracker.example/pack.torrent',
      torrentUrl: 'https://tracker.example/pack.torrent',
      torrentInfoHash: parsedMulti.infoHash,
      torrentRootName: parsedMulti.name,
      torrentFiles: parsedMulti.files,
      selectFile: '1,2',
      expectedMd5: '0'.repeat(32),
      filename: 'DigestPack',
      destinationDir: dlDir,
      savedPath: path.join(dlDir, 'DigestPack'),
      partPath: '',
      category: 'document',
      status: 'queued',
      priority: 0,
      totalBytes: file1Data.length + file2Data.length,
      downloadedBytes: 0,
      speedBps: 0,
      avgSpeedBps: 0,
      etaSeconds: null,
      connections: 4,
      supportsRanges: true,
      segments: [],
      safety: null,
      routingLog: [],
      createdAt: Date.now(),
      userDeemedSafe: true,
    };
    await new Aria2Runner({
      item: badDigestItem,
      binary: process.execPath,
      binaryArgsPrefix: [mockScript],
      readManifestBytes: async () => multiTorrentBuf,
      onUpdate: () => {},
    }).run();
    assert.equal(badDigestItem.status, 'failed');
    assert.equal(badDigestItem.md5Verified, false);
    assert.ok(badDigestItem.error?.includes('digest check failed'));
    assert.equal((await fs.readdir(dlDir)).length, 0);

    // 2. Multi-file torrent with matching expectedMd5 (via encrypted readManifestBytes) succeeds
    const goodDigestItem = {
      ...badDigestItem,
      id: 'p2-good-digest',
      expectedMd5: file2Md5,
      md5Verified: undefined,
      status: 'queued',
      partPath: '',
      error: undefined,
      routingLog: [],
    };
    await new Aria2Runner({
      item: goodDigestItem,
      binary: process.execPath,
      binaryArgsPrefix: [mockScript],
      readManifestBytes: async () => multiTorrentBuf,
      onUpdate: () => {},
    }).run();
    assert.equal(goodDigestItem.status, 'completed');
    assert.equal(goodDigestItem.md5Verified, true);
    assert.equal(goodDigestItem.publishedFiles?.length, 2);

    // 3. Multi-file publish rollback: failure on 2nd file rolls back 1st published file & keeps stagingDir intact!
    const rollbackDlDir = path.join(tmpDir, 'rollback-dl');
    await fs.mkdir(rollbackDlDir, { recursive: true });
    let linkCalls = 0;
    const rollbackItem = {
      ...badDigestItem,
      id: 'p2-rollback',
      expectedMd5: undefined,
      md5Verified: undefined,
      destinationDir: rollbackDlDir,
      savedPath: path.join(rollbackDlDir, 'DigestPack'),
      status: 'queued',
      partPath: '',
      error: undefined,
      publishedFiles: undefined,
      routingLog: [],
    };
    await new Aria2Runner({
      item: rollbackItem,
      binary: process.execPath,
      binaryArgsPrefix: [mockScript],
      readManifestBytes: async () => multiTorrentBuf,
      publishFsOps: {
        link: async (src, dst) => {
          linkCalls++;
          if (linkCalls === 1) return fs.link(src, dst);
          throw Object.assign(new Error('hard link failed on second file'), { code: 'ENOTSUP' });
        },
      },
      onUpdate: () => {},
    }).run();
    assert.equal(rollbackItem.status, 'failed');
    // 1st file must have been rolled back (no published files left in rollbackDlDir except staging dir)
    const entriesAfterRollback = await fs.readdir(rollbackDlDir);
    assert.equal(entriesAfterRollback.includes('alpha.txt'), false, 'First published file must be rolled back');
    assert.ok(rollbackItem.partPath, 'Staging dir path must remain preserved for recovery');
    await fs.access(rollbackItem.partPath);

    // 4. Unmanifested magnet publishes ONLY aria2 |OK| reported files (ignores unselected decoy file)
    process.env.MOCK_P2_MODE = 'magnet_extra';
    const magDlDir = path.join(tmpDir, 'magnet-dl');
    await fs.mkdir(magDlDir, { recursive: true });
    const magnetItem = {
      ...badDigestItem,
      id: 'p2-magnet-ok',
      originalUrl: 'magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567',
      finalUrl: 'magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567',
      magnetUri: 'magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567',
      torrentUrl: undefined,
      torrentInfoHash: undefined,
      torrentRootName: undefined,
      torrentFiles: undefined,
      selectFile: undefined,
      expectedMd5: undefined,
      destinationDir: magDlDir,
      savedPath: path.join(magDlDir, 'magnet-download'),
      status: 'queued',
      partPath: '',
      error: undefined,
      publishedFiles: undefined,
      routingLog: [],
    };
    await new Aria2Runner({
      item: magnetItem,
      binary: process.execPath,
      binaryArgsPrefix: [mockScript],
      onUpdate: () => {},
    }).run();
    delete process.env.MOCK_P2_MODE;
    assert.equal(magnetItem.status, 'completed');
    assert.equal(magnetItem.publishedFiles?.length, 1);
    assert.ok(magnetItem.publishedFiles[0].endsWith('selected.txt'));
    assert.equal((await fs.readdir(magDlDir)).includes('unselected_decoy.txt'), false);

    // 5. Unknown-length HTTP stream with rounded CLI progress (50KiB/100KiB) completes without false size mismatch
    process.env.MOCK_P2_MODE = 'http_unknown_len';
    const httpDlDir = path.join(tmpDir, 'http-dl');
    await fs.mkdir(httpDlDir, { recursive: true });
    const unknownLenItem = {
      ...magnetItem,
      id: 'p2-http-unknown',
      originalUrl: 'https://mirror.example/unknown-len.txt',
      finalUrl: 'https://mirror.example/unknown-len.txt',
      magnetUri: undefined,
      filename: 'unknown-len.txt',
      destinationDir: httpDlDir,
      savedPath: path.join(httpDlDir, 'unknown-len.txt'),
      totalBytes: null,
      status: 'queued',
      partPath: '',
      error: undefined,
      publishedFiles: undefined,
      routingLog: [],
    };
    await new Aria2Runner({
      item: unknownLenItem,
      binary: process.execPath,
      binaryArgsPrefix: [mockScript],
      onUpdate: () => {},
    }).run();
    delete process.env.MOCK_P2_MODE;
    assert.equal(unknownLenItem.status, 'completed');
    assert.equal(unknownLenItem.totalBytes, Buffer.byteLength('EXACT_UNKNOWN_LEN_STREAM'));
    assert.equal(await fs.readFile(unknownLenItem.savedPath, 'utf8'), 'EXACT_UNKNOWN_LEN_STREAM');
  } finally {
    delete process.env.MOCK_P2_MODE;
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Codex review round 14 — aria2c result tables, zero-byte entries, digest-to-file binding,
// nested batch rollback + journal recovery, unproven HTTP identity, cooldown recheck, IPv6 CLI
// ---------------------------------------------------------------------------

function baseAria2Item(overrides) {
  return {
    id: crypto.randomUUID(),
    originalUrl: '',
    finalUrl: '',
    filename: 'job',
    destinationDir: '',
    savedPath: '',
    partPath: '',
    category: 'document',
    status: 'queued',
    priority: 0,
    totalBytes: null,
    downloadedBytes: 0,
    speedBps: 0,
    avgSpeedBps: 0,
    etaSeconds: null,
    connections: 4,
    supportsRanges: true,
    segments: [],
    safety: null,
    routingLog: [],
    createdAt: Date.now(),
    userDeemedSafe: true,
    ...overrides,
  };
}

test('Aria2ResultTableParser parses REAL --download-result=full tables (percent column, continuation rows, ANSI, ERR/partial rows, [MEMORY] metadata) and magnet runs publish only fully completed files', async () => {
  const parser = new Aria2ResultTableParser();
  const table = [
    '',
    'Download Results:',
    'gid   |stat|avg speed  |  %|path/URI',
    '======+====+===========+===+===================================================',
    '7ae1c0|OK  |       0B/s|  -|[MEMORY][METADATA]Pack',
    '2089b0|\u001b[1;32mOK\u001b[0m  |   1.4MiB/s|100|/dl/stage/Pack/a.txt',
    '      |    |           |100|/dl/stage/Pack/sub/b.txt',
    '      |    |           | 42|/dl/stage/Pack/sub/partial.txt',
    '      |    |           |  -|/dl/stage/Pack/empty.txt',
    'd1e2f3|ERR |   1.0KiB/s| 12|/dl/stage/Other/x.bin',
    '      |    |           |100|/dl/stage/Other/y.bin',
    '',
    'Status Legend:',
    '(OK):download completed.',
    '(ERR):error occurred.',
  ];
  for (const line of table) parser.feedLine(line);
  assert.deepEqual(parser.completedPaths(), [
    '/dl/stage/Pack/a.txt',
    '/dl/stage/Pack/sub/b.txt',
    '/dl/stage/Pack/empty.txt',
  ]);
  const partial = parser.records.find((r) => r.path.endsWith('partial.txt'));
  assert.equal(partial.percent, 42);
  assert.equal(partial.gid, '2089b0', 'continuation rows inherit the head row gid');
  assert.equal(parser.records.find((r) => r.path.endsWith('y.bin')).status, 'ERR', 'continuation rows inherit status');

  // Default (no % column) layout is still understood
  const legacy = new Aria2ResultTableParser();
  legacy.feedLine('gid   |stat|avg speed  |path/URI');
  legacy.feedLine('abc123|OK  |   2.0MiB/s|/dl/stage/one.iso');
  assert.deepEqual(legacy.completedPaths(), ['/dl/stage/one.iso']);

  // End-to-end: magnet run publishes EXACTLY the fully completed files from a real table
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-aria2-table-'));
  const dlDir = path.join(tmpDir, 'dl');
  await fs.mkdir(dlDir, { recursive: true });
  const mock = path.join(tmpDir, 'mock-table.mjs');
  await fs.writeFile(
    mock,
    `
import fs from 'node:fs/promises';
import path from 'node:path';
const args = process.argv.slice(2);
const dir = args.find((a) => a.startsWith('--dir=')).slice(6);
const files = { 'Pack/a.txt': 'AAA', 'Pack/sub/b.txt': 'BBBB', 'Pack/sub/partial.txt': 'PARTIAL', 'Pack/empty.txt': '', 'Other/x.bin': 'ERRDATA' };
for (const [rel, body] of Object.entries(files)) {
  await fs.mkdir(path.dirname(path.join(dir, rel)), { recursive: true });
  await fs.writeFile(path.join(dir, rel), body);
}
const p = (rel) => path.join(dir, rel);
const out = [
  '[#2089b0 3.0KiB/3.0KiB(100%) CN:1 SD:2 DL:1.0KiB]',
  '',
  'Download Results:',
  'gid   |stat|avg speed  |  %|path/URI',
  '======+====+===========+===+=============',
  '7ae1c0|OK  |       0B/s|  -|[MEMORY][METADATA]Pack',
  '2089b0|OK  |   1.4MiB/s|100|' + p('Pack/a.txt'),
  '      |    |           |100|' + p('Pack/sub/b.txt'),
  '      |    |           | 42|' + p('Pack/sub/partial.txt'),
  '      |    |           |  -|' + p('Pack/empty.txt'),
  'd1e2f3|ERR |   1.0KiB/s| 12|' + p('Other/x.bin'),
  '',
  'Status Legend:',
  '(OK):download completed.',
];
// Emit in awkward chunk boundaries to exercise line reassembly
const text = out.join('\\n') + '\\n';
for (let i = 0; i < text.length; i += 37) process.stdout.write(text.slice(i, i + 37));
process.exit(0);
`,
    'utf8'
  );
  try {
    const magnet = 'magnet:?xt=urn:btih:00112233445566778899aabbccddeeff00112233';
    const item = baseAria2Item({
      originalUrl: magnet,
      finalUrl: magnet,
      magnetUri: magnet,
      filename: 'MagPack',
      destinationDir: dlDir,
      savedPath: path.join(dlDir, 'MagPack'),
    });
    await new Aria2Runner({ item, binary: process.execPath, binaryArgsPrefix: [mock], onUpdate: () => {} }).run();
    assert.equal(item.status, 'completed', item.error);
    const names = item.publishedFiles.map((f) => path.basename(f)).sort();
    assert.deepEqual(names, ['a.txt', 'b.txt', 'empty.txt']);
    for (const f of item.publishedFiles) {
      assert.equal(f.includes('partial') || f.includes('x.bin'), false);
    }
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('Aria2Runner enforces exact sizes for zero-byte manifest entries, binds job digests to the matched manifest file, and journals nested multi-file publication with verified rollback + recovery', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-aria2-r14-'));
  const mock = path.join(tmpDir, 'mock-r14.mjs');
  await fs.writeFile(
    mock,
    `
import fs from 'node:fs/promises';
import path from 'node:path';
const args = process.argv.slice(2);
const dir = args.find((a) => a.startsWith('--dir=')).slice(6);
const spec = JSON.parse(process.env.MOCK_R14_FILES || '{}');
for (const [rel, body] of Object.entries(spec)) {
  await fs.mkdir(path.dirname(path.join(dir, rel)), { recursive: true });
  await fs.writeFile(path.join(dir, rel), body);
}
process.exit(0);
`,
    'utf8'
  );
  const runWith = async (item, files, extra = {}) => {
    process.env.MOCK_R14_FILES = JSON.stringify(files);
    try {
      await new Aria2Runner({
        item,
        binary: process.execPath,
        binaryArgsPrefix: [mock],
        readManifestBytes: async () => extra.manifest,
        manifestScratchDir: path.join(tmpDir, 'scratch'),
        publishFsOps: extra.publishFsOps,
        onUpdate: () => {},
      }).run();
    } finally {
      delete process.env.MOCK_R14_FILES;
    }
  };
  const torrentItem = (manifest, dlDir, overrides = {}) => {
    const parsed = parseTorrentMetadata(manifest);
    return baseAria2Item({
      originalUrl: 'https://tracker.example/p.torrent',
      finalUrl: 'https://tracker.example/p.torrent',
      torrentUrl: 'https://tracker.example/p.torrent',
      torrentInfoHash: parsed.infoHash,
      torrentRootName: parsed.name,
      torrentFiles: parsed.files,
      filename: parsed.name,
      destinationDir: dlDir,
      savedPath: path.join(dlDir, parsed.name),
      totalBytes: parsed.totalBytes,
      ...overrides,
    });
  };

  try {
    // 1. Zero-byte manifest entries get an EXACT size check (non-empty file -> fail)
    const zeroManifest = bencode({
      info: {
        name: 'ZeroPack',
        'piece length': 16384,
        pieces: Buffer.alloc(20, 0x55),
        files: [
          { length: 5, path: ['z', 'data.txt'] },
          { length: 0, path: ['z', 'empty.flag'] },
        ],
      },
    });
    const zeroDl1 = path.join(tmpDir, 'zero-1');
    await fs.mkdir(zeroDl1, { recursive: true });
    const zeroBad = torrentItem(zeroManifest, zeroDl1);
    await runWith(zeroBad, { 'ZeroPack/z/data.txt': 'DATA5', 'ZeroPack/z/empty.flag': 'NOT_EMPTY' }, { manifest: zeroManifest });
    assert.equal(zeroBad.status, 'failed');
    assert.match(zeroBad.error, /empty\.flag.*size mismatch/i);
    assert.equal((await fs.readdir(zeroDl1)).filter((n) => !n.startsWith('.boltgate-')).length, 0, 'nothing published');

    //    ...and a missing empty entry is materialized exactly (0 bytes), never skipped
    const zeroDl2 = path.join(tmpDir, 'zero-2');
    await fs.mkdir(zeroDl2, { recursive: true });
    const zeroOk = torrentItem(zeroManifest, zeroDl2);
    await runWith(zeroOk, { 'ZeroPack/z/data.txt': 'DATA5' }, { manifest: zeroManifest });
    assert.equal(zeroOk.status, 'completed', zeroOk.error);
    const emptyPublished = zeroOk.publishedFiles.find((f) => f.endsWith('empty.flag'));
    assert.ok(emptyPublished);
    assert.equal((await fs.stat(emptyPublished)).size, 0);

    // 2. Job-level digest is BOUND to the matched manifest file (savedPath/open/re-verify target)
    const alpha = 'ALPHA_FILE_CONTENT_0001';
    const beta = 'BETA_FILE_CONTENT_TARGET_02';
    const betaSha = crypto.createHash('sha256').update(beta).digest('hex');
    const digestManifest = bencode({
      info: {
        name: 'DigestPack',
        'piece length': 16384,
        pieces: Buffer.alloc(20, 0x66),
        files: [
          { length: alpha.length, path: ['docs', 'alpha.txt'] },
          { length: beta.length, path: ['docs', 'beta.txt'] },
        ],
      },
    });
    const digestDl = path.join(tmpDir, 'digest');
    await fs.mkdir(digestDl, { recursive: true });
    const digestItem = torrentItem(digestManifest, digestDl, { expectedSha256: betaSha });
    await runWith(digestItem, { 'DigestPack/docs/alpha.txt': alpha, 'DigestPack/docs/beta.txt': beta }, { manifest: digestManifest });
    assert.equal(digestItem.status, 'completed', digestItem.error);
    assert.equal(digestItem.verifiedHashMatch, true);
    assert.equal(digestItem.verifiedFileIndex, 2);
    assert.equal(digestItem.verifiedFilePath, 'docs/beta.txt');
    assert.ok(digestItem.savedPath.endsWith(path.join('docs', 'beta.txt')), 'savedPath must be the verified file, not publishedFiles[0]');
    assert.equal(digestItem.sha256, betaSha);
    const onDisk = crypto.createHash('sha256').update(await fs.readFile(digestItem.savedPath)).digest('hex');
    assert.equal(onDisk, digestItem.sha256, 'displayed/re-verified file == digest-matched file');

    // 3. Nested multi-file batch: publish failure + rollback failure is SURFACED, leftovers stay
    //    tracked, journal + staging are preserved, and the next run recovers and completes cleanly.
    const nestedManifest = bencode({
      info: {
        name: 'NestPack',
        'piece length': 16384,
        pieces: Buffer.alloc(20, 0x77),
        files: [
          { length: 3, path: ['a', 'b', 'c.txt'] },
          { length: 4, path: ['a', 'd.txt'] },
          { length: 5, path: ['e.txt'] },
        ],
      },
    });
    const nestedFiles = { 'NestPack/a/b/c.txt': 'CCC', 'NestPack/a/d.txt': 'DDDD', 'NestPack/e.txt': 'EEEEE' };
    const nestDl = path.join(tmpDir, 'nested');
    await fs.mkdir(nestDl, { recursive: true });
    const nestItem = torrentItem(nestedManifest, nestDl);
    let linkCalls = 0;
    await runWith(nestItem, nestedFiles, {
      manifest: nestedManifest,
      publishFsOps: {
        link: async (src, dst) => {
          linkCalls += 1;
          if (linkCalls <= 2) return fs.link(src, dst);
          throw Object.assign(new Error('hard link refused on third file'), { code: 'ENOTSUP' });
        },
        unlink: async () => {
          throw Object.assign(new Error('EPERM: published file locked'), { code: 'EPERM' });
        },
      },
    });
    assert.equal(nestItem.status, 'failed');
    assert.match(nestItem.error, /rollback INCOMPLETE/);
    assert.equal(nestItem.publishedFiles?.length, 2, 'leftover outputs stay tracked');
    for (const leftover of nestItem.publishedFiles) await fs.access(leftover);
    const journalPath = path.join(nestItem.partPath, '.boltgate-publish-journal.json');
    const journal = JSON.parse(await fs.readFile(journalPath, 'utf8'));
    assert.equal(journal.entries.filter((e) => e.state === 'published').length, 2);
    assert.ok(journal.createdDirs.some((d) => d.endsWith(path.join('NestPack', 'a', 'b'))), 'nested dirs journaled');

    // Recovery run: journal rolled back (identity-checked), then the full batch publishes once
    nestItem.status = 'queued';
    nestItem.error = undefined;
    await runWith(nestItem, nestedFiles, { manifest: nestedManifest });
    assert.equal(nestItem.status, 'completed', nestItem.error);
    assert.equal(nestItem.publishedFiles.length, 3);
    const listing = [];
    const walk = async (d) => {
      for (const e of await fs.readdir(d, { withFileTypes: true })) {
        const full = path.join(d, e.name);
        if (e.isDirectory()) await walk(full);
        else listing.push(path.relative(nestDl, full).replace(/\\/g, '/'));
      }
    };
    await walk(nestDl);
    assert.deepEqual(listing.sort(), ['NestPack/a/b/c.txt', 'NestPack/a/d.txt', 'NestPack/e.txt'], 'no duplicates, no untracked partial outputs');

    // 4. Rollback that succeeds removes published files AND the nested dirs this batch created
    const cleanDl = path.join(tmpDir, 'nested-clean');
    await fs.mkdir(cleanDl, { recursive: true });
    const cleanItem = torrentItem(nestedManifest, cleanDl);
    let cleanLinks = 0;
    await runWith(cleanItem, nestedFiles, {
      manifest: nestedManifest,
      publishFsOps: {
        link: async (src, dst) => {
          cleanLinks += 1;
          if (cleanLinks <= 2) return fs.link(src, dst);
          throw Object.assign(new Error('hard link refused'), { code: 'ENOTSUP' });
        },
      },
    });
    assert.equal(cleanItem.status, 'failed');
    assert.doesNotMatch(cleanItem.error, /INCOMPLETE/);
    assert.deepEqual((await fs.readdir(cleanDl)).filter((n) => !n.startsWith('.boltgate-')), [], 'files and created dirs rolled back');
    await assert.rejects(fs.access(path.join(cleanItem.partPath, '.boltgate-publish-journal.json')));
  } finally {
    delete process.env.MOCK_R14_FILES;
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('Aria2Runner HTTP: unproven identity forces a single uninterrupted stream from offset 0 (purges stale partial output), digest unlocks multi-source, and shared cooldowns are re-checked right before spawn', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-aria2-http14-'));
  const dlDir = path.join(tmpDir, 'dl');
  await fs.mkdir(dlDir, { recursive: true });
  const logPath = path.join(tmpDir, 'http14.json');
  const mock = path.join(tmpDir, 'mock-http14.mjs');
  await fs.writeFile(
    mock,
    `
import fs from 'node:fs/promises';
import path from 'node:path';
const spawnedAt = Date.now();
const args = process.argv.slice(2);
const dir = args.find((a) => a.startsWith('--dir=')).slice(6);
const out = args.find((a) => a.startsWith('--out=')).slice(6);
const sep = args.indexOf('--');
const stalePresent = await fs.access(path.join(dir, out)).then(() => true).catch(() => false);
await fs.writeFile(${JSON.stringify(logPath)}, JSON.stringify({ args, targets: args.slice(sep + 1), stalePresent, spawnedAt }));
await fs.writeFile(path.join(dir, out), 'HTTP14_BODY');
process.exit(0);
`,
    'utf8'
  );
  try {
    // Seed an OWNED staging dir holding a stale partial output + control file from an earlier attempt
    const jobId = 'http14-unproven';
    const stagingDir = path.join(dlDir, `.boltgate-aria2-${jobId}`);
    await fs.mkdir(stagingDir, { recursive: true });
    await fs.writeFile(path.join(stagingDir, '.boltgate-owner.json'), JSON.stringify({ jobId }));
    await fs.writeFile(path.join(stagingDir, 'h14.txt'), 'STALE_PARTIAL');
    await fs.writeFile(path.join(stagingDir, 'h14.txt.aria2'), 'control');
    const unproven = baseAria2Item({
      id: jobId,
      originalUrl: 'https://m1.example/h14.txt',
      finalUrl: 'https://m1.example/h14.txt',
      mirrorUrls: ['https://m1.example/h14.txt', 'https://m2.example/h14.txt'],
      filename: 'h14.txt',
      destinationDir: dlDir,
      savedPath: path.join(dlDir, 'h14.txt'),
      partPath: stagingDir,
      connections: 8,
      totalBytes: Buffer.byteLength('HTTP14_BODY'),
    });
    await new Aria2Runner({ item: unproven, binary: process.execPath, binaryArgsPrefix: [mock], onUpdate: () => {} }).run();
    assert.equal(unproven.status, 'completed', unproven.error);
    const log1 = JSON.parse(await fs.readFile(logPath, 'utf8'));
    for (const flag of ['--split=1', '--max-connection-per-server=1', '--continue=false', '--max-tries=1']) {
      assert.ok(log1.args.includes(flag), `unproven identity must pass ${flag}`);
    }
    assert.deepEqual(log1.targets, ['https://m1.example/h14.txt'], 'single source only');
    assert.equal(log1.stalePresent, false, 'stale partial output purged -> restart from offset 0');

    // Trusted digest: multi-source + configured split allowed
    const body = 'HTTP14_BODY';
    const proven = baseAria2Item({
      originalUrl: 'https://m1.example/h14b.txt',
      finalUrl: 'https://m1.example/h14b.txt',
      mirrorUrls: ['https://m1.example/h14b.txt', 'https://m2.example/h14b.txt'],
      filename: 'h14b.txt',
      destinationDir: dlDir,
      savedPath: path.join(dlDir, 'h14b.txt'),
      connections: 8,
      totalBytes: Buffer.byteLength(body),
      expectedSha256: crypto.createHash('sha256').update(body).digest('hex'),
    });
    await new Aria2Runner({ item: proven, binary: process.execPath, binaryArgsPrefix: [mock], onUpdate: () => {} }).run();
    assert.equal(proven.status, 'completed', proven.error);
    const log2 = JSON.parse(await fs.readFile(logPath, 'utf8'));
    assert.equal(log2.targets.length, 2);
    assert.ok(log2.args.includes('--split=8'));
    assert.ok(log2.args.includes('--continue=true'));

    // Shared origin cooldown is re-read right before spawn (a concurrent Retry-After extends it)
    const rl = new OriginRateLimiter();
    const coolUrl = 'https://m1.example/h14c.txt';
    const coolKey = new URL(coolUrl).origin.toLowerCase();
    rl['origins'].set(coolKey, { origin: coolKey, cooldownUntil: Date.now() + 250, consecutiveRateLimits: 0, maxWorkersCap: 1 }); // short initial cooldown
    const cooled = baseAria2Item({
      originalUrl: coolUrl,
      finalUrl: coolUrl,
      filename: 'h14c.txt',
      destinationDir: dlDir,
      savedPath: path.join(dlDir, 'h14c.txt'),
      totalBytes: Buffer.byteLength(body),
    });
    const tStart = Date.now();
    const runP = new Aria2Runner({ item: cooled, binary: process.execPath, binaryArgsPrefix: [mock], rateLimiter: rl, onUpdate: () => {} }).run();
    await new Promise((r) => setTimeout(r, 60));
    rl.recordRateLimit(coolUrl, 429, '1', 1); // extends the shared deadline to >= +1000ms
    await runP;
    assert.equal(cooled.status, 'completed', cooled.error);
    const log3 = JSON.parse(await fs.readFile(logPath, 'utf8'));
    assert.ok(log3.spawnedAt - tStart >= 950, `aria2c spawned before extended cooldown elapsed (${log3.spawnedAt - tStart}ms)`);

    // Rounded progress tokens never exceed / replace the authoritative size
    assert.equal(cooled.totalBytes, Buffer.byteLength(body));
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('Companion CLI formats IPv6 loopback listener URLs with brackets (http://[::1]:port)', async (t) => {
  const v6Ok = await new Promise((resolve) => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.listen(0, '::1', () => probe.close(() => resolve(true)));
  });
  if (!v6Ok) {
    t.skip('IPv6 loopback (::1) is unavailable on this machine');
    return;
  }
  const port = await new Promise((resolve) => {
    const probe = net.createServer();
    probe.listen(0, '::1', () => {
      const p = probe.address().port;
      probe.close(() => resolve(p));
    });
  });
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-cli-v6-'));
  const entryPath = path.resolve(process.cwd(), 'dist-server', 'companion', 'index.js');
  try {
    const out = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [entryPath], {
        env: { ...process.env, HOST: '::1', PORT: String(port), BOLTGATE_DATA_DIR: tmpDataDir, BOLTGATE_OPEN_BROWSER: '0' },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let buf = '';
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error(`Timed out waiting for IPv6 startup: ${buf}`));
      }, 6000);
      child.stdout.on('data', (c) => {
        buf += c.toString('utf8');
        if (buf.includes('One-Time Pairing Code')) {
          clearTimeout(timer);
          child.kill('SIGTERM');
          setTimeout(() => child.kill('SIGKILL'), 800).unref();
        }
      });
      child.on('close', () => resolve(buf));
    });
    assert.ok(out.includes(`http://[::1]:${port}`), `Expected bracketed IPv6 URL, got: ${out}`);
    assert.equal(out.includes(`http://::1:${port}`), false);
  } finally {
    await fs.rm(tmpDataDir, { recursive: true, force: true });
  }
});
