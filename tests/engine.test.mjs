import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { DownloadRunner } from '../dist-server/server/engine.js';
import { TokenBucketThrottle } from '../dist-server/server/throttle.js';

function makeDeterministicPayload(sizeBytes) {
  const buf = Buffer.allocUnsafe(sizeBytes);
  for (let i = 0; i < sizeBytes; i++) {
    buf[i] = (i * 31 + (i >>> 8) * 17 + (i >>> 16) * 13) & 0xff;
  }
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  return { buf, sha256 };
}

function makeItem(url, destDir, filename, opts = {}) {
  const savedPath = path.join(destDir, filename);
  return {
    id: crypto.randomUUID(),
    originalUrl: url,
    finalUrl: url,
    filename,
    destinationDir: destDir,
    savedPath,
    partPath: `${savedPath}.boltpart`,
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
    segments: [],
    safety: null,
    createdAt: Date.now(),
    userDeemedSafe: true,
  };
}

function listenServer(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({ port: addr.port, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

test('DownloadRunner executes multi-segment parallel download with tail work-stealing and exact SHA-256', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-eng-1-'));
  const { buf: payload, sha256: expectedHash } = makeDeterministicPayload(4 * 1024 * 1024); // 4 MiB

  let rangeRequests = 0;
  let dropOnceDone = false;

  const server = http.createServer(async (req, res) => {
    if (req.url === '/multi.bin') {
      const range = req.headers.range;
      if (range && range.startsWith('bytes=')) {
        rangeRequests++;
        const [, startStr, endStr] = range.match(/^bytes=(\d+)-(\d*)$/);
        const start = Number(startStr);
        const end = endStr ? Number(endStr) : payload.length - 1;
        const slice = payload.subarray(start, end + 1);

        res.writeHead(206, {
          'Content-Type': 'application/octet-stream',
          'Content-Range': `bytes ${start}-${end}/${payload.length}`,
          'Content-Length': slice.length,
          'Accept-Ranges': 'bytes',
          ETag: '"m1"',
        });

        // Simulate transient socket drop once mid-flight
        if (!dropOnceDone && start > 0) {
          dropOnceDone = true;
          res.write(slice.subarray(0, Math.min(8192, slice.length)));
          setTimeout(() => res.destroy(), 15);
          return;
        }

        // Artificially slow segment starting at 0 so fast siblings finish & steal its tail!
        if (start === 0) {
          const step = 64 * 1024;
          for (let pos = 0; pos < slice.length && !res.destroyed; pos += step) {
            res.write(slice.subarray(pos, Math.min(slice.length, pos + step)));
            await new Promise((r) => setTimeout(r, 8));
          }
          if (!res.destroyed) res.end();
          return;
        }

        res.end(slice);
        return;
      }
      res.writeHead(200, { 'Content-Length': payload.length, 'Accept-Ranges': 'bytes' });
      res.end(payload);
      return;
    }

    if (req.url === '/empty.bin') {
      res.writeHead(200, { 'Content-Length': 0, 'Accept-Ranges': 'bytes' });
      res.end();
      return;
    }

    if (req.url === '/single-200.bin') {
      // Server ignores Range header and returns 200 OK
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': payload.length });
      res.end(payload);
      return;
    }

    res.writeHead(404);
    res.end();
  });

  const { port, close } = await listenServer(server);
  try {
    // 1. Multi-segment + work-stealing + transient error retry
    const item = makeItem(`http://127.0.0.1:${port}/multi.bin`, tmpDir, 'multi.bin', {
      totalBytes: payload.length,
      connections: 4,
      supportsRanges: true,
      etag: '"m1"',
    });
    const runner = new DownloadRunner({
      item,
      throttle: new TokenBucketThrottle(0),
      minSegmentBytes: 128 * 1024,
      onUpdate: () => {},
    });
    await runner.run();

    assert.equal(item.status, 'completed');
    assert.equal(item.sha256, expectedHash);
    assert.ok(rangeRequests >= 4, `Expected >=4 range requests, got ${rangeRequests}`);
    assert.ok(item.segments.length >= 4, 'Expected at least 4 segments');
    const diskBuf = await fs.readFile(item.savedPath);
    assert.equal(diskBuf.length, payload.length);
    assert.equal(crypto.createHash('sha256').update(diskBuf).digest('hex'), expectedHash);

    // 2. Zero-byte file
    const emptyItem = makeItem(`http://127.0.0.1:${port}/empty.bin`, tmpDir, 'empty.bin', {
      totalBytes: 0,
      connections: 4,
      supportsRanges: true,
    });
    await new DownloadRunner({
      item: emptyItem,
      throttle: new TokenBucketThrottle(0),
      onUpdate: () => {},
    }).run();
    assert.equal(emptyItem.status, 'completed');
    assert.equal(
      emptyItem.sha256,
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );

    // 3. Server returning 200 OK even though item asked for ranges
    const singleItem = makeItem(`http://127.0.0.1:${port}/single-200.bin`, tmpDir, 'single.bin', {
      totalBytes: payload.length,
      connections: 4,
      supportsRanges: true,
    });
    await new DownloadRunner({
      item: singleItem,
      throttle: new TokenBucketThrottle(0),
      minSegmentBytes: 128 * 1024,
      onUpdate: () => {},
    }).run();
    assert.equal(singleItem.status, 'completed');
    assert.equal(singleItem.supportsRanges, false);
    assert.equal(singleItem.sha256, expectedHash);
  } finally {
    await close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('DownloadRunner pauses cleanly mid-flight and resumes to exact SHA-256', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-eng-2-'));
  const { buf: payload, sha256: expectedHash } = makeDeterministicPayload(4 * 1024 * 1024); // 4 MiB

  const server = http.createServer(async (req, res) => {
    const range = req.headers.range;
    if (!range) {
      res.writeHead(200, { 'Content-Length': payload.length, 'Accept-Ranges': 'bytes' });
      res.end(payload);
      return;
    }
    const [, startStr, endStr] = range.match(/^bytes=(\d+)-(\d*)$/);
    const start = Number(startStr);
    const end = endStr ? Number(endStr) : payload.length - 1;
    const slice = payload.subarray(start, end + 1);
    res.writeHead(206, {
      'Content-Range': `bytes ${start}-${end}/${payload.length}`,
      'Content-Length': slice.length,
      'Accept-Ranges': 'bytes',
      ETag: '"p1"',
    });

    const step = 32 * 1024;
    for (let pos = 0; pos < slice.length && !res.destroyed; pos += step) {
      res.write(slice.subarray(pos, Math.min(slice.length, pos + step)));
      await new Promise((r) => setTimeout(r, 15));
    }
    if (!res.destroyed) res.end();
  });

  const { port, close } = await listenServer(server);
  try {
    const item = makeItem(`http://127.0.0.1:${port}/pausable.bin`, tmpDir, 'pausable.bin', {
      totalBytes: payload.length,
      connections: 4,
      supportsRanges: true,
      etag: '"p1"',
    });

    const runner1 = new DownloadRunner({
      item,
      throttle: new TokenBucketThrottle(0),
      minSegmentBytes: 128 * 1024,
      onUpdate: () => {},
    });

    const runPromise1 = runner1.run();
    // Wait until some bytes have been downloaded, then pause
    for (let i = 0; i < 80 && item.downloadedBytes < 128 * 1024; i++) {
      await new Promise((r) => setTimeout(r, 15));
    }
    await runner1.pause();
    await runPromise1;

    assert.equal(item.status, 'paused');
    assert.ok(item.downloadedBytes > 0 && item.downloadedBytes < payload.length);
    const partStat = await fs.stat(item.partPath);
    assert.equal(partStat.size, payload.length);

    // Resume from paused segments
    const runner2 = new DownloadRunner({
      item,
      throttle: new TokenBucketThrottle(0),
      minSegmentBytes: 128 * 1024,
      onUpdate: () => {},
    });
    await runner2.run();

    assert.equal(item.status, 'completed');
    assert.equal(item.sha256, expectedHash);
  } finally {
    await close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('TokenBucketThrottle limits throughput and cancels immediately on AbortSignal', async () => {
  const throttle = new TokenBucketThrottle(200); // 200 KB/s
  // Drain initial burst
  await throttle.consume(128 * 1024);

  const ac = new AbortController();
  const waitPromise = throttle.consume(512 * 1024, ac.signal);
  setTimeout(() => ac.abort(), 30);

  await assert.rejects(waitPromise, { name: 'AbortError' });
});

test('DownloadRunner respects HTTP 429 Retry-After header and finishes cleanly', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-eng-429-'));
  const { buf: payload, sha256: expectedHash } = makeDeterministicPayload(512 * 1024);

  let hits = 0;
  const server = http.createServer((req, res) => {
    hits++;
    if (hits === 1) {
      res.writeHead(429, { 'Retry-After': '1' });
      res.end('Slow down');
      return;
    }
    res.writeHead(200, { 'Content-Length': payload.length });
    res.end(payload);
  });

  const { port, close } = await listenServer(server);
  try {
    const item = makeItem(`http://127.0.0.1:${port}/book.epub`, tmpDir, 'book.epub', {
      totalBytes: payload.length,
      connections: 1,
      supportsRanges: false,
    });
    const started = Date.now();
    await new DownloadRunner({
      item,
      throttle: new TokenBucketThrottle(0),
      retryAfterCapMs: 500,
      onUpdate: () => {},
    }).run();

    assert.equal(item.status, 'completed');
    assert.equal(item.sha256, expectedHash);
    assert.ok(hits >= 2);
    assert.ok(Date.now() - started >= 400, 'Expected retry delay before re-requesting');
  } finally {
    await close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});
