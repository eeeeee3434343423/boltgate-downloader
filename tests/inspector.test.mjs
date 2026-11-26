import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { probeUrl } from '../dist-server/server/inspector.js';
import {
  extractUrlsFromText,
  matchDomainTrust,
  sanitizeFilename,
} from '../dist-server/server/utils.js';

function listenServer(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({ port: addr.port, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

test('extractUrlsFromText parses messy text, deduplicates, and flags unsafe schemes', () => {
  const input = `
    Check out https://example.com/archive.zip, and also (https://cdn.example.org/file_(v2).tar.gz)!
    Duplicate: https://example.com/archive.zip.
    Bad links: javascript:alert(1) file:///C:/Windows/System32/cmd.exe ftp://files.example.com/a.bin
  `;
  const { urls, rejectedTokens } = extractUrlsFromText(input);
  assert.deepEqual(urls, [
    'https://example.com/archive.zip',
    'https://cdn.example.org/file_(v2).tar.gz',
  ]);
  assert.equal(rejectedTokens.length, 3);
});

test('sanitizeFilename prevents traversal, illegal Windows characters, and reserved DOS names', () => {
  assert.equal(sanitizeFilename('../../evil<file>:name?.exe'), 'evil_file__name_.exe');
  assert.equal(sanitizeFilename('CON.txt'), '_CON.txt');
  assert.equal(sanitizeFilename('nul'), '_nul');
  assert.equal(sanitizeFilename('trailing.dots... '), 'trailing.dots');
});

test('matchDomainTrust matches exact or subdomain suffix only', () => {
  const rules = [
    { domain: 'github.com', status: 'trusted', note: '', createdAt: 1 },
    { domain: 'bad.example.com', status: 'blocked', note: '', createdAt: 2 },
  ];
  assert.equal(matchDomainTrust('github.com', rules), 'trusted');
  assert.equal(matchDomainTrust('releases.github.com', rules), 'trusted');
  assert.equal(matchDomainTrust('evilgithub.com', rules), 'unknown');
  assert.equal(matchDomainTrust('dl.bad.example.com', rules), 'blocked');
});

test('probeUrl detects 405 HEAD -> 206 Range fallback, redirects, double-extension, and MIME mismatch', async () => {
  const payload = Buffer.alloc(4096, 65);
  let bodyDownloadedBytes = 0;

  const server = http.createServer((req, res) => {
    if (req.url === '/redir') {
      res.writeHead(302, { Location: `http://localhost:${port}/range-only.zip` });
      res.end();
      return;
    }

    if (req.url === '/range-only.zip') {
      if (req.method === 'HEAD') {
        res.writeHead(405);
        res.end();
        return;
      }
      if (req.headers.range === 'bytes=0-0') {
        res.writeHead(206, {
          'Content-Type': 'application/zip',
          'Content-Range': `bytes 0-0/${payload.length}`,
          'Content-Length': 1,
          'Accept-Ranges': 'bytes',
          ETag: '"v1"',
        });
        res.end(payload.subarray(0, 1));
        return;
      }
      bodyDownloadedBytes += payload.length;
      res.writeHead(200, { 'Content-Length': payload.length });
      res.end(payload);
      return;
    }

    if (req.url === '/invoice.pdf.exe') {
      res.writeHead(200, {
        'Content-Type': 'application/x-msdownload',
        'Content-Length': 1024,
        'Accept-Ranges': 'bytes',
      });
      res.end();
      return;
    }

    if (req.url === '/report.pdf') {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Length': 512,
      });
      res.end();
      return;
    }

    res.writeHead(404);
    res.end();
  });

  const { port, close } = await listenServer(server);
  try {
    // 1. Cross-domain redirect + 405 HEAD fallback to Range: bytes=0-0
    const redirReport = await probeUrl(`http://127.0.0.1:${port}/redir`, {
      trustRules: [],
      existingDownloads: [],
    });
    assert.equal(redirReport.redirectChain.length, 1);
    assert.equal(redirReport.initialHost, '127.0.0.1');
    assert.equal(redirReport.finalHost, 'localhost');
    assert.equal(redirReport.supportsRanges, true);
    assert.equal(redirReport.totalBytes, 4096);
    assert.equal(redirReport.suggestedFilename, 'range-only.zip');
    assert.equal(bodyDownloadedBytes, 0);
    assert.ok(redirReport.signals.some((s) => s.id === 'redirects' && s.level === 'warn'));

    // 2. Double extension disguise
    const doubleExt = await probeUrl(`http://127.0.0.1:${port}/invoice.pdf.exe`, {
      trustRules: [],
      existingDownloads: [],
    });
    assert.equal(doubleExt.riskLevel, 'high_risk');
    assert.equal(doubleExt.isExecutable, true);
    assert.ok(
      doubleExt.signals.some((s) => s.id === 'filename_type' && s.title.includes('Double-Extension'))
    );

    // 3. MIME mismatch (HTML returned for .pdf)
    const mimeMismatch = await probeUrl(`http://127.0.0.1:${port}/report.pdf`, {
      trustRules: [],
      existingDownloads: [],
    });
    assert.equal(mimeMismatch.riskLevel, 'high_risk');
    assert.ok(mimeMismatch.signals.some((s) => s.id === 'mime_check' && s.level === 'danger'));
  } finally {
    await close();
  }
});

test('probeUrl probes GET Range: bytes=0-0 when HEAD returns 200 without Accept-Ranges and preserves Content-Disposition', async () => {
  const server = http.createServer((req, res) => {
    if (req.method === 'HEAD') {
      res.writeHead(200, {
        'Content-Type': 'application/epub+zip',
        'Content-Disposition': 'attachment; filename="Distributed_Systems.epub"',
        'Content-Length': 2097152,
      });
      res.end();
      return;
    }
    if (req.headers.range === 'bytes=0-0') {
      res.writeHead(206, {
        'Content-Range': 'bytes 0-0/2097152',
        'Content-Length': 1,
        'Accept-Ranges': 'bytes',
      });
      res.end(Buffer.from([0x50]));
      return;
    }
    res.writeHead(200);
    res.end();
  });

  const { port, close } = await listenServer(server);
  try {
    const report = await probeUrl(`http://127.0.0.1:${port}/download?id=99`, {
      trustRules: [],
      existingDownloads: [],
    });
    assert.equal(report.supportsRanges, true);
    assert.equal(report.totalBytes, 2097152);
    assert.equal(report.suggestedFilename, 'Distributed_Systems.epub');
    assert.equal(report.category, 'ebook');
  } finally {
    await close();
  }
});
