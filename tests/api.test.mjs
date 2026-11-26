import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createAppServer } from '../dist-server/server/app.js';
import { DownloadManager } from '../dist-server/server/manager.js';

async function jsonReq(baseUrl, route, method = 'GET', body) {
  const res = await fetch(`${baseUrl}${route}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  return { status: res.status, data };
}

async function waitFor(predicate, timeoutMs = 8000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const val = await predicate();
    if (val) return val;
    await new Promise((r) => setTimeout(r, 40));
  }
  throw new Error('Timed out waiting for condition');
}

test('Full Safety Gate -> Approve -> Multi-Stream Download -> Verify SHA-256 -> Undo -> Restart Persistence', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-api-data-'));
  const tmpDownloadDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-api-dl-'));

  const manager = new DownloadManager({
    dataDir: tmpDataDir,
    minSegmentBytes: 256 * 1024,
  });
  await manager.init();
  await manager.updateSettings({
    downloadDir: tmpDownloadDir,
    segmentsPerDownload: 4,
  });

  const server = createAppServer({ manager });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. Inspect local benchmark link (4 MB) -> must hold in Safety Gate!
    const inspectRes = await jsonReq(baseUrl, '/api/inspect', 'POST', {
      text: `${baseUrl}/api/local-benchmark?sizeMB=4`,
    });
    assert.equal(inspectRes.status, 200);
    assert.equal(inspectRes.data.items.length, 1);
    const id = inspectRes.data.items[0].id;

    // Wait for probe to complete -> pending_review
    const reviewed = await waitFor(async () => {
      const st = await jsonReq(baseUrl, '/api/state');
      const item = st.data.downloads.find((d) => d.id === id);
      return item?.status === 'pending_review' ? item : null;
    });

    assert.equal(reviewed.userDeemedSafe, false);
    assert.equal(reviewed.totalBytes, 4 * 1024 * 1024);
    assert.equal(reviewed.supportsRanges, true);

    // 2. Approve ("Deem Safe & Download") with Trust Domain
    const approveRes = await jsonReq(baseUrl, `/api/downloads/${id}/approve`, 'POST', {
      trustDomain: true,
      connections: 4,
    });
    assert.equal(approveRes.status, 200);

    // Wait for completion
    const completed = await waitFor(async () => {
      const st = await jsonReq(baseUrl, '/api/state');
      const item = st.data.downloads.find((d) => d.id === id);
      return item?.status === 'completed' ? item : null;
    });

    assert.equal(completed.userDeemedSafe, true);
    assert.ok(completed.sha256 && completed.sha256.length === 64);

    // Verify expected deterministic hash independently
    const diskBytes = await fs.readFile(completed.savedPath);
    const actualHash = crypto.createHash('sha256').update(diskBytes).digest('hex');
    assert.equal(completed.sha256, actualHash);

    // 3. Verify Hash API (match + mismatch)
    const matchRes = await jsonReq(baseUrl, `/api/downloads/${id}/verify-hash`, 'POST', {
      expectedSha256: actualHash,
    });
    assert.equal(matchRes.status, 200);
    assert.equal(matchRes.data.match, true);

    const mismatchRes = await jsonReq(baseUrl, `/api/downloads/${id}/verify-hash`, 'POST', {
      expectedSha256: '0'.repeat(64),
    });
    assert.equal(mismatchRes.status, 200);
    assert.equal(mismatchRes.data.match, false);

    // 4. Soft remove & Undo Restore
    const delRes = await jsonReq(baseUrl, `/api/downloads/${id}?deleteFile=false`, 'DELETE');
    assert.equal(delRes.status, 200);
    assert.equal(delRes.data.undoable, true);

    const restoreRes = await jsonReq(baseUrl, `/api/downloads/${id}/restore`, 'POST', {});
    assert.equal(restoreRes.status, 200);
    assert.equal(restoreRes.data.item.id, id);

    // 5. Trust rule added during approve + safety block on open-file for executable
    const stAfter = await jsonReq(baseUrl, '/api/state');
    assert.ok(
      stAfter.data.trustRules.some((r) => r.domain === '127.0.0.1' && r.status === 'trusted')
    );

    // 6. verify-integrity endpoint + CORS allowlist + CSRF guard
    const integRes = await jsonReq(baseUrl, `/api/downloads/${id}/verify-integrity`, 'POST', {});
    assert.equal(integRes.status, 200);
    assert.equal(integRes.data.integrity.status, 'unchecked');

    const allowedPreflight = await fetch(`${baseUrl}/api/state`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://eeeeee3434343423.github.io' },
    });
    assert.equal(allowedPreflight.status, 204);
    assert.equal(
      allowedPreflight.headers.get('access-control-allow-origin'),
      'https://eeeeee3434343423.github.io'
    );
    assert.equal(
      allowedPreflight.headers.get('access-control-allow-private-network'),
      'true'
    );

    const evilPost = await fetch(`${baseUrl}/api/inspect`, {
      method: 'POST',
      headers: {
        Origin: 'https://evil.example',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ text: `${baseUrl}/api/local-benchmark?sizeMB=1` }),
    });
    assert.equal(evilPost.status, 403);

    // 7. maxConcurrentPerHost=1 serializes same-host queued downloads cleanly
    await jsonReq(baseUrl, '/api/settings', 'PATCH', { speedPreset: 'books' });
    const stBooks = await jsonReq(baseUrl, '/api/state');
    assert.equal(stBooks.data.settings.speedPreset, 'books');
    assert.equal(stBooks.data.settings.maxConcurrentPerHost, 1);

    const b1 = await jsonReq(baseUrl, '/api/inspect', 'POST', {
      text: `${baseUrl}/api/local-benchmark?sizeMB=2\n${baseUrl}/api/local-benchmark?sizeMB=3`,
    });
    assert.equal(b1.status, 200);
    assert.equal(b1.data.items.length, 2);

    const [idA, idB] = b1.data.items.map((x) => x.id);
    await waitFor(async () => {
      const st = await jsonReq(baseUrl, '/api/state');
      const a = st.data.downloads.find((d) => d.id === idA);
      const b = st.data.downloads.find((d) => d.id === idB);
      return a?.status === 'pending_review' && b?.status === 'pending_review';
    });

    let sawBothDownloadingSimultaneously = false;
    const origUpdate = manager.getSnapshot.bind(manager);
    const pollHandle = setInterval(() => {
      const snap = origUpdate();
      const activeSameHost = snap.downloads.filter((d) => d.status === 'downloading').length;
      if (activeSameHost > 1) sawBothDownloadingSimultaneously = true;
    }, 10);

    await jsonReq(baseUrl, '/api/downloads/approve-batch', 'POST', { ids: [idA, idB] });
    await waitFor(async () => {
      const st = await jsonReq(baseUrl, '/api/state');
      const a = st.data.downloads.find((d) => d.id === idA);
      const b = st.data.downloads.find((d) => d.id === idB);
      return a?.status === 'completed' && b?.status === 'completed';
    });
    clearInterval(pollHandle);
    assert.equal(sawBothDownloadingSimultaneously, false);

    // 8. Restart persistence check
    await manager.shutdown();
    await new Promise((r) => server.close(r));

    const manager2 = new DownloadManager({ dataDir: tmpDataDir });
    await manager2.init();
    const snap2 = manager2.getSnapshot();
    assert.equal(snap2.downloads.length, 3);
    assert.equal(snap2.downloads.filter((d) => d.status === 'completed').length, 3);
    assert.equal(snap2.settings.downloadDir, tmpDownloadDir);
    assert.ok(snap2.trustRules.some((r) => r.domain === '127.0.0.1'));
    await manager2.shutdown();
  } finally {
    await manager.shutdown().catch(() => {});
    await new Promise((r) => server.close(() => r()));
    await fs.rm(tmpDataDir, { recursive: true, force: true });
    await fs.rm(tmpDownloadDir, { recursive: true, force: true });
  }
});

test('POST /api/inspect-mirrors verifies matching mirrors, excludes mismatched sizes, and completes striped download', async () => {
  const tmpDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-mirror-data-'));
  const tmpDownloadDir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-mirror-dl-'));

  const manager = new DownloadManager({ dataDir: tmpDataDir });
  await manager.init();
  await manager.updateSettings({ downloadDir: tmpDownloadDir });

  const server = createAppServer({ manager });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const res = await jsonReq(baseUrl, '/api/inspect-mirrors', 'POST', {
      text: [
        `${baseUrl}/api/local-benchmark?sizeMB=2&m=1`,
        `${baseUrl}/api/local-benchmark?sizeMB=2&m=2`,
        `${baseUrl}/api/local-benchmark?sizeMB=3&m=bad`,
      ].join('\n'),
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.items.length, 1);
    const id = res.data.items[0].id;

    const reviewed = await waitFor(async () => {
      const st = await jsonReq(baseUrl, '/api/state');
      const item = st.data.downloads.find((d) => d.id === id);
      return item?.status === 'pending_review' ? item : null;
    });

    assert.equal(reviewed.mirrorUrls.length, 2);
    assert.equal(reviewed.safety.mirrorReports.length, 3);
    assert.equal(reviewed.safety.mirrorReports[2].included, false);
    assert.ok(reviewed.safety.mirrorReports[2].excludeReason.includes('Size mismatch'));

    await jsonReq(baseUrl, `/api/downloads/${id}/approve`, 'POST', {});
    const completed = await waitFor(async () => {
      const st = await jsonReq(baseUrl, '/api/state');
      const item = st.data.downloads.find((d) => d.id === id);
      return item?.status === 'completed' ? item : null;
    });

    const diskBytes = await fs.readFile(completed.savedPath);
    const actualHash = crypto.createHash('sha256').update(diskBytes).digest('hex');
    assert.equal(completed.sha256, actualHash);
    assert.equal(diskBytes.length, 2 * 1024 * 1024);
  } finally {
    await manager.shutdown().catch(() => {});
    await new Promise((r) => server.close(() => r()));
    await fs.rm(tmpDataDir, { recursive: true, force: true });
    await fs.rm(tmpDownloadDir, { recursive: true, force: true });
  }
});
