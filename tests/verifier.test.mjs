import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { verifyFileIntegrity } from '../dist-server/server/verifier.js';

test('verifyFileIntegrity validates PDF, EPUB, MOBI, DJVU, FB2 and catches truncation & HTML traps', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'boltgate-verify-'));
  try {
    // 1. Valid PDF
    const goodPdf = path.join(dir, 'book.pdf');
    await fs.writeFile(goodPdf, Buffer.from('%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n'));
    const pdfRes = await verifyFileIntegrity(goodPdf, 'book.pdf');
    assert.equal(pdfRes.status, 'valid');
    assert.equal(pdfRes.format, 'PDF');

    // 2. Truncated PDF (missing %%EOF)
    const truncPdf = path.join(dir, 'truncated.pdf');
    await fs.writeFile(truncPdf, Buffer.from('%PDF-1.7\n1 0 obj\n<<>>\n'));
    const truncPdfRes = await verifyFileIntegrity(truncPdf, 'truncated.pdf');
    assert.equal(truncPdfRes.status, 'corrupted');

    // 3. HTML trap masquerading as EPUB and PDF
    const trapEpub = path.join(dir, 'fake.epub');
    await fs.writeFile(
      trapEpub,
      '<!DOCTYPE html><html><head><title>Please wait</title></head><body>Rate limited</body></html>'
    );
    const trapEpubRes = await verifyFileIntegrity(trapEpub, 'fake.epub');
    assert.equal(trapEpubRes.status, 'html_trap');

    const trapPdf = path.join(dir, 'fake.pdf');
    await fs.writeFile(trapPdf, '<html><body>Slow download queue</body></html>');
    const trapPdfRes = await verifyFileIntegrity(trapPdf, 'fake.pdf');
    assert.equal(trapPdfRes.status, 'html_trap');

    // 4. Valid EPUB (PK local header + mimetype + PK EOCD) vs truncated EPUB
    const goodEpub = path.join(dir, 'good.epub');
    const zipHeader = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]);
    const zipBody = Buffer.from('mimetypeapplication/epub+zip');
    const zipEocd = Buffer.from([0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00]);
    await fs.writeFile(goodEpub, Buffer.concat([zipHeader, zipBody, zipEocd]));
    const epubRes = await verifyFileIntegrity(goodEpub, 'good.epub');
    assert.equal(epubRes.status, 'valid');
    assert.equal(epubRes.format, 'EPUB');

    const truncEpub = path.join(dir, 'trunc.epub');
    await fs.writeFile(truncEpub, Buffer.concat([zipHeader, zipBody]));
    const truncEpubRes = await verifyFileIntegrity(truncEpub, 'trunc.epub');
    assert.equal(truncEpubRes.status, 'corrupted');

    // 5. Valid MOBI (BOOKMOBI at offset 60) vs invalid MOBI
    const goodMobi = path.join(dir, 'good.mobi');
    const mobiBuf = Buffer.alloc(128, 0);
    mobiBuf.write('BOOKMOBI', 60, 'ascii');
    await fs.writeFile(goodMobi, mobiBuf);
    const mobiRes = await verifyFileIntegrity(goodMobi, 'good.mobi');
    assert.equal(mobiRes.status, 'valid');
    assert.equal(mobiRes.format, 'MOBI');

    const badMobi = path.join(dir, 'bad.mobi');
    await fs.writeFile(badMobi, Buffer.alloc(128, 0));
    const badMobiRes = await verifyFileIntegrity(badMobi, 'bad.mobi');
    assert.equal(badMobiRes.status, 'corrupted');

    // 6. Valid DJVU & FB2
    const goodDjvu = path.join(dir, 'scan.djvu');
    await fs.writeFile(goodDjvu, Buffer.from('AT&TFORM\x00\x00\x00\x10DJVU'));
    assert.equal((await verifyFileIntegrity(goodDjvu, 'scan.djvu')).status, 'valid');

    const goodFb2 = path.join(dir, 'novel.fb2');
    await fs.writeFile(goodFb2, '<?xml version="1.0"?><FictionBook><body></body></FictionBook>');
    assert.equal((await verifyFileIntegrity(goodFb2, 'novel.fb2')).status, 'valid');
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
