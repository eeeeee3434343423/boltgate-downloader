import assert from 'node:assert/strict';
import test from 'node:test';
import { parseSmartInput } from '../dist-server/shared/inputParser.js';

test('parseSmartInput parses direct URLs, multi-line mirrors, Anna MD5 URLs, raw MD5s, magnets, .torrent, and IPFS URIs', () => {
  const md5A = '0123456789abcdef0123456789abcdef';
  const md5B = 'fedcba9876543210fedcba9876543210';
  const sha256 = 'a'.repeat(64);
  const cid = 'QmYwAPJzv5CZsnAzt8auVZRn3b7Q9s7d5y8i3v7o2x9p1q';

  // 1. Anna's Archive /md5/<hash> URL
  const annas = parseSmartInput(`https://annas-archive.org/md5/${md5A}`);
  assert.equal(annas.entries.length, 1);
  assert.equal(annas.entries[0].kind, 'annas_md5');
  assert.equal(annas.entries[0].md5, md5A);

  // 2. Raw 32-char MD5 (and ensures 64-char SHA-256 is NOT parsed as raw MD5)
  const rawMd5 = parseSmartInput(`${md5B} ${sha256}`);
  assert.equal(rawMd5.entries.length, 1);
  assert.equal(rawMd5.entries[0].kind, 'raw_md5');
  assert.equal(rawMd5.entries[0].md5, md5B);

  // 3. Multi-line mirror URLs
  const mirrors = parseSmartInput(
    'https://mirror1.example.com/book.epub\nhttps://mirror2.example.com/book.epub'
  );
  assert.equal(mirrors.entries.length, 2);
  assert.equal(mirrors.hasMultiMirrors, true);
  assert.equal(mirrors.directUrls.length, 2);

  // 4. Magnet & .torrent
  const p2p = parseSmartInput(
    'magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=Sample+Book.epub\nhttps://cdn.example.org/books/pack.torrent'
  );
  assert.equal(p2p.entries.length, 2);
  assert.equal(p2p.entries[0].kind, 'magnet');
  assert.equal(p2p.entries[0].displayName, 'Sample Book.epub');
  assert.equal(p2p.entries[1].kind, 'torrent_url');

  // 5. ipfs:// URI and unsafe scheme rejection
  const ipfsAndUnsafe = parseSmartInput(
    `ipfs://${cid}/sample.pdf javascript:alert(1) file:///C:/bad.exe`
  );
  assert.equal(ipfsAndUnsafe.entries.length, 1);
  assert.equal(ipfsAndUnsafe.entries[0].kind, 'ipfs_uri');
  assert.equal(ipfsAndUnsafe.entries[0].cid, cid);
  assert.equal(ipfsAndUnsafe.entries[0].filename, 'sample.pdf');
  assert.equal(ipfsAndUnsafe.rejectedTokens.length, 2);
});
