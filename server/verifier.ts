import fs from 'node:fs/promises';
import path from 'node:path';
import type { FileIntegrityReport } from '../shared/types.js';

const HEAD_READ_BYTES = 4096;
const TAIL_READ_BYTES = 65536;

const CHECKED_TRAP_EXTS = new Set([
  '.pdf',
  '.epub',
  '.mobi',
  '.azw',
  '.azw3',
  '.kfx',
  '.djvu',
  '.djv',
  '.cbz',
  '.cbr',
  '.fb2',
  '.zip',
  '.rar',
  '.7z',
  '.gz',
  '.tgz',
]);

function looksLikeHtmlTrap(headBuf: Buffer): boolean {
  const preview = headBuf
    .toString('utf8')
    .replace(/^\uFEFF/, '')
    .trimStart()
    .toLowerCase();

  if (
    preview.startsWith('<!doctype html') ||
    preview.startsWith('<html') ||
    preview.startsWith('<head') ||
    preview.startsWith('<script')
  ) {
    return true;
  }

  if (
    preview.includes('<title>') &&
    (preview.includes('</html') || preview.includes('<body') || preview.includes('</head>'))
  ) {
    return true;
  }

  return false;
}

export async function verifyFileIntegrity(
  filePath: string,
  filename: string
): Promise<FileIntegrityReport> {
  const ext = path.extname(filename).toLowerCase();
  const verifiedAt = Date.now();
  const checks: string[] = [];

  if (!CHECKED_TRAP_EXTS.has(ext)) {
    return {
      status: 'unchecked',
      format: ext ? ext.slice(1).toUpperCase() : 'Binary',
      summary: 'SHA-256 checksum recorded; no format-specific parser needed for this extension.',
      checks: ['SHA-256 digest computed after disk assembly'],
      verifiedAt,
    };
  }

  let fh: fs.FileHandle | null = null;
  try {
    fh = await fs.open(filePath, 'r');
    const stat = await fh.stat();
    const size = stat.size;

    if (size === 0) {
      return {
        status: 'corrupted',
        format: ext.slice(1).toUpperCase(),
        summary: 'File is 0 bytes (empty download).',
        checks: ['File size is 0 bytes'],
        verifiedAt,
      };
    }

    const headLen = Math.min(size, HEAD_READ_BYTES);
    const headBuf = Buffer.allocUnsafe(headLen);
    await fh.read(headBuf, 0, headLen, 0);

    const tailLen = Math.min(size, TAIL_READ_BYTES);
    const tailOffset = Math.max(0, size - tailLen);
    const tailBuf = Buffer.allocUnsafe(tailLen);
    await fh.read(tailBuf, 0, tailLen, tailOffset);

    // 1. HTML Trap Check (e.g. expired link / slow-download page saved with .epub/.pdf name)
    if (looksLikeHtmlTrap(headBuf)) {
      return {
        status: 'html_trap',
        format: ext.slice(1).toUpperCase(),
        summary:
          'HTML webpage saved instead of a real book/archive (likely an expired link, waiting room, or rate-limit page).',
        checks: [`Detected HTML markup inside "${filename}" instead of binary ${ext.slice(1).toUpperCase()} header`],
        verifiedAt,
      };
    }

    // 2. PDF validation (%PDF- header + %%EOF trailer)
    if (ext === '.pdf') {
      const hasHeader = headBuf.subarray(0, 1024).includes('%PDF-');
      const hasEof = tailBuf.includes('%%EOF');
      checks.push(hasHeader ? 'PDF %PDF- header verified' : 'Missing PDF %PDF- header');
      checks.push(hasEof ? 'PDF %%EOF trailer verified' : 'Missing PDF %%EOF end marker (file likely truncated)');
      if (hasHeader && hasEof) {
        return {
          status: 'valid',
          format: 'PDF',
          summary: 'PDF header and %%EOF end marker intact.',
          checks,
          verifiedAt,
        };
      }
      return {
        status: 'corrupted',
        format: 'PDF',
        summary: !hasHeader
          ? 'Invalid PDF file (missing %PDF- signature).'
          : 'PDF appears truncated (missing %%EOF end marker).',
        checks,
        verifiedAt,
      };
    }

    // 3. ZIP-based containers (.epub, .cbz, .zip)
    if (ext === '.epub' || ext === '.cbz' || ext === '.zip') {
      const label = ext === '.epub' ? 'EPUB' : ext === '.cbz' ? 'CBZ' : 'ZIP';
      const hasZipStart =
        headBuf.length >= 4 &&
        headBuf[0] === 0x50 &&
        headBuf[1] === 0x4b &&
        ((headBuf[2] === 0x03 && headBuf[3] === 0x04) ||
          (headBuf[2] === 0x05 && headBuf[3] === 0x06));
      const eocdSig = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
      const hasEocd = tailBuf.includes(eocdSig);

      checks.push(hasZipStart ? `${label} ZIP local header (PK) verified` : `Missing ${label} ZIP header`);
      checks.push(
        hasEocd
          ? 'ZIP End-of-Central-Directory (EOCD) verified'
          : 'Missing ZIP End-of-Central-Directory (archive truncated)'
      );

      if (ext === '.epub') {
        const hasEpubMimetype = headBuf.includes('application/epub+zip');
        checks.push(
          hasEpubMimetype
            ? 'EPUB mimetype entry detected'
            : 'ZIP container valid (no uncompressed mimetype marker in first 4 KB)'
        );
      }

      if (hasZipStart && hasEocd) {
        return {
          status: 'valid',
          format: label,
          summary: `${label} container header and central directory intact.`,
          checks,
          verifiedAt,
        };
      }
      return {
        status: 'corrupted',
        format: label,
        summary: !hasZipStart
          ? `Invalid ${label} file (missing ZIP container signature).`
          : `${label} archive appears truncated (missing End-of-Central-Directory).`,
        checks,
        verifiedAt,
      };
    }

    // 4. MOBI / AZW / AZW3 (PalmDOC header at offset 60)
    if (ext === '.mobi' || ext === '.azw' || ext === '.azw3' || ext === '.kfx') {
      const label = ext.slice(1).toUpperCase();
      if (ext === '.kfx') {
        const isKfx = headBuf.subarray(0, 4).toString('ascii') === 'CONT';
        checks.push(isKfx ? 'KFX CONT container header verified' : 'Unrecognized KFX header');
        return {
          status: isKfx ? 'valid' : 'corrupted',
          format: 'KFX',
          summary: isKfx ? 'KFX container header verified.' : 'Invalid KFX header signature.',
          checks,
          verifiedAt,
        };
      }

      const palmType = size >= 68 ? headBuf.subarray(60, 68).toString('ascii') : '';
      const validPalm = palmType === 'BOOKMOBI' || palmType === 'TEXtREAd';
      checks.push(
        validPalm
          ? `PalmDB ebook signature "${palmType}" verified at offset 60`
          : `Expected BOOKMOBI/TEXtREAd at offset 60 (found "${palmType || 'too short'}")`
      );
      return {
        status: validPalm ? 'valid' : 'corrupted',
        format: label,
        summary: validPalm
          ? `${label} (${palmType}) container header verified.`
          : `Invalid ${label} file (missing BOOKMOBI signature).`,
        checks,
        verifiedAt,
      };
    }

    // 5. DJVU / DJV
    if (ext === '.djvu' || ext === '.djv') {
      const isDjvu = headBuf.subarray(0, 8).toString('ascii') === 'AT&TFORM';
      checks.push(isDjvu ? 'DjVu AT&TFORM header verified' : 'Missing AT&TFORM DjVu header');
      return {
        status: isDjvu ? 'valid' : 'corrupted',
        format: 'DJVU',
        summary: isDjvu ? 'DjVu AT&TFORM signature verified.' : 'Invalid DjVu header.',
        checks,
        verifiedAt,
      };
    }

    // 6. CBR / RAR
    if (ext === '.cbr' || ext === '.rar') {
      const isRar =
        headBuf.length >= 6 &&
        headBuf[0] === 0x52 &&
        headBuf[1] === 0x61 &&
        headBuf[2] === 0x72 &&
        headBuf[3] === 0x21 &&
        headBuf[4] === 0x1a &&
        headBuf[5] === 0x07;
      checks.push(isRar ? 'RAR archive magic bytes verified' : 'Missing RAR signature');
      return {
        status: isRar ? 'valid' : 'corrupted',
        format: ext === '.cbr' ? 'CBR' : 'RAR',
        summary: isRar ? 'RAR container header verified.' : 'Invalid RAR/CBR file header.',
        checks,
        verifiedAt,
      };
    }

    // 7. FB2 XML
    if (ext === '.fb2') {
      const headAscii = headBuf.toString('utf8').replace(/^\uFEFF/, '').trimStart();
      const tailAscii = tailBuf.toString('utf8');
      const hasStart = headAscii.startsWith('<?xml') || headAscii.startsWith('<FictionBook');
      const hasEnd = tailAscii.includes('</FictionBook>');
      checks.push(hasStart ? 'FB2 XML root header verified' : 'Missing FB2 XML header');
      checks.push(hasEnd ? 'FB2 </FictionBook> closing tag verified' : 'Missing </FictionBook> closing tag');
      return {
        status: hasStart && hasEnd ? 'valid' : 'corrupted',
        format: 'FB2',
        summary:
          hasStart && hasEnd
            ? 'FictionBook2 XML structure intact.'
            : 'FB2 file is malformed or truncated.',
        checks,
        verifiedAt,
      };
    }

    // 8. 7z / GZ
    if (ext === '.7z') {
      const magic7z = Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);
      const ok = headBuf.length >= 6 && headBuf.subarray(0, 6).equals(magic7z);
      checks.push(ok ? '7-Zip header signature verified' : 'Missing 7-Zip header signature');
      return {
        status: ok ? 'valid' : 'corrupted',
        format: '7Z',
        summary: ok ? '7-Zip header verified.' : 'Invalid 7-Zip archive header.',
        checks,
        verifiedAt,
      };
    }

    if (ext === '.gz' || ext === '.tgz') {
      const ok = headBuf.length >= 2 && headBuf[0] === 0x1f && headBuf[1] === 0x8b;
      checks.push(ok ? 'Gzip magic header (1F 8B) verified' : 'Missing Gzip header');
      return {
        status: ok ? 'valid' : 'corrupted',
        format: ext.slice(1).toUpperCase(),
        summary: ok ? 'Gzip header verified.' : 'Invalid Gzip header.',
        checks,
        verifiedAt,
      };
    }

    return {
      status: 'unchecked',
      format: ext.slice(1).toUpperCase(),
      summary: 'No format parser configured.',
      checks,
      verifiedAt,
    };
  } finally {
    await fh?.close().catch(() => {});
  }
}
