import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import type { FileCategory, TrustRule } from '../shared/types.js';

const RESERVED_DOS_NAMES = new Set([
  'CON',
  'PRN',
  'AUX',
  'NUL',
  'COM1',
  'COM2',
  'COM3',
  'COM4',
  'COM5',
  'COM6',
  'COM7',
  'COM8',
  'COM9',
  'LPT1',
  'LPT2',
  'LPT3',
  'LPT4',
  'LPT5',
  'LPT6',
  'LPT7',
  'LPT8',
  'LPT9',
]);

const EXECUTABLE_EXTS = new Set([
  '.exe',
  '.msi',
  '.msix',
  '.appx',
  '.bat',
  '.cmd',
  '.ps1',
  '.vbs',
  '.vbe',
  '.js',
  '.jse',
  '.wsf',
  '.wsh',
  '.scr',
  '.pif',
  '.com',
  '.hta',
  '.jar',
  '.lnk',
  '.reg',
  '.dll',
  '.cpl',
  '.sh',
  '.run',
  '.appimage',
  '.deb',
  '.rpm',
  '.apk',
  '.pkg',
]);

const INNOCENT_OUTER_EXTS = new Set([
  '.pdf',
  '.doc',
  '.docx',
  '.xls',
  '.xlsx',
  '.ppt',
  '.pptx',
  '.txt',
  '.rtf',
  '.csv',
  '.jpg',
  '.jpeg',
  '.png',
  '.gif',
  '.webp',
  '.mp3',
  '.mp4',
  '.mkv',
  '.zip',
  '.rar',
]);

const CATEGORY_BY_EXT: Record<string, FileCategory> = {
  // Video
  '.mp4': 'video',
  '.mkv': 'video',
  '.webm': 'video',
  '.mov': 'video',
  '.avi': 'video',
  '.flv': 'video',
  '.wmv': 'video',
  '.m4v': 'video',
  '.ts': 'video',
  // Audio
  '.mp3': 'audio',
  '.wav': 'audio',
  '.flac': 'audio',
  '.aac': 'audio',
  '.ogg': 'audio',
  '.m4a': 'audio',
  '.opus': 'audio',
  '.wma': 'audio',
  // Archive
  '.zip': 'archive',
  '.rar': 'archive',
  '.7z': 'archive',
  '.tar': 'archive',
  '.gz': 'archive',
  '.bz2': 'archive',
  '.xz': 'archive',
  '.zst': 'archive',
  '.tgz': 'archive',
  // Disk images
  '.iso': 'disk',
  '.img': 'disk',
  '.vhd': 'disk',
  '.vhdx': 'disk',
  '.vmdk': 'disk',
  '.dmg': 'disk',
  '.ova': 'disk',
  // Ebooks
  '.epub': 'ebook',
  '.mobi': 'ebook',
  '.azw': 'ebook',
  '.azw3': 'ebook',
  '.kfx': 'ebook',
  '.fb2': 'ebook',
  '.djvu': 'ebook',
  '.djv': 'ebook',
  '.cbz': 'ebook',
  '.cbr': 'ebook',
  '.lit': 'ebook',
  '.lrf': 'ebook',
  '.pdb': 'ebook',
  // Document
  '.pdf': 'document',
  '.doc': 'document',
  '.docx': 'document',
  '.xls': 'document',
  '.xlsx': 'document',
  '.ppt': 'document',
  '.pptx': 'document',
  '.txt': 'document',
  '.md': 'document',
  '.csv': 'document',
  '.json': 'document',
  '.xml': 'document',
  '.rtf': 'document',
  '.odt': 'document',
  // Image
  '.png': 'image',
  '.jpg': 'image',
  '.jpeg': 'image',
  '.gif': 'image',
  '.webp': 'image',
  '.svg': 'image',
  '.avif': 'image',
  '.bmp': 'image',
  '.ico': 'image',
  '.tiff': 'image',
  '.raw': 'image',
};

const MIME_TO_EXT: Record<string, string> = {
  'application/epub+zip': '.epub',
  'application/x-mobipocket-ebook': '.mobi',
  'image/vnd.djvu': '.djvu',
  'image/x-djvu': '.djvu',
  'application/vnd.comicbook+zip': '.cbz',
  'application/x-fictionbook+xml': '.fb2',
  'application/pdf': '.pdf',
  'application/zip': '.zip',
  'application/x-zip-compressed': '.zip',
  'application/x-7z-compressed': '.7z',
  'application/x-rar-compressed': '.rar',
  'application/gzip': '.gz',
  'application/x-tar': '.tar',
  'application/x-iso9660-image': '.iso',
  'application/x-msdownload': '.exe',
  'application/x-msi': '.msi',
  'application/json': '.json',
  'text/plain': '.txt',
  'text/csv': '.csv',
  'text/html': '.html',
  'video/mp4': '.mp4',
  'video/webm': '.webm',
  'video/x-matroska': '.mkv',
  'audio/mpeg': '.mp3',
  'audio/flac': '.flac',
  'audio/wav': '.wav',
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/webp': '.webp',
  'image/gif': '.gif',
  'image/svg+xml': '.svg',
};

const EXECUTABLE_MIMES = new Set([
  'application/x-msdownload',
  'application/x-dosexec',
  'application/vnd.microsoft.portable-executable',
  'application/x-msi',
  'application/x-sh',
  'application/x-shellscript',
  'application/x-executable',
  'application/x-mach-binary',
  'application/java-archive',
]);

export function extractUrlsFromText(rawText: string): {
  urls: string[];
  rejectedTokens: string[];
} {
  const urls: string[] = [];
  const seen = new Set<string>();
  const rejectedTokens: string[] = [];
  const seenRejected = new Set<string>();

  const httpMatches = rawText.match(/https?:\/\/[^\s<>"'`]+/gi) ?? [];
  for (const match of httpMatches) {
    let cleaned = match.trim();
    // Strip trailing punctuation often included when copying from chat/docs
    while (cleaned.length > 0 && /[.,;!?"'>\]]$/.test(cleaned)) {
      cleaned = cleaned.slice(0, -1);
    }
    while (cleaned.endsWith(')')) {
      const openCount = (cleaned.match(/\(/g) ?? []).length;
      const closeCount = (cleaned.match(/\)/g) ?? []).length;
      if (closeCount > openCount) {
        cleaned = cleaned.slice(0, -1);
      } else {
        break;
      }
    }
    try {
      const parsed = new URL(cleaned);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') continue;
      const canonical = parsed.toString();
      if (!seen.has(canonical)) {
        seen.add(canonical);
        urls.push(canonical);
      }
    } catch {
      if (!seenRejected.has(cleaned)) {
        seenRejected.add(cleaned);
        rejectedTokens.push(cleaned);
      }
    }
  }

  // Flag explicit unsafe/unsupported schemes pasted by user
  const unsafeSchemeMatches =
    rawText.match(/(?:javascript|file|data|vbscript|ftp|magnet):[^\s<>"'`]*/gi) ?? [];
  for (const token of unsafeSchemeMatches) {
    if (!seenRejected.has(token)) {
      seenRejected.add(token);
      rejectedTokens.push(token);
    }
  }

  return { urls, rejectedTokens };
}

export function parseContentDispositionFilename(header?: string): string | null {
  if (!header) return null;
  // RFC 5987 filename*=UTF-8''...
  const extMatch = header.match(/filename\*\s*=\s*(?:UTF-8|utf-8|ISO-8859-1|iso-8859-1)?''([^;\r\n]+)/i);
  if (extMatch && extMatch[1]) {
    const raw = extMatch[1].trim().replace(/^["']|["']$/g, '');
    try {
      return decodeURIComponent(raw);
    } catch {
      return raw;
    }
  }
  const quotedMatch = header.match(/filename\s*=\s*"([^"\r\n]+)"/i);
  if (quotedMatch && quotedMatch[1]) {
    return quotedMatch[1].trim();
  }
  const plainMatch = header.match(/filename\s*=\s*([^;\r\n]+)/i);
  if (plainMatch && plainMatch[1]) {
    return plainMatch[1].trim().replace(/^["']|["']$/g, '');
  }
  return null;
}

export function extensionFromMime(contentType?: string): string {
  if (!contentType) return '';
  const mime = contentType.split(';')[0]?.trim().toLowerCase() ?? '';
  return MIME_TO_EXT[mime] ?? '';
}

export function sanitizeFilename(rawName: string, fallbackExt = ''): string {
  let name = rawName.trim();
  try {
    name = decodeURIComponent(name);
  } catch {
    // Keep raw if malformed percent encoding
  }
  // Normalize slashes and grab basename only (strips traversal like ../../foo)
  name = name.replace(/\\/g, '/');
  const lastSlash = name.lastIndexOf('/');
  if (lastSlash !== -1) {
    name = name.slice(lastSlash + 1);
  }
  // Replace Windows illegal characters & control chars
  name = name.replace(/[<>:"/\\|?*\x00-\x1f]/g, '_');
  // Collapse whitespace
  name = name.replace(/\s+/g, ' ').trim();
  // Trim trailing dots/spaces (invalid on Windows)
  name = name.replace(/[.\s]+$/, '');

  if (!name || name === '.' || name === '..') {
    name = 'download';
  }

  let ext = path.extname(name);
  let stem = ext ? name.slice(0, -ext.length) : name;

  if (!ext && fallbackExt) {
    ext = fallbackExt.startsWith('.') ? fallbackExt : `.${fallbackExt}`;
  }

  stem = stem.replace(/[.\s]+$/, '') || 'download';

  if (RESERVED_DOS_NAMES.has(stem.toUpperCase())) {
    stem = `_${stem}`;
  }

  const maxStemLen = Math.max(16, 180 - ext.length);
  if (stem.length > maxStemLen) {
    stem = stem.slice(0, maxStemLen).replace(/[.\s]+$/, '');
  }

  return `${stem}${ext}`;
}

export async function resolveUniquePath(
  dir: string,
  filename: string
): Promise<{ filename: string; savedPath: string; partPath: string }> {
  const safe = sanitizeFilename(filename);
  const ext = path.extname(safe);
  const stem = ext ? safe.slice(0, -ext.length) : safe;

  const exists = async (filePath: string): Promise<boolean> => {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  };

  for (let i = 0; i < 500; i++) {
    const candidate = i === 0 ? safe : `${stem} (${i})${ext}`;
    const savedPath = path.join(dir, candidate);
    const partPath = `${savedPath}.part`;
    const legacyPartPath = `${savedPath}.boltpart`;
    if (!(await exists(savedPath)) && !(await exists(partPath)) && !(await exists(legacyPartPath))) {
      return { filename: candidate, savedPath, partPath };
    }
  }

  const fallback = `${stem}-${Date.now()}${ext}`;
  const savedPath = path.join(dir, fallback);
  return { filename: fallback, savedPath, partPath: `${savedPath}.part` };
}

export async function reserveExclusiveStagingFile(
  dir: string,
  desiredFilename: string,
  jobId: string
): Promise<{
  filename: string;
  savedPath: string;
  partPath: string;
  handle: fs.FileHandle;
}> {
  await fs.mkdir(dir, { recursive: true });
  const { filename, savedPath } = await resolveUniquePath(dir, desiredFilename);
  const ext = path.extname(filename);
  const rawStem = ext ? filename.slice(0, -ext.length) : filename;
  const shortStem = rawStem.slice(0, 64).replace(/[.\s]+$/, '') || 'file';
  const safeJobId = jobId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 16) || 'job';

  for (let i = 0; i < 200; i++) {
    const suffix = i === 0 ? '' : `-${i}`;
    const partName = `.boltgate-${safeJobId}${suffix}-${shortStem}${ext}.part`;
    const reserved = await tryReserveStagingPair(path.join(dir, partName));
    if (reserved) return { filename, savedPath, partPath: reserved.partPath, handle: reserved.handle };
  }

  for (let i = 0; i < 20; i++) {
    const randPartPath = path.join(
      dir,
      `.boltgate-${safeJobId}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.part`
    );
    const reserved = await tryReserveStagingPair(randPartPath);
    if (reserved) return { filename, savedPath, partPath: reserved.partPath, handle: reserved.handle };
  }
  throw new Error('Could not reserve an exclusive staging payload + checkpoint sidecar pair');
}

/** Suffix of the `.part.meta` checkpoint sidecar paired with every staging payload. */
export const PART_META_SUFFIX = '.meta';

/**
 * Reserves a staging payload AND its `.part.meta` sidecar identity together, both exclusively.
 * A slot whose sidecar already exists (e.g. an orphaned or locked stale checkpoint) is never
 * paired with a new payload, so a stale checkpoint can never sit over a newly allocated file.
 * The sidecar placeholder is empty (an invalid checkpoint) until the runner writes real metadata.
 */
async function tryReserveStagingPair(
  partPath: string
): Promise<{ partPath: string; handle: fs.FileHandle } | null> {
  let handle: fs.FileHandle;
  try {
    handle = await fs.open(partPath, 'wx+');
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code === 'EEXIST') return null;
    throw err;
  }
  const metaPath = `${partPath}${PART_META_SUFFIX}`;
  try {
    const metaFh = await fs.open(metaPath, 'wx');
    await metaFh.close();
    return { partPath, handle };
  } catch (err) {
    // Release ONLY the payload we just created; never touch the pre-existing sidecar.
    await handle.close().catch(() => undefined);
    await fs.unlink(partPath).catch(() => undefined);
    if ((err as NodeJS.ErrnoException)?.code === 'EEXIST') return null;
    throw err;
  }
}

export interface FileIdentity {
  dev: bigint;
  ino: bigint;
  size: bigint;
  mtimeNs: bigint;
}

/** Captures the physical identity of a regular, non-symlink file (rejects links/junctions). */
export async function captureFileIdentity(filePath: string): Promise<FileIdentity> {
  const st = await fs.lstat(filePath, { bigint: true });
  if (st.isSymbolicLink() || !st.isFile()) {
    throw new Error(`Refusing non-regular or symlinked file at ${path.basename(filePath)}`);
  }
  return { dev: st.dev, ino: st.ino, size: st.size, mtimeNs: st.mtimeNs };
}

export function sameFileIdentity(a: FileIdentity, b: FileIdentity): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeNs === b.mtimeNs;
}

/**
 * Validates that `targetDir` is physically inside `rootDir`: every existing path component BELOW
 * the user-chosen root must be a real directory (no symlinks / junctions / reparse points), and the
 * resolved real path must stay inside the real root.
 */
export async function assertPhysicalDirInside(targetDir: string, rootDir: string): Promise<void> {
  const resolvedRoot = path.resolve(rootDir);
  const resolvedTarget = path.resolve(targetDir);
  if (!isPathInsideDir(resolvedTarget, resolvedRoot)) {
    throw new Error('Publication directory escapes the destination folder');
  }
  const rootStat = await fs.stat(resolvedRoot).catch(() => null);
  if (rootStat && !rootStat.isDirectory()) {
    throw new Error('Destination folder is not a directory');
  }
  const rel = path.relative(resolvedRoot, resolvedTarget);
  let cursor = resolvedRoot;
  for (const part of rel ? rel.split(path.sep) : []) {
    cursor = path.join(cursor, part);
    const st = await fs.lstat(cursor).catch((err: NodeJS.ErrnoException) => {
      if (err?.code === 'ENOENT') return null;
      throw err;
    });
    if (!st) break;
    if (st.isSymbolicLink() || !st.isDirectory()) {
      throw new Error(`Refusing to publish through symlink/junction or non-directory "${part}"`);
    }
  }
  const realRoot = await fs.realpath(resolvedRoot).catch(() => resolvedRoot);
  const realTarget = await fs.realpath(resolvedTarget).catch(() => null);
  if (realTarget && !isPathInsideDir(realTarget, realRoot)) {
    throw new Error('Publication directory physically resolves outside the destination folder');
  }
}

export interface PublishFsOps {
  mkdir?: typeof fs.mkdir;
  link?: typeof fs.link;
  unlink?: typeof fs.unlink;
  open?: typeof fs.open;
  preserveStaging?: boolean;
  /**
   * Physical identity of the staging file captured when it was verified (hashed). Publication is
   * refused if the staging file was swapped/replaced since, and the published path is re-checked.
   */
  expectedIdentity?: FileIdentity;
  /** Destination root the publication directory must physically stay inside (no symlinks). */
  physicalRootDir?: string;
}

async function copyStagingToHiddenTempInDir(
  stagingPath: string,
  destinationDir: string,
  openFn: typeof fs.open,
  unlinkFn: typeof fs.unlink
): Promise<string> {
  let destFh: fs.FileHandle | null = null;
  let tmpPath = '';

  for (let attempt = 0; attempt < 20; attempt++) {
    tmpPath = path.join(
      destinationDir,
      `.boltgate-pub-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.tmp`
    );
    try {
      destFh = await openFn(tmpPath, 'wx');
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code === 'EEXIST') continue;
      throw err;
    }
  }
  if (!destFh) {
    throw new Error('Could not allocate hidden temporary file for atomic publication');
  }

  let srcFh: fs.FileHandle | null = null;
  try {
    srcFh = await openFn(stagingPath, 'r');
    const buf = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0;
    while (true) {
      const { bytesRead } = await srcFh.read(buf, 0, buf.length, offset);
      if (bytesRead <= 0) break;
      let written = 0;
      while (written < bytesRead) {
        const res = await destFh.write(buf, written, bytesRead - written, offset + written);
        if (res.bytesWritten <= 0) {
          throw new Error('Zero bytes written while staging file for atomic publication');
        }
        written += res.bytesWritten;
      }
      offset += bytesRead;
    }
    await destFh.datasync();
  } catch (err) {
    await destFh.close().catch(() => undefined);
    await unlinkFn(tmpPath).catch(() => undefined);
    throw err;
  } finally {
    if (srcFh) await srcFh.close().catch(() => undefined);
  }
  await destFh.close();
  return tmpPath;
}

/**
 * Publishes a verified staging file to a non-colliding final destination path atomically
 * without replacing existing files or ever exposing a partial file at the destination path.
 * On cross-device EXDEV, copies into a hidden temp file in `destinationDir`, datasyncs, then
 * publishes via atomic no-replace hard link. If atomic no-replace linking is unsupported
 * (EPERM / ENOTSUP), cleans up any temp file, preserves the verified staging file, and throws.
 */
export async function publishStagingFileAtomically(
  stagingPath: string,
  destinationDir: string,
  desiredFilename: string,
  fsOps: PublishFsOps = {}
): Promise<{ filename: string; savedPath: string }> {
  const mkdirFn = fsOps.mkdir ?? fs.mkdir;
  const linkFn = fsOps.link ?? fs.link;
  const unlinkFn = fsOps.unlink ?? fs.unlink;
  const openFn = fsOps.open ?? fs.open;

  await mkdirFn(destinationDir, { recursive: true });
  // Validate the physical publication directory (no symlink/junction escapes) BEFORE linking
  await assertPhysicalDirInside(destinationDir, fsOps.physicalRootDir ?? destinationDir);
  const safe = sanitizeFilename(desiredFilename);
  const ext = path.extname(safe);
  const stem = ext ? safe.slice(0, -ext.length) : safe;

  // Validate the staging file is still the exact regular file that was verified
  const stagingIdentity = await captureFileIdentity(stagingPath);
  if (fsOps.expectedIdentity && !sameFileIdentity(fsOps.expectedIdentity, stagingIdentity)) {
    throw new Error('Verified staging file was replaced or modified before publication');
  }

  let linkSourcePath = stagingPath;
  let linkSourceIdentity = stagingIdentity;
  let sameDirTmpPath: string | null = null;

  /** Confirms the published path is physically the file we linked (same dev/inode/size). */
  const assertPublishedIdentity = async (candidatePath: string) => {
    const published = await captureFileIdentity(candidatePath);
    if (
      published.dev !== linkSourceIdentity.dev ||
      published.ino !== linkSourceIdentity.ino ||
      published.size !== linkSourceIdentity.size
    ) {
      throw new Error('Published file identity does not match the verified staging file');
    }
  };

  const tryPublishCandidate = async (
    candidateName: string
  ): Promise<{ filename: string; savedPath: string } | null> => {
    const candidatePath = path.join(destinationDir, candidateName);
    try {
      await linkFn(linkSourcePath, candidatePath);
      await assertPublishedIdentity(candidatePath);
      if (sameDirTmpPath) {
        await unlinkFn(sameDirTmpPath).catch(() => undefined);
      }
      if (!fsOps.preserveStaging) {
        await unlinkFn(stagingPath).catch(() => undefined);
      }
      return { filename: candidateName, savedPath: candidatePath };
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === 'EEXIST') {
        return null;
      }
      if (code === 'EXDEV' && !sameDirTmpPath) {
        // Cross-device move: copy into a hidden synced temp file inside destinationDir,
        // then retry atomic no-replace hard link without ever exposing a partial target.
        sameDirTmpPath = await copyStagingToHiddenTempInDir(
          stagingPath,
          destinationDir,
          openFn,
          unlinkFn
        );
        linkSourcePath = sameDirTmpPath;
        linkSourceIdentity = await captureFileIdentity(sameDirTmpPath);
        if (linkSourceIdentity.size !== stagingIdentity.size) {
          throw new Error('Cross-device publication copy size mismatch');
        }
        try {
          await linkFn(linkSourcePath, candidatePath);
          await assertPublishedIdentity(candidatePath);
          await unlinkFn(sameDirTmpPath).catch(() => undefined);
          if (!fsOps.preserveStaging) {
            await unlinkFn(stagingPath).catch(() => undefined);
          }
          return { filename: candidateName, savedPath: candidatePath };
        } catch (retryErr) {
          const retryCode = (retryErr as NodeJS.ErrnoException)?.code;
          if (retryCode === 'EEXIST') {
            return null;
          }
          await unlinkFn(sameDirTmpPath).catch(() => undefined);
          sameDirTmpPath = null;
          if (retryCode === 'EPERM' || retryCode === 'ENOTSUP' || retryCode === 'EXDEV') {
            throw Object.assign(
              new Error(
                `Atomic no-replace publication is unavailable on destination filesystem (${retryCode}); verified staging file preserved at ${stagingPath}`
              ),
              { code: retryCode }
            );
          }
          throw retryErr;
        }
      }
      if (sameDirTmpPath) {
        await unlinkFn(sameDirTmpPath).catch(() => undefined);
        sameDirTmpPath = null;
      }
      if (code === 'EPERM' || code === 'ENOTSUP') {
        throw Object.assign(
          new Error(
            `Atomic no-replace publication is unavailable on destination filesystem (${code}); verified staging file preserved at ${stagingPath}`
          ),
          { code }
        );
      }
      throw err;
    }
  };

  try {
    for (let i = 0; i < 500; i++) {
      const candidateName = i === 0 ? safe : `${stem} (${i})${ext}`;
      const published = await tryPublishCandidate(candidateName);
      if (published) return published;
    }

    const fallbackName = `${stem}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}${ext}`;
    const published = await tryPublishCandidate(fallbackName);
    if (published) return published;
    throw new Error(`Could not publish non-colliding destination path for ${safe}`);
  } catch (err) {
    if (sameDirTmpPath) {
      await unlinkFn(sameDirTmpPath).catch(() => undefined);
    }
    throw err;
  }
}

export function classifyFile(
  filename: string,
  contentType?: string
): {
  extension: string;
  category: FileCategory;
  isExecutable: boolean;
  riskTier: 'low' | 'medium' | 'high';
  hasDoubleExtension: boolean;
} {
  const lower = filename.toLowerCase();
  const extension = path.extname(lower);
  const stem = extension ? lower.slice(0, -extension.length) : lower;
  const innerExt = path.extname(stem);

  const isExecutable = EXECUTABLE_EXTS.has(extension);
  const hasDoubleExtension =
    (isExecutable || extension === '.dmg' || extension === '.pkg') &&
    INNOCENT_OUTER_EXTS.has(innerExt);

  let category: FileCategory = 'other';
  if (isExecutable) {
    category = 'software';
  } else if (CATEGORY_BY_EXT[extension]) {
    category = CATEGORY_BY_EXT[extension];
  } else if (contentType) {
    const mime = contentType.split(';')[0]?.trim().toLowerCase() ?? '';
    if (
      mime === 'application/epub+zip' ||
      mime === 'application/x-mobipocket-ebook' ||
      mime === 'image/vnd.djvu' ||
      mime === 'image/x-djvu' ||
      mime === 'application/vnd.comicbook+zip' ||
      mime === 'application/x-fictionbook+xml'
    ) {
      category = 'ebook';
    } else if (mime.startsWith('video/')) category = 'video';
    else if (mime.startsWith('audio/')) category = 'audio';
    else if (mime.startsWith('image/')) category = 'image';
    else if (mime === 'application/pdf' || mime.startsWith('text/')) category = 'document';
    else if (mime.includes('zip') || mime.includes('tar') || mime.includes('compressed'))
      category = 'archive';
  }

  const riskTier: 'low' | 'medium' | 'high' =
    isExecutable || hasDoubleExtension
      ? 'high'
      : category === 'archive' || category === 'disk'
        ? 'medium'
        : 'low';

  return { extension, category, isExecutable, riskTier, hasDoubleExtension };
}

export function checkMimeExtensionMismatch(
  extension: string,
  contentType?: string
): { mismatch: boolean; severity?: 'warn' | 'danger'; reason?: string } {
  if (!contentType) return { mismatch: false };
  const mime = contentType.split(';')[0]?.trim().toLowerCase() ?? '';
  if (!mime || mime === 'application/octet-stream' || mime === 'binary/octet-stream') {
    return { mismatch: false };
  }

  const ext = extension.toLowerCase();

  // HTML returned for non-HTML file extension (common phishing/login-wall/broken link)
  if (
    (mime === 'text/html' || mime === 'application/xhtml+xml') &&
    ext !== '' &&
    ext !== '.html' &&
    ext !== '.htm' &&
    ext !== '.xhtml'
  ) {
    return {
      mismatch: true,
      severity: 'danger',
      reason: `Server returned an HTML page (${mime}) instead of a ${ext} file. This link may lead to a login wall, countdown page, or broken redirect.`,
    };
  }

  // Executable MIME disguised under non-executable extension
  if (EXECUTABLE_MIMES.has(mime) && !EXECUTABLE_EXTS.has(ext)) {
    return {
      mismatch: true,
      severity: 'danger',
      reason: `Server sent an executable binary (${mime}) while filename claims "${ext || 'no extension'}".`,
    };
  }

  // Media / document extension serving text/plain or unrelated image/video mismatch
  if (
    ['.mp4', '.mkv', '.mp3', '.zip', '.7z', '.iso', '.exe', '.msi'].includes(ext) &&
    mime === 'text/plain'
  ) {
    return {
      mismatch: true,
      severity: 'warn',
      reason: `Server reported text/plain for a ${ext} file. Verify the link isn't an error message.`,
    };
  }

  return { mismatch: false };
}

export function normalizeHostname(host: string): string {
  return host.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}

export function isPrivateOrIpHost(hostname: string): boolean {
  const host = normalizeHostname(hostname);
  if (!host) return false;
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) {
    return true;
  }
  const ipVersion = net.isIP(host);
  if (ipVersion === 4) {
    return true;
  }
  if (ipVersion === 6) {
    return true;
  }
  return false;
}

export function isLoopbackOrPrivateIp(hostname: string): boolean {
  const host = normalizeHostname(hostname);
  if (host === 'localhost' || host === '::1') return true;
  if (net.isIPv4(host)) {
    const parts = host.split('.').map(Number);
    if (parts[0] === 127 || parts[0] === 10 || parts[0] === 0) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
  }
  return false;
}

export function matchDomainTrust(
  hostname: string,
  rules: TrustRule[]
): 'trusted' | 'blocked' | 'unknown' {
  const host = normalizeHostname(hostname);
  if (!host) return 'unknown';

  let bestRule: TrustRule | null = null;
  let bestLen = -1;

  for (const rule of rules) {
    const ruleHost = normalizeHostname(rule.domain);
    if (!ruleHost) continue;
    const isMatch = host === ruleHost || host.endsWith(`.${ruleHost}`);
    if (!isMatch) continue;

    if (ruleHost.length > bestLen) {
      bestLen = ruleHost.length;
      bestRule = rule;
    } else if (ruleHost.length === bestLen && rule.status === 'blocked') {
      bestRule = rule;
    }
  }

  return bestRule ? bestRule.status : 'unknown';
}

export function normalizeDomainRuleInput(input: string): string | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  try {
    const url = trimmed.includes('://') ? new URL(trimmed) : new URL(`https://${trimmed}`);
    const host = normalizeHostname(url.hostname);
    return host || null;
  } catch {
    return null;
  }
}

export function isPathInsideDir(targetPath: string, parentDir: string): boolean {
  const resolvedTarget = path.resolve(targetPath);
  const resolvedParent = path.resolve(parentDir);
  if (resolvedTarget === resolvedParent) return true;
  const rel = path.relative(resolvedParent, resolvedTarget);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}
