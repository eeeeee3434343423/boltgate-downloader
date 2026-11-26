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
    const partPath = `${savedPath}.boltpart`;
    if (!(await exists(savedPath)) && !(await exists(partPath))) {
      return { filename: candidate, savedPath, partPath };
    }
  }

  const fallback = `${stem}-${Date.now()}${ext}`;
  const savedPath = path.join(dir, fallback);
  return { filename: fallback, savedPath, partPath: `${savedPath}.boltpart` };
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
