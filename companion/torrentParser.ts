import crypto from 'node:crypto';
import type { TorrentFileEntry } from '../shared/types.js';
import { sanitizeFilename } from '../server/utils.js';

type BencodeValue =
  | number
  | Buffer
  | BencodeValue[]
  | { [key: string]: BencodeValue };

interface DecodeResult {
  value: BencodeValue;
  nextOffset: number;
  infoSlice?: Buffer;
}

function decodeValue(buf: Buffer, offset: number, captureInfo = false): DecodeResult {
  if (offset >= buf.length) {
    throw new Error('Unexpected end of bencode stream');
  }
  const ch = buf[offset]!;

  // Integer: i<number>e
  if (ch === 0x69 /* 'i' */) {
    const endIdx = buf.indexOf(0x65 /* 'e' */, offset + 1);
    if (endIdx === -1) throw new Error('Unterminated bencode integer');
    const numStr = buf.subarray(offset + 1, endIdx).toString('ascii');
    const val = Number(numStr);
    if (!Number.isFinite(val)) throw new Error(`Invalid bencode integer: ${numStr}`);
    return { value: val, nextOffset: endIdx + 1 };
  }

  // List: l...e
  if (ch === 0x6c /* 'l' */) {
    const items: BencodeValue[] = [];
    let pos = offset + 1;
    while (pos < buf.length && buf[pos] !== 0x65 /* 'e' */) {
      const res = decodeValue(buf, pos, false);
      items.push(res.value);
      pos = res.nextOffset;
    }
    if (pos >= buf.length) throw new Error('Unterminated bencode list');
    return { value: items, nextOffset: pos + 1 };
  }

  // Dict: d...e
  if (ch === 0x64 /* 'd' */) {
    const dict: Record<string, BencodeValue> = {};
    let pos = offset + 1;
    let infoSlice: Buffer | undefined;
    while (pos < buf.length && buf[pos] !== 0x65 /* 'e' */) {
      const keyRes = decodeValue(buf, pos, false);
      if (!Buffer.isBuffer(keyRes.value)) {
        throw new Error('Bencode dictionary key must be a byte string');
      }
      const key = keyRes.value.toString('utf8');
      const valStart = keyRes.nextOffset;
      const valRes = decodeValue(buf, valStart, false);
      if (captureInfo && key === 'info') {
        infoSlice = buf.subarray(valStart, valRes.nextOffset);
      } else if (valRes.infoSlice && !infoSlice) {
        infoSlice = valRes.infoSlice;
      }
      dict[key] = valRes.value;
      pos = valRes.nextOffset;
    }
    if (pos >= buf.length) throw new Error('Unterminated bencode dictionary');
    return { value: dict, nextOffset: pos + 1, infoSlice };
  }

  // Byte string: <len>:<bytes>
  if (ch >= 0x30 && ch <= 0x39) {
    const colonIdx = buf.indexOf(0x3a /* ':' */, offset);
    if (colonIdx === -1) throw new Error('Invalid bencode byte string length');
    const len = Number(buf.subarray(offset, colonIdx).toString('ascii'));
    if (!Number.isInteger(len) || len < 0) {
      throw new Error('Negative or invalid bencode string length');
    }
    const start = colonIdx + 1;
    const end = start + len;
    if (end > buf.length) throw new Error('Truncated bencode byte string');
    return { value: buf.subarray(start, end), nextOffset: end };
  }

  throw new Error(`Unexpected bencode token byte 0x${ch.toString(16)} at offset ${offset}`);
}

export interface ParsedTorrentMetadata {
  name: string;
  infoHash: string;
  totalBytes: number;
  files: TorrentFileEntry[];
  /**
   * Every embedded destination aria2c may contact on its own: trackers (`announce`,
   * `announce-list`) and web seeds (`url-list`, `httpseeds`).
   */
  outboundUrls: string[];
}

function collectByteStrings(val: BencodeValue | undefined, out: string[]): void {
  if (val === undefined) return;
  if (Buffer.isBuffer(val)) {
    const s = val.toString('utf8').trim();
    if (s) out.push(s);
    return;
  }
  if (Array.isArray(val)) {
    for (const v of val) collectByteStrings(v, out);
  }
}

function collectOutboundUrls(root: { [key: string]: BencodeValue }): string[] {
  const urls: string[] = [];
  collectByteStrings(root.announce, urls);
  collectByteStrings(root['announce-list'], urls);
  collectByteStrings(root['url-list'], urls);
  collectByteStrings(root.httpseeds, urls);
  return Array.from(new Set(urls));
}

/**
 * Decodes a `.torrent` metadata buffer into its infoHash, name, and 1-based file manifest.
 */
export function parseTorrentMetadata(buf: Buffer): ParsedTorrentMetadata {
  const root = decodeValue(buf, 0, true);
  if (typeof root.value !== 'object' || Buffer.isBuffer(root.value) || Array.isArray(root.value)) {
    throw new Error('Invalid torrent metadata root');
  }
  if (!root.infoSlice) {
    throw new Error('Torrent missing info dictionary');
  }

  const infoHash = crypto.createHash('sha1').update(root.infoSlice).digest('hex');
  const info = root.value.info;
  if (!info || typeof info !== 'object' || Buffer.isBuffer(info) || Array.isArray(info)) {
    throw new Error('Invalid torrent info dictionary');
  }

  const rawName = Buffer.isBuffer(info.name) ? info.name.toString('utf8') : 'torrent-download';
  const name = sanitizeFilename(rawName) || 'torrent-download';

  if (Array.isArray(info.files)) {
    const files: TorrentFileEntry[] = [];
    let totalBytes = 0;
    for (let i = 0; i < info.files.length; i++) {
      const entry = info.files[i];
      if (!entry || typeof entry !== 'object' || Buffer.isBuffer(entry) || Array.isArray(entry)) {
        continue;
      }
      const length = typeof entry.length === 'number' && entry.length >= 0 ? entry.length : 0;
      const pathParts = Array.isArray(entry.path)
        ? entry.path
            .filter((p): p is Buffer => Buffer.isBuffer(p))
            .map((p) => sanitizeFilename(p.toString('utf8')))
            .filter(Boolean)
        : [];
      const relPath = pathParts.length > 0 ? pathParts.join('/') : `file-${i + 1}`;
      files.push({
        index: i + 1,
        path: relPath,
        length,
      });
      totalBytes += length;
    }
    if (files.length === 0) {
      throw new Error('Torrent contains no valid files');
    }
    return { name, infoHash, totalBytes, files, outboundUrls: collectOutboundUrls(root.value) };
  }

  const singleLength = typeof info.length === 'number' && info.length >= 0 ? info.length : 0;
  return {
    name,
    infoHash,
    totalBytes: singleLength,
    files: [{ index: 1, path: name, length: singleLength }],
    outboundUrls: collectOutboundUrls(root.value),
  };
}
