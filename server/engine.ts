import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import type { DownloadItem, SegmentState } from '../shared/types.js';
import type { TokenBucketThrottle } from './throttle.js';
import { resolveUniquePath } from './utils.js';
import { verifyFileIntegrity } from './verifier.js';

export interface RunnerOptions {
  item: DownloadItem;
  throttle: TokenBucketThrottle;
  minSegmentBytes?: number;
  stallTimeoutMs?: number;
  maxRetries?: number;
  retryAfterCapMs?: number;
  onUpdate: (item: DownloadItem, immediatePersist?: boolean) => void;
}

class RetryableHttpError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly retryAfterMs: number,
    message: string
  ) {
    super(message);
    this.name = 'RetryableHttpError';
  }
}

interface MirrorMetric {
  url: string;
  bytes: number;
  speedBps: number;
  lastSampleBytes: number;
  cooldownUntil: number;
  failures: number;
}

const DEFAULT_MIN_SEGMENT_BYTES = 128 * 1024; // 128 KiB (enables 8-16 parallel streams on 1-10 MB ebooks)
const DEFAULT_STALL_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_RETRIES = 5;
const MAX_REDIRECTS = 10;

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 64 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 64 });

export class DownloadRunner {
  public readonly item: DownloadItem;
  private readonly throttle: TokenBucketThrottle;
  private readonly minSegmentBytes: number;
  private readonly stallTimeoutMs: number;
  private readonly maxRetries: number;
  private readonly retryAfterCapMs: number;
  private readonly onUpdate: (item: DownloadItem, immediatePersist?: boolean) => void;

  private abortController = new AbortController();
  private epoch = 0;
  private fileHandle: fs.FileHandle | null = null;
  private inFlightWrites = new Set<Promise<unknown>>();
  private activeWorkers = new Set<Promise<void>>();
  private activeRequests = new Set<http.ClientRequest>();
  private stopReason: 'none' | 'paused' | 'cancelled' = 'none';
  private nextSegmentId = 1;
  private telemetryTimer: NodeJS.Timeout | null = null;
  private lastSampleTime = Date.now();
  private lastSampleBytes = 0;
  private segLastSampleBytes = new Map<number, number>();
  private emaSpeedBps = 0;
  private mirrorMetrics: MirrorMetric[] = [];

  constructor(options: RunnerOptions) {
    this.item = options.item;
    this.throttle = options.throttle;
    this.minSegmentBytes = options.minSegmentBytes ?? DEFAULT_MIN_SEGMENT_BYTES;
    this.stallTimeoutMs = options.stallTimeoutMs ?? DEFAULT_STALL_TIMEOUT_MS;
    this.maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.retryAfterCapMs = options.retryAfterCapMs ?? 60_000;
    this.onUpdate = options.onUpdate;
  }

  private getStopReason(): 'none' | 'paused' | 'cancelled' {
    return this.stopReason;
  }

  async run(): Promise<void> {
    this.stopReason = 'none';
    this.abortController = new AbortController();
    this.epoch += 1;
    this.item.status = 'downloading';
    this.item.error = undefined;
    if (!this.item.startedAt) {
      this.item.startedAt = Date.now();
    }

    try {
      await fs.mkdir(this.item.destinationDir, { recursive: true });

      const partExists = await fileExists(this.item.partPath);
      const canResumeExisting =
        partExists &&
        this.item.segments.length > 0 &&
        this.item.supportsRanges &&
        this.item.totalBytes !== null &&
        this.item.totalBytes > 0;

      if (!canResumeExisting) {
        if (!this.item.savedPath || !partExists || !this.item.supportsRanges) {
          const resolved = await resolveUniquePath(this.item.destinationDir, this.item.filename);
          this.item.filename = resolved.filename;
          this.item.savedPath = resolved.savedPath;
          this.item.partPath = resolved.partPath;
        }
        this.item.segments = this.buildInitialSegments();
        this.item.downloadedBytes = 0;
      } else {
        for (const seg of this.item.segments) {
          if (seg.end >= 0) {
            const maxSegBytes = seg.end - seg.start + 1;
            seg.downloaded = Math.max(0, Math.min(seg.downloaded, maxSegBytes));
          }
          seg.speedBps = 0;
          seg.status = seg.end >= 0 && seg.downloaded >= seg.end - seg.start + 1 ? 'done' : 'pending';
        }
        this.recomputeDownloadedTotal();
      }

      this.nextSegmentId =
        this.item.segments.reduce((max, s) => Math.max(max, s.id), 0) + 1;

      if (this.item.totalBytes === 0) {
        const fh = await fs.open(this.item.partPath, 'w+');
        await fh.close();
        await this.finalizeCompletedFile();
        return;
      }

      this.fileHandle = await fs.open(this.item.partPath, canResumeExisting ? 'r+' : 'w+');
      if (!canResumeExisting && this.item.totalBytes && this.item.totalBytes > 0) {
        await this.fileHandle.truncate(this.item.totalBytes);
      }

      this.lastSampleTime = Date.now();
      this.lastSampleBytes = this.item.downloadedBytes;
      const activeMirrors =
        this.item.mirrorUrls && this.item.mirrorUrls.length > 0
          ? this.item.mirrorUrls
          : [this.item.finalUrl];
      this.mirrorMetrics = activeMirrors.map((url) => ({
        url,
        bytes: 0,
        speedBps: 0,
        lastSampleBytes: 0,
        cooldownUntil: 0,
        failures: 0,
      }));
      for (const seg of this.item.segments) {
        this.segLastSampleBytes.set(seg.id, seg.downloaded);
      }

      this.startTelemetryTimer();
      this.onUpdate(this.item, true);

      const initialEpoch = this.epoch;
      for (const seg of this.item.segments) {
        if (seg.status !== 'done') {
          this.spawnWorker(seg, initialEpoch);
        }
      }

      while (this.activeWorkers.size > 0) {
        await Promise.allSettled(Array.from(this.activeWorkers));
      }

      await Promise.allSettled(Array.from(this.inFlightWrites));

      if (this.fileHandle) {
        await this.fileHandle.close();
        this.fileHandle = null;
      }

      this.stopTelemetryTimer();

      const stopAfterWait = this.getStopReason();
      if (stopAfterWait === 'paused') {
        this.item.status = 'paused';
        this.item.speedBps = 0;
        this.item.etaSeconds = null;
        for (const s of this.item.segments) {
          s.speedBps = 0;
          if (s.status !== 'done') s.status = 'paused';
        }
        this.recomputeDownloadedTotal();
        this.onUpdate(this.item, true);
        return;
      }

      if (stopAfterWait === 'cancelled') {
        await fs.unlink(this.item.partPath).catch(() => {});
        return;
      }

      const failedSeg = this.item.segments.find((s) => s.status === 'error');
      if (failedSeg) {
        throw new Error(failedSeg.lastError || `Segment ${failedSeg.id} failed`);
      }

      this.recomputeDownloadedTotal();
      if (
        this.item.totalBytes !== null &&
        this.item.downloadedBytes !== this.item.totalBytes
      ) {
        throw new Error(
          `Incomplete transfer: received ${this.item.downloadedBytes} of ${this.item.totalBytes} bytes`
        );
      }

      await this.finalizeCompletedFile();
    } catch (err) {
      this.stopTelemetryTimer();
      await Promise.allSettled(Array.from(this.inFlightWrites));
      if (this.fileHandle) {
        await this.fileHandle.close().catch(() => {});
        this.fileHandle = null;
      }

      const stopOnErr = this.getStopReason();
      if (stopOnErr === 'paused') {
        this.item.status = 'paused';
        this.item.speedBps = 0;
        this.item.etaSeconds = null;
        this.onUpdate(this.item, true);
        return;
      }

      if (stopOnErr === 'cancelled') {
        await fs.unlink(this.item.partPath).catch(() => {});
        return;
      }

      this.item.status = 'failed';
      this.item.speedBps = 0;
      this.item.etaSeconds = null;
      this.item.error = err instanceof Error ? err.message : String(err);
      for (const s of this.item.segments) {
        s.speedBps = 0;
        if (s.status === 'active') s.status = 'error';
      }
      this.onUpdate(this.item, true);
    }
  }

  async pause(): Promise<void> {
    if (this.stopReason !== 'none') return;
    this.stopReason = 'paused';
    this.epoch += 1;
    this.abortController.abort();
    for (const req of this.activeRequests) {
      req.destroy();
    }
    this.activeRequests.clear();
  }

  async cancel(deletePartFile = true): Promise<void> {
    this.stopReason = 'cancelled';
    this.epoch += 1;
    this.abortController.abort();
    for (const req of this.activeRequests) {
      req.destroy();
    }
    this.activeRequests.clear();
    while (this.activeWorkers.size > 0) {
      await Promise.allSettled(Array.from(this.activeWorkers));
    }
    await Promise.allSettled(Array.from(this.inFlightWrites));
    if (this.fileHandle) {
      await this.fileHandle.close().catch(() => {});
      this.fileHandle = null;
    }
    if (deletePartFile) {
      await fs.unlink(this.item.partPath).catch(() => {});
    }
  }

  private buildInitialSegments(): SegmentState[] {
    const total = this.item.totalBytes;
    const requested = Math.max(1, Math.min(16, this.item.connections || 1));
    const mirrorCount = Math.max(1, this.item.mirrorUrls?.length || this.mirrorMetrics.length || 1);

    if (!this.item.supportsRanges || total === null || total < this.minSegmentBytes * 2 || requested === 1) {
      return [
        {
          id: 0,
          start: 0,
          end: total !== null ? total - 1 : -1,
          downloaded: 0,
          speedBps: 0,
          status: 'pending',
          retries: 0,
          mirrorIndex: 0,
        },
      ];
    }

    const maxBySize = Math.max(1, Math.floor(total / this.minSegmentBytes));
    const count = Math.min(requested, maxBySize);
    const chunkSize = Math.floor(total / count);
    const segments: SegmentState[] = [];

    for (let i = 0; i < count; i++) {
      const start = i * chunkSize;
      const end = i === count - 1 ? total - 1 : (i + 1) * chunkSize - 1;
      segments.push({
        id: i,
        start,
        end,
        downloaded: 0,
        speedBps: 0,
        status: 'pending',
        retries: 0,
        mirrorIndex: i % mirrorCount,
      });
    }
    return segments;
  }

  private spawnWorker(seg: SegmentState, workerEpoch: number): void {
    const p = this.runSegmentWorker(seg, workerEpoch).finally(() => {
      this.activeWorkers.delete(p);
    });
    this.activeWorkers.add(p);
  }

  private async runSegmentWorker(seg: SegmentState, initialWorkerEpoch: number): Promise<void> {
    let workerEpoch = initialWorkerEpoch;
    seg.status = 'active';

    while (!this.abortController.signal.aborted && workerEpoch === this.epoch) {
      if (seg.end >= 0 && seg.start + seg.downloaded > seg.end) {
        seg.status = 'done';
        seg.speedBps = 0;
        this.tryStealWork(workerEpoch);
        return;
      }

      try {
        const result = await this.executeSegmentAttempt(seg, workerEpoch);
        if (result.switchedEpoch !== undefined) {
          // This worker transitioned the whole download cleanly to single-stream
          workerEpoch = result.switchedEpoch;
          seg = this.item.segments[0]!;
        }

        if (this.abortController.signal.aborted || workerEpoch !== this.epoch) {
          return;
        }

        if (seg.end === -1 || seg.start + seg.downloaded > seg.end) {
          seg.status = 'done';
          seg.speedBps = 0;
          this.tryStealWork(workerEpoch);
          return;
        }

        throw new Error(
          `Connection closed early at offset ${seg.start + seg.downloaded} (expected end ${seg.end})`
        );
      } catch (err) {
        if (
          this.abortController.signal.aborted ||
          workerEpoch !== this.epoch ||
          isAbortError(err)
        ) {
          return;
        }
        seg.retries += 1;
        seg.lastError = err instanceof Error ? err.message : String(err);

        const failedMirrorIdx = seg.mirrorIndex ?? 0;
        const failedMetric = this.mirrorMetrics[failedMirrorIdx];
        if (failedMetric) {
          failedMetric.failures += 1;
          failedMetric.cooldownUntil =
            Date.now() + (err instanceof RetryableHttpError ? err.retryAfterMs : 2_000);
        }

        const altIdx = this.pickHealthyAlternateMirror(failedMirrorIdx);
        if (altIdx !== null && seg.retries <= this.maxRetries + this.mirrorMetrics.length) {
          seg.mirrorIndex = altIdx;
          await abortableDelay(50, this.abortController.signal).catch(() => {});
          continue;
        }

        if (seg.retries > this.maxRetries) {
          seg.status = 'error';
          seg.speedBps = 0;
          this.epoch += 1;
          this.abortController.abort();
          return;
        }
        const backoffMs =
          err instanceof RetryableHttpError
            ? err.retryAfterMs
            : Math.min(12_000, 500 * Math.pow(2, seg.retries - 1));
        await abortableDelay(backoffMs, this.abortController.signal).catch(() => {});
      }
    }
  }

  private async executeSegmentAttempt(
    seg: SegmentState,
    workerEpoch: number
  ): Promise<{ switchedEpoch?: number }> {
    const isRanged = this.item.supportsRanges && seg.end >= 0;
    const rangeStart = seg.start + seg.downloaded;
    const headers: Record<string, string> = {
      'User-Agent': 'BoltGate/1.0 (+SafeDownloader)',
      Accept: '*/*',
    };

    if (isRanged) {
      headers.Range = `bytes=${rangeStart}-${seg.end}`;
      if (seg.downloaded > 0 && (this.item.etag || this.item.lastModified)) {
        headers['If-Range'] = (this.item.etag || this.item.lastModified)!;
      }
    }

    const mirrorIdx = seg.mirrorIndex ?? 0;
    const targetUrl = this.mirrorMetrics[mirrorIdx]?.url ?? this.item.finalUrl;

    const { res, req } = await this.openStreamWithRedirects(
      targetUrl,
      headers,
      workerEpoch
    );

    try {
      if (this.abortController.signal.aborted || workerEpoch !== this.epoch) {
        res.destroy();
        return {};
      }

      const status = res.statusCode ?? 0;

      // Server ignored Range header and sent full 200 OK body
      if (isRanged && status === 200) {
        const newEpoch = ++this.epoch;

        // Abort all sibling requests immediately except our winning 200 OK request
        for (const otherReq of this.activeRequests) {
          if (otherReq !== req) {
            otherReq.destroy();
          }
        }

        // Wait for any in-flight positional writes from retired range workers to finish
        await Promise.allSettled(Array.from(this.inFlightWrites));
        if (this.abortController.signal.aborted || this.epoch !== newEpoch) {
          res.destroy();
          return {};
        }

        const len = Number(res.headers['content-length']);
        const total = Number.isFinite(len) && len >= 0 ? len : this.item.totalBytes;

        this.item.supportsRanges = false;
        this.item.connections = 1;
        this.item.totalBytes = total;
        this.item.downloadedBytes = 0;
        this.item.mirrorUrls = [targetUrl];
        this.mirrorMetrics = [
          {
            url: targetUrl,
            bytes: 0,
            speedBps: 0,
            lastSampleBytes: 0,
            cooldownUntil: 0,
            failures: 0,
          },
        ];

        if (this.fileHandle) {
          await this.fileHandle.truncate(total && total > 0 ? total : 0);
        }

        const singleSeg: SegmentState = {
          id: 0,
          start: 0,
          end: total !== null ? total - 1 : -1,
          downloaded: 0,
          speedBps: 0,
          status: 'active',
          retries: 0,
          mirrorIndex: 0,
        };
        this.item.segments = [singleSeg];
        this.segLastSampleBytes.clear();
        this.segLastSampleBytes.set(0, 0);

        await this.streamResponseIntoSegment(singleSeg, res, newEpoch, 0);
        return { switchedEpoch: newEpoch };
      }

      if (status === 429 || status === 503) {
        const retryAfterMs = parseRetryAfterMs(res.headers['retry-after'], this.retryAfterCapMs);
        res.destroy();
        throw new RetryableHttpError(
          status,
          retryAfterMs,
          `Rate limited (HTTP ${status}) on segment ${seg.id}, waiting ${retryAfterMs}ms before retry`
        );
      }

      if (status < 200 || status >= 300) {
        res.destroy();
        throw new Error(`HTTP ${status} while fetching segment ${seg.id}`);
      }

      if (status === 200 && this.item.totalBytes === null) {
        const len = Number(res.headers['content-length']);
        if (Number.isFinite(len) && len >= 0) {
          this.item.totalBytes = len;
          seg.end = len - 1;
        }
      }

      await this.streamResponseIntoSegment(seg, res, workerEpoch, mirrorIdx);
      return {};
    } finally {
      this.activeRequests.delete(req);
      if (!res.destroyed) {
        res.destroy();
      }
    }
  }

  private async streamResponseIntoSegment(
    seg: SegmentState,
    res: http.IncomingMessage,
    workerEpoch: number,
    mirrorIdx = 0
  ): Promise<void> {
    let stallTimer: NodeJS.Timeout | null = null;
    const resetStall = () => {
      if (stallTimer) clearTimeout(stallTimer);
      stallTimer = setTimeout(() => {
        res.destroy(new Error(`Segment ${seg.id} stalled (no data for ${this.stallTimeoutMs}ms)`));
      }, this.stallTimeoutMs);
    };

    const onAbort = () => {
      res.destroy();
    };
    this.abortController.signal.addEventListener('abort', onAbort, { once: true });
    resetStall();

    try {
      for await (const rawChunk of res) {
        if (this.abortController.signal.aborted || workerEpoch !== this.epoch) {
          res.destroy();
          break;
        }
        resetStall();

        const buf = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
        if (buf.length === 0) continue;

        let slice = buf;
        if (seg.end >= 0) {
          const remaining = seg.end - (seg.start + seg.downloaded) + 1;
          if (remaining <= 0) {
            res.destroy();
            break;
          }
          if (slice.length > remaining) {
            slice = slice.subarray(0, remaining);
          }
        }

        await this.throttle.consume(slice.length, this.abortController.signal);
        if (this.abortController.signal.aborted || workerEpoch !== this.epoch) {
          res.destroy();
          break;
        }

        if (seg.end >= 0) {
          const remainingAfterThrottle = seg.end - (seg.start + seg.downloaded) + 1;
          if (remainingAfterThrottle <= 0) {
            res.destroy();
            break;
          }
          if (slice.length > remainingAfterThrottle) {
            slice = slice.subarray(0, remainingAfterThrottle);
          }
        }

        if (!this.fileHandle) {
          throw new Error('File handle closed unexpectedly');
        }

        // Advance cursors synchronously before awaiting pwrite so work-stealing never overlaps
        const writeOffset = seg.start + seg.downloaded;
        seg.downloaded += slice.length;
        this.item.downloadedBytes += slice.length;
        if (this.mirrorMetrics[mirrorIdx]) {
          this.mirrorMetrics[mirrorIdx]!.bytes += slice.length;
        }

        const writePromise = this.fileHandle.write(slice, 0, slice.length, writeOffset);
        this.inFlightWrites.add(writePromise);
        try {
          await writePromise;
        } finally {
          this.inFlightWrites.delete(writePromise);
        }

        if (seg.end >= 0 && seg.start + seg.downloaded > seg.end) {
          res.destroy();
          break;
        }
      }
    } finally {
      if (stallTimer) clearTimeout(stallTimer);
      this.abortController.signal.removeEventListener('abort', onAbort);
    }
  }

  private tryStealWork(workerEpoch: number): void {
    if (
      this.abortController.signal.aborted ||
      workerEpoch !== this.epoch ||
      !this.item.supportsRanges
    ) {
      return;
    }

    let bestDonor: SegmentState | null = null;
    let bestRemaining = 0;

    for (const candidate of this.item.segments) {
      if (candidate.status !== 'active' || candidate.end < 0) continue;
      const cursor = candidate.start + candidate.downloaded;
      const remaining = candidate.end - cursor + 1;
      if (remaining > bestRemaining) {
        bestRemaining = remaining;
        bestDonor = candidate;
      }
    }

    if (!bestDonor || bestRemaining < this.minSegmentBytes * 2) {
      return;
    }

    const cursor = bestDonor.start + bestDonor.downloaded;
    const mid = cursor + Math.floor(bestRemaining / 2);
    const oldEnd = bestDonor.end;
    if (mid <= cursor || mid > oldEnd) return;

    bestDonor.end = mid - 1;
    const stolen: SegmentState = {
      id: this.nextSegmentId++,
      start: mid,
      end: oldEnd,
      downloaded: 0,
      speedBps: 0,
      status: 'pending',
      retries: 0,
      mirrorIndex: this.pickFastestMirrorIndex(bestDonor.mirrorIndex),
    };
    this.item.segments.push(stolen);
    this.segLastSampleBytes.set(stolen.id, 0);
    this.spawnWorker(stolen, workerEpoch);
  }

  private pickHealthyAlternateMirror(excludeIdx: number): number | null {
    if (this.mirrorMetrics.length <= 1) return null;
    const now = Date.now();
    let bestIdx: number | null = null;
    let bestScore = -1;

    for (let i = 0; i < this.mirrorMetrics.length; i++) {
      if (i === excludeIdx) continue;
      const m = this.mirrorMetrics[i]!;
      if (m.cooldownUntil > now) continue;
      const score = m.speedBps * 10 - m.failures;
      if (bestIdx === null || score > bestScore) {
        bestIdx = i;
        bestScore = score;
      }
    }
    return bestIdx;
  }

  private pickFastestMirrorIndex(fallbackIdx = 0): number {
    if (this.mirrorMetrics.length <= 1) return 0;
    const now = Date.now();
    let bestIdx = fallbackIdx;
    let bestSpeed = -1;

    for (let i = 0; i < this.mirrorMetrics.length; i++) {
      const m = this.mirrorMetrics[i]!;
      if (m.cooldownUntil > now) continue;
      if (m.speedBps > bestSpeed) {
        bestSpeed = m.speedBps;
        bestIdx = i;
      }
    }
    return bestIdx;
  }

  private openStreamWithRedirects(
    startUrl: string,
    headers: Record<string, string>,
    workerEpoch: number
  ): Promise<{ res: http.IncomingMessage; req: http.ClientRequest }> {
    return new Promise((resolve, reject) => {
      const follow = (target: URL, hop: number) => {
        if (this.abortController.signal.aborted || workerEpoch !== this.epoch) {
          reject(new DOMException('Aborted', 'AbortError'));
          return;
        }
        const isHttps = target.protocol === 'https:';
        const client = isHttps ? https : http;
        const req = client.request(
          target,
          {
            method: 'GET',
            headers,
            agent: isHttps ? httpsAgent : httpAgent,
            timeout: this.stallTimeoutMs,
          },
          (res) => {
            const status = res.statusCode ?? 0;
            if (status >= 300 && status < 400 && typeof res.headers.location === 'string') {
              res.destroy();
              this.activeRequests.delete(req);
              if (hop >= MAX_REDIRECTS) {
                reject(new Error(`Too many redirects (>${MAX_REDIRECTS})`));
                return;
              }
              const nextUrl = new URL(res.headers.location, target);
              follow(nextUrl, hop + 1);
              return;
            }
            resolve({ res, req });
          }
        );

        this.activeRequests.add(req);

        req.on('timeout', () => {
          req.destroy(new Error(`Request timed out after ${this.stallTimeoutMs}ms`));
        });

        req.on('error', (err) => {
          this.activeRequests.delete(req);
          reject(err);
        });

        req.end();
      };

      follow(new URL(startUrl), 0);
    });
  }

  private async finalizeCompletedFile(): Promise<void> {
    this.item.status = 'verifying';
    this.item.speedBps = 0;
    this.item.etaSeconds = 0;
    for (const s of this.item.segments) {
      s.speedBps = 0;
      s.status = 'done';
    }
    this.onUpdate(this.item, false);

    await renameWithRetry(this.item.partPath, this.item.savedPath);

    const sha256 = await computeFileSha256(this.item.savedPath);
    const stat = await fs.stat(this.item.savedPath);
    const integrity = await verifyFileIntegrity(this.item.savedPath, this.item.filename);

    this.item.totalBytes = stat.size;
    this.item.downloadedBytes = stat.size;
    this.item.sha256 = sha256;
    this.item.integrity = integrity;
    this.item.completedAt = Date.now();
    const elapsedSec = Math.max(
      0.05,
      (this.item.completedAt - (this.item.startedAt ?? this.item.createdAt)) / 1000
    );
    this.item.avgSpeedBps = Math.round(stat.size / elapsedSec);
    this.item.speedBps = 0;
    this.item.etaSeconds = 0;
    this.item.status = 'completed';
    this.onUpdate(this.item, true);
  }

  private recomputeDownloadedTotal(): void {
    let total = 0;
    for (const seg of this.item.segments) {
      total += seg.downloaded;
    }
    this.item.downloadedBytes = total;
  }

  private startTelemetryTimer(): void {
    if (this.telemetryTimer) return;
    this.telemetryTimer = setInterval(() => {
      const now = Date.now();
      const dtSec = Math.max(0.05, (now - this.lastSampleTime) / 1000);
      this.recomputeDownloadedTotal();

      const deltaBytes = Math.max(0, this.item.downloadedBytes - this.lastSampleBytes);
      const instantSpeed = deltaBytes / dtSec;
      this.emaSpeedBps =
        this.emaSpeedBps === 0 ? instantSpeed : this.emaSpeedBps * 0.55 + instantSpeed * 0.45;
      this.item.speedBps = Math.round(this.emaSpeedBps);

      for (const seg of this.item.segments) {
        const prev = this.segLastSampleBytes.get(seg.id) ?? seg.downloaded;
        const segDelta = Math.max(0, seg.downloaded - prev);
        seg.speedBps = seg.status === 'active' ? Math.round(segDelta / dtSec) : 0;
        this.segLastSampleBytes.set(seg.id, seg.downloaded);
      }

      for (const m of this.mirrorMetrics) {
        const mDelta = Math.max(0, m.bytes - m.lastSampleBytes);
        m.speedBps = Math.round(mDelta / dtSec);
        m.lastSampleBytes = m.bytes;
      }

      if (this.item.totalBytes !== null && this.item.speedBps > 0) {
        const remaining = Math.max(0, this.item.totalBytes - this.item.downloadedBytes);
        this.item.etaSeconds = Math.ceil(remaining / this.item.speedBps);
      } else {
        this.item.etaSeconds = null;
      }

      this.lastSampleTime = now;
      this.lastSampleBytes = this.item.downloadedBytes;
      this.onUpdate(this.item, false);
    }, 250);
  }

  private stopTelemetryTimer(): void {
    if (this.telemetryTimer) {
      clearInterval(this.telemetryTimer);
      this.telemetryTimer = null;
    }
  }
}

export async function computeFileSha256(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = createReadStream(filePath, { highWaterMark: 256 * 1024 });
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

async function fileExists(target: string): Promise<boolean> {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

async function renameWithRetry(src: string, dest: string): Promise<void> {
  for (let i = 0; i < 6; i++) {
    try {
      await fs.rename(src, dest);
      return;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if ((code === 'EPERM' || code === 'EBUSY') && i < 5) {
        await new Promise((r) => setTimeout(r, 40 * (i + 1)));
        continue;
      }
      throw err;
    }
  }
}

function parseRetryAfterMs(header: string | string[] | undefined, capMs: number): number {
  const raw = Array.isArray(header) ? header[0] : header;
  const minMs = Math.min(1_000, capMs);
  if (!raw) return Math.min(capMs, 2_000);
  const trimmed = raw.trim();
  const seconds = Number(trimmed);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.max(minMs, Math.min(capMs, Math.round(seconds * 1000)));
  }
  const dateMs = Date.parse(trimmed);
  if (Number.isFinite(dateMs)) {
    const delta = dateMs - Date.now();
    return Math.max(minMs, Math.min(capMs, delta));
  }
  return Math.min(capMs, 2_000);
}

function isAbortError(err: unknown): boolean {
  return (err as Error)?.name === 'AbortError';
}

function abortableDelay(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.reject(new DOMException('Aborted', 'AbortError'));
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException('Aborted', 'AbortError'));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal.addEventListener('abort', onAbort, { once: true });
  });
}
