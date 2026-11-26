export class TokenBucketThrottle {
  private bytesPerSec = 0; // 0 = unlimited
  private tokens = 0;
  private lastRefillMs = Date.now();
  private tail: Promise<void> = Promise.resolve();

  constructor(limitKBps = 0) {
    this.setLimitKBps(limitKBps);
  }

  setLimitKBps(kbps: number): void {
    const safeKbps = Number.isFinite(kbps) && kbps > 0 ? kbps : 0;
    this.bytesPerSec = Math.floor(safeKbps * 1024);
    this.lastRefillMs = Date.now();
    if (this.bytesPerSec > 0) {
      this.tokens = Math.min(this.tokens, this.maxBurstBytes());
    }
  }

  getLimitKBps(): number {
    return this.bytesPerSec === 0 ? 0 : Math.round(this.bytesPerSec / 1024);
  }

  private maxBurstBytes(): number {
    return Math.max(65_536, Math.floor(this.bytesPerSec * 0.5));
  }

  async consume(bytes: number, signal?: AbortSignal): Promise<void> {
    if (this.bytesPerSec <= 0 || bytes <= 0) return;
    if (signal?.aborted) {
      throw new DOMException('Aborted', 'AbortError');
    }

    // Serialize consumers fairly so multiple parallel segments share the exact cap
    const run = this.tail.then(() => this.consumeSerialized(bytes, signal));
    // Keep tail resilient even if one caller aborts
    this.tail = run.catch(() => {});
    return run;
  }

  private async consumeSerialized(bytes: number, signal?: AbortSignal): Promise<void> {
    if (this.bytesPerSec <= 0) return;
    let remaining = bytes;

    while (remaining > 0) {
      if (signal?.aborted) {
        throw new DOMException('Aborted', 'AbortError');
      }

      const now = Date.now();
      const elapsedSec = Math.max(0, (now - this.lastRefillMs) / 1000);
      if (elapsedSec > 0) {
        this.tokens = Math.min(this.maxBurstBytes(), this.tokens + elapsedSec * this.bytesPerSec);
        this.lastRefillMs = now;
      }

      if (this.tokens >= 1) {
        const take = Math.min(remaining, Math.floor(this.tokens));
        this.tokens -= take;
        remaining -= take;
        if (remaining <= 0) return;
      }

      const needed = Math.min(remaining, this.maxBurstBytes());
      const waitMs = Math.max(10, Math.ceil(((needed - Math.max(0, this.tokens)) / this.bytesPerSec) * 1000));
      await abortableSleep(waitMs, signal);
    }
  }
}

function abortableSleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (!signal) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
  if (signal.aborted) {
    return Promise.reject(new DOMException('Aborted', 'AbortError'));
  }
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
