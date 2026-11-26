export interface OriginCooldownState {
  origin: string;
  cooldownUntil: number;
  consecutiveRateLimits: number;
  maxWorkersCap: number;
  lastStatusCode?: number;
}

const MAX_RETRY_AFTER_MS = 24 * 60 * 60_000; // 24 hours sanity bound

export function getOriginKey(rawUrl: string): string {
  try {
    return new URL(rawUrl).origin.toLowerCase();
  } catch {
    return 'unknown';
  }
}

export function parseRetryAfterMs(
  headerValue: string | string[] | undefined,
  now = Date.now()
): number | null {
  const raw = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (!raw) return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;

  if (/^\d+(?:\.\d+)?$/.test(trimmed)) {
    const secs = Number(trimmed);
    if (Number.isFinite(secs) && secs >= 0) {
      return Math.min(MAX_RETRY_AFTER_MS, Math.ceil(secs * 1000));
    }
  }

  const parsedDate = Date.parse(trimmed);
  if (Number.isFinite(parsedDate)) {
    const diff = parsedDate - now;
    return Math.min(MAX_RETRY_AFTER_MS, Math.max(0, Math.ceil(diff)));
  }

  return null;
}

export class OriginRateLimiter {
  private readonly origins = new Map<string, OriginCooldownState>();

  getCooldownRemainingMs(urlOrOrigin: string, now = Date.now()): number {
    const key = urlOrOrigin.includes('://') ? getOriginKey(urlOrOrigin) : urlOrOrigin.toLowerCase();
    const state = this.origins.get(key);
    if (!state) return 0;
    return Math.max(0, state.cooldownUntil - now);
  }

  isCoolingDown(urlOrOrigin: string, now = Date.now()): boolean {
    return this.getCooldownRemainingMs(urlOrOrigin, now) > 0;
  }

  getRecommendedMaxWorkers(urlOrOrigin: string, defaultWorkers: number): number {
    const key = urlOrOrigin.includes('://') ? getOriginKey(urlOrOrigin) : urlOrOrigin.toLowerCase();
    const state = this.origins.get(key);
    if (!state) return defaultWorkers;
    return Math.max(1, Math.min(defaultWorkers, state.maxWorkersCap));
  }

  recordRateLimit(
    urlOrOrigin: string,
    statusCode: number,
    retryAfterHeader?: string | string[],
    currentWorkers = 8,
    now = Date.now()
  ): { delayMs: number; retryAfterMs: number | null; newMaxWorkers: number; origin: string } {
    const key = urlOrOrigin.includes('://') ? getOriginKey(urlOrOrigin) : urlOrOrigin.toLowerCase();
    const prev = this.origins.get(key);
    const consecutive = (prev?.consecutiveRateLimits ?? 0) + 1;

    const retryMs = parseRetryAfterMs(retryAfterHeader, now);
    const expMs = Math.min(60_000, 1200 * Math.pow(2, Math.min(consecutive - 1, 5)));

    let delayMs: number;
    if (retryMs !== null) {
      // Honor Retry-After deadlines strictly: never shorten via negative jitter or a low cap.
      const positiveJitter = Math.round(Math.random() * Math.min(500, Math.max(50, retryMs * 0.1)));
      delayMs = Math.max(retryMs, expMs) + positiveJitter;
    } else {
      const jitter = 1.0 + Math.random() * 0.25;
      delayMs = Math.max(250, Math.round(expMs * jitter));
    }

    const prevCap = prev?.maxWorkersCap ?? Math.max(1, currentWorkers);
    const steppedCap = Math.max(1, Math.floor(prevCap / 2));
    const cooldownUntil = Math.max(prev?.cooldownUntil ?? 0, now + delayMs);

    this.origins.set(key, {
      origin: key,
      cooldownUntil,
      consecutiveRateLimits: consecutive,
      maxWorkersCap: steppedCap,
      lastStatusCode: statusCode,
    });

    return {
      // Report the SHARED deadline (a concurrent, longer Retry-After may already extend it)
      delayMs: Math.max(delayMs, cooldownUntil - now),
      retryAfterMs: retryMs,
      newMaxWorkers: steppedCap,
      origin: key,
    };
  }

  /**
   * Waits until every listed origin's shared cooldown has elapsed, re-reading the live deadlines
   * after each wait so a concurrent Retry-After extension is honored right before dispatch.
   */
  async waitForCooldowns(urls: readonly string[], signal?: AbortSignal): Promise<void> {
    while (true) {
      if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
      const now = Date.now();
      const remaining = urls.reduce((max, u) => Math.max(max, this.getCooldownRemainingMs(u, now)), 0);
      if (remaining <= 0) return;
      await new Promise<void>((resolve, reject) => {
        const onAbort = () => {
          clearTimeout(timer);
          reject(new DOMException('Aborted', 'AbortError'));
        };
        const timer = setTimeout(() => {
          signal?.removeEventListener('abort', onAbort);
          resolve();
        }, remaining);
        signal?.addEventListener('abort', onAbort, { once: true });
      });
    }
  }

  recordSuccess(urlOrOrigin: string): void {
    const key = urlOrOrigin.includes('://') ? getOriginKey(urlOrOrigin) : urlOrOrigin.toLowerCase();
    const prev = this.origins.get(key);
    if (!prev) return;
    if (prev.consecutiveRateLimits <= 1 && Date.now() >= prev.cooldownUntil) {
      this.origins.delete(key);
      return;
    }
    this.origins.set(key, {
      ...prev,
      consecutiveRateLimits: Math.max(0, prev.consecutiveRateLimits - 1),
      maxWorkersCap: Math.min(16, prev.maxWorkersCap + 1),
    });
  }

  getBackingOffHostsForUrls(urls: readonly string[], now = Date.now()): string[] {
    const hosts = new Set<string>();
    for (const url of urls) {
      const origin = getOriginKey(url);
      if (this.getCooldownRemainingMs(origin, now) > 0) {
        try {
          hosts.add(new URL(url).hostname.toLowerCase());
        } catch {
          hosts.add(origin);
        }
      }
    }
    return Array.from(hosts);
  }
}
