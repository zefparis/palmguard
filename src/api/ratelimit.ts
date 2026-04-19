/**
 * PalmGuard In-Memory Rate Limiter
 *
 * Limits:
 *   Enroll — max 3 attempts per userId per 24 hours
 *   Verify — max 10 attempts per userId per 60 minutes
 *
 * Uses a sliding window (array of timestamps). Entries are pruned on each
 * check to keep memory bounded. A hard ceiling of 10_000 distinct users
 * is applied (LRU eviction by insertion order).
 *
 * Production note: replace with Redis / Supabase KV for multi-instance deployments.
 * This in-memory implementation is correct for single-process (Render/Fly.io single instance).
 */

const ENROLL_MAX = 3;
const ENROLL_WINDOW_MS = 24 * 60 * 60 * 1000; // 24 h

const VERIFY_MAX = 10;
const VERIFY_WINDOW_MS = 60 * 60 * 1000; // 1 h

const MAX_USERS = 10_000;

export interface RateLimitResult {
  allowed: boolean;
  /** Seconds to wait before retrying (0 when allowed). */
  retryAfterSecs: number;
}

class SlidingWindowCounter {
  private map = new Map<string, number[]>();

  constructor(
    private readonly maxAttempts: number,
    private readonly windowMs: number
  ) {}

  check(userId: string): RateLimitResult {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const history = (this.map.get(userId) ?? []).filter((t) => t > cutoff);

    if (history.length >= this.maxAttempts) {
      const oldest = history[0] ?? now;
      const retryAfterMs = oldest + this.windowMs - now;
      return { allowed: false, retryAfterSecs: Math.ceil(retryAfterMs / 1000) };
    }
    return { allowed: true, retryAfterSecs: 0 };
  }

  record(userId: string): void {
    const now = Date.now();
    const cutoff = now - this.windowMs;

    // LRU eviction: remove oldest entry if at capacity
    if (!this.map.has(userId) && this.map.size >= MAX_USERS) {
      const firstKey = this.map.keys().next().value as string | undefined;
      if (firstKey !== undefined) this.map.delete(firstKey);
    }

    const history = (this.map.get(userId) ?? []).filter((t) => t > cutoff);
    history.push(now);
    this.map.set(userId, history);
  }

  _reset(): void {
    this.map.clear();
  }
}

// ─── RateLimiter interface ────────────────────────────────────────────────────

export interface RateLimiter {
  checkEnroll(userId: string): RateLimitResult | Promise<RateLimitResult>;
  recordEnroll(userId: string): void | Promise<void>;
  checkVerify(userId: string): RateLimitResult | Promise<RateLimitResult>;
  recordVerify(userId: string): void | Promise<void>;
  _resetForTesting(): void | Promise<void>;
}

// ─── MemoryRateLimiter ────────────────────────────────────────────────────────

export class MemoryRateLimiter implements RateLimiter {
  private readonly _enroll = new SlidingWindowCounter(ENROLL_MAX, ENROLL_WINDOW_MS);
  private readonly _verify = new SlidingWindowCounter(VERIFY_MAX, VERIFY_WINDOW_MS);

  checkEnroll(userId: string): RateLimitResult  { return this._enroll.check(userId);  }
  recordEnroll(userId: string): void            { this._enroll.record(userId);         }
  checkVerify(userId: string): RateLimitResult  { return this._verify.check(userId);   }
  recordVerify(userId: string): void            { this._verify.record(userId);         }
  _resetForTesting(): void {
    this._enroll._reset();
    this._verify._reset();
  }
}

// ─── SupabaseRateLimiter ──────────────────────────────────────────────────────

/**
 * Supabase-backed rate limiter for multi-instance deployments.
 * Falls back to the in-memory limiter if Supabase is unreachable (fail-open).
 *
 * Uses an optimistic two-call pattern:
 *   1. SELECT current count/window from palm_rate_limits
 *   2. INSERT or UPDATE (upsert)
 * TOCTOU race is acceptable for rate limiting (non-security-critical throttle).
 */
export class SupabaseRateLimiter implements RateLimiter {
  private readonly fallback: MemoryRateLimiter;

  constructor(
    private readonly supabaseUrl: string,
    private readonly supabaseKey: string
  ) {
    this.fallback = new MemoryRateLimiter();
  }

  private async checkAndRecord(
    userId: string,
    action: "enroll" | "verify",
    maxCount: number,
    windowMs: number
  ): Promise<{ check: RateLimitResult; record: () => Promise<void> }> {
    let client: import("@supabase/supabase-js").SupabaseClient;
    try {
      const { createClient } = await import("@supabase/supabase-js");
      client = createClient(this.supabaseUrl, this.supabaseKey, {
        auth: { persistSession: false, autoRefreshToken: false },
      });
    } catch {
      // Supabase module unavailable — fall back
      return {
        check: this.fallback.checkEnroll(userId),
        record: async () => { this.fallback.recordEnroll(userId); },
      };
    }

    try {
      const now = Date.now();
      const { data } = await client
        .from("palm_rate_limits")
        .select("count, window_start")
        .eq("user_id", userId)
        .eq("action", action)
        .maybeSingle();

      const windowStart = data ? new Date(data.window_start as string).getTime() : 0;
      const inWindow    = now - windowStart < windowMs;
      const count       = inWindow ? (data?.count as number ?? 0) : 0;

      if (count >= maxCount) {
        const retryAfterMs = windowStart + windowMs - now;
        return {
          check:  { allowed: false, retryAfterSecs: Math.ceil(retryAfterMs / 1000) },
          record: async () => {},
        };
      }

      return {
        check: { allowed: true, retryAfterSecs: 0 },
        record: async () => {
          await client.from("palm_rate_limits").upsert(
            {
              user_id:      userId,
              action,
              window_start: inWindow && data ? (data.window_start as string) : new Date(now).toISOString(),
              count:        count + 1,
            },
            { onConflict: "user_id,action" }
          );
        },
      };
    } catch (err) {
      console.error("[palmguard] SupabaseRateLimiter error — falling back:", err);
      const fbCheck = action === "enroll"
        ? this.fallback.checkEnroll(userId)
        : this.fallback.checkVerify(userId);
      return {
        check: fbCheck,
        record: async () => {
          if (action === "enroll") this.fallback.recordEnroll(userId);
          else                     this.fallback.recordVerify(userId);
        },
      };
    }
  }

  async checkEnroll(userId: string): Promise<RateLimitResult> {
    const { check } = await this.checkAndRecord(userId, "enroll", ENROLL_MAX, ENROLL_WINDOW_MS);
    return check;
  }
  async recordEnroll(userId: string): Promise<void> {
    const { record } = await this.checkAndRecord(userId, "enroll", ENROLL_MAX, ENROLL_WINDOW_MS);
    await record();
  }
  async checkVerify(userId: string): Promise<RateLimitResult> {
    const { check } = await this.checkAndRecord(userId, "verify", VERIFY_MAX, VERIFY_WINDOW_MS);
    return check;
  }
  async recordVerify(userId: string): Promise<void> {
    const { record } = await this.checkAndRecord(userId, "verify", VERIFY_MAX, VERIFY_WINDOW_MS);
    await record();
  }
  _resetForTesting(): void { this.fallback._resetForTesting(); }
}

// ─── Factory ──────────────────────────────────────────────────────────────────

export function createRateLimiter(
  mode: "memory" | "supabase",
  supabaseUrl?: string | null,
  supabaseKey?: string | null
): RateLimiter {
  if (mode === "supabase" && supabaseUrl && supabaseKey) {
    return new SupabaseRateLimiter(supabaseUrl, supabaseKey);
  }
  if (mode === "supabase") {
    console.warn("[palmguard] RATE_LIMITER_MODE=supabase but Supabase creds absent — using memory");
  }
  return new MemoryRateLimiter();
}

// ─── Public singleton (backward compat) ──────────────────────────────────────

const _singleton = new MemoryRateLimiter();

export const rateLimiter = {
  checkEnroll(userId: string): RateLimitResult  { return _singleton.checkEnroll(userId);  },
  recordEnroll(userId: string): void            { _singleton.recordEnroll(userId);         },
  checkVerify(userId: string): RateLimitResult  { return _singleton.checkVerify(userId);   },
  recordVerify(userId: string): void            { _singleton.recordVerify(userId);         },
  _resetForTesting(): void                      { _singleton._resetForTesting();           },
} as const;
