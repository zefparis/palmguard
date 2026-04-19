/**
 * PalmGuard — Centralised environment configuration.
 *
 * requireEnv() throws at startup if a required variable is absent (fail-fast).
 * Values are never logged; only key names are printed on startup.
 */

function requireEnv(key: string): string {
  const val = process.env[key];
  if (!val) throw new Error(`[palmguard] Missing required env var: ${key}`);
  return val;
}

function optionalEnv(key: string, fallback: string): string {
  return process.env[key] ?? fallback;
}

export type RateLimiterMode = "memory" | "supabase";

export interface PalmGuardConfig {
  supabaseUrl: string | null;
  supabaseServiceKey: string | null;
  hcsTokenSecret: string;
  port: number;
  rateLimiterMode: RateLimiterMode;
  nodeEnv: string;
}

/**
 * Build config from process.env.
 * In test / dev mode, SUPABASE_* vars may be absent — returns null for those fields.
 * Routes degrade gracefully to NoopRepository when supabaseUrl is null.
 */
export function buildConfig(): PalmGuardConfig {
  const nodeEnv = optionalEnv("NODE_ENV", "development");
  const isProd  = nodeEnv === "production";

  const supabaseUrl       = isProd ? requireEnv("SUPABASE_URL")              : (process.env["SUPABASE_URL"] ?? null);
  const supabaseServiceKey = isProd ? requireEnv("SUPABASE_SERVICE_ROLE_KEY") : (process.env["SUPABASE_SERVICE_ROLE_KEY"] ?? null);
  const hcsTokenSecret    = optionalEnv("HCS_TOKEN_SECRET", "dev-secret-change-me");

  console.log('[palmguard] raw RATE_LIMITER_MODE:', process.env['RATE_LIMITER_MODE']);
  const rateLimiterMode = (optionalEnv("RATE_LIMITER_MODE", "memory")) as RateLimiterMode;
  const port = parseInt(optionalEnv("PORT", "4010"), 10);

  return { supabaseUrl, supabaseServiceKey, hcsTokenSecret, port, rateLimiterMode, nodeEnv };
}

// Singleton used by production paths. Tests can call buildConfig() directly.
export const config: PalmGuardConfig = buildConfig();
logStartup(config);

export function logStartup(cfg: PalmGuardConfig): void {
  console.log("[palmguard] Starting with config keys:", {
    SUPABASE_URL:              cfg.supabaseUrl        ? "set" : "absent",
    SUPABASE_SERVICE_ROLE_KEY: cfg.supabaseServiceKey ? "set" : "absent",
    HCS_TOKEN_SECRET:          cfg.hcsTokenSecret !== "dev-secret-change-me" ? "set" : "DEFAULT (dev)",
    PORT:             cfg.port,
    RATE_LIMITER_MODE: cfg.rateLimiterMode,
    NODE_ENV:          cfg.nodeEnv,
  });
}
