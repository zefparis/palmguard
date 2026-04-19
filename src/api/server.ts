import express, { type Express } from "express";
import cors from "cors";
import { createPalmRoutes } from "./routes.js";
import { rateLimiter, createRateLimiter } from "./ratelimit.js";
import { createPalmRepositorySync, createPalmRepository } from "../db/palm.repository.js";
import type { PalmRepository } from "../db/types.js";
import type { RateLimiter } from "./ratelimit.js";
import { config } from "../config.js";

const ALLOWED_ORIGINS = [
  "https://hcs-u7.online",
  "https://app.hcs-u7.org",
  "https://palmguard-three.vercel.app",
  "https://hybrid-concept.vercel.app",
  "http://localhost:3000",
  "http://localhost:5174",
];

export interface AppDeps {
  repo?:    PalmRepository;
  limiter?: RateLimiter;
}

/**
 * Create and configure the Express application without starting the listener.
 *
 * Dependency injection:
 *   - Production: no args → NoopRepository (or Supabase if env vars present) + singleton rateLimiter.
 *   - Tests: pass overrides.repo (MemoryRepository) + overrides.limiter to isolate from network.
 *   - Rate limit reset: tests call rateLimiter._resetForTesting() on the exported singleton,
 *     which is the same instance used by default — so resets propagate correctly.
 */
/**
 * Production async factory — wires real SupabaseRepository + correct RateLimiter.
 * Call this from start.ts. Tests use createApp(deps) with injected mocks instead.
 */
export async function createAppAsync(): Promise<Express> {
  const repo    = await createPalmRepository(null, config.supabaseUrl, config.supabaseServiceKey);
  const limiter = createRateLimiter(config.rateLimiterMode, config.supabaseUrl, config.supabaseServiceKey);
  console.log('[palmguard] createAppAsync: repo=%s limiter=%s', repo.constructor.name, limiter.constructor.name);
  return createApp({ repo, limiter });
}

export function createApp(overrides?: AppDeps): Express {
  const repo    = overrides?.repo    ?? createPalmRepositorySync();
  const limiter = overrides?.limiter ?? rateLimiter; // singleton for backward compat

  const app = express();
  app.use(express.json({ limit: "64kb" }));
  app.use(cors({ origin: ALLOWED_ORIGINS, credentials: false }));
  app.use("/api/palm", createPalmRoutes({ repo, limiter }));

  return app;
}
