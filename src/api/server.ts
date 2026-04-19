import express, { type Express } from "express";
import cors from "cors";
import { createPalmRoutes } from "./routes.js";
import { rateLimiter } from "./ratelimit.js";
import { createPalmRepositorySync } from "../db/palm.repository.js";
import type { PalmRepository } from "../db/types.js";
import type { RateLimiter } from "./ratelimit.js";

const ALLOWED_ORIGINS = [
  "https://hcs-u7.online",
  "https://app.hcs-u7.org",
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
export function createApp(overrides?: AppDeps): Express {
  const repo    = overrides?.repo    ?? createPalmRepositorySync();
  const limiter = overrides?.limiter ?? rateLimiter; // singleton for backward compat

  const app = express();
  app.use(express.json({ limit: "64kb" }));
  app.use(cors({ origin: ALLOWED_ORIGINS, credentials: false }));
  app.use("/api/palm", createPalmRoutes({ repo, limiter }));

  return app;
}
