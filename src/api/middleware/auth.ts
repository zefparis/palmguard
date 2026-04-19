/**
 * PalmGuard Bearer Token Authentication Middleware
 *
 * Validates `Authorization: Bearer <token>` against HCS_TOKEN_SECRET env var.
 * Uses timing-safe comparison to prevent oracle attacks on the secret.
 *
 * Applied to all /api/palm/* routes except GET /api/palm/health.
 */

import { timingSafeEqual } from "node:crypto";
import type { Request, Response, NextFunction } from "express";

const MIN_LATENCY_MS = 150;
const JITTER_MAX_MS  = 50;

async function timingFloor(startMs: number): Promise<void> {
  const target = MIN_LATENCY_MS + Math.random() * JITTER_MAX_MS;
  const elapsed = Date.now() - startMs;
  if (elapsed < target) {
    await new Promise<void>((r) => setTimeout(r, target - elapsed));
  }
}

/**
 * Extract and validate the Bearer token from the Authorization header.
 * Responds 401 on any failure — error messages are intentionally identical
 * regardless of failure mode (missing vs wrong token).
 * The 401 response is always delayed ≥ MIN_LATENCY_MS so it is indistinguishable
 * from a successful auth that proceeds to the route handler.
 */
export function requireBearerAuth(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  // Record start time on first middleware entry (shared with route handler)
  if (!res.locals["startMs"]) {
    res.locals["startMs"] = Date.now();
  }
  const startMs = res.locals["startMs"] as number;

  const secret = process.env["HCS_TOKEN_SECRET"];
  if (!secret) {
    void timingFloor(startMs).then(() => {
      res.status(503).json({
        success: false,
        code: "SERVICE_UNAVAILABLE",
        message: "Authentication service misconfigured",
      });
    });
    return;
  }

  const authHeader = req.headers["authorization"] ?? "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";

  const secretBuf = Buffer.from(secret, "utf8");
  // Always compare exactly secret.length bytes (padding with 0 if token is shorter)
  // so the comparison time does not depend on token length.
  const compareBuf = Buffer.alloc(secretBuf.length, 0);
  Buffer.from(token, "utf8").copy(compareBuf);

  // timingSafeEqual runs in constant time; length check done separately
  const equal = timingSafeEqual(compareBuf, secretBuf);
  const valid = token.length === secret.length && equal;

  if (!valid) {
    void timingFloor(startMs).then(() => {
      res.status(401).json({
        success: false,
        code: "UNAUTHORIZED",
        message: "Valid Bearer token required",
      });
    });
    return;
  }

  next();
}
