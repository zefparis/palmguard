/**
 * PalmGuard JWT middleware — HS256 verification (no external JWT library).
 *
 * Two auth paths:
 *   1. X-Internal-Token: <HCS_TOKEN_SECRET>
 *      — Proxy-internal calls and CI tests.
 *      — userId comes from request body / params.
 *
 *   2. Authorization: Bearer <jwt>
 *      — Normal HCS-U7 client calls.
 *      — JWT must be HS256-signed with HCS_TOKEN_SECRET.
 *      — Payload must contain { userId: string, exp: number }.
 *      — userId is set in res.locals.userId for downstream routes.
 *
 * Algorithm confusion attacks: any JWT with alg ≠ HS256 is rejected.
 * All rejection paths wait ≥ MIN_LATENCY_MS before responding.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
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

// ─── JWT parsing helpers ──────────────────────────────────────────────────────

function b64urlToBuffer(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

export class JwtError extends Error {
  constructor(
    public readonly jwtCode:
      | "MALFORMED"
      | "ALGORITHM"
      | "SIGNATURE"
      | "EXPIRED"
      | "MISSING_CLAIM",
    message: string
  ) {
    super(message);
    this.name = "JwtError";
  }
}

export interface JwtPayload {
  userId:    string;
  sessionId?: string;
  exp:       number;
  iat?:      number;
}

/**
 * Verify an HS256 JWT and return its payload.
 * Throws JwtError on any validation failure.
 */
export function verifyHs256Jwt(token: string, secret: string): JwtPayload {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new JwtError("MALFORMED", "JWT must have exactly 3 parts");
  }

  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  // 1. Parse + validate header
  let header: Record<string, unknown>;
  try {
    header = JSON.parse(b64urlToBuffer(headerB64).toString("utf8")) as Record<string, unknown>;
  } catch {
    throw new JwtError("MALFORMED", "Cannot parse JWT header");
  }
  if (header["alg"] !== "HS256") {
    throw new JwtError(
      "ALGORITHM",
      `Expected alg=HS256, got ${String(header["alg"] ?? "none")} — possible algorithm confusion attack`
    );
  }

  // 2. Verify HMAC-SHA256 signature (timing-safe)
  const message  = `${headerB64}.${payloadB64}`;
  const expected = createHmac("sha256", secret).update(message).digest();
  const actual   = b64urlToBuffer(sigB64);

  if (
    expected.length !== actual.length ||
    !timingSafeEqual(expected, actual)
  ) {
    throw new JwtError("SIGNATURE", "Invalid JWT signature");
  }

  // 3. Parse payload
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(b64urlToBuffer(payloadB64).toString("utf8")) as Record<string, unknown>;
  } catch {
    throw new JwtError("MALFORMED", "Cannot parse JWT payload");
  }

  // 4. Check expiry (allow 5 s clock skew)
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload["exp"] !== "number" || payload["exp"] + 5 < now) {
    throw new JwtError("EXPIRED", "JWT has expired");
  }

  // 5. Required claims
  if (!payload["userId"] || typeof payload["userId"] !== "string") {
    throw new JwtError("MISSING_CLAIM", "JWT payload must contain userId (string)");
  }

  const result: JwtPayload = {
    userId: payload["userId"] as string,
    exp:    payload["exp"] as number,
  };
  if (typeof payload["sessionId"] === "string") result.sessionId = payload["sessionId"];
  if (typeof payload["iat"] === "number")       result.iat       = payload["iat"];
  return result;
}

/**
 * Convenience: create a signed HS256 JWT.
 * Used in tests and by hcs-u7-backend session issuance.
 */
export function createHs256Jwt(
  payload: Omit<JwtPayload, "exp" | "iat"> & { exp?: number; iat?: number },
  secret: string
): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const now    = Math.floor(Date.now() / 1000);
  const body   = Buffer.from(
    JSON.stringify({ iat: now, exp: now + 3600, ...payload })
  ).toString("base64url");
  const sig = createHmac("sha256", secret).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${sig}`;
}

// ─── Express middleware ───────────────────────────────────────────────────────

/**
 * requireAuth middleware:
 *
 *   X-Internal-Token path (backward-compat, proxy-internal):
 *     — Timing-safe compare against HCS_TOKEN_SECRET
 *     — res.locals.userId = req.body.userId ?? req.params.userId
 *     — res.locals.authMode = "internal"
 *
 *   JWT Bearer path (normal client auth):
 *     — Verify HS256 JWT signed with HCS_TOKEN_SECRET
 *     — res.locals.userId = payload.userId
 *     — res.locals.authMode = "jwt"
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!res.locals["startMs"]) {
    res.locals["startMs"] = Date.now();
  }
  const startMs = res.locals["startMs"] as number;

  const secret = process.env["HCS_TOKEN_SECRET"] ?? "";
  if (!secret) {
    void timingFloor(startMs).then(() =>
      res.status(503).json({ success: false, code: "SERVICE_UNAVAILABLE", message: "Auth not configured" })
    );
    return;
  }

  // ── Path 1: X-Internal-Token ──────────────────────────────────────────────
  const internalToken = req.headers["x-internal-token"] as string | undefined;
  if (internalToken !== undefined) {
    // ── Path 1a: optional public-demo bypass (PALMGUARD_DEMO_TOKEN env var) ──
    // Set PALMGUARD_DEMO_TOKEN=demo on the server to allow the standalone demo
    // to call the API without exposing HCS_TOKEN_SECRET.
    const demoToken = process.env["PALMGUARD_DEMO_TOKEN"];
    if (demoToken && internalToken === demoToken) {
      const bodyUserId   = (req.body as Record<string, unknown> | undefined)?.["userId"];
      const paramsUserId = req.params["userId"];
      res.locals["userId"]   = (typeof bodyUserId === "string" ? bodyUserId : paramsUserId) ?? "demo-user";
      res.locals["authMode"] = "demo";
      next();
      return;
    }

    // ── Path 1b: timing-safe compare against HCS_TOKEN_SECRET ────────────────
    const secretBuf = Buffer.from(secret, "utf8");
    const tokenBuf  = Buffer.alloc(secretBuf.length, 0);
    Buffer.from(internalToken, "utf8").copy(tokenBuf);
    const valid =
      internalToken.length === secret.length &&
      timingSafeEqual(tokenBuf, secretBuf);

    if (!valid) {
      void timingFloor(startMs).then(() =>
        res.status(401).json({ success: false, code: "UNAUTHORIZED", message: "Invalid internal token" })
      );
      return;
    }

    // Internal path: userId from body or params (set by caller)
    const bodyUserId   = (req.body as Record<string, unknown> | undefined)?.["userId"];
    const paramsUserId = req.params["userId"];
    res.locals["userId"]   = (typeof bodyUserId === "string" ? bodyUserId : paramsUserId) ?? "";
    res.locals["authMode"] = "internal";
    next();
    return;
  }

  // ── Path 2: Authorization: Bearer <jwt> ───────────────────────────────────
  const authHeader = req.headers["authorization"] ?? "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) {
    void timingFloor(startMs).then(() =>
      res.status(401).json({ success: false, code: "UNAUTHORIZED", message: "Authorization header required" })
    );
    return;
  }

  try {
    const payload = verifyHs256Jwt(token, secret);
    res.locals["userId"]    = payload.userId;
    res.locals["sessionId"] = payload.sessionId;
    res.locals["authMode"]  = "jwt";
    next();
  } catch (err) {
    const msg = err instanceof JwtError ? err.message : "Invalid token";
    void timingFloor(startMs).then(() =>
      res.status(401).json({ success: false, code: "UNAUTHORIZED", message: msg })
    );
  }
}
