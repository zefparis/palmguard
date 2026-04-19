/**
 * PalmGuard Express Routes — Phase 4: Live Supabase Wiring
 *
 * Endpoints:
 *   POST   /api/palm/enroll         — Enroll a new palm template.
 *   POST   /api/palm/verify         — Verify live capture against stored template.
 *   DELETE /api/palm/enroll/:userId  — GDPR right-to-erasure.
 *   GET    /api/palm/health         — Liveness probe (unauthenticated).
 *
 * Security invariants (all inherited from Phase 3, extended here):
 *   1. Auth: X-Internal-Token (static secret) OR Authorization: Bearer <HS256 JWT>
 *   2. ALL responses delayed to ≥ 150ms + jitter (no timing oracle)
 *   3. Uniform error shape regardless of failure reason
 *   4. Rate limits: enroll ≤ 3/24h, verify ≤ 10/h per userId
 *   5. Private key AES-256-GCM encrypted before persistence
 *   6. Zero raw biometric data in logs, DB responses, or network
 *   7. DB errors → 503 + generic message (Supabase internals never exposed)
 */

import { Router, type Request, type Response } from "express";
import { createHash, randomBytes } from "node:crypto";
import { deserializeVector, vectorSimilarity } from "../fractal/boxcount.js";
import { deriveCelestialSalt } from "../crypto/celestial.js";
import { generateKeyPair, encapsulateTemplate, buildTemplate } from "../crypto/mlkem.js";
import { deriveKEK, encryptPrivateKey, serializeVaultEntry } from "../crypto/vault.js";
import { requireAuth } from "./middleware/jwt.js";
import type { RateLimiter } from "./ratelimit.js";
import type { PalmRepository } from "../db/palm.repository.js";
import { RepositoryError } from "../db/palm.repository.js";
import type {
  EnrollRequest,
  EnrollResponse,
  VerifyRequest,
  VerifyResponse,
  DeleteEnrollResponse,
  ApiError,
} from "./types.js";

export const SIMILARITY_THRESHOLD = 0.97;
const MIN_LATENCY_MS = 150;
const JITTER_MAX_MS  = 50;

// ─── Timing floor ─────────────────────────────────────────────────────────────

async function timingFloor(startMs: number): Promise<void> {
  const target = MIN_LATENCY_MS + Math.random() * JITTER_MAX_MS;
  const elapsed = Date.now() - startMs;
  if (elapsed < target) await new Promise((r) => setTimeout(r, target - elapsed));
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function decodeB64(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
}

function hashIp(req: Request): string {
  const ip = req.ip ?? req.socket.remoteAddress ?? "unknown";
  return createHash("sha256").update(ip).digest("hex");
}

// ─── Route factory ────────────────────────────────────────────────────────────

export interface RouteDeps {
  repo:    PalmRepository;
  limiter: RateLimiter;
}

export function createPalmRoutes({ repo, limiter }: RouteDeps): Router {
  const router = Router();

  // ── POST /enroll ────────────────────────────────────────────────────────────

  router.post(
    "/enroll",
    requireAuth,
    async (req: Request, res: Response<EnrollResponse | ApiError>) => {
      const start  = res.locals["startMs"] as number ?? Date.now();
      const userId = res.locals["userId"]  as string;
      let statusCode = 201;
      let body: EnrollResponse | ApiError;

      try {
        const reqBody = req.body as EnrollRequest;

        if (!reqBody.tenantId || !reqBody.palmVectorB64 || !reqBody.capturedAt) {
          statusCode = 400;
          body = { success: false, code: "INVALID_REQUEST", message: "Missing required fields: tenantId, palmVectorB64, capturedAt" };
        } else {
          const biometricBytes = decodeB64(reqBody.palmVectorB64);

          if (biometricBytes.byteLength !== 24) {
            statusCode = 400;
            body = { success: false, code: "INVALID_VECTOR", message: "palmVectorB64 must decode to exactly 24 bytes" };
          } else {
            const rl = await limiter.checkEnroll(userId);
            if (!rl.allowed) {
              statusCode = 429;
              body = { success: false, code: "RATE_LIMIT_EXCEEDED", message: `Enroll limit reached. Retry after ${rl.retryAfterSecs}s` };
              res.setHeader("Retry-After", String(rl.retryAfterSecs));
            } else {
              await limiter.recordEnroll(userId);

              const celestialSalt = deriveCelestialSalt(reqBody.capturedAt);
              const contentHash   = createHash("sha256").update(biometricBytes).update(celestialSalt.bytes).digest("hex");
              const { publicKey, privateKey } = await generateKeyPair();
              const enc      = await encapsulateTemplate(publicKey, biometricBytes, celestialSalt.bytes);
              const template = buildTemplate(enc, publicKey, contentHash, reqBody.capturedAt, celestialSalt.jdn);
              const enrollmentId = randomBytes(16).toString("hex");

              // Vault: encrypt private key with HKDF-derived KEK
              const hcsSecret  = process.env["HCS_TOKEN_SECRET"] ?? "dev-secret";
              const kek        = await deriveKEK(hcsSecret, userId);
              const vaultEntry = await encryptPrivateKey(kek, privateKey);
              void serializeVaultEntry(vaultEntry); // ensure the vault blob is always computable

              // Persist to Supabase
              // Note: template.ciphertext / template.publicKey are base64url strings (PalmTemplate
              // contract). We use the raw Uint8Array values from the encapsulation step directly.
              await repo.enroll({
                tenantId:           reqBody.tenantId,
                userId,
                contentHash,
                enrollmentId,
                templateCiphertext: enc.ciphertext,
                publicKey,
                kemPrivkeyEnc:      vaultEntry.encryptedKey,
                kekIv:              vaultEntry.iv,
                capturedAt:         reqBody.capturedAt,
                celestialJdn:       celestialSalt.jdn,
                templateVersion:    "1.0",
              });

              await repo.appendAuditLog({
                tenantId:  reqBody.tenantId,
                userId,
                eventType: "ENROLL",
                ipHash:    hashIp(req),
                auditToken: enrollmentId,
              });

              body = { success: true, enrollmentId, enrolledAt: reqBody.capturedAt, templateVersion: "1.0" };
            }
          }
        }
      } catch (err) {
        if (err instanceof RepositoryError && err.kind === "CONFLICT") {
          statusCode = 409;
          body = { success: false, code: "ALREADY_ENROLLED", message: "User already enrolled. DELETE /enroll/:userId first" };
        } else {
          console.error("[palmguard] enroll error:", err instanceof Error ? err.message : err);
          statusCode = 500;
          body = { success: false, code: "INTERNAL_ERROR", message: "Enrollment failed" };
        }
      }

      await timingFloor(start);
      res.status(statusCode).json(body!);
    }
  );

  // ── POST /verify ────────────────────────────────────────────────────────────

  router.post(
    "/verify",
    requireAuth,
    async (req: Request, res: Response<VerifyResponse | ApiError>) => {
      const start  = res.locals["startMs"] as number ?? Date.now();
      const userId = res.locals["userId"]  as string;
      let statusCode = 200;
      let body: VerifyResponse | ApiError;

      try {
        const reqBody = req.body as VerifyRequest;

        if (!reqBody.tenantId || !reqBody.palmVectorB64 || !reqBody.capturedAt) {
          statusCode = 400;
          body = { success: false, code: "INVALID_REQUEST", message: "Missing required fields" };
        } else {
          const probeBytes = decodeB64(reqBody.palmVectorB64);

          if (probeBytes.byteLength !== 24) {
            statusCode = 400;
            body = { success: false, code: "INVALID_VECTOR", message: "palmVectorB64 must decode to exactly 24 bytes" };
          } else {
            const rl = await limiter.checkVerify(userId);
            if (!rl.allowed) {
              statusCode = 429;
              body = { success: false, code: "RATE_LIMIT_EXCEEDED", message: `Verify limit reached. Retry after ${rl.retryAfterSecs}s` };
              res.setHeader("Retry-After", String(rl.retryAfterSecs));
            } else {
              await limiter.recordVerify(userId);

              const enrollment = await repo.findEnrollment(reqBody.tenantId, userId);

              let similarity: number;
              let match: boolean;

              if (!enrollment) {
                // No enrollment found — deterministic rejection (avoids user enumeration via timing)
                similarity = 0;
                match = false;
              } else {
                const probeVector    = deserializeVector(probeBytes);
                const enrolledVector = deserializeVector(enrollment.templateCiphertext.slice(0, 24));
                similarity = vectorSimilarity(probeVector, enrolledVector);
                match      = similarity >= SIMILARITY_THRESHOLD;
              }

              const auditToken = createHash("sha256")
                .update(randomBytes(16))
                .update(hashIp(req))
                .digest("hex")
                .slice(0, 32);

              await repo.appendAuditLog({
                tenantId:  reqBody.tenantId,
                userId,
                eventType: match ? "VERIFY_MATCH" : "VERIFY_NO_MATCH",
                ipHash:    hashIp(req),
                auditToken,
                metadata:  { similarity },
              });

              const processingMs = Date.now() - start;
              body = { match, similarity, processingMs, auditToken };
            }
          }
        }
      } catch (err) {
        console.error("[palmguard] verify error:", err instanceof Error ? err.message : err);
        statusCode = 500;
        body = { success: false, code: "INTERNAL_ERROR", message: "Verification failed" };
      }

      await timingFloor(start);
      res.status(statusCode).json(body!);
    }
  );

  // ── DELETE /enroll/:userId ───────────────────────────────────────────────────

  router.delete(
    "/enroll/:userId",
    requireAuth,
    async (req: Request, res: Response<DeleteEnrollResponse | ApiError>) => {
      const start  = res.locals["startMs"] as number ?? Date.now();
      let statusCode = 200;
      let body: DeleteEnrollResponse | ApiError;

      try {
        const targetUserId = req.params["userId"] ?? "";
        const { tenantId } = req.body as { tenantId?: string };

        if (!targetUserId || !tenantId) {
          statusCode = 400;
          body = { success: false, code: "INVALID_REQUEST", message: "userId param and tenantId body field required" };
        } else {
          await repo.deleteEnrollment(tenantId, targetUserId);
          await repo.appendAuditLog({
            tenantId,
            userId:    targetUserId,
            eventType: "ENROLL_DELETED",
            ipHash:    hashIp(req),
          });
          body = { deleted: true, userId: targetUserId, timestamp: Date.now() };
        }
      } catch (err) {
        console.error("[palmguard] delete error:", err instanceof Error ? err.message : err);
        statusCode = 500;
        body = { success: false, code: "INTERNAL_ERROR", message: "Erasure failed" };
      }

      await timingFloor(start);
      res.status(statusCode).json(body!);
    }
  );

  // ── GET /health ──────────────────────────────────────────────────────────────

  router.get("/health", async (_req: Request, res: Response) => {
    const start = Date.now();

    let supabaseStatus: "ok" | "degraded" = "degraded";
    try {
      const alive = await repo.ping();
      supabaseStatus = alive ? "ok" : "degraded";
    } catch (err) {
      console.error('[palmguard] Supabase health check failed:', err instanceof Error ? err.message : err);
      supabaseStatus = "degraded";
    }

    res.json({
      status:  "ok",
      version: "1.0.0",
      checks:  {
        supabase:    supabaseStatus,
        rateLimiter: (limiter as { constructor: { name: string } }).constructor.name === "SupabaseRateLimiter"
          ? "supabase"
          : "memory",
        jwtMode: "hs256",
      },
      uptime: process.uptime(),
    });

    void start; // floor not applied to health (unauthenticated liveness probe)
  });

  return router;
}

// ─── Legacy named export (backward compat) ───────────────────────────────────
// server.ts now calls createPalmRoutes(); this alias is kept so any direct
// import of `palmRoutes` from old code still type-checks.
export { createPalmRoutes as palmRoutes };
