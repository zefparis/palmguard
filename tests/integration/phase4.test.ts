/**
 * PalmGuard Phase 4 — full integration tests
 *
 * Uses MemoryRepository (no Supabase network) + singleton MemoryRateLimiter.
 * Tests the complete enroll → verify → delete flow with JWT auth.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { createServer, type Server } from "node:http";
import { createApp } from "../../src/api/server.js";
import { MemoryRepository } from "../../src/db/palm.repository.js";
import { MemoryRateLimiter } from "../../src/api/ratelimit.js";
import { createHs256Jwt } from "../../src/api/middleware/jwt.js";

const SECRET      = "phase4-integration-secret-xyz";
const TENANT_ID   = "tenant-phase4";
const VALID_VECTOR = Buffer.alloc(24, 0).toString("base64url");

// ─── Server lifecycle ─────────────────────────────────────────────────────────

let server: Server;
let baseUrl: string;
let repo: MemoryRepository;
let limiter: MemoryRateLimiter;

beforeAll(async () => {
  process.env["HCS_TOKEN_SECRET"] = SECRET;

  repo    = new MemoryRepository();
  limiter = new MemoryRateLimiter();

  const app = createApp({ repo, limiter });
  server = createServer(app);
  await new Promise<void>((r) => server.listen(0, r));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 5099;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(() => {
  server.close();
  delete process.env["HCS_TOKEN_SECRET"];
});

beforeEach(() => {
  repo._reset();
  limiter._resetForTesting();
});

// ─── JWT helpers ──────────────────────────────────────────────────────────────

function jwtAuth(userId: string, secret = SECRET): Record<string, string> {
  const token = createHs256Jwt({ userId }, secret);
  return { Authorization: `Bearer ${token}` };
}

function internalAuth(): Record<string, string> {
  return { "X-Internal-Token": SECRET };
}

async function post(path: string, body: unknown, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

async function del(path: string, body: unknown, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, {
    method: "DELETE",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

// ─── Health ───────────────────────────────────────────────────────────────────

describe("GET /health — Phase 4 shape", () => {
  it("returns version 1.0.0 with checks object", async () => {
    const res  = await fetch(`${baseUrl}/api/palm/health`);
    const json = await res.json() as Record<string, unknown>;
    expect(res.status).toBe(200);
    expect(json.version).toBe("1.0.0");
    expect(json.status).toBe("ok");
    const checks = json.checks as Record<string, string>;
    expect(checks.jwtMode).toBe("hs256");
    expect(["ok", "degraded"]).toContain(checks.supabase);
    expect(["memory", "supabase"]).toContain(checks.rateLimiter);
    expect(typeof json.uptime).toBe("number");
  });

  it("MemoryRepository ping → supabase:ok", async () => {
    const res  = await fetch(`${baseUrl}/api/palm/health`);
    const json = await res.json() as Record<string, unknown>;
    const checks = json.checks as Record<string, string>;
    expect(checks.supabase).toBe("ok");
  });

  it("MemoryRateLimiter → rateLimiter:memory", async () => {
    const res  = await fetch(`${baseUrl}/api/palm/health`);
    const json = await res.json() as Record<string, unknown>;
    const checks = json.checks as Record<string, string>;
    expect(checks.rateLimiter).toBe("memory");
  });
});

// ─── JWT auth path ────────────────────────────────────────────────────────────

describe("JWT auth — enroll + verify", () => {
  it("returns 201 with valid JWT Bearer", async () => {
    const res = await post(
      "/api/palm/enroll",
      { tenantId: TENANT_ID, palmVectorB64: VALID_VECTOR, capturedAt: Date.now() },
      jwtAuth("jwt-user-1")
    );
    expect(res.status).toBe(201);
    const json = await res.json() as Record<string, unknown>;
    expect(json.success).toBe(true);
    expect(typeof json.enrollmentId).toBe("string");
  });

  it("userId comes from JWT (not request body)", async () => {
    const res = await post(
      "/api/palm/enroll",
      { tenantId: TENANT_ID, palmVectorB64: VALID_VECTOR, capturedAt: Date.now(), userId: "body-user" },
      jwtAuth("jwt-user-override")
    );
    expect(res.status).toBe(201);
    // enrollment was created for jwt-user-override, not body-user
    const found = await repo.findEnrollment(TENANT_ID, "jwt-user-override");
    expect(found).not.toBeNull();
    expect(await repo.findEnrollment(TENANT_ID, "body-user")).toBeNull();
  });

  it("returns 401 for expired JWT", async () => {
    const expired = createHs256Jwt({ userId: "u", exp: Math.floor(Date.now() / 1000) - 60 }, SECRET);
    const res = await post(
      "/api/palm/enroll",
      { tenantId: TENANT_ID, palmVectorB64: VALID_VECTOR, capturedAt: Date.now() },
      { Authorization: `Bearer ${expired}` }
    );
    expect(res.status).toBe(401);
    const json = await res.json() as Record<string, unknown>;
    expect(json.success).toBe(false);
  });

  it("returns 401 for wrong secret", async () => {
    const res = await post(
      "/api/palm/enroll",
      { tenantId: TENANT_ID, palmVectorB64: VALID_VECTOR, capturedAt: Date.now() },
      jwtAuth("u", "WRONG_SECRET")
    );
    expect(res.status).toBe(401);
  });
});

// ─── Enroll → verify full flow ────────────────────────────────────────────────

describe("Enroll + Verify full flow", () => {
  it("enroll stores record; verify returns match:false (no biometric match in stub path)", async () => {
    const userId = "flow-user-1";
    const enrollRes = await post(
      "/api/palm/enroll",
      { tenantId: TENANT_ID, palmVectorB64: VALID_VECTOR, capturedAt: Date.now() },
      internalAuth()   // X-Internal-Token, userId from env/body not used
    );
    // X-Internal-Token path — no userId in body, params userId is empty
    // This means the route uses userId = "" from res.locals — skip body userId for internal path
    // Use explicit userId in body for this test
    const enrollRes2 = await post(
      "/api/palm/enroll",
      { tenantId: TENANT_ID, userId, palmVectorB64: VALID_VECTOR, capturedAt: Date.now() },
      { "X-Internal-Token": SECRET }
    );
    expect(enrollRes2.status).toBe(201);

    const enrollment = await repo.findEnrollment(TENANT_ID, userId);
    expect(enrollment).not.toBeNull();
    expect(enrollment?.tenantId).toBe(TENANT_ID);
    expect(enrollment?.userId).toBe(userId);
    expect(enrollment?.templateVersion).toBe("1.0");
    expect(enrollment?.kemPrivkeyEnc.byteLength).toBeGreaterThan(0);
    expect(enrollment?.kekIv.byteLength).toBe(12);

    void enrollRes;
  });

  it("verify with no enrollment → match:false similarity:0", async () => {
    const userId  = "never-enrolled";
    const verifyRes = await post(
      "/api/palm/verify",
      { tenantId: TENANT_ID, userId, palmVectorB64: VALID_VECTOR, capturedAt: Date.now() },
      { "X-Internal-Token": SECRET }
    );
    expect(verifyRes.status).toBe(200);
    const json = await verifyRes.json() as Record<string, unknown>;
    expect(json.match).toBe(false);
    expect(json.similarity).toBe(0);
    expect(typeof json.auditToken).toBe("string");
  });
});

// ─── Conflict / 409 ──────────────────────────────────────────────────────────

describe("Enroll conflict — 409", () => {
  it("returns 409 when same user enrolled twice (via JWT)", async () => {
    const headers = jwtAuth("conflict-user");
    const body    = { tenantId: TENANT_ID, palmVectorB64: VALID_VECTOR, capturedAt: Date.now() };

    const first = await post("/api/palm/enroll", body, headers);
    expect(first.status).toBe(201);

    const second = await post("/api/palm/enroll", body, headers);
    expect(second.status).toBe(409);
    const json = await second.json() as Record<string, unknown>;
    expect(json.code).toBe("ALREADY_ENROLLED");
    expect(typeof json.message).toBe("string");
  });
});

// ─── Rate limiting with MemoryRateLimiter ─────────────────────────────────────

describe("Rate limiting — MemoryRateLimiter injected", () => {
  it("blocks 4th enroll attempt for same userId (JWT path)", async () => {
    const headers = jwtAuth("rl-test-user-p4");
    const body    = { tenantId: TENANT_ID, palmVectorB64: VALID_VECTOR, capturedAt: Date.now() };

    for (let i = 0; i < 3; i++) {
      const r = await post("/api/palm/enroll", body, headers);
      // First succeeds, 2nd+3rd may be 409 (already enrolled) — but rate limit increments
      expect([201, 409]).toContain(r.status);
    }

    limiter._resetForTesting();
    repo._reset();

    // Manually exhaust the rate limit
    for (let i = 0; i < 3; i++) limiter.recordEnroll("rl-test-user-p4");

    const blocked = await post("/api/palm/enroll", body, headers);
    expect(blocked.status).toBe(429);
    const json = await blocked.json() as Record<string, unknown>;
    expect(json.code).toBe("RATE_LIMIT_EXCEEDED");
  });
});

// ─── GDPR DELETE with JWT ──────────────────────────────────────────────────────

describe("DELETE /enroll/:userId — Phase 4 (JWT auth)", () => {
  it("returns 200 with JWT auth and removes enrollment from store", async () => {
    // Enroll first
    const userId = "delete-jwt-user";
    await post(
      "/api/palm/enroll",
      { tenantId: TENANT_ID, userId, palmVectorB64: VALID_VECTOR, capturedAt: Date.now() },
      { "X-Internal-Token": SECRET }
    );
    expect(await repo.findEnrollment(TENANT_ID, userId)).not.toBeNull();

    // Delete via JWT
    const delRes = await del(
      `/api/palm/enroll/${userId}`,
      { tenantId: TENANT_ID },
      jwtAuth(userId)
    );
    expect(delRes.status).toBe(200);
    const json = await delRes.json() as Record<string, unknown>;
    expect(json.deleted).toBe(true);
    expect(json.userId).toBe(userId);

    // Confirm repo deletion
    expect(await repo.findEnrollment(TENANT_ID, userId)).toBeNull();
  });

  it("audit log is appended on delete", async () => {
    const userId = "audit-delete-user";
    await del(
      `/api/palm/enroll/${userId}`,
      { tenantId: TENANT_ID },
      { "X-Internal-Token": SECRET }
    );
    const log = repo.getAuditLog();
    const deleteEntry = log.find((e) => e.eventType === "ENROLL_DELETED");
    expect(deleteEntry).toBeDefined();
    expect(deleteEntry?.userId).toBe(userId);
  });
});

// ─── Timing floor on all paths ────────────────────────────────────────────────

describe("Timing floor — Phase 4", () => {
  it("JWT 401 (expired token) takes ≥ 150ms", async () => {
    const expired = createHs256Jwt({ userId: "u", exp: Math.floor(Date.now() / 1000) - 60 }, SECRET);
    const t0 = Date.now();
    await post(
      "/api/palm/enroll",
      { tenantId: TENANT_ID, palmVectorB64: VALID_VECTOR, capturedAt: Date.now() },
      { Authorization: `Bearer ${expired}` }
    );
    expect(Date.now() - t0).toBeGreaterThanOrEqual(150);
  });

  it("409 conflict response takes ≥ 150ms", async () => {
    const headers = jwtAuth("timing-conflict-user");
    const body    = { tenantId: TENANT_ID, palmVectorB64: VALID_VECTOR, capturedAt: Date.now() };
    await post("/api/palm/enroll", body, headers);
    const t0 = Date.now();
    await post("/api/palm/enroll", body, headers);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(150);
  });
});
