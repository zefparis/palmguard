/**
 * PalmGuard API — Bearer auth, rate limiting, and erasure integration tests.
 *
 * Starts the Express app on a random OS port (listen(0)).
 * Uses Node.js built-in fetch (Node 20+).
 * Sets PALMGUARD_NO_LISTEN=1 to prevent the auto-listen side-effect in server.ts.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { createServer, type Server } from "node:http";
import { rateLimiter } from "../../src/api/ratelimit.js";
import { createApp } from "../../src/api/server.js";

const TEST_SECRET = "test-bearer-secret-abc123";

// Valid 24-byte (6 × float32) palm vector: all zeros except first float = 1.0
const VALID_VECTOR_B64 = Buffer.alloc(24, 0).toString("base64url");

const VALID_ENROLL_BODY = {
  tenantId: "tenant-test",
  userId: "user-test-001",
  palmVectorB64: VALID_VECTOR_B64,
  capturedAt: Date.now(),
  confidence: 0.95,
};

const VALID_VERIFY_BODY = {
  ...VALID_ENROLL_BODY,
  userId: "user-test-verify",
};

// ─── Server lifecycle ─────────────────────────────────────────────────────────

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  process.env["HCS_TOKEN_SECRET"] = TEST_SECRET;

  const app = createApp();
  server = createServer(app);

  await new Promise<void>((resolve) => server.listen(0, resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 4099;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(() => {
  server.close();
  delete process.env["HCS_TOKEN_SECRET"];
});

beforeEach(() => {
  rateLimiter._resetForTesting();
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Use X-Internal-Token for static-secret auth (proxy-internal / CI path).
 * JWT Bearer tests live in tests/middleware/jwt.test.ts.
 */
function authHeader(token: string): Record<string, string> {
  return { "X-Internal-Token": token };
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

// ─── Health endpoint (unauthenticated) ────────────────────────────────────────

describe("GET /api/palm/health", () => {
  it("returns 200 without auth header", async () => {
    const res = await fetch(`${baseUrl}/api/palm/health`);
    expect(res.status).toBe(200);
    const json = await res.json() as Record<string, unknown>;
    expect(json.status).toBe("ok");
    expect(json.version).toBe("1.0.0");
    const checks = json.checks as Record<string, string>;
    expect(typeof checks.supabase).toBe("string");
    expect(checks.jwtMode).toBe("hs256");
    expect(typeof json.uptime).toBe("number");
  });

  it("health is not in the guarded route set", async () => {
    // Verify /health does NOT require Bearer even if present
    const res = await fetch(`${baseUrl}/api/palm/health`, {
      headers: { Authorization: "Bearer wrong" },
    });
    expect(res.status).toBe(200);
  });
});

// ─── Enroll — auth ────────────────────────────────────────────────────────────

describe("POST /api/palm/enroll — authentication", () => {
  it("returns 401 when Authorization header is absent", async () => {
    const res = await post("/api/palm/enroll", VALID_ENROLL_BODY);
    expect(res.status).toBe(401);
    const json = await res.json() as Record<string, unknown>;
    expect(json.code).toBe("UNAUTHORIZED");
    expect(json.success).toBe(false);
  });

  it("returns 401 with wrong Bearer token", async () => {
    const res = await post("/api/palm/enroll", VALID_ENROLL_BODY, authHeader("wrong-token"));
    expect(res.status).toBe(401);
    const json = await res.json() as Record<string, unknown>;
    expect(json.code).toBe("UNAUTHORIZED");
  });

  it("returns 401 with empty Bearer value", async () => {
    const res = await post("/api/palm/enroll", VALID_ENROLL_BODY, { Authorization: "Bearer " });
    expect(res.status).toBe(401);
  });

  it("returns 401 with malformed Authorization scheme", async () => {
    const res = await post("/api/palm/enroll", VALID_ENROLL_BODY, { Authorization: `Basic ${TEST_SECRET}` });
    expect(res.status).toBe(401);
  });

  it("returns 201 with correct Bearer token", async () => {
    const res = await post("/api/palm/enroll", VALID_ENROLL_BODY, authHeader(TEST_SECRET));
    expect(res.status).toBe(201);
    const json = await res.json() as Record<string, unknown>;
    expect(json.success).toBe(true);
    expect(typeof json.enrollmentId).toBe("string");
    expect(typeof json.enrolledAt).toBe("number");
    expect(json.templateVersion).toBe("1.0");
  });
});

// ─── Enroll — validation ──────────────────────────────────────────────────────

describe("POST /api/palm/enroll — validation", () => {
  it("returns 400 when required fields are missing", async () => {
    const res = await post("/api/palm/enroll", { tenantId: "t" }, authHeader(TEST_SECRET));
    expect(res.status).toBe(400);
    const json = await res.json() as Record<string, unknown>;
    expect(json.code).toBe("INVALID_REQUEST");
  });

  it("returns 400 when palmVectorB64 decodes to wrong byte count", async () => {
    const shortVec = Buffer.alloc(10).toString("base64url");
    const res = await post(
      "/api/palm/enroll",
      { ...VALID_ENROLL_BODY, palmVectorB64: shortVec },
      authHeader(TEST_SECRET)
    );
    expect(res.status).toBe(400);
    const json = await res.json() as Record<string, unknown>;
    expect(json.code).toBe("INVALID_VECTOR");
  });
});

// ─── Verify — auth ────────────────────────────────────────────────────────────

describe("POST /api/palm/verify — authentication", () => {
  it("returns 401 when Authorization header is absent", async () => {
    const res = await post("/api/palm/verify", VALID_VERIFY_BODY);
    expect(res.status).toBe(401);
  });

  it("returns 401 with wrong Bearer token", async () => {
    const res = await post("/api/palm/verify", VALID_VERIFY_BODY, authHeader("bad-token"));
    expect(res.status).toBe(401);
  });

  it("returns 200 with correct Bearer token", async () => {
    const res = await post("/api/palm/verify", VALID_VERIFY_BODY, authHeader(TEST_SECRET));
    expect(res.status).toBe(200);
    const json = await res.json() as Record<string, unknown>;
    expect(typeof json.match).toBe("boolean");
    expect(typeof json.similarity).toBe("number");
    expect(typeof json.auditToken).toBe("string");
  });
});

// ─── Rate limiting — enroll ───────────────────────────────────────────────────

describe("Rate limiting — enroll (max 3 / 24h)", () => {
  const USER = "rl-user-enroll";
  const body = { ...VALID_ENROLL_BODY, userId: USER };

  it("allows 3 enrollments and blocks the 4th with 429", async () => {
    for (let i = 0; i < 3; i++) {
      const res = await post("/api/palm/enroll", body, authHeader(TEST_SECRET));
      expect(res.status).toBe(201);
    }
    const res4 = await post("/api/palm/enroll", body, authHeader(TEST_SECRET));
    expect(res4.status).toBe(429);
    const json = await res4.json() as Record<string, unknown>;
    expect(json.code).toBe("RATE_LIMIT_EXCEEDED");
  });

  it("429 includes Retry-After header", async () => {
    const body2 = { ...VALID_ENROLL_BODY, userId: "rl-retry-after" };
    for (let i = 0; i < 3; i++) {
      await post("/api/palm/enroll", body2, authHeader(TEST_SECRET));
    }
    const res = await post("/api/palm/enroll", body2, authHeader(TEST_SECRET));
    expect(res.status).toBe(429);
    expect(res.headers.has("retry-after")).toBe(true);
    const retryAfter = parseInt(res.headers.get("retry-after") ?? "0", 10);
    expect(retryAfter).toBeGreaterThan(0);
  });

  it("different users have independent rate limit counters", async () => {
    for (let i = 0; i < 3; i++) {
      await post("/api/palm/enroll", { ...VALID_ENROLL_BODY, userId: "rl-user-A" }, authHeader(TEST_SECRET));
    }
    // User B should still be allowed
    const res = await post(
      "/api/palm/enroll",
      { ...VALID_ENROLL_BODY, userId: "rl-user-B" },
      authHeader(TEST_SECRET)
    );
    expect(res.status).toBe(201);
  });
});

// ─── Rate limiting — verify ───────────────────────────────────────────────────

describe("Rate limiting — verify (max 10 / hour)", () => {
  it("allows 10 verifies and blocks the 11th with 429", async () => {
    const userId = "rl-verify-user";
    const body = { ...VALID_VERIFY_BODY, userId };

    for (let i = 0; i < 10; i++) {
      const res = await post("/api/palm/verify", body, authHeader(TEST_SECRET));
      expect(res.status).toBe(200);
    }
    const res11 = await post("/api/palm/verify", body, authHeader(TEST_SECRET));
    expect(res11.status).toBe(429);
    const json = await res11.json() as Record<string, unknown>;
    expect(json.code).toBe("RATE_LIMIT_EXCEEDED");
    expect(res11.headers.has("retry-after")).toBe(true);
  });
});

// ─── Timing floor ─────────────────────────────────────────────────────────────

describe("Timing floor", () => {
  it("401 response takes ≥ 150ms (timing oracle protection)", async () => {
    const t0 = Date.now();
    const res = await post("/api/palm/enroll", VALID_ENROLL_BODY);
    const elapsed = Date.now() - t0;
    expect(res.status).toBe(401);
    expect(elapsed).toBeGreaterThanOrEqual(150);
  });

  it("400 response (bad vector) takes ≥ 150ms", async () => {
    const t0 = Date.now();
    const res = await post(
      "/api/palm/enroll",
      { ...VALID_ENROLL_BODY, palmVectorB64: "aaaa" },
      authHeader(TEST_SECRET)
    );
    const elapsed = Date.now() - t0;
    expect(res.status).toBe(400);
    expect(elapsed).toBeGreaterThanOrEqual(150);
  });

  it("error response shape is structurally identical to success for 401 and 400", async () => {
    const r401 = await (await post("/api/palm/enroll", VALID_ENROLL_BODY)).json() as Record<string, unknown>;
    const r400 = await (await post("/api/palm/enroll", { tenantId: "x" }, authHeader(TEST_SECRET))).json() as Record<string, unknown>;
    // Both must have success: false + code + message
    for (const body of [r401, r400]) {
      expect(body.success).toBe(false);
      expect(typeof body.code).toBe("string");
      expect(typeof body.message).toBe("string");
    }
  });
});

// ─── RGPD DELETE /enroll/:userId ──────────────────────────────────────────────

describe("DELETE /api/palm/enroll/:userId — right to erasure", () => {
  it("returns 401 without auth", async () => {
    const res = await del("/api/palm/enroll/user-to-delete", { tenantId: "t1" });
    expect(res.status).toBe(401);
  });

  it("returns 200 with valid auth and correct body", async () => {
    const res = await del(
      "/api/palm/enroll/user-delete-test",
      { tenantId: "tenant-test" },
      authHeader(TEST_SECRET)
    );
    expect(res.status).toBe(200);
    const json = await res.json() as Record<string, unknown>;
    expect(json.deleted).toBe(true);
    expect(json.userId).toBe("user-delete-test");
    expect(typeof json.timestamp).toBe("number");
  });

  it("returns 400 when tenantId is missing", async () => {
    const res = await del(
      "/api/palm/enroll/some-user",
      {},
      authHeader(TEST_SECRET)
    );
    expect(res.status).toBe(400);
    const json = await res.json() as Record<string, unknown>;
    expect(json.code).toBe("INVALID_REQUEST");
  });

  it("erasure response also takes ≥ 150ms", async () => {
    const t0 = Date.now();
    await del("/api/palm/enroll/u", { tenantId: "t" }, authHeader(TEST_SECRET));
    expect(Date.now() - t0).toBeGreaterThanOrEqual(150);
  });
});
