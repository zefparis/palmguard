#!/usr/bin/env npx ts-node --esm
/**
 * PalmGuard Smoke Test — Phase 5
 *
 * Full end-to-end test against a live Render deployment.
 *
 * Usage:
 *   npx ts-node scripts/smoke-test.ts --url https://palmguard.onrender.com
 *   npx ts-node scripts/smoke-test.ts --url http://localhost:4010
 *
 * Env:
 *   HCS_TOKEN_SECRET — used to issue X-Internal-Token (required)
 *   SMOKE_TENANT_ID  — tenant ID to use (default: smoke-tenant)
 *   SMOKE_USER_ID    — user ID to use   (default: smoke-user-{timestamp})
 */

import { createHmac } from "node:crypto";

// ── Args ──────────────────────────────────────────────────────────────────────

const args     = process.argv.slice(2);
const urlIdx   = args.indexOf("--url");
const BASE_URL = urlIdx >= 0 ? args[urlIdx + 1] : "http://localhost:4010";

if (!BASE_URL) {
  console.error("Usage: npx ts-node scripts/smoke-test.ts --url <url>");
  process.exit(1);
}

const SECRET    = process.env["HCS_TOKEN_SECRET"] ?? "";
const TENANT_ID = process.env["SMOKE_TENANT_ID"]  ?? "smoke-tenant";
const USER_ID   = process.env["SMOKE_USER_ID"]    ?? `smoke-user-${Date.now()}`;

if (!SECRET) {
  console.error("ERROR: HCS_TOKEN_SECRET env var is required");
  process.exit(1);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function pass(label: string) {
  console.log(`  ✅ ${label}`);
  passed++;
}

function fail(label: string, detail?: unknown) {
  console.error(`  ❌ ${label}`);
  if (detail !== undefined) console.error("     ", detail);
  failed++;
}

function auth(): Record<string, string> {
  return { "X-Internal-Token": SECRET };
}

async function get(path: string, headers: Record<string, string> = {}): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json", ...headers },
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

async function post(path: string, body: unknown, headers: Record<string, string> = {}): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

async function del(path: string, body: unknown, headers: Record<string, string> = {}): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "DELETE",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

// ── HMAC-SHA256 JWT for smoke test auth (alternative to X-Internal-Token) ────

function makeJwt(userId: string): string {
  const h = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const p = Buffer.from(JSON.stringify({
    userId,
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
  })).toString("base64url");
  const sig = createHmac("sha256", SECRET).update(`${h}.${p}`).digest("base64url");
  return `${h}.${p}.${sig}`;
}

function jwtAuth(): Record<string, string> {
  return { Authorization: `Bearer ${makeJwt(USER_ID)}` };
}

// ── Mock palm vector (6 fractal floats × 4 bytes = 24 bytes) ───────────────────

const MOCK_PALM_VECTOR = Buffer.alloc(24).fill(0x42).toString('base64');

// ── Test suite ────────────────────────────────────────────────────────────────

async function runSmokeTest(): Promise<void> {
  console.log(`\n🌴 PalmGuard Smoke Test`);
  console.log(`   URL:      ${BASE_URL}`);
  console.log(`   UserId:   ${USER_ID}`);
  console.log(`   TenantId: ${TENANT_ID}`);
  console.log();

  // ── Step 1: GET /health ───────────────────────────────────────────────────
  console.log("Step 1 — GET /api/palm/health");
  const h1 = await get("/api/palm/health");
  if (h1.status === 200) {
    pass("status 200");
  } else {
    fail(`status ${h1.status}`, h1.body);
  }
  const h1b = h1.body as Record<string, unknown> | null;
  if (h1b?.status === "ok")   pass("body.status = ok");
  else                         fail("body.status != ok", h1b);
  if (h1b?.version === "1.0.0") pass("version = 1.0.0");
  else                           fail("unexpected version", h1b?.version);
  const checks = h1b?.checks as Record<string, string> | undefined;
  if (checks?.jwtMode === "hs256") pass("checks.jwtMode = hs256");
  else                              fail("checks.jwtMode unexpected", checks);
  if (["ok", "degraded"].includes(checks?.supabase ?? "")) pass(`checks.supabase = ${checks?.supabase}`);
  else fail("checks.supabase unexpected", checks?.supabase);

  // ── Step 2: Enroll (X-Internal-Token) ────────────────────────────────────
  console.log("\nStep 2 — POST /api/palm/enroll (X-Internal-Token)");
  const e1 = await post(
    "/api/palm/enroll",
    { tenantId: TENANT_ID, userId: USER_ID, palmVectorB64: MOCK_PALM_VECTOR, capturedAt: Date.now(), confidence: 0.95 },
    auth()
  );
  if (e1.status === 201) {
    pass("status 201");
    const eb = e1.body as Record<string, unknown>;
    if (eb.success === true && typeof eb.enrollmentId === "string") pass("enrollmentId returned");
    else fail("unexpected body", eb);
  } else if (e1.status === 409) {
    pass("status 409 (already enrolled — re-run)");
  } else {
    fail(`status ${e1.status}`, e1.body);
  }

  // ── Step 3: Verify (JWT Bearer) ───────────────────────────────────────────
  console.log("\nStep 3 — POST /api/palm/verify (JWT Bearer)");
  const v1 = await post(
    "/api/palm/verify",
    { tenantId: TENANT_ID, userId: USER_ID, palmVectorB64: MOCK_PALM_VECTOR, capturedAt: Date.now() },
    jwtAuth()
  );
  if (v1.status === 200) {
    pass("status 200");
    const vb = v1.body as Record<string, unknown>;
    if (typeof vb.match === "boolean")          pass("body.match is boolean");
    else                                         fail("body.match not boolean", vb);
    if (typeof vb.similarity === "number")       pass("body.similarity is number");
    else                                         fail("body.similarity not number", vb);
    if (typeof vb.auditToken === "string")       pass("body.auditToken present");
    else                                         fail("body.auditToken missing", vb);
  } else {
    fail(`status ${v1.status}`, v1.body);
  }

  // ── Step 4: GET /health again ─────────────────────────────────────────────
  console.log("\nStep 4 — GET /api/palm/health (post-verify)");
  const h2 = await get("/api/palm/health");
  if (h2.status === 200) pass("still 200");
  else                    fail(`status ${h2.status}`, h2.body);

  // ── Step 5: DELETE enrollment ─────────────────────────────────────────────
  console.log("\nStep 5 — DELETE /api/palm/enroll/:userId");
  const d1 = await del(
    `/api/palm/enroll/${USER_ID}`,
    { tenantId: TENANT_ID },
    auth()
  );
  if (d1.status === 200) {
    pass("status 200");
    const db = d1.body as Record<string, unknown>;
    if (db.deleted === true)       pass("deleted = true");
    else                            fail("deleted != true", db);
    if (db.userId === USER_ID)     pass("userId matches");
    else                            fail("userId mismatch", db.userId);
  } else {
    fail(`status ${d1.status}`, d1.body);
  }

  // ── Step 6: Verify after delete → match:false ─────────────────────────────
  console.log("\nStep 6 — POST /api/palm/verify after delete (no enrollment)");
  const v2 = await post(
    "/api/palm/verify",
    { tenantId: TENANT_ID, userId: USER_ID, palmVectorB64: MOCK_PALM_VECTOR, capturedAt: Date.now() },
    jwtAuth()
  );
  if (v2.status === 200) {
    pass("status 200");
    const vb2 = v2.body as Record<string, unknown>;
    if (vb2.match === false && vb2.similarity === 0) pass("match=false, similarity=0 (no enrollment)");
    else                                               fail("unexpected body after delete", vb2);
  } else {
    fail(`status ${v2.status}`, v2.body);
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log(`\n──────────────────────────────────────`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed === 0) {
    console.log("🎉 All smoke tests passed — PalmGuard is healthy!\n");
  } else {
    console.error(`\n⚠️  ${failed} test(s) failed\n`);
    process.exit(1);
  }
}

runSmokeTest().catch((err) => {
  console.error("Fatal smoke test error:", err);
  process.exit(1);
});
