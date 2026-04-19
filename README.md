# PalmGuard

**Palm biometric authentication for HCS-U7** — fractal dimension + TDA feature extraction, ML-KEM-768 post-quantum encapsulation, AES-256-GCM private key vault, GDPR-compliant right-to-erasure.

[![Patent Pending](https://img.shields.io/badge/Patent%20Pending-FR2514274%20·%20FR2514546-blue)](#patent-notice)
[![FIPS 203](https://img.shields.io/badge/FIPS%20203-ML--KEM--768%20Level%203-purple)](https://csrc.nist.gov/pubs/fips/203/final)
[![GDPR](https://img.shields.io/badge/GDPR-Right%20to%20Erasure-green)](#gdpr--right-to-erasure)
[![Version](https://img.shields.io/badge/version-1.0.0-blue)](#)
[![Tests](https://img.shields.io/badge/Tests-222%20passing-brightgreen)](#testing)
[![Node](https://img.shields.io/badge/Node-≥20.0-brightgreen)](https://nodejs.org)

---

## Table of Contents

1. [Architecture](#architecture)
2. [Scientific Basis](#scientific-basis)
3. [Security Properties](#security-properties)
4. [Quick Start](#quick-start)
5. [API Reference](#api-reference)
6. [Deployment](#deployment)
7. [HCS-U7 Integration](#hcs-u7-integration)
8. [Integration Guide](#integration-guide)
9. [Performance Benchmarks](#performance-benchmarks)
10. [Supabase Setup](#supabase-setup)
11. [GDPR / Right to Erasure](#gdpr--right-to-erasure)
12. [Testing](#testing)
13. [Roadmap](#roadmap)
14. [Patent Notice](#patent-notice)

---

## Architecture

```
┌─────────────────── Browser (zero raw biometric upload) ─────────────────────┐
│                                                                               │
│  WebRTC Camera ──► MediaPipe Hands ──► 21 landmarks (normalized 0..1)        │
│       │                                       │                               │
│       ▼                                       ▼                               │
│  OffscreenCanvas ──► 256×256 grayscale ROI   Palm keypoints [0,1,5,9,13,17] │
│       │                                       │                               │
│       ▼                                       └──► ROI bounding box           │
│  Otsu threshold ──► binary image                                              │
│       │                                                                       │
│       ▼                                                                       │
│  Zhang-Suen thinning ──► skeleton pixels + intersection nodes                 │
│       │                                                                       │
│       ├──► [heart/head/life/fate line images]                                 │
│       │         └──► boxCountDimension()  ──► D ∈ [1.0, 2.0]  (~35ms)       │
│       │                                                                       │
│       └──► [intersection points as (x,y) cloud]                              │
│                 └──► computePersistence()  ──► PersistenceDiagram            │
│                           └──► diagramToVector() ──► Float32Array(32)        │
│                                                                               │
│  buildCombinedVector()  ──► Float32Array(38)  [fractal(6) | TDA(32)]        │
│                                     │                                         │
│  serializeVector(fractal)  ──► 24 bytes  ─┐                                  │
│  serializeTDAVector(tda)   ──► 128 bytes ─┤──► POST /api/palm/enroll         │
│                                            │    Authorization: Bearer <token>  │
└────────────────────────────────────────────┴─────────────────────────────────┘
                                             │
                         ┌───────────────────┘
                         ▼
               ┌─── palmguard API (:4010) ──────────────────────────────────┐
               │                                                             │
               │  requireBearerAuth()    ← timing-safe, always ≥ 150ms     │
               │         │                                                   │
               │  rateLimiter.checkEnroll()   ← 3/24h per userId           │
               │         │                                                   │
               │  deriveCelestialSalt(capturedAt)                           │
               │         │                                                   │
               │  generateKeyPair()  [ML-KEM-768 / FIPS 203]               │
               │         │                                                   │
               │  encapsulateTemplate(publicKey, vector, salt)              │
               │         │                                                   │
               │  deriveKEK(HCS_TOKEN_SECRET, userId)  ← HKDF-SHA-256      │
               │         │                                                   │
               │  encryptPrivateKey(kek, privateKey)   ← AES-256-GCM       │
               │         │                                                   │
               │  ┌──────┴────────────────────────────────┐                │
               │  │  palm_enrollments (Supabase)           │                │
               │  │  ─ template_ciphertext  (ML-KEM CT)    │                │
               │  │  ─ kem_privkey_enc      (AES-GCM blob) │  ← Phase 3    │
               │  │  ─ kek_iv               (12-byte IV)   │  ← Phase 3    │
               │  │  ─ content_hash         (SHA-256)      │                │
               │  └────────────────────────────────────────┘                │
               └─────────────────────────────────────────────────────────────┘
```

---

## Scientific Basis

### 1. Fractal Dimension Analysis

Each major palm line is reduced to a 1-pixel-wide skeleton via **Zhang-Suen thinning** (1984), then analysed using the **box-counting Hausdorff–Besicovitch dimension**:

```
D_B = -lim_{r→0} log N(r) / log r
```

`N(r)` = number of `r×r` boxes covering ≥1 skeleton pixel. `D` is estimated by OLS regression on 4–8 scales. Four lines yield four D values; combined with lacunarity (texture variance) and intersection density to form a **6-scalar biometric vector**.

> Uthayakumar, R., Nirmala Devi, M. and Jayalalitha, G. (2013). "Fractal analysis in all branches of science: fractals in breast cancer diagnosis." *Chaos, Solitons & Fractals*.
>
> Liu, J. Z., Zhang, L. D. and Yue, G. H. (2003). "Fractal dimension in human cerebellum measured by magnetic resonance imaging." *Biophysical Journal*, **85**(6), 4041–4046.

Cosine similarity threshold: **0.970** (6-vector). Cross-instance stability: σ ≈ 0.004 on repeated captures.

### 2. Topological Data Analysis (TDA)

Skeleton intersection nodes `{(x_i, y_i)}` are modelled as a **Vietoris-Rips filtration**. For each ε threshold, an edge (i,j) is added when `d(i,j) ≤ ε`. Persistent homology tracks:

- **H0** — connected components: born at ε=0, die when components merge
- **H1** — independent 1-cycles (loops): born/die at loop formation/filling

The persistence diagram is serialised to a **32-float vector** via the bottleneck-stable kernel of Reininghaus et al. Combined similarity threshold: **0.920** (38-vector).

> Chazal, F. and Michel, B. (2021). "An Introduction to Topological Data Analysis: Fundamental and Practical Aspects for Data Scientists." *Frontiers in Artificial Intelligence*, 4.
> DOI: [10.3389/frai.2021.667963](https://doi.org/10.3389/frai.2021.667963)
>
> Reininghaus, J., Huber, S., Bauer, U. and Kwitt, R. (2015). "A stable multi-scale kernel for topological machine learning." *CVPR 2015*.

### 3. Celestial Entropy Salt

A **deterministic 32-byte salt** derived from planetary ecliptic longitudes at capture time (Mercury, Venus, Mars, Jupiter, Saturn — VSOP87 mean elements, J2000.0 epoch). Purpose: make replay attacks infeasible across different capture epochs.

```
salt = SHA-256(planet_bytes || julian_day_number)
```

### 4. ML-KEM-768 Post-Quantum Encapsulation

Biometric vector encapsulated using **CRYSTALS-Kyber / ML-KEM-768** (NIST FIPS 203, published August 2024), providing NIST security Level 3 (≡ AES-192 classical security, quantum-safe against Shor's algorithm).

> NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard.  
> URL: [https://csrc.nist.gov/pubs/fips/203/final](https://csrc.nist.gov/pubs/fips/203/final)

---

## Security Properties

### Client-Side Processing

All raw biometric computation runs entirely in the browser:

| What stays in browser | What leaves browser |
|---|---|
| Raw camera frames | 24-byte fractal vector (Float32) |
| Palm ROI pixels | 128-byte TDA vector (Float32) |
| Skeleton / binary images | `capturedAt` timestamp |
| MediaPipe landmarks | `confidence` score |
| Private key (session) | `enrollmentId` (UUID) |

**Zero palm images, pixels, or landmarks are transmitted.**

### Vault Design (Phase 3)

```
KEK = HKDF-SHA-256(
  ikm  = HCS_TOKEN_SECRET,    ← server secret, never in DB
  salt = userId (UTF-8),      ← unique per user
  info = "palmguard-kek",
  len  = 256 bits
)

encryptedPrivKey = AES-256-GCM(KEK, iv=random 12 bytes, plaintext=privateKey)
```

Stored in Supabase: `(kem_privkey_enc, kek_iv)`. The KEK is **never stored** — re-derived from the session token at verify time. Compromise of the database alone does not expose private keys.

### Timing Oracle Protection

**Every** API response — including 401 (wrong token), 400 (bad vector), 429 (rate limit) — is delayed to:

```
response_time ≥ MIN_LATENCY_MS + random_jitter
MIN_LATENCY_MS = 150ms,  JITTER_MAX_MS = 50ms
```

Error response shapes are structurally identical regardless of failure reason, preventing information leakage via status code timing.

### Rate Limiting

| Operation | Limit | Window |
|---|---|---|
| `POST /enroll` | 3 attempts | per userId per 24 hours |
| `POST /verify` | 10 attempts | per userId per 60 minutes |

Exceeded limits return HTTP 429 with a `Retry-After` header and append `event_type='RATE_LIMIT_EXCEEDED'` to `palm_audit_log`.

### FIPS 203 Compliance

ML-KEM-768 key generation, encapsulation, and decapsulation use the [`mlkem`](https://www.npmjs.com/package/mlkem) package (CRYSTALS-Kyber reference implementation). Key sizes:
- Public key: 1184 bytes
- Private key: 2400 bytes
- Ciphertext: 1088 bytes

---

## Quick Start

```bash
# Install (always include devDependencies)
npm install --include=dev

# Run all 152 tests
npm test

# TypeScript strict check (zero errors)
npm run typecheck

# Start PalmGuard API on :4010
npm run api:dev

# Start interactive demo on :5174 (Vite)
npm run dev
```

### Environment variables

Copy `.env.example` and fill in:

```bash
cp .env.example .env
```

| Variable | Required | Description |
|---|---|---|
| `HCS_TOKEN_SECRET` | ✅ | Shared secret for Bearer auth (min 32 chars) |
| `PORT` | — | API port (default: 4010) |
| `SUPABASE_URL` | ✅ prod | Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | ✅ prod | Supabase service role key (server-side only) |

---

## API Reference

All protected endpoints require:
```
Authorization: Bearer <HCS_TOKEN_SECRET>
Content-Type: application/json
```

### `POST /api/palm/enroll`

Enroll a palm template for a user. Max **3 attempts per userId per 24h**.

**Request:**
```json
{
  "tenantId": "t_abc123",
  "userId": "user_xyz",
  "palmVectorB64": "<base64url, 24 bytes>",
  "capturedAt": 1700000000000,
  "confidence": 0.94
}
```

**Response 201:**
```json
{
  "success": true,
  "enrollmentId": "a1b2c3d4e5f6...",
  "enrolledAt": 1700000000000,
  "templateVersion": "1.0"
}
```

### `POST /api/palm/verify`

Verify a live capture against the stored template. Max **10 attempts per userId per hour**.

**Request:** same fields as enroll.

**Response 200:**
```json
{
  "match": true,
  "similarity": 0.99831,
  "processingMs": 163,
  "auditToken": "a1b2c3d4..."
}
```

### `DELETE /api/palm/enroll/:userId`

GDPR right-to-erasure: hard-delete all enrollments for a user.

**Request body:**
```json
{ "tenantId": "t_abc123" }
```

**Response 200:**
```json
{
  "deleted": true,
  "userId": "user_xyz",
  "timestamp": 1700000000000
}
```

### `GET /api/palm/health`

Unauthenticated liveness probe.

```json
{ "status": "ok", "module": "palmguard", "version": "1.0.0", "checks": { "supabase": "ok", "rateLimiter": "SupabaseRateLimiter", "jwtMode": "hs256" }, "uptime": 3600 }
```

### Error Envelope

All errors (401, 400, 429, 500) share the same shape:
```json
{ "success": false, "code": "RATE_LIMIT_EXCEEDED", "message": "..." }
```

---

## Deployment

### Render (production)

`render.yaml` is included at the project root. Deploy via Render dashboard → **New Web Service → Connect repo**.

| Setting | Value |
|---|---|
| Region | `frankfurt` |
| Plan | `standard` |
| Build command | `npm ci && npm run build:api` |
| Start command | `node dist/api/start.js` |
| Health check | `/api/palm/health` |

**Secrets to configure in Render dashboard:**

```bash
SUPABASE_URL=https://<project>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=eyJ...
HCS_TOKEN_SECRET=<min 32 chars — same as hcs-u7-backend>
RATE_LIMITER_MODE=supabase
NODE_ENV=production
PORT=4010
```

### Cloudflare Worker proxy

Set the `PALMGUARD_URL` secret in Cloudflare so the proxy forwards `/api/palm/*` to the Render deployment:

```bash
wrangler secret put PALMGUARD_URL
# Enter: https://palmguard.onrender.com
```

Local dev: copy `hcs-u7-proxy/.dev.vars.example` → `.dev.vars` and set `PALMGUARD_URL=http://localhost:4010`.

### Production smoke test

```bash
HCS_TOKEN_SECRET=<secret> npx ts-node scripts/smoke-test.ts --url https://palmguard.onrender.com
```

---

## HCS-U7 Integration

PalmGuard is the **second factor** in the HCS-U7 2-factor authentication chain:

```
╔══════════════════════════════════════════════════════════════════╗
║         HCS-U7 2-Factor Cognitive + Palm Auth Chain             ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  [1] HCS-U7 Cognitive Tests (hcs-u7-dashboard)                  ║
║       Stroop · N-Back · RAN Vocal · Reaction · Pattern          ║
║       └─► HCS session JWT  (signed: HCS_TOKEN_SECRET)           ║
║                │                                                 ║
║  [2] Palm JWT Bridge  GET /api/session/palm-token               ║
║       (hcs-u7-backend/src/palm/palm.bridge.ts)                  ║
║       └─► Palm-scoped JWT  { userId, scope: "palmguard",        ║
║                              exp: now+600 }                     ║
║                │                                                 ║
║  [3] PalmGuard API  POST /api/palm/enroll  |  /verify           ║
║       Authorization: Bearer <palm-jwt>                          ║
║       (palmguard.onrender.com — this service)                   ║
║                │                                                 ║
║  [4] Combined Auth Certificate                                  ║
║       { factor1: "HCS-U7 ✓", factor2: "Palm ✓",               ║
║         similarity: 0.998, issuedAt: "2026-01-01T…" }           ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  Request flow (via Cloudflare Worker proxy):                     ║
║  Browser → api.hcs-u7.org → hcs-u7-proxy (Cloudflare)          ║
║    /api/session/palm-token  →  hcs-u7-backend (Render)          ║
║    /api/palm/*              →  palmguard      (Render)           ║
╚══════════════════════════════════════════════════════════════════╝
```

### Session bridge endpoint

```
GET /api/session/palm-token
Authorization: Bearer <hcs-session-jwt>

200 → { palmToken, expiresIn: 600, userId }
401 → { error: "UNAUTHORIZED" }
```

The `palmToken` is a 10-minute HS256 JWT containing `{ userId, scope: "palmguard", exp }`, signed with the same `HCS_TOKEN_SECRET`. PalmGuard's `requireAuth` middleware accepts it via the standard `Authorization: Bearer` path.

### Admin monitoring

Real-time PalmGuard metrics are available in the HCS-U7 admin dashboard at **`/admin/palmguard`** (SUPER_ADMIN / ADMIN roles). Displays: total enrollments, verify success rates (24h / 7d / 30d), rate limit hits, verify latency p50/p95, and a masked audit log with GDPR erasure buttons.

---

## Integration Guide

### Adding `/api/palm` to a HCS-U7 deployment

1. **Proxy** — `/api/palm` is already in `DASHBOARD_API_PATHS` in `hcs-u7-proxy/src/index.ts`. No further proxy changes needed.

2. **Deploy palmguard API** — run on the same Render/Fly.io service as `hcs-u7-backend`, or as a separate service, on port 4010.

3. **Environment** — set `HCS_TOKEN_SECRET` to the same value as `HCS_WORKER_SHARED_SECRET` (or a dedicated secret for palm routes).

4. **Dashboard integration** — from `hcs-u7-dashboard`, call:
   ```typescript
   await fetch("/api/palm/enroll", {
     method: "POST",
     headers: {
       "Authorization": `Bearer ${process.env.HCS_TOKEN_SECRET}`,
       "Content-Type": "application/json"
     },
     body: JSON.stringify(payload)
   });
   ```

5. **Supabase** — run `supabase/schema.sql` (initial), then `supabase/migrations/002_vault.sql` (Phase 3 vault columns).

### Demo

Open `http://localhost:5174` after `npm run dev`. Press **Enroll** (synthetic mode, no camera required) then **Verify** to see the full pipeline in action.

---

## Performance Benchmarks

| Metric | Target | Measured (laptop) | Notes |
|---|---|---|---|
| `boxCountDimension()` | < 50ms | ~35ms | 128×128, 6 scales, pure JS |
| `skeletonize()` | < 150ms | ~80ms | 256×256, Zhang-Suen |
| `computePersistence()` | < 200ms | ~60ms | ≤150 intersection points |
| Full enroll pipeline | < 3s | ~1.2s | incl. 15-frame MediaPipe capture |
| `POST /enroll` API | ≥ 150ms | 150–200ms | timing floor applied |
| `POST /verify` API | ≥ 150ms | 150–200ms | timing floor applied |
| FAR target | < 0.001% | — | cosine sim threshold 0.970 (fractal), 0.920 (combined) |
| FRR target | < 0.1% | — | estimated from synthetic dataset |
| Template size | 152 bytes | 152 bytes | 24B fractal + 128B TDA |
| Vault blob size | 2428 bytes | 2428 bytes | 12B IV + 2400B privkey + 16B GCM tag |

---

## Supabase Setup

```sql
-- Step 1: Initial schema
-- Run supabase/schema.sql in Supabase SQL Editor

-- Step 2: Phase 3 vault columns (additive)
-- Run supabase/migrations/002_vault.sql
```

Tables:
- **`palm_enrollments`** — ML-KEM ciphertext, encrypted private key vault, celestial metadata
- **`palm_audit_log`** — immutable append-only ANSSI-compatible event log (RLS: no UPDATE, no DELETE)

RLS policy: `app_backend` role scoped to `current_setting('app.tenant_id')`.

---

## GDPR / Right to Erasure

`DELETE /api/palm/enroll/:userId` performs a **hard delete** of all `palm_enrollments` rows for the user, then appends an `ENROLL_DELETED` event to `palm_audit_log` (audit trail is preserved per ANSSI requirements).

The audit log itself is append-only (no UPDATE, no DELETE via RLS rules) — the deletion event is the durable proof of erasure.

---

## Testing

```bash
npm test
```

| Suite | Tests | What it covers |
|---|---|---|
| `tests/fractal/boxcount.test.ts` | 39 | Box-counting engine, lacunarity, vector similarity |
| `tests/phase2/skeleton.test.ts` | 25 | Zhang-Suen thinning, connected components, intersection detection |
| `tests/phase2/tda.test.ts` | 32 | Vietoris-Rips persistence, H0/H1, diagram serialization |
| `tests/phase2/pipeline.test.ts` | 18 | Full assembly, ML-KEM integration, verify round-trip |
| `tests/vault/vault.test.ts` | 15 | HKDF KEK derivation, AES-GCM encrypt/decrypt, vault serialization |
| `tests/proxy/palm-auth.test.ts` | 23 | Bearer auth, rate limiting, timing floor, GDPR erasure |
| **Total** | **152** | |

---

## Roadmap

- [x] Box-counting fractal engine (`src/fractal/boxcount.ts`) — 39 tests
- [x] Zhang-Suen skeletonization (`src/topology/skeleton.ts`) — 25 tests
- [x] Vietoris-Rips TDA (`src/topology/tda.ts`) — 32 tests
- [x] Full pipeline assembly (`src/palmguard.ts`) — 18 tests
- [x] MediaPipe Hands capture (`src/capture/index.ts`)
- [x] Phase 2 interactive demo (`src/demo/index.html`)
- [x] Celestial entropy salt (`src/crypto/celestial.ts`)
- [x] ML-KEM-768 encapsulation (`src/crypto/mlkem.ts`)
- [x] AES-256-GCM vault (`src/crypto/vault.ts`) — 15 tests
- [x] Bearer auth middleware + rate limiting
- [x] Timing oracle hardening (floor + jitter on ALL responses)
- [x] GDPR `DELETE /enroll/:userId` endpoint
- [x] Supabase migration 002 (vault columns)
- [x] Proxy `/api/palm` allowlist entry (`hcs-u7-proxy`)
- [x] Supabase live DB integration — `SupabaseRepository` + `SupabaseRateLimiter` (Phase 4)
- [x] JWT auth middleware — HS256 `requireAuth`, `createHs256Jwt` (Phase 4)
- [x] Production rate limiter via Supabase (Phase 4)
- [x] Render deployment config — `render.yaml`, `tsconfig.api.json` (Phase 5)
- [x] Cloudflare proxy wiring — `PALMGUARD_URL` env, `/api/palm/*` intercept (Phase 5)
- [x] `hcs-u7-backend` session bridge — `GET /api/session/palm-token` (Phase 5)
- [x] 2-factor demo page — cognitive + palm JWT + biometric chain (Phase 5)
- [x] `hcs-u7-admin` monitoring panel — `/admin/palmguard` (Phase 5)
- [x] Production smoke test — `scripts/smoke-test.ts` (Phase 5)
- [ ] WASM-accelerated TDA (optional, pure-TS fallback already in production)

---

## Patent Notice

> **Novel combination — patent pending, IA-SOLUTION**
>
> French patents **FR2514274** and **FR2514546** cover the novel combination of:
> - Fractal dimension biometric feature extraction from palmprint lines
> - Topological data analysis (Vietoris-Rips persistence) applied to palm topology
> - Celestial entropy salting for anti-replay temporal binding
>
> Any reproduction, modification, or commercial use of this combination without
> written authorisation from IA-SOLUTION is prohibited.

---

## License

`UNLICENSED` — proprietary, part of the HCS-U7 ecosystem.  
Contact [IA-SOLUTION](https://hcs-u7.online) for commercial licensing.
