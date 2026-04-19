/**
 * PalmGuard JWT middleware — unit tests
 *
 * Covers:
 *   - verifyHs256Jwt: valid, expired, tampered, malformed, algorithm confusion
 *   - createHs256Jwt: round-trip
 *   - requireAuth Express middleware: JWT path, X-Internal-Token path, rejections
 */

import { describe, it, expect, vi } from "vitest";
import { createHmac } from "node:crypto";
import {
  verifyHs256Jwt,
  createHs256Jwt,
  JwtError,
  requireAuth,
} from "../../src/api/middleware/jwt.js";
import type { Request, Response, NextFunction } from "express";

const SECRET = "test-secret-for-jwt-tests-abc";

// ─── Helper: hand-craft a JWT without createHs256Jwt ─────────────────────────

function rawJwt(header: object, payload: object, secret: string): string {
  const h = Buffer.from(JSON.stringify(header)).toString("base64url");
  const p = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", secret).update(`${h}.${p}`).digest("base64url");
  return `${h}.${p}.${sig}`;
}

function validPayload(overrides?: object) {
  return {
    userId:    "user-abc",
    sessionId: "sess-xyz",
    iat:       Math.floor(Date.now() / 1000),
    exp:       Math.floor(Date.now() / 1000) + 3600,
    ...overrides,
  };
}

// ─── createHs256Jwt / verifyHs256Jwt round-trip ───────────────────────────────

describe("createHs256Jwt + verifyHs256Jwt round-trip", () => {
  it("creates and verifies a valid token", () => {
    const token = createHs256Jwt({ userId: "u1", sessionId: "s1" }, SECRET);
    const payload = verifyHs256Jwt(token, SECRET);
    expect(payload.userId).toBe("u1");
    expect(payload.sessionId).toBe("s1");
    expect(payload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("round-trips without sessionId", () => {
    const token   = createHs256Jwt({ userId: "u2" }, SECRET);
    const payload = verifyHs256Jwt(token, SECRET);
    expect(payload.userId).toBe("u2");
    expect(payload.sessionId).toBeUndefined();
  });

  it("uses custom exp when provided", () => {
    const exp   = Math.floor(Date.now() / 1000) + 7200;
    const token = createHs256Jwt({ userId: "u3", exp }, SECRET);
    const p     = verifyHs256Jwt(token, SECRET);
    expect(p.exp).toBe(exp);
  });
});

// ─── verifyHs256Jwt — valid ───────────────────────────────────────────────────

describe("verifyHs256Jwt — valid tokens", () => {
  it("accepts a well-formed HS256 token", () => {
    const token = rawJwt({ alg: "HS256", typ: "JWT" }, validPayload(), SECRET);
    expect(() => verifyHs256Jwt(token, SECRET)).not.toThrow();
  });

  it("returns correct userId and exp", () => {
    const token   = rawJwt({ alg: "HS256" }, validPayload({ userId: "alice" }), SECRET);
    const payload = verifyHs256Jwt(token, SECRET);
    expect(payload.userId).toBe("alice");
  });

  it("accepts token with 5 s clock skew (exp = now - 3)", () => {
    // exp is 3 s ago but within the 5 s skew window
    const near = rawJwt({ alg: "HS256" }, validPayload({ exp: Math.floor(Date.now() / 1000) - 3 }), SECRET);
    expect(() => verifyHs256Jwt(near, SECRET)).not.toThrow();
  });
});

// ─── verifyHs256Jwt — malformed ───────────────────────────────────────────────

describe("verifyHs256Jwt — malformed tokens", () => {
  it("throws MALFORMED when token has fewer than 3 parts", () => {
    expect(() => verifyHs256Jwt("only.two", SECRET))
      .toThrowError(expect.objectContaining({ jwtCode: "MALFORMED" }));
  });

  it("throws MALFORMED when token has more than 3 parts", () => {
    expect(() => verifyHs256Jwt("a.b.c.d", SECRET))
      .toThrowError(expect.objectContaining({ jwtCode: "MALFORMED" }));
  });

  it("throws MALFORMED when header is invalid JSON", () => {
    const bad = `${Buffer.from("!bad!").toString("base64url")}.payload.sig`;
    expect(() => verifyHs256Jwt(bad, SECRET))
      .toThrowError(expect.objectContaining({ jwtCode: "MALFORMED" }));
  });

  it("throws MALFORMED when payload is invalid JSON", () => {
    const header = Buffer.from(JSON.stringify({ alg: "HS256" })).toString("base64url");
    const badPayload = Buffer.from("!notjson").toString("base64url");
    const sig = createHmac("sha256", SECRET).update(`${header}.${badPayload}`).digest("base64url");
    expect(() => verifyHs256Jwt(`${header}.${badPayload}.${sig}`, SECRET))
      .toThrowError(expect.objectContaining({ jwtCode: "MALFORMED" }));
  });
});

// ─── verifyHs256Jwt — algorithm confusion ────────────────────────────────────

describe("verifyHs256Jwt — algorithm confusion attacks", () => {
  it("rejects RS256 algorithm header (confusion attack)", () => {
    const token = rawJwt({ alg: "RS256", typ: "JWT" }, validPayload(), SECRET);
    expect(() => verifyHs256Jwt(token, SECRET))
      .toThrowError(expect.objectContaining({ jwtCode: "ALGORITHM" }));
  });

  it("rejects none algorithm", () => {
    const token = rawJwt({ alg: "none" }, validPayload(), SECRET);
    expect(() => verifyHs256Jwt(token, SECRET))
      .toThrowError(expect.objectContaining({ jwtCode: "ALGORITHM" }));
  });

  it("rejects HS512 algorithm", () => {
    const token = rawJwt({ alg: "HS512" }, validPayload(), SECRET);
    expect(() => verifyHs256Jwt(token, SECRET))
      .toThrowError(expect.objectContaining({ jwtCode: "ALGORITHM" }));
  });

  it("rejects missing alg field", () => {
    const token = rawJwt({ typ: "JWT" }, validPayload(), SECRET);
    expect(() => verifyHs256Jwt(token, SECRET))
      .toThrowError(expect.objectContaining({ jwtCode: "ALGORITHM" }));
  });
});

// ─── verifyHs256Jwt — signature ──────────────────────────────────────────────

describe("verifyHs256Jwt — signature validation", () => {
  it("rejects token signed with wrong secret", () => {
    const token = createHs256Jwt({ userId: "u" }, "WRONG-SECRET");
    expect(() => verifyHs256Jwt(token, SECRET))
      .toThrowError(expect.objectContaining({ jwtCode: "SIGNATURE" }));
  });

  it("rejects token with tampered payload", () => {
    const token  = createHs256Jwt({ userId: "original" }, SECRET);
    const parts  = token.split(".");
    const tampered = Buffer.from(JSON.stringify({ alg: "HS256" })).toString("base64url")
      + "."
      + Buffer.from(JSON.stringify({ userId: "hacker", exp: 9999999999 })).toString("base64url")
      + "."
      + parts[2];
    expect(() => verifyHs256Jwt(tampered, SECRET))
      .toThrowError(expect.objectContaining({ jwtCode: "SIGNATURE" }));
  });

  it("rejects token with truncated signature", () => {
    const token = createHs256Jwt({ userId: "u" }, SECRET);
    const [h, p] = token.split(".");
    expect(() => verifyHs256Jwt(`${h}.${p}.abc`, SECRET))
      .toThrowError(expect.objectContaining({ jwtCode: "SIGNATURE" }));
  });
});

// ─── verifyHs256Jwt — expiry ─────────────────────────────────────────────────

describe("verifyHs256Jwt — expiry", () => {
  it("rejects expired token (exp < now - 5)", () => {
    const token = rawJwt({ alg: "HS256" }, validPayload({ exp: Math.floor(Date.now() / 1000) - 10 }), SECRET);
    expect(() => verifyHs256Jwt(token, SECRET))
      .toThrowError(expect.objectContaining({ jwtCode: "EXPIRED" }));
  });
});

// ─── verifyHs256Jwt — missing claims ─────────────────────────────────────────

describe("verifyHs256Jwt — claim validation", () => {
  it("rejects token without userId", () => {
    const token = rawJwt({ alg: "HS256" }, { exp: Math.floor(Date.now() / 1000) + 3600 }, SECRET);
    expect(() => verifyHs256Jwt(token, SECRET))
      .toThrowError(expect.objectContaining({ jwtCode: "MISSING_CLAIM" }));
  });

  it("rejects token where userId is a number", () => {
    const token = rawJwt({ alg: "HS256" }, { userId: 123, exp: Math.floor(Date.now() / 1000) + 3600 }, SECRET);
    expect(() => verifyHs256Jwt(token, SECRET))
      .toThrowError(expect.objectContaining({ jwtCode: "MISSING_CLAIM" }));
  });
});

// ─── JwtError ────────────────────────────────────────────────────────────────

describe("JwtError", () => {
  it("is instanceof Error", () => {
    const err = new JwtError("EXPIRED", "test");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("JwtError");
    expect(err.jwtCode).toBe("EXPIRED");
    expect(err.message).toBe("test");
  });
});

// ─── requireAuth middleware ───────────────────────────────────────────────────

function mockRes() {
  const json = vi.fn();
  const status = vi.fn().mockReturnThis();
  const setHeader = vi.fn();
  const locals: Record<string, unknown> = {};
  return { res: { json, status, setHeader, locals } as unknown as Response, json, status };
}

function mockReq(
  headers: Record<string, string> = {},
  body: Record<string, unknown> = {},
  params: Record<string, string> = {}
): Request {
  return { headers, body, params, ip: "127.0.0.1", socket: {} } as unknown as Request;
}

function mockNext() { return vi.fn() as unknown as NextFunction; }

describe("requireAuth middleware — X-Internal-Token path", () => {
  const secret = "internal-secret-xyz";

  it("accepts valid X-Internal-Token and sets userId from body", async () => {
    process.env["HCS_TOKEN_SECRET"] = secret;
    const { res } = mockRes();
    const next = mockNext();
    const req = mockReq({ "x-internal-token": secret }, { userId: "body-user" });
    requireAuth(req, res, next);
    await new Promise((r) => setTimeout(r, 0));
    expect(next).toHaveBeenCalled();
    expect(res.locals["userId"]).toBe("body-user");
    expect(res.locals["authMode"]).toBe("internal");
    delete process.env["HCS_TOKEN_SECRET"];
  });

  it("accepts valid X-Internal-Token and falls back to params userId", async () => {
    process.env["HCS_TOKEN_SECRET"] = secret;
    const { res } = mockRes();
    const next = mockNext();
    const req = mockReq({ "x-internal-token": secret }, {}, { userId: "param-user" });
    requireAuth(req, res, next);
    await new Promise((r) => setTimeout(r, 0));
    expect(next).toHaveBeenCalled();
    expect(res.locals["userId"]).toBe("param-user");
    delete process.env["HCS_TOKEN_SECRET"];
  });

  it("rejects invalid X-Internal-Token with 401 after delay", async () => {
    process.env["HCS_TOKEN_SECRET"] = secret;
    const { res, status, json } = mockRes();
    const next = mockNext();
    const t0 = Date.now();
    requireAuth(mockReq({ "x-internal-token": "wrong" }), res, next);
    await new Promise((r) => setTimeout(r, 250));
    expect(Date.now() - t0).toBeGreaterThanOrEqual(150);
    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: "UNAUTHORIZED" }));
    delete process.env["HCS_TOKEN_SECRET"];
  });
});

describe("requireAuth middleware — JWT Bearer path", () => {
  const secret = "jwt-bearer-secret-abc";

  it("accepts valid JWT Bearer and sets userId", async () => {
    process.env["HCS_TOKEN_SECRET"] = secret;
    const token = createHs256Jwt({ userId: "jwt-user", sessionId: "s1" }, secret);
    const { res } = mockRes();
    const next = mockNext();
    requireAuth(mockReq({ authorization: `Bearer ${token}` }), res, next);
    await new Promise((r) => setTimeout(r, 0));
    expect(next).toHaveBeenCalled();
    expect(res.locals["userId"]).toBe("jwt-user");
    expect(res.locals["authMode"]).toBe("jwt");
    delete process.env["HCS_TOKEN_SECRET"];
  });

  it("rejects expired JWT with 401 after delay", async () => {
    process.env["HCS_TOKEN_SECRET"] = secret;
    const expired = rawJwt(
      { alg: "HS256" },
      { userId: "u", exp: Math.floor(Date.now() / 1000) - 60 },
      secret
    );
    const { res, status } = mockRes();
    const next = mockNext();
    const t0 = Date.now();
    requireAuth(mockReq({ authorization: `Bearer ${expired}` }), res, next);
    await new Promise((r) => setTimeout(r, 250));
    expect(Date.now() - t0).toBeGreaterThanOrEqual(150);
    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(401);
    delete process.env["HCS_TOKEN_SECRET"];
  });

  it("rejects RS256 algorithm confusion with 401", async () => {
    process.env["HCS_TOKEN_SECRET"] = secret;
    const confusion = rawJwt({ alg: "RS256" }, validPayload({ userId: "u" }), secret);
    const { res, status } = mockRes();
    const next = mockNext();
    requireAuth(mockReq({ authorization: `Bearer ${confusion}` }), res, next);
    await new Promise((r) => setTimeout(r, 250));
    expect(status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
    delete process.env["HCS_TOKEN_SECRET"];
  });

  it("rejects missing auth header with 401", async () => {
    process.env["HCS_TOKEN_SECRET"] = secret;
    const { res, status } = mockRes();
    const next = mockNext();
    requireAuth(mockReq({}), res, next);
    await new Promise((r) => setTimeout(r, 250));
    expect(status).toHaveBeenCalledWith(401);
    delete process.env["HCS_TOKEN_SECRET"];
  });

  it("returns 503 when HCS_TOKEN_SECRET is not configured", async () => {
    delete process.env["HCS_TOKEN_SECRET"];
    const { res, status } = mockRes();
    const next = mockNext();
    requireAuth(mockReq({}), res, next);
    await new Promise((r) => setTimeout(r, 250));
    expect(status).toHaveBeenCalledWith(503);
  });
});
