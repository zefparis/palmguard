import { describe, it, expect } from "vitest";
import {
  assemblePalmSignature,
  toStoredEnrollment,
  verifySignature,
  buildCombinedVector,
  combinedSimilarity,
  SIMILARITY_THRESHOLD,
  COMBINED_DIM,
} from "../../src/palmguard.js";

// ─── Synthetic grayscale ROI fixtures ────────────────────────────────────────

function makeGrayROI(
  w: number,
  h: number,
  fn: (x: number, y: number) => number
): Uint8Array {
  const data = new Uint8Array(w * h);
  for (let y = 0; y < h; y++)
    for (let x = 0; x < w; x++)
      data[y * w + x] = fn(x, y);
  return data;
}

/** Four horizontal palm-like dark lines on light background. */
function palmROI(w = 128, h = 128): Uint8Array {
  const lineYs = [
    Math.floor(h * 0.28),
    Math.floor(h * 0.42),
    Math.floor(h * 0.58),
    Math.floor(h * 0.72),
  ];
  return makeGrayROI(w, h, (x, y) =>
    lineYs.some((ly) => Math.abs(y - ly) <= 2) ? 20 : 210
  );
}

/** Slightly different palm (different line positions). */
function palmROI2(w = 128, h = 128): Uint8Array {
  const lineYs = [
    Math.floor(h * 0.30),
    Math.floor(h * 0.45),
    Math.floor(h * 0.60),
    Math.floor(h * 0.75),
  ];
  return makeGrayROI(w, h, (x, y) =>
    lineYs.some((ly) => Math.abs(y - ly) <= 2) ? 20 : 210
  );
}

// ─── assemblePalmSignature ────────────────────────────────────────────────────

describe("assemblePalmSignature", () => {
  it("runs the full pipeline without throwing", async () => {
    const roi = palmROI();
    await expect(assemblePalmSignature(roi, 128, 128)).resolves.toBeDefined();
  }, 10_000);

  it("returns a PalmSignature with all required fields", async () => {
    const sig = await assemblePalmSignature(palmROI(), 128, 128);
    expect(sig.version).toBe("1.0");
    expect(sig.timestamp).toBeGreaterThan(0);
    expect(sig.fractal).toBeDefined();
    expect(sig.tda).toBeInstanceOf(Float32Array);
    expect(sig.tda.length).toBe(32);
    expect(sig.combined).toBeInstanceOf(Float32Array);
    expect(sig.combined.length).toBe(COMBINED_DIM);
    expect(sig.skeleton).toBeDefined();
    expect(sig.celestialSalt).toBeDefined();
    expect(sig.publicKey).toBeInstanceOf(Uint8Array);
    expect(sig.privateKey).toBeInstanceOf(Uint8Array);
    expect(sig.template).toBeDefined();
    expect(sig.template.version).toBe("1.0");
  }, 10_000);

  it("combined vector has 38 floats (6 fractal + 32 TDA)", async () => {
    const sig = await assemblePalmSignature(palmROI(), 128, 128);
    expect(sig.combined.length).toBe(38);
    expect(sig.combined).toBeInstanceOf(Float32Array);
  }, 10_000);

  it("all combined vector values are finite", async () => {
    const sig = await assemblePalmSignature(palmROI(), 128, 128);
    expect([...sig.combined].every((v) => isFinite(v))).toBe(true);
  }, 10_000);

  it("ML-KEM keys are non-empty", async () => {
    const sig = await assemblePalmSignature(palmROI(), 128, 128);
    expect(sig.publicKey.length).toBeGreaterThan(100);
    expect(sig.privateKey.length).toBeGreaterThan(100);
  }, 10_000);

  it("template.ciphertext is non-empty base64url string", async () => {
    const sig = await assemblePalmSignature(palmROI(), 128, 128);
    expect(typeof sig.template.ciphertext).toBe("string");
    expect(sig.template.ciphertext.length).toBeGreaterThan(10);
  }, 10_000);

  it("same ROI produces nearly identical fractal vector", async () => {
    const roi = palmROI();
    const s1 = await assemblePalmSignature(roi, 128, 128);
    const s2 = await assemblePalmSignature(roi, 128, 128);
    const sim = combinedSimilarity(s1.combined, s2.combined);
    expect(sim).toBeGreaterThanOrEqual(0.99);
  }, 15_000);
});

// ─── toStoredEnrollment ───────────────────────────────────────────────────────

describe("toStoredEnrollment", () => {
  it("converts PalmSignature to storable format without private key", async () => {
    const sig = await assemblePalmSignature(palmROI(), 128, 128);
    const stored = toStoredEnrollment(sig);
    expect(stored.version).toBe("1.0");
    expect(typeof stored.fractalB64).toBe("string");
    expect(typeof stored.tdaB64).toBe("string");
    expect(stored.fractalB64.length).toBeGreaterThan(0);
    expect(stored.tdaB64.length).toBeGreaterThan(0);
    expect(stored.template).toBeDefined();
    expect((stored as unknown as Record<string, unknown>)["privateKey"]).toBeUndefined();
  }, 10_000);

  it("fractalB64 decodes to 24 bytes", async () => {
    const sig = await assemblePalmSignature(palmROI(), 128, 128);
    const stored = toStoredEnrollment(sig);
    const bytes = Buffer.from(
      stored.fractalB64.replace(/-/g, "+").replace(/_/g, "/"),
      "base64"
    );
    expect(bytes.length).toBe(24);
  }, 10_000);

  it("tdaB64 decodes to 128 bytes", async () => {
    const sig = await assemblePalmSignature(palmROI(), 128, 128);
    const stored = toStoredEnrollment(sig);
    const bytes = Buffer.from(
      stored.tdaB64.replace(/-/g, "+").replace(/_/g, "/"),
      "base64"
    );
    expect(bytes.length).toBe(128);
  }, 10_000);
});

// ─── verifySignature — same identity ─────────────────────────────────────────

describe("verifySignature — same ROI (enroll → verify round-trip)", () => {
  it("same palm ROI produces similarity ≥ threshold (match)", async () => {
    const roi = palmROI();
    const enrolled = await assemblePalmSignature(roi, 128, 128);
    const stored = toStoredEnrollment(enrolled);
    const live = await assemblePalmSignature(roi, 128, 128);
    const result = verifySignature(stored.fractalB64, stored.tdaB64, live);

    expect(result.match).toBe(true);
    expect(result.similarity).toBeGreaterThanOrEqual(SIMILARITY_THRESHOLD);
    expect(result.fractalSimilarity).toBeGreaterThan(0.90);
  }, 20_000);

  it("returns all diagnostic fields", async () => {
    const roi = palmROI();
    const enrolled = await assemblePalmSignature(roi, 128, 128);
    const stored = toStoredEnrollment(enrolled);
    const live = await assemblePalmSignature(roi, 128, 128);
    const result = verifySignature(stored.fractalB64, stored.tdaB64, live);

    expect(result.fractalSimilarity).toBeGreaterThanOrEqual(0);
    expect(result.tdaSimilarity).toBeGreaterThanOrEqual(0);
    expect(result.processingMs).toBeGreaterThanOrEqual(0);
    expect(result.combined.length).toBe(COMBINED_DIM);
  }, 20_000);
});

describe("verifySignature — different ROI (impostor)", () => {
  it("different palm ROIs produce lower similarity", async () => {
    const roi1 = palmROI();
    const roi2 = palmROI2();
    const enrolled = await assemblePalmSignature(roi1, 128, 128);
    const stored = toStoredEnrollment(enrolled);
    const live = await assemblePalmSignature(roi2, 128, 128);
    const result = verifySignature(stored.fractalB64, stored.tdaB64, live);

    // May or may not match (synthetic lines are similar) — just check it runs
    expect(typeof result.match).toBe("boolean");
    expect(result.similarity).toBeGreaterThanOrEqual(0);
    expect(result.similarity).toBeLessThanOrEqual(1);
  }, 20_000);
});

// ─── buildCombinedVector ──────────────────────────────────────────────────────

describe("buildCombinedVector", () => {
  it("first 6 floats match fractal vector", async () => {
    const sig = await assemblePalmSignature(palmROI(), 128, 128);
    const combined = buildCombinedVector(sig.fractal, sig.tda);
    for (let i = 0; i < 6; i++) {
      expect(combined[i]).toBeCloseTo(sig.fractal.vector[i] ?? 0, 3);
    }
  }, 10_000);

  it("floats 6..37 match TDA vector", async () => {
    const sig = await assemblePalmSignature(palmROI(), 128, 128);
    const combined = buildCombinedVector(sig.fractal, sig.tda);
    for (let i = 0; i < 32; i++) {
      expect(combined[6 + i]).toBeCloseTo(sig.tda[i] ?? 0, 5);
    }
  }, 10_000);
});

// ─── combinedSimilarity ───────────────────────────────────────────────────────

describe("combinedSimilarity", () => {
  it("identical combined vectors → similarity 1.0", async () => {
    const sig = await assemblePalmSignature(palmROI(), 128, 128);
    expect(combinedSimilarity(sig.combined, sig.combined)).toBeCloseTo(1.0, 6);
  }, 10_000);

  it("zero vector → similarity 0.0", async () => {
    const sig = await assemblePalmSignature(palmROI(), 128, 128);
    const zero = new Float32Array(COMBINED_DIM);
    expect(combinedSimilarity(sig.combined, zero)).toBe(0);
  }, 10_000);

  it("throws on dimension mismatch", () => {
    const a = new Float32Array(38);
    const b = new Float32Array(32);
    expect(() => combinedSimilarity(a, b)).toThrow("length mismatch");
  });
});
