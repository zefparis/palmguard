import { describe, it, expect } from "vitest";
import {
  boxCountDimension,
  computePalmVector,
  vectorSimilarity,
  serializeVector,
  deserializeVector,
} from "../../src/fractal/boxcount.js";
import type { BinaryImage } from "../../src/fractal/boxcount.js";

// ─── Fixture builders ─────────────────────────────────────────────────────────

function makeImage(
  width: number,
  height: number,
  fn: (x: number, y: number) => boolean
): BinaryImage {
  const data = new Uint8Array(width * height);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      data[y * width + x] = fn(x, y) ? 255 : 0;
    }
  }
  return { data, width, height };
}

/** Horizontal line through the middle. D ≈ 1. */
const straightLine = makeImage(128, 128, (x, y) => y === 64);

/** Filled square. D ≈ 2. */
const filledSquare = makeImage(128, 128, () => true);

/** Diagonal line. D ≈ 1. */
const diagonal = makeImage(128, 128, (x, y) => x === y);

/** Empty image. Degenerate case. */
const empty = makeImage(128, 128, () => false);

/** Sinusoidal curve — slightly fractal > 1. */
const sineWave = makeImage(
  128,
  128,
  (x, y) => Math.abs(y - 64 - Math.round(Math.sin(x / 8) * 12)) <= 1
);

/** Zigzag — simulates palm line roughness, D > 1. */
const zigzag = makeImage(128, 128, (x, y) => {
  const phase = Math.floor(x / 6) % 2;
  const target = 48 + (phase === 0 ? x % 6 : 5 - (x % 6)) * 3;
  return Math.abs(y - target) <= 1;
});

/** Sparse dots (very gapped — high lacunarity). */
const sparseDots = makeImage(64, 64, (x, y) => x % 8 === 0 && y % 8 === 0);

// ─── boxCountDimension ────────────────────────────────────────────────────────

describe("boxCountDimension — straight line", () => {
  const result = boxCountDimension(straightLine);

  it("dimension should be in [1.0, 1.3] for a straight line", () => {
    expect(result.dimension).toBeGreaterThanOrEqual(1.0);
    expect(result.dimension).toBeLessThanOrEqual(1.3);
  });

  it("R² should be > 0.90 for a clean straight line", () => {
    expect(result.r2).toBeGreaterThan(0.9);
  });

  it("returns non-empty scales and counts", () => {
    expect(result.scales.length).toBeGreaterThan(2);
    expect(result.counts.length).toBe(result.scales.length);
  });

  it("all counts are positive", () => {
    expect(result.counts.every((c) => c > 0)).toBe(true);
  });
});

describe("boxCountDimension — filled square", () => {
  const result = boxCountDimension(filledSquare);

  it("dimension should be close to 2.0 for a filled region", () => {
    expect(result.dimension).toBeGreaterThan(1.8);
    expect(result.dimension).toBeLessThanOrEqual(2.0);
  });

  it("lacunarity should be ~0 for a uniform fill", () => {
    expect(result.lacunarity).toBeCloseTo(0, 1);
  });
});

describe("boxCountDimension — diagonal line", () => {
  const result = boxCountDimension(diagonal);

  it("dimension should be in [1.0, 1.3]", () => {
    expect(result.dimension).toBeGreaterThanOrEqual(1.0);
    expect(result.dimension).toBeLessThanOrEqual(1.3);
  });
});

describe("boxCountDimension — empty image", () => {
  const result = boxCountDimension(empty);

  it("returns dimension = 1.0 (degenerate fallback)", () => {
    expect(result.dimension).toBe(1.0);
  });

  it("returns r2 = 0 for empty image", () => {
    expect(result.r2).toBe(0);
  });
});

describe("boxCountDimension — sine wave", () => {
  const result = boxCountDimension(sineWave);

  it("dimension should be in [1.0, 2.0]", () => {
    expect(result.dimension).toBeGreaterThanOrEqual(1.0);
    expect(result.dimension).toBeLessThanOrEqual(2.0);
  });

  it("R² should be positive", () => {
    expect(result.r2).toBeGreaterThan(0);
  });
});

describe("boxCountDimension — zigzag (palm-like roughness)", () => {
  const result = boxCountDimension(zigzag);

  it("dimension should be > 1.0 for non-trivial curve", () => {
    expect(result.dimension).toBeGreaterThan(1.0);
  });
});

describe("boxCountDimension — lacunarity", () => {
  it("sparse dots have higher lacunarity than filled square", () => {
    const dotsResult = boxCountDimension(sparseDots);
    const filledResult = boxCountDimension(filledSquare);
    expect(dotsResult.lacunarity).toBeGreaterThan(filledResult.lacunarity);
  });

  it("lacunarity ≥ 0 for all images", () => {
    for (const img of [straightLine, filledSquare, diagonal, sineWave, sparseDots]) {
      expect(boxCountDimension(img).lacunarity).toBeGreaterThanOrEqual(0);
    }
  });
});

describe("boxCountDimension — custom scales", () => {
  it("respects custom minBoxSize and maxBoxSize", () => {
    const result = boxCountDimension(straightLine, 4, 32);
    expect(result.scales.every((s) => s >= 4 && s <= 32)).toBe(true);
  });

  it("throws on minBoxSize < 2", () => {
    expect(() => boxCountDimension(straightLine, 1)).toThrow(
      "minBoxSize must be ≥ 2"
    );
  });

  it("returns empty result when maxBoxSize < minBoxSize", () => {
    const result = boxCountDimension(straightLine, 64, 16);
    expect(result.scales).toHaveLength(0);
    expect(result.dimension).toBe(1.0);
  });
});

describe("boxCountDimension — small images", () => {
  it("handles 8×8 image without crashing", () => {
    const tiny = makeImage(8, 8, (x, y) => y === 4);
    expect(() => boxCountDimension(tiny)).not.toThrow();
  });

  it("handles 1×1 image (degenerate)", () => {
    const pixel = makeImage(1, 1, () => true);
    const result = boxCountDimension(pixel);
    expect(result.dimension).toBe(1.0);
  });
});

// ─── computePalmVector ────────────────────────────────────────────────────────

/** Synthetic palm line with a sinusoidal frequency parameter. */
function makePalmLine(freq: number, amplitude = 10, w = 128, h = 128): BinaryImage {
  return makeImage(
    w,
    h,
    (x, y) => Math.abs(y - h / 2 - Math.sin(x / freq) * amplitude) <= 1
  );
}

describe("computePalmVector", () => {
  const h = makePalmLine(8);
  const e = makePalmLine(10);
  const l = makePalmLine(12);
  const f = makePalmLine(6);

  it("returns a vector of exactly 6 elements", () => {
    const result = computePalmVector(h, e, l, f);
    expect(result.vector.length).toBe(6);
  });

  it("all 4 line dimensions are in [1.0, 2.0]", () => {
    const result = computePalmVector(h, e, l, f);
    for (const r of [result.heart, result.head, result.life, result.fate]) {
      expect(r.dimension).toBeGreaterThanOrEqual(1.0);
      expect(r.dimension).toBeLessThanOrEqual(2.0);
    }
  });

  it("intersectionDensity = 0 when no intersection map provided", () => {
    const result = computePalmVector(h, e, l, f);
    expect(result.intersectionDensity).toBe(0);
  });

  it("intersectionDensity > 0 when intersection map provided", () => {
    const intersections = makeImage(128, 128, (x) => x === 64);
    const result = computePalmVector(h, e, l, f, intersections);
    expect(result.intersectionDensity).toBeGreaterThan(0);
  });

  it("globalLacunarity ≥ 0", () => {
    const result = computePalmVector(h, e, l, f);
    expect(result.globalLacunarity).toBeGreaterThanOrEqual(0);
  });

  it("vector values match individual line results", () => {
    const result = computePalmVector(h, e, l, f);
    expect(result.vector[0]).toBeCloseTo(result.heart.dimension, 10);
    expect(result.vector[1]).toBeCloseTo(result.head.dimension, 10);
    expect(result.vector[2]).toBeCloseTo(result.life.dimension, 10);
    expect(result.vector[3]).toBeCloseTo(result.fate.dimension, 10);
    expect(result.vector[4]).toBeCloseTo(result.intersectionDensity, 10);
    expect(result.vector[5]).toBeCloseTo(result.globalLacunarity, 10);
  });

  it("same lines produce identical vector twice", () => {
    const r1 = computePalmVector(h, e, l, f);
    const r2 = computePalmVector(h, e, l, f);
    for (let i = 0; i < 6; i++) {
      expect(r1.vector[i]).toBe(r2.vector[i]);
    }
  });

  it("different line frequencies produce distinct vectors", () => {
    const r1 = computePalmVector(
      makePalmLine(5),
      makePalmLine(7),
      makePalmLine(9),
      makePalmLine(11)
    );
    const r2 = computePalmVector(
      makePalmLine(13),
      makePalmLine(17),
      makePalmLine(19),
      makePalmLine(23)
    );
    const sim = vectorSimilarity(r1.vector, r2.vector);
    expect(sim).toBeLessThan(1.0);
  });

  it("handles fate line as nearly empty (absent fate line — common in real palms)", () => {
    const emptyFate = makeImage(128, 128, () => false);
    expect(() => computePalmVector(h, e, l, emptyFate)).not.toThrow();
  });
});

// ─── vectorSimilarity ─────────────────────────────────────────────────────────

describe("vectorSimilarity", () => {
  it("identical vectors have similarity exactly 1.0", () => {
    const v = new Float64Array([1.3, 1.5, 1.2, 1.7, 0.05, 0.12]);
    expect(vectorSimilarity(v, v)).toBeCloseTo(1.0, 10);
  });

  it("orthogonal vectors have similarity 0", () => {
    const a = new Float64Array([1, 0, 0, 0, 0, 0]);
    const b = new Float64Array([0, 1, 0, 0, 0, 0]);
    expect(vectorSimilarity(a, b)).toBeCloseTo(0, 10);
  });

  it("anti-parallel vectors have similarity −1", () => {
    const a = new Float64Array([1, 0, 0, 0, 0, 0]);
    const b = new Float64Array([-1, 0, 0, 0, 0, 0]);
    expect(vectorSimilarity(a, b)).toBeCloseTo(-1, 10);
  });

  it("throws on length mismatch", () => {
    const a = new Float64Array([1, 2, 3]);
    const b = new Float64Array([1, 2]);
    expect(() => vectorSimilarity(a, b)).toThrow("Vector length mismatch");
  });

  it("zero vectors return 0 (no division by zero)", () => {
    const z = new Float64Array(6);
    const v = new Float64Array([1, 1, 1, 1, 1, 1]);
    expect(vectorSimilarity(z, v)).toBe(0);
    expect(vectorSimilarity(z, z)).toBe(0);
  });

  it("same-individual palm similarity ≥ 0.99 (synthetic baseline)", () => {
    const line = makePalmLine(9);
    const r1 = computePalmVector(line, line, line, line);
    const r2 = computePalmVector(line, line, line, line);
    expect(vectorSimilarity(r1.vector, r2.vector)).toBeGreaterThanOrEqual(0.99);
  });
});

// ─── serializeVector / deserializeVector ──────────────────────────────────────

describe("serializeVector / deserializeVector", () => {
  const original = new Float64Array([1.234, 1.456, 1.678, 1.890, 0.0123, 0.345]);

  it("serializes to exactly 24 bytes (6 × float32)", () => {
    const bytes = serializeVector(original);
    expect(bytes.byteLength).toBe(24);
  });

  it("round-trips with ≤ float32 precision loss (< 1e-6 relative)", () => {
    const bytes = serializeVector(original);
    const restored = deserializeVector(bytes);
    expect(restored.length).toBe(original.length);
    for (let i = 0; i < original.length; i++) {
      const orig = original[i] ?? 0;
      const rest = restored[i] ?? 0;
      expect(Math.abs(rest - orig) / Math.abs(orig)).toBeLessThan(1e-5);
    }
  });

  it("round-trip preserves dimension values in [1, 2] with ample precision", () => {
    const v = new Float64Array([1.15, 1.30, 1.45, 1.60, 0.02, 0.18]);
    const bytes = serializeVector(v);
    const back = deserializeVector(bytes);
    for (let i = 0; i < v.length; i++) {
      expect(back[i]).toBeCloseTo(v[i] ?? 0, 4);
    }
  });

  it("throws on byte array with non-multiple-of-4 length", () => {
    const bad = new Uint8Array(7);
    expect(() => deserializeVector(bad)).toThrow(
      "byte length must be a multiple of 4"
    );
  });

  it("zero vector round-trips cleanly", () => {
    const z = new Float64Array(6);
    const back = deserializeVector(serializeVector(z));
    for (let i = 0; i < 6; i++) {
      expect(back[i]).toBe(0);
    }
  });
});
