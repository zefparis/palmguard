import { describe, it, expect } from "vitest";
import {
  computePersistence,
  diagramToVector,
  tdaVectorSimilarity,
  serializeTDAVector,
  deserializeTDAVector,
} from "../../src/topology/tda.js";
import type { Pixel } from "../../src/topology/skeleton.js";

// ─── Fixture builders ─────────────────────────────────────────────────────────

/** Simple square: 4 corners form a H1 loop. */
const squarePoints: Pixel[] = [
  { x: 0, y: 0 }, { x: 10, y: 0 },
  { x: 10, y: 10 }, { x: 0, y: 10 },
];

/** Triangle: 3 points form a H1 loop. */
const trianglePoints: Pixel[] = [
  { x: 0, y: 0 }, { x: 20, y: 0 }, { x: 10, y: 17 },
];

/** Line: no loops, one H0 component. */
const linePoints: Pixel[] = [
  { x: 0, y: 0 }, { x: 5, y: 0 }, { x: 10, y: 0 },
  { x: 15, y: 0 }, { x: 20, y: 0 },
];

/** Two isolated clusters → 2 H0 components. */
const twoClusterPoints: Pixel[] = [
  { x: 0, y: 0 }, { x: 1, y: 0 }, { x: 0, y: 1 },
  { x: 50, y: 50 }, { x: 51, y: 50 }, { x: 50, y: 51 },
];

/** Realistic palm intersections: ~12 nodes in a grid pattern. */
const palmLikePoints: Pixel[] = Array.from({ length: 12 }, (_, i) => ({
  x: (i % 4) * 30 + ((Math.floor(i / 4) % 2) * 10),
  y: Math.floor(i / 4) * 25,
}));

// ─── computePersistence ───────────────────────────────────────────────────────

describe("computePersistence — empty", () => {
  it("returns empty diagram for empty point cloud", () => {
    const d = computePersistence([]);
    expect(d.pairs).toHaveLength(0);
    expect(d.betti0).toBe(0);
    expect(d.betti1).toBe(0);
  });
});

describe("computePersistence — single point", () => {
  it("betti0=1, betti1=0", () => {
    const d = computePersistence([{ x: 0, y: 0 }]);
    expect(d.betti0).toBe(1);
    expect(d.betti1).toBe(0);
  });
});

describe("computePersistence — line (no loops)", () => {
  const d = computePersistence(linePoints);

  it("has exactly 1 surviving H0 component", () => {
    expect(d.betti0).toBe(1);
  });

  it("has at most 0 significant H1 loops", () => {
    expect(d.betti1).toBe(0);
  });

  it("all pairs have non-negative persistence", () => {
    for (const p of d.pairs) {
      if (p.death !== Infinity) {
        expect(p.persistence).toBeGreaterThanOrEqual(0);
      }
    }
  });
});

describe("computePersistence — two clusters", () => {
  const d = computePersistence(twoClusterPoints);

  it("has 1 surviving H0 component (all points merge in complete filtration)", () => {
    // In Vietoris-Rips at ε=∞, every connected graph has exactly 1 H0 survivor.
    // The two-cluster nature is encoded in the large finite H0 death value.
    expect(d.betti0).toBe(1);
  });

  it("H0 pairs include a large death value for inter-cluster edge (~70)", () => {
    const finiteH0 = d.pairs.filter((p) => p.dimension === 0 && p.death !== Infinity);
    const maxDeath = Math.max(...finiteH0.map((p) => p.death));
    expect(maxDeath).toBeGreaterThan(40); // inter-cluster Euclidean distance ≈ 70.7
  });
});

describe("computePersistence — triangle (H1 loop)", () => {
  const d = computePersistence(trianglePoints);

  it("has 1 surviving H0 component", () => {
    expect(d.betti0).toBe(1);
  });

  it("H0 has N-1 finite pairs (N=3)", () => {
    const finiteH0 = d.pairs.filter((p) => p.dimension === 0 && p.death !== Infinity);
    expect(finiteH0.length).toBe(2);
  });

  it("produces at least some persistence pairs", () => {
    expect(d.pairs.length).toBeGreaterThan(0);
  });
});

describe("computePersistence — square (4-cycle)", () => {
  const d = computePersistence(squarePoints);

  it("has 1 surviving H0 component", () => {
    expect(d.betti0).toBe(1);
  });

  it("has 3 finite H0 pairs (4 points merge to 1)", () => {
    const finiteH0 = d.pairs.filter((p) => p.dimension === 0 && p.death !== Infinity);
    expect(finiteH0.length).toBe(3);
  });

  it("all finite persistence values are positive", () => {
    for (const p of d.pairs.filter((p) => p.death !== Infinity)) {
      expect(p.persistence).toBeGreaterThan(0);
    }
  });
});

describe("computePersistence — palm-like intersection grid", () => {
  const d = computePersistence(palmLikePoints);

  it("returns pairs without crashing", () => {
    expect(Array.isArray(d.pairs)).toBe(true);
  });

  it("has exactly 1 surviving H0 component (connected grid)", () => {
    expect(d.betti0).toBe(1);
  });

  it("epsilons array is non-empty", () => {
    expect(d.epsilons.length).toBeGreaterThan(0);
  });
});

describe("computePersistence — stability (same input, same output)", () => {
  it("produces identical diagrams on repeated calls", () => {
    const d1 = computePersistence(palmLikePoints);
    const d2 = computePersistence(palmLikePoints);
    expect(d1.pairs.length).toBe(d2.pairs.length);
    expect(d1.betti0).toBe(d2.betti0);
    expect(d1.betti1).toBe(d2.betti1);
    for (let i = 0; i < d1.pairs.length; i++) {
      expect(d1.pairs[i]!.birth).toBeCloseTo(d2.pairs[i]!.birth, 10);
      expect(d1.pairs[i]!.dimension).toBe(d2.pairs[i]!.dimension);
    }
  });
});

describe("computePersistence — downsampling", () => {
  it("handles 100 points by downsampling to maxPts=64", () => {
    const large = Array.from({ length: 100 }, (_, i) => ({
      x: (i % 10) * 8,
      y: Math.floor(i / 10) * 8,
    }));
    expect(() => computePersistence(large, 64)).not.toThrow();
  });
});

// ─── diagramToVector ──────────────────────────────────────────────────────────

describe("diagramToVector", () => {
  it("always returns Float32Array of length 32", () => {
    for (const pts of [[], linePoints, squarePoints, palmLikePoints]) {
      const d = computePersistence(pts);
      const v = diagramToVector(d);
      expect(v.length).toBe(32);
      expect(v).toBeInstanceOf(Float32Array);
    }
  });

  it("all values are finite", () => {
    const d = computePersistence(palmLikePoints);
    const v = diagramToVector(d);
    expect([...v].every((x) => isFinite(x))).toBe(true);
  });

  it("all values are non-negative (persistence ≥ 0)", () => {
    const d = computePersistence(palmLikePoints);
    const v = diagramToVector(d);
    expect([...v].every((x) => x >= 0)).toBe(true);
  });

  it("empty diagram produces zero vector", () => {
    const d = computePersistence([]);
    const v = diagramToVector(d);
    expect([...v].every((x) => x === 0)).toBe(true);
  });

  it("same point cloud → same vector (deterministic)", () => {
    const v1 = diagramToVector(computePersistence(palmLikePoints));
    const v2 = diagramToVector(computePersistence(palmLikePoints));
    for (let i = 0; i < 32; i++) {
      expect(v1[i]).toBeCloseTo(v2[i]!, 6);
    }
  });

  it("different point clouds → different vectors", () => {
    const v1 = diagramToVector(computePersistence(linePoints));
    const v2 = diagramToVector(computePersistence(palmLikePoints));
    const diff = [...v1].reduce((a, x, i) => a + Math.abs(x - (v2[i] ?? 0)), 0);
    expect(diff).toBeGreaterThan(0.01);
  });
});

// ─── tdaVectorSimilarity ──────────────────────────────────────────────────────

describe("tdaVectorSimilarity", () => {
  it("identical vectors have similarity 1.0", () => {
    const v = diagramToVector(computePersistence(palmLikePoints));
    expect(tdaVectorSimilarity(v, v)).toBeCloseTo(1.0, 6);
  });

  it("same cloud captures similarity ≥ 0.99", () => {
    const v1 = diagramToVector(computePersistence(palmLikePoints));
    const v2 = diagramToVector(computePersistence(palmLikePoints));
    expect(tdaVectorSimilarity(v1, v2)).toBeGreaterThanOrEqual(0.99);
  });

  it("zero vector returns similarity 0", () => {
    const zero = new Float32Array(32);
    const v = diagramToVector(computePersistence(palmLikePoints));
    expect(tdaVectorSimilarity(zero, v)).toBe(0);
  });

  it("throws on length mismatch", () => {
    const a = new Float32Array(32);
    const b = new Float32Array(16);
    expect(() => tdaVectorSimilarity(a, b)).toThrow("length mismatch");
  });
});

// ─── serialize / deserialize ──────────────────────────────────────────────────

describe("serializeTDAVector / deserializeTDAVector", () => {
  const v = diagramToVector(computePersistence(palmLikePoints));

  it("serializes to exactly 128 bytes", () => {
    expect(serializeTDAVector(v).byteLength).toBe(128);
  });

  it("round-trips exactly", () => {
    const back = deserializeTDAVector(serializeTDAVector(v));
    for (let i = 0; i < 32; i++) {
      expect(back[i]).toBeCloseTo(v[i]!, 5);
    }
  });

  it("zero vector round-trips to zero", () => {
    const zero = new Float32Array(32);
    const back = deserializeTDAVector(serializeTDAVector(zero));
    expect([...back].every((x) => x === 0)).toBe(true);
  });

  it("throws on wrong byte length", () => {
    expect(() => deserializeTDAVector(new Uint8Array(64))).toThrow("Expected 128 bytes");
  });
});
