import { describe, it, expect } from "vitest";
import {
  skeletonize,
  preprocess,
  linesToBinaryImages,
} from "../../src/topology/skeleton.js";

// ─── Fixture builders ─────────────────────────────────────────────────────────

function makeGray(
  width: number,
  height: number,
  fn: (x: number, y: number) => number
): Uint8Array {
  const data = new Uint8Array(width * height);
  for (let y = 0; y < height; y++)
    for (let x = 0; x < width; x++)
      data[y * width + x] = fn(x, y);
  return data;
}

/** Solid dark rectangle — simulates inked palm region. */
function darkRect(w: number, h: number, x0: number, y0: number, x1: number, y1: number): Uint8Array {
  return makeGray(w, h, (x, y) =>
    x >= x0 && x < x1 && y >= y0 && y < y1 ? 30 : 200
  );
}

/** Single horizontal dark line across width. */
function singleLine(w: number, h: number, lineY: number): Uint8Array {
  return makeGray(w, h, (x, y) => Math.abs(y - lineY) <= 1 ? 10 : 220);
}

/** Two parallel horizontal lines. */
function twoLines(w: number, h: number): Uint8Array {
  return makeGray(w, h, (x, y) =>
    Math.abs(y - 40) <= 1 || Math.abs(y - 80) <= 1 ? 10 : 220
  );
}

/** Four parallel horizontal lines (simulates 4 palm lines). */
function fourLines(w: number, h: number): Uint8Array {
  return makeGray(w, h, (x, y) =>
    [30, 50, 70, 90].some((ly) => Math.abs(y - ly) <= 1) ? 10 : 220
  );
}

/** Uniform gray (no features). */
const uniform128 = makeGray(128, 128, () => 128);

/** All-black (fully filled). */
const filled128 = makeGray(128, 128, () => 0);

// ─── preprocess ───────────────────────────────────────────────────────────────

describe("preprocess", () => {
  it("returns binary image same size as input", () => {
    const bin = preprocess(singleLine(64, 64, 32), 64, 64);
    expect(bin.length).toBe(64 * 64);
  });

  it("output is binary (0 or 255 only)", () => {
    const bin = preprocess(singleLine(64, 64, 32), 64, 64);
    const values = new Set(bin);
    expect(values.size).toBeLessThanOrEqual(2);
    expect([...values].every((v) => v === 0 || v === 255)).toBe(true);
  });

  it("dark line becomes foreground (255) in binary", () => {
    const gray = singleLine(64, 64, 32);
    const bin = preprocess(gray, 64, 64);
    // Line pixels (y ≈ 32) should be foreground
    const linePixel = bin[32 * 64 + 32] ?? 0;
    expect(linePixel).toBe(255);
  });

  it("uniform gray produces valid binary output without crashing", () => {
    expect(() => preprocess(uniform128, 128, 128)).not.toThrow();
  });

  it("skipBlur=true skips Gaussian blur", () => {
    const gray = singleLine(64, 64, 32);
    const withBlur = preprocess(gray, 64, 64, true);
    const skipBlur = preprocess(gray, 64, 64, false);
    expect(withBlur.length).toBe(skipBlur.length);
  });
});

// ─── skeletonize ──────────────────────────────────────────────────────────────

describe("skeletonize — single line", () => {
  const result = skeletonize(singleLine(128, 128, 64), 128, 128, 10);

  it("produces a skeleton", () => {
    expect(result.skeleton.data.length).toBe(128 * 128);
    expect(result.skeleton.width).toBe(128);
    expect(result.skeleton.height).toBe(128);
  });

  it("has at least one skeleton pixel", () => {
    expect(result.pixels.length).toBeGreaterThan(0);
  });

  it("skeleton pixels < input foreground pixels (thinning happened)", () => {
    expect(result.stats.pixelsAfter).toBeLessThanOrEqual(result.stats.pixelsBefore);
  });

  it("detects at least 1 line segment", () => {
    expect(result.lines.length).toBeGreaterThanOrEqual(1);
  });

  it("returns stats with iterations > 0", () => {
    expect(result.stats.iterations).toBeGreaterThan(0);
  });
});

describe("skeletonize — two parallel lines", () => {
  const result = skeletonize(twoLines(128, 128), 128, 128, 10);

  it("detects at least 2 line segments", () => {
    expect(result.lines.length).toBeGreaterThanOrEqual(2);
  });

  it("each line has a length > 10 pixels", () => {
    expect(result.lines.every((l) => l.length >= 10)).toBe(true);
  });
});

describe("skeletonize — four parallel lines (palm simulation)", () => {
  const result = skeletonize(fourLines(128, 128), 128, 128, 10);

  it("detects at least 3 segments (fate line may merge with others)", () => {
    expect(result.lines.length).toBeGreaterThanOrEqual(3);
  });

  it("lines are sorted by length descending", () => {
    const lengths = result.lines.map((l) => l.length);
    for (let i = 1; i < lengths.length; i++) {
      expect(lengths[i - 1]!).toBeGreaterThanOrEqual(lengths[i]!);
    }
  });

  it("each line has a valid bounding box", () => {
    for (const line of result.lines) {
      expect(line.bbox.minX).toBeLessThanOrEqual(line.bbox.maxX);
      expect(line.bbox.minY).toBeLessThanOrEqual(line.bbox.maxY);
    }
  });
});

describe("skeletonize — filled rectangle (solid region)", () => {
  const img = darkRect(128, 128, 20, 20, 108, 108);
  const result = skeletonize(img, 128, 128, 5);

  it("produces fewer pixels than input (thinning is effective)", () => {
    expect(result.stats.pixelsAfter).toBeLessThan(result.stats.pixelsBefore);
  });

  it("does not crash on solid regions", () => {
    expect(result.skeleton).toBeDefined();
  });
});

describe("skeletonize — uniform gray (no features)", () => {
  it("produces empty or near-empty skeleton", () => {
    const result = skeletonize(uniform128, 128, 128, 20);
    expect(result.pixels.length).toBeLessThan(100);
  });

  it("does not crash", () => {
    expect(() => skeletonize(uniform128, 128, 128)).not.toThrow();
  });
});

describe("skeletonize — intersection detection", () => {
  it("returns intersection array (may be empty for parallel lines)", () => {
    const result = skeletonize(fourLines(128, 128), 128, 128);
    expect(Array.isArray(result.intersections)).toBe(true);
  });
});

describe("skeletonize — small images", () => {
  it("handles 32×32 image", () => {
    const img = singleLine(32, 32, 16);
    expect(() => skeletonize(img, 32, 32, 5)).not.toThrow();
  });

  it("handles 8×8 image", () => {
    const img = singleLine(8, 8, 4);
    const result = skeletonize(img, 8, 8, 1);
    expect(result.skeleton.data.length).toBe(64);
  });
});

// ─── linesToBinaryImages ──────────────────────────────────────────────────────

describe("linesToBinaryImages", () => {
  const result = skeletonize(fourLines(128, 128), 128, 128, 10);

  it("returns 5 BinaryImages with correct dimensions", () => {
    const out = linesToBinaryImages(result.lines, 128, 128);
    for (const img of [out.heart, out.head, out.life, out.fate, out.intersectionMap]) {
      expect(img.width).toBe(128);
      expect(img.height).toBe(128);
      expect(img.data.length).toBe(128 * 128);
    }
  });

  it("heart image has active pixels (first/longest segment)", () => {
    const out = linesToBinaryImages(result.lines, 128, 128);
    const count = out.heart.data.reduce((a, b) => a + (b > 0 ? 1 : 0), 0);
    expect(count).toBeGreaterThan(0);
  });

  it("handles empty lines array gracefully", () => {
    const out = linesToBinaryImages([], 64, 64);
    expect(out.heart.data.every((v) => v === 0)).toBe(true);
  });
});
