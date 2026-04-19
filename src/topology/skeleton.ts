/**
 * Skeletonization — Zhang-Suen Thinning + Connected-Component Line Extraction
 *
 * Converts a grayscale palm ROI into a 1-pixel-wide binary skeleton, then
 * extracts ordered line segments for the fractal engine and TDA pipeline.
 *
 * Processing pipeline:
 *   grayscale ROI → Gaussian blur (3×3) → adaptive Otsu threshold
 *   → Zhang-Suen iterative thinning → connected components → ordered lines
 *
 * Pure TypeScript, no native dependencies. Runs in Node.js and browser.
 *
 * Reference:
 *   Zhang T.Y., Suen C.Y. (1984). "A fast parallel algorithm for thinning
 *   digital patterns." Communications of the ACM 27(3):236-239.
 */

import type { BinaryImage } from "../fractal/boxcount.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface Pixel {
  x: number;
  y: number;
}

export interface LineSegment {
  /** Ordered pixel coordinates tracing the line. */
  points: Pixel[];
  /** Bounding box of this segment. */
  bbox: { minX: number; maxX: number; minY: number; maxY: number };
  /** Pixel length of the segment. */
  length: number;
}

export interface SkeletonResult {
  /** 1-pixel-wide binary skeleton (same dimensions as input). */
  skeleton: BinaryImage;
  /** All active skeleton pixels. */
  pixels: Pixel[];
  /** Connected-component line segments, sorted by length descending. */
  lines: LineSegment[];
  /** Intersection nodes: pixels with ≥ 3 skeleton neighbours. */
  intersections: Pixel[];
  /** Algorithm stats. */
  stats: { iterations: number; pixelsBefore: number; pixelsAfter: number };
}

// ─── 3×3 Gaussian blur (integer, σ ≈ 0.85) ───────────────────────────────────

const GAUSS3: readonly number[] = [1, 2, 1, 2, 4, 2, 1, 2, 1];
const GAUSS3_SUM = 16;

function gaussianBlur3(src: Uint8Array, w: number, h: number): Uint8Array {
  const dst = new Uint8Array(src); // copy source so border pixels retain original values
  for (let y = 1; y < h - 1; y++) {
    for (let x = 1; x < w - 1; x++) {
      let sum = 0;
      let ki = 0;
      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          sum += (src[(y + dy) * w + (x + dx)] ?? 0) * (GAUSS3[ki++] ?? 0);
        }
      }
      dst[y * w + x] = (sum / GAUSS3_SUM) | 0;
    }
  }
  return dst;
}

// ─── Otsu threshold ───────────────────────────────────────────────────────────

function otsuThreshold(src: Uint8Array): number {
  const hist = new Float64Array(256);
  for (const v of src) hist[v] = (hist[v] ?? 0) + 1;
  const total = src.length;

  let sumB = 0,
    wB = 0,
    best = 0,
    bestVar = 0;
  const sum = hist.reduce((a, v, i) => a + v * i, 0);

  for (let t = 0; t < 256; t++) {
    wB += hist[t] ?? 0;
    if (wB === 0) continue;
    const wF = total - wB;
    if (wF === 0) break;
    sumB += t * (hist[t] ?? 0);
    const mB = sumB / wB;
    const mF = (sum - sumB) / wF;
    const between = wB * wF * (mB - mF) ** 2;
    if (between > bestVar) {
      bestVar = between;
      best = t;
    }
  }
  return best;
}

// ─── Zhang-Suen thinning ──────────────────────────────────────────────────────

/** 8-neighbours in clockwise order starting from top: P2,P3,P4,P5,P6,P7,P8,P9 */
const DX = [0, 1, 1, 1, 0, -1, -1, -1];
const DY = [-1, -1, 0, 1, 1, 1, 0, -1];

function getNeighbours(img: Uint8Array, w: number, x: number, y: number): number[] {
  return DX.map((dx, i) => (img[(y + (DY[i] ?? 0)) * w + (x + dx)] ?? 0) > 0 ? 1 : 0);
}

function zeroOneTransitions(n: number[]): number {
  let count = 0;
  for (let i = 0; i < 8; i++) {
    if ((n[i] ?? 0) === 0 && (n[(i + 1) % 8] ?? 0) === 1) count++; // modulo always in [0,7]
  }
  return count;
}

function zhangSuenThin(src: Uint8Array, w: number, h: number, maxIter = 500): { img: Uint8Array; iters: number } {
  const img = new Uint8Array(src);
  const toDelete: number[] = [];
  let iters = 0;

  for (; iters < maxIter; iters++) {
    // Sub-iteration A
    toDelete.length = 0;
    for (let y = 1; y < h - 1; y++) {
      for (let x = 1; x < w - 1; x++) {
        if ((img[y * w + x] ?? 0) === 0) continue;
        const n = getNeighbours(img, w, x, y);
        const N = n.reduce((a, b) => a + b, 0);
        const T = zeroOneTransitions(n);
        if (N >= 2 && N <= 6 && T === 1 &&
            (n[0]! * n[2]! * n[4]!) === 0 &&
            (n[2]! * n[4]! * n[6]!) === 0) {
          toDelete.push(y * w + x);
        }
      }
    }
    toDelete.forEach((i) => { img[i] = 0; });
    const deletedA = toDelete.length;

    // Sub-iteration B
    toDelete.length = 0;
    for (let y = 1; y < h - 1; y++) {
      for (let x = 1; x < w - 1; x++) {
        if ((img[y * w + x] ?? 0) === 0) continue;
        const n = getNeighbours(img, w, x, y);
        const N = n.reduce((a, b) => a + b, 0);
        const T = zeroOneTransitions(n);
        if (N >= 2 && N <= 6 && T === 1 &&
            (n[0]! * n[2]! * n[6]!) === 0 &&
            (n[0]! * n[4]! * n[6]!) === 0) {
          toDelete.push(y * w + x);
        }
      }
    }
    toDelete.forEach((i) => { img[i] = 0; });

    if (deletedA === 0 && toDelete.length === 0) {
      iters++;
      break;
    }
  }

  return { img, iters };
}

// ─── Connected components (flood-fill) ───────────────────────────────────────

function findConnectedComponents(img: Uint8Array, w: number, h: number): Pixel[][] {
  const visited = new Uint8Array(w * h);
  const components: Pixel[][] = [];

  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const idx = y * w + x;
      if ((img[idx] ?? 0) === 0 || (visited[idx] ?? 0) !== 0) continue;

      const component: Pixel[] = [];
      const queue: number[] = [idx];
      visited[idx] = 1;

      while (queue.length > 0) {
        const cur = queue.pop()!;
        const cx = cur % w;
        const cy = (cur / w) | 0;
        component.push({ x: cx, y: cy });

        for (let di = 0; di < 8; di++) {
          const nx = cx + (DX[di] ?? 0);
          const ny = cy + (DY[di] ?? 0);
          if (nx < 0 || nx >= w || ny < 0 || ny >= h) continue;
          const ni = ny * w + nx;
          if ((img[ni] ?? 0) === 0 || (visited[ni] ?? 0) !== 0) continue;
          visited[ni] = 1;
          queue.push(ni);
        }
      }
      components.push(component);
    }
  }
  return components;
}

function pixelsToBbox(pts: Pixel[]): LineSegment["bbox"] {
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const { x, y } of pts) {
    if (x < minX) minX = x;
    if (x > maxX) maxX = x;
    if (y < minY) minY = y;
    if (y > maxY) maxY = y;
  }
  return { minX, maxX, minY, maxY };
}

// ─── Intersection detection ───────────────────────────────────────────────────

function findIntersections(img: Uint8Array, w: number, h: number): Pixel[] {
  const intersections: Pixel[] = [];
  for (let y = 1; y < h - 1; y++) {
    for (let x = 1; x < w - 1; x++) {
      if ((img[y * w + x] ?? 0) === 0) continue;
      const n = getNeighbours(img, w, x, y);
      if (n.reduce((a, b) => a + b, 0) >= 3) {
        intersections.push({ x, y });
      }
    }
  }
  return intersections;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Preprocess a raw grayscale image: blur → Otsu threshold.
 * Returns a binary Uint8Array (255 = foreground).
 */
export function preprocess(
  src: Uint8Array,
  width: number,
  height: number,
  blur = true
): Uint8Array {
  const blurred = blur ? gaussianBlur3(src, width, height) : src;
  const t = otsuThreshold(blurred);
  const bin = new Uint8Array(width * height);
  for (let i = 0; i < bin.length; i++) {
    bin[i] = (blurred[i] ?? 0) > t ? 0 : 255;
  }
  return bin;
}

/**
 * Extract a 1-pixel-wide skeleton from a binary palm ROI.
 *
 * The `raw` input should be a grayscale [0..255] image where dark pixels
 * (< threshold) represent palm lines.
 *
 * @param raw        Grayscale pixel data (Uint8Array, row-major).
 * @param width      Image width in pixels.
 * @param height     Image height in pixels.
 * @param minLineLen Minimum number of pixels for a segment to be kept (default: 20).
 * @param skipBlur   Skip Gaussian blur (use if input is already preprocessed).
 */
export function skeletonize(
  raw: Uint8Array,
  width: number,
  height: number,
  minLineLen = 20,
  skipBlur = false
): SkeletonResult {
  const pixelsBefore = raw.reduce((a, b) => a + (b > 0 ? 1 : 0), 0);

  // 1. Preprocess: blur + Otsu threshold
  const binary = preprocess(raw, width, height, !skipBlur);

  // 2. Zhang-Suen thinning
  const { img: thin, iters } = zhangSuenThin(binary, width, height);

  const pixelsAfter = thin.reduce((a, b) => a + (b > 0 ? 1 : 0), 0);

  // 3. Collect all skeleton pixels
  const pixels: Pixel[] = [];
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      if ((thin[y * width + x] ?? 0) > 0) pixels.push({ x, y });
    }
  }

  // 4. Connected components → line segments
  const components = findConnectedComponents(thin, width, height);
  const lines: LineSegment[] = components
    .filter((c) => c.length >= minLineLen)
    .map((c) => ({
      points: c,
      bbox: pixelsToBbox(c),
      length: c.length,
    }))
    .sort((a, b) => b.length - a.length);

  // 5. Intersection nodes (pixels with ≥ 3 neighbours in skeleton)
  const intersections = findIntersections(thin, width, height);

  const skeleton: BinaryImage = { data: thin, width, height };

  return { skeleton, pixels, lines, intersections, stats: { iterations: iters, pixelsBefore, pixelsAfter } };
}

/**
 * Convert skeleton line segments to BinaryImage per-line (for boxCountDimension).
 * Assigns the 4 longest segments to heart/head/life/fate by convention.
 * Shorter segments and isolated points are discarded.
 */
export function linesToBinaryImages(
  lines: LineSegment[],
  width: number,
  height: number
): {
  heart: BinaryImage;
  head: BinaryImage;
  life: BinaryImage;
  fate: BinaryImage;
  intersectionMap: BinaryImage;
} {
  function makeImg(pts: Pixel[]): BinaryImage {
    const data = new Uint8Array(width * height);
    for (const { x, y } of pts) data[y * width + x] = 255;
    return { data, width, height };
  }

  const empty = makeImg([]);

  return {
    heart:  lines[0] ? makeImg(lines[0].points) : empty,
    head:   lines[1] ? makeImg(lines[1].points) : empty,
    life:   lines[2] ? makeImg(lines[2].points) : empty,
    fate:   lines[3] ? makeImg(lines[3].points) : empty,
    intersectionMap: empty, // caller overlays intersections if needed
  };
}
