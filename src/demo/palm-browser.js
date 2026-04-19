/**
 * PalmGuard — Browser-only pure math helpers
 * Extracted from palmguard.ts — no Node.js deps (no Buffer, no crypto built-in).
 * Used by the Vite demo bundle.
 */

/** Cosine similarity threshold for authentication decision. */
export const SIMILARITY_THRESHOLD = 0.92;

/** Combined vector dimension: 6 (fractal) + 32 (TDA) + 12 (geometry). */
export const COMBINED_DIM = 50;
export const GEO_DIM = 12;

/**
 * Build the 50-float combined biometric vector.
 * @param {import('../../fractal/boxcount').PalmBiometricVector} fractal
 * @param {Float32Array} tda
 * @param {Float32Array|null} geoVec  12 normalised inter-landmark distances (or null → zeros)
 * @returns {Float32Array}
 */
export function buildCombinedVector(fractal, tda, geoVec = null) {
  const v = new Float32Array(COMBINED_DIM);
  for (let i = 0; i < 6;        i++) v[i]      = fractal.vector[i] ?? 0;
  for (let i = 0; i < 32;       i++) v[6  + i] = tda[i]            ?? 0;
  if (geoVec) {
    for (let i = 0; i < GEO_DIM; i++) v[38 + i] = geoVec[i]        ?? 0;
  }
  return v;
}

/**
 * Cosine similarity between two Float32Arrays.
 * @param {Float32Array} a
 * @param {Float32Array} b
 * @returns {number}
 */
export function combinedSimilarity(a, b) {
  if (a.length !== b.length) throw new RangeError("Combined vector length mismatch");
  let dot = 0, nA = 0, nB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += (a[i] ?? 0) * (b[i] ?? 0);
    nA  += (a[i] ?? 0) ** 2;
    nB  += (b[i] ?? 0) ** 2;
  }
  if (nA === 0 || nB === 0) return 0;
  return dot / (Math.sqrt(nA) * Math.sqrt(nB));
}
