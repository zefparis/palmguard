/**
 * PalmGuard — Browser-only pure math helpers
 * Extracted from palmguard.ts — no Node.js deps (no Buffer, no crypto built-in).
 * Used by the Vite demo bundle.
 */

/** Cosine similarity threshold for authentication decision. */
export const SIMILARITY_THRESHOLD = 0.97;

/**
 * Combined vector dimension:
 *   12 (fractal robust: D+Λ+ρ × 4 lines)
 * + 18 (Procrustes-stable phalange + palm arch angles)
 * + 12 (Hu moments × 4 quadrants)
 * + 32 (TDA H0/H1 persistence)
 * = 74 total
 */
export const COMBINED_DIM = 74;

/**
 * Build the 74-float combined biometric vector.
 * Layout: [fractal_robust(12) | angles(18) | hu_moments(12) | tda(32)]
 *
 * @param {import('../../fractal/boxcount').PalmBiometricVector} fractal
 * @param {Float32Array} tda           32-float TDA persistence vector
 * @param {Float32Array|null} angleVec 18 Procrustes-stable joint angles (or null → zeros)
 * @param {Float32Array|null} huVec    12 Hu moments × 4 quadrants      (or null → zeros)
 * @returns {Float32Array}
 */
export function buildCombinedVector(fractal, tda, angleVec = null, huVec = null) {
  const v = new Float32Array(COMBINED_DIM);
  const fv = fractal.featureVector ?? fractal.vector; // 12-float robust, fallback 6-float crypto
  for (let i = 0; i < Math.min(12, fv.length); i++) v[i]      = fv[i]       ?? 0;
  if (angleVec) for (let i = 0; i < 18; i++)         v[12 + i] = angleVec[i] ?? 0;
  if (huVec)    for (let i = 0; i < 12; i++)         v[30 + i] = huVec[i]    ?? 0;
  for (let i = 0; i < 32; i++)                        v[42 + i] = tda[i]      ?? 0;
  return v;
}

/**
 * Hybrid cosine + L2 similarity: 0.6 × cosine + 0.4 × 1/(1+L2).
 * More discriminative than cosine alone for high-dimensional biometric vectors.
 *
 * @param {Float32Array} a
 * @param {Float32Array} b
 * @returns {number} similarity ∈ [0, 1]
 */
export function combinedSimilarity(a, b) {
  if (a.length !== b.length) throw new RangeError("Combined vector length mismatch");
  let dot = 0, nA = 0, nB = 0, l2sq = 0;
  for (let i = 0; i < a.length; i++) {
    const ai = a[i] ?? 0, bi = b[i] ?? 0;
    dot  += ai * bi;
    nA   += ai ** 2;
    nB   += bi ** 2;
    l2sq += (ai - bi) ** 2;
  }
  if (nA === 0 || nB === 0) return 0;
  const cosine = dot / (Math.sqrt(nA) * Math.sqrt(nB));
  return 0.6 * cosine + 0.4 * (1 / (1 + Math.sqrt(l2sq)));
}
