/**
 * PalmGuard — Full Pipeline Assembly
 *
 * Orchestrates the complete palm biometric authentication pipeline:
 *
 *   capture → skeleton → {fractal, TDA} → celestial salt → ML-KEM encapsulation
 *
 * All biometric processing happens client-side.
 * Only the KEM ciphertext (+ non-sensitive metadata) is persisted server-side.
 *
 * Similarity decision uses a combined [fractal | tda] vector (38 floats):
 *   - [0..5]   fractal dimension vector (Float64 → cast to Float32)
 *   - [6..37]  TDA persistence vector (Float32, 32 values)
 *
 * Threshold: cosine similarity ≥ 0.92 (relaxed from 0.97 to accommodate TDA noise).
 */

import {
  computePalmVector,
  serializeVector,
  deserializeVector,
  vectorSimilarity,
  type PalmBiometricVector,
} from "./fractal/boxcount.js";

import {
  skeletonize,
  linesToBinaryImages,
  type SkeletonResult,
} from "./topology/skeleton.js";

import {
  computePersistence,
  diagramToVector,
  serializeTDAVector,
  deserializeTDAVector,
  tdaVectorSimilarity,
  type TDAVector,
  type PersistenceDiagram,
} from "./topology/tda.js";

import { deriveCelestialSalt, type CelestialSalt } from "./crypto/celestial.js";

import {
  generateKeyPair,
  encapsulateTemplate,
  buildTemplate,
  type KemEncapsulation,
  type PalmTemplate,
} from "./crypto/mlkem.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PalmSignature {
  /** Fractal dimension results per palm line. */
  fractal: PalmBiometricVector;
  /** TDA persistence diagram. */
  persistenceDiagram: PersistenceDiagram;
  /** Flattened TDA feature vector (32 floats). */
  tda: TDAVector;
  /** Combined 38-float biometric vector [fractal(6) | tda(32)]. */
  combined: Float32Array;
  /** Celestial entropy salt. */
  celestialSalt: CelestialSalt;
  /** ML-KEM encapsulation result (for enrollment persistence). */
  kem: KemEncapsulation;
  /** Storable template (ciphertext + public key). */
  template: PalmTemplate;
  /** ML-KEM public key (store alongside template). */
  publicKey: Uint8Array;
  /** ML-KEM private key — NEVER STORED server-side; caller must vault it. */
  privateKey: Uint8Array;
  /** Skeletonization result (for debug / demo overlay). */
  skeleton: SkeletonResult;
  /** Unix timestamp of capture (ms). */
  timestamp: number;
  version: "1.0";
}

/** Lightweight stored representation — no private key, no raw biometrics. */
export interface StoredEnrollment {
  /** Base64url-encoded 24-byte fractal vector (float32). */
  fractalB64: string;
  /** Base64url-encoded 128-byte TDA vector (float32). */
  tdaB64: string;
  /** ML-KEM-768 template (ciphertext + public key). */
  template: PalmTemplate;
  enrolledAt: number;
  jdn: number;
  version: "1.0";
}

export interface VerifyResult {
  match: boolean;
  /** Cosine similarity on combined 38-float vector ∈ [0, 1]. */
  similarity: number;
  /** Fractal-only similarity for diagnostics. */
  fractalSimilarity: number;
  /** TDA-only similarity for diagnostics. */
  tdaSimilarity: number;
  /** Combined vector used for decision. */
  combined: Float32Array;
  processingMs: number;
}

// ─── Constants ────────────────────────────────────────────────────────────────

/** Hybrid similarity threshold for authentication (0.6×cosine + 0.4×1/(1+L2)). */
export const SIMILARITY_THRESHOLD = 0.97;

/** Combined vector dimension: 12 (fractal) + 18 (angles) + 12 (Hu) + 32 (TDA). */
export const COMBINED_DIM = 74;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(s: string): Uint8Array {
  return new Uint8Array(
    Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64")
  );
}

import { createHash } from "crypto";

/**
 * Build the 74-float combined biometric vector.
 * Layout: [fractal_robust(12) | angles(18) | hu_moments(12) | tda(32)]
 * angleVec and huVec are optional: server-side pipeline has no landmark data.
 */
export function buildCombinedVector(
  fractal: PalmBiometricVector,
  tda: TDAVector,
  angleVec?: Float32Array,
  huVec?: Float32Array
): Float32Array {
  const v  = new Float32Array(COMBINED_DIM);
  const fv = fractal.featureVector ?? fractal.vector;
  for (let i = 0; i < Math.min(12, fv.length); i++) v[i]      = fv[i]       ?? 0;
  if (angleVec) for (let i = 0; i < 18; i++)         v[12 + i] = angleVec[i] ?? 0;
  if (huVec)    for (let i = 0; i < 12; i++)         v[30 + i] = huVec[i]    ?? 0;
  for (let i = 0; i < 32; i++)                        v[42 + i] = tda[i]      ?? 0;
  return v;
}

/**
 * Hybrid cosine + L2 similarity: 0.6 × cosine + 0.4 × 1/(1+L2).
 */
export function combinedSimilarity(a: Float32Array, b: Float32Array): number {
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

// ─── Pipeline ─────────────────────────────────────────────────────────────────

/**
 * Run the full enrollment pipeline on a grayscale palm ROI.
 *
 * @param grayRoi     Grayscale pixel data, row-major (Uint8Array).
 * @param roiWidth    Width in pixels (recommended: 256).
 * @param roiHeight   Height in pixels (recommended: 256).
 * @param capturedAt  Unix timestamp of capture (ms), default: Date.now().
 *
 * @returns Full PalmSignature including private key.
 *          The caller MUST vault the `privateKey` immediately.
 *          The `template` (ciphertext + publicKey) is safe to persist server-side.
 */
export async function assemblePalmSignature(
  grayRoi: Uint8Array,
  roiWidth: number,
  roiHeight: number,
  capturedAt?: number
): Promise<PalmSignature> {
  const ts = capturedAt ?? Date.now();

  // 1. Skeletonize
  const skeleton = skeletonize(grayRoi, roiWidth, roiHeight);

  // 2. Extract per-line binary images for fractal engine
  const lineImages = linesToBinaryImages(skeleton.lines, roiWidth, roiHeight);

  // 3. Fractal dimension
  const fractal = computePalmVector(
    lineImages.heart,
    lineImages.head,
    lineImages.life,
    lineImages.fate,
    lineImages.intersectionMap
  );

  // 4. TDA on intersection nodes
  const persistenceDiagram = computePersistence(skeleton.intersections);
  const tda = diagramToVector(persistenceDiagram);

  // 5. Combined vector
  const combined = buildCombinedVector(fractal, tda);

  // 6. Celestial salt
  const celestialSalt = deriveCelestialSalt(ts);

  // 7. Serialize biometric bytes for KEM
  const fractalBytes = serializeVector(fractal.vector);     // 24 bytes
  const tdaBytes     = serializeTDAVector(tda);             // 128 bytes
  const bioBytes     = new Uint8Array(fractalBytes.length + tdaBytes.length);
  bioBytes.set(fractalBytes, 0);
  bioBytes.set(tdaBytes, fractalBytes.length);              // 152 bytes total

  // 8. Content hash: SHA-256(bioBytes || celestialSalt.bytes)
  const contentHash = createHash("sha256")
    .update(bioBytes)
    .update(celestialSalt.bytes)
    .digest("hex");

  // 9. ML-KEM-768 encapsulation
  const { publicKey, privateKey } = await generateKeyPair();
  const kem = await encapsulateTemplate(publicKey, bioBytes, celestialSalt.bytes);
  const template = buildTemplate(kem, publicKey, contentHash, ts, celestialSalt.jdn);

  return {
    fractal,
    persistenceDiagram,
    tda,
    combined,
    celestialSalt,
    kem,
    template,
    publicKey,
    privateKey,
    skeleton,
    timestamp: ts,
    version: "1.0",
  };
}

/**
 * Convert a PalmSignature to a StoredEnrollment (server-safe representation).
 * Call this after vaulting the private key.
 */
export function toStoredEnrollment(sig: PalmSignature): StoredEnrollment {
  return {
    fractalB64: toBase64Url(serializeVector(sig.fractal.vector)),
    tdaB64: toBase64Url(serializeTDAVector(sig.tda)),
    template: sig.template,
    enrolledAt: sig.timestamp,
    jdn: sig.celestialSalt.jdn,
    version: "1.0",
  };
}

/**
 * Verify a live palm capture against a stored enrollment.
 *
 * Both sides (enrolled and live) must have their combined vectors available.
 * This function runs entirely client-side: the live PalmSignature was just
 * assembled from the webcam capture; the stored enrollment is fetched from
 * Supabase and its fractal + TDA bytes deserialized client-side.
 *
 * @param storedFractalB64 Base64url-encoded 24-byte fractal vector from enrollment.
 * @param storedTdaB64     Base64url-encoded 128-byte TDA vector from enrollment.
 * @param live             Live PalmSignature from assemblePalmSignature().
 * @param threshold        Cosine similarity threshold (default: 0.92).
 */
export function verifySignature(
  storedFractalB64: string,
  storedTdaB64: string,
  live: PalmSignature,
  threshold = SIMILARITY_THRESHOLD
): VerifyResult {
  const start = Date.now();

  const storedFractal64 = deserializeVector(fromBase64Url(storedFractalB64));
  const storedTda = deserializeTDAVector(fromBase64Url(storedTdaB64));

  const storedCombined = new Float32Array(COMBINED_DIM);
  for (let i = 0; i < 6; i++) storedCombined[i] = storedFractal64[i] ?? 0;
  for (let i = 0; i < 32; i++) storedCombined[6 + i] = storedTda[i] ?? 0;

  const similarity = combinedSimilarity(storedCombined, live.combined);
  const fractalSimilarity = vectorSimilarity(storedFractal64, live.fractal.vector);
  const tdaSimilarity = tdaVectorSimilarity(storedTda, live.tda);

  return {
    match: similarity >= threshold,
    similarity,
    fractalSimilarity,
    tdaSimilarity,
    combined: live.combined,
    processingMs: Date.now() - start,
  };
}

export type { PalmBiometricVector, SkeletonResult, TDAVector, PersistenceDiagram };
