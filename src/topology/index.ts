/**
 * Topology module — Persistent Homology via Ripser (TDA).
 *
 * Models palm line intersections as a Vietoris-Rips simplicial complex.
 * Ripser computes the persistence diagram (birth/death pairs) for H0 and H1.
 * The resulting barcode encodes the topological fingerprint of the palm:
 *   - H0: connected components (number of distinct line segments)
 *   - H1: loops / cycles at the intersections
 *
 * Invariant to: rotation, scale (up to ±20%), lighting, minor deformations.
 *
 * Scientific reference:
 *   Reininghaus J. et al. (2015). "A Stable Multi-Scale Kernel for Topological
 *   Machine Learning." CVPR. doi:10.1109/CVPR.2015.7299106
 *
 * Implementation note:
 *   Ripser.js is loaded as a WASM module (see public/ripser.wasm).
 *   Until the WASM binding is finalized, this module is a typed stub.
 */

import type { PalmLineSet } from "../capture/types.js";

/** A single persistence pair (birth, death) in filtration value space. */
export interface PersistencePair {
  birth: number;
  death: number;
  /** Persistence = death − birth. Higher = more topologically significant. */
  persistence: number;
  /** Homology dimension: 0 = components, 1 = loops. */
  dimension: 0 | 1;
}

/** Full persistence diagram for one palm capture. */
export interface PersistenceDiagram {
  pairs: PersistencePair[];
  /** Betti-0: number of connected components at filtration ε = 0. */
  betti0: number;
  /** Betti-1: number of independent loops. */
  betti1: number;
}

/**
 * Compact TDA fingerprint: 8-scalar vector derived from the persistence diagram.
 * Layout:
 *   [mean_H0, std_H0, max_H0, sum_H0, mean_H1, std_H1, max_H1, betti1]
 */
export type TDAVector = Float64Array;

/**
 * Build point cloud from palm line intersections and compute persistence diagram.
 *
 * @todo Integrate Ripser.js WASM binding.
 */
export async function computePersistenceDiagram(
  _lines: PalmLineSet
): Promise<PersistenceDiagram> {
  throw new Error("topology.computePersistenceDiagram: not yet implemented — awaiting Ripser.js WASM binding");
}

/**
 * Derive a compact 8-scalar TDA vector from a persistence diagram.
 * Suitable for cosine similarity matching and ML-KEM encapsulation.
 */
export function diagramToVector(_diagram: PersistenceDiagram): TDAVector {
  throw new Error("topology.diagramToVector: not yet implemented");
}

/**
 * Wasserstein distance between two persistence diagrams.
 * Used for template matching (enrollment vs probe).
 *
 * @returns distance ∈ [0, ∞). Empirical threshold for same individual: < 0.05.
 */
export function wassersteinDistance(
  _a: PersistenceDiagram,
  _b: PersistenceDiagram
): number {
  throw new Error("topology.wassersteinDistance: not yet implemented");
}
