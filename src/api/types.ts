/**
 * PalmGuard API — shared request/response types.
 * Compatible with hcs-u7-backend auth pipeline conventions.
 */

/** POST /api/palm/enroll — request body */
export interface EnrollRequest {
  /** Tenant ID from HCS-U7 JWT. */
  tenantId: string;
  /** User identifier within tenant scope. */
  userId: string;
  /** Base64 JPEG/PNG image of the palm for server-side biometric extraction. */
  image_b64: string;
  /**
   * Base64url-encoded serialized palm biometric vector (24 bytes).
   * Legacy field — kept for backward compatibility; optional when image_b64 is provided.
   */
  palmVectorB64?: string;
  /** Unix timestamp of capture (ms). Used to derive celestial salt. */
  capturedAt: number;
  /** MediaPipe confidence score [0, 1] of the best frame used. */
  confidence: number;
  /** Device fingerprint for audit log (non-biometric). */
  deviceId?: string;
}

/** POST /api/palm/enroll — response */
export interface EnrollResponse {
  success: true;
  enrollmentId: string;
  enrolledAt: number;
  /** Template version for future migration compatibility. */
  templateVersion: "1.0";
}

/** POST /api/palm/verify — request body */
export interface VerifyRequest {
  tenantId: string;
  userId: string;
  /** Base64 JPEG/PNG image of the palm for server-side biometric extraction. */
  image_b64: string;
  /** Legacy field — used as fallback when enrollment has no biometricVector. */
  palmVectorB64?: string;
  capturedAt: number;
  confidence: number;
  deviceId?: string;
}

/** POST /api/palm/verify — response */
export interface VerifyResponse {
  /** Whether the probe matches the enrolled template. */
  match: boolean;
  /** Cosine similarity score ∈ [0, 1]. */
  similarity: number;
  /** Time taken server-side (ms). Constant-time enforced: always ≥ 150ms. */
  processingMs: number;
  /** ANSSI audit token — opaque, for correlation with audit log. */
  auditToken: string;
}

/** Standard error envelope. */
export interface ApiError {
  success: false;
  code: string;
  message: string;
}

export type ApiResponse<T> = T | ApiError;

/** GET /api/palm/enroll/:userId — response */
export interface EnrollStatusResponse {
  enrolled: boolean;
  enrolledAt?: string;
}

/** DELETE /api/palm/enroll/:userId — response */
export interface DeleteEnrollResponse {
  deleted: true;
  userId: string;
  timestamp: number;
}

/** Rate-limit error extension. */
export interface RateLimitError extends ApiError {
  code: "RATE_LIMIT_EXCEEDED";
  retryAfterSecs: number;
}

/** Phase 4 health check response. */
export interface HealthCheckResponse {
  status: "ok";
  version: string;
  checks: {
    supabase:    "ok" | "degraded";
    rateLimiter: "memory" | "supabase";
    jwtMode:     "hs256";
  };
  uptime: number;
}

/** Palm enrollment record — maps to Supabase `palm_enrollments` table. */
export interface PalmEnrollment {
  id: string;
  tenantId: string;
  userId: string;
  /** Base64url ML-KEM-768 ciphertext. */
  templateCiphertext: string;
  /** Base64url ML-KEM-768 public key. */
  publicKey: string;
  contentHash: string;
  enrolledAt: Date;
  jdn: number;
  templateVersion: string;
  isActive: boolean;
}
