/**
 * PalmGuard DB layer — shared interfaces.
 * Consumed by palm.repository.ts and tests (mock implementations).
 */

export interface EnrollRecord {
  tenantId:          string;
  userId:            string;
  contentHash:       string;
  enrollmentId:      string;
  templateCiphertext: Uint8Array;
  publicKey:         Uint8Array;
  kemPrivkeyEnc:     Uint8Array;  // AES-256-GCM encrypted ML-KEM private key
  kekIv:             Uint8Array;  // 12-byte AES-GCM IV
  capturedAt:        number;      // unix ms
  celestialJdn:      number;
  templateVersion:   string;
  captureConfidence?: number;
  biometricVector?:  number[];  // Float32[74] from Python biometric engine
  vectorVersion?:    string;    // 'python-v1' for Python pipeline enrollments
}

export type AuditEventType =
  | "ENROLL"
  | "VERIFY_MATCH"
  | "VERIFY_NO_MATCH"
  | "ENROLL_REVOKED"
  | "ENROLL_DELETED"
  | "RATE_LIMIT_EXCEEDED"
  | "ERROR";

export interface AuditEntry {
  tenantId:   string;
  userId:     string;
  eventType:  AuditEventType;
  ipHash:     string;
  auditToken?: string;
  metadata?:  Record<string, unknown>;
}

export interface PalmRepository {
  enroll(record: EnrollRecord): Promise<void>;
  findEnrollment(tenantId: string, userId: string): Promise<EnrollRecord | null>;
  deleteEnrollment(tenantId: string, userId: string): Promise<void>;
  appendAuditLog(entry: AuditEntry): Promise<void>;
  ping(): Promise<boolean>;
}
