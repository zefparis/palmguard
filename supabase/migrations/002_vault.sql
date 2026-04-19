-- PalmGuard Migration 002 — Vault Columns + Audit Log Expansion
-- Additive only: no existing columns modified or dropped.
-- Run after 001 (schema.sql initial migration).

-- ─── Phase 3: Vault columns on palm_enrollments ───────────────────────────────

-- AES-256-GCM encrypted ML-KEM-768 private key.
-- Encrypted with KEK = HKDF(HCS_TOKEN_SECRET, userId, 'palmguard-kek').
-- Ciphertext length: 2400 (privkey) + 16 (GCM tag) = 2416 bytes.
ALTER TABLE palm_enrollments
  ADD COLUMN IF NOT EXISTS kem_privkey_enc BYTEA;

-- 12-byte AES-GCM initialisation vector (unique per enrollment).
ALTER TABLE palm_enrollments
  ADD COLUMN IF NOT EXISTS kek_iv BYTEA;

-- Constraint: both columns must be set together (atomically).
ALTER TABLE palm_enrollments
  ADD CONSTRAINT vault_columns_both_set
    CHECK (
      (kem_privkey_enc IS NULL AND kek_iv IS NULL) OR
      (kem_privkey_enc IS NOT NULL AND kek_iv IS NOT NULL)
    );

-- ─── Phase 3: Expand audit_log event_type to include new events ───────────────

-- Drop the existing constraint and recreate with the extended set.
-- Existing CHECK was:
--   event_type IN ('ENROLL', 'VERIFY_MATCH', 'VERIFY_NO_MATCH', 'ENROLL_REVOKED', 'ERROR')

ALTER TABLE palm_audit_log
  DROP CONSTRAINT IF EXISTS palm_audit_log_event_type_check;

ALTER TABLE palm_audit_log
  ADD CONSTRAINT palm_audit_log_event_type_check
    CHECK (event_type IN (
      'ENROLL',
      'VERIFY_MATCH',
      'VERIFY_NO_MATCH',
      'ENROLL_REVOKED',
      'ENROLL_DELETED',       -- RGPD right-to-erasure
      'RATE_LIMIT_EXCEEDED',  -- Rate limit hit
      'ERROR'
    ));

-- ─── Phase 3: Index for rate-limit queries ────────────────────────────────────

-- Fast lookup of recent events per user for rate-limit enforcement in DB layer.
CREATE INDEX IF NOT EXISTS idx_audit_log_user_event_time
  ON palm_audit_log (user_id, event_type, id DESC);

-- ─── Rollback hint (manual) ───────────────────────────────────────────────────
-- To rollback this migration:
--   ALTER TABLE palm_enrollments DROP COLUMN IF EXISTS kem_privkey_enc;
--   ALTER TABLE palm_enrollments DROP COLUMN IF EXISTS kek_iv;
--   ALTER TABLE palm_enrollments DROP CONSTRAINT IF EXISTS vault_columns_both_set;
--   ALTER TABLE palm_audit_log DROP CONSTRAINT palm_audit_log_event_type_check;
--   ALTER TABLE palm_audit_log ADD CONSTRAINT palm_audit_log_event_type_check
--     CHECK (event_type IN ('ENROLL','VERIFY_MATCH','VERIFY_NO_MATCH','ENROLL_REVOKED','ERROR'));
--   DROP INDEX IF EXISTS idx_audit_log_user_event_time;
