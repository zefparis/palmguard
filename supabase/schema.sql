-- PalmGuard — Supabase Schema
-- Run this in the Supabase SQL Editor (project: hcs-u7 EU Frankfurt)
-- Follows same RLS conventions as hcs-u7-backend migrations.

-- ─── Extensions ───────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── Enrollments ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS palm_enrollments (
  id                  TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
  tenant_id           TEXT        NOT NULL,
  user_id             TEXT        NOT NULL,

  -- ML-KEM-768 ciphertext (base64url, ~1452 chars for 1088 bytes).
  template_ciphertext TEXT        NOT NULL,
  -- ML-KEM-768 public key (base64url, ~1579 chars for 1184 bytes).
  public_key          TEXT        NOT NULL,

  -- SHA-256(palmVector || celestialSalt) — integrity check, NOT the biometric.
  content_hash        TEXT        NOT NULL,

  -- Celestial entropy metadata (non-sensitive — public astronomy data).
  enrolled_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  captured_at_unix_ms BIGINT      NOT NULL,
  julian_day_number   DOUBLE PRECISION NOT NULL,

  -- MediaPipe confidence of the best frame used at enrollment.
  capture_confidence  REAL        NOT NULL CHECK (capture_confidence BETWEEN 0 AND 1),

  template_version    TEXT        NOT NULL DEFAULT '1.0',
  device_id           TEXT,

  -- Only one active enrollment per (tenant, user) is enforced by application layer.
  -- Historical enrollments are kept for audit purposes.
  is_active           BOOLEAN     NOT NULL DEFAULT TRUE,

  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_palm_enrollments_tenant_user
  ON palm_enrollments (tenant_id, user_id)
  WHERE is_active = TRUE;

CREATE INDEX idx_palm_enrollments_tenant
  ON palm_enrollments (tenant_id);

-- ─── Audit Log ────────────────────────────────────────────────────────────────

-- ANSSI-compatible immutable audit log for every enrollment and verification event.
-- Never stores biometric data or private keys.

CREATE TABLE IF NOT EXISTS palm_audit_log (
  id              BIGSERIAL   PRIMARY KEY,
  tenant_id       TEXT        NOT NULL,
  user_id         TEXT        NOT NULL,
  enrollment_id   TEXT        REFERENCES palm_enrollments(id) ON DELETE SET NULL,

  event_type      TEXT        NOT NULL
    CHECK (event_type IN ('ENROLL', 'VERIFY_MATCH', 'VERIFY_NO_MATCH', 'ENROLL_REVOKED', 'ERROR')),

  -- Cosine similarity score (NULL for non-verify events).
  similarity      REAL        CHECK (similarity IS NULL OR similarity BETWEEN -1 AND 1),

  -- Whether the authentication was accepted.
  matched         BOOLEAN,

  -- Server-side processing time in ms (constant-time floor applied).
  processing_ms   INTEGER,

  -- Opaque audit token returned to caller for correlation.
  audit_token     TEXT        NOT NULL DEFAULT encode(gen_random_bytes(16), 'hex'),

  -- Non-sensitive device/network metadata.
  device_id       TEXT,
  ip_hash         TEXT,       -- SHA-256 of client IP (GDPR-compliant)
  user_agent_hash TEXT,       -- SHA-256 of User-Agent

  -- HMAC-SHA256 chain link (links to previous row for tamper detection).
  chain_hash      TEXT,

  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_palm_audit_tenant_user
  ON palm_audit_log (tenant_id, user_id, created_at DESC);

CREATE INDEX idx_palm_audit_enrollment
  ON palm_audit_log (enrollment_id, created_at DESC);

-- Prevent any UPDATE or DELETE on audit rows (append-only).
CREATE OR REPLACE RULE palm_audit_no_update AS
  ON UPDATE TO palm_audit_log DO INSTEAD NOTHING;

CREATE OR REPLACE RULE palm_audit_no_delete AS
  ON DELETE TO palm_audit_log DO INSTEAD NOTHING;

-- ─── Updated-at trigger ───────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

CREATE TRIGGER palm_enrollments_updated_at
  BEFORE UPDATE ON palm_enrollments
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ─── Row Level Security ───────────────────────────────────────────────────────

ALTER TABLE palm_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE palm_audit_log   ENABLE ROW LEVEL SECURITY;

-- Backend service role (app_backend) has full access scoped to tenant.
-- The app_backend role must set: SET LOCAL app.tenant_id = '<tenant_id>'
-- before any query (same pattern as hcs-u7-backend RLS).

CREATE POLICY palm_enrollments_backend_select ON palm_enrollments
  FOR SELECT TO app_backend
  USING (tenant_id = current_setting('app.tenant_id', TRUE));

CREATE POLICY palm_enrollments_backend_insert ON palm_enrollments
  FOR INSERT TO app_backend
  WITH CHECK (tenant_id = current_setting('app.tenant_id', TRUE));

CREATE POLICY palm_enrollments_backend_update ON palm_enrollments
  FOR UPDATE TO app_backend
  USING (tenant_id = current_setting('app.tenant_id', TRUE));

CREATE POLICY palm_audit_backend_select ON palm_audit_log
  FOR SELECT TO app_backend
  USING (tenant_id = current_setting('app.tenant_id', TRUE));

CREATE POLICY palm_audit_backend_insert ON palm_audit_log
  FOR INSERT TO app_backend
  WITH CHECK (tenant_id = current_setting('app.tenant_id', TRUE));

-- Admin role (read-only cross-tenant for monitoring).
CREATE POLICY palm_enrollments_admin_select ON palm_enrollments
  FOR SELECT TO authenticated
  USING (TRUE);

CREATE POLICY palm_audit_admin_select ON palm_audit_log
  FOR SELECT TO authenticated
  USING (TRUE);
