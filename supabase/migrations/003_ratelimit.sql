-- PalmGuard Migration 003 — Supabase Rate Limit Table
-- Additive only. Run after 002_vault.sql.

-- ─── Rate limit table ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS palm_rate_limits (
  user_id      TEXT        NOT NULL,
  action       TEXT        NOT NULL CHECK (action IN ('enroll', 'verify')),
  window_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  count        INT         NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, action)
);

COMMENT ON TABLE palm_rate_limits IS
  'Sliding-window rate limit counters for PalmGuard. '
  'One row per (user_id, action). Reset when window_start + window expires.';

-- ─── RLS ──────────────────────────────────────────────────────────────────────

ALTER TABLE palm_rate_limits ENABLE ROW LEVEL SECURITY;

-- Only the service-role key (server-side) may read/write rate limit rows.
-- No client-side access is needed or permitted.
CREATE POLICY palm_rate_limits_service_only
  ON palm_rate_limits
  USING (false);

-- ─── Index ────────────────────────────────────────────────────────────────────

-- Composite PK already provides the primary lookup index.
-- Additional index for bulk cleanup of stale rows (maintenance job).
CREATE INDEX IF NOT EXISTS idx_rate_limits_window_start
  ON palm_rate_limits (window_start);

-- ─── Rollback hint ────────────────────────────────────────────────────────────
-- DROP TABLE IF EXISTS palm_rate_limits;
