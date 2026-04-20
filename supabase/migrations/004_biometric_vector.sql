-- Migration 004: Add biometric_vector column to palm_enrollments
-- Stores the Float32[74] vector from the Python biometric engine as JSONB.

ALTER TABLE palm_enrollments
  ADD COLUMN IF NOT EXISTS biometric_vector JSONB;
