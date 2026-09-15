-- 0003_verification_reason: rollback.

DROP INDEX IF EXISTS findings_verified_reason_idx;

ALTER TABLE findings DROP COLUMN IF EXISTS verified_reason;
