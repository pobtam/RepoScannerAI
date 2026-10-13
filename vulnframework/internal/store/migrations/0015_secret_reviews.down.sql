DROP TABLE IF EXISTS secret_removals;
DROP TABLE IF EXISTS suppression_proposals;
UPDATE findings SET verified_reason = 'external' WHERE verified_reason = 'rotation_confirmed';
ALTER TABLE findings DROP CONSTRAINT findings_verified_reason_check;
ALTER TABLE findings ADD CONSTRAINT findings_verified_reason_check CHECK (
  verified_reason IS NULL OR verified_reason IN ('framework_merge', 'upstream', 'external'));
