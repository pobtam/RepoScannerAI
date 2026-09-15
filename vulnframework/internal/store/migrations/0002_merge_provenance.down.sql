-- 0002_merge_provenance: rollback.

DROP INDEX IF EXISTS findings_reach_conflict_idx;

ALTER TABLE findings
  DROP COLUMN IF EXISTS fixed_candidates,
  DROP COLUMN IF EXISTS reach_conflict_detail,
  DROP COLUMN IF EXISTS reach_conflict;
