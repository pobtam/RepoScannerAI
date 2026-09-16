-- 0005_reports: rollback.

DROP INDEX IF EXISTS reports_hash_idx;
DROP INDEX IF EXISTS reports_repo_idx;
DROP INDEX IF EXISTS reports_anchor_idx;
DROP TABLE IF EXISTS reports;
