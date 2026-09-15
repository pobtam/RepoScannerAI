-- 0004_run_plan: rollback.

ALTER TABLE repo_scan_results DROP CONSTRAINT repo_scan_results_outcome_check;
DELETE FROM repo_scan_results WHERE outcome IN ('not_dispatched','no_result');
ALTER TABLE repo_scan_results ADD CONSTRAINT repo_scan_results_outcome_check
  CHECK (outcome IN ('complete','partial','failed'));

DROP INDEX IF EXISTS run_plan_run_idx;
DROP TABLE IF EXISTS run_plan;
