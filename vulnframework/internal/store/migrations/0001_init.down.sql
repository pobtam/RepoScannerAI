-- 0001_init: rollback.
--
-- Dropped in reverse dependency order so foreign keys never block the rollback.

DROP TABLE IF EXISTS wave_consumers;
DROP TABLE IF EXISTS module_deps;
DROP TABLE IF EXISTS repo_scan_results;
DROP TABLE IF EXISTS token_usage;
DROP TABLE IF EXISTS tickets;
DROP TABLE IF EXISTS remediation_attempts;
DROP TABLE IF EXISTS state_transitions;
DROP TABLE IF EXISTS finding_observations;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS pr_scans;
DROP TABLE IF EXISTS runs;
DROP TABLE IF EXISTS repos;

DROP SEQUENCE IF EXISTS run_seq_rescan;
DROP SEQUENCE IF EXISTS run_seq_manual;
DROP SEQUENCE IF EXISTS run_seq_advisory;
DROP SEQUENCE IF EXISTS run_seq_sweep;
