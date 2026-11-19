DROP TABLE IF EXISTS ai_sbom;
ALTER TABLE repo_scan_results
  DROP COLUMN IF EXISTS tools_not_requested,
  DROP COLUMN IF EXISTS effective_nuguard;
ALTER TABLE scan_requests DROP COLUMN IF EXISTS nuguard;
DROP TABLE IF EXISTS nuguard_status;
DROP TABLE IF EXISTS nuguard_settings_audit;
DROP TABLE IF EXISTS nuguard_repo_overrides;
DROP TABLE IF EXISTS nuguard_settings;
