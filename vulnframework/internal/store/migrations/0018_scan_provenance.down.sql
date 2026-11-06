ALTER TABLE repo_scan_results
  DROP COLUMN IF EXISTS ai_inventory,
  DROP COLUMN IF EXISTS commit_sha;
