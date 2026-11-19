-- 0018_scan_provenance: which commit a scan read, and what AI use it found.
--
-- commit_sha is the commit the scanned tree was taken at, so a report can
-- quote exactly what was scanned and every adapter, local or remote, is held
-- to the same one. NULL where nothing recorded it (a copied tree with no .git,
-- every scan before this migration).
--
-- ai_inventory is the AI component inventory an opt-in adapter (NuGuard)
-- reported: agents, models, tools, prompts, frameworks, providers, with the
-- tool and version that produced it. An inventory signal, never a finding:
-- nothing reads it to score or route. NULL is "not measured", which the
-- interface says in words, never as zero.
--
-- Both columns are nullable and added without a default, so existing rows
-- are untouched and the migration rolls back by dropping them.

ALTER TABLE repo_scan_results
  ADD COLUMN commit_sha   TEXT,
  ADD COLUMN ai_inventory JSONB;
