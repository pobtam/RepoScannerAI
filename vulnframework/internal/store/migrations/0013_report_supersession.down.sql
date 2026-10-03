-- 0013_report_supersession: rollback.
--
-- The column comes back empty. Nothing wrote it before this migration and
-- nothing writes it after, so there is no data to restore — which is the
-- whole reason it could be dropped.

DROP INDEX IF EXISTS reports_supersedes_idx;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS superseded_by TEXT REFERENCES reports(id);
