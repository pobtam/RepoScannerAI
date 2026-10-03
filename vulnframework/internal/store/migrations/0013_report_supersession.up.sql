-- 0013_report_supersession: give supersession one direction and one writer
-- (VM-ADR-15, VM-UI-F-1108, D10).
--
-- 0005 created both `supersedes` and `superseded_by`. Nothing ever wrote
-- either, and now that something does, holding both would be a mistake:
--
--   `superseded_by` lives on the report being REPLACED, so setting it means
--   updating a row that was already issued. Reports are immutable, and a
--   column whose only writer mutates an issued report is a hole in that
--   claim — a narrow one, but the kind that gets widened later by somebody
--   who reads the precedent rather than the reasoning.
--
--   It is also derivable. `superseded_by` is exactly "the report whose
--   supersedes is this one", so storing it adds a second copy of a fact that
--   can disagree with the first. This repository has spent its whole length
--   removing values that can disagree with themselves.
--
-- So: one column, one direction, write-once rows, and the reverse lookup
-- served by an index.
--
-- The unique index is the substantive part. It makes "a report may be
-- superseded at most once" a property of the database rather than a rule the
-- application hopes it is following. Two reports both claiming to replace one
-- original is a fork in the lineage with no defined winner, and VM-UI-F-1108
-- requires the relationship to be STATED — which cannot be done when there
-- are two of them.

DROP INDEX IF EXISTS reports_superseded_by_idx;
ALTER TABLE reports DROP COLUMN IF EXISTS superseded_by;

CREATE UNIQUE INDEX reports_supersedes_idx
  ON reports (supersedes)
  WHERE supersedes IS NOT NULL;
