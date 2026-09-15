-- 0002_merge_provenance: record the cross-source merge outcome (VM-AD §8.6).
--
-- The merged finding is a deterministic projection over per-source
-- observations. Two columns make the projection's own verdict inspectable
-- without recomputing it: whether two reachability-capable sources disagreed,
-- and what the disagreement was.
--
-- A conflict is not reachable with today's tool matrix, since govulncheck is
-- the only source that determines reachability. Recording it now means adding a
-- second such source is a configuration change rather than a schema change.

ALTER TABLE findings
  ADD COLUMN reach_conflict BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN reach_conflict_detail TEXT;

-- Every fixed version any source proposed, so the chosen fix is auditable
-- rather than merely asserted (VM-AD §8.6).
ALTER TABLE findings
  ADD COLUMN fixed_candidates TEXT[] NOT NULL DEFAULT '{}';

CREATE INDEX findings_reach_conflict_idx ON findings (reach_conflict)
  WHERE reach_conflict;
