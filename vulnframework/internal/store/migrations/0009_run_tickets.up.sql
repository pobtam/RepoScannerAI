-- Run parent tickets (VM-AD §13.3 row 1).
--
-- A separate table from `tickets` because the subject is different: `tickets`
-- is keyed on a fingerprint and references findings, and a run parent has no
-- finding. Overloading that key with a synthetic fingerprint would break the
-- foreign key that keeps finding tickets honest.
CREATE TABLE run_tickets (
  run_id      TEXT PRIMARY KEY REFERENCES runs(id),
  backend     TEXT NOT NULL,
  ref         TEXT NOT NULL,
  url         TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL
);

-- The pull request's own ticket (VM-AD §13.3 row 2). It belongs on the pull
-- request record rather than in its own table: the ticket exists because the
-- pull request does, and closes when it does.
ALTER TABLE remediation_prs ADD COLUMN ticket_ref TEXT;
ALTER TABLE remediation_prs ADD COLUMN ticket_url TEXT;

-- Whether the pull request was merged, as distinct from merely closed. The
-- difference decides between MERGED and DECLINED (VM-F-545), and a single
-- "closed" state cannot express it.
ALTER TABLE remediation_prs ADD COLUMN merged BOOLEAN NOT NULL DEFAULT FALSE;
