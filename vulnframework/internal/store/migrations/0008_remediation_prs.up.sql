-- Remediation pull requests (VM-AD §11, VM-F-501).
--
-- One row per fix group, keyed on the branch, which is derived from the fix
-- group identity -- so re-running remediation for the same group finds the same
-- row and cannot open a second pull request (VM-F-502).
--
-- Kept out of the finding document for the same reason the ticket reference is:
-- the document is rebuilt from observations on every scan, so a reference held
-- inside it would be erased by the next run.
CREATE TABLE remediation_prs (
  branch        TEXT PRIMARY KEY,
  repo          TEXT NOT NULL REFERENCES repos(name),
  fix_group_id  TEXT NOT NULL,
  number        INTEGER,
  url           TEXT,
  state         TEXT NOT NULL,
  opened_at     TIMESTAMPTZ NOT NULL,
  closed_at     TIMESTAMPTZ
);

CREATE INDEX remediation_prs_repo_idx ON remediation_prs (repo);

-- Which findings a pull request addresses. A pull request covers a fix group,
-- and the group is the actionable unit (VM-ADR-05), so the relation is
-- many-to-one and must be stored rather than recomputed: the group membership
-- that produced a branch is history, and recomputing it from current findings
-- would silently disagree once a finding changed state.
CREATE TABLE remediation_pr_findings (
  branch      TEXT NOT NULL REFERENCES remediation_prs(branch) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL REFERENCES findings(fingerprint),
  PRIMARY KEY (branch, fingerprint)
);

CREATE INDEX remediation_pr_findings_fp_idx ON remediation_pr_findings (fingerprint);
