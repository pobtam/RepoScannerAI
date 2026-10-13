-- 0015_secret_reviews: secrets are never closed by disappearing.
--
-- Two records, both kept OUTSIDE the finding document because the document is
-- rebuilt from observations on every scan, and both joined in when findings
-- are read.
--
-- suppression_proposals — the repository's own scanner configuration
-- (.gitleaks.toml, .gitleaksignore, an inline gitleaks:allow) hides a secret
-- that is still in the files. That is a proposal for a human, not a fix. One
-- row per finding, carrying the latest proposal and its decision; the history
-- of state changes is in state_transitions.
--
-- secret_removals — a complete scan no longer sees a secret, and nobody has
-- confirmed the credential was rotated. Removal from source is not
-- remediation (VM-F-856): the secret is still in history, and still valid
-- until rotated. The row goes when the secret is seen again or a human
-- confirms rotation.
--
-- Nothing here holds, hashes or derives from a credential (VM-F-263):
-- config_sha256 is a hash of the CONFIGURATION file.

CREATE TABLE suppression_proposals (
  fingerprint    TEXT PRIMARY KEY REFERENCES findings(fingerprint),
  mechanism      TEXT NOT NULL CHECK (mechanism IN ('gitleaks_toml', 'gitleaksignore', 'inline_allow')),
  path           TEXT NOT NULL,
  config_sha256  TEXT,
  description    TEXT,
  status         TEXT NOT NULL CHECK (status IN ('pending', 'overdue', 'confirmed', 'rejected', 'withdrawn')),
  proposed_run   TEXT NOT NULL REFERENCES runs(id),
  proposed_at    TIMESTAMPTZ NOT NULL,
  escalated_at   TIMESTAMPTZ,
  decided_by     TEXT,
  decided_at     TIMESTAMPTZ,
  withdrawn_run  TEXT REFERENCES runs(id),
  withdrawn_at   TIMESTAMPTZ
);
CREATE INDEX suppression_proposals_open_idx ON suppression_proposals (status)
  WHERE status IN ('pending', 'overdue');

CREATE TABLE secret_removals (
  fingerprint  TEXT PRIMARY KEY REFERENCES findings(fingerprint),
  run_id       TEXT NOT NULL REFERENCES runs(id),
  removed_at   TIMESTAMPTZ NOT NULL
);

-- A fourth way to be verified: a human attested rotation.
ALTER TABLE findings DROP CONSTRAINT findings_verified_reason_check;
ALTER TABLE findings ADD CONSTRAINT findings_verified_reason_check CHECK (
  verified_reason IS NULL OR verified_reason IN ('framework_merge', 'upstream', 'external', 'rotation_confirmed'));
