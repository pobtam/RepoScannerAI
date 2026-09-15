-- 0001_init: the findings store schema (VM-AD §4.2).

CREATE TABLE repos (
  name              TEXT PRIMARY KEY,
  tier              SMALLINT NOT NULL DEFAULT 3,
  languages         TEXT[] NOT NULL DEFAULT '{}',
  archived          BOOLEAN NOT NULL DEFAULT FALSE,
  has_test_suite    BOOLEAN,
  module_topology   TEXT,
  codeowners        TEXT[],
  last_scanned_at   TIMESTAMPTZ
);

-- One sequence per run kind (VM-F-115). Sweep numbering must not be consumed
-- by higher-volume kinds. Allocation is by the datastore, never derived from a
-- timestamp, so two runs starting in the same second remain distinct
-- (VM-F-112, VM-ADR-11).
CREATE SEQUENCE run_seq_sweep    START 1;
CREATE SEQUENCE run_seq_advisory START 1;
CREATE SEQUENCE run_seq_manual   START 1;
CREATE SEQUENCE run_seq_rescan   START 1;

CREATE TABLE runs (
  id                TEXT PRIMARY KEY,
  kind              TEXT NOT NULL
                    CHECK (kind IN ('sweep','advisory','manual','rescan')),
  seq               BIGINT NOT NULL,
  trigger_detail    TEXT,
  started_at        TIMESTAMPTZ NOT NULL,
  finished_at       TIMESTAMPTZ,
  scanner_image     TEXT NOT NULL,
  tool_versions     JSONB NOT NULL,
  repos_planned     INT,
  repos_scanned     INT,
  repos_failed      INT,
  UNIQUE (kind, seq)
);
CREATE INDEX runs_started_at_idx ON runs (started_at DESC);

-- PR-gate scans are NOT runs (VM-F-116). At several thousand per week they
-- would push sweep numbering into six figures within a year.
CREATE TABLE pr_scans (
  id                BIGSERIAL PRIMARY KEY,
  repo              TEXT NOT NULL REFERENCES repos(name),
  pr_number         INT NOT NULL,
  head_sha          TEXT NOT NULL,
  scanned_at        TIMESTAMPTZ NOT NULL,
  scanner_image     TEXT NOT NULL,
  conclusion        TEXT NOT NULL,
  UNIQUE (repo, head_sha)
);

CREATE TABLE findings (
  fingerprint       TEXT PRIMARY KEY,
  repo              TEXT NOT NULL REFERENCES repos(name),
  category          TEXT NOT NULL,
  data              JSONB NOT NULL,
  state             TEXT NOT NULL,
  reason_code       TEXT,
  priority          TEXT,
  first_seen_at     TIMESTAMPTZ NOT NULL,
  last_seen_at      TIMESTAMPTZ NOT NULL,
  -- Run provenance is queried directly (delta reporting, run-scoped corpora)
  -- as well as carried in data.provenance, so it is a column rather than a
  -- JSON path (VM-AD §4.1 provenance.first_seen_run / last_seen_run).
  first_seen_run    TEXT NOT NULL,
  last_seen_run     TEXT NOT NULL,
  resolved_at       TIMESTAMPTZ,
  lease_owner       TEXT,
  lease_expires_at  TIMESTAMPTZ,
  -- Derived, maintained by reconciliation (VM-F-161). A finding the most
  -- recent applicable run did not observe while it remains unresolved. It is
  -- not a resolution: see gap_run_id for the coverage gap that explains it.
  not_reobserved    BOOLEAN NOT NULL DEFAULT FALSE,
  gap_run_id        TEXT
);
CREATE INDEX findings_repo_state_idx ON findings (repo, state);
CREATE INDEX findings_state_priority_idx ON findings (state, priority);
CREATE INDEX findings_data_idx ON findings USING GIN (data jsonb_path_ops);

-- One row per source per run (VM-AD §8.6).
--
-- This widens the VM-AD §4.2 primary key from (fingerprint, run_id) to
-- (fingerprint, run_id, tool). Two tools reporting one defect in one run
-- produce one fingerprint but two observations, and §8.6 requires every
-- per-source value be retained so the merged finding is auditable. The narrower
-- key cannot hold both rows.
CREATE TABLE finding_observations (
  fingerprint       TEXT NOT NULL REFERENCES findings(fingerprint),
  run_id            TEXT NOT NULL REFERENCES runs(id),
  tool              TEXT NOT NULL,
  observed_at       TIMESTAMPTZ NOT NULL,
  source            JSONB NOT NULL,
  raw               JSONB,
  PRIMARY KEY (fingerprint, run_id, tool)
);
CREATE INDEX finding_observations_fp_idx ON finding_observations (fingerprint);
CREATE INDEX finding_observations_run_idx ON finding_observations (run_id);

CREATE TABLE state_transitions (
  id                BIGSERIAL PRIMARY KEY,
  fingerprint       TEXT NOT NULL,
  from_state        TEXT,
  to_state          TEXT NOT NULL,
  actor             TEXT NOT NULL,
  cause             TEXT,
  at                TIMESTAMPTZ NOT NULL
);
CREATE INDEX state_transitions_fp_idx ON state_transitions (fingerprint, at);

CREATE TABLE remediation_attempts (
  id                BIGSERIAL PRIMARY KEY,
  run_id            TEXT NOT NULL,
  repo              TEXT NOT NULL,
  fingerprints      TEXT[] NOT NULL,
  mode              TEXT NOT NULL,
  branch            TEXT,
  pr_url            TEXT,
  outcome           TEXT NOT NULL,
  reason_code       TEXT,
  build_ok          BOOLEAN,
  tests_ok          BOOLEAN,
  scan_clean        BOOLEAN,
  verification_log  TEXT,
  started_at        TIMESTAMPTZ,
  finished_at       TIMESTAMPTZ
);

CREATE TABLE tickets (
  fingerprint       TEXT PRIMARY KEY REFERENCES findings(fingerprint),
  backend           TEXT NOT NULL,
  ref               TEXT NOT NULL,
  url               TEXT NOT NULL,
  mirror_backend    TEXT,
  mirror_ref        TEXT,
  created_at        TIMESTAMPTZ NOT NULL,
  closed_at         TIMESTAMPTZ
);
CREATE UNIQUE INDEX tickets_backend_ref_idx ON tickets (backend, ref);

CREATE TABLE token_usage (
  id                BIGSERIAL PRIMARY KEY,
  run_id            TEXT NOT NULL,
  repo              TEXT,
  stage             TEXT NOT NULL,
  model             TEXT NOT NULL,
  input_tokens      INT NOT NULL,
  output_tokens     INT NOT NULL,
  cache_read_tokens INT NOT NULL DEFAULT 0,
  cache_write_tokens INT NOT NULL DEFAULT 0,
  findings_count    INT,
  duration_sec      INT,
  outcome           TEXT,
  at                TIMESTAMPTZ NOT NULL
);

-- Per-repository scan outcome, retained per run (VM-F-213). This is what makes
-- consecutive-failure count, last-clean-scan and coverage trend computable.
CREATE TABLE repo_scan_results (
  run_id            TEXT NOT NULL REFERENCES runs(id),
  repo              TEXT NOT NULL REFERENCES repos(name),
  outcome           TEXT NOT NULL
                    CHECK (outcome IN ('complete','partial','failed')),
  tools_ok          TEXT[] NOT NULL DEFAULT '{}',
  tools_failed      TEXT[] NOT NULL DEFAULT '{}',
  failure_cause     TEXT,
  failure_detail    TEXT,
  failure_owner     TEXT,
  duration_sec      INT,
  PRIMARY KEY (run_id, repo)
);
CREATE INDEX repo_scan_results_repo_idx ON repo_scan_results (repo, run_id DESC);

-- Both the SBOM index (VM-F-210) and the reverse-dependency index (VM-F-602).
-- One table serves both; do not build a second.
CREATE TABLE module_deps (
  run_id            TEXT NOT NULL,
  repo              TEXT NOT NULL,
  module            TEXT NOT NULL,
  version           TEXT NOT NULL,
  direct            BOOLEAN NOT NULL,
  replaced          BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (run_id, repo, module)
);
CREATE INDEX module_deps_module_idx ON module_deps (module);

-- Per-consumer reachability for first-party findings (VM-F-610, VM-ADR-13).
CREATE TABLE wave_consumers (
  upstream_fp       TEXT NOT NULL REFERENCES findings(fingerprint),
  consumer_repo     TEXT NOT NULL REFERENCES repos(name),
  consumer_fp       TEXT REFERENCES findings(fingerprint),
  module_version    TEXT NOT NULL,
  reachable         TEXT NOT NULL CHECK (reachable IN ('true','false','unknown')),
  status            TEXT NOT NULL,
  exclusion_reason  TEXT,
  PRIMARY KEY (upstream_fp, consumer_repo)
);
