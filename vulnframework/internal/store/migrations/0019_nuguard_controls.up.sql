-- 0019_nuguard_controls: security owners control NuGuard within the
-- operator's ceiling (VM-UI-F-1201..1212).
--
-- Settings live at three levels, each resolving to the next one up when
-- unset: a scan request's options, a repository's override, the fleet's
-- setting, then the scan worker's flag defaults. The scan worker resolves
-- them for every repository it scans and clips them to the ceiling its
-- flags set; the API only stores them. Nothing here is a credential.
--
-- Every change is a row in nuguard_settings_audit: who, when, before, after
-- and the reason given. Rows are never deleted.
--
-- nuguard_status is written only by the scan worker, which is the only
-- process that talks to NuGuard: the API reads it to say whether NuGuard is
-- configured, reachable and on the pinned version, and what the operator's
-- ceiling is.
--
-- Every repository scan records the NuGuard options it actually used
-- (effective_nuguard) and the tools it did not ask for, with the reason
-- (tools_not_requested): neither ok nor failed. A finding from a tool not
-- requested keeps its state and is flagged not re-observed (VM-F-160/161).
--
-- ai_sbom keeps the AI-SBOM a scan asked to keep, served by the API from
-- here: NuGuard deletes its results after its own retention period, and the
-- API holds no key to ask. A document over the worker's size cap is not
-- stored; the row says why.

CREATE TABLE nuguard_settings (
  id          BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
  settings    JSONB NOT NULL,
  changed_by  TEXT NOT NULL,
  changed_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE nuguard_repo_overrides (
  repo        TEXT PRIMARY KEY,
  override    JSONB NOT NULL CHECK (override->>'mode' IN ('inherit', 'on', 'off')),
  changed_by  TEXT NOT NULL,
  changed_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE nuguard_settings_audit (
  id          BIGSERIAL PRIMARY KEY,
  scope       TEXT NOT NULL CHECK (scope IN ('fleet', 'repository')),
  repo        TEXT,
  before      JSONB,
  after       JSONB,
  changed_by  TEXT NOT NULL,
  changed_at  TIMESTAMPTZ NOT NULL,
  reason      TEXT NOT NULL DEFAULT '',
  CHECK ((scope = 'fleet') = (repo IS NULL))
);
CREATE INDEX nuguard_settings_audit_by_repo ON nuguard_settings_audit (repo, id DESC);
CREATE INDEX nuguard_settings_audit_by_person ON nuguard_settings_audit (changed_by, changed_at);

CREATE TABLE nuguard_status (
  id          BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
  status      JSONB NOT NULL,
  checked_at  TIMESTAMPTZ NOT NULL
);

ALTER TABLE scan_requests ADD COLUMN nuguard JSONB;

ALTER TABLE repo_scan_results
  ADD COLUMN effective_nuguard   JSONB,
  ADD COLUMN tools_not_requested JSONB;

CREATE TABLE ai_sbom (
  run_id           TEXT NOT NULL REFERENCES runs(id),
  repo             TEXT NOT NULL,
  commit_sha       TEXT NOT NULL,
  nuguard_version  TEXT NOT NULL,
  size_bytes       BIGINT NOT NULL,
  sha256           TEXT NOT NULL,
  document         JSONB,
  withheld         TEXT,
  stored_at        TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (run_id, repo),
  CHECK ((document IS NULL) = (withheld IS NOT NULL))
);
