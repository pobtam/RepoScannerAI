-- 0017_scan_requests: scans requested from the interface, vfctl or the timer.
--
-- A request is a row; the scan worker claims it, runs it through the same
-- sweep and download path as a scheduled sweep, and records the run it
-- produced. The API only ever inserts here: it never runs a scanner and
-- never holds the GitHub token.
--
-- At most one request per repository may be queued or running. The partial
-- unique index enforces it, so a second click (or a second API replica)
-- merges into the existing request instead of queueing the scan twice.
--
-- Every row is also the audit record of the request: who asked, for which
-- repository, when, and what came of it. Rows are never deleted.

CREATE TABLE scan_requests (
  id            TEXT PRIMARY KEY,
  repo          TEXT NOT NULL,
  batch_id      TEXT,
  source        TEXT NOT NULL CHECK (source IN ('web', 'vfctl', 'timer')),
  requested_by  TEXT NOT NULL,
  requested_at  TIMESTAMPTZ NOT NULL,
  status        TEXT NOT NULL CHECK (status IN ('queued', 'running', 'finished', 'failed',
                                                'timed_out', 'interrupted', 'refused')),
  reason        TEXT,
  run_id        TEXT REFERENCES runs(id),
  worker_id     TEXT,
  started_at    TIMESTAMPTZ,
  heartbeat_at  TIMESTAMPTZ,
  finished_at   TIMESTAMPTZ,
  retry_of      TEXT REFERENCES scan_requests(id),
  CHECK (status NOT IN ('failed', 'timed_out', 'interrupted', 'refused') OR reason IS NOT NULL)
);
CREATE UNIQUE INDEX scan_requests_one_active ON scan_requests (repo)
  WHERE status IN ('queued', 'running');
CREATE INDEX scan_requests_queue ON scan_requests (requested_at, id) WHERE status = 'queued';
CREATE INDEX scan_requests_by_requester ON scan_requests (requested_by, requested_at);
CREATE INDEX scan_requests_by_repo ON scan_requests (repo, requested_at DESC);
