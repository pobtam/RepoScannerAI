-- Per-repository remediation serialisation (VM-AD §7.3, VM-F-503, OQ-P4-02).
--
-- A lock ROW with an expiry, deliberately not pg_advisory_lock. An advisory
-- lock is held by a Postgres session, so it could not exist in the in-memory
-- backend at all -- the fake would enforce weaker rules than production, which
-- makes every test using it a statement about the fake. It also dies with its
-- session in ways the store cannot observe.
--
-- A row with an expiry gives the same mutual exclusion plus crash safety: a
-- worker that dies does not strand the repository, because the sweeper reclaims
-- the lock exactly as it reverts an expired finding lease (§6.2).
CREATE TABLE repo_locks (
  repo        TEXT PRIMARY KEY REFERENCES repos(name),
  owner       TEXT NOT NULL,
  acquired_at TIMESTAMPTZ NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX repo_locks_expiry_idx ON repo_locks (expires_at);
