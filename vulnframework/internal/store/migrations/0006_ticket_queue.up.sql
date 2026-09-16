-- Ticket operations queue (VM-F-812, VM-AD §13.5).
--
-- Tracker unavailability must never fail a run, so an operation that cannot be
-- performed is persisted and retried. The payload carries enough to replay the
-- operation in full: a queue that records only "something failed" cannot retry
-- anything, and the ticket is lost with no trace of what it should have been.
CREATE TABLE ticket_ops (
  id                BIGSERIAL PRIMARY KEY,
  fingerprint       TEXT NOT NULL,
  kind              TEXT NOT NULL,
  -- TEXT, not JSONB: the payload is a replay blob, never queried into. JSONB
  -- would normalise whitespace and reorder keys, so what came back would not be
  -- what was enqueued -- which matters the moment a payload is hashed, signed,
  -- or compared against what was intended.
  payload           TEXT NOT NULL,
  attempts          INTEGER NOT NULL DEFAULT 0,
  next_attempt_at   TIMESTAMPTZ NOT NULL,
  last_error        TEXT,
  created_at        TIMESTAMPTZ NOT NULL
);

CREATE INDEX ticket_ops_due_idx ON ticket_ops (next_attempt_at);
CREATE INDEX ticket_ops_fingerprint_idx ON ticket_ops (fingerprint);
