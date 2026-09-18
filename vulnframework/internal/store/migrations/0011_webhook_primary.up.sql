-- The webhook becomes the primary path for pull request state (OQ-P12-01).
--
-- Two facts are needed to stop polling every open pull request on every sweep,
-- and neither can be inferred:
--
--   confirmed_at -- when this pull request's state was last established by
--   authoritative word: a verified webhook delivery about it, or a successful
--   query. A pull request confirmed a minute ago does not need asking about
--   again; one confirmed never, or long ago, does.
--
--   webhook_health -- when the endpoint last received ANY verified delivery.
--   This is what distinguishes "quiet because nothing has happened" from
--   "quiet because deliveries are not arriving", which look identical from
--   inside the framework and mean opposite things. A single row.
ALTER TABLE remediation_prs ADD COLUMN confirmed_at TIMESTAMPTZ;

CREATE TABLE webhook_health (
    id                SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_delivery_at  TIMESTAMPTZ NOT NULL,
    deliveries        BIGINT NOT NULL DEFAULT 0
);
