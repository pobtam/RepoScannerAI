-- Exploitation intelligence, keyed by vulnerability identifier
-- (OQ-AUDIT-01(b), VM-AD §9.4).
--
-- Keyed by identifier rather than by finding because EPSS and KEV are
-- properties of a vulnerability, not of an occurrence: one row serves every
-- finding in the fleet carrying the identifier, and per-finding copies would
-- let two findings of the same CVE disagree about whether it is being
-- exploited.
--
-- Outside the finding document, like the ticket and pull request references,
-- because the document is rebuilt from observations on every scan.
--
-- Availability is stored SEPARATELY from the value. A NULL epss and an epss of
-- 0 are different facts -- nobody looked, versus measured and negligible --
-- and a schema that could not express the difference would force the
-- collapse the framework exists to avoid.
CREATE TABLE vuln_intel (
    id              TEXT PRIMARY KEY,
    epss            DOUBLE PRECISION,
    epss_available  BOOLEAN NOT NULL DEFAULT FALSE,
    epss_as_of      TIMESTAMPTZ,
    kev             BOOLEAN NOT NULL DEFAULT FALSE,
    kev_available   BOOLEAN NOT NULL DEFAULT FALSE,
    kev_as_of       TIMESTAMPTZ,
    fetched_at      TIMESTAMPTZ NOT NULL,
    sources         TEXT[] NOT NULL DEFAULT '{}',
    CONSTRAINT epss_needs_a_date CHECK (NOT epss_available OR epss_as_of IS NOT NULL),
    CONSTRAINT kev_needs_a_date  CHECK (NOT kev_available OR kev_as_of IS NOT NULL),
    CONSTRAINT epss_in_range     CHECK (epss IS NULL OR (epss >= 0 AND epss <= 1))
);
