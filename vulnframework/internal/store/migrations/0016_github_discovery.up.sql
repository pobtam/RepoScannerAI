-- 0016_github_discovery: the GitHub account a key reaches, and what it found.
--
-- github_connections records what GitHub said about a token when it was
-- connected: the account, the kind of token, a classic token's scopes, and
-- its expiry. NEVER the token. The token lives in the environment or the
-- cloud's secret manager and is read at the moment of use; nothing here can
-- be used to reach GitHub (VM-F-263). One row per account, so a second
-- account is a second row rather than a redesign.
--
-- discovered_repos is the latest discovery for each account: every
-- repository the token can see, and whether it is scanned. A skipped
-- repository is kept with its reason, because a repository silently left
-- out is outside the coverage denominator and the fleet would report
-- complete coverage of a smaller fleet than the one that exists.
--
-- repo_exclusions are a person's decisions to leave a repository out, with
-- who and why. They outlive discoveries.

CREATE TABLE github_connections (
  account     TEXT PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('fine_grained', 'classic')),
  scopes      TEXT[] NOT NULL DEFAULT '{}',
  expires_at  TIMESTAMPTZ,
  read_only   TEXT NOT NULL,
  checked_at  TIMESTAMPTZ NOT NULL,
  checked_by  TEXT NOT NULL
);

CREATE TABLE discovered_repos (
  name            TEXT PRIMARY KEY,
  account         TEXT NOT NULL REFERENCES github_connections(account) ON DELETE CASCADE,
  affiliation     TEXT NOT NULL CHECK (affiliation IN ('owner', 'organization', 'collaborator')),
  private         BOOLEAN NOT NULL,
  archived        BOOLEAN NOT NULL,
  fork            BOOLEAN NOT NULL,
  size_kb         INTEGER NOT NULL,
  default_branch  TEXT NOT NULL,
  language        TEXT NOT NULL DEFAULT '',
  included        BOOLEAN NOT NULL,
  reason          TEXT,
  detail          TEXT,
  discovered_at   TIMESTAMPTZ NOT NULL,
  CHECK (included = (reason IS NULL))
);
CREATE INDEX discovered_repos_account_idx ON discovered_repos (account);

CREATE TABLE repo_exclusions (
  name         TEXT PRIMARY KEY,
  reason       TEXT NOT NULL,
  excluded_by  TEXT NOT NULL,
  excluded_at  TIMESTAMPTZ NOT NULL
);
