-- 0014_repo_lockfile: record whether a repository commits a dependency
-- lockfile (VM-F-241).
--
-- scan.RepoProfile.HasLockfile already gated the npm-audit adapter, but the
-- registry had nowhere to keep the fact, so the orchestrator's sweep never set
-- it and npm audit never ran in a sweep — only from a hand-run scanworker
-- given -lockfile. The column gives the field a durable producer (vfctl).

ALTER TABLE repos ADD COLUMN has_lockfile BOOLEAN NOT NULL DEFAULT FALSE;
