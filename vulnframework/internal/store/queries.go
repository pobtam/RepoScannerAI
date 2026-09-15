package store

// SQL statements for the Postgres store (VM-AD §3: store/queries.go).
//
// Kept together and named so the schema's access pattern is readable in one
// place rather than scattered through method bodies.

const (
	qUpsertRepo = `
INSERT INTO repos (name, tier, languages, archived, has_test_suite, module_topology, codeowners)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (name) DO UPDATE SET
  tier = EXCLUDED.tier,
  languages = EXCLUDED.languages,
  archived = EXCLUDED.archived,
  has_test_suite = EXCLUDED.has_test_suite,
  module_topology = EXCLUDED.module_topology,
  codeowners = EXCLUDED.codeowners`

	qGetRepo = `
SELECT name, tier, languages::text, archived, has_test_suite, module_topology, codeowners::text
FROM repos WHERE name = $1`

	qInsertRun = `
INSERT INTO runs (id, kind, seq, trigger_detail, started_at, scanner_image, tool_versions)
VALUES ($1, $2, $3, $4, $5, $6, $7)`

	qFinishRun = `
UPDATE runs SET finished_at = $1, repos_planned = $2, repos_scanned = $3, repos_failed = $4
WHERE id = $5`

	qGetRun = `
SELECT id, kind, seq, trigger_detail, started_at, finished_at, scanner_image,
       tool_versions, repos_planned, repos_scanned, repos_failed
FROM runs WHERE id = $1`

	qUpsertScanResult = `
INSERT INTO repo_scan_results
  (run_id, repo, outcome, tools_ok, tools_failed, failure_cause, failure_detail, failure_owner, duration_sec)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (run_id, repo) DO UPDATE SET
  outcome = EXCLUDED.outcome,
  tools_ok = EXCLUDED.tools_ok,
  tools_failed = EXCLUDED.tools_failed,
  failure_cause = EXCLUDED.failure_cause,
  failure_detail = EXCLUDED.failure_detail,
  failure_owner = EXCLUDED.failure_owner,
  duration_sec = EXCLUDED.duration_sec`

	qScanResults = `
SELECT run_id, repo, outcome, tools_ok::text, tools_failed::text,
       failure_cause, failure_detail, failure_owner, duration_sec
FROM repo_scan_results WHERE repo = $1 ORDER BY run_id DESC LIMIT $2`

	qInsertFinding = `
INSERT INTO findings
  (fingerprint, repo, category, data, state, first_seen_at, last_seen_at, first_seen_run, last_seen_run)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	// Observing a finding clears the derived absence flag: it is present.
	qTouchFinding = `
UPDATE findings
SET last_seen_at = $1, last_seen_run = $2, not_reobserved = FALSE, gap_run_id = NULL
WHERE fingerprint = $3`

	// One row per source per run (VM-AD §8.6). Re-running the same tool in the
	// same run replaces its observation, so replay is idempotent.
	qUpsertObservation = `
INSERT INTO finding_observations (fingerprint, run_id, tool, observed_at, source, raw)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (fingerprint, run_id, tool) DO UPDATE SET
  observed_at = EXCLUDED.observed_at,
  source = EXCLUDED.source,
  raw = EXCLUDED.raw`

	qObservations = `
SELECT source FROM finding_observations WHERE fingerprint = $1 ORDER BY run_id, tool`

	// Unresolved findings in a repository that the given run did not observe.
	qAbsentFindings = `
SELECT f.fingerprint, f.state
FROM findings f
WHERE f.repo = $1
  AND NOT EXISTS (
    SELECT 1 FROM finding_observations o
    WHERE o.fingerprint = f.fingerprint AND o.run_id = $2
  )
ORDER BY f.fingerprint`

	qMarkVerified = `
UPDATE findings SET resolved_at = $1, not_reobserved = FALSE, gap_run_id = NULL
WHERE fingerprint = $2`

	qMarkNotReobserved = `
UPDATE findings SET not_reobserved = $1, gap_run_id = $2 WHERE fingerprint = $3`

	qSetState = `UPDATE findings SET state = $1 WHERE fingerprint = $2`

	qSetProjection = `
UPDATE findings
SET data = $1, reach_conflict = $2, reach_conflict_detail = $3, fixed_candidates = $4
WHERE fingerprint = $5`

	qInsertTransition = `
INSERT INTO state_transitions (fingerprint, from_state, to_state, actor, cause, at)
VALUES ($1, $2, $3, $4, $5, $6)`

	qTransitions = `
SELECT fingerprint, from_state, to_state, actor, cause, at
FROM state_transitions WHERE fingerprint = $1 ORDER BY at, id`

	qListFindingsBase = `
SELECT f.fingerprint, f.repo, f.category, f.data, f.state, f.reason_code, f.priority,
       f.first_seen_run, f.last_seen_run, f.not_reobserved, f.gap_run_id
FROM findings f`

	qGetFinding = qListFindingsBase + ` WHERE f.fingerprint = $1`
)
