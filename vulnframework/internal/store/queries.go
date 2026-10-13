package store

// SQL statements for the Postgres store (VM-AD §3: store/queries.go).
//
// Kept together and named so the schema's access pattern is readable in one
// place rather than scattered through method bodies.

const (
	qUpsertRepo = `
INSERT INTO repos (name, tier, languages, archived, has_test_suite, module_topology, codeowners, has_lockfile)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (name) DO UPDATE SET
  tier = EXCLUDED.tier,
  languages = EXCLUDED.languages,
  archived = EXCLUDED.archived,
  has_test_suite = EXCLUDED.has_test_suite,
  module_topology = EXCLUDED.module_topology,
  codeowners = EXCLUDED.codeowners,
  has_lockfile = EXCLUDED.has_lockfile`

	qGetRepo = `
SELECT name, tier, languages::text, archived, has_test_suite, module_topology, codeowners::text, has_lockfile
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
SELECT f.fingerprint, f.state, f.category
FROM findings f
WHERE f.repo = $1
  AND NOT EXISTS (
    SELECT 1 FROM finding_observations o
    WHERE o.fingerprint = f.fingerprint AND o.run_id = $2
  )
ORDER BY f.fingerprint`

	// The residual warning is written on the same statement as the
	// verification, not by a later update. A verification that landed and a
	// warning that did not would be the silent case OQ-AUDIT-02 forbids.
	qMarkVerified = `
UPDATE findings
SET resolved_at = $1, verified_reason = $2, not_reobserved = FALSE, gap_run_id = NULL,
    lease_owner = NULL, lease_expires_at = NULL,
    data = jsonb_set(
             jsonb_set(data, '{derived,residual_possible}', to_jsonb($4::boolean), true),
             '{derived,residual_detail}', to_jsonb($5::text), true)
WHERE fingerprint = $3`

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
       f.first_seen_run, f.last_seen_run, f.not_reobserved, f.gap_run_id, f.verified_reason,
       f.first_seen_at, f.last_seen_at, f.resolved_at, f.upstream_finding
FROM findings f`

	qGetFinding = qListFindingsBase + ` WHERE f.fingerprint = $1`
)

// Planned scope and leases (OQ-P2-02, VM-AD §6.2).
const (
	qUpsertPlan = `
INSERT INTO run_plan (run_id, repo, dispatch_state, skip_reason, planned_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (run_id, repo) DO UPDATE SET
  dispatch_state = EXCLUDED.dispatch_state,
  skip_reason = EXCLUDED.skip_reason`

	qMarkDispatched = `
UPDATE run_plan SET dispatch_state = 'dispatched', dispatched_at = $1, skip_reason = NULL
WHERE run_id = $2 AND repo = $3`

	qMarkSkipped = `
UPDATE run_plan SET dispatch_state = 'skipped', skip_reason = $1
WHERE run_id = $2 AND repo = $3`

	qPlanEntries = `
SELECT run_id, repo, dispatch_state, skip_reason, planned_at, dispatched_at
FROM run_plan WHERE run_id = $1 ORDER BY repo`

	// Planned repositories that produced no scan result: the delta coverage is
	// measured against (OQ-P2-02).
	qPlanWithoutResult = `
SELECT p.run_id, p.repo, p.dispatch_state, p.skip_reason, p.planned_at, p.dispatched_at
FROM run_plan p
WHERE p.run_id = $1
  AND NOT EXISTS (
    SELECT 1 FROM repo_scan_results r
    WHERE r.run_id = p.run_id AND r.repo = p.repo
  )
ORDER BY p.repo`

	qCountProduced = `
SELECT count(*) FROM repo_scan_results r
JOIN run_plan p ON p.run_id = r.run_id AND p.repo = r.repo
WHERE r.run_id = $1`

	qAcquireLease = `
UPDATE findings SET lease_owner = $1, lease_expires_at = $2 WHERE fingerprint = $3`

	qReleaseLease = `
UPDATE findings SET lease_owner = NULL, lease_expires_at = NULL WHERE fingerprint = $1`

	qGetLease = `SELECT lease_owner, lease_expires_at FROM findings WHERE fingerprint = $1`

	// Lease-bound findings whose claim has lapsed. AUTO_REMEDIATING is the only
	// lease-bound state (VM-AD §6.2); without this a crashed worker strands a
	// finding there permanently (VM-F-158).
	qExpiredLeases = `
SELECT fingerprint FROM findings
WHERE state = $1 AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL
  AND lease_expires_at <= $2
ORDER BY fingerprint`
)

// qRepoNames lists the fleet registry.
const qRepoNames = `SELECT name FROM repos ORDER BY name`

// qRepoScanHistory returns a repository's scan outcomes for one run kind,
// newest run first, with the run's start time so coverage age is computable.
const qRepoScanHistory = `
SELECT r.run_id, r.outcome, r.failure_cause, n.started_at
FROM repo_scan_results r
JOIN runs n ON n.id = r.run_id
WHERE r.repo = $1 AND n.kind = $2
ORDER BY n.seq DESC`

// Triage narrative and computed priority.
const (
	qSetTriage = `
UPDATE findings SET data = jsonb_set(data, '{triage}', $1::jsonb, true)
WHERE fingerprint = $2`

	qSetPriority = `UPDATE findings SET priority = $1, reason_code = $2 WHERE fingerprint = $3`
)

// Previous run of a kind, and issued reports (VM-ADR-15).
const (
	qPreviousRun = `
SELECT id, kind, seq, trigger_detail, started_at, finished_at, scanner_image,
       tool_versions, repos_planned, repos_scanned, repos_failed
FROM runs WHERE kind = $1 AND seq < $2 ORDER BY seq DESC LIMIT 1`

	qInsertReport = `
INSERT INTO reports
  (id, anchor_run_id, kind, repo, template, query, content_hash, content, issued_at, issued_by, supersedes, redacted, withheld_count)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (id) DO NOTHING`

	qGetReport = `
SELECT id, anchor_run_id, kind, repo, template, query, content_hash, content, issued_at, issued_by, supersedes, redacted, withheld_count
FROM reports WHERE id = $1`

	qRunsList = `
SELECT id, kind, seq, trigger_detail, started_at, finished_at, scanner_image, tool_versions,
       repos_planned, repos_scanned, repos_failed
FROM runs
WHERE ($1 = '' OR kind = $1) AND ($2 <= 0 OR seq < $2)
ORDER BY seq DESC, id DESC
LIMIT $3`

	qPRsForFinding = `
SELECT p.branch
FROM remediation_prs p
JOIN remediation_pr_findings pf ON pf.branch = p.branch
WHERE pf.fingerprint = $1
ORDER BY p.opened_at DESC, p.branch`

	qReportsForRun = `
SELECT id, anchor_run_id, kind, repo, template, query, content_hash, content, issued_at, issued_by, supersedes, redacted, withheld_count
FROM reports WHERE anchor_run_id = $1 ORDER BY id`

	// qSupersededBy reads the lineage backwards, from the `supersedes` column
	// rather than from a stored back-pointer. The unique partial index added
	// by migration 0013 is what guarantees at most one row comes back.
	qSupersededBy = `
SELECT id, anchor_run_id, kind, repo, template, query, content_hash, content, issued_at, issued_by, supersedes, redacted, withheld_count
FROM reports WHERE supersedes = $1`
)

// qSetSLA persists the derived SLA block into the finding document.
const qSetSLA = `
UPDATE findings SET data = jsonb_set(data, '{derived}', $1::jsonb, true)
WHERE fingerprint = $2`

// --- Tickets (VM-AD §13.2) ---------------------------------------------------

const (
	// qUpsertTicket keys on the fingerprint, which is what makes ticket
	// creation idempotent (VM-F-804). closed_at is preserved on conflict: a
	// later create must never silently reopen a closed ticket.
	qUpsertTicket = `
INSERT INTO tickets (fingerprint, backend, ref, url, mirror_backend, mirror_ref, created_at, closed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (fingerprint) DO UPDATE SET
  backend        = EXCLUDED.backend,
  ref            = EXCLUDED.ref,
  url            = EXCLUDED.url,
  mirror_backend = EXCLUDED.mirror_backend,
  mirror_ref     = EXCLUDED.mirror_ref,
  closed_at      = COALESCE(EXCLUDED.closed_at, tickets.closed_at)`

	qGetTicket = `
SELECT fingerprint, backend, ref, url, mirror_backend, mirror_ref, created_at, closed_at
FROM tickets WHERE fingerprint = $1`

	qTicketURLs = `
SELECT fingerprint, url FROM tickets WHERE url <> ''`

	qDeleteTicket = `DELETE FROM tickets WHERE fingerprint = $1`

	qCloseTicket = `UPDATE tickets SET closed_at = $2 WHERE fingerprint = $1`

	qInsertTicketOp = `
INSERT INTO ticket_ops (fingerprint, kind, payload, attempts, next_attempt_at, last_error, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`

	qDueTicketOps = `
SELECT id, fingerprint, kind, payload, attempts, next_attempt_at, last_error, created_at
FROM ticket_ops WHERE next_attempt_at <= $1 ORDER BY id LIMIT $2`

	qCompleteTicketOp = `DELETE FROM ticket_ops WHERE id = $1`

	qRetryTicketOp = `
UPDATE ticket_ops SET attempts = attempts + 1, next_attempt_at = $2, last_error = $3 WHERE id = $1`
)

// --- Per-repository remediation lock (VM-AD §7.3) ----------------------------

const (
	// qAcquireRepoLock is one statement, so mutual exclusion is the database's
	// guarantee rather than a read-then-write race in application code.
	//
	// The conflict clause takes the lock only when it is the caller's own
	// (reentrant, extending the expiry) or has expired (reclaim). Otherwise no
	// row is updated and the caller sees zero rows affected, which is the
	// contention signal.
	qAcquireRepoLock = `
INSERT INTO repo_locks (repo, owner, acquired_at, expires_at)
VALUES ($1, $2, $4, $3)
ON CONFLICT (repo) DO UPDATE SET
  owner       = EXCLUDED.owner,
  acquired_at = CASE WHEN repo_locks.owner = EXCLUDED.owner THEN repo_locks.acquired_at ELSE EXCLUDED.acquired_at END,
  expires_at  = EXCLUDED.expires_at
WHERE repo_locks.owner = EXCLUDED.owner OR repo_locks.expires_at <= $4`

	qGetRepoLock = `SELECT repo, owner, acquired_at, expires_at FROM repo_locks WHERE repo = $1`

	qReleaseRepoLock = `DELETE FROM repo_locks WHERE repo = $1 AND owner = $2`

	qSweepRepoLocks = `DELETE FROM repo_locks WHERE expires_at <= $1`
)

// --- Remediation pull requests (VM-AD §11) -----------------------------------

const (
	qUpsertRemediationPR = `
INSERT INTO remediation_prs (branch, repo, fix_group_id, number, url, state, opened_at, closed_at, merged, ticket_ref, ticket_url)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (branch) DO UPDATE SET
  number     = EXCLUDED.number,
  url        = EXCLUDED.url,
  state      = EXCLUDED.state,
  closed_at  = COALESCE(EXCLUDED.closed_at, remediation_prs.closed_at),
  merged     = remediation_prs.merged OR EXCLUDED.merged,
  ticket_ref = COALESCE(NULLIF(EXCLUDED.ticket_ref, ''), remediation_prs.ticket_ref),
  ticket_url = COALESCE(NULLIF(EXCLUDED.ticket_url, ''), remediation_prs.ticket_url)`

	qGetRemediationPR = `
SELECT branch, repo, fix_group_id, number, url, state, opened_at, closed_at, merged, ticket_ref, ticket_url, confirmed_at
FROM remediation_prs WHERE branch = $1`

	qRemediationPRForFinding = `
SELECT p.branch, p.repo, p.fix_group_id, p.number, p.url, p.state, p.opened_at, p.closed_at, p.merged, p.ticket_ref, p.ticket_url, p.confirmed_at
FROM remediation_prs p
JOIN remediation_pr_findings f ON f.branch = p.branch
WHERE f.fingerprint = $1 AND p.state = 'open'
ORDER BY p.branch
LIMIT 1`

	qCloseRemediationPR = `UPDATE remediation_prs SET state = 'closed', closed_at = $2, merged = $3 WHERE branch = $1`

	qOpenRemediationPRs = `
SELECT branch, repo, fix_group_id, number, url, state, opened_at, closed_at, merged, ticket_ref, ticket_url, confirmed_at
FROM remediation_prs WHERE repo = $1 AND state = 'open' ORDER BY branch`

	qConfirmRemediationPR = `UPDATE remediation_prs SET confirmed_at = $2 WHERE branch = $1`

	// qUnconfirmedRemediationPRs is what replaces the poll fan-out: the open
	// pull requests nothing has vouched for since $2, oldest confirmation
	// first (never-confirmed first), bounded by $3.
	qUnconfirmedRemediationPRs = `
SELECT branch
FROM remediation_prs
WHERE repo = $1 AND state = 'open' AND (confirmed_at IS NULL OR confirmed_at < $2)
ORDER BY confirmed_at ASC NULLS FIRST, branch
LIMIT $3`

	qRecordWebhookDelivery = `
INSERT INTO webhook_health (id, last_delivery_at, deliveries) VALUES (1, $1, 1)
ON CONFLICT (id) DO UPDATE SET
  last_delivery_at = GREATEST(webhook_health.last_delivery_at, EXCLUDED.last_delivery_at),
  deliveries       = webhook_health.deliveries + 1`

	qWebhookHealth = `SELECT last_delivery_at, deliveries FROM webhook_health WHERE id = 1`

	// --- Exploitation intelligence (OQ-AUDIT-01(b)) -------------------------

	qUpsertIntel = `
INSERT INTO vuln_intel (id, epss, epss_available, epss_as_of, kev, kev_available, kev_as_of, fetched_at, sources)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (id) DO UPDATE SET
  epss           = EXCLUDED.epss,
  epss_available = EXCLUDED.epss_available,
  epss_as_of     = EXCLUDED.epss_as_of,
  kev            = EXCLUDED.kev,
  kev_available  = EXCLUDED.kev_available,
  kev_as_of      = EXCLUDED.kev_as_of,
  fetched_at     = EXCLUDED.fetched_at,
  sources        = EXCLUDED.sources`

	qIntelFor = `
SELECT id, epss, epss_available, epss_as_of, kev, kev_available, kev_as_of, fetched_at, sources
FROM vuln_intel WHERE id = ANY($1)`

	qDeletePRFindings = `DELETE FROM remediation_pr_findings WHERE branch = $1`

	qInsertPRFinding = `
INSERT INTO remediation_pr_findings (branch, fingerprint) VALUES ($1, $2)
ON CONFLICT DO NOTHING`

	qPRFindings = `SELECT fingerprint FROM remediation_pr_findings WHERE branch = $1 ORDER BY fingerprint`

	// qOpenPRURLs feeds the finding projection: the open pull request per
	// finding, joined in rather than stored in the finding document.
	qOpenPRURLs = `
SELECT f.fingerprint, MIN(p.url)
FROM remediation_prs p
JOIN remediation_pr_findings f ON f.branch = p.branch
WHERE p.state = 'open' AND p.url <> ''
GROUP BY f.fingerprint`
)

// --- Run parent tickets (VM-AD §13.3 row 1) ----------------------------------

const (
	qUpsertRunTicket = `
INSERT INTO run_tickets (run_id, backend, ref, url, created_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (run_id) DO UPDATE SET backend = EXCLUDED.backend, ref = EXCLUDED.ref, url = EXCLUDED.url`

	qGetRunTicket = `SELECT run_id, backend, ref, url, created_at FROM run_tickets WHERE run_id = $1`

	// qTicketByRef is the reverse lookup the mirror falls back to when its
	// in-process index misses (OQ-P8-01). The unique index on (backend, ref)
	// is what makes it a lookup rather than a scan.
	qTicketByRef = `
SELECT fingerprint, backend, ref, url, mirror_backend, mirror_ref, created_at, closed_at
FROM tickets WHERE backend = $1 AND ref = $2`

	// qReopenTicket clears the closure. Separate from the upsert because
	// reopening is a decision, not a side effect of a re-save (VM-F-806).
	qReopenTicket = `UPDATE tickets SET closed_at = NULL WHERE fingerprint = $1`
)

// qSetUpstreamFinding records the owner's finding a consumer is blocked on.
const qSetUpstreamFinding = `UPDATE findings SET upstream_finding = $2 WHERE fingerprint = $1`

// --- Dependency manifests (VM-F-602) ----------------------------------------

const (
	qDeleteRepoDeps = `DELETE FROM module_deps WHERE repo = $1`

	qInsertDep = `
INSERT INTO module_deps (run_id, repo, module, version, direct, replaced)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (run_id, repo, module) DO UPDATE SET
  version = EXCLUDED.version, direct = EXCLUDED.direct, replaced = EXCLUDED.replaced`

	qDependents = `
SELECT run_id, repo, module, version, direct, replaced
FROM module_deps WHERE module = $1 ORDER BY repo, module`

	qAllDeps = `
SELECT run_id, repo, module, version, direct, replaced
FROM module_deps ORDER BY repo, module`
)

// qIntelFreshness is when each feed last answered for anything.
const qIntelFreshness = `
SELECT max(fetched_at) FILTER (WHERE kev_available),
       max(fetched_at) FILTER (WHERE epss_available)
FROM vuln_intel`
