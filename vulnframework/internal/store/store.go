// Package store is the findings store: the system of record (VM-AD P2).
//
// Every other component is a stateless worker that reads and writes it. Two
// implementations satisfy Store — Postgres for production and Memory for
// offline testing — and both are held to one conformance suite, because an
// in-memory fake that enforces different invariants than production is worse
// than no fake at all.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
)

// RunKind is the class of run. Each kind draws from its own sequence so that
// sweep numbering is not consumed by higher-volume kinds (VM-F-115).
type RunKind string

const (
	KindSweep    RunKind = "sweep"
	KindAdvisory RunKind = "advisory"
	KindManual   RunKind = "manual"
	KindRescan   RunKind = "rescan"
)

// AllRunKinds is the closed enumeration (VM-FR §5.2).
var AllRunKinds = []RunKind{KindSweep, KindAdvisory, KindManual, KindRescan}

// Prefix returns the run identifier prefix for a kind (VM-FR §5.2).
func (k RunKind) Prefix() string {
	switch k {
	case KindSweep:
		return "S"
	case KindAdvisory:
		return "A"
	case KindManual:
		return "M"
	case KindRescan:
		return "R"
	default:
		return ""
	}
}

// Valid reports whether k is a member of the closed enumeration.
func (k RunKind) Valid() bool { return k.Prefix() != "" }

// FormatRunID renders a run identifier: prefix plus a zero-padded sequence,
// for example S-001247.
//
// The identifier is short enough to be spoken, written in a ticket and typed
// from memory (VM-F-117). It is deliberately not self-dating, which is why it
// must always be rendered alongside the start timestamp (VM-F-119).
func FormatRunID(kind RunKind, seq int64) string {
	return fmt.Sprintf("%s-%06d", kind.Prefix(), seq)
}

// Run is one end-to-end execution of the pipeline.
type Run struct {
	ID            string            `json:"id"`
	Kind          RunKind           `json:"kind"`
	Seq           int64             `json:"seq"`
	TriggerDetail string            `json:"trigger_detail,omitempty"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    *time.Time        `json:"finished_at,omitempty"`
	ScannerImage  string            `json:"scanner_image"`
	ToolVersions  map[string]string `json:"tool_versions"`
	ReposPlanned  int               `json:"repos_planned"`
	ReposScanned  int               `json:"repos_scanned"`
	ReposFailed   int               `json:"repos_failed"`
}

// ScanOutcome re-exports the model's outcome enumeration for store callers.
type ScanOutcome = model.ScanOutcome

// RepoScanResult is the per-repository outcome of a run (VM-F-213).
//
// Retaining one row per repository per run is what makes consecutive-failure
// count and last-successful-scan computable. Without it a coverage gap is a
// point observation with no context.
type RepoScanResult struct {
	RunID         string      `json:"run_id"`
	Repo          string      `json:"repo"`
	Outcome       ScanOutcome `json:"outcome"`
	ToolsOK       []string    `json:"tools_ok"`
	ToolsFailed   []string    `json:"tools_failed"`
	FailureCause  string      `json:"failure_cause,omitempty"`
	FailureDetail string      `json:"failure_detail,omitempty"`
	FailureOwner  string      `json:"failure_owner,omitempty"`
	DurationSec   int         `json:"duration_sec,omitempty"`
}

// Report is an issued report record (VM-ADR-15).
type Report struct {
	ID            string          `json:"id"`
	AnchorRunID   string          `json:"anchor_run_id"`
	Kind          string          `json:"kind"`
	Repo          string          `json:"repo,omitempty"`
	Template      string          `json:"template"`
	Query         json.RawMessage `json:"query"`
	ContentHash   string          `json:"content_hash"`
	Content       json.RawMessage `json:"content"`
	IssuedAt      time.Time       `json:"issued_at"`
	IssuedBy      string          `json:"issued_by,omitempty"`
	Supersedes    string          `json:"supersedes,omitempty"`
	Redacted      bool            `json:"redacted"`
	WithheldCount int             `json:"withheld_count"`
}

// ModuleDep is one repository's recorded use of one module (VM-F-602).
type ModuleDep struct {
	RunID    string `json:"run_id"`
	Repo     string `json:"repo"`
	Module   string `json:"module"`
	Version  string `json:"version"`
	Direct   bool   `json:"direct"`
	Replaced bool   `json:"replaced"`
}

// Repo is a repository in the fleet registry.
type Repo struct {
	Name         string   `json:"name"`
	Tier         int      `json:"tier"`
	Languages    []string `json:"languages"`
	Archived     bool     `json:"archived"`
	HasTestSuite bool     `json:"has_test_suite"`
	// HasLockfile records a committed dependency lockfile (VM-F-241). It is
	// what lets the sweep run npm audit, which refuses to run without one.
	HasLockfile    bool     `json:"has_lockfile"`
	ModuleTopology string   `json:"module_topology,omitempty"`
	Codeowners     []string `json:"codeowners,omitempty"`
}

// UpsertStats summarises what an observation batch changed.
type UpsertStats struct {
	// Created counts fingerprints seen for the first time (state DETECTED).
	Created int
	// Observed counts fingerprints already present: an observation is recorded
	// against the existing finding rather than a duplicate being created
	// (VM-F-104, VM-F-106).
	Observed int
	// Regressed counts findings that were VERIFIED and have been observed again
	// (VM-F-105).
	Regressed int
	// Observations counts observation rows written, which exceeds the finding
	// count when several tools report one defect.
	Observations int
}

// ReconcileStats summarises what a post-scan reconciliation changed.
type ReconcileStats struct {
	// Verified counts findings confirmed absent by a successful scan.
	Verified int
	// NotReobserved counts unresolved findings the run did not observe while
	// the scan did not complete successfully — retained, flagged, never closed
	// (VM-ADR-12, VM-F-161).
	NotReobserved int
	// RetainedUnverified counts findings that would have verified had the scan
	// succeeded. This is the number VM-F-216 requires reported alongside a gap.
	RetainedUnverified int
	// SecretsRemoved counts secrets a complete scan no longer saw, held open
	// for a human to confirm rotation rather than verified (VM-F-856).
	SecretsRemoved int
}

// Query selects findings.
//
// Scope is required and never defaulted (VM-ADR-14): a finding list is
// meaningless without stating which findings, and the three plausible corpora
// differ by large factors.
type Query struct {
	Scope       Scope
	Repo        string
	States      []model.State
	Categories  []model.Category
	RunID       string
	Fingerprint string
	Limit       int
}

// Scope names the corpus a query addresses (VM-ADR-14).
type Scope string

const (
	// ScopeOpen is every currently unresolved finding.
	ScopeOpen Scope = "open"
	// ScopeRun is every finding observed in one run.
	ScopeRun Scope = "run"
	// ScopeAll is every finding ever recorded.
	ScopeAll Scope = "all"
)

// Valid reports whether s is a member of the closed enumeration.
func (s Scope) Valid() bool {
	return s == ScopeOpen || s == ScopeRun || s == ScopeAll
}

// ErrScopeRequired is returned for a query with no scope. Defaulting it would
// mean some readers are silently looking at the wrong corpus (VM-ADR-14).
var ErrScopeRequired = errors.New("store: query scope is required and is never defaulted (VM-ADR-14)")

// ErrNotFound is returned when an addressed record does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrRepoLocked is returned when another worker holds a repository's
// remediation lock.
//
// It is a distinct sentinel because it is not a failure: the correct response
// is to defer this repository to the next sweep, not to retry or to report an
// error. A caller that treated it as a failure would count a correctly
// serialised repository as a coverage gap.
var ErrRepoLocked = errors.New("store: another worker holds this repository's remediation lock (VM-F-503)")

// Store is the findings store.
type Store interface {
	// Migrate applies every pending migration.
	Migrate(ctx context.Context) error
	// MigrateTo migrates up or down to a target version. Version 0 is the empty
	// database.
	MigrateTo(ctx context.Context, version int) error
	// SchemaVersion reports the currently applied migration version.
	SchemaVersion(ctx context.Context) (int, error)

	// UpsertRepo registers or updates a repository (VM-NF-501).
	UpsertRepo(ctx context.Context, r Repo) error
	// GetRepo returns a repository.
	GetRepo(ctx context.Context, name string) (Repo, error)

	// CreateRun allocates a run identifier from the per-kind sequence
	// (VM-ADR-11). The sequence is allocated by the datastore, never derived
	// from a timestamp, so two runs starting in the same second remain distinct
	// (VM-F-112).
	CreateRun(ctx context.Context, kind RunKind, trigger, scannerImage string, toolVersions map[string]string) (Run, error)
	// FinishRun records completion.
	FinishRun(ctx context.Context, runID string, planned, scanned, failed int) error
	// GetRun returns a run.
	GetRun(ctx context.Context, id string) (Run, error)

	// RecordScanResult persists the per-repository outcome of a run.
	RecordScanResult(ctx context.Context, res RepoScanResult) error
	// ScanResults returns a repository's scan outcomes, most recent first.
	ScanResults(ctx context.Context, repo string, limit int) ([]RepoScanResult, error)

	// UpsertObservations records what a run's tools observed for a repository.
	//
	// An existing fingerprint receives an observation; it does not create a
	// second finding (VM-F-104). A VERIFIED finding observed again transitions
	// to REGRESSED rather than being created anew (VM-F-105).
	UpsertObservations(ctx context.Context, runID, repo string, raws []model.RawFinding) (UpsertStats, error)

	// Reconcile applies the absence rules after a repository's scan completes.
	//
	// Findings absent from a successful scan verify. Findings absent because the
	// scan did not complete retain their state and are flagged not re-observed
	// (VM-ADR-12, VM-F-160/161).
	Reconcile(ctx context.Context, runID, repo string) (ReconcileStats, error)

	// GetFinding returns the merged view of one finding.
	GetFinding(ctx context.Context, fingerprint string) (model.Finding, error)
	// ListFindings returns findings matching a query.
	ListFindings(ctx context.Context, q Query) ([]model.Finding, error)
	// Observations returns every retained per-source observation for a finding,
	// so the projection can be audited (VM-AD §8.6).
	Observations(ctx context.Context, fingerprint string) ([]SourceObservation, error)
	// Transitions returns a finding's state history (VM-F-153).
	Transitions(ctx context.Context, fingerprint string) ([]model.StateTransition, error)

	// ApplyTransition records a validated state change.
	ApplyTransition(ctx context.Context, fingerprint string, to model.State, tc model.TransitionContext) error

	// --- Planned scope (OQ-P2-02) ---
	//
	// Coverage is measured against planned scope. An in-scope repository that
	// never runs must leave a record, or its absence reads as a clean scan.

	// RecordPlan writes the planned in-scope set for a run.
	RecordPlan(ctx context.Context, entries []PlanEntry) error
	// MarkDispatched records that a worker was started for a repository.
	MarkDispatched(ctx context.Context, runID, repo string) error
	// MarkSkipped records a deliberate decision not to dispatch, with a reason.
	MarkSkipped(ctx context.Context, runID, repo, reason string) error
	// PlanEntries returns a run's planned scope.
	PlanEntries(ctx context.Context, runID string) ([]PlanEntry, error)
	// CloseRun writes a scan result for every planned repository that produced
	// none, distinguishing "never started" from "started and lost".
	CloseRun(ctx context.Context, runID string) (CloseStats, error)

	// --- Leases (VM-AD §6.2, VM-F-158) ---

	// AcquireLease claims a finding for a worker until expiresAt.
	AcquireLease(ctx context.Context, fingerprint, owner string, expiresAt time.Time) error
	// ReleaseLease clears a claim.
	ReleaseLease(ctx context.Context, fingerprint string) error
	// GetLease returns a finding's current claim.
	GetLease(ctx context.Context, fingerprint string) (Lease, error)
	// SweepExpiredLeases reverts findings whose lease has lapsed from
	// AUTO_REMEDIATING back to TRIAGED and returns how many it moved.
	SweepExpiredLeases(ctx context.Context, now time.Time) (int, error)

	// SetTriage persists a finding's triage narrative (VM-F-301).
	//
	// Separate from ApplyTransition on purpose: the narrative is data and the
	// state change is a decision, and the caller must be able to record one
	// without implying the other.
	SetTriage(ctx context.Context, fingerprint string, t model.Triage) error
	// SetSLA persists the computed SLA position (VM-F-908).
	//
	// Separate from the priority write because the two are computed from
	// different inputs and either can be recomputed without the other.
	SetSLA(ctx context.Context, fingerprint string, d model.Derived) error
	// SetPriority persists the computed priority and reason code.
	SetPriority(ctx context.Context, fingerprint string, p model.Priority, reason *model.ReasonCode) error

	// PreviousRun returns the run of the same kind immediately before seq, or a
	// zero Run when there is none. Deltas compare same-kind runs only: an
	// advisory rescan that touched six repositories against a full sweep
	// produces a delta that looks like a catastrophe or a miracle, and is
	// neither (VM-F-14).
	PreviousRun(ctx context.Context, kind RunKind, beforeSeq int64) (Run, error)

	// SaveReport records an issued report. Reports are immutable: re-issuing
	// the same content for the same anchor is idempotent, and changing a
	// report means issuing a new one that supersedes it (VM-ADR-15).
	SaveReport(ctx context.Context, r Report) error
	// GetReport returns an issued report.
	GetReport(ctx context.Context, id string) (Report, error)
	// ReportsForRun lists the reports anchored to a run.
	ReportsForRun(ctx context.Context, runID string) ([]Report, error)
	// SupersededBy returns the report that replaces id, if one has been
	// issued (VM-UI-F-1108).
	//
	// Derived from the `supersedes` column rather than stored on the report
	// being replaced. A stored back-pointer would mean UPDATING an issued
	// report, which is a hole in immutability, and it would be a second copy
	// of a fact that can disagree with the first.
	//
	// At most one: a report superseded twice is a fork in the lineage with no
	// defined winner, and VM-UI-F-1108 requires the relationship to be
	// STATED, which cannot be done when there are two of them. Both backends
	// refuse the second.
	SupersededBy(ctx context.Context, id string) (Report, bool, error)

	// --- Tickets (VM-AD §13.2) ---
	//
	// The local record is the primary idempotency mechanism; the backend query
	// is the reconciliation fallback. Both are needed: without the record every
	// run re-queries the tracker, and without the fallback a lost record
	// produces a duplicate ticket.

	// SaveTicket records or updates a finding's ticket. It is keyed on the
	// fingerprint, which is what makes creation idempotent (VM-F-804).
	SaveTicket(ctx context.Context, t Ticket) error
	// GetTicket returns a finding's ticket record, if one is known.
	GetTicket(ctx context.Context, fingerprint string) (Ticket, bool, error)
	// DeleteTicket removes the local record. The ticket in the backend is
	// untouched: this is how the record is discarded when it is known stale.
	DeleteTicket(ctx context.Context, fingerprint string) error
	// CloseTicket records that a finding's ticket was closed (VM-F-811).
	CloseTicket(ctx context.Context, fingerprint string, at time.Time) error

	// --- Per-repository remediation lock (VM-AD §7.3, VM-F-503) ---
	//
	// Remediation is parallel across repositories and strictly serialised
	// within one. Acquisition order is repo lock OUTER, finding leases INNER,
	// and a repository's findings are batched under one acquisition: fixed
	// ordering makes deadlock impossible, and batching holds the lock once per
	// repository per attempt rather than once per finding.

	// AcquireRepoLock claims a repository for a worker until expiresAt. It is
	// reentrant for the current owner, which extends the expiry. It reclaims an
	// expired lock rather than waiting for the sweeper.
	AcquireRepoLock(ctx context.Context, repo, owner string, expiresAt time.Time) error
	// AcquireRepoLockAt is AcquireRepoLock with an explicit now, so expiry is
	// testable without sleeping.
	AcquireRepoLockAt(ctx context.Context, repo, owner string, expiresAt, now time.Time) error
	// ReleaseRepoLock releases a lock the caller owns. Releasing another
	// worker's lock is refused: it would silently reintroduce the concurrency
	// the lock exists to prevent, mid-remediation.
	ReleaseRepoLock(ctx context.Context, repo, owner string) error
	// GetRepoLock returns a repository's current lock, zero if unlocked.
	GetRepoLock(ctx context.Context, repo string) (RepoLock, error)
	// SweepExpiredRepoLocks reclaims locks whose holder died and returns how
	// many it released.
	SweepExpiredRepoLocks(ctx context.Context, now time.Time) (int, error)

	// --- Dependency manifests (VM-F-602) ---

	// RecordDeps writes a repository's dependency manifest for a run.
	//
	// The reverse-dependency index that first-party waves rest on has no other
	// source, and until Phase 11 closed OQ-P11-01 nothing wrote this table at
	// all: the schema had existed since migration 0001 and every wave test ran
	// over a hand-built index.
	RecordDeps(ctx context.Context, runID, repo string, deps []ModuleDep) error
	// Dependents returns the repositories depending on a module, from the most
	// recent run that recorded each.
	Dependents(ctx context.Context, module string) ([]ModuleDep, error)
	// AllDeps returns every recorded dependency from the latest run per
	// repository, for building the standing index (VM-F-612).
	AllDeps(ctx context.Context) ([]ModuleDep, error)

	// SetUpstreamFinding records which upstream finding a consumer is blocked
	// on (VM-F-604).
	//
	// Without it a blocked finding says "blocked" and names nothing: the
	// consumer cannot discover what it is waiting for, and neither can anyone
	// reading the report.
	SetUpstreamFinding(ctx context.Context, fingerprint, upstream string) error

	// SecretPaths returns the files in a repository that currently hold an
	// unresolved secret finding (VM-F-854).
	//
	// "Currently" is the load-bearing word: a rotated credential's finding is
	// resolved, and its file is ordinary again. A list that included resolved
	// findings would freeze a file out of automated remediation for ever,
	// which is how a control becomes something people route around.
	SecretPaths(ctx context.Context, repo string) ([]string, error)

	// --- Remediation pull requests (VM-AD §11, VM-F-501/502) ---

	// SaveRemediationPR records or updates a fix group's pull request.
	SaveRemediationPR(ctx context.Context, pr RemediationPR) error
	// GetRemediationPR returns the pull request for a branch, if any.
	GetRemediationPR(ctx context.Context, branch string) (RemediationPR, bool, error)
	// RemediationPRForFinding returns the open pull request addressing a
	// finding, if any. This is what tells the settle path there is a pull
	// request to close when a finding is fixed elsewhere.
	RemediationPRForFinding(ctx context.Context, fingerprint string) (RemediationPR, bool, error)
	// CloseRemediationPR marks a pull request closed. merged distinguishes a
	// pull request that landed from one a human closed, which is the
	// difference between MERGED and DECLINED (VM-F-545).
	CloseRemediationPR(ctx context.Context, branch string, at time.Time, merged bool) error
	// OpenRemediationPRs returns a repository's open pull request records.
	OpenRemediationPRs(ctx context.Context, repo string) ([]RemediationPR, error)
	// ConfirmRemediationPR records that a pull request's state was established
	// by authoritative word at this time — a verified delivery about it, or a
	// successful query (OQ-P12-01).
	ConfirmRemediationPR(ctx context.Context, branch string, at time.Time) error
	// UnconfirmedRemediationPRs returns open pull requests whose state has not
	// been confirmed since `since`, oldest first, at most limit.
	//
	// This is what replaces polling every open pull request on every sweep:
	// reconciliation asks about what nothing has vouched for recently, in a
	// bounded batch, oldest first so nothing starves.
	UnconfirmedRemediationPRs(ctx context.Context, repo string, since time.Time, limit int) ([]RemediationPR, error)

	// Runs lists runs newest first, optionally of one kind, for the history
	// views (VM-UI-F-301). Cursor is a sequence number, not an offset.
	Runs(ctx context.Context, q RunQuery) ([]Run, error)
	// RemediationPRsForFinding returns EVERY pull request that has carried a
	// finding, open or closed.
	//
	// Every one, because the attempt history is what a reader needs: showing
	// only the open one hides that two earlier attempts were declined
	// (VM-UI-F-508).
	RemediationPRsForFinding(ctx context.Context, fingerprint string) ([]RemediationPR, error)

	// --- The interface query surface (VM-UI-F-402/403/408, UI-ADR-06) ---

	// Search returns one filtered, sorted, cursor-paginated page.
	//
	// Separate from ListFindings, which is the pipeline's query: the pipeline
	// asks for a repository's open findings and processes all of them, while
	// the interface asks narrow questions of the whole history and shows a
	// page. One method serving both would make every pipeline caller pass
	// pagination it does not want, and would tempt a reader into fetching the
	// whole corpus to filter it client-side — which is what VM-UI-F-402
	// forbids.
	Search(ctx context.Context, q SearchQuery) (Page, error)
	// Facets counts each filter option under the OTHER active filters
	// (VM-UI-F-408). An aggregate query, not a count of the returned page.
	Facets(ctx context.Context, q SearchQuery) (FacetCounts, error)

	// --- Exploitation intelligence (OQ-AUDIT-01(b)) ---

	// SaveIntel records what the feeds said, keyed by identifier. Repeated
	// saves for one identifier overwrite: a later fetch is a better answer,
	// and keeping a history of feed snapshots is a different feature.
	SaveIntel(ctx context.Context, rows []Intel) error
	// IntelFor returns what is known about these identifiers. Identifiers with
	// no row are OMITTED, never zero-filled: the caller must be able to tell
	// "not looked up" from "looked up and negligible".
	IntelFor(ctx context.Context, ids []string) (map[string]Intel, error)
	// --- Secret reviews: allowlist proposals and removals (VM-F-856) ---

	// ApplyAllowlist records one run's allowlist evidence for a repository's
	// secrets: allowlisted maps a fingerprint to the evidence that only an
	// allowlist hid it, and observed lists the secret fingerprints the
	// ordinary scan reported. Decisions are PlanAllowlist's.
	ApplyAllowlist(ctx context.Context, runID, repo string, allowlisted map[string]model.Allowlist, observed []string) (AllowlistStats, error)
	// EscalateProposal moves an unreviewed proposal back to NEEDS_HUMAN and
	// marks it overdue. It stays decidable.
	EscalateProposal(ctx context.Context, fp string, at time.Time, cause string) error
	// DecideSuppression records a human's decision on an open proposal:
	// confirm suppresses the finding; reject keeps it open and stops the same
	// allowlist re-proposing it.
	DecideSuppression(ctx context.Context, fp string, confirm bool, by string, at time.Time) error
	// ConfirmRotation records a human's attestation that a removed secret was
	// rotated, and verifies the finding on that evidence.
	ConfirmRotation(ctx context.Context, fp, by string, at time.Time) error

	// IntelFreshness reports when each feed last answered for any identifier.
	// It is what lets a deployment-wide statement — "KEV is unavailable" — be
	// derived from what the store holds rather than asserted at startup.
	IntelFreshness(ctx context.Context) (IntelFreshness, error)

	// --- Webhook health (OQ-P12-01) ---

	// RecordWebhookDelivery notes that a VERIFIED delivery arrived.
	//
	// Recorded for every verified delivery, including those the framework then
	// ignores: the fact being recorded is that the path works, which an
	// irrelevant event proves just as well as a relevant one.
	RecordWebhookDelivery(ctx context.Context, at time.Time) error
	// WebhookHealth reports what is known about the delivery path.
	WebhookHealth(ctx context.Context) (WebhookHealth, error)

	// --- Run parent tickets (VM-AD §13.3 row 1) ---

	// SaveRunTicket records a run's parent ticket.
	SaveRunTicket(ctx context.Context, t RunTicket) error
	// GetRunTicket returns a run's parent ticket, if one exists.
	GetRunTicket(ctx context.Context, runID string) (RunTicket, bool, error)

	// TicketByRef reverse-resolves a backend reference to its ticket record.
	//
	// This is the durable path the mirror falls back to when its in-process
	// index misses — after a restart, every reference misses, and skipping
	// would leave the mirrored ticket silently un-updated (OQ-P8-01).
	TicketByRef(ctx context.Context, backend, ref string) (Ticket, bool, error)

	// --- Ticket operation queue (VM-F-812) ---

	// EnqueueTicketOp durably records an operation to retry.
	EnqueueTicketOp(ctx context.Context, op TicketOp) error
	// DueTicketOps returns operations whose backoff has expired, oldest first.
	DueTicketOps(ctx context.Context, now time.Time, limit int) ([]TicketOp, error)
	// CompleteTicketOp removes a successfully applied operation.
	CompleteTicketOp(ctx context.Context, id int64) error
	// RetryTicketOp records a failed attempt and schedules the next one.
	RetryTicketOp(ctx context.Context, id int64, next time.Time, lastErr string) error

	// --- Coverage age (OQ-P4-01) ---

	// RepoNames lists every registered repository, sorted.
	RepoNames(ctx context.Context) ([]string, error)
	// FleetCoverage returns each repository's coverage state, derived from its
	// scan history across runs of the given kind.
	FleetCoverage(ctx context.Context, kind RunKind, repos []string) ([]CoverageState, error)

	// --- GitHub discovery (migration 0016) ---
	GitHubStore
	// --- Scan queue (migration 0017) ---
	ScanQueue

	// Close releases resources.
	Close() error
}
