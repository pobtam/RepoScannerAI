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

// Repo is a repository in the fleet registry.
type Repo struct {
	Name           string   `json:"name"`
	Tier           int      `json:"tier"`
	Languages      []string `json:"languages"`
	Archived       bool     `json:"archived"`
	HasTestSuite   bool     `json:"has_test_suite"`
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

	// Close releases resources.
	Close() error
}
