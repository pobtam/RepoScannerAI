package store

import (
	"time"

	"github.com/wanaware/vulnframework/internal/model"
)

// DispatchState is what the planner intended for a repository in a run.
type DispatchState string

const (
	// DispatchPlanned — in scope, not yet dispatched.
	DispatchPlanned DispatchState = "planned"
	// DispatchDispatched — a worker was started for it.
	DispatchDispatched DispatchState = "dispatched"
	// DispatchSkipped — deliberately not dispatched; SkipReason says why.
	DispatchSkipped DispatchState = "skipped"
)

// Valid reports whether d is a member of the closed enumeration.
func (d DispatchState) Valid() bool {
	return d == DispatchPlanned || d == DispatchDispatched || d == DispatchSkipped
}

// Skip reasons. They are an enumeration rather than free text because the gaps
// view groups by them, and "budget" spelled three ways is three problems.
const (
	// SkipBudgetExhausted — the API rate budget could not fund the scan
	// (VM-AD §7.2). Deliberate, and the run is expected to resume it next time.
	SkipBudgetExhausted = "budget_exhausted"
	// SkipConcurrencyCap — the run hit its concurrency ceiling.
	SkipConcurrencyCap = "concurrency_cap"
	// SkipFiltered — excluded by the repository selector.
	SkipFiltered = "filtered"
	// SkipArchived — the repository is archived.
	SkipArchived = "archived"
	// SkipNeverDispatched — planned, never picked up. Not a deliberate skip:
	// this is the one that means something went wrong in dispatch itself.
	SkipNeverDispatched = "never_dispatched"
	// CauseWorkerNoResult — dispatched, but the worker produced nothing.
	CauseWorkerNoResult = "worker_produced_no_result"
)

// PlanEntry is one repository's place in a run's planned scope.
type PlanEntry struct {
	RunID        string        `json:"run_id"`
	Repo         string        `json:"repo"`
	State        DispatchState `json:"dispatch_state"`
	SkipReason   string        `json:"skip_reason,omitempty"`
	PlannedAt    time.Time     `json:"planned_at"`
	DispatchedAt *time.Time    `json:"dispatched_at,omitempty"`
}

// CloseStats summarises what closing a run recorded.
type CloseStats struct {
	// Produced counts repositories that reported a scan result.
	Produced int
	// NotDispatched counts planned repositories whose scan never started.
	NotDispatched int
	// NoResult counts repositories that were dispatched and produced nothing.
	NoResult int
	// SkipReasons counts the deliberate skips by reason, so a run summary can
	// say "twelve repositories deferred for budget" rather than "twelve gaps".
	SkipReasons map[string]int
}

// Lease is a claim on a finding while remediation is in flight (VM-AD §6.2).
type Lease struct {
	Fingerprint string     `json:"fingerprint"`
	Owner       string     `json:"lease_owner"`
	ExpiresAt   *time.Time `json:"lease_expires_at"`
}

// Held reports whether the lease is currently claimed.
func (l Lease) Held() bool { return l.Owner != "" }

// Expired reports whether the lease has lapsed as of now.
func (l Lease) Expired(now time.Time) bool {
	return l.Held() && l.ExpiresAt != nil && !now.Before(*l.ExpiresAt)
}

// The planning and lease methods live on Store; both backends implement them
// and both are held to the same conformance suite.

// planCloseAction decides what a planned repository that produced no scan
// result should be recorded as.
//
// Three different operational problems, kept apart on purpose: a deliberate
// skip is expected and self-explaining, a never-dispatched repository means
// dispatch itself failed, and a dispatched-but-silent repository means a worker
// died. Folding them into 'failed' would merge them into one unactionable
// number (OQ-P2-02).
func planCloseAction(e PlanEntry) (model.ScanOutcome, string) {
	switch e.State {
	case DispatchSkipped:
		reason := e.SkipReason
		if reason == "" {
			reason = SkipFiltered
		}
		return model.ScanNotDispatched, reason
	case DispatchDispatched:
		return model.ScanNoResult, CauseWorkerNoResult
	default:
		return model.ScanNotDispatched, SkipNeverDispatched
	}
}
