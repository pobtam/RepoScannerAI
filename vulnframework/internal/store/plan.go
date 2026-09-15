package store

import "github.com/wanaware/vulnframework/internal/model"

// The decisions in this file are pure functions shared by every Store
// implementation. The invariants they encode — absence is not resolution, an
// existing fingerprint is observed rather than duplicated — must not be
// expressed twice, because an in-memory fake that enforces different rules than
// Postgres is worse than no fake at all: it makes every test that uses it a
// statement about the fake.

// UpsertDecision is what observing a fingerprint implies for its finding.
type UpsertDecision struct {
	// Create: the fingerprint has never been seen. The finding enters DETECTED.
	Create bool
	// Regress: the finding was VERIFIED and has been observed again. It
	// transitions to REGRESSED rather than being created anew (VM-F-105).
	Regress bool
}

// PlanUpsert decides what an observation implies for an existing finding.
//
// The central rule is that observing a known fingerprint records an observation
// against the existing finding; it never creates a second one (VM-F-104,
// VM-F-106). Findings reported by several tools share a fingerprint and merge
// into one record.
func PlanUpsert(current model.State, exists bool) UpsertDecision {
	if !exists {
		return UpsertDecision{Create: true}
	}
	if current == model.Verified {
		return UpsertDecision{Regress: true}
	}
	return UpsertDecision{}
}

// FindingState is the minimum a reconciliation needs to know about a finding.
type FindingState struct {
	Fingerprint string
	State       model.State
}

// ReconcileAction is what a reconciliation does to one absent finding.
type ReconcileAction struct {
	Fingerprint string

	// Verify transitions the finding to VERIFIED. Only ever set where the scan
	// completed successfully (VM-ADR-12).
	Verify bool

	// NotReobserved sets the derived flag: the finding was not observed by the
	// most recent applicable run while remaining unresolved (VM-F-161).
	NotReobserved bool

	// GapRunID links the finding to the coverage gap that explains its absence,
	// where one exists (VM-F-162). Empty where the scan succeeded and the
	// absence is genuine.
	GapRunID string

	// RetainedUnverified marks a finding that would have verified had the scan
	// succeeded. This is the count VM-F-216 requires reported alongside a gap.
	RetainedUnverified bool

	// VerificationReason records how the finding verified, for honest
	// attribution (VM-AD §6.1.1). Only meaningful when Verify is set.
	VerificationReason model.VerificationReason
}

// PlanReconcile decides what a run's outcome implies for the findings it did
// not observe.
//
// This function is where VM-ADR-12 lives. Absence is not resolution: a finding
// is verified only where the scan that failed to observe it completed
// successfully for that repository. Without this, a repository that stops
// scanning marks its entire finding set as verified — the fleet numbers
// improve, the risk does not, and the failure is invisible precisely because it
// looks like success.
//
// Findings observed by the run are not passed here; only the absent ones are.
func PlanReconcile(outcome ScanOutcome, absent []FindingState) []ReconcileAction {
	scanSucceeded := outcome == model.ScanComplete

	actions := make([]ReconcileAction, 0, len(absent))
	for _, f := range absent {
		// A resolved finding is already settled; absence tells us nothing new.
		if model.PartitionOf(f.State) == model.PartitionResolved {
			continue
		}

		a := ReconcileAction{Fingerprint: f.Fingerprint}

		// Disappearance is the universal verification trigger (VM-AD §6.1.1):
		// any unresolved state with a legal edge to VERIFIED verifies when a
		// qualifying scan no longer observes the finding. Reaching VERIFIED only
		// from MERGED would leave every externally fixed finding open for ever,
		// and the open count would drift permanently away from reality.
		canVerify := model.CanTransition(f.State, model.Verified)

		switch {
		case scanSucceeded && canVerify:
			a.Verify = true
			a.VerificationReason = model.VerificationReasonFor(f.State)

		case !scanSucceeded && canVerify:
			// The gate clause, unchanged and now covering every verifiable
			// state. The defect may well be gone, but a scan that did not
			// complete is not evidence of that. Retained, flagged, counted
			// against the gap — never verified.
			a.NotReobserved = true
			a.GapRunID = gapRunFor(outcome)
			a.RetainedUnverified = true

		default:
			// An unresolved state with no legal edge to VERIFIED — DETECTED,
			// which has not yet been triaged, and FALSE_POSITIVE_CANDIDATE,
			// which is awaiting a human. Flag, never close (VM-F-163).
			a.NotReobserved = true
			if !scanSucceeded {
				a.GapRunID = gapRunFor(outcome)
			}
		}
		actions = append(actions, a)
	}
	return actions
}

// gapRunFor returns a sentinel the caller replaces with the run identifier. It
// exists so PlanReconcile stays a pure function of the outcome while still
// expressing whether a gap link is warranted.
func gapRunFor(outcome ScanOutcome) string {
	if outcome == model.ScanComplete {
		return ""
	}
	return gapSentinel
}

// gapSentinel marks an action that should carry the reconciling run's
// identifier as its coverage-gap link.
const gapSentinel = "\x00gap"

// resolveGapLinks replaces the sentinel with the actual run identifier.
func resolveGapLinks(actions []ReconcileAction, runID string) []ReconcileAction {
	for i := range actions {
		if actions[i].GapRunID == gapSentinel {
			actions[i].GapRunID = runID
		}
	}
	return actions
}
