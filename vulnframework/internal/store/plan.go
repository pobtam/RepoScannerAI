package store

import (
	"fmt"

	"github.com/wanaware/vulnframework/internal/model"
)

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
	// Category decides the residual warning a verification carries
	// (OQ-AUDIT-02). Carried here so the decision is made once, in the shared
	// pure function, rather than looked up separately by each backend — which
	// is how the two came to disagree about state history in Phase 2.
	Category model.Category
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

	// Category travels with the action so a backend applying it does not have
	// to re-derive anything.
	Category model.Category

	// ResidualDetail is the warning a verification at this finding's
	// fingerprint granularity must carry, empty where the granularity hides
	// nothing (OQ-AUDIT-02). Computed here so both backends word it
	// identically.
	ResidualDetail string

	// RetainedUnverified marks a finding that would have verified had the scan
	// succeeded. This is the count VM-F-216 requires reported alongside a gap.
	RetainedUnverified bool

	// VerificationReason records how the finding verified, for honest
	// attribution (VM-AD §6.1.1). Only meaningful when Verify is set.
	VerificationReason model.VerificationReason

	// SecretRemoved marks a secret a complete scan no longer sees. It is NOT
	// verified: removal from the files is not remediation, the secret is
	// still in history, and the credential is live until rotated (VM-F-856).
	// It stays open until a human confirms rotation.
	SecretRemoved bool
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
	scanSucceeded := outcome.Succeeded()

	actions := make([]ReconcileAction, 0, len(absent))
	for _, f := range absent {
		// A resolved finding is already settled; absence tells us nothing new.
		if model.PartitionOf(f.State) == model.PartitionResolved {
			continue
		}

		a := ReconcileAction{Fingerprint: f.Fingerprint, Category: f.Category}

		// Disappearance is the universal verification trigger (VM-AD §6.1.1):
		// any unresolved state with a legal edge to VERIFIED verifies when a
		// qualifying scan no longer observes the finding. Reaching VERIFIED only
		// from MERGED would leave every externally fixed finding open for ever,
		// and the open count would drift permanently away from reality.
		canVerify := model.CanTransition(f.State, model.Verified)

		switch {
		case scanSucceeded && f.Category == model.CategorySecret:
			// A secret is never verified by disappearing (VM-F-856). Flag it
			// as not re-observed, and record the removal for a human to
			// confirm rotation against.
			a.SecretRemoved = true
			a.NotReobserved = true

		case scanSucceeded && canVerify:
			a.Verify = true
			a.VerificationReason = model.VerificationReasonFor(f.State)
			// A verification that could be hiding a live same-file twin says
			// so (OQ-AUDIT-02). Decided here rather than in either backend so
			// the wording cannot diverge.
			a.ResidualDetail = model.ResidualWarning(f.Category)

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

// AllowlistInput is what PlanAllowlist needs to know about one secret finding.
type AllowlistInput struct {
	Fingerprint string
	State       model.State
	// Proposal is the finding's existing proposal record, if any.
	Proposal *model.SuppressionProposal
	// Allowlisted is set when this run found the secret only by looking past
	// the repository's allowlist.
	Allowlisted *model.Allowlist
	// Observed is set when this run's ordinary scan reported the secret — the
	// allowlist, if there was one, no longer hides it.
	Observed bool
}

// AllowlistAction is what one run's allowlist evidence implies for a finding.
type AllowlistAction struct {
	Fingerprint string
	// Propose opens a new proposal with this evidence.
	Propose *model.Allowlist
	// Withdraw closes the open (or confirmed) proposal: the allowlist stopped
	// hiding the secret.
	Withdraw bool
	// To is the state to move to, or empty for none.
	To model.State
}

// PlanAllowlist decides what allowlist evidence implies, for both backends.
//
// An allowlisted secret becomes a suppression PROPOSAL: anyone with commit
// access can write an allowlist, so it waits for a human rather than closing
// itself. A secret the ordinary scan sees again withdraws the proposal and
// comes back, whether the proposal was pending or already confirmed. A human
// rejection holds while the allowlist configuration is unchanged; a changed
// configuration is a new proposal.
func PlanAllowlist(in []AllowlistInput) []AllowlistAction {
	var out []AllowlistAction
	for _, f := range in {
		p := f.Proposal
		switch {
		case f.Observed && p != nil && (p.Status.Open() || p.Status == model.ProposalConfirmed):
			a := AllowlistAction{Fingerprint: f.Fingerprint, Withdraw: true}
			if f.State == model.FPCandidate || f.State == model.Suppressed {
				a.To = model.NeedsHuman
			}
			out = append(out, a)

		case f.Allowlisted != nil:
			fresh := p == nil || p.Status == model.ProposalWithdrawn ||
				(p.Status == model.ProposalRejected && changedAllowlist(p.Allowlist, *f.Allowlisted))
			if !fresh {
				continue
			}
			if f.State == model.Suppressed {
				// Already suppressed by a human with no allowlist involved;
				// the allowlist agrees, and there is nothing to propose.
				continue
			}
			a := AllowlistAction{Fingerprint: f.Fingerprint, Propose: f.Allowlisted}
			if model.CanTransition(f.State, model.FPCandidate) {
				a.To = model.FPCandidate
			}
			out = append(out, a)
		}
	}
	return out
}

func changedAllowlist(old, now model.Allowlist) bool {
	return old.Mechanism != now.Mechanism || old.Path != now.Path || old.ConfigSHA256 != now.ConfigSHA256
}

// AllowlistStats summarises an allowlist pass.
type AllowlistStats struct {
	Proposed  int `json:"proposed"`
	Withdrawn int `json:"withdrawn"`
}

// ProposalCause words the transition into FALSE_POSITIVE_CANDIDATE, for both
// backends.
func ProposalCause(a model.Allowlist, runID string) string {
	desc := ""
	if a.Description != "" {
		desc = fmt.Sprintf(", %q", a.Description)
	}
	return fmt.Sprintf("secret still present but allowlisted by %s (%s%s) in %s: suppression proposed, awaiting a human",
		a.Path, a.Mechanism, desc, runID)
}

// WithdrawalCause words the transition back to NEEDS_HUMAN.
func WithdrawalCause(p model.SuppressionProposal, runID string) string {
	return fmt.Sprintf("allowlist %s (%s) no longer hides this secret in %s: proposal withdrawn",
		p.Path, p.Mechanism, runID)
}

// decidable checks a human decision can be taken on a proposal.
func decidable(fp string, p model.SuppressionProposal, exists bool, by string) error {
	if by == "" {
		return fmt.Errorf("store: a suppression decision must name the human who made it")
	}
	if !exists {
		return fmt.Errorf("%w: no suppression proposal for %q", ErrNotFound, fp)
	}
	if !p.Status.Open() {
		return fmt.Errorf("store: the suppression proposal for %s is %s, not awaiting a decision", fp, p.Status)
	}
	return nil
}

// decisionTransition is the state change a human decision implies. A
// confirmation suppresses; a rejection of a proposal still sitting as a
// candidate returns it to the queue, where policy escalates it again as the
// secret it is. A rejection of an overdue proposal, already escalated, moves
// nothing.
func decisionTransition(state model.State, p model.SuppressionProposal, confirm bool, by string) (model.State, string) {
	if confirm {
		return model.Suppressed, fmt.Sprintf("suppression confirmed by %s (allowlisted by %s, %s)", by, p.Path, p.Mechanism)
	}
	if state == model.FPCandidate {
		return model.Triaged, fmt.Sprintf("suppression rejected by %s; allowlist %s does not make this secret safe", by, p.Path)
	}
	return "", ""
}

// rotatable checks a rotation can be confirmed for a finding.
func rotatable(fp string, cat model.Category, state model.State, removed bool, by string) error {
	if by == "" {
		return fmt.Errorf("store: a rotation confirmation must name the human who made it")
	}
	if cat != model.CategorySecret {
		return fmt.Errorf("store: %s is a %s finding; rotation applies only to secrets", fp, cat)
	}
	if !removed {
		return fmt.Errorf("store: %s is still in the scanned files (or was never marked removed); "+
			"confirm rotation after the secret is gone from the files, or allowlist a rotated value instead", fp)
	}
	if !model.CanTransition(state, model.Verified) {
		return fmt.Errorf("store: %s is %s, which cannot be verified", fp, state)
	}
	return nil
}

// RotationCause words a confirmed rotation.
func RotationCause(by string, r model.SecretRemoval) string {
	return fmt.Sprintf("rotation confirmed by %s; the secret left the scanned files in %s", by, r.Run)
}
