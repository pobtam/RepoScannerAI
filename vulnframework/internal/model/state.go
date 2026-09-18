package model

import (
	"fmt"
	"sort"
	"time"
)

// State is the lifecycle state of a finding. Closed enumeration (VM-F-151,
// VM-AD §6).
type State string

const (
	Detected        State = "DETECTED"
	Triaged         State = "TRIAGED"
	AutoRemediating State = "AUTO_REMEDIATING"
	PROpen          State = "PR_OPEN"
	Merged          State = "MERGED"
	Verified        State = "VERIFIED"
	BlockedUpstream State = "BLOCKED_UPSTREAM"
	NeedsHuman      State = "NEEDS_HUMAN"
	FPCandidate     State = "FALSE_POSITIVE_CANDIDATE"
	Suppressed      State = "SUPPRESSED"
	Declined        State = "DECLINED"
	WontFix         State = "WONT_FIX"
	Regressed       State = "REGRESSED"
)

// AllStates is the closed enumeration, in the order declared by VM-AD §6.
var AllStates = []State{
	Detected, Triaged, AutoRemediating, PROpen, Merged, Verified,
	BlockedUpstream, NeedsHuman, FPCandidate, Suppressed, Declined,
	WontFix, Regressed,
}

var stateSet = func() map[State]bool {
	m := make(map[State]bool, len(AllStates))
	for _, s := range AllStates {
		m[s] = true
	}
	return m
}()

// Valid reports whether s is a member of the closed enumeration.
func (s State) Valid() bool { return stateSet[s] }

func (s State) String() string { return string(s) }

// Partition is the resolution bucket a state belongs to (VM-F-159).
type Partition string

const (
	// PartitionResolved — the risk is gone or accepted as absent.
	PartitionResolved Partition = "resolved"
	// PartitionPendingVerification — the fix shipped but no successful scan has
	// yet confirmed the finding absent.
	PartitionPendingVerification Partition = "pending_verification"
	// PartitionUnresolved — the vulnerability is still present.
	PartitionUnresolved Partition = "unresolved"
)

// statePartition defines the partition once (VM-F-159) so that reporting,
// ticketing, metrics and any user interface cannot disagree about what
// "resolved" means.
//
// DECLINED is unresolved: a reviewer rejecting an automated fix does not remove
// the vulnerability. MERGED is its own partition because it is genuinely
// neither — counting it resolved would let a bad patch close the record before
// verification, and counting it unresolved overstates outstanding work
// (VM-OQ-09 remains open on how headline figures present it; this partition is
// the structural answer that keeps the question askable).
var statePartition = map[State]Partition{
	Verified:   PartitionResolved,
	Suppressed: PartitionResolved,

	Merged: PartitionPendingVerification,

	Detected:        PartitionUnresolved,
	Triaged:         PartitionUnresolved,
	AutoRemediating: PartitionUnresolved,
	PROpen:          PartitionUnresolved,
	BlockedUpstream: PartitionUnresolved,
	NeedsHuman:      PartitionUnresolved,
	FPCandidate:     PartitionUnresolved,
	Regressed:       PartitionUnresolved,
	Declined:        PartitionUnresolved,
	WontFix:         PartitionUnresolved,
}

// PartitionOf returns the resolution partition for s. It panics on an unknown
// state: a state absent from the partition map is a programming error that must
// not reach a report, where it would silently vanish from every total.
func PartitionOf(s State) Partition {
	p, ok := statePartition[s]
	if !ok {
		panic(fmt.Sprintf("model: state %q has no partition; every state must be partitioned (VM-F-159)", s))
	}
	return p
}

// IsResolved reports whether s is in the resolved partition.
func IsResolved(s State) bool { return PartitionOf(s) == PartitionResolved }

// IsUnresolved reports whether s is in the unresolved partition.
// MERGED is neither resolved nor unresolved; see PartitionOf.
func IsUnresolved(s State) bool { return PartitionOf(s) == PartitionUnresolved }

// StatesInPartition returns the states belonging to p, sorted for determinism.
func StatesInPartition(p Partition) []State {
	var out []State
	for _, s := range AllStates {
		if statePartition[s] == p {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Actor is the party that caused a state change (VM-F-153).
type Actor string

const (
	ActorScanWorker   Actor = "scanworker"
	ActorTriage       Actor = "triage"
	ActorOrchestrator Actor = "orchestrator"
	ActorWorker       Actor = "worker"
	ActorHuman        Actor = "human"
)

// Trigger names the event that authorises a transition, per the VM-AD §6.1
// transition table.
type Trigger string

const (
	TriggerFirstObservation Trigger = "first_observation"
	TriggerTriageComplete   Trigger = "triage_complete"
	// TriggerRemediationDispatched — a fix attempt has STARTED for this
	// finding, on the strength of policy's auto_remediate decision.
	//
	// The trigger is dispatch and not the decision (OQ-AUDIT-05). AUTO_REMEDIATING
	// is the only lease-bound state (VM-AD §6.2): a finding placed there by a
	// decision alone holds a lease nobody owns, which policy rule 2 then skips
	// as in progress and the lease sweeper cannot see. The decision marks work
	// claimable; entering the state is what claiming it looks like.
	TriggerRemediationDispatched Trigger = "remediation_dispatched"
	TriggerPolicyTicket          Trigger = "policy_open_ticket_or_escalate"
	TriggerPolicyDefer           Trigger = "policy_defer_upstream"
	TriggerTriageNomination      Trigger = "triage_nomination"
	TriggerPRCreated             Trigger = "pull_request_created"
	TriggerAttemptFailed         Trigger = "attempt_failed"
	TriggerLeaseExpiry           Trigger = "lease_expiry"
	TriggerMergeWebhook          Trigger = "merge_webhook"
	TriggerClosedUnmerged        Trigger = "closed_unmerged"
	TriggerNotObserved           Trigger = "post_merge_scan_absent"
	TriggerStillObserved         Trigger = "post_merge_scan_present"
	TriggerUpstreamPublished     Trigger = "upstream_published"
	// TriggerRemediationLinkLost — the pull request record for a PR_OPEN
	// finding is gone, so no state-sync can ever discover what became of it
	// (VM-AD §6.1.2). The finding returns to the queue; re-planning derives the
	// same branch from the same fix group and adopts the existing pull request
	// rather than opening a second one (VM-F-502).
	TriggerRemediationLinkLost Trigger = "remediation_link_lost"
	// TriggerWaveExcluded — the upstream fix shipped but this consumer cannot
	// be advanced automatically: a replace directive (VM-F-608) or a version
	// too far behind the fleet (VM-F-613). It is waiting for something that
	// has already happened (VM-AD §6.1.4).
	TriggerWaveExcluded   Trigger = "wave_excluded"
	TriggerHumanApproval  Trigger = "human_approval"
	TriggerHumanRejection Trigger = "human_rejection"
	TriggerObservedAgain  Trigger = "observed_again"
	TriggerReentry        Trigger = "reentry"
	TriggerHumanReset     Trigger = "human_reset"

	// TriggerQualifyingScanAbsent is the universal verification trigger
	// (VM-AD §6.1.1): a qualifying scan no longer observes the finding.
	TriggerQualifyingScanAbsent Trigger = "qualifying_scan_absent"
)

// VerificationReason records how a finding came to be verified (VM-AD §6.1.1).
//
// There is one VERIFIED state; this keeps attribution honest, so a fleet report
// cannot claim the framework fixed something it merely watched disappear.
type VerificationReason string

const (
	// VerifiedByFrameworkMerge — the finding passed through MERGED: this
	// framework's remediation closed it.
	VerifiedByFrameworkMerge VerificationReason = "framework_merge"
	// VerifiedByUpstream — closed by a first-party upstream fix, via
	// BLOCKED_UPSTREAM.
	VerifiedByUpstream VerificationReason = "upstream"
	// VerifiedExternal — disappeared without the framework merging anything.
	// Someone else fixed it, or the code carrying it was deleted.
	VerifiedExternal VerificationReason = "external"
)

// AllVerificationReasons is the closed enumeration.
var AllVerificationReasons = []VerificationReason{
	VerifiedByFrameworkMerge, VerifiedByUpstream, VerifiedExternal,
}

// Valid reports whether r is a member of the closed enumeration.
func (r VerificationReason) Valid() bool {
	return r == VerifiedByFrameworkMerge || r == VerifiedByUpstream || r == VerifiedExternal
}

func (r VerificationReason) String() string { return string(r) }

// VerificationReasonFor returns the reason a finding in state `from` verifies
// by disappearance (VM-AD §6.1.1).
//
// Attribution follows the path the finding actually took: MERGED means this
// framework's pull request closed it; BLOCKED_UPSTREAM means an upstream
// first-party fix did; anything else means it went away without the framework
// merging anything, and claiming credit for that would be false.
func VerificationReasonFor(from State) VerificationReason {
	switch from {
	case Merged:
		return VerifiedByFrameworkMerge
	case BlockedUpstream:
		return VerifiedByUpstream
	default:
		return VerifiedExternal
	}
}

// edge is one legal transition in the normative table.
type edge struct {
	Trigger Trigger
	Actor   Actor
}

// transitions is the normative transition table (VM-AD §6.1). Every transition
// absent from this table is illegal and must be rejected with an error and a
// logged event (VM-F-152).
//
// The zero State ("") is the origin for creation: — → DETECTED.
var transitions = map[State]map[State]edge{
	"": {
		Detected: {TriggerFirstObservation, ActorScanWorker},
	},
	Detected: {
		Triaged: {TriggerTriageComplete, ActorTriage},
		// Disappearance is universal (VM-AD §6.1.3). A finding can be fixed
		// out of band between the scan that first saw it and the triage pass
		// that would have routed it — a dependency bot, an unrelated
		// refactor, a deleted repository. Leaving DETECTED out was the one
		// state where that went unnoticed.
		Verified: {TriggerQualifyingScanAbsent, ActorScanWorker},
	},
	Triaged: {
		AutoRemediating: {TriggerRemediationDispatched, ActorOrchestrator},
		NeedsHuman:      {TriggerPolicyTicket, ActorOrchestrator},
		BlockedUpstream: {TriggerPolicyDefer, ActorOrchestrator},
		FPCandidate:     {TriggerTriageNomination, ActorTriage},
		Verified:        {TriggerQualifyingScanAbsent, ActorScanWorker},
	},
	AutoRemediating: {
		PROpen:     {TriggerPRCreated, ActorWorker},
		NeedsHuman: {TriggerAttemptFailed, ActorWorker},
		Triaged:    {TriggerLeaseExpiry, ActorOrchestrator},
		// Verifying from here releases the lease: the work it was held for is
		// no longer needed (VM-AD §6.1.1).
		Verified: {TriggerQualifyingScanAbsent, ActorScanWorker},
	},
	PROpen: {
		Merged:   {TriggerMergeWebhook, ActorOrchestrator},
		Declined: {TriggerClosedUnmerged, ActorOrchestrator},
		// The pull request reference was lost, so nothing could otherwise move
		// this finding again: every other exit from PR_OPEN needs to know
		// which pull request it belongs to (VM-AD §6.1.2).
		Triaged: {TriggerRemediationLinkLost, ActorOrchestrator},
		// Verifying from here closes the now-moot pull request: the defect is
		// gone, so the change is no longer wanted (VM-AD §6.1.1).
		Verified: {TriggerQualifyingScanAbsent, ActorScanWorker},
	},
	Merged: {
		Verified: {TriggerNotObserved, ActorScanWorker},
		Triaged:  {TriggerStillObserved, ActorScanWorker},
	},
	BlockedUpstream: {
		// The upstream fix shipped, so the consumer's bump is claimable. It
		// returns to the QUEUE rather than to the lease-bound state: wave two
		// decides that the work can proceed, and a dispatch claims it
		// (OQ-AUDIT-05).
		Triaged:  {TriggerUpstreamPublished, ActorOrchestrator},
		Verified: {TriggerQualifyingScanAbsent, ActorScanWorker},
		// The fix shipped and this consumer still cannot be advanced. Without
		// this edge it waits for something that has already happened, for
		// ever (VM-AD §6.1.4).
		NeedsHuman: {TriggerWaveExcluded, ActorOrchestrator},
	},
	FPCandidate: {
		Suppressed: {TriggerHumanApproval, ActorHuman},
		Triaged:    {TriggerHumanRejection, ActorHuman},
	},
	Verified: {
		Regressed: {TriggerObservedAgain, ActorScanWorker},
	},
	Regressed: {
		Triaged:  {TriggerReentry, ActorOrchestrator},
		Verified: {TriggerQualifyingScanAbsent, ActorScanWorker},
	},
	NeedsHuman: {
		// A human reset returns the finding to the queue, exactly as it does
		// from DECLINED. Resetting straight into the lease-bound state would
		// hand the finding a lease nobody holds (OQ-AUDIT-05).
		Triaged:  {TriggerHumanReset, ActorHuman},
		Verified: {TriggerQualifyingScanAbsent, ActorScanWorker},
	},
	Declined: {
		// Human reset only for *remediation* (VM-F-154). No automated path
		// re-remediates a finding a reviewer has rejected.
		Triaged: {TriggerHumanReset, ActorHuman},
		// Disappearance is different: the decline was a decision about
		// remediation, not about the facts. If a qualifying scan can no longer
		// see the defect, reality outranks the earlier decision, and holding
		// the finding open would record something untrue (VM-AD §6.1.1).
		Verified: {TriggerQualifyingScanAbsent, ActorScanWorker},
	},
	WontFix: {
		// Accepted risk, same reasoning as DECLINED: the acceptance was about
		// not acting, not about the vulnerability still being there.
		Verified: {TriggerQualifyingScanAbsent, ActorScanWorker},
	},
	// SUPPRESSED is deliberately absent. It is already resolved, and a
	// suppression is a human judgement that the finding was never real;
	// silently converting it to VERIFIED would overwrite that judgement with a
	// machine's (VM-AD §6.1.1).
}

// ScanOutcome is the per-repository outcome of the scan that informs a
// transition (VM-AD §4.2 repo_scan_results.outcome).
type ScanOutcome string

const (
	ScanComplete ScanOutcome = "complete"
	ScanPartial  ScanOutcome = "partial"
	ScanFailed   ScanOutcome = "failed"

	// ScanNotDispatched — the scan never started, either because the planner
	// deliberately skipped the repository (budget, quota, filter) or because it
	// was never picked up. Coverage is measured against planned scope, so an
	// in-scope repository that never ran must appear as a gap rather than as
	// silently clean (OQ-P2-02).
	ScanNotDispatched ScanOutcome = "not_dispatched"

	// ScanNoResult — a worker was dispatched and produced nothing. The scan
	// started and its result was lost, which is a different operational problem
	// from never starting, and from a tool failing.
	ScanNoResult ScanOutcome = "no_result"

	// ScanOutcomeUnknown is the zero value: no scan outcome supplied.
	ScanOutcomeUnknown ScanOutcome = ""
)

// AllScanOutcomes is the closed enumeration.
var AllScanOutcomes = []ScanOutcome{
	ScanComplete, ScanPartial, ScanFailed, ScanNotDispatched, ScanNoResult,
}

// Succeeded reports whether an outcome qualifies a scan to verify findings by
// their absence (VM-ADR-12, VM-AD §6.1.1).
//
// Only a complete scan qualifies. This is the single predicate every caller
// must use: defining "successful" in more than one place is how the guard comes
// to mean different things in reconciliation and in reporting.
func (o ScanOutcome) Succeeded() bool { return o == ScanComplete }

// IsGap reports whether an outcome represents lost coverage.
func (o ScanOutcome) IsGap() bool {
	return o == ScanPartial || o == ScanFailed || o == ScanNotDispatched || o == ScanNoResult
}

// TransitionContext carries the evidence and provenance for a state change
// (VM-F-153).
type TransitionContext struct {
	Actor Actor
	Cause string
	At    time.Time

	// ScanOutcome is the outcome of the scan of this finding's repository in
	// the run driving the transition. It is required for any transition into
	// VERIFIED (VM-ADR-12) and ignored otherwise.
	ScanOutcome ScanOutcome
}

// IllegalTransitionError reports a transition absent from the normative table.
//
// The model does not log — it has no dependencies (VM-AD §3). The error carries
// the full context VM-F-152 requires to be logged, and the caller (orchestrator,
// Phase 4) is responsible for emitting it.
type IllegalTransitionError struct {
	From  State
	To    State
	Actor Actor
	Cause string
}

func (e *IllegalTransitionError) Error() string {
	from := string(e.From)
	if from == "" {
		from = "<new>"
	}
	return fmt.Sprintf("illegal state transition %s -> %s (actor=%s cause=%q)", from, e.To, e.Actor, e.Cause)
}

// UnverifiedAbsenceError reports an attempt to verify a finding on the strength
// of an absence that a successful scan did not establish (VM-ADR-12, VM-F-160).
//
// Absence is not resolution. Without this guard a repository that stops scanning
// marks its entire finding set as verified: the fleet numbers improve, the risk
// does not, and the failure is invisible precisely because it looks like success.
type UnverifiedAbsenceError struct {
	From    State
	Outcome ScanOutcome
}

func (e *UnverifiedAbsenceError) Error() string {
	got := string(e.Outcome)
	if got == "" {
		got = "<none supplied>"
	}
	return fmt.Sprintf(
		"refusing %s -> VERIFIED: verification requires a successful scan of the repository, got outcome %s (VM-ADR-12: absence is not resolution)",
		e.From, got)
}

// CanTransition reports whether from -> to appears in the normative transition
// table. It does not evaluate guards; use ValidateTransition for that.
func CanTransition(from, to State) bool {
	_, ok := transitions[from][to]
	return ok
}

// TransitionEdge returns the trigger and actor the table associates with
// from -> to.
func TransitionEdge(from, to State) (Trigger, Actor, bool) {
	e, ok := transitions[from][to]
	return e.Trigger, e.Actor, ok
}

// AllowedTransitions returns the states reachable from s in one legal step,
// sorted for determinism.
func AllowedTransitions(s State) []State {
	var out []State
	for to := range transitions[s] {
		out = append(out, to)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ErrWrongActor reports a transition attempted by an actor the table does not
// authorise for it (VM-F-152).
//
// Until Phase 10 the actor column was documentation: validation checked the
// edge and the scan-outcome guard, and took the caller's word for who it was.
// That was tolerable while every actor was framework code written in this
// repository. It stopped being tolerable when an agent joined the set — the
// actor set is no longer uniformly trusted, and "convention, not control" is
// exactly the gap this system spends its effort closing everywhere else.
type ErrWrongActor struct {
	From, To State
	Actor    Actor
	Want     Actor
	Cause    string
}

func (e *ErrWrongActor) Error() string {
	return fmt.Sprintf(
		"transition %s -> %s is authorised for actor %q, not %q (actor=%q cause=%q). "+
			"The actor column of the VM-AD §6.1 table is enforced, not advisory: a caller cannot "+
			"authorise itself for a transition by claiming to be something else (VM-F-152)",
		e.From, e.To, e.Want, e.Actor, e.Actor, e.Cause)
}

// ActorFor returns the actor the table authorises for a transition.
func ActorFor(from, to State) (Actor, bool) {
	edges, ok := transitions[from]
	if !ok {
		return "", false
	}
	e, ok := edges[to]
	if !ok {
		return "", false
	}
	return e.Actor, true
}

// ValidateTransition checks a proposed state change against the normative
// transition table and the guards that table does not express.
//
// It returns *IllegalTransitionError for a transition absent from the table
// (VM-F-152) and *UnverifiedAbsenceError for a transition into VERIFIED that is
// not backed by a successful scan (VM-ADR-12).
func ValidateTransition(from, to State, ctx TransitionContext) error {
	if to != "" && !to.Valid() {
		return &IllegalTransitionError{From: from, To: to, Actor: ctx.Actor, Cause: ctx.Cause}
	}
	if from != "" && !from.Valid() {
		return &IllegalTransitionError{From: from, To: to, Actor: ctx.Actor, Cause: ctx.Cause}
	}
	if !CanTransition(from, to) {
		return &IllegalTransitionError{From: from, To: to, Actor: ctx.Actor, Cause: ctx.Cause}
	}
	// The actor column is enforced (OQ-P10a-02). A human may take any
	// transition — a person with access to the system can always correct it,
	// and pretending otherwise would just move the override somewhere less
	// visible — but no automated actor may take another's.
	if want, ok := ActorFor(from, to); ok && ctx.Actor != want && ctx.Actor != ActorHuman {
		return &ErrWrongActor{From: from, To: to, Actor: ctx.Actor, Want: want, Cause: ctx.Cause}
	}
	// Guard: absence is not resolution (VM-ADR-12, VM-F-160). A finding reaches
	// VERIFIED only where the scan that failed to observe it completed
	// successfully for that repository. A partial scan is not sufficient: the
	// lost signal may be precisely the one that would have observed it.
	if to == Verified && ctx.ScanOutcome != ScanComplete {
		return &UnverifiedAbsenceError{From: from, Outcome: ctx.ScanOutcome}
	}
	return nil
}

// StateTransition is the audit record of an applied state change (VM-F-153).
type StateTransition struct {
	Fingerprint string    `json:"fingerprint"`
	From        State     `json:"from_state,omitempty"`
	To          State     `json:"to_state"`
	Actor       Actor     `json:"actor"`
	Cause       string    `json:"cause,omitempty"`
	At          time.Time `json:"at"`
}

// ApplyTransition validates a proposed state change and, on success, returns
// the audit record the caller must persist (VM-F-153).
//
// It never mutates the finding: the orchestrator is the only component
// permitted to write findings.state (VM-AD §7.1), and keeping the decision pure
// lets every other component ask whether a transition is legal without being
// able to perform one.
func ApplyTransition(fingerprint string, from, to State, ctx TransitionContext) (StateTransition, error) {
	if err := ValidateTransition(from, to, ctx); err != nil {
		return StateTransition{}, err
	}
	at := ctx.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	return StateTransition{
		Fingerprint: fingerprint,
		From:        from,
		To:          to,
		Actor:       ctx.Actor,
		Cause:       ctx.Cause,
		At:          at.UTC(),
	}, nil
}
