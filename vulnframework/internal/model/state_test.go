package model_test

import (
	"errors"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
)

func ctx(actor model.Actor) model.TransitionContext {
	return model.TransitionContext{Actor: actor, Cause: "test", At: time.Unix(1757000000, 0).UTC()}
}

// legalTransitions is the normative table from VM-AD §6.1, transcribed
// independently of the implementation. If the two disagree, one of them is
// wrong and the gate fails.
var legalTransitions = []struct {
	from, to model.State
	actor    model.Actor
}{
	{"", model.Detected, model.ActorScanWorker},
	{model.Detected, model.Triaged, model.ActorTriage},
	{model.Triaged, model.AutoRemediating, model.ActorOrchestrator},
	{model.Triaged, model.NeedsHuman, model.ActorOrchestrator},
	{model.Triaged, model.BlockedUpstream, model.ActorOrchestrator},
	{model.Triaged, model.FPCandidate, model.ActorTriage},
	{model.AutoRemediating, model.PROpen, model.ActorWorker},
	{model.AutoRemediating, model.NeedsHuman, model.ActorWorker},
	{model.AutoRemediating, model.Triaged, model.ActorOrchestrator},
	{model.PROpen, model.Merged, model.ActorOrchestrator},
	{model.PROpen, model.Declined, model.ActorOrchestrator},
	{model.Merged, model.Verified, model.ActorScanWorker},
	{model.Merged, model.Triaged, model.ActorScanWorker},
	{model.BlockedUpstream, model.AutoRemediating, model.ActorOrchestrator},
	{model.FPCandidate, model.Suppressed, model.ActorHuman},
	{model.FPCandidate, model.Triaged, model.ActorHuman},
	{model.Verified, model.Regressed, model.ActorScanWorker},
	{model.Regressed, model.Triaged, model.ActorOrchestrator},
	{model.NeedsHuman, model.AutoRemediating, model.ActorHuman},
	{model.Declined, model.Triaged, model.ActorHuman},

	// Disappearance is the universal verification trigger (VM-AD §6.1.1).
	// SUPPRESSED is deliberately absent: it is already resolved, and a
	// suppression is a human judgement that the finding was never real.
	{model.Triaged, model.Verified, model.ActorScanWorker},
	{model.NeedsHuman, model.Verified, model.ActorScanWorker},
	{model.BlockedUpstream, model.Verified, model.ActorScanWorker},
	{model.AutoRemediating, model.Verified, model.ActorScanWorker},
	{model.PROpen, model.Verified, model.ActorScanWorker},
	{model.Regressed, model.Verified, model.ActorScanWorker},
	{model.Declined, model.Verified, model.ActorScanWorker},
	{model.WontFix, model.Verified, model.ActorScanWorker},
}

func TestEveryNormativeTransitionIsAccepted(t *testing.T) {
	for _, tc := range legalTransitions {
		c := ctx(tc.actor)
		// Verification requires a successful scan (VM-ADR-12); supply one for
		// the single edge that enters VERIFIED.
		if tc.to == model.Verified {
			c.ScanOutcome = model.ScanComplete
		}
		if err := model.ValidateTransition(tc.from, tc.to, c); err != nil {
			t.Errorf("normative transition %s -> %s rejected: %v", tc.from, tc.to, err)
		}
	}
}

func TestTransitionTableMatchesTheSpecificationExactly(t *testing.T) {
	legal := map[[2]model.State]bool{}
	for _, tc := range legalTransitions {
		legal[[2]model.State{tc.from, tc.to}] = true
	}

	// Every from/to pair over the full state set, plus the "" origin.
	froms := append([]model.State{""}, model.AllStates...)
	for _, from := range froms {
		for _, to := range model.AllStates {
			want := legal[[2]model.State{from, to}]
			if got := model.CanTransition(from, to); got != want {
				t.Errorf("CanTransition(%q, %q) = %v, want %v (VM-AD §6.1)", from, to, got, want)
			}
		}
	}
}

// TestIllegalTransitionsAreRejected is the Phase 0 gate clause on the state
// machine. Every transition absent from the table must be rejected with an
// error, never silently applied (VM-F-152).
func TestIllegalTransitionsAreRejected(t *testing.T) {
	legal := map[[2]model.State]bool{}
	for _, tc := range legalTransitions {
		legal[[2]model.State{tc.from, tc.to}] = true
	}

	froms := append([]model.State{""}, model.AllStates...)
	checked := 0
	for _, from := range froms {
		for _, to := range model.AllStates {
			if legal[[2]model.State{from, to}] {
				continue
			}
			checked++
			c := ctx(model.ActorOrchestrator)
			c.ScanOutcome = model.ScanComplete // deny the guard any credit for the rejection
			err := model.ValidateTransition(from, to, c)
			if err == nil {
				t.Errorf("illegal transition %q -> %q was accepted", from, to)
				continue
			}
			var ite *model.IllegalTransitionError
			if !errors.As(err, &ite) {
				t.Errorf("illegal transition %q -> %q: got %T, want *IllegalTransitionError", from, to, err)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no illegal transitions exercised; the table cannot be complete")
	}
	t.Logf("rejected %d illegal transitions", checked)
}

// TestSpecificIllegalTransitions names the ones that would be most damaging,
// so a regression reads as the requirement it broke rather than as a count.
func TestSpecificIllegalTransitions(t *testing.T) {
	cases := []struct {
		name     string
		from, to model.State
		why      string
	}{
		{"detected straight to verified", model.Detected, model.Verified, "skips triage, remediation and merge"},
		{"detected straight to merged", model.Detected, model.Merged, "no pull request was ever opened"},
		{"declined auto-remediated", model.Declined, model.AutoRemediating, "VM-F-154: a declined finding is never automatically re-remediated"},
		{"suppressed reopened automatically", model.Suppressed, model.Triaged, "suppression is a human decision to undo"},
		{"suppressed auto-verified", model.Suppressed, model.Verified, "VM-AD §6.1.1: a suppression is a human judgement the finding was never real; verifying it would overwrite that with a machine's"},
		{"verified straight back to triaged", model.Verified, model.Triaged, "re-observation must pass through REGRESSED (VM-F-105)"},
		{"detected verifies before triage", model.Detected, model.Verified, "a finding that has never been triaged has no verifiable claim to close"},
		{"false positive candidate auto-verified", model.FPCandidate, model.Verified, "it is awaiting a human decision"},
		{"triaged straight to pr open", model.Triaged, model.PROpen, "dispatch must pass through AUTO_REMEDIATING and take a lease"},
		{"same-state no-op", model.Triaged, model.Triaged, "a no-op transition would write a spurious audit record"},
		{"recreating an existing finding", "", model.Triaged, "creation only ever enters DETECTED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := ctx(model.ActorOrchestrator)
			c.ScanOutcome = model.ScanComplete
			if err := model.ValidateTransition(tc.from, tc.to, c); err == nil {
				t.Errorf("%s -> %s was accepted; it must be rejected (%s)", tc.from, tc.to, tc.why)
			}
		})
	}
}

func TestUnknownStatesAreRejected(t *testing.T) {
	c := ctx(model.ActorOrchestrator)
	if err := model.ValidateTransition(model.Triaged, "MADE_UP", c); err == nil {
		t.Error("transition to an unknown state was accepted")
	}
	if err := model.ValidateTransition("MADE_UP", model.Triaged, c); err == nil {
		t.Error("transition from an unknown state was accepted")
	}
}

// --- Gate: absence is not resolution (VM-ADR-12, VM-F-160) ------------------

// TestVerificationRequiresSuccessfulScan is the structural expression of
// VM-ADR-12. Without this guard, a repository that stops scanning marks its
// entire finding set verified: the fleet numbers improve, the risk does not,
// and the failure is invisible precisely because it looks like success.
func TestVerificationRequiresSuccessfulScan(t *testing.T) {
	tests := []struct {
		name    string
		outcome model.ScanOutcome
		wantOK  bool
	}{
		{"successful scan verifies", model.ScanComplete, true},
		{"failed scan does not verify", model.ScanFailed, false},
		{"partial scan does not verify", model.ScanPartial, false},
		{"no scan outcome supplied does not verify", model.ScanOutcomeUnknown, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := ctx(model.ActorScanWorker)
			c.ScanOutcome = tc.outcome
			err := model.ValidateTransition(model.Merged, model.Verified, c)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("MERGED -> VERIFIED after a complete scan was rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("MERGED -> VERIFIED was accepted on scan outcome %q; absence is not resolution (VM-ADR-12)", tc.outcome)
			}
			var uae *model.UnverifiedAbsenceError
			if !errors.As(err, &uae) {
				t.Fatalf("got %T (%v), want *UnverifiedAbsenceError", err, err)
			}
		})
	}
}

// TestRegressionPathIsAvailableFromVerified covers VM-F-105: a verified finding
// observed again becomes REGRESSED rather than being created anew.
func TestRegressionPathIsAvailableFromVerified(t *testing.T) {
	if err := model.ValidateTransition(model.Verified, model.Regressed, ctx(model.ActorScanWorker)); err != nil {
		t.Fatalf("VERIFIED -> REGRESSED rejected: %v", err)
	}
	if err := model.ValidateTransition(model.Regressed, model.Triaged, ctx(model.ActorOrchestrator)); err != nil {
		t.Fatalf("REGRESSED -> TRIAGED rejected: %v", err)
	}
}

// --- Apply ------------------------------------------------------------------

func TestApplyTransitionProducesAnAuditRecord(t *testing.T) {
	at := time.Date(2026, 9, 2, 3, 14, 22, 0, time.UTC)
	rec, err := model.ApplyTransition("a3f9c21e8b7d4056", model.Detected, model.Triaged,
		model.TransitionContext{Actor: model.ActorTriage, Cause: "triage complete", At: at})
	if err != nil {
		t.Fatalf("ApplyTransition: %v", err)
	}
	if rec.Fingerprint != "a3f9c21e8b7d4056" || rec.From != model.Detected || rec.To != model.Triaged {
		t.Errorf("unexpected record: %+v", rec)
	}
	// VM-F-153: timestamp, actor and cause are all recorded.
	if rec.Actor != model.ActorTriage || rec.Cause != "triage complete" || !rec.At.Equal(at) {
		t.Errorf("audit record lost provenance: %+v", rec)
	}
}

func TestApplyTransitionRejectsIllegalAndReturnsNoRecord(t *testing.T) {
	rec, err := model.ApplyTransition("fp", model.Declined, model.AutoRemediating, ctx(model.ActorOrchestrator))
	if err == nil {
		t.Fatal("DECLINED -> AUTO_REMEDIATING was applied; VM-F-154 forbids it")
	}
	if rec != (model.StateTransition{}) {
		t.Errorf("a rejected transition produced an audit record: %+v", rec)
	}
}

func TestApplyTransitionDefaultsTimestamp(t *testing.T) {
	rec, err := model.ApplyTransition("fp", model.Detected, model.Triaged,
		model.TransitionContext{Actor: model.ActorTriage})
	if err != nil {
		t.Fatalf("ApplyTransition: %v", err)
	}
	if rec.At.IsZero() {
		t.Error("audit record has no timestamp; VM-F-153 requires one")
	}
	if rec.At.Location() != time.UTC {
		t.Errorf("audit timestamp is not UTC: %v", rec.At.Location())
	}
}

// --- Partition (VM-F-159) ---------------------------------------------------

// TestEveryStateIsPartitionedExactlyOnce guards the partition being defined
// once and used consistently. A state missing from the partition would vanish
// from every total that reporting, ticketing and the interface compute.
func TestEveryStateIsPartitionedExactlyOnce(t *testing.T) {
	seen := map[model.State]int{}
	for _, p := range []model.Partition{
		model.PartitionResolved, model.PartitionPendingVerification, model.PartitionUnresolved,
	} {
		for _, s := range model.StatesInPartition(p) {
			seen[s]++
		}
	}
	for _, s := range model.AllStates {
		switch seen[s] {
		case 1:
		case 0:
			t.Errorf("state %s belongs to no partition (VM-F-159)", s)
		default:
			t.Errorf("state %s belongs to %d partitions, want exactly 1", s, seen[s])
		}
	}
}

func TestPartitionContents(t *testing.T) {
	// Transcribed from the normative table in VM-FR §5.3.
	want := map[model.State]model.Partition{
		model.Verified:        model.PartitionResolved,
		model.Suppressed:      model.PartitionResolved,
		model.Merged:          model.PartitionPendingVerification,
		model.Detected:        model.PartitionUnresolved,
		model.Triaged:         model.PartitionUnresolved,
		model.AutoRemediating: model.PartitionUnresolved,
		model.PROpen:          model.PartitionUnresolved,
		model.BlockedUpstream: model.PartitionUnresolved,
		model.NeedsHuman:      model.PartitionUnresolved,
		model.FPCandidate:     model.PartitionUnresolved,
		model.Regressed:       model.PartitionUnresolved,
		model.Declined:        model.PartitionUnresolved,
	}
	for s, wantP := range want {
		if got := model.PartitionOf(s); got != wantP {
			t.Errorf("PartitionOf(%s) = %s, want %s", s, got, wantP)
		}
	}
}

// TestDeclinedIsUnresolved is called out separately because it is the one an
// implementer is most likely to get wrong: a reviewer rejecting an automated
// fix does not remove the vulnerability.
func TestDeclinedIsUnresolved(t *testing.T) {
	if model.IsResolved(model.Declined) {
		t.Error("DECLINED counted as resolved; a rejected fix does not remove the vulnerability")
	}
	if !model.IsUnresolved(model.Declined) {
		t.Error("DECLINED must be in the unresolved partition")
	}
}

// TestMergedIsNeitherResolvedNorUnresolved guards the third partition. Counting
// MERGED as resolved lets a bad patch close the record before verification;
// counting it as unresolved overstates outstanding work.
func TestMergedIsNeitherResolvedNorUnresolved(t *testing.T) {
	if model.IsResolved(model.Merged) {
		t.Error("MERGED counted as resolved before a successful scan confirmed it")
	}
	if model.IsUnresolved(model.Merged) {
		t.Error("MERGED counted as unresolved; it is its own partition")
	}
	if got := model.PartitionOf(model.Merged); got != model.PartitionPendingVerification {
		t.Errorf("PartitionOf(MERGED) = %s, want %s", got, model.PartitionPendingVerification)
	}
}

func TestPartitionOfPanicsOnUnknownState(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("PartitionOf did not panic on an unpartitioned state; it would silently vanish from every total")
		}
	}()
	_ = model.PartitionOf("MADE_UP")
}

// --- Enumerations -----------------------------------------------------------

func TestStateEnumerationIsClosed(t *testing.T) {
	if !model.State("DETECTED").Valid() {
		t.Error("DETECTED should be valid")
	}
	for _, s := range []model.State{"", "detected", "Detected", "MADE_UP"} {
		if s.Valid() {
			t.Errorf("state %q should not be valid; the enumeration is closed (VM-F-151)", s)
		}
	}
}

func TestAllowedTransitionsIsSortedAndComplete(t *testing.T) {
	got := model.AllowedTransitions(model.Triaged)
	want := []model.State{model.AutoRemediating, model.BlockedUpstream, model.FPCandidate, model.NeedsHuman, model.Verified}
	if len(got) != len(want) {
		t.Fatalf("AllowedTransitions(TRIAGED) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AllowedTransitions(TRIAGED) = %v, want %v (sorted)", got, want)
		}
	}
}

func TestTransitionEdgeCarriesTriggerAndActor(t *testing.T) {
	trig, actor, ok := model.TransitionEdge(model.AutoRemediating, model.Triaged)
	if !ok {
		t.Fatal("AUTO_REMEDIATING -> TRIAGED missing from the table")
	}
	// The lease-expiry edge is what prevents a crashed worker stranding a
	// finding permanently (VM-F-158).
	if trig != model.TriggerLeaseExpiry {
		t.Errorf("trigger = %q, want %q", trig, model.TriggerLeaseExpiry)
	}
	if actor != model.ActorOrchestrator {
		t.Errorf("actor = %q, want %q", actor, model.ActorOrchestrator)
	}
}

// TestWontFixIsUnreachable documents a gap in the specification rather than
// asserting desired behaviour: WONT_FIX is declared in the VM-AD §6 enumeration
// but appears in no row of the §6.1 transition table, so no finding can enter
// it. Recorded as OQ-P0-01 in BUILD-LOG.md.
func TestWontFixIsUnreachable(t *testing.T) {
	// Note: WONT_FIX -> VERIFIED exists under §6.1.1, but nothing enters
	// WONT_FIX. The planned NEEDS_HUMAN -> WONT_FIX edit still has not landed.
	for _, from := range append([]model.State{""}, model.AllStates...) {
		if model.CanTransition(from, model.WontFix) {
			t.Fatalf("WONT_FIX is now reachable from %s — the specification gap (OQ-P0-01) has been resolved; "+
				"update BUILD-LOG.md and this test", from)
		}
	}
}
