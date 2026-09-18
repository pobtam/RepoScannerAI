package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// VM-AD §6.1.5 — the lease-bound state is entered only by a dispatch
// (OQ-AUDIT-05).
//
// The rule lives in the store rather than in its callers because three
// separate callers got it wrong in the same way: policy routing, wave two, and
// a human reset each put a finding into AUTO_REMEDIATING on the strength of a
// DECISION. A decision holds no lease, and a finding in that state with no
// lease is moved by nothing — policy rule 2 skips it as in progress, and the
// lease sweeper has no lease to expire. Asking callers to remember the
// invariant is how it was forgotten; refusing the write is how it stops.
//
// Both backends are held to this, because a rule enforced on one backend is a
// rule the other silently permits.

// leaseBoundFixture drives a finding to TRIAGED, the only state the
// lease-bound edge starts from.
func leaseBoundFixture(t *testing.T, s store.Store) string {
	t.Helper()
	ctx := context.Background()
	seedRepo(t, s)
	fp := cryptoFP()
	r := newRun(t, s, store.KindSweep)
	mustUpsert(t, s, r.ID, cryptoFinding("govulncheck"))
	scanned(t, s, r.ID, model.ScanComplete, []string{"govulncheck"}, nil)
	if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{
		Actor: model.ActorTriage, Cause: "triage complete", At: leaseNow,
	}); err != nil {
		t.Fatalf("to TRIAGED: %v", err)
	}
	return fp
}

var leaseNow = time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)

func TestTheLeaseBoundStateIsRefusedWithoutALease(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fp := leaseBoundFixture(t, s)

		err := s.ApplyTransition(ctx, fp, model.AutoRemediating, model.TransitionContext{
			Actor: model.ActorOrchestrator, Cause: "policy rule 3 (auto_remediate)", At: leaseNow,
		})
		var want *store.ErrLeaseRequired
		if !errors.As(err, &want) {
			t.Fatalf("entering the lease-bound state with no lease returned %v, want *store.ErrLeaseRequired", err)
		}

		// The negative: nothing was written. A refusal that still moved the
		// finding would be worse than no rule at all, because the error would
		// be logged and ignored while the strand persisted.
		if got := stateOf(t, s, fp); got != model.Triaged {
			t.Errorf("state after the refusal = %s, want TRIAGED — the refusal must not half-apply", got)
		}
		trail, err := s.Transitions(ctx, fp)
		if err != nil {
			t.Fatalf("transitions: %v", err)
		}
		for _, tr := range trail {
			if tr.To == model.AutoRemediating {
				t.Errorf("the refused transition was recorded in the audit trail: %+v", tr)
			}
		}
	})
}

func TestAnExpiredLeaseDoesNotAuthoriseTheLeaseBoundState(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fp := leaseBoundFixture(t, s)

		// A lease from a worker that died an hour ago. The row is still there;
		// the guarantee is not. Accepting it would readmit the whole class
		// through the one door the rule leaves open.
		if err := s.AcquireLease(ctx, fp, "dead-worker", leaseNow.Add(-time.Hour)); err != nil {
			t.Fatalf("AcquireLease: %v", err)
		}
		err := s.ApplyTransition(ctx, fp, model.AutoRemediating, model.TransitionContext{
			Actor: model.ActorOrchestrator, Cause: "dispatch", At: leaseNow,
		})
		var want *store.ErrLeaseRequired
		if !errors.As(err, &want) {
			t.Fatalf("an expired lease authorised the transition: %v", err)
		}
		if !want.Expired || want.Owner != "dead-worker" {
			t.Errorf("the error does not say whose lease expired: %+v", want)
		}
		if got := stateOf(t, s, fp); got != model.Triaged {
			t.Errorf("state = %s, want TRIAGED", got)
		}
	})
}

func TestADispatchHoldingTheLeaseEntersTheLeaseBoundState(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fp := leaseBoundFixture(t, s)

		if err := s.AcquireLease(ctx, fp, "fixworker-1", leaseNow.Add(30*time.Minute)); err != nil {
			t.Fatalf("AcquireLease: %v", err)
		}
		if err := s.ApplyTransition(ctx, fp, model.AutoRemediating, model.TransitionContext{
			Actor: model.ActorOrchestrator, Cause: "remediation started for fix group abc123", At: leaseNow,
		}); err != nil {
			t.Fatalf("a dispatch holding a live lease was refused: %v", err)
		}
		if got := stateOf(t, s, fp); got != model.AutoRemediating {
			t.Fatalf("state = %s, want AUTO_REMEDIATING", got)
		}
		// And the pairing holds in the store: the state and the lease agree.
		lease, err := s.GetLease(ctx, fp)
		if err != nil {
			t.Fatalf("GetLease: %v", err)
		}
		if !lease.Held() || lease.Expired(leaseNow) {
			t.Errorf("the finding is in the lease-bound state with lease %+v", lease)
		}
	})
}

// TestNoFindingSitsInTheLeaseBoundStateWithoutALease is the invariant stated
// over the store rather than over one transition: whatever sequence of
// legal operations has run, a finding in AUTO_REMEDIATING has a live lease.
//
// It is the assertion an operator would make, and it is what the API and the
// interface may rely on when they render "being fixed".
func TestNoFindingSitsInTheLeaseBoundStateWithoutALease(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fp := leaseBoundFixture(t, s)
		if err := s.AcquireLease(ctx, fp, "fixworker-1", leaseNow.Add(30*time.Minute)); err != nil {
			t.Fatalf("AcquireLease: %v", err)
		}
		if err := s.ApplyTransition(ctx, fp, model.AutoRemediating, model.TransitionContext{
			Actor: model.ActorOrchestrator, Cause: "dispatch", At: leaseNow,
		}); err != nil {
			t.Fatalf("dispatch: %v", err)
		}

		findings, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeOpen})
		if err != nil {
			t.Fatalf("ListFindings: %v", err)
		}
		var seen int
		for _, f := range findings {
			if f.State != model.AutoRemediating {
				continue
			}
			seen++
			lease, err := s.GetLease(ctx, f.Fingerprint)
			if err != nil {
				t.Fatalf("GetLease: %v", err)
			}
			if !lease.Held() {
				t.Errorf("%s is in the lease-bound state with no lease", f.Fingerprint)
			}
		}
		if seen == 0 {
			t.Fatal("no finding reached the lease-bound state; the invariant was not exercised")
		}
	})
}
