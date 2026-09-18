package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// Phase 3 gate, reconciliation clause:
//
//	a finding present in run N and absent in a COMPLETE run N+1 verifies
//	(reason framework_merge if it went through MERGED, else external);
//	absent in a PARTIAL or FAILED run N+1 retains its state and is flagged
//	not_reobserved, never VERIFIED.

// TestDisappearanceVerifiesFromEveryEligibleState covers VM-AD §6.1.1. Before
// this rule, a finding fixed outside the framework stayed open for ever, and
// the fleet's open count drifted permanently away from reality.
func TestDisappearanceVerifiesFromEveryEligibleState(t *testing.T) {
	cases := []struct {
		name       string
		walk       []model.State
		wantReason model.VerificationReason
	}{
		{
			name:       "triaged, fixed by someone else",
			walk:       []model.State{model.Triaged},
			wantReason: model.VerifiedExternal,
		},
		{
			name:       "needs human, fixed by hand",
			walk:       []model.State{model.Triaged, model.NeedsHuman},
			wantReason: model.VerifiedExternal,
		},
		{
			name:       "blocked upstream, released upstream",
			walk:       []model.State{model.Triaged, model.BlockedUpstream},
			wantReason: model.VerifiedByUpstream,
		},
		{
			name:       "auto-remediating, disappeared mid-flight",
			walk:       []model.State{model.Triaged, model.AutoRemediating},
			wantReason: model.VerifiedExternal,
		},
		{
			name:       "pull request open, fixed another way",
			walk:       []model.State{model.Triaged, model.AutoRemediating, model.PROpen},
			wantReason: model.VerifiedExternal,
		},
		{
			name:       "merged, the framework's own fix",
			walk:       []model.State{model.Triaged, model.AutoRemediating, model.PROpen, model.Merged},
			wantReason: model.VerifiedByFrameworkMerge,
		},
		{
			name:       "declined by a reviewer, but gone anyway",
			walk:       []model.State{model.Triaged, model.AutoRemediating, model.PROpen, model.Declined},
			wantReason: model.VerifiedExternal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run(t, func(t *testing.T, s store.Store) {
				ctx := context.Background()
				seedRepo(t, s)
				fp := cryptoFP()

				r1 := newRun(t, s, store.KindSweep)
				mustUpsert(t, s, r1.ID, cryptoFinding("govulncheck"))
				scanned(t, s, r1.ID, model.ScanComplete, []string{"govulncheck"}, nil)
				walkStates(t, s, fp, tc.walk)

				// Run N+1 completes successfully and does not observe it.
				r2 := newRun(t, s, store.KindSweep)
				scanned(t, s, r2.ID, model.ScanComplete, []string{"govulncheck"}, nil)
				stats, err := s.Reconcile(ctx, r2.ID, testRepo)
				if err != nil {
					t.Fatalf("reconcile: %v", err)
				}
				if stats.Verified != 1 {
					t.Fatalf("verified=%d, want 1 from state %s", stats.Verified, tc.walk[len(tc.walk)-1])
				}

				f, err := s.GetFinding(ctx, fp)
				if err != nil {
					t.Fatalf("get finding: %v", err)
				}
				if f.State != model.Verified {
					t.Errorf("state = %q, want VERIFIED", f.State)
				}
				if f.VerifiedReason == nil {
					t.Fatal("no verification reason recorded; a report could not tell a framework fix from a disappearance")
				}
				if *f.VerifiedReason != tc.wantReason {
					t.Errorf("verified_reason = %q, want %q", *f.VerifiedReason, tc.wantReason)
				}
				if f.Derived.NotReobserved {
					t.Error("a verified finding must not remain flagged not_reobserved")
				}
			})
		})
	}
}

// TestSuppressedNeverAutoVerifies covers the one exclusion. A suppression is a
// human judgement that the finding was never real; converting it to VERIFIED
// would overwrite that judgement with a machine's.
func TestSuppressedNeverAutoVerifies(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		fp := cryptoFP()

		r1 := newRun(t, s, store.KindSweep)
		mustUpsert(t, s, r1.ID, cryptoFinding("govulncheck"))
		scanned(t, s, r1.ID, model.ScanComplete, []string{"govulncheck"}, nil)
		walkStates(t, s, fp, []model.State{model.Triaged, model.FPCandidate, model.Suppressed})

		r2 := newRun(t, s, store.KindSweep)
		scanned(t, s, r2.ID, model.ScanComplete, []string{"govulncheck"}, nil)
		stats, err := s.Reconcile(ctx, r2.ID, testRepo)
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if stats.Verified != 0 {
			t.Errorf("verified=%d, want 0: a suppression must not be auto-verified", stats.Verified)
		}

		f, _ := s.GetFinding(ctx, fp)
		if f.State != model.Suppressed {
			t.Errorf("state = %q, want SUPPRESSED retained", f.State)
		}
		if f.VerifiedReason != nil {
			t.Errorf("a suppressed finding recorded a verification reason: %q", *f.VerifiedReason)
		}
	})
}

// TestDisappearanceInAnIncompleteScanNeverVerifies is the guard, applied to the
// widened rule. The universal trigger must not become a way around VM-ADR-12.
func TestDisappearanceInAnIncompleteScanNeverVerifies(t *testing.T) {
	states := [][]model.State{
		{model.Triaged},
		{model.Triaged, model.NeedsHuman},
		{model.Triaged, model.AutoRemediating, model.PROpen, model.Merged},
	}
	outcomes := []model.ScanOutcome{model.ScanPartial, model.ScanFailed}

	for _, walk := range states {
		final := walk[len(walk)-1]
		for _, outcome := range outcomes {
			t.Run(string(final)+"/"+string(outcome), func(t *testing.T) {
				run(t, func(t *testing.T, s store.Store) {
					ctx := context.Background()
					seedRepo(t, s)
					fp := cryptoFP()

					r1 := newRun(t, s, store.KindSweep)
					mustUpsert(t, s, r1.ID, cryptoFinding("govulncheck"))
					scanned(t, s, r1.ID, model.ScanComplete, []string{"govulncheck"}, nil)
					walkStates(t, s, fp, walk)

					r2 := newRun(t, s, store.KindSweep)
					scanned(t, s, r2.ID, outcome, nil, []string{"govulncheck"})
					stats, err := s.Reconcile(ctx, r2.ID, testRepo)
					if err != nil {
						t.Fatalf("reconcile: %v", err)
					}

					if stats.Verified != 0 {
						t.Fatalf("a %s scan verified a finding in state %s; absence is not resolution (VM-ADR-12)", outcome, final)
					}
					f, _ := s.GetFinding(ctx, fp)
					if f.State != final {
						t.Errorf("state = %q, want %q retained", f.State, final)
					}
					if !f.Derived.NotReobserved {
						t.Error("finding is not flagged not_reobserved (VM-F-161)")
					}
					if f.Derived.GapRepoScan == nil || *f.Derived.GapRepoScan != r2.ID {
						t.Errorf("gap link = %v, want %s (VM-F-162)", f.Derived.GapRepoScan, r2.ID)
					}
					if f.VerifiedReason != nil {
						t.Errorf("an unverified finding recorded a verification reason: %q", *f.VerifiedReason)
					}
				})
			})
		}
	}
}

// TestPresentThenAbsentAcrossRuns is the gate clause stated end to end: present
// in run N, absent in a complete run N+1, verified with honest attribution.
func TestPresentThenAbsentAcrossRuns(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		fp := cryptoFP()

		// Run N: observed.
		r1 := newRun(t, s, store.KindSweep)
		mustUpsert(t, s, r1.ID, cryptoFinding("govulncheck"), cryptoFinding("osv-scanner"))
		scanned(t, s, r1.ID, model.ScanComplete, []string{"govulncheck", "osv-scanner"}, nil)
		if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{Actor: model.ActorTriage}); err != nil {
			t.Fatalf("triage: %v", err)
		}

		open, _ := s.ListFindings(ctx, store.Query{Scope: store.ScopeOpen})
		if len(open) != 1 {
			t.Fatalf("open=%d after run N, want 1", len(open))
		}

		// Run N+1: complete, and does not observe it.
		r2 := newRun(t, s, store.KindSweep)
		scanned(t, s, r2.ID, model.ScanComplete, []string{"govulncheck", "osv-scanner"}, nil)
		stats, err := s.Reconcile(ctx, r2.ID, testRepo)
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if stats.Verified != 1 {
			t.Fatalf("verified=%d, want 1", stats.Verified)
		}

		f, _ := s.GetFinding(ctx, fp)
		if f.State != model.Verified {
			t.Errorf("state = %q, want VERIFIED", f.State)
		}
		// It never went through MERGED, so the framework must not claim credit.
		if f.VerifiedReason == nil || *f.VerifiedReason != model.VerifiedExternal {
			t.Errorf("verified_reason = %v, want external: the framework merged nothing", f.VerifiedReason)
		}

		open, _ = s.ListFindings(ctx, store.Query{Scope: store.ScopeOpen})
		if len(open) != 0 {
			t.Errorf("open=%d after verification, want 0", len(open))
		}

		// And the per-source observations survive for audit.
		obs, _ := s.Observations(ctx, fp)
		if len(obs) != 2 {
			t.Errorf("observations=%d after verification, want 2 retained", len(obs))
		}
	})
}

// walkStates drives a finding along a sequence of legal transitions.
// walkStates drives a finding along a legal path.
//
// Entering AUTO_REMEDIATING acquires a lease first, because that is the only
// way a finding enters it in production: the store refuses the transition
// otherwise (VM-AD §6.1.5). A fixture that could park a finding there without
// a lease would be testing a state the running system cannot reach.
func walkStates(t *testing.T, s store.Store, fp string, states []model.State) {
	t.Helper()
	ctx := context.Background()
	for _, to := range states {
		if store.LeaseBound(to) {
			if err := s.AcquireLease(ctx, fp, "test-worker", leaseFarFuture); err != nil {
				t.Fatalf("acquiring the lease before entering %s: %v", to, err)
			}
		}
		actor := model.ActorOrchestrator
		switch to {
		case model.Triaged, model.FPCandidate:
			actor = model.ActorTriage
		case model.PROpen:
			actor = model.ActorWorker
		case model.Suppressed:
			actor = model.ActorHuman
		}
		if err := s.ApplyTransition(ctx, fp, to, model.TransitionContext{
			Actor: actor, Cause: "test walk",
		}); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}
}

// leaseFarFuture is an expiry no test clock reaches, so a walk's lease is live
// whatever clock the backend under test is stamping with.
var leaseFarFuture = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
