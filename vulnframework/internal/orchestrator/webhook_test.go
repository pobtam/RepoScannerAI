package orchestrator_test

import (
	"context"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/store"
)

// Phase 12 — webhook-prompt transitions.
//
// Phase 9b made these transitions EVENTUAL, by asking the remote each sweep.
// The webhook makes them PROMPT. It does not make them certain: a delivery can
// be lost, an endpoint can be down for an hour, a secret can be rotated
// without the App being told. So reconciliation stays, and the property that
// matters most is that the two paths agree.

func prFixture(t *testing.T, s store.Store) (string, string) {
	t.Helper()
	ctx := context.Background()
	repos := fleet(t, s, "org/api")
	raw := depFinding("org/api", "GO-2025-3487", "v0.16.0", "v0.16.1")
	seedDetected(t, s, repos, raw)
	fp := fingerprint.Compute(raw)

	if err := s.SaveRemediationPR(ctx, store.RemediationPR{
		Branch: "security/fix-abc123", Repo: "org/api", FixGroupID: "abc123",
		Number: 41, URL: "https://github.com/org/api/pull/41", State: "open",
		OpenedAt: at, Findings: []string{fp},
	}); err != nil {
		t.Fatalf("SaveRemediationPR: %v", err)
	}
	mustTransition(t, s, fp, model.Triaged, model.ActorTriage)
	mustTransition(t, s, fp, model.AutoRemediating, model.ActorOrchestrator)
	mustTransition(t, s, fp, model.PROpen, model.ActorWorker)
	return fp, "security/fix-abc123"
}

// --- The two paths must agree ------------------------------------------------

// TestWebhookAndReconciliationProduceTheSameTransition is the clause that
// keeps the fallback honest.
//
// Two code paths that can each move a finding will diverge unless something
// holds them together. The divergence would be invisible: whichever fired
// first would look correct, and the bug would only appear when an endpoint
// outage switched the system from one path to the other — the moment nobody is
// watching closely.
func TestWebhookAndReconciliationProduceTheSameTransition(t *testing.T) {
	cases := []struct {
		name   string
		merged bool
		want   model.State
	}{
		{"merged", true, model.Merged},
		{"closed without merging", false, model.Declined},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// --- via the webhook ---
			viaWebhook := func() model.Finding {
				s := newMemStore(t)
				fp, branch := prFixture(t, s)
				o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50),
					orchestrator.Config{})
				o.Clock = func() time.Time { return at.Add(time.Hour) }

				if _, err := o.ApplyWebhook(context.Background(), gh.Event{
					Kind: gh.EventPullRequestClosed, DeliveryID: "d1",
					Repo: "org/api", Number: 41, Branch: branch, Merged: tc.merged,
				}); err != nil {
					t.Fatalf("ApplyWebhook: %v", err)
				}
				f, err := s.GetFinding(context.Background(), fp)
				if err != nil {
					t.Fatalf("get finding: %v", err)
				}
				return f
			}()

			// --- via reconciliation, with no webhook at all ---
			viaReconcile := func() model.Finding {
				s := newMemStore(t)
				fp, _ := prFixture(t, s)
				remote := gh.NewFake("main")
				remote.SeedBranch("org/api", "security/fix-abc123")
				pr, err := remote.OpenPR(context.Background(), "org/api", gh.OpenRequest{
					Head: "security/fix-abc123", Base: "main", Title: "t", Body: "b",
				})
				if err != nil {
					t.Fatalf("OpenPR: %v", err)
				}
				if err := s.SaveRemediationPR(context.Background(), store.RemediationPR{
					Branch: "security/fix-abc123", Repo: "org/api", FixGroupID: "abc123",
					Number: pr.Number, URL: pr.URL, State: "open", OpenedAt: at, Findings: []string{fp},
				}); err != nil {
					t.Fatalf("SaveRemediationPR: %v", err)
				}
				if tc.merged {
					remote.MergePR("org/api", pr.Number)
				} else {
					if err := remote.ClosePR(context.Background(), "org/api", pr.Number, "no"); err != nil {
						t.Fatalf("ClosePR: %v", err)
					}
				}
				o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50),
					orchestrator.Config{})
				o.Clock = func() time.Time { return at.Add(time.Hour) }
				if _, err := o.ReconcilePullRequests(context.Background(), orchestrator.ReconcileConfig{
					PR: remote, Repo: "org/api",
				}); err != nil {
					t.Fatalf("ReconcilePullRequests: %v", err)
				}
				f, err := s.GetFinding(context.Background(), fp)
				if err != nil {
					t.Fatalf("get finding: %v", err)
				}
				return f
			}()

			if viaWebhook.State != tc.want {
				t.Errorf("webhook produced %s, want %s", viaWebhook.State, tc.want)
			}
			if viaReconcile.State != tc.want {
				t.Errorf("reconciliation produced %s, want %s", viaReconcile.State, tc.want)
			}
			if viaWebhook.State != viaReconcile.State {
				t.Errorf("the two paths disagree: webhook %s, reconciliation %s. The divergence would "+
					"be invisible until an endpoint outage switched the system from one to the other",
					viaWebhook.State, viaReconcile.State)
			}
			// The reason too, not only the state: a DECLINED with no reason is
			// a queue entry nobody can action.
			if reasonOf(viaWebhook) != reasonOf(viaReconcile) {
				t.Errorf("the two paths recorded different reasons: %q and %q",
					reasonOf(viaWebhook), reasonOf(viaReconcile))
			}
		})
	}
}

// TestAWebhookThenReconciliationDoesNotActTwice is the belt to that braces. In
// production both run: the webhook arrives and the next sweep reconciles
// anyway. The second must find nothing to do.
func TestAWebhookThenReconciliationDoesNotActTwice(t *testing.T) {
	ctx := context.Background()
	s := newMemStore(t)
	fp, branch := prFixture(t, s)

	remote := gh.NewFake("main")
	remote.SeedBranch("org/api", branch)
	pr, err := remote.OpenPR(ctx, "org/api", gh.OpenRequest{Head: branch, Base: "main", Title: "t", Body: "b"})
	if err != nil {
		t.Fatalf("OpenPR: %v", err)
	}
	if err := s.SaveRemediationPR(ctx, store.RemediationPR{
		Branch: branch, Repo: "org/api", FixGroupID: "abc123",
		Number: pr.Number, URL: pr.URL, State: "open", OpenedAt: at, Findings: []string{fp},
	}); err != nil {
		t.Fatalf("SaveRemediationPR: %v", err)
	}
	remote.MergePR("org/api", pr.Number)

	o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
	o.Clock = func() time.Time { return at.Add(time.Hour) }

	if _, err := o.ApplyWebhook(ctx, gh.Event{
		Kind: gh.EventPullRequestClosed, DeliveryID: "d1",
		Repo: "org/api", Number: pr.Number, Branch: branch, Merged: true,
	}); err != nil {
		t.Fatalf("ApplyWebhook: %v", err)
	}
	after, err := s.GetFinding(ctx, fp)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if after.State != model.Merged {
		t.Fatalf("state = %s after the webhook, want MERGED", after.State)
	}

	stats, err := o.ReconcilePullRequests(ctx, orchestrator.ReconcileConfig{PR: remote, Repo: "org/api"})
	if err != nil {
		t.Fatalf("ReconcilePullRequests: %v", err)
	}
	if stats.Merged != 0 || stats.Declined != 0 {
		t.Errorf("reconciliation acted again after the webhook had: %+v", stats)
	}
	// And it did not even ASK: the pull request is closed, so it is not in the
	// unconfirmed set at all (OQ-P12-01).
	if stats.Examined != 0 {
		t.Errorf("reconciliation queried the remote %d times about a pull request the webhook "+
			"had already settled", stats.Examined)
	}
	final, _ := s.GetFinding(ctx, fp)
	if final.State != model.Merged {
		t.Errorf("state = %s after both paths ran, want MERGED", final.State)
	}
}

// --- A forged event cannot drive an illegal transition ----------------------

// TestAForgedEventCannotDriveAnIllegalTransition is the defence in depth.
//
// The signature check is the first line and should stop this. But a webhook
// endpoint is the most exposed surface in the system, and the transition
// table plus actor enforcement are what remain if the secret leaks — so they
// have to hold on their own.
func TestAForgedEventCannotDriveAnIllegalTransition(t *testing.T) {
	ctx := context.Background()
	s := newMemStore(t)
	repos := fleet(t, s, "org/api")
	raw := depFinding("org/api", "GO-2025-3487", "v0.16.0", "v0.16.1")
	seedDetected(t, s, repos, raw)
	fp := fingerprint.Compute(raw)

	// The finding is DETECTED: it has never been remediated, and there is no
	// pull request. An attacker who knew the secret would try exactly this.
	if err := s.SaveRemediationPR(ctx, store.RemediationPR{
		Branch: "security/fix-forged", Repo: "org/api", FixGroupID: "forged",
		Number: 999, URL: "https://github.com/org/api/pull/999", State: "open",
		OpenedAt: at, Findings: []string{fp},
	}); err != nil {
		t.Fatalf("SaveRemediationPR: %v", err)
	}

	o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
	o.Clock = func() time.Time { return at.Add(time.Hour) }

	// "This pull request merged" — which would mean the finding is fixed.
	if _, err := o.ApplyWebhook(ctx, gh.Event{
		Kind: gh.EventPullRequestClosed, DeliveryID: "forged-1",
		Repo: "org/api", Number: 999, Branch: "security/fix-forged", Merged: true,
	}); err != nil {
		t.Logf("ApplyWebhook refused outright: %v", err)
	}

	f, err := s.GetFinding(ctx, fp)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if f.State == model.Merged || f.State == model.Verified {
		t.Fatalf("a forged merge event moved a DETECTED finding to %s. The transition table is the "+
			"last defence when the webhook secret leaks, and it did not hold", f.State)
	}
	if f.State != model.Detected {
		t.Errorf("state = %s, want DETECTED unchanged", f.State)
	}
}

func reasonOf(f model.Finding) string {
	if f.ReasonCode == nil {
		return ""
	}
	return string(*f.ReasonCode)
}

func newMemStore(t *testing.T) store.Store {
	t.Helper()
	s := store.NewMemory()
	s.SetClock(fixedAt())
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

func fixedAt() func() time.Time {
	n := 0
	return func() time.Time {
		n++
		return at.Add(time.Duration(n) * time.Second)
	}
}
