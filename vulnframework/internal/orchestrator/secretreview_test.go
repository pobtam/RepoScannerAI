package orchestrator_test

import (
	"context"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/store"
)

func allowlistedSecret(repo string) model.RawFinding {
	return model.RawFinding{
		Repo: repo, Category: model.CategorySecret,
		DetectorRuleID: "aws-access-token", Tool: "gitleaks", ToolVersion: "v8.30.1",
		File: "testdata/fixture.yaml", Line: 3, CredentialType: "aws-access-token",
		Classification: model.Classification{
			Severity: model.SeverityCritical, Reachable: model.ReachableUnknown, DepClass: model.DepNotApplicable,
		},
		Allowlisted: &model.Allowlist{Mechanism: model.AllowlistConfig, Path: ".gitleaks.toml", ConfigSHA256: "aaaa"},
	}
}

// A sweep records an allowlisted secret as a proposal; routing leaves it
// there; it escalates only once the secret SLA window has passed.
func TestAProposalIsLeftByRoutingAndEscalatesWhenOverdue(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api") // tier 2
		raw := allowlistedSecret("org/api")
		fp := fingerprint.Compute(raw)

		d := orchestrator.NewFakeDispatcher().WithFindings("org/api", []string{"gitleaks"}, raw)
		o := newOrchestrator(s, d, orchestrator.NewRateBudget(10), orchestrator.Config{CreditsPerScan: 1})
		if _, err := o.Sweep(ctx, store.KindSweep, "test", repos, nil); err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		if got := stateOf(t, s, fp); got != model.FPCandidate {
			t.Fatalf("an allowlisted secret after a sweep is %s, want FALSE_POSITIVE_CANDIDATE", got)
		}

		// Policy escalates every secret (rule 1), but must not undo the proposal.
		tr, sc, pol := pipeline(t)
		if _, err := o.TriageAndRoute(ctx, repos[0], tr, sc, pol, routeView{}); err != nil {
			t.Fatalf("TriageAndRoute: %v", err)
		}
		if got := stateOf(t, s, fp); got != model.FPCandidate {
			t.Fatalf("routing moved a pending proposal to %s", got)
		}

		window := o.SLAWindows().Window(repos[0].Tier, model.P0)
		o.Clock = func() time.Time { return at.Add(window - time.Minute) }
		if n, err := o.EscalateOverdueProposals(ctx, repos[0]); err != nil || n != 0 {
			t.Fatalf("inside the window: escalated %d (%v), want 0", n, err)
		}
		o.Clock = func() time.Time { return at.Add(window + time.Minute) }
		if n, err := o.EscalateOverdueProposals(ctx, repos[0]); err != nil || n != 1 {
			t.Fatalf("past the window: escalated %d (%v), want 1", n, err)
		}
		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatal(err)
		}
		if f.State != model.NeedsHuman || f.SuppressionProposal.Status != model.ProposalOverdue {
			t.Fatalf("after escalation: %s, proposal %+v", f.State, f.SuppressionProposal)
		}
		if n, _ := o.EscalateOverdueProposals(ctx, repos[0]); n != 0 {
			t.Error("an overdue proposal escalated twice")
		}
	})
}

// The ordinary scan reporting a secret outranks anything calling it
// allowlisted in the same scan.
func TestAnObservedSecretIsNeverTreatedAsAllowlisted(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")
		hidden := allowlistedSecret("org/api")
		seen := hidden
		seen.Allowlisted = nil
		d := orchestrator.NewFakeDispatcher().WithFindings("org/api", []string{"gitleaks"}, hidden, seen)
		o := newOrchestrator(s, d, orchestrator.NewRateBudget(10), orchestrator.Config{CreditsPerScan: 1})
		if _, err := o.Sweep(ctx, store.KindSweep, "test", repos, nil); err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		f, err := s.GetFinding(ctx, fingerprint.Compute(seen))
		if err != nil {
			t.Fatal(err)
		}
		if f.State == model.FPCandidate || f.SuppressionProposal != nil {
			t.Fatalf("a secret the scan reported became a proposal: %s %+v", f.State, f.SuppressionProposal)
		}
	})
}

func stateOf(t *testing.T, s store.Store, fp string) model.State {
	t.Helper()
	f, err := s.GetFinding(context.Background(), fp)
	if err != nil {
		t.Fatalf("GetFinding %s: %v", fp, err)
	}
	return f.State
}
