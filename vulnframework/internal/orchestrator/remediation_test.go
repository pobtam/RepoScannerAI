package orchestrator_test

import (
	"context"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/remediate"
	"github.com/wanaware/vulnframework/internal/remediate/guard"
	"github.com/wanaware/vulnframework/internal/store"
)

// OQ-AUDIT-05 — the step between a decision and an attempt.
//
// The producer-coverage audit could not find a real producer for
// store.RemediationPR or store.RepoLock in a full pipeline run, and the reason
// was not a missing field: policy routed findings for auto-remediation, the
// remediation worker claimed findings from TRIAGED, and nothing connected the
// two. Every test that had ever exercised the worker placed its own findings
// by hand, so the gap was invisible to all of them.
//
// These tests are anchored at the scanner end on purpose: a run starts with
// adapter output and ends with a pull request, and nothing in between is
// staged.

func dispatchWorker(t *testing.T, s store.Store, remote *gh.Fake, tc *remediate.FakeToolchain) *remediate.Worker {
	t.Helper()
	g, err := guard.New(guard.Config{DenyPaths: []string{
		".github/workflows/**", ".github/actions/**", "CODEOWNERS", "**/*.tf", "**/*.tfvars",
	}})
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	return &remediate.Worker{
		Store: s, PR: remote, Guard: g, Toolchain: tc,
		Owner: "fixworker-1", LeaseTTL: 30 * time.Minute,
		Clock: func() time.Time { return at },
	}
}

func TestRoutedWorkIsDispatchedAllTheWayToAPullRequest(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")

		raw := depFinding("org/api", "GO-2025-3106", "v0.35.0", "v0.36.0")
		seedDetected(t, s, repos, raw)
		fp := fingerprint.Compute(raw)

		tr, sc, pol := pipeline(t)
		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(10), orchestrator.Config{})
		if _, err := o.TriageAndRoute(ctx, repos[0], tr, sc, pol, routeView{}); err != nil {
			t.Fatalf("TriageAndRoute: %v", err)
		}

		remote := gh.NewFake("main")
		tc := remediate.NewFakeToolchain().
			WithModule("golang.org/x/crypto", "v0.35.0").
			WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0")

		stats, err := o.RemediationPass(ctx, orchestrator.RemediationRequest{
			Repo: repos[0], Worker: dispatchWorker(t, s, remote, tc), Policy: pol,
			View: routeView{}, Groups: remediate.GroupConfig{MaxPerPR: 8, MaxPerPRCode: 1},
		})
		if err != nil {
			t.Fatalf("RemediationPass: %v", err)
		}
		if stats.Claimable != 1 {
			t.Fatalf("claimable=%d, want 1: policy routed the finding for auto-remediation, so "+
				"the dispatch pass must see it", stats.Claimable)
		}
		if stats.PROpened != 1 {
			t.Fatalf("pull requests opened = %d, want 1. outcomes=%v", stats.PROpened, stats.Outcomes)
		}

		// The finding, the pull request record and the remote all agree.
		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		if f.State != model.PROpen {
			t.Errorf("state = %s, want PR_OPEN", f.State)
		}
		rec, ok, err := s.RemediationPRForFinding(ctx, fp)
		if err != nil {
			t.Fatalf("RemediationPRForFinding: %v", err)
		}
		if !ok {
			t.Fatal("no remediation pull request record was written by the pipeline; " +
				"store.RemediationPR had no producer outside hand-built fixtures (OQ-AUDIT-05)")
		}
		if len(remote.OpenPRs("org/api")) != 1 {
			t.Errorf("open pull requests on the remote = %d, want 1", len(remote.OpenPRs("org/api")))
		}
		if rec.Number != remote.OpenPRs("org/api")[0].Number {
			t.Errorf("the record names pull request %d, the remote has %d",
				rec.Number, remote.OpenPRs("org/api")[0].Number)
		}
	})
}

// TestADispatchPassLeavesNoFindingClaimedByNobody is the negative that matters
// most here: a pass that ends with findings in the lease-bound state and no
// live lease has produced the exact strand the audit was chasing.
func TestADispatchPassLeavesNoFindingClaimedByNobody(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")

		// Three findings: one bumpable, one whose bump cannot close the
		// advisory (the toolchain has a ceiling), one the toolchain does not
		// know at all. The pass must handle all three without leaving any of
		// them looking like work in flight.
		a := depFinding("org/api", "GO-2025-3106", "v0.35.0", "v0.36.0")
		b := depFinding("org/api", "GO-2025-0002", "v1.2.0", "v1.2.4")
		b.Module, b.ModuleMajor = "golang.org/x/text", "v1"
		c := depFinding("org/api", "GO-2025-0003", "v2.1.0", "v2.1.9")
		c.Module, c.ModuleMajor = "github.com/unknown/mod", "v2"
		seedDetected(t, s, repos, a, b, c)

		tr, sc, pol := pipeline(t)
		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(10), orchestrator.Config{})
		if _, err := o.TriageAndRoute(ctx, repos[0], tr, sc, pol, routeView{}); err != nil {
			t.Fatalf("TriageAndRoute: %v", err)
		}

		remote := gh.NewFake("main")
		tc := remediate.NewFakeToolchain().
			WithModule("golang.org/x/crypto", "v0.35.0").
			WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0").
			WithModule("golang.org/x/text", "v1.2.0").
			WithAdvisory("GO-2025-0002", "golang.org/x/text", "v1.2.4").
			WithCeiling("golang.org/x/text", "v1.2.1")

		if _, err := o.RemediationPass(ctx, orchestrator.RemediationRequest{
			Repo: repos[0], Worker: dispatchWorker(t, s, remote, tc), Policy: pol,
			View: routeView{}, Groups: remediate.GroupConfig{MaxPerPR: 1, MaxPerPRCode: 1},
		}); err != nil {
			t.Fatalf("RemediationPass: %v", err)
		}

		open, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeOpen, Repo: "org/api"})
		if err != nil {
			t.Fatalf("ListFindings: %v", err)
		}
		for _, f := range open {
			if f.State != model.AutoRemediating {
				continue
			}
			lease, err := s.GetLease(ctx, f.Fingerprint)
			if err != nil {
				t.Fatalf("GetLease: %v", err)
			}
			if !lease.Held() || lease.Expired(at) {
				t.Errorf("%s was left in the lease-bound state with lease %+v after the pass ended; "+
					"nothing will move it (VM-AD §6.1.5)", f.Fingerprint, lease)
			}
		}

		// And the repository lock is released, so the next pass is not
		// deferred behind a holder that has gone home.
		lock, err := s.GetRepoLock(ctx, "org/api")
		if err != nil {
			t.Fatalf("GetRepoLock: %v", err)
		}
		if lock.Owner != "" {
			t.Errorf("the pass ended holding the repository lock (%+v)", lock)
		}
	})
}

// TestADispatchPassDoesNotRemediateWhatPolicyNoLongerAllows carries VM-F-154
// into the dispatch: the pass re-decides rather than trusting the routing
// decision recorded earlier, because the world moves between the two.
func TestADispatchPassDoesNotRemediateWhatPolicyNoLongerAllows(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")
		raw := depFinding("org/api", "GO-2025-3106", "v0.35.0", "v0.36.0")
		seedDetected(t, s, repos, raw)

		tr, sc, pol := pipeline(t)
		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(10), orchestrator.Config{})
		if _, err := o.TriageAndRoute(ctx, repos[0], tr, sc, pol, routeView{}); err != nil {
			t.Fatalf("TriageAndRoute: %v", err)
		}

		remote := gh.NewFake("main")
		tc := remediate.NewFakeToolchain().
			WithModule("golang.org/x/crypto", "v0.35.0").
			WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0")

		// A pull request already exists for this work — opened by the previous
		// run, or by a dependency bot. Policy rule 2 skips it as in progress.
		stats, err := o.RemediationPass(ctx, orchestrator.RemediationRequest{
			Repo: repos[0], Worker: dispatchWorker(t, s, remote, tc), Policy: pol,
			View: inProgressView{}, Groups: remediate.GroupConfig{MaxPerPR: 8},
		})
		if err != nil {
			t.Fatalf("RemediationPass: %v", err)
		}
		if stats.Claimable != 0 || stats.Attempted != 0 {
			t.Errorf("claimable=%d attempted=%d, want 0: policy skips work already in progress, "+
				"and a dispatch acting on a stale decision opens a second pull request",
				stats.Claimable, stats.Attempted)
		}
		if len(remote.OpenPRs("org/api")) != 0 {
			t.Errorf("the pass opened %d pull requests for work policy declined to remediate",
				len(remote.OpenPRs("org/api")))
		}
		if got := tc.Version("golang.org/x/crypto"); got != "v0.35.0" {
			t.Errorf("the working tree was modified (%s) for a finding policy skipped", got)
		}
	})
}

// inProgressView reports an open pull request for every finding, which is what
// policy rule 2 consults.
type inProgressView struct{}

func (inProgressView) HasOpenPullRequest(string) bool        { return true }
func (inProgressView) IsFirstPartyOwner(string, string) bool { return false }

var _ policy.StoreView = inProgressView{}
