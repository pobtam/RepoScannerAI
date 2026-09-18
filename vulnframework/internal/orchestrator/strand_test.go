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

// The stranding class.
//
// Phase 9a found one instance: a finding left in AUTO_REMEDIATING with no lease
// held, which nothing could move — policy rule 2 skips it as in progress and
// the lease sweeper has no lease to find. It drops out of remediation with no
// error and no report, which is the worst failure shape this system has: it
// looks exactly like a repository with nothing to do.
//
// This file is the general form. For every state a finding can hold, the
// question is: if nothing else happens, WHAT moves it? A state that looks
// active and has no answer is a strand.

// activeLookingStates are the states in which a finding is presented as "being
// worked on", so nothing escalates it and no human is asked about it.
var activeLookingStates = []model.State{model.AutoRemediating, model.PROpen}

// TestNoActiveLookingStateCanStrand is the audit. Each case constructs the
// residue a crash leaves — the state with its mechanism removed — and asserts
// the recovery sweep moves it.
func TestNoActiveLookingStateCanStrand(t *testing.T) {
	cases := []struct {
		name string
		// setup leaves the finding in an active-looking state with NOTHING
		// pointing at it.
		setup func(t *testing.T, s store.Store, fp string)
		want  model.State
		why   string
	}{
		{
			name: "AUTO_REMEDIATING with no lease",
			setup: func(t *testing.T, s store.Store, fp string) {
				mustTransition(t, s, fp, model.Triaged, model.ActorTriage)
				mustTransition(t, s, fp, model.AutoRemediating, model.ActorOrchestrator)
				// The worker released its claim and died before reverting the
				// state. The finding cannot be PLACED here unleased any more
				// (VM-AD §6.1.5), so this is the one way the condition still
				// arises — and the sweep must still recover it.
				releaseLease(t, s, fp)
			},
			want: model.Triaged,
			why:  "the lease sweeper has no lease to find, and policy rule 2 skips it as in progress",
		},
		{
			name: "AUTO_REMEDIATING with an expired lease nobody swept",
			setup: func(t *testing.T, s store.Store, fp string) {
				ctx := context.Background()
				mustTransition(t, s, fp, model.Triaged, model.ActorTriage)
				// Dispatched with a live lease, as production does, and then
				// the holder died: the lease lapsed where it lay.
				if err := s.AcquireLease(ctx, fp, "dead-worker", at.Add(time.Hour)); err != nil {
					t.Fatalf("acquire lease: %v", err)
				}
				mustTransition(t, s, fp, model.AutoRemediating, model.ActorOrchestrator)
				if err := s.AcquireLease(ctx, fp, "dead-worker", at.Add(-time.Hour)); err != nil {
					t.Fatalf("expiring the lease: %v", err)
				}
			},
			want: model.Triaged,
			why:  "an expired lease must be reclaimed whether or not the lease sweeper ran first",
		},
		{
			name: "PR_OPEN with no pull request record",
			setup: func(t *testing.T, s store.Store, fp string) {
				mustTransition(t, s, fp, model.Triaged, model.ActorTriage)
				mustTransition(t, s, fp, model.AutoRemediating, model.ActorOrchestrator)
				mustTransition(t, s, fp, model.PROpen, model.ActorWorker)
				// No remediation_prs row: the worker died between opening the
				// pull request and recording it, or the record was lost.
			},
			want: model.Triaged,
			why:  "nothing knows which pull request to sync, so no state-sync will ever move it",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run(t, func(t *testing.T, s store.Store) {
				ctx := context.Background()
				repos := fleet(t, s, "org/api")
				raw := depFinding("org/api", "GO-2025-3487", "v0.16.0", "v0.16.1")
				seedDetected(t, s, repos, raw)
				fp := fingerprint.Compute(raw)

				tc.setup(t, s, fp)

				before, err := s.GetFinding(ctx, fp)
				if err != nil {
					t.Fatalf("get finding: %v", err)
				}
				if !isActiveLooking(before.State) {
					t.Fatalf("the fixture is in %s, which is not an active-looking state; the test proves nothing",
						before.State)
				}

				o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
				o.Clock = func() time.Time { return at.Add(2 * time.Hour) }

				stats, err := o.SweepStranded(ctx, orchestrator.StrandSweep{
					Repo: "org/api", PR: gh.NewFake("main"),
				})
				if err != nil {
					t.Fatalf("SweepStranded: %v", err)
				}
				if stats.Recovered == 0 {
					t.Errorf("nothing recovered a finding stranded in %s: %s", before.State, tc.why)
				}

				after, err := s.GetFinding(ctx, fp)
				if err != nil {
					t.Fatalf("get finding: %v", err)
				}
				if after.State == before.State {
					t.Fatalf("the finding is still %s with nothing able to move it: %s", after.State, tc.why)
				}
				if after.State != tc.want {
					t.Errorf("recovered to %s, want %s", after.State, tc.want)
				}
			})
		})
	}
}

// TestRecoveredFindingIsActionableAgain is the point of the sweep. Moving the
// state is worthless if policy still declines to act: the finding would be
// out of AUTO_REMEDIATING and still ignored, which is the same strand wearing
// a different label.
func TestRecoveredFindingIsActionableAgain(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")
		raw := depFinding("org/api", "GO-2025-3487", "v0.16.0", "v0.16.1")
		seedDetected(t, s, repos, raw)
		fp := fingerprint.Compute(raw)

		mustTransition(t, s, fp, model.Triaged, model.ActorTriage)
		mustTransition(t, s, fp, model.AutoRemediating, model.ActorOrchestrator)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
		o.Clock = func() time.Time { return at.Add(2 * time.Hour) }
		if _, err := o.SweepStranded(ctx, orchestrator.StrandSweep{Repo: "org/api", PR: gh.NewFake("main")}); err != nil {
			t.Fatalf("SweepStranded: %v", err)
		}

		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		_, _, pol := pipeline(t)
		decision, err := pol.Evaluate(f, policy.Repo{
			Name: "org/api", Tier: 1, Language: policy.LangGo, HasTestSuite: true,
		}, routeView{})
		if err != nil {
			t.Fatalf("policy: %v", err)
		}
		if decision.Outcome == policy.SkipInProgress {
			t.Error("policy still skips the recovered finding as in progress; moving the state without " +
				"making it actionable is the same strand with a different label")
		}
	})
}

// --- OQ-P9a-02: a human closes the pull request, cold path ------------------

// TestClosedUnmergedPullRequestDeclinesItsFindingsWithNoWebhook closes
// OQ-P9a-02 (VM-F-545).
//
// There is no webhook in this test and there is none in the system yet. The
// transition has to come from reconciliation asking the remote what it sees —
// the same reconciliation-driven / webhook-accelerated pattern as OQ-P2-01,
// where the webhook only makes it prompt rather than eventual.
//
// Left undriven, a human closing a remediation pull request leaves its findings
// in PR_OPEN for ever, and policy rule 2 skips them as in progress: the same
// silent strand as the 9a lease bug, one layer out.
func TestClosedUnmergedPullRequestDeclinesItsFindingsWithNoWebhook(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")
		raw := depFinding("org/api", "GO-2025-3487", "v0.16.0", "v0.16.1")
		seedDetected(t, s, repos, raw)
		fp := fingerprint.Compute(raw)

		remote := gh.NewFake("main")
		// A pull request was opened, and the framework recorded it.
		pr, err := remote.OpenPR(ctx, "org/api", gh.OpenRequest{
			Head: "security/fix-abc123", Base: "main", Title: "security: bump", Body: "b",
		})
		if err != nil {
			t.Fatalf("OpenPR: %v", err)
		}
		if err := s.SaveRemediationPR(ctx, store.RemediationPR{
			Branch: "security/fix-abc123", Repo: "org/api", FixGroupID: "abc123",
			Number: pr.Number, URL: pr.URL, State: "open", OpenedAt: at, Findings: []string{fp},
		}); err != nil {
			t.Fatalf("SaveRemediationPR: %v", err)
		}
		mustTransition(t, s, fp, model.Triaged, model.ActorTriage)
		mustTransition(t, s, fp, model.AutoRemediating, model.ActorOrchestrator)
		mustTransition(t, s, fp, model.PROpen, model.ActorWorker)

		// A human closes it without merging. No webhook fires; nothing tells
		// the framework.
		if err := remote.ClosePR(ctx, "org/api", pr.Number, "not doing this now"); err != nil {
			t.Fatalf("ClosePR: %v", err)
		}

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
		o.Clock = func() time.Time { return at.Add(2 * time.Hour) }

		stats, err := o.ReconcilePullRequests(ctx, orchestrator.ReconcileConfig{PR: remote, Repo: "org/api"})
		if err != nil {
			t.Fatalf("ReconcilePullRequests: %v", err)
		}
		if stats.Declined != 1 {
			t.Errorf("declined %d findings, want 1 (VM-F-545)", stats.Declined)
		}

		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		if f.State != model.Declined {
			t.Fatalf("state = %s, want DECLINED — a pull request closed without merge declines its "+
				"findings (VM-F-545)", f.State)
		}
		if f.ReasonCode == nil || *f.ReasonCode != model.ReasonDeclined {
			t.Errorf("reason = %v, want DECLINED", f.ReasonCode)
		}

		// The record is closed too, so the next sync does not re-examine it.
		rec, ok, err := s.GetRemediationPR(ctx, "security/fix-abc123")
		if err != nil || !ok {
			t.Fatalf("GetRemediationPR = (%v, %v)", ok, err)
		}
		if rec.Open() {
			t.Error("the stored pull request still reads as open")
		}

		// And policy no longer skips it as in progress — which is the whole
		// point. A finding moved out of PR_OPEN that policy still ignores has
		// not actually been recovered.
		_, _, pol := pipeline(t)
		decision, err := pol.Evaluate(f, policy.Repo{
			Name: "org/api", Tier: 1, Language: policy.LangGo, HasTestSuite: true,
		}, routeView{})
		if err != nil {
			t.Fatalf("policy: %v", err)
		}
		if decision.Outcome == policy.SkipInProgress {
			t.Error("policy still treats the finding as in progress after its pull request was closed")
		}
		if decision.Outcome != policy.SkipDeclined {
			t.Errorf("policy outcome = %s, want skip_declined: a human said no, and re-proposing the same "+
				"change next sweep would be the system arguing with them (VM-F-154)", decision.Outcome)
		}
	})
}

// TestMergedPullRequestMovesFindingsToMerged is the other branch, and the line
// it must not cross: MERGED is not VERIFIED. A merged pull request is a claim
// about intent; only a scan of the merged default branch that no longer
// observes the finding is evidence (VM-F-533, VM-ADR-12).
func TestMergedPullRequestMovesFindingsToMerged(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")
		raw := depFinding("org/api", "GO-2025-3487", "v0.16.0", "v0.16.1")
		seedDetected(t, s, repos, raw)
		fp := fingerprint.Compute(raw)

		remote := gh.NewFake("main")
		pr, err := remote.OpenPR(ctx, "org/api", gh.OpenRequest{
			Head: "security/fix-abc123", Base: "main", Title: "security: bump", Body: "b",
		})
		if err != nil {
			t.Fatalf("OpenPR: %v", err)
		}
		if err := s.SaveRemediationPR(ctx, store.RemediationPR{
			Branch: "security/fix-abc123", Repo: "org/api", FixGroupID: "abc123",
			Number: pr.Number, URL: pr.URL, State: "open", OpenedAt: at, Findings: []string{fp},
		}); err != nil {
			t.Fatalf("SaveRemediationPR: %v", err)
		}
		mustTransition(t, s, fp, model.Triaged, model.ActorTriage)
		mustTransition(t, s, fp, model.AutoRemediating, model.ActorOrchestrator)
		mustTransition(t, s, fp, model.PROpen, model.ActorWorker)

		remote.MergePR("org/api", pr.Number)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
		o.Clock = func() time.Time { return at.Add(2 * time.Hour) }
		stats, err := o.ReconcilePullRequests(ctx, orchestrator.ReconcileConfig{PR: remote, Repo: "org/api"})
		if err != nil {
			t.Fatalf("ReconcilePullRequests: %v", err)
		}
		if stats.Merged != 1 {
			t.Errorf("merged %d findings, want 1", stats.Merged)
		}

		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		if f.State != model.Merged {
			t.Fatalf("state = %s, want MERGED", f.State)
		}
		if f.State == model.Verified {
			t.Error("a merged pull request verified the finding; merging is not evidence (VM-F-533)")
		}
		if model.PartitionOf(f.State) == model.PartitionResolved {
			t.Error("MERGED is counted as resolved; it is pending verification, and counting it as " +
				"resolved would overstate what has been fixed (VM-F-159)")
		}
	})
}

func isActiveLooking(s model.State) bool {
	for _, a := range activeLookingStates {
		if s == a {
			return true
		}
	}
	return false
}

// mustTransition drives one legal transition.
//
// A dispatch into the lease-bound state takes the lease first, because that is
// the only way production enters it and the store refuses anything else
// (VM-AD §6.1.5). Tests that want the UNLEASED condition — which is what the
// stranding sweep exists for — release the lease afterwards, which is how the
// condition now arises in the running system.
func mustTransition(t *testing.T, s store.Store, fp string, to model.State, actor model.Actor) {
	t.Helper()
	ctx := context.Background()
	if store.LeaseBound(to) {
		// Only where the caller has not already staged one: a test that set up
		// a specific holder and expiry is describing the dispatch itself, and
		// overwriting it would quietly change the scenario.
		if lease, err := s.GetLease(ctx, fp); err == nil && !lease.Held() {
			if err := s.AcquireLease(ctx, fp, "test-dispatcher", at.Add(time.Hour)); err != nil {
				t.Fatalf("acquiring the lease before entering %s: %v", to, err)
			}
		}
	}
	if err := s.ApplyTransition(ctx, fp, to, model.TransitionContext{
		Actor: actor, Cause: "test", At: at,
	}); err != nil {
		t.Fatalf("transition to %s: %v", to, err)
	}
}

// releaseLease drops a finding's lease without touching its state, which is
// how a finding comes to sit in the lease-bound state with nothing holding it:
// a worker that released its claim without completing the revert.
func releaseLease(t *testing.T, s store.Store, fp string) {
	t.Helper()
	if err := s.ReleaseLease(context.Background(), fp); err != nil {
		t.Fatalf("ReleaseLease: %v", err)
	}
}

// TestRecoveredLinkLostFindingAdoptsRatherThanDuplicates is why the recovery
// for a lost pull request link is TRIAGED rather than a human queue.
//
// It is self-healing, and the self-healing has to be proven rather than
// assumed: re-planning the same findings derives the same fix group identity,
// which derives the same branch, which the worker's adoption path finds
// already pushed with a pull request open. If that chain were broken anywhere,
// the "recovery" would open a second pull request for work already in review —
// strictly worse than the strand it replaced.
func TestRecoveredLinkLostFindingAdoptsRatherThanDuplicates(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")
		raw := depFinding("org/api", "GO-2025-3487", "v0.16.0", "v0.16.1")
		seedDetected(t, s, repos, raw)
		fp := fingerprint.Compute(raw)

		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		group := remediate.Group("org/api", []model.Finding{f},
			policy.ClassDependencyMinor, remediate.GroupConfig{MaxPerPR: 8, MaxPerPRCode: 1})[0]

		// A pull request exists on the remote for this group's branch, opened
		// by a worker whose record was then lost.
		remote := gh.NewFake("main")
		remote.SeedBranch("org/api", group.Branch)
		pr, err := remote.OpenPR(ctx, "org/api", gh.OpenRequest{
			Head: group.Branch, Base: "main", Title: "security: bump", Body: "b",
		})
		if err != nil {
			t.Fatalf("OpenPR: %v", err)
		}
		mustTransition(t, s, fp, model.Triaged, model.ActorTriage)
		mustTransition(t, s, fp, model.AutoRemediating, model.ActorOrchestrator)
		mustTransition(t, s, fp, model.PROpen, model.ActorWorker)
		// No remediation_prs row at all: the link is lost.

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
		o.Clock = func() time.Time { return at.Add(2 * time.Hour) }
		if _, err := o.SweepStranded(ctx, orchestrator.StrandSweep{Repo: "org/api", PR: remote}); err != nil {
			t.Fatalf("SweepStranded: %v", err)
		}

		recovered, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		if recovered.State != model.Triaged {
			t.Fatalf("state = %s, want TRIAGED", recovered.State)
		}

		// Re-planning derives the same branch, and the worker adopts.
		regrouped := remediate.Group("org/api", []model.Finding{recovered},
			policy.ClassDependencyMinor, remediate.GroupConfig{MaxPerPR: 8, MaxPerPRCode: 1})[0]
		if regrouped.Branch != group.Branch {
			t.Fatalf("re-planning derived branch %q, want %q; without a stable branch the recovery would "+
				"open a second pull request", regrouped.Branch, group.Branch)
		}

		g, err := guard.New(guard.Config{DenyPaths: []string{
			".github/workflows/**", "CODEOWNERS", "**/*.tf",
		}})
		if err != nil {
			t.Fatalf("guard: %v", err)
		}
		w := &remediate.Worker{
			Store: s, PR: remote, Guard: g,
			Toolchain: remediate.NewFakeToolchain().
				WithModule("golang.org/x/crypto", "v0.16.0").
				WithAdvisory("GO-2025-3487", "golang.org/x/crypto", "v0.16.1"),
			Owner: "worker-1", LeaseTTL: 30 * time.Minute,
			Clock: func() time.Time { return at.Add(3 * time.Hour) },
		}
		res, err := w.Remediate(ctx, regrouped)
		if err != nil {
			t.Fatalf("Remediate: %v", err)
		}
		if res.Outcome != remediate.OutcomeAlreadyOpen {
			t.Errorf("outcome = %s, want already_open: the branch and its pull request are already there",
				res.Outcome)
		}
		if all := remote.AllPRs("org/api"); len(all) != 1 {
			t.Errorf("%d pull requests exist after recovery, want 1 — the recovery duplicated the work "+
				"it was meant to rescue", len(all))
		}
		if res.PullRequest.Number != pr.Number {
			t.Errorf("adopted pull request #%d, want the original #%d", res.PullRequest.Number, pr.Number)
		}
	})
}

// TestStrandSweepLeavesLiveWorkAlone is the direction that does damage.
//
// A sweep that is too eager is worse than no sweep. Returning a finding to the
// queue while a worker is actively fixing it produces exactly the concurrent
// remediation the repository lock exists to prevent — two branches, two pull
// requests — and it does so from the code whose job is to make the system more
// reliable.
//
// A mutation removing the live-lease check survived every other test in this
// file, because every one of them asserts that something IS recovered. This is
// the assertion that nothing is.
func TestStrandSweepLeavesLiveWorkAlone(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, s store.Store, fp string, remote *gh.Fake)
		why   string
	}{
		{
			name: "a worker holds a live lease",
			setup: func(t *testing.T, s store.Store, fp string, _ *gh.Fake) {
				ctx := context.Background()
				mustTransition(t, s, fp, model.Triaged, model.ActorTriage)
				// The lease outlives the sweep's clock: a worker is mid-flight.
				if err := s.AcquireLease(ctx, fp, "busy-worker", at.Add(6*time.Hour)); err != nil {
					t.Fatalf("acquire lease: %v", err)
				}
				mustTransition(t, s, fp, model.AutoRemediating, model.ActorOrchestrator)
			},
			why: "recovering it would start a second worker on work already in flight",
		},
		{
			name: "a real pull request is open and recorded",
			setup: func(t *testing.T, s store.Store, fp string, remote *gh.Fake) {
				ctx := context.Background()
				pr, err := remote.OpenPR(ctx, "org/api", gh.OpenRequest{
					Head: "security/fix-live", Base: "main", Title: "security: bump", Body: "b",
				})
				if err != nil {
					t.Fatalf("OpenPR: %v", err)
				}
				if err := s.SaveRemediationPR(ctx, store.RemediationPR{
					Branch: "security/fix-live", Repo: "org/api", FixGroupID: "live",
					Number: pr.Number, URL: pr.URL, State: "open", OpenedAt: at, Findings: []string{fp},
				}); err != nil {
					t.Fatalf("SaveRemediationPR: %v", err)
				}
				mustTransition(t, s, fp, model.Triaged, model.ActorTriage)
				mustTransition(t, s, fp, model.AutoRemediating, model.ActorOrchestrator)
				mustTransition(t, s, fp, model.PROpen, model.ActorWorker)
			},
			why: "the pull request is waiting for a human, which IS a mechanism",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run(t, func(t *testing.T, s store.Store) {
				ctx := context.Background()
				repos := fleet(t, s, "org/api")
				raw := depFinding("org/api", "GO-2025-3487", "v0.16.0", "v0.16.1")
				seedDetected(t, s, repos, raw)
				fp := fingerprint.Compute(raw)

				remote := gh.NewFake("main")
				tc.setup(t, s, fp, remote)

				before, err := s.GetFinding(ctx, fp)
				if err != nil {
					t.Fatalf("get finding: %v", err)
				}

				o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
				o.Clock = func() time.Time { return at.Add(2 * time.Hour) }
				stats, err := o.SweepStranded(ctx, orchestrator.StrandSweep{Repo: "org/api", PR: remote})
				if err != nil {
					t.Fatalf("SweepStranded: %v", err)
				}

				if stats.Recovered != 0 {
					t.Errorf("the sweep recovered %d findings that were not stranded: %s", stats.Recovered, tc.why)
				}
				after, err := s.GetFinding(ctx, fp)
				if err != nil {
					t.Fatalf("get finding: %v", err)
				}
				if after.State != before.State {
					t.Errorf("state moved %s → %s: %s", before.State, after.State, tc.why)
				}
				// And the lease, if one was held, is still held: releasing it
				// would let a second worker in while the first is running.
				if tc.name == "a worker holds a live lease" {
					if lease, _ := s.GetLease(ctx, fp); !lease.Held() {
						t.Error("the sweep released a live worker's lease")
					}
				}
			})
		})
	}
}
