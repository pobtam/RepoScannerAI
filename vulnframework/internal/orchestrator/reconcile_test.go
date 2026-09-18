package orchestrator_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/store"
)

// OQ-P12-01 — the webhook REPLACES the poll.
//
// Phase 12 added the webhook and left the poll running underneath it. The
// framework then asked the remote about every open remediation pull request on
// every sweep, forever, to re-learn what a delivery had already told it: one
// API call per open pull request per sweep, growing with the fleet, spent
// exactly where the rate budget is tightest. "Webhook-accelerated" was true of
// the transition and false of the cost.
//
// The tests below assert the poll is GONE, which is a different claim from the
// webhook working:
//
//   - a live webhook means no queries at all for what it has vouched for;
//   - the fallback is bounded per sweep and pays from the rate budget;
//   - a silent webhook makes it revert to asking about everything, LOUDLY;
//   - both paths still produce identical transitions.

func countCalls(calls []string, prefix string) int {
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// openPRs records n open remediation pull requests, each with its own finding.
func openPRs(t *testing.T, s store.Store, remote *gh.Fake, repo string, n int) []store.RemediationPR {
	t.Helper()
	ctx := context.Background()
	repos := fleet(t, s, repo)

	// One scan for all of them. Seeding them one at a time would make each
	// scan a COMPLETE scan that did not observe the previous findings, and
	// reconciliation would verify them by disappearance — correctly, and
	// entirely beside the point of this fixture.
	var raws []model.RawFinding
	for i := 0; i < n; i++ {
		raw := depFinding(repo, fmt.Sprintf("GO-2025-%04d", i), "v0.16.0", "v0.16.1")
		raw.Module = fmt.Sprintf("golang.org/x/mod%d", i)
		raws = append(raws, raw)
	}
	seedDetected(t, s, repos, raws...)

	var out []store.RemediationPR
	for i, raw := range raws {
		fp := fingerprint.Compute(raw)

		branch := fmt.Sprintf("security/fix-%04d", i)
		pr, err := remote.OpenPR(ctx, repo, gh.OpenRequest{
			Head: branch, Base: "main", Title: "security: bump", Body: "b",
		})
		if err != nil {
			t.Fatalf("OpenPR: %v", err)
		}
		rec := store.RemediationPR{
			Branch: branch, Repo: repo, FixGroupID: fmt.Sprintf("%04d", i),
			Number: pr.Number, URL: pr.URL, State: "open", OpenedAt: at, Findings: []string{fp},
		}
		if err := s.SaveRemediationPR(ctx, rec); err != nil {
			t.Fatalf("SaveRemediationPR: %v", err)
		}
		mustTransition(t, s, fp, model.Triaged, model.ActorTriage)
		mustTransition(t, s, fp, model.AutoRemediating, model.ActorOrchestrator)
		mustTransition(t, s, fp, model.PROpen, model.ActorWorker)
		out = append(out, rec)
	}
	return out
}

// TestALiveWebhookMeansTheRemoteIsNotAskedAtAll is the clause that says the
// poll is gone rather than supplemented.
//
// A supplemented poll passes every other test in this package: transitions
// happen, both paths agree, nothing strands. The only thing that distinguishes
// "the webhook is primary" from "the webhook is a nice-to-have on top of a
// poll" is the call count.
func TestALiveWebhookMeansTheRemoteIsNotAskedAtAll(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		remote := gh.NewFake("main")
		recs := openPRs(t, s, remote, "org/api", 12)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(500),
			orchestrator.Config{PR: remote})
		o.Clock = func() time.Time { return at.Add(10 * time.Minute) }

		// The App reports each pull request it opened. These are deliveries
		// the framework has nothing to DRIVE from — the worker already
		// recorded the pull requests — and they are exactly what spares it
		// twelve queries.
		for _, rec := range recs {
			if _, err := o.ApplyWebhook(ctx, gh.Event{
				Kind: gh.EventPullRequestOpened, Repo: rec.Repo, Number: rec.Number, Branch: rec.Branch,
			}); err != nil {
				t.Fatalf("ApplyWebhook: %v", err)
			}
		}

		before := countCalls(remote.Calls(), "GetPR")
		stats, err := o.ReconcilePullRequests(ctx, orchestrator.ReconcileConfig{
			PR: remote, Repo: "org/api",
		})
		if err != nil {
			t.Fatalf("ReconcilePullRequests: %v", err)
		}
		asked := countCalls(remote.Calls(), "GetPR") - before

		if asked != 0 {
			t.Errorf("reconciliation made %d GetPR calls about twelve pull requests the webhook had "+
				"just vouched for. That is the poll still running underneath the webhook, which is "+
				"what OQ-P12-01 removes", asked)
		}
		if stats.Examined != 0 {
			t.Errorf("examined=%d, want 0", stats.Examined)
		}
		if !stats.WebhookLive {
			t.Error("the webhook delivered twelve verified events and the pass did not consider it live")
		}
	})
}

// TestASilentWebhookFallsBackToAskingAboutEverythingAndSaysSo is the
// fail-closed half. A framework that quietly polls its way through a dead
// webhook looks healthy on every dashboard it has.
func TestASilentWebhookFallsBackToAskingAboutEverythingAndSaysSo(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		remote := gh.NewFake("main")
		recs := openPRs(t, s, remote, "org/api", 5)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(500),
			orchestrator.Config{PR: remote})
		o.Clock = func() time.Time { return at.Add(10 * time.Minute) }

		// The App vouches for everything, and then goes quiet for a day.
		for _, rec := range recs {
			if _, err := o.ApplyWebhook(ctx, gh.Event{
				Kind: gh.EventPullRequestOpened, Repo: rec.Repo, Number: rec.Number, Branch: rec.Branch,
			}); err != nil {
				t.Fatalf("ApplyWebhook: %v", err)
			}
		}
		o.Clock = func() time.Time { return at.Add(24 * time.Hour) }

		// One of them was merged during the silence, and no delivery said so.
		remote.MergePR("org/api", recs[2].Number)

		before := countCalls(remote.Calls(), "GetPR")
		stats, err := o.ReconcilePullRequests(ctx, orchestrator.ReconcileConfig{
			PR: remote, Repo: "org/api", Silence: 30 * time.Minute, Horizon: 6 * time.Hour,
		})
		if err != nil {
			t.Fatalf("ReconcilePullRequests: %v", err)
		}
		asked := countCalls(remote.Calls(), "GetPR") - before

		if stats.WebhookLive {
			t.Error("a webhook silent for a day was treated as live; the fallback would then trust " +
				"confirmations nothing has renewed")
		}
		if asked != len(recs) {
			t.Errorf("asked about %d of %d pull requests; with no deliveries arriving, every "+
				"confirmation is stale and the fallback must ask about all of them", asked, len(recs))
		}
		if stats.Merged != 1 || stats.Lost != 1 {
			t.Errorf("merged=%d lost=%d, want 1 and 1: the closure the webhook missed", stats.Merged, stats.Lost)
		}

		// Loudly. A recovery that fires silently is an observability gap
		// (the Phase 9b standing principle).
		var silent, lost bool
		for _, e := range o.Recovery.Events() {
			if e.Kind == orchestrator.RecoveryWebhookSilent {
				silent = true
				if !strings.Contains(e.Reason, "no verified webhook delivery") {
					t.Errorf("the silence event does not say what is wrong: %q", e.Reason)
				}
			}
			if e.Kind == orchestrator.RecoveryPRStateSync && strings.Contains(e.Reason, "LOST DELIVERY") {
				lost = true
			}
		}
		if !silent {
			t.Error("reconciliation reverted to full polling and recorded nothing; the primary path " +
				"is broken and no operator would learn it from this run")
		}
		if !lost {
			t.Error("a closure the webhook never reported was recorded as a reconciliation success " +
				"rather than as a lost delivery")
		}
	})
}

// TestTheFallbackIsBoundedAndPaysForItself covers the fan-out and the budget.
//
// The old poll was unbounded in both: it iterated every open pull request and
// its API calls were invisible to the rate budget, so a fleet with four hundred
// open remediation pull requests spent four hundred unaccounted calls per
// sweep and discovered the rate limit mid-run.
func TestTheFallbackIsBoundedAndPaysForItself(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		remote := gh.NewFake("main")
		openPRs(t, s, remote, "org/api", 20)

		budget := orchestrator.NewRateBudget(500)
		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), budget,
			orchestrator.Config{PR: remote, CreditsPerScan: 1})
		o.Clock = func() time.Time { return at.Add(time.Hour) }

		availBefore := budget.Available()
		before := countCalls(remote.Calls(), "GetPR")
		stats, err := o.ReconcilePullRequests(ctx, orchestrator.ReconcileConfig{
			PR: remote, Repo: "org/api", MaxChecks: 5,
		})
		if err != nil {
			t.Fatalf("ReconcilePullRequests: %v", err)
		}
		asked := countCalls(remote.Calls(), "GetPR") - before

		if asked != 5 {
			t.Errorf("asked about %d pull requests with MaxChecks=5; an unbounded fan-out is the "+
				"thing being removed", asked)
		}
		if stats.Confirmed != 5 {
			t.Errorf("confirmed=%d, want 5", stats.Confirmed)
		}
		if spent := availBefore - budget.Available(); spent != 5 {
			t.Errorf("the pass spent %d credits for 5 remote calls; reconciliation that does not "+
				"draw on the budget is how a rate limit arrives mid-sweep", spent)
		}

		// And the next pass picks up where this one left off rather than
		// re-asking about the five it just confirmed: nothing starves.
		before = countCalls(remote.Calls(), "GetPR")
		if _, err := o.ReconcilePullRequests(ctx, orchestrator.ReconcileConfig{
			PR: remote, Repo: "org/api", MaxChecks: 5,
		}); err != nil {
			t.Fatalf("second pass: %v", err)
		}
		second := remote.Calls()[len(remote.Calls())-(countCalls(remote.Calls(), "GetPR")-before):]
		for _, call := range second {
			for i := 0; i < 5; i++ {
				// The first pass took the five never-confirmed pull requests in
				// branch order, which are numbers 1..5 on the fake.
				if call == fmt.Sprintf("GetPR org/api#%d", i+1) {
					t.Errorf("the second pass re-asked about %s, which the first pass just "+
						"confirmed; oldest-first ordering is what keeps a bounded batch from "+
						"starving the tail", call)
				}
			}
		}
	})
}

// TestReconciliationStopsWhenTheBudgetIsGoneAndSaysWhat is the other half of
// paying for itself: a pass that runs out of budget must report what it did not
// reach, not finish quietly.
func TestReconciliationStopsWhenTheBudgetIsGoneAndSaysWhat(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		remote := gh.NewFake("main")
		openPRs(t, s, remote, "org/api", 10)

		// Two credits for ten pull requests.
		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(2),
			orchestrator.Config{PR: remote, CreditsPerScan: 1})
		o.Clock = func() time.Time { return at.Add(time.Hour) }

		stats, err := o.ReconcilePullRequests(ctx, orchestrator.ReconcileConfig{
			PR: remote, Repo: "org/api", MaxChecks: 10,
		})
		if err != nil {
			t.Fatalf("ReconcilePullRequests: %v", err)
		}
		if stats.Examined != 2 {
			t.Errorf("examined=%d with two credits, want 2", stats.Examined)
		}
		if stats.Deferred != 8 {
			t.Errorf("deferred=%d, want 8: a pass that reached two of ten and reported nothing "+
				"deferred looks like a fleet with two pull requests", stats.Deferred)
		}
	})
}

// TestTheTwoPathsWriteTheSameHistory strengthens the Phase 12 agreement test.
//
// Agreeing on the final STATE is not enough: a report or a ticket quotes the
// reason code and the audit trail, so two paths that reach MERGED by different
// routes would produce two different records of the same event.
func TestTheTwoPathsWriteTheSameHistory(t *testing.T) {
	for _, merged := range []bool{true, false} {
		name := "declined"
		if merged {
			name = "merged"
		}
		t.Run(name, func(t *testing.T) {
			type outcome struct {
				state       model.State
				reason      string
				trail       []model.State
				prClosed    bool
				prMerged    bool
				verifiedRsn string
			}
			observe := func(t *testing.T, viaWebhook bool) outcome {
				t.Helper()
				ctx := context.Background()
				s := store.NewMemory()
				if err := s.Migrate(ctx); err != nil {
					t.Fatalf("migrate: %v", err)
				}
				remote := gh.NewFake("main")
				recs := openPRs(t, s, remote, "org/api", 1)
				rec := recs[0]
				fp := rec.Findings[0]

				o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50),
					orchestrator.Config{PR: remote, CreditsPerScan: 1})
				o.Clock = func() time.Time { return at.Add(time.Hour) }

				if merged {
					remote.MergePR("org/api", rec.Number)
				} else if err := remote.ClosePR(ctx, "org/api", rec.Number, "no"); err != nil {
					t.Fatalf("ClosePR: %v", err)
				}

				if viaWebhook {
					if _, err := o.ApplyWebhook(ctx, gh.Event{
						Kind: gh.EventPullRequestClosed, Repo: rec.Repo, Number: rec.Number,
						Branch: rec.Branch, Merged: merged,
					}); err != nil {
						t.Fatalf("ApplyWebhook: %v", err)
					}
				} else if _, err := o.ReconcilePullRequests(ctx, orchestrator.ReconcileConfig{
					PR: remote, Repo: "org/api",
				}); err != nil {
					t.Fatalf("ReconcilePullRequests: %v", err)
				}

				f, err := s.GetFinding(ctx, fp)
				if err != nil {
					t.Fatalf("GetFinding: %v", err)
				}
				trail, err := s.Transitions(ctx, fp)
				if err != nil {
					t.Fatalf("Transitions: %v", err)
				}
				var states []model.State
				for _, tr := range trail {
					states = append(states, tr.To)
				}
				pr, _, err := s.GetRemediationPR(ctx, rec.Branch)
				if err != nil {
					t.Fatalf("GetRemediationPR: %v", err)
				}
				out := outcome{
					state: f.State, trail: states,
					prClosed: pr.ClosedAt != nil, prMerged: pr.Merged,
				}
				if f.ReasonCode != nil {
					out.reason = string(*f.ReasonCode)
				}
				if f.VerifiedReason != nil {
					out.verifiedRsn = string(*f.VerifiedReason)
				}
				return out
			}

			viaWebhook := observe(t, true)
			viaReconcile := observe(t, false)

			if fmt.Sprintf("%+v", viaWebhook) != fmt.Sprintf("%+v", viaReconcile) {
				t.Errorf("the two paths wrote different histories for the same event:\n"+
					"  webhook:        %+v\n  reconciliation: %+v\n"+
					"Whichever fires first looks correct, and the divergence only surfaces when an "+
					"endpoint outage switches the system from one to the other", viaWebhook, viaReconcile)
			}
		})
	}
}

// TestNoPollingFunctionRemains is a deliberate structural assertion.
//
// The fallback must be reachable only through ReconcilePullRequests, which
// consults webhook health and the confirmation horizon. A second entry point
// that asked about every open pull request — even one kept "just for the
// sweep" — would restore the behaviour this item removed, and it would pass
// every behavioural test above.
func TestNoPollingFunctionRemains(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		remote := gh.NewFake("main")
		openPRs(t, s, remote, "org/api", 3)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50),
			orchestrator.Config{PR: remote, CreditsPerScan: 1})
		o.Clock = func() time.Time { return at.Add(time.Hour) }

		// A full sweep, which is where the poll used to live (step 6).
		repos, err := s.RepoNames(ctx)
		if err != nil {
			t.Fatalf("RepoNames: %v", err)
		}
		var fleetRepos []store.Repo
		for _, n := range repos {
			r, err := s.GetRepo(ctx, n)
			if err != nil {
				t.Fatalf("GetRepo: %v", err)
			}
			fleetRepos = append(fleetRepos, r)
		}
		d := orchestrator.NewFakeDispatcher()
		for _, r := range fleetRepos {
			d.WithFindings(r.Name, []string{"govulncheck"})
		}
		o2 := newOrchestrator(s, d, orchestrator.NewRateBudget(50),
			orchestrator.Config{PR: remote, CreditsPerScan: 1})
		o2.Clock = func() time.Time { return at.Add(time.Hour) }

		// The webhook vouched for every pull request a minute ago.
		for i := 1; i <= 3; i++ {
			if _, err := o.ApplyWebhook(ctx, gh.Event{
				Kind: gh.EventPullRequestOpened, Repo: "org/api", Number: i,
				Branch: fmt.Sprintf("security/fix-%04d", i-1),
			}); err != nil {
				t.Fatalf("ApplyWebhook: %v", err)
			}
		}

		before := countCalls(remote.Calls(), "GetPR")
		stats, err := o2.Sweep(ctx, store.KindSweep, "cron", fleetRepos, nil)
		if err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		asked := countCalls(remote.Calls(), "GetPR") - before

		if asked != 0 {
			t.Errorf("a full sweep made %d GetPR calls with every pull request freshly confirmed; "+
				"the sweep is still polling", asked)
		}
		if !stats.PRSync.WebhookLive {
			t.Error("the sweep's reconciliation did not see the webhook as live")
		}
	})
}
