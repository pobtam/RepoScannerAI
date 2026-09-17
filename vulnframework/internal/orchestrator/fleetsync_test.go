package orchestrator_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/store"
)

// Fleet sync (A18, VM-OQ-10) and VM-F-614.

// --- Fleet sync: an unsynced repository is a gap, never invisible ----------

// TestARepositoryAddedOnGitHubButUnsyncedAppearsAsAGap is the coverage-honesty
// clause, and it is the whole reason A18 was recorded at Phase 4.
//
// Coverage is measured against PLANNED scope (OQ-P2-02), and planned scope
// comes from the registry. If the registry is stale, a repository that exists
// and has never been scanned is not a gap — it is absent from the denominator
// entirely, and the fleet reports 100% coverage while missing it. That is the
// most dangerous number this system can produce: complete, confident, and
// wrong in the direction of safety.
func TestARepositoryAddedOnGitHubButUnsyncedAppearsAsAGap(t *testing.T) {
	ctx := context.Background()
	s := newMemStore(t)

	// The registry knows one repository.
	if err := s.UpsertRepo(ctx, store.Repo{
		Name: "org/known", Tier: 2, Languages: []string{"go"}, HasTestSuite: true,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// GitHub has two. The second was created this morning.
	app := gh.NewFakeApp().
		WithRepo(gh.RemoteRepo{FullName: "org/known", DefaultBranch: "main", Languages: []string{"Go"}}).
		WithRepo(gh.RemoteRepo{FullName: "org/brand-new", DefaultBranch: "main", Languages: []string{"Go"}})

	o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
	o.Clock = func() time.Time { return at }

	// BEFORE the sync, the unsynced repository must be visible as a gap rather
	// than absent. This is the assertion that matters: a system that can only
	// see what it has already synced cannot report what it has missed.
	drift, err := o.FleetDrift(ctx, app)
	if err != nil {
		t.Fatalf("FleetDrift: %v", err)
	}
	if len(drift.Unsynced) != 1 || drift.Unsynced[0] != "org/brand-new" {
		t.Fatalf("unsynced = %v, want [org/brand-new]. A repository that exists on GitHub and is "+
			"absent from the registry is not in the coverage denominator at all: the fleet reports "+
			"full coverage while never having looked at it", drift.Unsynced)
	}
	if drift.Clean() {
		t.Error("the fleet reads as clean while a repository is unsynced")
	}
	if !strings.Contains(strings.ToLower(drift.Summary()), "org/brand-new") {
		t.Errorf("the summary does not name the unsynced repository: %s", drift.Summary())
	}

	// After the sync it is an ordinary member of the fleet.
	stats, err := o.SyncFleet(ctx, app)
	if err != nil {
		t.Fatalf("SyncFleet: %v", err)
	}
	if stats.Added != 1 {
		t.Errorf("added %d repositories, want 1", stats.Added)
	}
	names, err := s.RepoNames(ctx)
	if err != nil {
		t.Fatalf("RepoNames: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("the registry holds %v, want both repositories", names)
	}

	drift, err = o.FleetDrift(ctx, app)
	if err != nil {
		t.Fatalf("FleetDrift: %v", err)
	}
	if !drift.Clean() {
		t.Errorf("the fleet still reads as drifted after a sync: %s", drift.Summary())
	}
}

// TestARepositoryDeletedOnGitHubIsNotSilentlyDropped is the other direction,
// and the subtler one.
//
// Removing it from the registry would make historical coverage unreadable: the
// runs that scanned it would reference a repository nobody can look up. It is
// ARCHIVED instead, which keeps the history intact and takes it out of the
// denominator honestly.
func TestARepositoryDeletedOnGitHubIsNotSilentlyDropped(t *testing.T) {
	ctx := context.Background()
	s := newMemStore(t)
	for _, name := range []string{"org/kept", "org/deleted"} {
		if err := s.UpsertRepo(ctx, store.Repo{
			Name: name, Tier: 2, Languages: []string{"go"}, HasTestSuite: true,
		}); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	app := gh.NewFakeApp().
		WithRepo(gh.RemoteRepo{FullName: "org/kept", DefaultBranch: "main", Languages: []string{"Go"}})

	o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
	o.Clock = func() time.Time { return at }

	stats, err := o.SyncFleet(ctx, app)
	if err != nil {
		t.Fatalf("SyncFleet: %v", err)
	}
	if stats.Archived != 1 {
		t.Errorf("archived %d, want 1", stats.Archived)
	}

	gone, err := s.GetRepo(ctx, "org/deleted")
	if err != nil {
		t.Fatalf("the deleted repository was removed from the registry entirely: %v. Its historical "+
			"scan results now reference a repository nobody can look up", err)
	}
	if !gone.Archived {
		t.Error("the deleted repository is not archived; it would stay in the coverage denominator " +
			"and report as a permanent gap nobody can close")
	}
}

// TestSyncFailureDoesNotSilentlyEmptyTheFleet is the negative that would be
// catastrophic. A GitHub outage returning an empty list must not archive the
// entire fleet — which would read, next sweep, as nothing to scan.
func TestSyncFailureDoesNotSilentlyEmptyTheFleet(t *testing.T) {
	ctx := context.Background()
	s := newMemStore(t)
	for _, name := range []string{"org/a", "org/b", "org/c"} {
		if err := s.UpsertRepo(ctx, store.Repo{
			Name: name, Tier: 2, Languages: []string{"go"}, HasTestSuite: true,
		}); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
	o.Clock = func() time.Time { return at }

	// An App that returns nothing, as a permissions change or an outage would.
	empty := gh.NewFakeApp()
	if _, err := o.SyncFleet(ctx, empty); err == nil {
		t.Fatal("a sync returning no repositories archived the entire fleet. Next sweep there would " +
			"be nothing to scan, every finding would stop being re-observed, and the coverage report " +
			"would say 100%")
	}
	for _, name := range []string{"org/a", "org/b", "org/c"} {
		r, err := s.GetRepo(ctx, name)
		if err != nil {
			t.Fatalf("get repo: %v", err)
		}
		if r.Archived {
			t.Errorf("%s was archived by an empty sync", name)
		}
	}

	// An App that errors is likewise not evidence of anything.
	broken := gh.NewFakeApp().FailWith(errors.New("401 Bad credentials"))
	if _, err := o.SyncFleet(ctx, broken); err == nil {
		t.Error("a failing sync reported success")
	}
}

// --- VM-F-614: merged without publish ---------------------------------------

// TestMergedWave1WithNoTagIsEscalated covers VM-F-614, which the specification
// calls "the most common silent failure of the two-wave design".
//
// Where wave2_trigger is `tag`, merging the Wave 1 pull request releases
// nothing. The pull request closes, the upstream finding looks handled, and
// every consumer stays blocked with nothing signalling it. Each individual
// signal is correct — the merge happened, the consumers are legitimately
// waiting — and the combination is a fleet quietly stuck.
func TestMergedWave1WithNoTagIsEscalated(t *testing.T) {
	ctx := context.Background()
	s := newMemStore(t)
	repos := fleet(t, s, "org/api", "org/common")

	// A consumer blocked on an upstream fix.
	raw := depFinding("org/api", "GO-2025-3487", "v0.16.0", "v0.16.1")
	seedDetected(t, s, repos, raw)
	fp := fingerprint.Compute(raw)
	mustTransition(t, s, fp, model.Triaged, model.ActorTriage)
	mustTransition(t, s, fp, model.BlockedUpstream, model.ActorOrchestrator)
	if err := s.SetUpstreamFinding(ctx, fp, "upstream-fp-0001"); err != nil {
		t.Fatalf("SetUpstreamFinding: %v", err)
	}

	// The Wave 1 pull request merged two days ago, in the owning repository.
	// Closed through the real path, because that is how production reaches
	// this state and it is what sets the merge timestamp the grace period
	// measures from.
	if err := s.SaveRemediationPR(ctx, store.RemediationPR{
		Branch: "security/fix-upstream", Repo: "org/common", FixGroupID: "upstream",
		Number: 7, URL: "https://github.com/org/common/pull/7", State: "open",
		OpenedAt: at.Add(-96 * time.Hour), Findings: []string{},
	}); err != nil {
		t.Fatalf("SaveRemediationPR: %v", err)
	}
	if err := s.CloseRemediationPR(ctx, "security/fix-upstream", at.Add(-72*time.Hour), true); err != nil {
		t.Fatalf("CloseRemediationPR: %v", err)
	}

	o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
	o.Clock = func() time.Time { return at }

	// No tag was pushed.
	app := gh.NewFakeApp().WithRepo(gh.RemoteRepo{FullName: "org/common", DefaultBranch: "main"})

	escalations, err := o.DetectMergedWithoutPublish(ctx, app, orchestrator.PublishWatch{
		Owner: "org/common", Branch: "security/fix-upstream",
		Module: "github.com/wanaware/common", Grace: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("DetectMergedWithoutPublish: %v", err)
	}
	if len(escalations) != 1 {
		t.Fatalf("%d escalations, want 1 (VM-F-614)", len(escalations))
	}
	e := escalations[0]
	if e.BlockedConsumers != 1 {
		t.Errorf("blocked consumers = %d, want 1", e.BlockedConsumers)
	}
	// The escalation must say what is wrong, because every individual signal
	// looks correct and nobody will work it out from the states alone.
	for _, want := range []string{"merged", "tag", "blocked"} {
		if !strings.Contains(strings.ToLower(e.Reason), want) {
			t.Errorf("the escalation does not mention %q: %s", want, e.Reason)
		}
	}
	if o.Recovery == nil || len(o.Recovery.Events()) == 0 {
		t.Error("the escalation was not recorded; recovery must be loud, and this is the failure the " +
			"specification calls the most common one of the whole design")
	}
}

// TestAPublishedTagIsNotEscalated is the negative half. The escalation must
// not fire on the ordinary case, or it becomes noise and is filtered out —
// taking the real one with it.
func TestAPublishedTagIsNotEscalated(t *testing.T) {
	ctx := context.Background()
	s := newMemStore(t)
	fleet(t, s, "org/common")

	if err := s.SaveRemediationPR(ctx, store.RemediationPR{
		Branch: "security/fix-upstream", Repo: "org/common", FixGroupID: "upstream",
		Number: 7, URL: "u", State: "open",
		OpenedAt: at.Add(-96 * time.Hour), Findings: []string{},
	}); err != nil {
		t.Fatalf("SaveRemediationPR: %v", err)
	}
	if err := s.CloseRemediationPR(ctx, "security/fix-upstream", at.Add(-72*time.Hour), true); err != nil {
		t.Fatalf("CloseRemediationPR: %v", err)
	}

	o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
	o.Clock = func() time.Time { return at }

	// The tag exists.
	app := gh.NewFakeApp().
		WithRepo(gh.RemoteRepo{FullName: "org/common", DefaultBranch: "main"}).
		WithTag("org/common", "v1.5.0", at.Add(-time.Hour))

	escalations, err := o.DetectMergedWithoutPublish(ctx, app, orchestrator.PublishWatch{
		Owner: "org/common", Branch: "security/fix-upstream",
		Module: "github.com/wanaware/common", Grace: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("DetectMergedWithoutPublish: %v", err)
	}
	if len(escalations) != 0 {
		t.Errorf("%d escalations for a published tag: %+v. An escalation that fires on the ordinary "+
			"case becomes noise and is filtered out, taking the real one with it", len(escalations), escalations)
	}
}

// TestTheGracePeriodIsRespected stops the escalation firing between a merge
// and the release job that follows it minutes later.
func TestTheGracePeriodIsRespected(t *testing.T) {
	ctx := context.Background()
	s := newMemStore(t)
	fleet(t, s, "org/common")

	// Merged ten minutes ago.
	if err := s.SaveRemediationPR(ctx, store.RemediationPR{
		Branch: "security/fix-upstream", Repo: "org/common", FixGroupID: "upstream",
		Number: 7, URL: "u", State: "open",
		OpenedAt: at.Add(-time.Hour), Findings: []string{},
	}); err != nil {
		t.Fatalf("SaveRemediationPR: %v", err)
	}
	if err := s.CloseRemediationPR(ctx, "security/fix-upstream", at.Add(-10*time.Minute), true); err != nil {
		t.Fatalf("CloseRemediationPR: %v", err)
	}

	o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
	o.Clock = func() time.Time { return at }
	app := gh.NewFakeApp().WithRepo(gh.RemoteRepo{FullName: "org/common", DefaultBranch: "main"})

	escalations, err := o.DetectMergedWithoutPublish(ctx, app, orchestrator.PublishWatch{
		Owner: "org/common", Branch: "security/fix-upstream",
		Module: "github.com/wanaware/common", Grace: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("DetectMergedWithoutPublish: %v", err)
	}
	if len(escalations) != 0 {
		t.Error("the escalation fired inside the grace period; a release job that runs minutes after " +
			"a merge would page someone every time")
	}
}
