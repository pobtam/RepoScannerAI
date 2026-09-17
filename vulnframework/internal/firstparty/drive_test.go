package firstparty_test

import (
	"context"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// Driving the waves against the store: the state changes, and the liveness
// invariant carried from Phase 9.

func driveStore(t *testing.T, repos ...string) store.Store {
	t.Helper()
	ctx := context.Background()
	s := store.NewMemory()
	s.SetClock(func() time.Time { return atTime })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, r := range repos {
		if err := s.UpsertRepo(ctx, store.Repo{
			Name: r, Tier: 1, Languages: []string{"go"}, HasTestSuite: true,
		}); err != nil {
			t.Fatalf("upsert repo %s: %v", r, err)
		}
	}
	return s
}

// consumerFinding is the same defect as seen in a consuming repository.
func consumerFinding(repo string) model.RawFinding {
	return model.RawFinding{
		Repo: repo, Category: model.CategoryDependency,
		PrimaryID: "GO-2025-3106", Module: "golang.org/x/crypto", ModuleMajor: "v0",
		Tool: "govulncheck", ToolVersion: "v1.8.0",
		Versions: model.Versions{Current: "v0.35.0", Fixed: "v0.36.0"},
		Classification: model.Classification{
			Severity: model.SeverityHigh, Reachable: model.ReachableTrue, DepClass: model.DepProduction,
		},
		ImportPath: []string{repo, sharedModule, "golang.org/x/crypto"},
	}
}

func seedTriaged(t *testing.T, s store.Store, raws ...model.RawFinding) []string {
	t.Helper()
	ctx := context.Background()
	byRepo := map[string][]model.RawFinding{}
	for _, r := range raws {
		byRepo[r.Repo] = append(byRepo[r.Repo], r)
	}
	run, err := s.CreateRun(ctx, store.KindSweep, "cron", "img", map[string]string{"govulncheck": "v1.8.0"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	var plan []store.PlanEntry
	for repo := range byRepo {
		plan = append(plan, store.PlanEntry{RunID: run.ID, Repo: repo, State: store.DispatchPlanned})
	}
	if err := s.RecordPlan(ctx, plan); err != nil {
		t.Fatalf("record plan: %v", err)
	}
	for repo, rs := range byRepo {
		if _, err := s.UpsertObservations(ctx, run.ID, repo, registry(t).ClassifyAll(rs)); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	var fps []string
	for _, r := range raws {
		fp := fingerprint.Compute(r)
		if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{
			Actor: model.ActorTriage, Cause: "test", At: atTime,
		}); err != nil {
			t.Fatalf("triage: %v", err)
		}
		fps = append(fps, fp)
	}
	return fps
}

// --- Wave 1 drives consumers to BLOCKED_UPSTREAM ----------------------------

func TestWaveOneBlocksConsumersWithAnUpstreamReference(t *testing.T) {
	ctx := context.Background()
	s := driveStore(t, consumerRepo, "org/wanaware-jobs", ownerRepo)

	fps := seedTriaged(t, s,
		consumerFinding(consumerRepo),
		consumerFinding("org/wanaware-jobs"),
	)

	idx := firstparty.NewIndex(registry(t))
	idx.Add(firstparty.Dependency{Repo: consumerRepo, Module: sharedModule, Version: "v1.4.0"})
	idx.Add(firstparty.Dependency{Repo: "org/wanaware-jobs", Module: sharedModule, Version: "v1.4.0"})

	driver := firstparty.NewDriver(s, idx)
	driver.Clock = func() time.Time { return atTime }

	stats, err := driver.ApplyWaveOne(ctx, firstparty.WaveRequest{
		Module: sharedModule, UpstreamFP: "upstream-fp-0001",
	}, fps)
	if err != nil {
		t.Fatalf("ApplyWaveOne: %v", err)
	}
	if stats.Blocked != 2 {
		t.Fatalf("blocked %d findings, want 2 (VM-F-604)", stats.Blocked)
	}

	for _, fp := range fps {
		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		if f.State != model.BlockedUpstream {
			t.Errorf("%s is %s, want BLOCKED_UPSTREAM", f.Repo, f.State)
		}
		if f.ReasonCode == nil || *f.ReasonCode != model.ReasonBlockedUpstreamFirstParty {
			t.Errorf("%s reason = %v, want BLOCKED_UPSTREAM_FIRST_PARTY (VM-F-609)", f.Repo, f.ReasonCode)
		}
		// Without the reference a consumer cannot discover what it is waiting
		// for: the finding says "blocked" and names nothing (VM-F-604).
		if f.Refs.UpstreamFinding == nil || *f.Refs.UpstreamFinding != "upstream-fp-0001" {
			t.Errorf("%s upstream reference = %v, want the owner's fingerprint", f.Repo, f.Refs.UpstreamFinding)
		}
	}
}

// --- Wave 2 drives them back to AUTO_REMEDIATING ----------------------------

func TestWaveTwoAdvancesBlockedConsumersButNotTheExcluded(t *testing.T) {
	ctx := context.Background()
	s := driveStore(t, consumerRepo, "org/wanaware-web", ownerRepo)

	fps := seedTriaged(t, s,
		consumerFinding(consumerRepo),
		consumerFinding("org/wanaware-web"),
	)

	idx := firstparty.NewIndex(registry(t))
	idx.Add(firstparty.Dependency{Repo: consumerRepo, Module: sharedModule, Version: "v1.4.0"})
	// A replace directive: excluded from the wave (VM-F-608).
	idx.Add(firstparty.Dependency{Repo: "org/wanaware-web", Module: sharedModule, Version: "v1.4.0", Replaced: true})

	driver := firstparty.NewDriver(s, idx)
	driver.Clock = func() time.Time { return atTime }

	req := firstparty.WaveRequest{Module: sharedModule, UpstreamFP: "upstream-fp-0001", TargetVersion: "v1.5.0"}
	if _, err := driver.ApplyWaveOne(ctx, req, fps); err != nil {
		t.Fatalf("ApplyWaveOne: %v", err)
	}

	stats, err := driver.ApplyWaveTwo(ctx, req)
	if err != nil {
		t.Fatalf("ApplyWaveTwo: %v", err)
	}
	if stats.Advanced != 1 {
		t.Errorf("advanced %d, want 1", stats.Advanced)
	}
	if stats.Excluded != 1 {
		t.Errorf("excluded %d, want 1", stats.Excluded)
	}

	advanced, err := s.GetFinding(ctx, fps[0])
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if advanced.State != model.AutoRemediating {
		t.Errorf("the dispatched consumer is %s, want AUTO_REMEDIATING (VM-F-606)", advanced.State)
	}

	// --- THE LIVENESS INVARIANT ------------------------------------------
	//
	// The excluded consumer is the one that matters. It cannot be advanced
	// automatically, so the question is what CAN move it. Left in
	// BLOCKED_UPSTREAM it waits for an upstream fix that has already shipped:
	// nothing will ever arrive, nothing escalates it, and it reads as
	// correctly-pending for ever. That is the stranding shape from Phase 9,
	// reached by a different route.
	excluded, err := s.GetFinding(ctx, fps[1])
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if excluded.State == model.BlockedUpstream {
		t.Fatal("the excluded consumer is still BLOCKED_UPSTREAM after the upstream fix shipped. " +
			"It is waiting for something that has already happened: nothing will arrive, nothing " +
			"escalates it, and it reads as correctly-pending for ever")
	}
	if excluded.State != model.NeedsHuman {
		t.Errorf("the excluded consumer is %s, want NEEDS_HUMAN — a replace directive needs a person "+
			"(VM-F-608)", excluded.State)
	}
	if excluded.ReasonCode == nil {
		t.Error("the excluded consumer carries no reason; it is a queue entry nobody can action")
	}
}

// TestWaveTwoIsLoudAboutWhatItDidNotDo carries recovery-must-be-loud into wave
// sequencing. A wave that advanced nine of twelve consumers and said nothing
// about the other three has reported success for a partial action.
func TestWaveTwoIsLoudAboutWhatItDidNotDo(t *testing.T) {
	ctx := context.Background()
	s := driveStore(t, consumerRepo, "org/wanaware-web", ownerRepo)
	fps := seedTriaged(t, s, consumerFinding(consumerRepo), consumerFinding("org/wanaware-web"))

	idx := firstparty.NewIndex(registry(t))
	idx.Add(firstparty.Dependency{Repo: consumerRepo, Module: sharedModule, Version: "v1.4.0"})
	idx.Add(firstparty.Dependency{Repo: "org/wanaware-web", Module: sharedModule, Version: "v1.4.0", Replaced: true})

	driver := firstparty.NewDriver(s, idx)
	driver.Clock = func() time.Time { return atTime }
	req := firstparty.WaveRequest{Module: sharedModule, UpstreamFP: "up", TargetVersion: "v1.5.0"}
	if _, err := driver.ApplyWaveOne(ctx, req, fps); err != nil {
		t.Fatalf("ApplyWaveOne: %v", err)
	}
	stats, err := driver.ApplyWaveTwo(ctx, req)
	if err != nil {
		t.Fatalf("ApplyWaveTwo: %v", err)
	}
	if len(stats.Notes) == 0 {
		t.Fatal("the wave recorded nothing about the consumer it could not advance")
	}
	var named bool
	for _, n := range stats.Notes {
		if containsAll(n, "org/wanaware-web", "replace") {
			named = true
		}
	}
	if !named {
		t.Errorf("the wave's notes do not name the excluded consumer and why: %v", stats.Notes)
	}
}

// --- The negative: Wave 2 must not touch what it did not block -------------

// TestWaveTwoDoesNotAdvanceAFindingItNeverBlocked is the negative assertion.
//
// A wave that advanced every finding matching the module would pull in
// findings a human had declined, suppressed, or already fixed — reopening
// settled work on the strength of a module name.
func TestWaveTwoDoesNotAdvanceAFindingItNeverBlocked(t *testing.T) {
	ctx := context.Background()
	s := driveStore(t, consumerRepo, ownerRepo)
	fps := seedTriaged(t, s, consumerFinding(consumerRepo))

	// The finding is declined by a human, not blocked by a wave.
	if err := s.ApplyTransition(ctx, fps[0], model.NeedsHuman, model.TransitionContext{
		Actor: model.ActorOrchestrator, Cause: "policy", At: atTime,
	}); err != nil {
		t.Fatalf("to needs human: %v", err)
	}

	idx := firstparty.NewIndex(registry(t))
	idx.Add(firstparty.Dependency{Repo: consumerRepo, Module: sharedModule, Version: "v1.4.0"})

	driver := firstparty.NewDriver(s, idx)
	driver.Clock = func() time.Time { return atTime }

	stats, err := driver.ApplyWaveTwo(ctx, firstparty.WaveRequest{
		Module: sharedModule, UpstreamFP: "up", TargetVersion: "v1.5.0",
	})
	if err != nil {
		t.Fatalf("ApplyWaveTwo: %v", err)
	}
	if stats.Advanced != 0 {
		t.Errorf("the wave advanced %d findings it never blocked; a wave that moves everything "+
			"matching the module reopens work a human already settled", stats.Advanced)
	}

	f, _ := s.GetFinding(ctx, fps[0])
	if f.State != model.NeedsHuman {
		t.Errorf("state = %s, want NEEDS_HUMAN unchanged", f.State)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
