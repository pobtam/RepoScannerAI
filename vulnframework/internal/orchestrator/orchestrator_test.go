package orchestrator_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/store/storetest"
)

// The Phase 4 gate, extended:
//
//   a full sweep across ≥5 repositories;
//   an in-scope repository never dispatched produces a not_dispatched row and
//     shows as a coverage gap, never as silently clean;
//   exceeding the rate budget produces not_dispatched-with-reason rows rather
//     than silent omission;
//   a lease that expires returns its finding AUTO_REMEDIATING → TRIAGED;
//   and the cross-phase case: a finding under an active lease that disappears
//     on a qualifying scan verifies as external AND releases the lease cleanly.

type backend struct {
	name string
	open func(t *testing.T) store.Store
}

func backends(t *testing.T) []backend {
	t.Helper()
	out := []backend{{
		name: "memory",
		open: func(t *testing.T) store.Store {
			s := store.NewMemory()
			s.SetClock(fixedClock())
			if err := s.Migrate(context.Background()); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			return s
		},
	}}

	if os.Getenv(storetest.EnvDSN) == "" {
		return out
	}
	out = append(out, backend{
		name: "postgres",
		open: func(t *testing.T) store.Store {
			t.Helper()
			db := storetest.OpenDB(t, "orchestrator")
			ctx := context.Background()
			if err := store.NewPostgres(db).MigrateTo(ctx, 0); err != nil {
				t.Fatalf("reset schema: %v", err)
			}
			s := store.NewPostgres(db)
			s.SetClock(fixedClock())
			if err := s.Migrate(ctx); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			return s
		},
	})
	return out
}

// fixedClock advances a deterministic clock one second per call.
//
// It is mutex-guarded because the store calls its clock from concurrent
// dispatch goroutines; an unsynchronised counter here races under -race and the
// failure looks like a production bug rather than a test one.
func fixedClock() func() time.Time {
	base := time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	n := 0
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		n++
		return base.Add(time.Duration(n) * time.Second)
	}
}

// at is the deterministic base instant the tests reason about. The
// orchestrator keeps its own clock, so a test that cares about lease timing
// must pin both it and the store's, or expiry is measured against wall time.
var at = time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)

// newOrchestrator builds one with a pinned clock.
func newOrchestrator(s store.Store, d orchestrator.Dispatcher, b *orchestrator.RateBudget, cfg orchestrator.Config) *orchestrator.Orchestrator {
	o := orchestrator.New(s, d, b, cfg)
	o.Clock = func() time.Time { return at }
	return o
}

func run(t *testing.T, fn func(t *testing.T, s store.Store)) {
	t.Helper()
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) { fn(t, b.open(t)) })
	}
}

// fleet registers n repositories and returns them.
func fleet(t *testing.T, s store.Store, names ...string) []store.Repo {
	t.Helper()
	var out []store.Repo
	for _, n := range names {
		r := store.Repo{Name: n, Tier: 2, Languages: []string{"go"}, HasTestSuite: true}
		if err := s.UpsertRepo(context.Background(), r); err != nil {
			t.Fatalf("upsert repo %s: %v", n, err)
		}
		out = append(out, r)
	}
	return out
}

func finding(repo, advisory string) model.RawFinding {
	return model.RawFinding{
		Repo: repo, Category: model.CategoryDependency,
		PrimaryID: advisory, Tool: "govulncheck", ToolVersion: "v1.8.0",
		Module: "golang.org/x/crypto", ModuleMajor: "v0",
		Versions: model.Versions{Current: "v0.16.0", Fixed: "v0.36.0"},
		Classification: model.Classification{
			Severity: model.SeverityHigh, Reachable: model.ReachableTrue,
			DepClass: model.DepProduction,
		},
	}
}

func outcomeFor(t *testing.T, s store.Store, repo, runID string) store.RepoScanResult {
	t.Helper()
	results, err := s.ScanResults(context.Background(), repo, 50)
	if err != nil {
		t.Fatalf("scan results for %s: %v", repo, err)
	}
	for _, r := range results {
		if r.RunID == runID {
			return r
		}
	}
	t.Fatalf("no scan result for %s in %s — coverage is measured against planned scope, so every planned repository must leave a row (OQ-P2-02)", repo, runID)
	return store.RepoScanResult{}
}

// --- Gate: a full sweep across the fleet ------------------------------------

func TestSweepAcrossFleet(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/a", "org/b", "org/c", "org/d", "org/e")

		d := orchestrator.NewFakeDispatcher()
		for _, r := range repos {
			d.WithFindings(r.Name, []string{"govulncheck"}, finding(r.Name, "GO-2025-3487"))
		}

		o := newOrchestrator(s, d, orchestrator.NewRateBudget(100), orchestrator.Config{
			MaxConcurrentScans: 3, CreditsPerScan: 1, ScannerImage: "img@sha256:abc",
		})

		stats, err := o.Sweep(ctx, store.KindSweep, "cron", repos, nil)
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}
		if stats.Planned != 5 || stats.Dispatched != 5 {
			t.Fatalf("planned=%d dispatched=%d, want 5/5", stats.Planned, stats.Dispatched)
		}
		if stats.Close.Produced != 5 {
			t.Errorf("produced=%d, want 5", stats.Close.Produced)
		}
		if stats.Close.NotDispatched != 0 || stats.Close.NoResult != 0 {
			t.Errorf("unexpected gaps: not_dispatched=%d no_result=%d", stats.Close.NotDispatched, stats.Close.NoResult)
		}

		// Every repository's finding landed.
		all, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(all) != 5 {
			t.Errorf("got %d findings, want one per repository", len(all))
		}
		for _, r := range repos {
			if got := outcomeFor(t, s, r.Name, stats.RunID).Outcome; got != model.ScanComplete {
				t.Errorf("%s outcome = %q, want complete", r.Name, got)
			}
		}
	})
}

// --- Gate: an in-scope repository that never runs is a gap, not silence -----

// TestUndispatchedRepoIsAGapNotSilence is the OQ-P2-02 clause. Coverage is
// measured against planned scope: a repository that never ran must appear, or
// the fleet looks smaller than it is and nobody notices the hole.
func TestUndispatchedRepoIsAGapNotSilence(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/a", "org/b", "org/never-runs")

		d := orchestrator.NewFakeDispatcher()
		d.WithFindings("org/a", []string{"govulncheck"}, finding("org/a", "GO-2025-3487"))
		d.WithFindings("org/b", []string{"govulncheck"}, finding("org/b", "GO-2025-3487"))
		// org/never-runs is dispatched but its worker never reports.
		d.WithSilentWorker("org/never-runs")

		o := newOrchestrator(s, d, orchestrator.NewRateBudget(100), orchestrator.Config{CreditsPerScan: 1})
		stats, err := o.Sweep(ctx, store.KindSweep, "cron", repos, nil)
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}

		// It must not be silently absent.
		res := outcomeFor(t, s, "org/never-runs", stats.RunID)

		// Dispatched-and-lost is no_result, distinct from never-started and
		// from a tool failure: different owner, different remedy.
		if res.Outcome != model.ScanNoResult {
			t.Errorf("outcome = %q, want no_result: the worker was dispatched and produced nothing", res.Outcome)
		}
		if res.Outcome == model.ScanFailed {
			t.Error("a lost worker was folded into 'failed'; three different problems would share one number")
		}
		if res.FailureCause != store.CauseWorkerNoResult {
			t.Errorf("failure_cause = %q, want %q", res.FailureCause, store.CauseWorkerNoResult)
		}
		if !res.Outcome.IsGap() {
			t.Error("the outcome does not count as a coverage gap")
		}
		if stats.Close.NoResult != 1 {
			t.Errorf("close no_result=%d, want 1", stats.Close.NoResult)
		}
	})
}

// TestPlannedButNeverDispatchedIsRecorded covers the other half: a repository
// in the plan that dispatch never reached at all.
func TestPlannedButNeverDispatchedIsRecorded(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fleet(t, s, "org/a")

		// Plan it, then close the run without ever dispatching.
		r, err := s.CreateRun(ctx, store.KindSweep, "cron", "img", nil)
		if err != nil {
			t.Fatalf("create run: %v", err)
		}
		if err := s.RecordPlan(ctx, []store.PlanEntry{
			{RunID: r.ID, Repo: "org/a", State: store.DispatchPlanned},
		}); err != nil {
			t.Fatalf("record plan: %v", err)
		}

		stats, err := s.CloseRun(ctx, r.ID)
		if err != nil {
			t.Fatalf("close run: %v", err)
		}
		if stats.NotDispatched != 1 {
			t.Fatalf("not_dispatched=%d, want 1", stats.NotDispatched)
		}

		res := outcomeFor(t, s, "org/a", r.ID)
		if res.Outcome != model.ScanNotDispatched {
			t.Errorf("outcome = %q, want not_dispatched", res.Outcome)
		}
		if res.FailureCause != store.SkipNeverDispatched {
			t.Errorf("failure_cause = %q, want %q — this one means dispatch itself failed",
				res.FailureCause, store.SkipNeverDispatched)
		}
	})
}

// --- Gate: budget exhaustion is a recorded skip, not silence ---------------

func TestBudgetExhaustionRecordsSkippedRows(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/a", "org/b", "org/c", "org/d", "org/e")

		d := orchestrator.NewFakeDispatcher()
		for _, r := range repos {
			d.WithFindings(r.Name, []string{"govulncheck"}, finding(r.Name, "GO-2025-3487"))
		}

		// Only two repositories can be funded.
		o := newOrchestrator(s, d, orchestrator.NewRateBudget(2), orchestrator.Config{CreditsPerScan: 1})
		stats, err := o.Sweep(ctx, store.KindSweep, "cron", repos, nil)
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}

		if stats.Dispatched != 2 {
			t.Errorf("dispatched=%d, want 2 (the budget funds no more)", stats.Dispatched)
		}
		if stats.Skipped != 3 {
			t.Errorf("skipped=%d, want 3", stats.Skipped)
		}

		// Every planned repository leaves a row, and the three deferred ones say
		// why. Silent omission is the failure this guards against.
		budgetSkips := 0
		for _, r := range repos {
			res := outcomeFor(t, s, r.Name, stats.RunID)
			if res.Outcome == model.ScanNotDispatched && res.FailureCause == store.SkipBudgetExhausted {
				budgetSkips++
			}
		}
		if budgetSkips != 3 {
			t.Errorf("%d repositories recorded as deferred for budget, want 3", budgetSkips)
		}
		if got := stats.Close.SkipReasons[store.SkipBudgetExhausted]; got != 3 {
			t.Errorf("close skip reasons budget=%d, want 3", got)
		}
	})
}

func TestRateBudgetAccounting(t *testing.T) {
	b := orchestrator.NewRateBudget(3)

	if err := b.Acquire(2); err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	if got := b.Available(); got != 1 {
		t.Errorf("available=%d, want 1", got)
	}

	err := b.Acquire(2)
	var exhausted *orchestrator.ErrBudgetExhausted
	if !errors.As(err, &exhausted) {
		t.Fatalf("got %v, want ErrBudgetExhausted", err)
	}

	// Unused credits return to the pool; spent ones do not.
	b.Release(1)
	if got := b.Available(); got != 2 {
		t.Errorf("after release available=%d, want 2", got)
	}
	b.Consume(1)
	if got := b.Available(); got != 2 {
		t.Errorf("after consume available=%d, want 2 (spent credits are not returned)", got)
	}

	b.Refresh(50)
	if got := b.Available(); got != 50 {
		t.Errorf("after refresh available=%d, want 50", got)
	}
}

// --- Gate: lease expiry returns AUTO_REMEDIATING to TRIAGED ----------------

// TestExpiredLeaseRevertsFinding covers VM-F-158: worker failure must not leave
// a finding permanently in a transient state.
func TestExpiredLeaseRevertsFinding(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/a")

		d := orchestrator.NewFakeDispatcher().
			WithFindings("org/a", []string{"govulncheck"}, finding("org/a", "GO-2025-3487"))
		o := newOrchestrator(s, d, orchestrator.NewRateBudget(10), orchestrator.Config{
			CreditsPerScan: 1, LeaseDuration: time.Minute,
		})
		if _, err := o.Sweep(ctx, store.KindSweep, "cron", repos, nil); err != nil {
			t.Fatalf("sweep: %v", err)
		}

		fp := fingerprint.Compute(finding("org/a", "GO-2025-3487"))
		if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{Actor: model.ActorTriage}); err != nil {
			t.Fatalf("triage: %v", err)
		}

		// Dispatch to a remediation worker, then let the worker die.
		if err := o.Lease(ctx, fp, "fixworker-7"); err != nil {
			t.Fatalf("lease: %v", err)
		}
		f, _ := s.GetFinding(ctx, fp)
		if f.State != model.AutoRemediating {
			t.Fatalf("state = %q, want AUTO_REMEDIATING", f.State)
		}
		lease, _ := s.GetLease(ctx, fp)
		if !lease.Held() {
			t.Fatal("no lease held after dispatch")
		}

		// Sweeping before expiry must change nothing.
		n, err := s.SweepExpiredLeases(ctx, at.Add(30*time.Second))
		if err != nil {
			t.Fatalf("early sweep: %v", err)
		}
		if n != 0 {
			t.Errorf("early sweep reverted %d findings, want 0", n)
		}

		// After expiry the finding returns to TRIAGED and the claim is cleared.
		n, err = s.SweepExpiredLeases(ctx, at.Add(time.Hour))
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}
		if n != 1 {
			t.Fatalf("sweep reverted %d findings, want 1 (VM-F-158)", n)
		}
		f, _ = s.GetFinding(ctx, fp)
		if f.State != model.Triaged {
			t.Errorf("state = %q, want TRIAGED after lease expiry", f.State)
		}
		lease, _ = s.GetLease(ctx, fp)
		if lease.Held() {
			t.Errorf("lease still held by %q after expiry", lease.Owner)
		}

		// And it is re-dispatchable: the point of reverting is that the work
		// can be retried.
		if err := o.Lease(ctx, fp, "fixworker-8"); err != nil {
			t.Errorf("finding could not be re-dispatched after lease expiry: %v", err)
		}
	})
}

// --- Gate: the cross-phase case --------------------------------------------

// TestLeasedFindingThatDisappearsVerifiesAndReleasesLease is the interaction
// between Phase 4's leases and the §6.1.1 verification rule.
//
// A finding can be fixed by someone else while the framework's own remediation
// is in flight. It must verify as external — the framework merged nothing — and
// the lease must not survive, or the sweeper keeps finding a closed finding and
// the worker's slot is never returned.
func TestLeasedFindingThatDisappearsVerifiesAndReleasesLease(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/a")
		fp := fingerprint.Compute(finding("org/a", "GO-2025-3487"))

		// Run 1 observes it.
		d := orchestrator.NewFakeDispatcher().
			WithFindings("org/a", []string{"govulncheck"}, finding("org/a", "GO-2025-3487"))
		o := newOrchestrator(s, d, orchestrator.NewRateBudget(10), orchestrator.Config{
			CreditsPerScan: 1, LeaseDuration: time.Hour,
		})
		if _, err := o.Sweep(ctx, store.KindSweep, "cron", repos, nil); err != nil {
			t.Fatalf("sweep 1: %v", err)
		}

		if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{Actor: model.ActorTriage}); err != nil {
			t.Fatalf("triage: %v", err)
		}
		if err := o.Lease(ctx, fp, "fixworker-7"); err != nil {
			t.Fatalf("lease: %v", err)
		}
		if lease, _ := s.GetLease(ctx, fp); !lease.Held() {
			t.Fatal("no lease held before the second sweep")
		}

		// Run 2 completes successfully and no longer sees it: someone else
		// fixed it while remediation was in flight.
		d2 := orchestrator.NewFakeDispatcher().
			WithOutcome("org/a", model.ScanComplete, []string{"govulncheck"}, nil)
		o2 := newOrchestrator(s, d2, orchestrator.NewRateBudget(10), orchestrator.Config{CreditsPerScan: 1})
		stats, err := o2.Sweep(ctx, store.KindSweep, "cron", repos, nil)
		if err != nil {
			t.Fatalf("sweep 2: %v", err)
		}
		if got := stats.Reconcile["org/a"].Verified; got != 1 {
			t.Fatalf("verified=%d, want 1", got)
		}

		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		if f.State != model.Verified {
			t.Errorf("state = %q, want VERIFIED", f.State)
		}
		// The framework merged nothing, so it must not claim credit.
		if f.VerifiedReason == nil || *f.VerifiedReason != model.VerifiedExternal {
			t.Errorf("verified_reason = %v, want external (OQ-P2-01)", f.VerifiedReason)
		}

		// The lease must be gone.
		lease, err := s.GetLease(ctx, fp)
		if err != nil {
			t.Fatalf("get lease: %v", err)
		}
		if lease.Held() {
			t.Errorf("a verified finding still holds a lease owned by %q; the sweeper would keep finding it", lease.Owner)
		}

		// And a later sweep must find nothing stuck.
		n, err := s.SweepExpiredLeases(ctx, at.AddDate(1, 0, 0))
		if err != nil {
			t.Fatalf("sweep leases: %v", err)
		}
		if n != 0 {
			t.Errorf("lease sweeper reverted %d findings long after verification; a stuck lease was left behind", n)
		}
		f, _ = s.GetFinding(ctx, fp)
		if f.State != model.Verified {
			t.Errorf("state = %q after a later lease sweep, want VERIFIED undisturbed", f.State)
		}
	})
}

// --- Planned scope bookkeeping ---------------------------------------------

func TestArchivedRepoIsExcludedWithAReason(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/a")
		archived := store.Repo{Name: "org/archived", Tier: 3, Archived: true}
		if err := s.UpsertRepo(ctx, archived); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		repos = append(repos, archived)

		d := orchestrator.NewFakeDispatcher().
			WithFindings("org/a", []string{"govulncheck"}, finding("org/a", "GO-2025-3487"))
		o := newOrchestrator(s, d, orchestrator.NewRateBudget(10), orchestrator.Config{CreditsPerScan: 1})

		stats, err := o.Sweep(ctx, store.KindSweep, "cron", repos, nil)
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}
		// Archived repositories are out of scope, so they are not counted as
		// planned coverage — but the decision is still recorded.
		if stats.Planned != 1 {
			t.Errorf("planned=%d, want 1 (the archived repository is out of scope)", stats.Planned)
		}

		entries, err := s.PlanEntries(ctx, stats.RunID)
		if err != nil {
			t.Fatalf("plan entries: %v", err)
		}
		var found bool
		for _, e := range entries {
			if e.Repo == "org/archived" {
				found = true
				if e.State != store.DispatchSkipped || e.SkipReason != store.SkipArchived {
					t.Errorf("archived entry = %+v, want skipped/archived", e)
				}
			}
		}
		if !found {
			t.Error("the archived repository left no plan entry; the exclusion is unauditable")
		}
	})
}

func TestSkipRequiresAReason(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fleet(t, s, "org/a")
		r, err := s.CreateRun(ctx, store.KindSweep, "cron", "img", nil)
		if err != nil {
			t.Fatalf("create run: %v", err)
		}
		if err := s.RecordPlan(ctx, []store.PlanEntry{{RunID: r.ID, Repo: "org/a", State: store.DispatchPlanned}}); err != nil {
			t.Fatalf("record plan: %v", err)
		}
		if err := s.MarkSkipped(ctx, r.ID, "org/a", ""); err == nil {
			t.Error("a skip with no reason was accepted; the gaps view would have nothing to group by")
		}
	})
}

// TestFindingsInAnUndispatchedRepoAreFlaggedNotVerified is the interaction
// between planned scope and VM-ADR-12: a repository that never ran cannot
// verify anything.
func TestFindingsInAnUndispatchedRepoAreFlaggedNotVerified(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/a")
		fp := fingerprint.Compute(finding("org/a", "GO-2025-3487"))

		d := orchestrator.NewFakeDispatcher().
			WithFindings("org/a", []string{"govulncheck"}, finding("org/a", "GO-2025-3487"))
		o := newOrchestrator(s, d, orchestrator.NewRateBudget(10), orchestrator.Config{CreditsPerScan: 1})
		if _, err := o.Sweep(ctx, store.KindSweep, "cron", repos, nil); err != nil {
			t.Fatalf("sweep 1: %v", err)
		}
		if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{Actor: model.ActorTriage}); err != nil {
			t.Fatalf("triage: %v", err)
		}

		// Second run: the budget funds nothing, so the repository is skipped.
		d2 := orchestrator.NewFakeDispatcher()
		o2 := newOrchestrator(s, d2, orchestrator.NewRateBudget(0), orchestrator.Config{CreditsPerScan: 1})
		stats, err := o2.Sweep(ctx, store.KindSweep, "cron", repos, nil)
		if err != nil {
			t.Fatalf("sweep 2: %v", err)
		}

		if got := stats.Reconcile["org/a"].Verified; got != 0 {
			t.Fatalf("a repository that never ran verified %d findings; absence is not resolution (VM-ADR-12)", got)
		}
		f, _ := s.GetFinding(ctx, fp)
		if f.State != model.Triaged {
			t.Errorf("state = %q, want TRIAGED retained", f.State)
		}
		if !f.Derived.NotReobserved {
			t.Error("finding is not flagged not_reobserved (VM-F-161)")
		}
		if f.Derived.GapRepoScan == nil || *f.Derived.GapRepoScan != stats.RunID {
			t.Errorf("gap link = %v, want %s (VM-F-162)", f.Derived.GapRepoScan, stats.RunID)
		}
	})
}
