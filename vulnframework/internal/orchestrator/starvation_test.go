package orchestrator_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/store"
)

// Phase 4 amendment gate (OQ-P4-01):
//
//   over many sweeps of a fleet larger than the per-sweep budget, every
//     repository gets a qualifying scan within a bound and no repository's
//     coverage age grows without limit;
//   planning order is deterministic given (age, deferral-count, id);
//   a repository deferred — not failed — for the escalation threshold escalates.

// sweeper drives repeated sweeps with an advancing clock.
type sweeper struct {
	t      *testing.T
	s      store.Store
	repos  []store.Repo
	budget int
	now    time.Time
}

func (w *sweeper) sweep() orchestrator.RunStats {
	w.t.Helper()
	w.now = w.now.Add(7 * 24 * time.Hour) // one sweep a week (VM-FR §4 default)

	d := orchestrator.NewFakeDispatcher()
	for _, r := range w.repos {
		d.WithOutcome(r.Name, model.ScanComplete, []string{"govulncheck"}, nil)
	}

	o := orchestrator.New(w.s, d, orchestrator.NewRateBudget(w.budget), orchestrator.Config{
		CreditsPerScan: 1, MaxConcurrentScans: 4, EscalationThreshold: 2,
	})
	now := w.now
	o.Clock = func() time.Time { return now }

	// The store's clock must advance with the orchestrator's, or every run
	// records the same start time and coverage age never moves.
	switch impl := w.s.(type) {
	case *store.Memory:
		impl.SetClock(func() time.Time { return now })
	case *store.Postgres:
		impl.SetClock(func() time.Time { return now })
	}

	stats, err := o.Sweep(context.Background(), store.KindSweep, "cron", w.repos, nil)
	if err != nil {
		w.t.Fatalf("sweep: %v", err)
	}
	return stats
}

// TestNoRepositoryStarvesUnderABudget is the amendment's central clause.
//
// The fleet is three times the per-sweep budget. Before the ordering change a
// repository could lose the budget lottery for ever while the gap count stayed
// flat at the same number every run; nothing in the output would have said so.
func TestNoRepositoryStarvesUnderABudget(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		const (
			fleetSize = 9
			budget    = 3
			sweeps    = 12
		)
		var names []string
		for i := 0; i < fleetSize; i++ {
			names = append(names, fmt.Sprintf("org/repo-%02d", i))
		}
		repos := fleet(t, s, names...)

		w := &sweeper{t: t, s: s, repos: repos, budget: budget,
			now: time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)}

		// Track, per repository, the longest run of consecutive sweeps without a
		// qualifying scan.
		scannedIn := map[string][]int{}
		var maxAges []time.Duration

		for i := 1; i <= sweeps; i++ {
			stats := w.sweep()
			if stats.Dispatched != budget {
				t.Fatalf("sweep %d dispatched %d, want %d", i, stats.Dispatched, budget)
			}
			for _, repo := range stats.PlanOrder[:budget] {
				scannedIn[repo] = append(scannedIn[repo], i)
			}
			maxAges = append(maxAges, stats.Staleness.MaxAge)
		}

		// Every repository must have been scanned.
		for _, name := range names {
			if len(scannedIn[name]) == 0 {
				t.Errorf("%s was never scanned across %d sweeps; it starved", name, sweeps)
			}
		}

		// With a fleet of 9 and a budget of 3, a fair rotation covers everything
		// every 3 sweeps. Allow slack for the first pass, but the bound must
		// hold: no repository may wait longer than the round-trip.
		bound := fleetSize / budget * 2
		for _, name := range names {
			gaps := gapsBetween(scannedIn[name], sweeps)
			if gaps > bound {
				t.Errorf("%s went %d consecutive sweeps without a scan, bound is %d (scanned in %v)",
					name, gaps, bound, scannedIn[name])
			}
		}

		// And the fleet's worst coverage age must stop growing. Comparing the
		// last third against the middle third: a starving fleet's maximum age
		// climbs without limit, a rotating one plateaus.
		mid := maxAges[sweeps/3]
		last := maxAges[sweeps-1]
		ceiling := time.Duration(bound+1) * 7 * 24 * time.Hour
		if last > ceiling {
			t.Errorf("worst coverage age reached %v by sweep %d, above the %v ceiling; ages grow without limit",
				last, sweeps, ceiling)
		}
		t.Logf("max coverage age: mid=%v last=%v ceiling=%v", mid, last, ceiling)
	})
}

// gapsBetween returns the longest run of consecutive sweeps in which the
// repository was not scanned, including before the first and after the last.
func gapsBetween(scanned []int, total int) int {
	worst, prev := 0, 0
	for _, at := range scanned {
		if gap := at - prev - 1; gap > worst {
			worst = gap
		}
		prev = at
	}
	if tail := total - prev; tail > worst {
		worst = tail
	}
	return worst
}

// TestPlanOrderIsMostStaleFirst covers the ordering directly.
func TestPlanOrderIsMostStaleFirst(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		repos := fleet(t, s, "org/a", "org/b", "org/c")
		w := &sweeper{t: t, s: s, repos: repos, budget: 1,
			now: time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)}

		// Nothing has been scanned, so the order is the deterministic tie-break
		// on name.
		first := w.sweep()
		if got := first.PlanOrder[0]; got != "org/a" {
			t.Errorf("first sweep planned %q first, want org/a (never-scanned, tie-break on id)", got)
		}

		// org/a now has coverage; the next sweep must prefer the two that do not.
		second := w.sweep()
		if got := second.PlanOrder[0]; got == "org/a" {
			t.Errorf("second sweep planned the freshly scanned org/a first; stale repositories must come first")
		}

		third := w.sweep()
		if got := third.PlanOrder[0]; got == "org/a" {
			t.Errorf("third sweep planned org/a first while another repository was still unscanned")
		}

		// After every repository has coverage, the order rotates to the oldest.
		fourth := w.sweep()
		if got := fourth.PlanOrder[0]; got != "org/a" {
			t.Errorf("fourth sweep planned %q first, want org/a as the oldest coverage", got)
		}
	})
}

// TestPlanOrderIsDeterministic covers the gate's determinism clause: the order
// is a total function of (last-qualifying timestamp, deferral count, id).
func TestPlanOrderIsDeterministic(t *testing.T) {
	at := time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)
	older := at.Add(-30 * 24 * time.Hour)
	newer := at.Add(-1 * 24 * time.Hour)

	states := []store.CoverageState{
		{Repo: "org/d", LastQualifyingAt: &newer},
		{Repo: "org/b", LastQualifyingAt: &older},
		{Repo: "org/never-2"},
		{Repo: "org/a", LastQualifyingAt: &older, ConsecutiveDeferrals: 3},
		{Repo: "org/never-1"},
		{Repo: "org/c", LastQualifyingAt: &older, ConsecutiveDeferrals: 1},
	}

	want := []string{
		// Never scanned first, tie-broken by id.
		"org/never-1", "org/never-2",
		// Then equal-aged, most-deferred first, tie-broken by id.
		"org/a", "org/c", "org/b",
		// Then the freshest.
		"org/d",
	}

	// Every permutation of the input must produce the same order.
	for _, perm := range permutations(len(states)) {
		shuffled := make([]store.CoverageState, len(states))
		for i, idx := range perm {
			shuffled[i] = states[idx]
		}
		var got []string
		for _, c := range store.ByCoverageStaleness(shuffled) {
			got = append(got, c.Repo)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("order depends on input: perm %v gave %v, want %v", perm, got, want)
			}
		}
	}
}

func permutations(n int) [][]int {
	var out [][]int
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	var permute func(k int)
	permute = func(k int) {
		if k == n {
			cp := make([]int, n)
			copy(cp, idx)
			out = append(out, cp)
			return
		}
		for i := k; i < n; i++ {
			idx[k], idx[i] = idx[i], idx[k]
			permute(k + 1)
			idx[k], idx[i] = idx[i], idx[k]
		}
	}
	permute(0)
	return out
}

// --- Staleness metric -------------------------------------------------------

func TestStalenessDistribution(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	mk := func(repo string, daysAgo int) store.CoverageState {
		at := now.Add(-time.Duration(daysAgo) * day)
		return store.CoverageState{Repo: repo, LastQualifyingAt: &at}
	}

	rep := store.Staleness([]store.CoverageState{
		mk("a", 1), mk("b", 2), mk("c", 5), mk("d", 40),
		{Repo: "e"}, // never scanned
	}, now)

	if rep.InScope != 5 {
		t.Errorf("in_scope=%d, want 5", rep.InScope)
	}
	// A never-scanned repository has no age; counting it separately keeps it
	// visible without inventing a number that would swamp every percentile.
	if rep.NeverScanned != 1 {
		t.Errorf("never_scanned=%d, want 1", rep.NeverScanned)
	}
	if rep.MaxAge != 40*day {
		t.Errorf("max_age=%v, want %v", rep.MaxAge, 40*day)
	}
	if rep.StalestRepo != "d" {
		t.Errorf("stalest_repo=%q, want d", rep.StalestRepo)
	}
	if rep.P95Age != 40*day {
		t.Errorf("p95_age=%v, want %v", rep.P95Age, 40*day)
	}
	if rep.MedianAge != 2*day {
		t.Errorf("median_age=%v, want %v", rep.MedianAge, 2*day)
	}
}

// TestStalenessSurfacesStarvationAFlatCountHides is the point of the metric.
// Two fleets with the same gap count, one healthy and one starving.
func TestStalenessSurfacesStarvationAFlatCountHides(t *testing.T) {
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	week := 7 * 24 * time.Hour
	mk := func(repo string, weeksAgo int) store.CoverageState {
		at := now.Add(-time.Duration(weeksAgo) * week)
		return store.CoverageState{Repo: repo, LastQualifyingAt: &at}
	}

	// Rotating: everyone scanned within three weeks.
	rotating := store.Staleness([]store.CoverageState{
		mk("a", 1), mk("b", 2), mk("c", 3), mk("d", 1), mk("e", 2),
	}, now)

	// Starving: one repository has not been scanned in half a year, and the
	// per-sweep gap count is identical.
	starving := store.Staleness([]store.CoverageState{
		mk("a", 1), mk("b", 1), mk("c", 1), mk("d", 1), mk("e", 26),
	}, now)

	if starving.MaxAge <= rotating.MaxAge {
		t.Errorf("starvation is invisible: starving max_age=%v, rotating max_age=%v",
			starving.MaxAge, rotating.MaxAge)
	}
	if starving.StalestRepo != "e" {
		t.Errorf("stalest_repo=%q, want e — the metric must name the starved repository", starving.StalestRepo)
	}
}

// --- Unified escalation (VM-F-215) -----------------------------------------

// TestDeferredRepoEscalatesLikeAFailedOne is the gate's escalation clause. A
// repository deferred for budget is exactly as uncovered as one whose build
// fails, and counting only failures would let it escape escalation entirely.
func TestDeferredRepoEscalatesLikeAFailedOne(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		// Two repositories, budget for one. org/a is stale-first and wins every
		// time it is behind, so org/deferred accumulates deferrals.
		repos := fleet(t, s, "org/a", "org/deferred")

		now := time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)
		for i := 0; i < 3; i++ {
			now = now.Add(7 * 24 * time.Hour)
			at := now

			d := orchestrator.NewFakeDispatcher().
				WithOutcome("org/a", model.ScanComplete, []string{"govulncheck"}, nil)
			o := orchestrator.New(s, d, orchestrator.NewRateBudget(0), orchestrator.Config{
				CreditsPerScan: 1, EscalationThreshold: 2,
			})
			o.Clock = func() time.Time { return at }
			switch impl := s.(type) {
			case *store.Memory:
				impl.SetClock(func() time.Time { return at })
			case *store.Postgres:
				impl.SetClock(func() time.Time { return at })
			}

			// Budget zero: both repositories are deferred, never failed.
			stats, err := o.Sweep(ctx, store.KindSweep, "cron", repos, nil)
			if err != nil {
				t.Fatalf("sweep %d: %v", i, err)
			}
			if stats.Dispatched != 0 {
				t.Fatalf("sweep %d dispatched %d, want 0", i, stats.Dispatched)
			}

			// Deferral, not failure.
			res := outcomeFor(t, s, "org/deferred", stats.RunID)
			if res.Outcome != model.ScanNotDispatched {
				t.Fatalf("outcome = %q, want not_dispatched", res.Outcome)
			}
			if res.FailureCause != store.SkipBudgetExhausted {
				t.Fatalf("cause = %q, want %q", res.FailureCause, store.SkipBudgetExhausted)
			}

			if i >= 1 {
				// From the second sweep the streak has crossed the threshold.
				var found bool
				for _, e := range stats.Escalations {
					if e.Repo == "org/deferred" {
						found = true
						if e.SweepsSinceQualifying < 2 {
							t.Errorf("streak=%d, want at least 2", e.SweepsSinceQualifying)
						}
						// The cause is an attribute, not a filter.
						if e.Cause != store.SkipBudgetExhausted {
							t.Errorf("cause = %q, want %q carried as an attribute", e.Cause, store.SkipBudgetExhausted)
						}
					}
				}
				if !found {
					t.Errorf("sweep %d: a repository deferred %d times running did not escalate; "+
						"counting only failures lets a never-dispatched repository escape entirely (VM-F-215)",
						i, i+1)
				}
			}
		}
	})
}

func TestEscalationIsCauseAgnostic(t *testing.T) {
	states := []store.CoverageState{
		{Repo: "org/failing", SweepsSinceQualifying: 3, LastCause: "build_failure"},
		{Repo: "org/deferred", SweepsSinceQualifying: 3, LastCause: store.SkipBudgetExhausted},
		{Repo: "org/never-run", SweepsSinceQualifying: 3, LastCause: store.SkipNeverDispatched},
		{Repo: "org/lost", SweepsSinceQualifying: 2, LastCause: store.CauseWorkerNoResult},
		{Repo: "org/fine", SweepsSinceQualifying: 1, LastCause: "build_failure"},
	}

	got := store.Escalations(states, 2)
	if len(got) != 4 {
		t.Fatalf("escalated %d repositories, want 4 — every cause counts (VM-F-215): %+v", len(got), got)
	}
	// Ordered by streak length, so the worst is read first.
	if got[0].SweepsSinceQualifying != 3 {
		t.Errorf("first escalation streak=%d, want the longest first", got[0].SweepsSinceQualifying)
	}
	for _, e := range got {
		if e.Repo == "org/fine" {
			t.Error("a repository below the threshold escalated")
		}
		if e.Cause == "" {
			t.Errorf("%s escalated with no cause recorded; the remedy differs by cause", e.Repo)
		}
	}
}

// TestCoverageStreakIgnoresNonQualifyingScans covers the predicate: a partial
// scan does not refresh coverage any more than it verifies a finding.
func TestCoverageStreakIgnoresNonQualifyingScans(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/a")

		now := time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)
		outcomes := []model.ScanOutcome{model.ScanComplete, model.ScanPartial, model.ScanPartial}
		var lastRun string
		for _, outcome := range outcomes {
			now = now.Add(7 * 24 * time.Hour)
			at := now
			d := orchestrator.NewFakeDispatcher().
				WithOutcome("org/a", outcome, []string{"gosec"}, []string{"govulncheck"})
			o := orchestrator.New(s, d, orchestrator.NewRateBudget(10), orchestrator.Config{
				CreditsPerScan: 1, EscalationThreshold: 2,
			})
			o.Clock = func() time.Time { return at }
			switch impl := s.(type) {
			case *store.Memory:
				impl.SetClock(func() time.Time { return at })
			case *store.Postgres:
				impl.SetClock(func() time.Time { return at })
			}
			stats, err := o.Sweep(ctx, store.KindSweep, "cron", repos, nil)
			if err != nil {
				t.Fatalf("sweep: %v", err)
			}
			lastRun = stats.RunID
		}
		_ = lastRun

		coverage, err := s.FleetCoverage(ctx, store.KindSweep, []string{"org/a"})
		if err != nil {
			t.Fatalf("fleet coverage: %v", err)
		}
		if len(coverage) != 1 {
			t.Fatalf("got %d coverage states", len(coverage))
		}
		c := coverage[0]
		// Two partial scans since the complete one: uncovered for two sweeps.
		if c.SweepsSinceQualifying != 2 {
			t.Errorf("sweeps_since_qualifying=%d, want 2 — a partial scan does not refresh coverage", c.SweepsSinceQualifying)
		}
		if c.NeverScanned() {
			t.Error("the repository has a qualifying scan in its history")
		}
		if got := store.Escalations(coverage, 2); len(got) != 1 {
			t.Errorf("escalated %d, want 1", len(got))
		}
	})
}

// TestRotationIsEvenWhenTheBudgetDoesNotDivideTheFleet is the fairness clause
// the starvation test cannot see.
//
// Twelve of twenty per sweep. Every repository a sweep scans shares that run's
// start time, so planning ties are the normal case; breaking them by name let
// the alphabetically-early repositories take the spare slots every sweep. The
// fleet never starved — and still scanned some repositories every sweep and
// others every other one. Ten sweeps is 120 scans: a fair rotation gives every
// repository six.
func TestRotationIsEvenWhenTheBudgetDoesNotDivideTheFleet(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		const (
			fleetSize = 20
			budget    = 12
			sweeps    = 10
		)
		var names []string
		for i := 0; i < fleetSize; i++ {
			names = append(names, fmt.Sprintf("org/repo-%02d", i))
		}
		w := &sweeper{t: t, s: s, repos: fleet(t, s, names...), budget: budget,
			now: time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)}

		scans := map[string]int{}
		for i := 0; i < sweeps; i++ {
			for _, repo := range w.sweep().PlanOrder[:budget] {
				scans[repo]++
			}
		}
		lo, hi := sweeps, 0
		for _, name := range names {
			lo, hi = min(lo, scans[name]), max(hi, scans[name])
		}
		if hi-lo > 1 {
			t.Errorf("scan counts range from %d to %d over %d sweeps; a fair rotation differs by at most one: %v",
				lo, hi, sweeps, scans)
		}
	})
}
