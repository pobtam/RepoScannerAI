package demo_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/demo"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
)

// The demonstration is a deliverable, so it has a test.
//
// Two things are being asserted. First, that seeding WORKS: the demo runs the
// real pipeline, so a failure here is a pipeline that cannot complete without
// credentials, a network or Docker — which is the property that makes the
// framework runnable at all.
//
// Second, that the demonstration actually SHOWS what it claims to. A demo of a
// system whose whole argument is about honest reporting must contain the
// awkward cases: a coverage gap, a regression, a finding nothing re-observed,
// an input no feed answered, a consumer blocked on someone else's fix. A
// cheerful demo would misrepresent the framework more than no demo at all.

func seeded(t *testing.T) (*store.Memory, demo.Result) {
	t.Helper()
	ctx := context.Background()
	s := store.NewMemory()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cal, err := score.LoadCalibration("../../config/calibration.yaml")
	if err != nil {
		t.Fatalf("calibration: %v", err)
	}
	pol, err := policy.LoadConfig("../../config/policy.yaml")
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	res, err := demo.Seed(ctx, s, demo.Options{
		Calibration: cal, Policy: pol, Runs: 6,
		Now: time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	return s, res
}

func TestTheDemonstrationSeedsWithNoCredentialsOrNetwork(t *testing.T) {
	_, res := seeded(t)

	if len(res.Runs) != 6 {
		t.Errorf("seeded %d runs, want 6", len(res.Runs))
	}
	if res.Findings < 10 {
		t.Errorf("seeded %d findings; too few to show the interface's behaviour", res.Findings)
	}
	if res.Reports == 0 {
		t.Error("no report was issued, so no run has an immutable snapshot and every overview " +
			"renders as live")
	}
	if res.PRs == 0 {
		t.Error("no pull request is open, so the remediation path is invisible in the demonstration")
	}
	if res.Gaps == 0 {
		t.Error("no coverage gap, so the demonstration shows a fleet where a failed scan and a " +
			"clean scan cannot be told apart — and hides the framework's main argument")
	}
	if res.Waves == 0 {
		t.Error("no blocked consumer, so the first-party wave view is empty")
	}
}

func TestTheDemonstrationContainsEveryCategory(t *testing.T) {
	s, _ := seeded(t)
	ctx := context.Background()

	all, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	seen := map[model.Category]int{}
	repos := map[string]bool{}
	for _, f := range all {
		seen[f.Category]++
		repos[f.Repo] = true
	}
	for _, want := range []model.Category{
		model.CategoryDependency, model.CategoryCode, model.CategorySecret, model.CategoryConfig,
	} {
		if seen[want] == 0 {
			t.Errorf("the demonstration contains no %s findings; the interface renders each "+
				"category differently and an absent one cannot be looked at", want)
		}
	}
	if len(repos) < 4 {
		t.Errorf("findings span %d repositories, want several", len(repos))
	}
}

// TestTheDemonstrationShowsTheAwkwardCases is the test that matters.
func TestTheDemonstrationShowsTheAwkwardCases(t *testing.T) {
	s, res := seeded(t)
	ctx := context.Background()

	all, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}

	var (
		verified, regressed, notReobserved, blocked, breached, prOpen, merged int
		noExploitIntel, withExploitIntel, unknownReach, needsHuman            int
	)
	for _, f := range all {
		switch f.State {
		case model.Verified:
			verified++
		case model.Regressed:
			regressed++
		case model.BlockedUpstream:
			blocked++
		case model.PROpen:
			prOpen++
		case model.Merged:
			merged++
		case model.NeedsHuman:
			needsHuman++
		}
		if f.Derived.NotReobserved {
			notReobserved++
		}
		if f.Derived.SLAStatus == model.SLABreached {
			breached++
		}
		if f.Classification.EPSSAvailable || f.Classification.KEVAvailable {
			withExploitIntel++
		} else {
			noExploitIntel++
		}
		if f.Classification.Reachable == model.ReachableUnknown {
			unknownReach++
		}
	}

	for _, c := range []struct {
		n    int
		what string
		why  string
	}{
		{verified, "a verified finding", "the lifecycle ends somewhere and the interface must show it"},
		{notReobserved, "a finding nothing re-observed", "this is the case a reader must not read as 'fixed' (VM-UI-F-422)"},
		{blocked, "a consumer blocked on an upstream first-party fix", "the wave view has nothing to show without one"},
		{breached, "an SLA breach", "a breach count of zero teaches the reader that the column is decorative"},
		{prOpen, "an open remediation pull request", "the remediation path is otherwise invisible"},
		{needsHuman, "a finding routed to a human", "not everything can be automated, and the queue has to be visible"},
		{noExploitIntel, "a finding no exploitation feed answered for", "the absent-not-zero distinction is unviewable without one"},
		{withExploitIntel, "a finding the feeds DID answer for", "otherwise the absence looks like the only state"},
		{unknownReach, "a finding of unknown reachability", "the tri-state's middle value is the common one and must be visible"},
	} {
		if c.n == 0 {
			t.Errorf("the demonstration contains %s: 0. %s", c.what, c.why)
		}
	}

	// A regression is a DIFFERENT failure from a new finding and renders
	// differently, so the demonstration needs one. It arrives in the last run,
	// so it exists only if the earlier verification happened.
	if regressed == 0 && verified == 0 {
		t.Error("neither a regression nor a verification; the demonstration cannot show the " +
			"difference between a finding that went away and one that came back")
	}

	// Coverage: the gaps must be of DIFFERENT kinds, because the whole point
	// is that four causes need four different remedies.
	names, err := s.RepoNames(ctx)
	if err != nil {
		t.Fatalf("RepoNames: %v", err)
	}
	states, err := s.FleetCoverage(ctx, store.KindSweep, names)
	if err != nil {
		t.Fatalf("FleetCoverage: %v", err)
	}
	causes := map[string]bool{}
	for _, st := range states {
		if st.SweepsSinceQualifying > 0 {
			causes[st.LastCause] = true
		}
	}
	if len(causes) == 0 {
		t.Error("no coverage gap causes")
	}

	// And several scan outcomes across the fleet's history, so the coverage
	// history strip is not a flat line.
	outcomes := map[model.ScanOutcome]int{}
	for _, name := range names {
		results, err := s.ScanResults(ctx, name, 20)
		if err != nil {
			t.Fatalf("ScanResults: %v", err)
		}
		for _, r := range results {
			outcomes[r.Outcome]++
		}
	}
	if len(outcomes) < 3 {
		t.Errorf("the fleet's history contains %d distinct scan outcomes (%v); a demonstration "+
			"where every scan succeeded cannot show what a gap looks like", len(outcomes), outcomes)
	}

	// Every run has an immutable, hashed snapshot.
	for _, runID := range res.Runs {
		reports, err := s.ReportsForRun(ctx, runID)
		if err != nil {
			t.Fatalf("ReportsForRun: %v", err)
		}
		if len(reports) == 0 {
			t.Errorf("run %s has no issued report, so its overview renders as live", runID)
			continue
		}
		if reports[0].ContentHash == "" {
			t.Errorf("run %s's report has no content hash", runID)
		}
	}
}

// TestTheDemonstrationDataIsUnmistakablyFabricated is a small guard with a
// large purpose: a screenshot of this data must not be able to pass for a real
// fleet's security position.
func TestTheDemonstrationDataIsUnmistakablyFabricated(t *testing.T) {
	s, _ := seeded(t)
	ctx := context.Background()

	names, err := s.RepoNames(ctx)
	if err != nil {
		t.Fatalf("RepoNames: %v", err)
	}
	for _, name := range names {
		if len(name) < 5 || name[:9] != "demo-org/" {
			t.Errorf("repository %q is not obviously fabricated; every demonstration repository "+
				"is named demo-org/… so a copied number cannot be mistaken for a real fleet's", name)
		}
	}

	all, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	for _, f := range all {
		// Every identifier says DEMO somewhere. A plausible-looking CVE
		// number in demonstration data eventually becomes a real advisory
		// about something else, and a reader would follow it to a page
		// describing a vulnerability this fleet does not have.
		names := append([]string{f.Identity.PrimaryID}, f.Identity.Aliases...)
		var marked bool
		for _, n := range names {
			if strings.Contains(n, "DEMO") || strings.HasPrefix(n, "G4") ||
				strings.Contains(n, "aws-access-token") || strings.Contains(n, "generic-api-key") {
				marked = true
			}
		}
		if !marked {
			t.Errorf("%s's identifiers (%v) do not mark it as fabricated", f.Fingerprint, names)
		}
		if f.Location.Module != "" && len(f.Location.Module) >= 12 &&
			f.Location.Module[:12] == "golang.org/x" {
			t.Errorf("%s names a real module (%s)", f.Fingerprint, f.Location.Module)
		}
	}
}
