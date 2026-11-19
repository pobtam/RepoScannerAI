package store_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// Tool-aware reconciliation (VM-F-160/161, VM-ADR-12).
//
// A complete scan is evidence only about the tools that ran in it. Once a
// user can switch NuGuard off for a repository, or choose fewer of its tools,
// a scan can complete without the tool that found something — and if absence
// from a complete scan verified, every open NuGuard finding would close the
// moment NuGuard was switched off. The fleet numbers would improve; the risk
// would not.

// allNuGuard is every tool a full NuGuard scan reports ok.
var allNuGuard = []string{"gosec", "nuguard", "nuguard/atlas", "nuguard/nga-rules", "nuguard/semgrep"}

type toolAwareSeed struct {
	gosec, semgrep, atlas string // fingerprints
}

// seedToolAware observes one gosec finding and two NuGuard findings (from its
// semgrep and its atlas) in a complete scan, and triages all three so each
// could verify.
func seedToolAware(t *testing.T, s store.Store) toolAwareSeed {
	t.Helper()
	ctx := context.Background()
	seedRepo(t, s)
	code := func(tool, sub, rule, file string) model.RawFinding {
		return model.RawFinding{
			Repo: testRepo, Category: model.CategoryCode, Tool: tool, SubTool: sub, ToolVersion: "1",
			RuleID: rule, File: file,
			Classification: model.Classification{
				Severity: model.SeverityHigh, Reachable: model.ReachableTrue, DepClass: model.DepNotApplicable,
			},
		}
	}
	raws := []model.RawFinding{
		code("gosec", "", "G404", "internal/token/token.go"),
		code("nuguard", "semgrep", "ai.prompt-concat", "agent/chat.go"),
		code("nuguard", "atlas", "AML.T0051", "agent/tools.go"),
	}
	r1 := newRun(t, s, store.KindSweep)
	if _, err := s.UpsertObservations(ctx, r1.ID, testRepo, raws); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	scanned(t, s, r1.ID, model.ScanComplete, allNuGuard, nil)
	if _, err := s.Reconcile(ctx, r1.ID, testRepo); err != nil {
		t.Fatalf("reconcile r1: %v", err)
	}
	seed := toolAwareSeed{fingerprintOf(raws[0]), fingerprintOf(raws[1]), fingerprintOf(raws[2])}
	for _, fp := range []string{seed.gosec, seed.semgrep, seed.atlas} {
		if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{
			Actor: model.ActorTriage, Cause: "test",
		}); err != nil {
			t.Fatalf("triage %s: %v", fp, err)
		}
	}
	return seed
}

// rescan records a complete scan with toolsOK that observes nothing, and
// reconciles it.
func rescan(t *testing.T, s store.Store, toolsOK []string) (store.Run, store.ReconcileStats) {
	t.Helper()
	r := newRun(t, s, store.KindSweep)
	scanned(t, s, r.ID, model.ScanComplete, toolsOK, nil)
	stats, err := s.Reconcile(context.Background(), r.ID, testRepo)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return r, stats
}

func wantVerified(t *testing.T, s store.Store, fp, what string) {
	t.Helper()
	f, err := s.GetFinding(context.Background(), fp)
	if err != nil {
		t.Fatalf("get %s: %v", what, err)
	}
	if f.State != model.Verified {
		t.Errorf("%s: state %s, want VERIFIED: a complete scan that ran its tool no longer sees it", what, f.State)
	}
}

func wantRetained(t *testing.T, s store.Store, fp, what, runID string) {
	t.Helper()
	f, err := s.GetFinding(context.Background(), fp)
	if err != nil {
		t.Fatalf("get %s: %v", what, err)
	}
	if f.State != model.Triaged {
		t.Errorf("%s: state %s, want TRIAGED: the tool that found it did not run, so its absence is no evidence (VM-F-160)",
			what, f.State)
	}
	if !f.Derived.NotReobserved {
		t.Errorf("%s: not flagged not re-observed (VM-F-161)", what)
	}
	if f.Derived.GapRepoScan == nil || *f.Derived.GapRepoScan != runID {
		t.Errorf("%s: gap link %v, want the run %s that did not look (VM-F-162)", what, f.Derived.GapRepoScan, runID)
	}
}

func TestTurningNuGuardOffDoesNotVerifyItsFindings(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		seed := seedToolAware(t, s)
		r, stats := rescan(t, s, []string{"gosec"})

		wantVerified(t, s, seed.gosec, "the gosec finding")
		wantRetained(t, s, seed.semgrep, "the nuguard/semgrep finding", r.ID)
		wantRetained(t, s, seed.atlas, "the nuguard/atlas finding", r.ID)
		if stats.Verified != 1 || stats.SourceNotRun != 2 || stats.NotReobserved != 2 || stats.RetainedUnverified != 2 {
			t.Errorf("stats = %+v, want 1 verified and 2 retained because their source did not run", stats)
		}
	})
}

func TestNuGuardWithFewerToolsVerifiesOnlyWhatItsToolsCovered(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		seed := seedToolAware(t, s)
		// NuGuard ran, but semgrep was not among its tools this time.
		r, stats := rescan(t, s, []string{"gosec", "nuguard", "nuguard/atlas", "nuguard/nga-rules"})

		wantVerified(t, s, seed.gosec, "the gosec finding")
		wantVerified(t, s, seed.atlas, "the nuguard/atlas finding")
		wantRetained(t, s, seed.semgrep, "the nuguard/semgrep finding", r.ID)
		if stats.Verified != 2 || stats.SourceNotRun != 1 {
			t.Errorf("stats = %+v, want 2 verified and 1 retained", stats)
		}
	})
}

func TestNuGuardOnAndTheFindingGoneStillVerifies(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		seed := seedToolAware(t, s)
		_, stats := rescan(t, s, allNuGuard)

		wantVerified(t, s, seed.gosec, "the gosec finding")
		wantVerified(t, s, seed.semgrep, "the nuguard/semgrep finding")
		wantVerified(t, s, seed.atlas, "the nuguard/atlas finding")
		if stats.Verified != 3 || stats.SourceNotRun != 0 {
			t.Errorf("stats = %+v, want all 3 verified", stats)
		}
	})
}

// The same rule for every adapter, not only NuGuard: a Go finding is not
// verified by a complete scan that ran only JavaScript tools.
func TestAnAdapterThatDidNotRunVerifiesNothing(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		seed := seedToolAware(t, s)
		r, stats := rescan(t, s, []string{"npm-audit"})

		wantRetained(t, s, seed.gosec, "the gosec finding", r.ID)
		if stats.Verified != 0 {
			t.Errorf("verified %d with only npm-audit run, want 0", stats.Verified)
		}
	})
}

// A scan whose every tool was not requested ran nothing: it has a tool list
// (the not-requested one), so it is not judged by its outcome alone, and it
// verifies nothing.
func TestAScanThatRanNothingVerifiesNothing(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		seed := seedToolAware(t, s)
		r := newRun(t, s, store.KindSweep)
		if err := s.RecordScanResult(context.Background(), store.RepoScanResult{
			RunID: r.ID, Repo: testRepo, Outcome: model.ScanComplete,
			ToolsNotRequested: []store.ToolNotRequested{{Tool: "nuguard", Reason: "off for this repository"}},
		}); err != nil {
			t.Fatal(err)
		}
		stats, err := s.Reconcile(context.Background(), r.ID, testRepo)
		if err != nil {
			t.Fatal(err)
		}
		if stats.Verified != 0 || stats.SourceNotRun != 3 {
			t.Errorf("stats = %+v, want nothing verified: nothing ran", stats)
		}
		wantRetained(t, s, seed.semgrep, "the nuguard/semgrep finding", r.ID)
	})
}

// A secret is never "removed" by a scan in which its detector did not look.
func TestASecretIsNotRemovedByAScanWithoutItsDetector(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		secret := model.RawFinding{
			Repo: testRepo, Category: model.CategorySecret, Tool: "gitleaks", ToolVersion: "v8.28.0",
			DetectorRuleID: "generic-api-key", File: "config/dev.env", CredentialType: "api-key",
			Classification: model.Classification{
				Severity: model.SeverityHigh, Reachable: model.ReachableTrue, DepClass: model.DepNotApplicable,
			},
		}
		r1 := newRun(t, s, store.KindSweep)
		if _, err := s.UpsertObservations(ctx, r1.ID, testRepo, []model.RawFinding{secret}); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		scanned(t, s, r1.ID, model.ScanComplete, []string{"gitleaks", "gosec"}, nil)

		_, stats := rescan(t, s, []string{"gosec"})
		if stats.SecretsRemoved != 0 || stats.SourceNotRun != 1 {
			t.Errorf("stats = %+v: a scan without gitleaks recorded the secret as removed", stats)
		}
		f, err := s.GetFinding(ctx, fingerprintOf(secret))
		if err != nil {
			t.Fatal(err)
		}
		if f.RemovedUnrotated != nil {
			t.Errorf("secret removal recorded by a scan whose detector did not run: %+v", f.RemovedUnrotated)
		}
	})
}

// "Found by" filters on the tools that reported a finding (VM-UI-F-1207).
func TestFindingsFilterByTheToolThatFoundThem(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		seed := seedToolAware(t, s)
		for _, tc := range []struct {
			by   []string
			want []string
		}{
			{[]string{"nuguard"}, []string{seed.atlas, seed.semgrep}},
			{[]string{"gosec"}, []string{seed.gosec}},
			{[]string{"gosec", "nuguard"}, []string{seed.atlas, seed.gosec, seed.semgrep}},
			{[]string{"trivy"}, nil},
		} {
			page, err := s.Search(context.Background(), store.SearchQuery{Scope: store.ScopeOpen,
				Filter: store.Filter{FoundBy: tc.by}, Limit: 50,
				Sort: store.Sort{Field: store.SortPriority, Dir: store.SortDesc}})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, f := range page.Findings {
				got = append(got, f.Fingerprint)
			}
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("found by %v = %v, want %v", tc.by, got, want)
			}
		}
	})
}

// Each finding is an app or an AI vulnerability, by the scanners that found
// it, and the type filters and counts the same on both backends.
func TestFindingsFilterAndCountByAppOrAI(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seed := seedToolAware(t, s)
		for _, tc := range []struct {
			domains []model.Domain
			want    []string
		}{
			{[]model.Domain{model.DomainAI}, []string{seed.atlas, seed.semgrep}},
			{[]model.Domain{model.DomainApp}, []string{seed.gosec}},
			{[]model.Domain{model.DomainApp, model.DomainAI}, []string{seed.atlas, seed.gosec, seed.semgrep}},
		} {
			page, err := s.Search(ctx, store.SearchQuery{Scope: store.ScopeOpen,
				Filter: store.Filter{Domains: tc.domains}, Limit: 50,
				Sort: store.Sort{Field: store.SortPriority, Dir: store.SortDesc}})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, f := range page.Findings {
				got = append(got, f.Fingerprint)
				if d := model.DomainOf(f); !containsDomainT(tc.domains, d) {
					t.Errorf("%s classified %q, outside the filter %v", f.Fingerprint, d, tc.domains)
				}
			}
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("domain %v = %v, want %v", tc.domains, got, want)
			}
		}

		// The type's own counts ignore its own selection (so "app" still
		// says 1 with "ai" selected), and the other dimensions narrow to it.
		facets, err := s.Facets(ctx, store.SearchQuery{Scope: store.ScopeOpen,
			Filter: store.Filter{Domains: []model.Domain{model.DomainAI}}, Limit: 50,
			Sort: store.Sort{Field: store.SortPriority, Dir: store.SortDesc}})
		if err != nil {
			t.Fatal(err)
		}
		if facets.Domains["ai"] != 2 || facets.Domains["app"] != 1 {
			t.Errorf("domain counts = %v, want ai 2, app 1", facets.Domains)
		}
		if facets.Categories["code"] != 2 {
			t.Errorf("code count with AI selected = %d, want 2", facets.Categories["code"])
		}
		// Every option is present, even at zero, on both backends.
		empty, err := s.Facets(ctx, store.SearchQuery{Scope: store.ScopeOpen,
			Filter: store.Filter{Repos: []string{"nobody/nothing"}}, Limit: 50,
			Sort: store.Sort{Field: store.SortPriority, Dir: store.SortDesc}})
		if err != nil {
			t.Fatal(err)
		}
		if n, ok := empty.Domains["ai"]; !ok || n != 0 {
			t.Errorf("ai option missing or non-zero in an empty result: %v", empty.Domains)
		}
		if n, ok := empty.Domains["app"]; !ok || n != 0 {
			t.Errorf("app option missing or non-zero in an empty result: %v", empty.Domains)
		}
	})
}

func containsDomainT(set []model.Domain, d model.Domain) bool {
	for _, x := range set {
		if x == d {
			return true
		}
	}
	return false
}

// The observation keeps the sub-tool, so reconciliation can read it back.
func TestAnObservationKeepsItsSubTool(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		seed := seedToolAware(t, s)
		obs, err := s.Observations(context.Background(), seed.semgrep)
		if err != nil {
			t.Fatal(err)
		}
		if len(obs) != 1 || obs[0].Source() != "nuguard/semgrep" {
			t.Fatalf("observations = %+v, want one from nuguard/semgrep", obs)
		}
	})
}
