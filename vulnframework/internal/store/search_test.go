package store_test

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/store/storetest"
)

// Server-side filtering, sorting and cursor pagination (VM-UI-F-402/403/408,
// UI-ADR-06).
//
// The filter rules live in Go and are mirrored in SQL. That mirror is the risk:
// each backend would look correct in its own tests while returning different
// rows for the same query, and the difference would only show up as a
// deployment-dependent answer. So the central test here runs ONE corpus through
// BOTH backends and compares the pages row for row.

var searchNow = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

// searchCorpus is a deliberately awkward fixture: several repositories at
// different tiers and languages, every category, findings with and without
// priorities, reachability across all three states, one with an alias only, one
// never re-observed, one blocked upstream, one with a ticket, one with an open
// pull request.
type seedFinding struct {
	raw       model.RawFinding
	state     model.State
	priority  model.Priority
	reason    model.ReasonCode
	withPR    bool
	ticket    bool
	notReobs  bool
	firstSeen time.Time
}

func searchRaw(repo, id string, cat model.Category, sev model.Severity, reach model.Reachable) model.RawFinding {
	f := model.RawFinding{
		Repo: repo, Category: cat, PrimaryID: id, Tool: "govulncheck", ToolVersion: "v1.8.0",
		Classification: model.Classification{Severity: sev, Reachable: reach},
	}
	switch cat {
	case model.CategoryDependency:
		f.Module, f.ModuleMajor = "golang.org/x/"+id, "v0"
		f.Versions = model.Versions{Current: "v0.1.0", Fixed: "v0.2.0"}
		f.Classification.DepClass = model.DepProduction
		f.Aliases = []string{"CVE-2026-" + id, "GHSA-" + id}
	case model.CategoryCode:
		f.File, f.Line = "internal/handler/"+id+".go", 42
		f.RuleID = "G40" + id
	case model.CategorySecret:
		f.File, f.Line = "config/"+id+".yaml", 7
		f.DetectorRuleID = "aws-access-key"
		f.CredentialType = "aws_access_key"
	case model.CategoryConfig:
		f.File, f.Line = "deploy/"+id+".tf", 3
		f.CheckID = "TF-" + id
	}
	return f
}

// seedSearchCorpus builds the same corpus in any backend.
func seedSearchCorpus(t *testing.T, s store.Store) []seedFinding {
	t.Helper()
	ctx := context.Background()

	repos := []store.Repo{
		{Name: "org/api", Tier: 1, Languages: []string{"go"}, HasTestSuite: true},
		{Name: "org/web", Tier: 2, Languages: []string{"javascript", "go"}},
		{Name: "org/batch", Tier: 3, Languages: []string{"go"}},
	}
	for _, r := range repos {
		if err := s.UpsertRepo(ctx, r); err != nil {
			t.Fatalf("UpsertRepo: %v", err)
		}
	}

	seeds := []seedFinding{
		{raw: searchRaw("org/api", "1", model.CategoryDependency, model.SeverityCritical, model.ReachableTrue),
			state: model.Triaged, priority: model.P0},
		{raw: searchRaw("org/api", "2", model.CategoryDependency, model.SeverityHigh, model.ReachableUnknown),
			state: model.NeedsHuman, priority: model.P1, reason: model.ReasonNoUpstreamFix, ticket: true},
		{raw: searchRaw("org/api", "3", model.CategoryCode, model.SeverityMedium, model.ReachableFalse),
			state: model.Triaged, priority: model.P2},
		{raw: searchRaw("org/web", "4", model.CategorySecret, model.SeverityCritical, model.ReachableUnknown),
			state: model.NeedsHuman, priority: model.P0, ticket: true},
		{raw: searchRaw("org/web", "5", model.CategoryDependency, model.SeverityLow, model.ReachableFalse),
			state: model.Triaged, priority: model.P3},
		{raw: searchRaw("org/web", "6", model.CategoryConfig, model.SeverityUnknown, model.ReachableUnknown),
			state: model.Detected},
		{raw: searchRaw("org/batch", "7", model.CategoryDependency, model.SeverityHigh, model.ReachableTrue),
			state: model.BlockedUpstream, priority: model.P1, reason: model.ReasonBlockedUpstreamFirstParty},
		{raw: searchRaw("org/batch", "8", model.CategoryCode, model.SeverityMedium, model.ReachableUnknown),
			state: model.Triaged, priority: model.P2, notReobs: true},
	}

	// One run per repository, so first-seen timestamps differ and the
	// orderings are distinguishable.
	byRepo := map[string][]model.RawFinding{}
	for _, sd := range seeds {
		byRepo[sd.raw.Repo] = append(byRepo[sd.raw.Repo], sd.raw)
	}
	i := 0
	for _, r := range repos {
		run, err := s.CreateRun(ctx, store.KindSweep, "cron", "img@sha256:abc",
			map[string]string{"govulncheck": "v1.8.0"})
		if err != nil {
			t.Fatalf("CreateRun: %v", err)
		}
		if err := s.RecordPlan(ctx, []store.PlanEntry{{RunID: run.ID, Repo: r.Name, State: store.DispatchPlanned}}); err != nil {
			t.Fatalf("RecordPlan: %v", err)
		}
		if _, err := s.UpsertObservations(ctx, run.ID, r.Name, byRepo[r.Name]); err != nil {
			t.Fatalf("UpsertObservations: %v", err)
		}
		if err := s.RecordScanResult(ctx, store.RepoScanResult{
			RunID: run.ID, Repo: r.Name, Outcome: model.ScanComplete, ToolsOK: []string{"govulncheck"},
		}); err != nil {
			t.Fatalf("RecordScanResult: %v", err)
		}
		i++
	}

	// States, priorities, reasons, tickets and pull requests.
	for idx, sd := range seeds {
		fp := fingerprint.Compute(sd.raw)
		if sd.state != model.Detected {
			if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{
				Actor: model.ActorTriage, Cause: "triage complete", At: searchNow,
			}); err != nil {
				t.Fatalf("to TRIAGED: %v", err)
			}
		}
		switch sd.state {
		case model.NeedsHuman:
			if err := s.ApplyTransition(ctx, fp, model.NeedsHuman, model.TransitionContext{
				Actor: model.ActorOrchestrator, Cause: "policy", At: searchNow,
			}); err != nil {
				t.Fatalf("to NEEDS_HUMAN: %v", err)
			}
		case model.BlockedUpstream:
			if err := s.ApplyTransition(ctx, fp, model.BlockedUpstream, model.TransitionContext{
				Actor: model.ActorOrchestrator, Cause: "policy", At: searchNow,
			}); err != nil {
				t.Fatalf("to BLOCKED_UPSTREAM: %v", err)
			}
		}
		if sd.priority != "" {
			var reason *model.ReasonCode
			if sd.reason != "" {
				r := sd.reason
				reason = &r
			}
			if err := s.SetPriority(ctx, fp, sd.priority, reason); err != nil {
				t.Fatalf("SetPriority: %v", err)
			}
		}
		if sd.ticket {
			if err := s.SaveTicket(ctx, store.Ticket{
				Fingerprint: fp, Backend: "github", Ref: fmt.Sprintf("org/api#%d", idx+100),
				URL: fmt.Sprintf("https://github.com/org/api/issues/%d", idx+100), CreatedAt: searchNow,
			}); err != nil {
				t.Fatalf("SaveTicket: %v", err)
			}
		}
		if sd.withPR {
			branch := fmt.Sprintf("security/fix-%d", idx)
			if err := s.SaveRemediationPR(ctx, store.RemediationPR{
				Branch: branch, Repo: sd.raw.Repo, FixGroupID: branch, Number: idx + 1,
				URL:   fmt.Sprintf("https://github.com/%s/pull/%d", sd.raw.Repo, idx+1),
				State: "open", OpenedAt: searchNow, Findings: []string{fp},
			}); err != nil {
				t.Fatalf("SaveRemediationPR: %v", err)
			}
		}
	}
	return seeds
}

// bothBackends opens one store per backend and returns them side by side.
func bothBackends(t *testing.T) []struct {
	name  string
	store store.Store
} {
	t.Helper()
	out := []struct {
		name  string
		store store.Store
	}{}
	for _, b := range backends(t) {
		out = append(out, struct {
			name  string
			store store.Store
		}{b.name, b.open(t)})
	}
	return out
}

// TestBothBackendsAnswerEveryQueryIdentically is the load-bearing test for the
// whole query layer.
//
// The filter rules are written once in Go and mirrored in SQL. Nothing about
// either implementation reveals a disagreement — each passes its own tests —
// so the only way to find one is to ask both the same question about the same
// corpus and compare the answers.
func TestBothBackendsAnswerEveryQueryIdentically(t *testing.T) {
	if os.Getenv(storetest.EnvDSN) == "" {
		t.Skipf("%s not set: this test compares the two backends and needs both", storetest.EnvDSN)
	}
	ctx := context.Background()

	stores := bothBackends(t)
	if len(stores) != 2 {
		t.Fatalf("expected two backends, got %d", len(stores))
	}
	for _, s := range stores {
		seedSearchCorpus(t, s.store)
	}

	yes, no := true, false
	from := searchNow.Add(-48 * time.Hour)
	queries := map[string]store.SearchQuery{
		"everything":       {Scope: store.ScopeAll},
		"open":             {Scope: store.ScopeOpen},
		"one repo":         {Scope: store.ScopeAll, Filter: store.Filter{Repos: []string{"org/api"}}},
		"two repos":        {Scope: store.ScopeAll, Filter: store.Filter{Repos: []string{"org/api", "org/batch"}}},
		"tier 1":           {Scope: store.ScopeAll, Filter: store.Filter{Tiers: []int{1}}},
		"tiers 2 and 3":    {Scope: store.ScopeAll, Filter: store.Filter{Tiers: []int{2, 3}}},
		"javascript":       {Scope: store.ScopeAll, Filter: store.Filter{Languages: []string{"javascript"}}},
		"dependency":       {Scope: store.ScopeAll, Filter: store.Filter{Categories: []model.Category{model.CategoryDependency}}},
		"secret or code":   {Scope: store.ScopeAll, Filter: store.Filter{Categories: []model.Category{model.CategorySecret, model.CategoryCode}}},
		"triaged":          {Scope: store.ScopeAll, Filter: store.Filter{States: []model.State{model.Triaged}}},
		"P0 and P1":        {Scope: store.ScopeAll, Filter: store.Filter{Priorities: []model.Priority{model.P0, model.P1}}},
		"critical":         {Scope: store.ScopeAll, Filter: store.Filter{Severities: []model.Severity{model.SeverityCritical}}},
		"unknown severity": {Scope: store.ScopeAll, Filter: store.Filter{Severities: []model.Severity{model.SeverityUnknown}}},
		"reachable true":   {Scope: store.ScopeAll, Filter: store.Filter{Reachable: []model.Reachable{model.ReachableTrue}}},
		"reachable unknown": {Scope: store.ScopeAll,
			Filter: store.Filter{Reachable: []model.Reachable{model.ReachableUnknown}}},
		"production deps": {Scope: store.ScopeAll, Filter: store.Filter{DepClasses: []model.DepClass{model.DepProduction}}},
		"has ticket":      {Scope: store.ScopeAll, Filter: store.Filter{HasTicket: &yes}},
		"has no ticket":   {Scope: store.ScopeAll, Filter: store.Filter{HasTicket: &no}},
		"has pr":          {Scope: store.ScopeAll, Filter: store.Filter{HasPR: &yes}},
		"blocked":         {Scope: store.ScopeAll, Filter: store.Filter{Blocked: &yes}},
		"not blocked":     {Scope: store.ScopeAll, Filter: store.Filter{Blocked: &no}},
		"with a reason": {Scope: store.ScopeAll,
			Filter: store.Filter{Reasons: []model.ReasonCode{model.ReasonNoUpstreamFix, model.ReasonBlockedUpstreamFirstParty}}},
		"first seen since":               {Scope: store.ScopeAll, Filter: store.Filter{FirstSeenFrom: &from}},
		"text by module":                 {Scope: store.ScopeAll, Filter: store.Filter{Text: "golang.org/x/1"}},
		"text by alias":                  {Scope: store.ScopeAll, Filter: store.Filter{Text: "GHSA-4"}},
		"text by cve alias":              {Scope: store.ScopeAll, Filter: store.Filter{Text: "cve-2026-5"}},
		"text by file":                   {Scope: store.ScopeAll, Filter: store.Filter{Text: "handler/3.go"}},
		"text by repo":                   {Scope: store.ScopeAll, Filter: store.Filter{Text: "batch"}},
		"text with a wildcard character": {Scope: store.ScopeAll, Filter: store.Filter{Text: "50%"}},
		"text matching nothing":          {Scope: store.ScopeAll, Filter: store.Filter{Text: "no-such-thing"}},
		"conjunctive": {Scope: store.ScopeAll, Filter: store.Filter{
			Repos: []string{"org/api"}, Categories: []model.Category{model.CategoryDependency},
			Severities: []model.Severity{model.SeverityCritical, model.SeverityHigh},
		}},
	}

	sorts := []store.Sort{
		{Field: store.SortPriority, Dir: store.SortDesc},
		{Field: store.SortPriority, Dir: store.SortAsc},
		{Field: store.SortSeverity, Dir: store.SortDesc},
		{Field: store.SortFirstSeen, Dir: store.SortDesc},
		{Field: store.SortLastSeen, Dir: store.SortAsc},
		{Field: store.SortRepo, Dir: store.SortAsc},
	}

	for name, q := range queries {
		for _, srt := range sorts {
			label := fmt.Sprintf("%s/%s-%s", name, srt.Field, srt.Dir)
			t.Run(label, func(t *testing.T) {
				query := q
				query.Sort = srt
				query.Limit = 3

				// Walk every page of both backends together.
				var seen []string
				for page := 0; ; page++ {
					var first store.Page
					for i, s := range stores {
						got, err := s.store.Search(ctx, query)
						if err != nil {
							t.Fatalf("%s: Search: %v", s.name, err)
						}
						if i == 0 {
							first = got
							continue
						}
						if got.Matched != first.Matched || got.InCorpus != first.InCorpus {
							t.Fatalf("page %d counts differ: %s matched=%d in_corpus=%d, %s matched=%d in_corpus=%d",
								page, stores[0].name, first.Matched, first.InCorpus,
								s.name, got.Matched, got.InCorpus)
						}
						if !reflect.DeepEqual(fingerprints(got.Findings), fingerprints(first.Findings)) {
							t.Fatalf("page %d differs:\n  %s: %v\n  %s: %v",
								page, stores[0].name, fingerprints(first.Findings),
								s.name, fingerprints(got.Findings))
						}
						if (got.Next == "") != (first.Next == "") {
							t.Fatalf("page %d: %s says %q is next, %s says %q",
								page, stores[0].name, first.Next, s.name, got.Next)
						}
					}
					seen = append(seen, fingerprints(first.Findings)...)
					if first.Next == "" {
						break
					}
					query.Cursor = first.Next
					if page > 20 {
						t.Fatal("pagination did not terminate")
					}
				}

				// Pagination visits every matching row exactly once.
				if len(seen) != first(stores, ctx, t, q, srt) {
					t.Errorf("walked %d rows across pages, matched count says %d",
						len(seen), first(stores, ctx, t, q, srt))
				}
				if dup := duplicates(seen); len(dup) > 0 {
					t.Errorf("pagination served %v more than once", dup)
				}
			})
		}
	}
}

// first returns the matched count for a query, from the first backend.
func first(stores []struct {
	name  string
	store store.Store
}, ctx context.Context, t *testing.T, q store.SearchQuery, s store.Sort) int {
	t.Helper()
	q.Sort = s
	page, err := stores[0].store.Search(ctx, q)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	return page.Matched
}

func fingerprints(fs []model.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Fingerprint
	}
	return out
}

func duplicates(ss []string) []string {
	seen := map[string]int{}
	for _, s := range ss {
		seen[s]++
	}
	var out []string
	for s, n := range seen {
		if n > 1 {
			out = append(out, s)
		}
	}
	return out
}

// TestFacetsAgreeAcrossBackends applies the same treatment to the counts the
// filter panel shows. A facet count that differs by backend is worse than a
// wrong one: it is wrong in one deployment.
func TestFacetsAgreeAcrossBackends(t *testing.T) {
	if os.Getenv(storetest.EnvDSN) == "" {
		t.Skipf("%s not set: this test compares the two backends", storetest.EnvDSN)
	}
	ctx := context.Background()
	stores := bothBackends(t)
	for _, s := range stores {
		seedSearchCorpus(t, s.store)
	}

	queries := []store.SearchQuery{
		{Scope: store.ScopeAll},
		{Scope: store.ScopeOpen},
		{Scope: store.ScopeAll, Filter: store.Filter{Repos: []string{"org/api"}}},
		{Scope: store.ScopeAll, Filter: store.Filter{Categories: []model.Category{model.CategoryDependency}}},
		{Scope: store.ScopeAll, Filter: store.Filter{Severities: []model.Severity{model.SeverityCritical}}},
	}
	for i, q := range queries {
		t.Run(fmt.Sprintf("query-%d", i), func(t *testing.T) {
			var want store.FacetCounts
			for j, s := range stores {
				got, err := s.store.Facets(ctx, q)
				if err != nil {
					t.Fatalf("%s: Facets: %v", s.name, err)
				}
				if j == 0 {
					want = got
					continue
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("facets differ:\n  %s: %+v\n  %s: %+v", stores[0].name, want, s.name, got)
				}
			}
		})
	}
}

// --- properties that hold on either backend alone ---------------------------

func TestPaginationStaysCorrectWhileFindingsChangeUnderneath(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedSearchCorpus(t, s)

		q := store.SearchQuery{Scope: store.ScopeAll, Sort: store.Sort{
			Field: store.SortRepo, Dir: store.SortAsc}, Limit: 3}

		firstPage, err := s.Search(ctx, q)
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		if firstPage.Next == "" {
			t.Fatal("the corpus fits in one page; the property cannot be exercised")
		}

		// Between pages, a finding on the FIRST page resolves — exactly what
		// happens while someone pages through a live queue. Offset pagination
		// would now shift every later row up by one and skip whichever row
		// landed on the boundary.
		moved := firstPage.Findings[0].Fingerprint
		if err := s.SetPriority(ctx, moved, model.P0, nil); err != nil {
			t.Fatalf("SetPriority: %v", err)
		}

		q.Cursor = firstPage.Next
		second, err := s.Search(ctx, q)
		if err != nil {
			t.Fatalf("Search page 2: %v", err)
		}
		for _, f := range second.Findings {
			for _, seen := range firstPage.Findings {
				if f.Fingerprint == seen.Fingerprint {
					t.Errorf("%s appeared on both pages", f.Fingerprint)
				}
			}
		}

		// And the walk still reaches everything.
		seen := map[string]bool{}
		q.Cursor = ""
		for {
			page, err := s.Search(ctx, q)
			if err != nil {
				t.Fatalf("Search: %v", err)
			}
			for _, f := range page.Findings {
				if seen[f.Fingerprint] {
					t.Errorf("%s served twice", f.Fingerprint)
				}
				seen[f.Fingerprint] = true
			}
			if page.Next == "" {
				break
			}
			q.Cursor = page.Next
		}
		if len(seen) != firstPage.Matched {
			t.Errorf("walked %d of %d matching findings", len(seen), firstPage.Matched)
		}
	})
}

// TestACursorFromADifferentOrderingIsRefused is the negative. Reinterpreting
// it would silently skip or repeat rows, and the reader would see a page that
// looks ordinary.
func TestACursorFromADifferentOrderingIsRefused(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedSearchCorpus(t, s)

		byRepo := store.SearchQuery{Scope: store.ScopeAll,
			Sort: store.Sort{Field: store.SortRepo, Dir: store.SortAsc}, Limit: 2}
		page, err := s.Search(ctx, byRepo)
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		if page.Next == "" {
			t.Fatal("no second page to resume")
		}

		// The same token, a different sort: the reader clicked a column header
		// with a cursor in the URL.
		bySeverity := byRepo
		bySeverity.Sort = store.Sort{Field: store.SortSeverity, Dir: store.SortDesc}
		bySeverity.Cursor = page.Next
		if _, err := s.Search(ctx, bySeverity); err == nil {
			t.Error("a cursor issued for one ordering was accepted for another; the page it " +
				"returns is neither the next page of the old ordering nor of the new one")
		}
	})
}

func TestASearchRefusesWhatItCannotAnswerHonestly(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedSearchCorpus(t, s)

		if _, err := s.Search(ctx, store.SearchQuery{}); err == nil {
			t.Error("a query with no corpus was answered; a count is meaningless without saying " +
				"which findings it counts (VM-ADR-14)")
		}
		if _, err := s.Search(ctx, store.SearchQuery{Scope: store.ScopeRun}); err == nil {
			t.Error("a run-scoped query with no run was answered")
		}
		if _, err := s.Search(ctx, store.SearchQuery{
			Scope: store.ScopeAll, Limit: store.MaxPageSize + 1,
		}); err == nil {
			t.Error("an over-large page was silently clamped rather than refused; a client that " +
				"asked for 10,000 rows and got 500 would paginate wrongly and never know")
		}
		if _, err := s.Search(ctx, store.SearchQuery{
			Scope: store.ScopeAll, Sort: store.Sort{Field: "whatever", Dir: store.SortAsc},
		}); err == nil {
			t.Error("an unknown sort field was defaulted rather than refused; a shared URL would " +
				"then show two people different lists (VM-UI-F-401)")
		}
		if _, err := s.Search(ctx, store.SearchQuery{
			Scope: store.ScopeAll, Filter: store.Filter{Reachable: []model.Reachable{"maybe"}},
		}); err == nil {
			t.Error("an invalid reachability value was accepted; the tri-state is closed (VM-F-243)")
		}
	})
}

// TestSearchingByAnyAliasFindsTheFinding is VM-UI-F-405. Two tools name one
// vulnerability differently and the responder has whichever name the advisory
// they are reading used.
func TestSearchingByAnyAliasFindsTheFinding(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedSearchCorpus(t, s)

		for _, needle := range []string{"CVE-2026-1", "ghsa-1", "golang.org/x/1"} {
			page, err := s.Search(ctx, store.SearchQuery{
				Scope: store.ScopeAll, Filter: store.Filter{Text: needle},
			})
			if err != nil {
				t.Fatalf("Search %q: %v", needle, err)
			}
			if len(page.Findings) == 0 {
				t.Errorf("searching for %q found nothing; the finding is primarily identified as "+
					"%q and a reader who has the alias would conclude it is not tracked",
					needle, "1")
			}
		}
	})
}

// TestFacetsCountTheMatchingSetNotThePage is what makes the filter panel
// usable: the counts let a responder narrow from four thousand findings to the
// affected set without a sequence of empty screens.
func TestFacetsCountTheMatchingSetNotThePage(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedSearchCorpus(t, s)

		q := store.SearchQuery{Scope: store.ScopeAll, Limit: 2}
		page, err := s.Search(ctx, q)
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		facets, err := s.Facets(ctx, q)
		if err != nil {
			t.Fatalf("Facets: %v", err)
		}

		var total int
		for _, n := range facets.Categories {
			total += n
		}
		if total == len(page.Findings) {
			t.Errorf("the facet counts sum to the page size (%d); they are counting the page "+
				"rather than the matching set", total)
		}
		if total != page.Matched {
			t.Errorf("category counts sum to %d, the query matched %d", total, page.Matched)
		}

		// Every option is present, including at zero: a hidden option looks
		// like a dimension that does not exist (VM-UI-F-408).
		for _, st := range model.AllStates {
			if _, ok := facets.States[string(st)]; !ok {
				t.Errorf("state %q is absent from the facets; an option that disappears when it "+
					"has no results teaches the reader the wrong thing about the fleet", st)
			}
		}
		for _, r := range model.AllReachable {
			if _, ok := facets.Reachable[string(r)]; !ok {
				t.Errorf("reachability %q is absent from the facets", r)
			}
		}
	})
}

// TestAFacetCountsWhatSelectingItWouldGive is the subtle half of VM-UI-F-408:
// each dimension is counted with its OWN filter cleared. Counting with it
// applied would show every unselected option at zero, which is exactly the
// sequence of empty screens the counts exist to prevent.
func TestAFacetCountsWhatSelectingItWouldGive(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedSearchCorpus(t, s)

		// One category selected. The OTHER categories must still show what
		// they would return, while the other dimensions narrow to it.
		q := store.SearchQuery{Scope: store.ScopeAll,
			Filter: store.Filter{Categories: []model.Category{model.CategoryDependency}}}
		facets, err := s.Facets(ctx, q)
		if err != nil {
			t.Fatalf("Facets: %v", err)
		}
		if facets.Categories[string(model.CategoryCode)] == 0 {
			t.Error("with 'dependency' selected, the 'code' option shows zero. Selecting it would " +
				"return results, so the count is answering the wrong question — and the reader is " +
				"told a whole category is empty")
		}
		if facets.Categories[string(model.CategoryDependency)] == 0 {
			t.Error("the selected category shows zero")
		}

		// A dimension other than category IS narrowed by the category filter.
		unfiltered, err := s.Facets(ctx, store.SearchQuery{Scope: store.ScopeAll})
		if err != nil {
			t.Fatalf("Facets: %v", err)
		}
		if facets.Severities[string(model.SeverityCritical)] >= unfiltered.Severities[string(model.SeverityCritical)] {
			t.Errorf("severity counts did not narrow when a category was selected: %d with the "+
				"filter, %d without", facets.Severities[string(model.SeverityCritical)],
				unfiltered.Severities[string(model.SeverityCritical)])
		}
	})
}

// TestUnscoredFindingsSortAfterScoredOnes is the ordering decision that is
// easy to get backwards. A finding nobody has scored is not the most urgent
// thing in the fleet.
func TestUnscoredFindingsSortAfterScoredOnes(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedSearchCorpus(t, s)

		page, err := s.Search(ctx, store.SearchQuery{
			Scope: store.ScopeAll, Sort: store.Sort{Field: store.SortPriority, Dir: store.SortDesc},
			Limit: store.MaxPageSize,
		})
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		var sawUnscored bool
		for _, f := range page.Findings {
			if f.Priority == "" {
				sawUnscored = true
				continue
			}
			if sawUnscored {
				t.Errorf("%s (%s) sorts after an unscored finding; an unscored finding has no "+
					"priority, and putting it first puts it above every P0", f.Fingerprint, f.Priority)
			}
		}
		if !sawUnscored {
			t.Skip("the corpus has no unscored finding")
		}
		// And the urgent ones come first.
		if page.Findings[0].Priority != model.P0 {
			t.Errorf("the first row of a priority-descending page is %q, want P0",
				page.Findings[0].Priority)
		}
	})
}
