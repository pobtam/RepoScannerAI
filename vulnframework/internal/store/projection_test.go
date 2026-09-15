package store_test

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// The projection is the VM-AD §8.6 merge rule. These tests exercise it directly
// as a pure function, independently of either backend, because it is the piece
// that must not depend on arrival order.

func obs(tool string, mutate func(*store.SourceObservation)) store.SourceObservation {
	o := store.SourceObservation{
		Fingerprint: "fp",
		RunID:       "S-000001",
		Tool:        tool,
		ObservedAt:  time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC),
		Severity:    model.SeverityUnknown,
		Reachable:   model.ReachableUnknown,
	}
	if mutate != nil {
		mutate(&o)
	}
	return o
}

// --- Order independence -----------------------------------------------------

// TestProjectIsOrderIndependent is the property the whole rule rests on. Every
// permutation of the same observation set must yield the same projection.
func TestProjectIsOrderIndependent(t *testing.T) {
	sources := []store.SourceObservation{
		obs("govulncheck", func(o *store.SourceObservation) {
			o.PrimaryID = "GO-2025-3106"
			o.Aliases = []string{"CVE-2025-22869"}
			o.Reachable = model.ReachableTrue
			o.FixedVer = "v0.36.0"
		}),
		obs("osv-scanner", func(o *store.SourceObservation) {
			o.PrimaryID = "GHSA-hcg3-q754-cr77"
			o.Aliases = []string{"CVE-2025-22869", "GO-2025-3106"}
			o.Severity = model.SeverityHigh
			o.CVSS = 7.5
			o.FixedVer = "v0.35.9"
		}),
		obs("trivy", func(o *store.SourceObservation) {
			o.Severity = model.SeverityMedium
			o.KEV = true
			o.FixedVer = "v0.36.0"
		}),
	}

	want := fmt.Sprint(store.Project(sources))
	for _, perm := range permutations(len(sources)) {
		shuffled := make([]store.SourceObservation, len(sources))
		for i, idx := range perm {
			shuffled[i] = sources[idx]
		}
		if got := fmt.Sprint(store.Project(shuffled)); got != want {
			t.Fatalf("projection depends on order.\n perm %v gave %s\n want           %s", perm, got, want)
		}
	}
}

// TestProjectIsIdempotentUnderDuplication covers replay: the same observation
// arriving twice must not change the result.
func TestProjectIsIdempotentUnderDuplication(t *testing.T) {
	a := obs("govulncheck", func(o *store.SourceObservation) { o.Reachable = model.ReachableTrue })
	b := obs("osv-scanner", func(o *store.SourceObservation) { o.Severity = model.SeverityHigh })

	once := fmt.Sprint(store.Project([]store.SourceObservation{a, b}))
	twice := fmt.Sprint(store.Project([]store.SourceObservation{a, b, a, b, a}))
	if once != twice {
		t.Errorf("projection is not idempotent under replay:\n once  %s\n twice %s", once, twice)
	}
}

// --- Field rules (VM-AD §8.6) -----------------------------------------------

func TestReachabilityRules(t *testing.T) {
	tests := []struct {
		name         string
		sources      []store.SourceObservation
		want         model.Reachable
		wantConflict bool
	}{
		{
			name:    "no source determines",
			sources: []store.SourceObservation{obs("osv-scanner", nil), obs("trivy", nil)},
			want:    model.ReachableUnknown,
		},
		{
			name: "a determination overrides unknown",
			sources: []store.SourceObservation{
				obs("osv-scanner", nil),
				obs("govulncheck", func(o *store.SourceObservation) { o.Reachable = model.ReachableTrue }),
			},
			want: model.ReachableTrue,
		},
		{
			name: "unknown never overrides a determination",
			sources: []store.SourceObservation{
				obs("govulncheck", func(o *store.SourceObservation) { o.Reachable = model.ReachableFalse }),
				obs("osv-scanner", nil),
			},
			want: model.ReachableFalse,
		},
		{
			name: "a false determination is preserved, not upgraded",
			sources: []store.SourceObservation{
				obs("govulncheck", func(o *store.SourceObservation) { o.Reachable = model.ReachableFalse }),
			},
			want: model.ReachableFalse,
		},
		{
			name: "true wins a genuine conflict, conservatively",
			sources: []store.SourceObservation{
				obs("govulncheck", func(o *store.SourceObservation) { o.Reachable = model.ReachableFalse }),
				obs("other-reachability-tool", func(o *store.SourceObservation) { o.Reachable = model.ReachableTrue }),
			},
			want:         model.ReachableTrue,
			wantConflict: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := store.Project(tc.sources)
			if p.Classification.Reachable != tc.want {
				t.Errorf("reachable = %q, want %q", p.Classification.Reachable, tc.want)
			}
			if p.ReachabilityConflict != tc.wantConflict {
				t.Errorf("conflict = %v, want %v", p.ReachabilityConflict, tc.wantConflict)
			}
			if tc.wantConflict && p.ConflictDetail == "" {
				t.Error("a conflict was flagged but not described; the disagreement itself is the signal")
			}
		})
	}
}

// TestSeverityIsMaxOverSuppliers covers the rule that most easily goes wrong: a
// source supplying no severity must contribute nothing, not drag the result
// down to UNKNOWN.
func TestSeverityIsMaxOverSuppliers(t *testing.T) {
	tests := []struct {
		name    string
		sources []store.SourceObservation
		want    model.Severity
	}{
		{
			name:    "no supplier",
			sources: []store.SourceObservation{obs("govulncheck", nil)},
			want:    model.SeverityUnknown,
		},
		{
			name: "a non-supplier does not dilute a supplier",
			sources: []store.SourceObservation{
				obs("govulncheck", nil),
				obs("osv-scanner", func(o *store.SourceObservation) { o.Severity = model.SeverityHigh }),
			},
			want: model.SeverityHigh,
		},
		{
			name: "maximum wins",
			sources: []store.SourceObservation{
				obs("osv-scanner", func(o *store.SourceObservation) { o.Severity = model.SeverityMedium }),
				obs("npm-audit", func(o *store.SourceObservation) { o.Severity = model.SeverityCritical }),
				obs("trivy", func(o *store.SourceObservation) { o.Severity = model.SeverityLow }),
			},
			want: model.SeverityCritical,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := store.Project(tc.sources).Classification.Severity; got != tc.want {
				t.Errorf("severity = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestToolsAndAliasesAreUnioned(t *testing.T) {
	p := store.Project([]store.SourceObservation{
		obs("govulncheck", func(o *store.SourceObservation) {
			o.PrimaryID = "GO-2025-3106"
			o.Aliases = []string{"CVE-2025-22869"}
		}),
		obs("osv-scanner", func(o *store.SourceObservation) {
			o.PrimaryID = "GHSA-hcg3-q754-cr77"
			o.Aliases = []string{"CVE-2025-22869"}
		}),
	})

	if fmt.Sprint(p.Tools) != "[govulncheck osv-scanner]" {
		t.Errorf("tools = %v, want the union", p.Tools)
	}
	want := "[CVE-2025-22869 GHSA-hcg3-q754-cr77 GO-2025-3106]"
	if fmt.Sprint(p.Aliases) != want {
		t.Errorf("aliases = %v, want %s", p.Aliases, want)
	}
	// The canonical identifier is the precedence winner over the union.
	if p.PrimaryID != "GO-2025-3106" {
		t.Errorf("primary id = %q, want GO-2025-3106", p.PrimaryID)
	}
}

// TestFixedVersionTakesTheFullyClosingFix covers the rule's intent: a bump to
// the lowest candidate would close one source's advisory and leave another's
// open, presenting as a verified finding the next scan immediately regresses.
func TestFixedVersionTakesTheFullyClosingFix(t *testing.T) {
	tests := []struct {
		name       string
		candidates []string
		want       string
	}{
		{"single", []string{"v0.36.0"}, "v0.36.0"},
		{"highest of several", []string{"v0.35.9", "v0.36.0", "v0.34.1"}, "v0.36.0"},
		{"minor beats patch", []string{"v1.7.4", "v1.10.0"}, "v1.10.0"},
		{"major beats minor", []string{"v1.99.0", "v2.0.0"}, "v2.0.0"},
		{"go toolchain versions", []string{"go1.22.2", "go1.21.9"}, "go1.22.2"},
		{"npm style without prefix", []string{"1.7.4", "1.7.9"}, "1.7.9"},
		{"release beats prerelease", []string{"v1.0.0", "v1.0.0-rc.1"}, "v1.0.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var sources []store.SourceObservation
			for i, c := range tc.candidates {
				fixed := c
				sources = append(sources, obs(fmt.Sprintf("tool%d", i), func(o *store.SourceObservation) {
					o.FixedVer = fixed
				}))
			}
			p := store.Project(sources)
			if p.FixedVersion != tc.want {
				t.Errorf("fixed = %q, want %q (candidates %v)", p.FixedVersion, tc.want, p.FixedCandidates)
			}
			// Every candidate is retained so the choice is auditable.
			if len(p.FixedCandidates) != len(uniq(tc.candidates)) {
				t.Errorf("candidates = %v, want all of %v retained", p.FixedCandidates, tc.candidates)
			}
		})
	}
}

func TestDepClassPrefersProduction(t *testing.T) {
	p := store.Project([]store.SourceObservation{
		obs("npm-audit", func(o *store.SourceObservation) { o.DepClass = model.DepDevelopment }),
		obs("osv-scanner", func(o *store.SourceObservation) { o.DepClass = model.DepProduction }),
	})
	if p.Classification.DepClass != model.DepProduction {
		t.Errorf("dep_class = %q, want production: over-stating exposure is safer than under-stating it",
			p.Classification.DepClass)
	}
}

func TestEmptyProjectionIsWellFormed(t *testing.T) {
	p := store.Project(nil)
	if p.Classification.Reachable != model.ReachableUnknown {
		t.Errorf("reachable = %q, want unknown", p.Classification.Reachable)
	}
	if p.Classification.Severity != model.SeverityUnknown {
		t.Errorf("severity = %q, want UNKNOWN", p.Classification.Severity)
	}
}

// --- LatestPerSource: the VM-ADR-12 consistency constraint ------------------

// TestLatestPerSourceKeepsOneRowPerTool covers supersession: a tool's later
// observation replaces its earlier one, and other tools are untouched.
func TestLatestPerSourceKeepsOneRowPerTool(t *testing.T) {
	early := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	late := time.Date(2026, 9, 8, 3, 0, 0, 0, time.UTC)

	in := []store.SourceObservation{
		{Tool: "govulncheck", RunID: "S-000001", ObservedAt: early, Reachable: model.ReachableFalse},
		{Tool: "govulncheck", RunID: "S-000002", ObservedAt: late, Reachable: model.ReachableTrue},
		{Tool: "osv-scanner", RunID: "S-000001", ObservedAt: early, Severity: model.SeverityHigh},
	}
	got := store.LatestPerSource(in)
	if len(got) != 2 {
		t.Fatalf("got %d observations, want one per tool", len(got))
	}

	p := store.Project(got)
	// The later govulncheck run supersedes the earlier one...
	if p.Classification.Reachable != model.ReachableTrue {
		t.Errorf("reachable = %q, want true from the later run", p.Classification.Reachable)
	}
	// ...and osv-scanner's older contribution survives, because nothing from
	// osv-scanner superseded it (VM-AD §8.6, VM-ADR-12).
	if p.Classification.Severity != model.SeverityHigh {
		t.Errorf("severity = %q, want HIGH retained from the older osv-scanner observation", p.Classification.Severity)
	}
}

// TestLatestPerSourceIsOrderIndependent guards the reduction itself.
func TestLatestPerSourceIsOrderIndependent(t *testing.T) {
	base := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	in := []store.SourceObservation{
		{Tool: "govulncheck", RunID: "S-000001", ObservedAt: base},
		{Tool: "govulncheck", RunID: "S-000002", ObservedAt: base.Add(time.Hour)},
		{Tool: "govulncheck", RunID: "S-000003", ObservedAt: base.Add(2 * time.Hour)},
		{Tool: "osv-scanner", RunID: "S-000002", ObservedAt: base.Add(time.Hour)},
	}
	want := fmt.Sprint(store.LatestPerSource(in))

	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 50; i++ {
		shuffled := append([]store.SourceObservation(nil), in...)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		if got := fmt.Sprint(store.LatestPerSource(shuffled)); got != want {
			t.Fatalf("LatestPerSource depends on input order:\n got  %s\n want %s", got, want)
		}
	}
}

// TestSameTimestampTiesBreakDeterministically covers two observations from one
// tool sharing a timestamp: replay must still be idempotent.
func TestSameTimestampTiesBreakDeterministically(t *testing.T) {
	at := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	in := []store.SourceObservation{
		{Tool: "govulncheck", RunID: "S-000001", ObservedAt: at, Severity: model.SeverityLow},
		{Tool: "govulncheck", RunID: "S-000002", ObservedAt: at, Severity: model.SeverityHigh},
	}
	first := store.LatestPerSource(in)
	reversed := store.LatestPerSource([]store.SourceObservation{in[1], in[0]})
	if fmt.Sprint(first) != fmt.Sprint(reversed) {
		t.Errorf("a timestamp tie resolves differently by order:\n %v\n %v", first, reversed)
	}
	if first[0].RunID != "S-000002" {
		t.Errorf("tie broke to run %s, want the later identifier S-000002", first[0].RunID)
	}
}

// --- helpers ----------------------------------------------------------------

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

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
