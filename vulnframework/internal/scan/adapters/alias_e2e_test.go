package adapters_test

import (
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

// Standing end-to-end guard for alias resolution (OQ-P3-03).
//
// Phase 1 assumed govulncheck and osv-scanner would name one defect under
// different namespaces. Real osv-scanner v2 reports GO identifiers, so that
// pair agrees outright and no longer exercises the precedence rule. Rather than
// accept alias resolution as unit-only coverage, this uses the pair that does
// diverge in the real tool set: trivy reports Go advisories under CVE
// identifiers while govulncheck reports them under GO ones.
//
// The case is genuinely hard, which is the point: trivy publishes no alias set
// at all, so nothing in its own output can connect CVE-2025-22869 to
// GO-2025-3487. Only the scan's alias table, populated from the tools that do
// publish OSV alias data, can close that gap (VM-AD §5).

// normaliseWith runs one adapter over its captured fixture.
func normaliseWith(t *testing.T, a scan.Adapter, tool, fixture, repo, dir string) []model.RawFinding {
	t.Helper()
	got, err := a.Normalize(out(tool, repo, dir, readFixture(t, tool, fixture)))
	if err != nil {
		t.Fatalf("%s Normalize: %v", tool, err)
	}
	return got
}

// TestCrossNamespaceAliasCollapse is the e2e guard. A CVE-reported defect and a
// GO-reported defect must collapse to one fingerprint, by the
// GO > GHSA > CVE > OSV > rule-id precedence.
func TestCrossNamespaceAliasCollapse(t *testing.T) {
	lock := testLock(t)
	r := runner.NewFake()

	gvc := normaliseWith(t, adapters.NewGovulncheck(r, lock.MustVersion("govulncheck")),
		"govulncheck", "go-api.json", goAPIRepo, goAPIDir)
	tv := normaliseWith(t, adapters.NewTrivy(r, lock.MustVersion("trivy")),
		"trivy", "go-api.json", goAPIRepo, goAPIDir)

	// Confirm the namespaces really do diverge, so the test cannot pass
	// vacuously the way the Phase 1 version came to.
	var goIDs, cveIDs int
	for _, f := range gvc {
		if strings.HasPrefix(f.PrimaryID, "GO-") {
			goIDs++
		}
	}
	for _, f := range tv {
		if f.Category == model.CategoryDependency && strings.HasPrefix(f.PrimaryID, "CVE-") {
			cveIDs++
		}
	}
	if goIDs == 0 || cveIDs == 0 {
		t.Fatalf("fixtures do not span two namespaces: %d GO ids from govulncheck, %d CVE ids from trivy", goIDs, cveIDs)
	}

	// Trivy alone cannot connect its CVE to a GO identifier.
	for _, f := range tv {
		if f.PrimaryID == "CVE-2025-22869" && len(f.Aliases) != 0 {
			t.Fatalf("trivy now publishes aliases (%v); this test no longer exercises the alias table", f.Aliases)
		}
	}

	// The alias table, built from the whole scan, closes the gap.
	all := append(append([]model.RawFinding{}, gvc...), tv...)
	table := scan.NewAliasTable()
	table.AddFindings(all)
	enriched := table.Enrich(all)

	find := func(tool, id string) (model.RawFinding, bool) {
		for _, f := range enriched {
			if f.Tool == tool && f.PrimaryID == id {
				return f, true
			}
		}
		return model.RawFinding{}, false
	}

	fromTrivy, ok := find("trivy", "CVE-2025-22869")
	if !ok {
		t.Fatal("trivy did not report CVE-2025-22869")
	}
	fromGvc, ok := find("govulncheck", "GO-2025-3487")
	if !ok {
		t.Fatal("govulncheck did not report GO-2025-3487")
	}

	if got, want := fingerprint.Compute(fromTrivy), fingerprint.Compute(fromGvc); got != want {
		t.Fatalf("one defect reported in two namespaces produced two fingerprints (VM-F-106):\n"+
			"  trivy       CVE-2025-22869 -> %s (aliases %v)\n"+
			"  govulncheck GO-2025-3487   -> %s (aliases %v)",
			got, fromTrivy.Aliases, want, fromGvc.Aliases)
	}

	// And both must resolve to the GO identifier, not the CVE.
	if got := fingerprint.Identity(fromTrivy); got != "GO-2025-3487" {
		t.Errorf("trivy's canonical identity = %q, want GO-2025-3487 (precedence GO > GHSA > CVE)", got)
	}
}

// TestCrossNamespaceCollapseIsBroad checks the property across every defect the
// two tools share, not just the one example, so a precedence regression cannot
// hide behind a single passing case.
func TestCrossNamespaceCollapseIsBroad(t *testing.T) {
	lock := testLock(t)
	r := runner.NewFake()

	all := append(
		normaliseWith(t, adapters.NewGovulncheck(r, lock.MustVersion("govulncheck")),
			"govulncheck", "go-api.json", goAPIRepo, goAPIDir),
		normaliseWith(t, adapters.NewTrivy(r, lock.MustVersion("trivy")),
			"trivy", "go-api.json", goAPIRepo, goAPIDir)...,
	)

	table := scan.NewAliasTable()
	table.AddFindings(all)
	enriched := table.Enrich(all)

	// Group by fingerprint and count how many carry findings from both tools
	// under different primary identifiers.
	type entry struct{ tools, ids map[string]bool }
	byFP := map[string]*entry{}
	for _, f := range enriched {
		if f.Category != model.CategoryDependency {
			continue
		}
		fp := fingerprint.Compute(f)
		e := byFP[fp]
		if e == nil {
			e = &entry{tools: map[string]bool{}, ids: map[string]bool{}}
			byFP[fp] = e
		}
		e.tools[f.Tool] = true
		e.ids[f.PrimaryID] = true
	}

	crossNamespace := 0
	for _, e := range byFP {
		if len(e.tools) > 1 && len(e.ids) > 1 {
			crossNamespace++
		}
	}
	if crossNamespace == 0 {
		t.Fatal("no fingerprint collapsed findings reported under different identifiers by different tools; " +
			"alias resolution is not exercised end to end (OQ-P3-03)")
	}
	t.Logf("%d defects collapsed across namespaces by alias resolution", crossNamespace)
}

// TestAliasEnrichmentDoesNotRewriteProvenance guards the boundary: enrichment
// widens the alias set, never the tool's own claim about what it found.
func TestAliasEnrichmentDoesNotRewriteProvenance(t *testing.T) {
	lock := testLock(t)
	r := runner.NewFake()
	tv := normaliseWith(t, adapters.NewTrivy(r, lock.MustVersion("trivy")),
		"trivy", "go-api.json", goAPIRepo, goAPIDir)

	before := map[int]string{}
	for i, f := range tv {
		before[i] = f.PrimaryID
	}

	table := scan.NewAliasTable()
	table.AddFindings(tv)
	after := table.Enrich(tv)

	for i, f := range after {
		if f.PrimaryID != before[i] {
			t.Errorf("enrichment rewrote a tool's reported identifier: %q became %q", before[i], f.PrimaryID)
		}
	}
}

// --- OQ-P3-01: experimental reachability is recorded, never determining -----

// TestOSVExperimentalAnalysisNeverDeterminesReachability enforces the decision
// that osv-scanner's experimental Go analysis is provenance, not a verdict.
//
// It is the same enforcement shape as the no-secret-value rule: the value is
// checked at the boundary where it would otherwise leak, so a future change
// that starts consuming it fails here rather than silently displacing the
// authority.
func TestOSVExperimentalAnalysisNeverDeterminesReachability(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewOSVScanner(runner.NewFake(), lock.MustVersion("osv-scanner"))
	got := normaliseWith(t, a, "osv-scanner", "go-api.json", goAPIRepo, goAPIDir)

	annotated, called := 0, 0
	for _, f := range got {
		// The determination field must always be unknown for this tool,
		// whatever the experimental analysis said.
		if f.Classification.Reachable != model.ReachableUnknown {
			t.Errorf("%s: reachable = %q; osv-scanner must never determine reachability — govulncheck is the authority (OQ-P3-01)",
				f.PrimaryID, f.Classification.Reachable)
		}
		for k, v := range f.Annotations {
			if !strings.Contains(k, "experimental_called") {
				continue
			}
			annotated++
			if v == "true" {
				called++
			}
			// The annotation must be version-tagged, or a later comparison
			// against the authority cannot say which build produced it.
			if !strings.HasPrefix(k, "osv-scanner/"+lock.MustVersion("osv-scanner")+"/") {
				t.Errorf("annotation key %q is not tagged with the producing osv-scanner version", k)
			}
		}
	}

	if annotated == 0 {
		t.Fatal("no finding carries the experimental analysis annotation; the guard is vacuous. " +
			"If osv-scanner stopped emitting experimental_analysis, revisit OQ-P3-01.")
	}
	t.Logf("%d findings annotated, %d with called=true — recorded as provenance, none determining", annotated, called)
}

// TestAnnotationsAreNotClassification is the structural half: no annotation key
// may collide with a classified field name, so the two can never be confused by
// a consumer reading the record.
func TestAnnotationsAreNotClassification(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewOSVScanner(runner.NewFake(), lock.MustVersion("osv-scanner"))
	got := normaliseWith(t, a, "osv-scanner", "go-api.json", goAPIRepo, goAPIDir)

	reserved := []string{"reachable", "severity", "cvss", "epss", "kev", "dep_class"}
	for _, f := range got {
		for k := range f.Annotations {
			for _, r := range reserved {
				if k == r {
					t.Errorf("annotation %q collides with a classified field; annotations must be distinguishable from determinations", k)
				}
			}
		}
	}
}
