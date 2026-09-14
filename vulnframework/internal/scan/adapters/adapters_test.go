package adapters_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

var update = flag.Bool("update", false, "rewrite golden files from current normaliser output")

const (
	goAPIRepo  = "org/wanaware-api"
	goAPIDir   = "/tmp/scan-7f21a/clone"
	webRepo    = "org/payments-web"
	webDir     = "/tmp/scan-91c40/clone"
	fixtureDir = "../../../testdata/fixtures"
)

func readFixture(t *testing.T, tool, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, tool, name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return b
}

// assertGolden is the byte-for-byte gate (VM-AD §17 Phase 1). The normalised
// output of a captured fixture is compared against a committed golden file.
//
// This is the only defence against a tool's output format changing silently on
// upgrade: a scanner that starts emitting a renamed field would otherwise
// normalise to zero findings, and zero findings reads exactly like a clean
// repository.
func assertGolden(t *testing.T, tool, name string, got []model.RawFinding) {
	t.Helper()

	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("encoding normalised output: %v", err)
	}
	encoded = append(encoded, '\n')

	path := filepath.Join(fixtureDir, tool, strings.TrimSuffix(name, ".json")+".golden.json")
	if *update {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatalf("writing golden: %v", err)
		}
		t.Logf("updated %s", path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden (run: go test ./internal/scan/adapters -update): %v", err)
	}
	if string(encoded) != string(want) {
		t.Errorf("normalised output does not match %s byte-for-byte.\n--- got ---\n%s\n--- want ---\n%s",
			path, encoded, want)
	}
}

// out builds the RawOutput an adapter's Normalize consumes.
func out(tool, repo, dir string, stdout []byte) scan.RawOutput {
	return scan.RawOutput{Tool: tool, Repo: repo, Dir: dir, Stdout: stdout}
}

func testLock(t *testing.T) scan.ToolsLock {
	t.Helper()
	lock, err := scan.LoadToolsLock("../../../config/tools.lock")
	if err != nil {
		t.Fatalf("loading tools.lock: %v", err)
	}
	return lock
}

// --- Gate: every adapter normalises its fixture byte-for-byte ---------------

func TestFixtureNormalisation(t *testing.T) {
	lock := testLock(t)
	r := runner.NewFake()

	tests := []struct {
		tool    string
		fixture string
		repo    string
		dir     string
		adapter scan.Adapter
		aux     map[string][]byte
	}{
		{"govulncheck", "go-api.json", goAPIRepo, goAPIDir, adapters.NewGovulncheck(r, lock.MustVersion("govulncheck")), nil},
		{"osv-scanner", "go-api.json", goAPIRepo, goAPIDir, adapters.NewOSVScanner(r, lock.MustVersion("osv-scanner")), nil},
		{"osv-scanner", "payments-web.json", webRepo, webDir, adapters.NewOSVScanner(r, lock.MustVersion("osv-scanner")), nil},
		{"gosec", "go-api.json", goAPIRepo, goAPIDir, adapters.NewGosec(r, lock.MustVersion("gosec")), nil},
		{"staticcheck", "go-api.json", goAPIRepo, goAPIDir, adapters.NewStaticcheck(r, lock.MustVersion("staticcheck")), nil},
		{"gitleaks", "go-api.json", goAPIRepo, goAPIDir, adapters.NewGitleaks(r, lock.MustVersion("gitleaks")), nil},
		{"trivy", "go-api.json", goAPIRepo, goAPIDir, adapters.NewTrivy(r, lock.MustVersion("trivy")), nil},
		{"semgrep", "payments-web.json", webRepo, webDir, adapters.NewSemgrep(r, lock.MustVersion("semgrep")), nil},
		{"actions-pin", "go-api.json", goAPIRepo, goAPIDir, adapters.NewActionsPin(r, lock.MustVersion("actions-pin")), nil},
	}

	for _, tc := range tests {
		t.Run(tc.tool+"/"+tc.fixture, func(t *testing.T) {
			o := out(tc.tool, tc.repo, tc.dir, readFixture(t, tc.tool, tc.fixture))
			o.Aux = tc.aux
			got, err := tc.adapter.Normalize(o)
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			assertGolden(t, tc.tool, tc.fixture, got)
		})
	}
}

// npm-audit is separate because it needs package.json to resolve the
// development-only classification (VM-F-242).
func TestNPMAuditFixtureNormalisation(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewNPMAudit(runner.NewFake(), lock.MustVersion("npm-audit"))

	o := out("npm-audit", webRepo, webDir, readFixture(t, "npm-audit", "payments-web.json"))
	o.Aux = map[string][]byte{
		adapters.PackageJSONPath: readFixture(t, "npm-audit", "package.json"),
	}

	got, err := a.Normalize(o)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	assertGolden(t, "npm-audit", "payments-web.json", got)
}

// TestEveryAdapterHasAFixtureTest enforces VM-AD §8.4's standing requirement
// that every adapter carry one. Adding an adapter without a fixture fails here
// rather than shipping an unverified normaliser.
func TestEveryAdapterHasAFixtureTest(t *testing.T) {
	lock := testLock(t)
	all := adapters.All(runner.NewFake(), lock)

	for _, a := range all {
		dir := filepath.Join(fixtureDir, a.Name())
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Errorf("adapter %q has no testdata/fixtures/%s directory: %v", a.Name(), a.Name(), err)
			continue
		}
		var goldens int
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".golden.json") {
				goldens++
			}
		}
		if goldens == 0 {
			t.Errorf("adapter %q has fixtures but no golden file; its normaliser is unverified", a.Name())
		}
	}
}

// --- Gate: cross-tool alias collapse (VM-F-106) ----------------------------

// TestCrossToolAliasCollapse is the second half of the Phase 1 gate.
//
// govulncheck reports GO-2025-3106 and osv-scanner reports GHSA-hcg3-q754-cr77
// for one defect in golang.org/x/crypto. Alias resolution must collapse them to
// a single fingerprint. If it does not, the store holds two findings for one
// vulnerability, two tickets are opened, and the deduplication requirement
// fails.
func TestCrossToolAliasCollapse(t *testing.T) {
	lock := testLock(t)
	r := runner.NewFake()

	gvc := adapters.NewGovulncheck(r, lock.MustVersion("govulncheck"))
	osv := adapters.NewOSVScanner(r, lock.MustVersion("osv-scanner"))

	gvcFindings, err := gvc.Normalize(out("govulncheck", goAPIRepo, goAPIDir, readFixture(t, "govulncheck", "go-api.json")))
	if err != nil {
		t.Fatalf("govulncheck Normalize: %v", err)
	}
	osvFindings, err := osv.Normalize(out("osv-scanner", goAPIRepo, goAPIDir, readFixture(t, "osv-scanner", "go-api.json")))
	if err != nil {
		t.Fatalf("osv-scanner Normalize: %v", err)
	}

	find := func(fs []model.RawFinding, module string) (model.RawFinding, bool) {
		for _, f := range fs {
			if f.Module == module {
				return f, true
			}
		}
		return model.RawFinding{}, false
	}

	fromGvc, ok := find(gvcFindings, "golang.org/x/crypto")
	if !ok {
		t.Fatal("govulncheck produced no finding for golang.org/x/crypto")
	}
	fromOSV, ok := find(osvFindings, "golang.org/x/crypto")
	if !ok {
		t.Fatal("osv-scanner produced no finding for golang.org/x/crypto")
	}

	// The two tools name the advisory differently...
	if fromGvc.PrimaryID == fromOSV.PrimaryID {
		t.Fatalf("fixtures do not exercise alias resolution: both tools reported %q", fromGvc.PrimaryID)
	}
	t.Logf("govulncheck reported %s; osv-scanner reported %s", fromGvc.PrimaryID, fromOSV.PrimaryID)

	// ...and must still land on one fingerprint.
	gvcFP := fingerprint.Compute(fromGvc)
	osvFP := fingerprint.Compute(fromOSV)
	if gvcFP != osvFP {
		t.Fatalf("one defect produced two fingerprints (VM-F-106 fails):\n  govulncheck %s -> %s\n  osv-scanner %s -> %s",
			fromGvc.PrimaryID, gvcFP, fromOSV.PrimaryID, osvFP)
	}

	// Both must resolve to the GO id, which outranks GHSA and CVE.
	if got := fingerprint.Identity(fromGvc); got != "GO-2025-3106" {
		t.Errorf("canonical identity = %q, want GO-2025-3106 (precedence GO > GHSA > CVE)", got)
	}
}

// TestCrossToolReachabilityDisagreement records what the collapse implies: the
// two tools carry different, complementary attributes for the same fingerprint.
// govulncheck alone knows reachability; osv-scanner alone carries the severity.
// Merging them is the store's job (Phase 2), and it can only happen because the
// fingerprints agree.
func TestCrossToolReachabilityDisagreement(t *testing.T) {
	lock := testLock(t)
	r := runner.NewFake()

	gvcFindings, _ := adapters.NewGovulncheck(r, lock.MustVersion("govulncheck")).
		Normalize(out("govulncheck", goAPIRepo, goAPIDir, readFixture(t, "govulncheck", "go-api.json")))
	osvFindings, _ := adapters.NewOSVScanner(r, lock.MustVersion("osv-scanner")).
		Normalize(out("osv-scanner", goAPIRepo, goAPIDir, readFixture(t, "osv-scanner", "go-api.json")))

	byFP := map[string]model.RawFinding{}
	for _, f := range gvcFindings {
		byFP[fingerprint.Compute(f)] = f
	}
	for _, f := range osvFindings {
		fp := fingerprint.Compute(f)
		gvc, both := byFP[fp]
		if !both {
			continue
		}
		if gvc.Classification.Reachable == model.ReachableUnknown {
			t.Errorf("govulncheck left reachability unknown for %s; it is the reachability authority for Go", fp)
		}
		if f.Classification.Reachable != model.ReachableUnknown {
			t.Errorf("osv-scanner asserted reachability %q for %s; it performs no reachability analysis",
				f.Classification.Reachable, fp)
		}
		if gvc.Classification.Severity != model.SeverityUnknown {
			t.Errorf("govulncheck asserted severity %q; the Go vulnerability database does not score advisories",
				gvc.Classification.Severity)
		}
		if f.Classification.Severity == model.SeverityUnknown {
			t.Errorf("osv-scanner left severity unknown for %s; it carries the advisory score", fp)
		}
		return
	}
	t.Fatal("no fingerprint was reported by both tools; the collapse test is not exercising a shared finding")
}

// --- Gate-adjacent: secret redaction in normalisation (VM-F-263/264) -------

// TestGitleaksRedactsCredentialMaterial is the normalisation-layer enforcement
// of VM-F-264. gitleaks reports the matched credential verbatim; none of it may
// survive into a finding, including into the retained raw output.
//
// This is the unit-level half of v1.0 acceptance criterion 8 ("a planted test
// secret ... never appears in any report or ticket body"). Enforcing it here,
// at the boundary, is the point: a redaction pass further downstream runs after
// the value has already reached a store or a log.
func TestGitleaksRedactsCredentialMaterial(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewGitleaks(runner.NewFake(), lock.MustVersion("gitleaks"))

	fixture := readFixture(t, "gitleaks", "go-api.json")

	// The planted credentials, taken from the fixture itself so the test cannot
	// drift from what the tool reported.
	planted := []string{
		"REDACTED-AWS-EXAMPLE-KEY-ID",
		"REDACTED-FAKE-GITHUB-TOKEN",
		"aws_access_key_id = REDACTED-AWS-EXAMPLE-KEY-ID",
	}
	for _, secret := range planted {
		if !strings.Contains(string(fixture), secret) {
			t.Fatalf("fixture does not contain %q; the redaction test is vacuous", secret)
		}
	}

	got, err := a.Normalize(out("gitleaks", goAPIRepo, goAPIDir, fixture))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("gitleaks normalised to no findings; the redaction test is vacuous")
	}

	// Serialise the entire normalised output — every field, including Raw — and
	// assert no credential material survives anywhere in it.
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, secret := range planted {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("credential material %q survived normalisation (VM-F-264):\n%s", secret, encoded)
		}
	}

	// The finding must still be useful: path, line and credential class.
	for _, f := range got {
		if f.File == "" {
			t.Error("secret finding has no file path")
		}
		if f.Line == 0 {
			t.Error("secret finding has no line number")
		}
		if f.CredentialType == "" {
			t.Error("secret finding does not record the credential type (VM-F-263)")
		}
		if f.Category != model.CategorySecret {
			t.Errorf("category = %q, want secret", f.Category)
		}
		if f.Classification.Severity != model.SeverityCritical {
			t.Errorf("severity = %q, want CRITICAL: secrets take a fixed maximum (VM-AD §9.4)", f.Classification.Severity)
		}
	}
}

// TestSecretFindingsSurviveTheModelBoundary confirms the redacted output also
// satisfies the model's own structural guarantee.
func TestSecretFindingsSurviveTheModelBoundary(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewGitleaks(runner.NewFake(), lock.MustVersion("gitleaks"))
	got, err := a.Normalize(out("gitleaks", goAPIRepo, goAPIDir, readFixture(t, "gitleaks", "go-api.json")))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	for _, f := range got {
		if err := fingerprint.Validate(f); err != nil {
			t.Errorf("secret finding is not fingerprintable: %v", err)
		}
	}
}

// --- Reachability (VM-F-221, VM-F-243) --------------------------------------

// TestGovulncheckReachability covers the distinction the tri-state exists for.
// govulncheck reports the same advisory at module, package and symbol level;
// only a symbol-level frame proves the vulnerable code is called.
func TestGovulncheckReachability(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewGovulncheck(runner.NewFake(), lock.MustVersion("govulncheck"))
	got, err := a.Normalize(out("govulncheck", goAPIRepo, goAPIDir, readFixture(t, "govulncheck", "go-api.json")))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	want := map[string]model.Reachable{
		"golang.org/x/crypto": model.ReachableTrue,  // symbol-level trace
		"golang.org/x/net":    model.ReachableFalse, // module-level only
		"stdlib":              model.ReachableTrue,  // symbol-level trace
	}
	seen := map[string]bool{}
	for _, f := range got {
		expected, tracked := want[f.Module]
		if !tracked {
			continue
		}
		seen[f.Module] = true
		if f.Classification.Reachable != expected {
			t.Errorf("module %s: reachable = %q, want %q", f.Module, f.Classification.Reachable, expected)
		}
		if !f.Classification.Reachable.Valid() {
			t.Errorf("module %s: reachable %q is not one of the three permitted values", f.Module, f.Classification.Reachable)
		}
	}
	for module := range want {
		if !seen[module] {
			t.Errorf("no finding produced for %s", module)
		}
	}
}

// TestGovulncheckCollapsesMultiLevelFindings covers VM-F-106 within one tool:
// three messages about one advisory in one module are one finding.
func TestGovulncheckCollapsesMultiLevelFindings(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewGovulncheck(runner.NewFake(), lock.MustVersion("govulncheck"))
	got, err := a.Normalize(out("govulncheck", goAPIRepo, goAPIDir, readFixture(t, "govulncheck", "go-api.json")))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	count := 0
	for _, f := range got {
		if f.Module == "golang.org/x/crypto" {
			count++
		}
	}
	// The fixture carries three finding messages for GO-2025-3106.
	if count != 1 {
		t.Errorf("golang.org/x/crypto produced %d findings, want 1: module, package and symbol messages must collapse", count)
	}

	fps := map[string]bool{}
	for _, f := range got {
		fp := fingerprint.Compute(f)
		if fps[fp] {
			t.Errorf("duplicate fingerprint %s in one adapter's output", fp)
		}
		fps[fp] = true
	}
}

// TestStdlibVulnerabilityIsReported covers VM-F-223: toolchain-level standard
// library vulnerabilities are findings like any other.
func TestStdlibVulnerabilityIsReported(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewGovulncheck(runner.NewFake(), lock.MustVersion("govulncheck"))
	got, _ := a.Normalize(out("govulncheck", goAPIRepo, goAPIDir, readFixture(t, "govulncheck", "go-api.json")))

	for _, f := range got {
		if f.Module == "stdlib" {
			if f.ModuleMajor != "go1" {
				t.Errorf("stdlib major = %q, want go1", f.ModuleMajor)
			}
			return
		}
	}
	t.Error("no stdlib finding reported (VM-F-223)")
}

// --- Dependency classification (VM-F-242) -----------------------------------

// TestNPMAuditDevDependencyClassification covers VM-F-242. Treating a
// development-only advisory as production inflates the priority queue with
// findings that never reach a production runtime.
func TestNPMAuditDevDependencyClassification(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewNPMAudit(runner.NewFake(), lock.MustVersion("npm-audit"))

	o := out("npm-audit", webRepo, webDir, readFixture(t, "npm-audit", "payments-web.json"))
	o.Aux = map[string][]byte{adapters.PackageJSONPath: readFixture(t, "npm-audit", "package.json")}

	got, err := a.Normalize(o)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	want := map[string]model.DepClass{
		"axios":   model.DepProduction,  // a dependency
		"postcss": model.DepDevelopment, // a devDependency
	}
	seen := map[string]bool{}
	for _, f := range got {
		expected, tracked := want[f.Module]
		if !tracked {
			continue
		}
		seen[f.Module] = true
		if f.Classification.DepClass != expected {
			t.Errorf("%s: dep_class = %q, want %q", f.Module, f.Classification.DepClass, expected)
		}
	}
	for module := range want {
		if !seen[module] {
			t.Errorf("no finding produced for %s", module)
		}
	}
}

// TestNPMAuditWithoutManifestDefaultsToProduction records the behaviour when
// package.json is unavailable: classify as production. Under-stating a
// development dependency is safe; over-stating a production one is not.
func TestNPMAuditWithoutManifestDefaultsToProduction(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewNPMAudit(runner.NewFake(), lock.MustVersion("npm-audit"))
	got, err := a.Normalize(out("npm-audit", webRepo, webDir, readFixture(t, "npm-audit", "payments-web.json")))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	for _, f := range got {
		if f.Classification.DepClass != model.DepProduction {
			t.Errorf("%s: dep_class = %q without a manifest, want production", f.Module, f.Classification.DepClass)
		}
	}
}

// TestNPMAuditExtractsGHSAIdentifier covers the deduplication path: npm audit
// carries no identifier field, so the GHSA id must come out of the advisory URL
// or these findings can never collapse onto osv-scanner's.
func TestNPMAuditExtractsGHSAIdentifier(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewNPMAudit(runner.NewFake(), lock.MustVersion("npm-audit"))
	got, _ := a.Normalize(out("npm-audit", webRepo, webDir, readFixture(t, "npm-audit", "payments-web.json")))

	for _, f := range got {
		if f.Module == "axios" {
			if f.PrimaryID != "GHSA-8hc4-vh64-cxmj" {
				t.Errorf("axios primary id = %q, want GHSA-8hc4-vh64-cxmj", f.PrimaryID)
			}
			return
		}
	}
	t.Error("no axios finding produced")
}

// --- Static analysis filtering ----------------------------------------------

// TestStaticcheckFiltersToSecuritySubset covers VM-AD §8.2's requirement to
// report only the security-relevant subset. Without the filter, correctness and
// style diagnostics would swamp the finding store.
func TestStaticcheckFiltersToSecuritySubset(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewStaticcheck(runner.NewFake(), lock.MustVersion("staticcheck"))
	got, err := a.Normalize(out("staticcheck", goAPIRepo, goAPIDir, readFixture(t, "staticcheck", "go-api.json")))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	reported := map[string]bool{}
	for _, f := range got {
		reported[f.RuleID] = true
	}
	// The fixture contains two in-subset and two out-of-subset diagnostics.
	for _, want := range []string{"SA1019", "SA1000"} {
		if !reported[want] {
			t.Errorf("security-relevant check %s was filtered out", want)
		}
	}
	for _, unwanted := range []string{"SA4006", "ST1005"} {
		if reported[unwanted] {
			t.Errorf("non-security check %s was reported", unwanted)
		}
	}
}

// TestSemgrepFiltersToSecurityCategory is the JavaScript equivalent.
func TestSemgrepFiltersToSecurityCategory(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewSemgrep(runner.NewFake(), lock.MustVersion("semgrep"))
	got, err := a.Normalize(out("semgrep", webRepo, webDir, readFixture(t, "semgrep", "payments-web.json")))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	for _, f := range got {
		if strings.Contains(f.RuleID, "best-practice") {
			t.Errorf("non-security rule reported: %s", f.RuleID)
		}
	}
	if len(got) != 2 {
		t.Errorf("got %d findings, want 2 security results from a fixture of 3", len(got))
	}
}

// TestGosecSkipsSuppressedIssues records that an explicit, reviewed in-repository
// #nosec decision is honoured rather than second-guessed.
func TestGosecSkipsSuppressedIssues(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewGosec(runner.NewFake(), lock.MustVersion("gosec"))
	got, err := a.Normalize(out("gosec", goAPIRepo, goAPIDir, readFixture(t, "gosec", "go-api.json")))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("got %d findings, want 3 (no suppressions in the fixture)", len(got))
	}
}

// --- Configuration and Actions pinning --------------------------------------

// TestTrivyReportsOnlyFailures covers the FAIL/PASS distinction: trivy reports
// passing checks alongside failures and only failures are findings.
func TestTrivyReportsOnlyFailures(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewTrivy(runner.NewFake(), lock.MustVersion("trivy"))
	got, err := a.Normalize(out("trivy", goAPIRepo, goAPIDir, readFixture(t, "trivy", "go-api.json")))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3 failing misconfigurations", len(got))
	}
	for _, f := range got {
		if f.Category != model.CategoryConfig {
			t.Errorf("category = %q, want config", f.Category)
		}
	}
}

// TestTrivyResourceKeySeparatesFindings covers the fingerprint location for
// config findings: two failures of one check against different resources in one
// manifest must remain two findings.
func TestTrivyResourceKeySeparatesFindings(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewTrivy(runner.NewFake(), lock.MustVersion("trivy"))
	got, _ := a.Normalize(out("trivy", goAPIRepo, goAPIDir, readFixture(t, "trivy", "go-api.json")))

	fps := map[string]string{}
	for _, f := range got {
		fp := fingerprint.Compute(f)
		if prev, dup := fps[fp]; dup {
			t.Errorf("config findings collide on %s: %q and %q", fp, prev, f.CheckID+"@"+f.ResourceKey)
		}
		fps[fp] = f.CheckID + "@" + f.ResourceKey
	}

	for _, f := range got {
		if f.CheckID == "KSV012" {
			if f.ResourceKey != "Deployment/wanaware-api/api" {
				t.Errorf("KSV012 resource key = %q, want the Kubernetes resource", f.ResourceKey)
			}
			return
		}
	}
	t.Error("KSV012 not reported")
}

// TestActionsPinFlagsMutableTags covers VM-F-266. A mutable tag can be
// repointed by whoever controls the action's repository, so every workflow
// referencing one carries a standing supply-chain exposure.
func TestActionsPinFlagsMutableTags(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewActionsPin(runner.NewFake(), lock.MustVersion("actions-pin"))
	got, err := a.Normalize(out("actions-pin", goAPIRepo, goAPIDir, readFixture(t, "actions-pin", "go-api.json")))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	flagged := map[string]bool{}
	for _, f := range got {
		flagged[f.ResourceKey] = true
	}
	// Two of the fixture's four references are tag-pinned.
	if len(got) != 2 {
		t.Errorf("got %d findings, want 2 unpinned actions", len(got))
	}
	for _, want := range []string{"actions/checkout", "docker/login-action"} {
		if !flagged[want] {
			t.Errorf("unpinned action %s was not flagged", want)
		}
	}
	for _, sha := range []string{"actions/setup-go", "docker/build-push-action"} {
		if flagged[sha] {
			t.Errorf("SHA-pinned action %s was flagged", sha)
		}
	}
}
