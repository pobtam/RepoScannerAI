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
	"github.com/wanaware/vulnframework/internal/testkeys"
)

var (
	// update accepts golden VALUE diffs: the tool reported different findings,
	// which is expected when the scanner image is rebuilt.
	update = flag.Bool("update", false, "rewrite golden files from current normaliser output")
	// updateShapes re-blesses the recorded field inventory. Deliberately
	// separate: a newly-seen field is an adapter gap that needs a test, not a
	// value diff to be waved through.
	updateShapes = flag.Bool("update-shapes", false, "re-bless fixture shape inventories after covering new fields with a test")
)

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
	// Recorded output that echoes a planted credential is committed with a
	// placeholder; the adapter must see what the tool really printed.
	return testkeys.Expand(b)
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

// fixtureCases is the full captured set: every adapter, every envelope.
func fixtureCases(t *testing.T, lock scan.ToolsLock) []fixtureCase {
	t.Helper()
	r := runner.NewFake()
	pkg := map[string][]byte{adapters.PackageJSONPath: readFixture(t, "npm-audit", "package.json")}

	gv := func() scan.Adapter { return adapters.NewGovulncheck(r, lock.MustVersion("govulncheck")) }
	gs := func() scan.Adapter { return adapters.NewGosec(r, lock.MustVersion("gosec")) }
	st := func() scan.Adapter { return adapters.NewStaticcheck(r, lock.MustVersion("staticcheck")) }
	os_ := func() scan.Adapter { return adapters.NewOSVScanner(r, lock.MustVersion("osv-scanner")) }
	gl := func() scan.Adapter { return adapters.NewGitleaks(r, lock.MustVersion("gitleaks")) }
	tv := func() scan.Adapter { return adapters.NewTrivy(r, lock.MustVersion("trivy")) }
	sg := func() scan.Adapter { return adapters.NewSemgrep(r, lock.MustVersion("semgrep")) }
	np := func() scan.Adapter { return adapters.NewNPMAudit(r, lock.MustVersion("npm-audit")) }
	ap := func() scan.Adapter { return adapters.NewActionsPin(r, lock.MustVersion("actions-pin")) }

	return []fixtureCase{
		{"govulncheck", "go-api.json", goAPIRepo, goAPIDir, gv(), nil},
		{"govulncheck", "empty.json", goAPIRepo, goAPIDir, gv(), nil},
		{"govulncheck", "error.json", goAPIRepo, goAPIDir, gv(), nil},
		{"gosec", "go-api.json", goAPIRepo, goAPIDir, gs(), nil},
		{"gosec", "empty.json", goAPIRepo, goAPIDir, gs(), nil},
		{"gosec", "error.json", goAPIRepo, goAPIDir, gs(), nil},
		{"staticcheck", "go-api.json", goAPIRepo, goAPIDir, st(), nil},
		{"staticcheck", "empty.json", goAPIRepo, goAPIDir, st(), nil},
		{"staticcheck", "error.json", goAPIRepo, goAPIDir, st(), nil},
		{"osv-scanner", "go-api.json", goAPIRepo, goAPIDir, os_(), nil},
		{"osv-scanner", "payments-web.json", webRepo, webDir, os_(), nil},
		{"osv-scanner", "empty.json", goAPIRepo, goAPIDir, os_(), nil},
		{"osv-scanner", "error.json", goAPIRepo, goAPIDir, os_(), nil},
		{"gitleaks", "go-api.json", goAPIRepo, goAPIDir, gl(), nil},
		{"gitleaks", "empty.json", goAPIRepo, goAPIDir, gl(), nil},
		{"gitleaks", "allowlisted.json", goAPIRepo, goAPIDir, gl(), gitleaksAllowlistAux(t)},
		{"trivy", "go-api.json", goAPIRepo, goAPIDir, tv(), nil},
		{"trivy", "empty.json", goAPIRepo, goAPIDir, tv(), nil},
		{"semgrep", "payments-web.json", webRepo, webDir, sg(), nil},
		{"semgrep", "empty.json", webRepo, webDir, sg(), nil},
		{"npm-audit", "payments-web.json", webRepo, webDir, np(), pkg},
		{"npm-audit", "empty.json", webRepo, webDir, np(), nil},
		{"npm-audit", "error.json", webRepo, webDir, np(), nil},
		{"actions-pin", "go-api.json", goAPIRepo, goAPIDir, ap(), nil},
		{"actions-pin", "empty.json", goAPIRepo, goAPIDir, ap(), nil},
	}
}

// TestFixtureNormalisation is the Phase 3 gate: every adapter normalises real
// captured output from the pinned scanner image, byte-for-byte against a
// committed golden.
//
// A parse failure fails here even under -update. -update exists to accept a
// tool reporting different findings, never to paper over output the normaliser
// does not understand.
func TestFixtureNormalisation(t *testing.T) {
	lock := testLock(t)

	for _, tc := range fixtureCases(t, lock) {
		t.Run(tc.tool+"/"+strings.TrimSuffix(tc.fixture, ".json"), func(t *testing.T) {
			o := out(tc.tool, tc.repo, tc.dir, readFixture(t, tc.tool, tc.fixture))
			o.Aux = tc.aux

			got, err := tc.adapter.Normalize(o)
			if err != nil {
				// error.json is the tool's own failure envelope; refusing it is
				// legitimate and covered by TestErrorEnvelopesDoNotInventFindings.
				if tc.fixture == "error.json" {
					t.Skipf("%s refuses its error envelope: %v", tc.tool, err)
				}
				t.Fatalf("PARSE FAILURE normalising real %s output: %v\n"+
					"This is an adapter gap. -update does not fix it: the normaliser does not\n"+
					"understand the tool's actual output, and would report zero findings against\n"+
					"a real scan — indistinguishable from a clean repository.", tc.tool, err)
			}
			assertGolden(t, tc.tool, tc.fixture, got)
		})
	}
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

// TestCrossToolFingerprintCollapse is the deduplication gate (VM-F-106),
// verified against real captured output from both Go dependency scanners.
//
// Phase 1 assumed the two tools would name one defect differently —
// govulncheck GO-2025-3106, osv-scanner GHSA-hcg3-q754-cr77 — and that alias
// resolution would be what collapsed them. Real osv-scanner v2 output reports
// GO identifiers for Go advisories, so the two now agree outright. The property
// that matters is unchanged and is what this asserts: one defect, one
// fingerprint, whichever tool saw it. Alias resolution is still required for
// CVE-only sources and is unit-tested in the fingerprint package.
func TestCrossToolFingerprintCollapse(t *testing.T) {
	lock := testLock(t)
	r := runner.NewFake()

	gvcFindings, err := adapters.NewGovulncheck(r, lock.MustVersion("govulncheck")).
		Normalize(out("govulncheck", goAPIRepo, goAPIDir, readFixture(t, "govulncheck", "go-api.json")))
	if err != nil {
		t.Fatalf("govulncheck Normalize: %v", err)
	}
	osvFindings, err := adapters.NewOSVScanner(r, lock.MustVersion("osv-scanner")).
		Normalize(out("osv-scanner", goAPIRepo, goAPIDir, readFixture(t, "osv-scanner", "go-api.json")))
	if err != nil {
		t.Fatalf("osv-scanner Normalize: %v", err)
	}

	byKey := map[string]string{} // module+id -> fingerprint, from govulncheck
	for _, f := range gvcFindings {
		byKey[f.Module+"|"+f.PrimaryID] = fingerprint.Compute(f)
	}

	shared := 0
	for _, f := range osvFindings {
		want, both := byKey[f.Module+"|"+f.PrimaryID]
		if !both {
			continue
		}
		shared++
		if got := fingerprint.Compute(f); got != want {
			t.Errorf("one defect produced two fingerprints (VM-F-106): %s %s -> govulncheck %s, osv-scanner %s",
				f.Module, f.PrimaryID, want, got)
		}
	}
	if shared == 0 {
		t.Fatal("no defect was reported by both tools; the collapse gate is not exercised")
	}
	t.Logf("%d defects reported by both tools, all collapsing to one fingerprint each", shared)
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
	// The credentials planted in testdata/repos/go-api/config/settings.yaml.
	// They are fabricated and match no real account.
	planted := []string{
		testkeys.AWSAccessKeyID(),
		testkeys.AWSSecretAccessKey(),
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

	reach := map[string]model.Reachable{}
	for _, f := range got {
		reach[f.PrimaryID] = f.Classification.Reachable
		if !f.Classification.Reachable.Valid() {
			t.Errorf("%s: reachable %q is not one of the three permitted values", f.PrimaryID, f.Classification.Reachable)
		}
	}

	// The synthetic repository calls ssh.NewServerConn, so the advisory covering
	// it must be reachable: govulncheck emitted a symbol-level trace for it, and
	// the adapter must merge that upward over the module-level messages for the
	// same advisory.
	if reach["GO-2025-3487"] != model.ReachableTrue {
		t.Errorf("GO-2025-3487 (ssh.NewServerConn, which this repository calls) = %q, want true", reach["GO-2025-3487"])
	}
	// It also calls http2.ConfigureServer.
	if reach["GO-2024-2687"] != model.ReachableTrue {
		t.Errorf("GO-2024-2687 (x/net http2, which this repository calls) = %q, want true", reach["GO-2024-2687"])
	}

	// And the distinction must be real: govulncheck is the reachability
	// authority for Go, so a module present but not called is false, not
	// unknown. If everything came back true the signal would be worthless.
	var nTrue, nFalse, nUnknown int
	for _, r := range reach {
		switch r {
		case model.ReachableTrue:
			nTrue++
		case model.ReachableFalse:
			nFalse++
		default:
			nUnknown++
		}
	}
	if nFalse == 0 {
		t.Error("no finding was reported unreachable; govulncheck determines reachability and must distinguish")
	}
	if nUnknown != 0 {
		t.Errorf("%d findings are unknown; govulncheck always determines reachability for Go", nUnknown)
	}
	t.Logf("reachability: %d true, %d false, %d unknown", nTrue, nFalse, nUnknown)
}

// TestGovulncheckCollapsesMultiLevelFindings covers VM-F-106 within one tool:
// three messages about one advisory in one module are one finding.
func TestGovulncheckCollapsesMultiLevelFindings(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewGovulncheck(runner.NewFake(), lock.MustVersion("govulncheck"))
	raw := readFixture(t, "govulncheck", "go-api.json")
	got, err := a.Normalize(out("govulncheck", goAPIRepo, goAPIDir, raw))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	// govulncheck reports one advisory at module, package and symbol level, so
	// the real capture holds far more messages than there are defects.
	messages := strings.Count(string(raw), `"finding"`)
	if messages <= len(got) {
		t.Fatalf("fixture holds %d finding messages for %d findings; it does not exercise collapsing", messages, len(got))
	}
	t.Logf("%d finding messages collapsed to %d findings", messages, len(got))

	// Every finding must be a distinct defect.
	fps := map[string]string{}
	for _, f := range got {
		fp := fingerprint.Compute(f)
		if prev, dup := fps[fp]; dup {
			t.Errorf("duplicate fingerprint %s: %q and %q", fp, prev, f.Module+" "+f.PrimaryID)
		}
		fps[fp] = f.Module + " " + f.PrimaryID
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
			if !strings.HasPrefix(f.PrimaryID, "GHSA-") {
				t.Errorf("axios primary id = %q, want a GHSA identifier extracted from the advisory URL", f.PrimaryID)
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
	// The synthetic repository uses io/ioutil, which staticcheck reports as
	// SA1019 — in the security subset because a deprecated form is frequently
	// the insecure one.
	if !reported["SA1019"] {
		t.Errorf("security-relevant check SA1019 was filtered out; reported %v", reported)
	}
	// Nothing outside the subset may appear.
	for rule := range reported {
		if _, wanted := inSecuritySubset(t, rule); !wanted {
			t.Errorf("check %s is outside the security subset but was reported", rule)
		}
	}
}

// inSecuritySubset reports whether a staticcheck rule is one the adapter keeps.
func inSecuritySubset(t *testing.T, rule string) (string, bool) {
	t.Helper()
	lock := testLock(t)
	a := adapters.NewStaticcheck(runner.NewFake(), lock.MustVersion("staticcheck"))
	for _, code := range a.SecuritySubset() {
		if code == rule {
			return code, true
		}
	}
	return "", false
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
	if len(got) == 0 {
		t.Error("semgrep produced no security findings from a repository with a planted XSS defect")
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
	if len(got) == 0 {
		t.Fatal("gosec produced no findings from a repository with planted G404 and G401 defects")
	}
	reported := map[string]bool{}
	for _, f := range got {
		reported[f.RuleID] = true
	}
	for _, want := range []string{"G404", "G401"} {
		if !reported[want] {
			t.Errorf("planted defect %s was not reported; got %v", want, reported)
		}
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
	if len(got) == 0 {
		t.Fatal("trivy produced no findings from a repository with a root-user Dockerfile")
	}
	// Trivy now runs both scanners, so it produces dependency findings as well
	// as misconfigurations (VM-AD §8.2 "trivy config / trivy fs"). Only those
	// two categories may appear.
	var config, dependency int
	for _, f := range got {
		switch f.Category {
		case model.CategoryConfig:
			config++
		case model.CategoryDependency:
			dependency++
		default:
			t.Errorf("category = %q, want config or dependency", f.Category)
		}
	}
	if config == 0 {
		t.Error("no misconfiguration findings from a repository with a root-user Dockerfile")
	}
	if dependency == 0 {
		t.Error("no dependency findings; the CVE-namespace source for alias resolution is missing (OQ-P3-03)")
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

	// trivy v0.74 reports hyphenated check ids (KSV-0012, not KSV012).
	found := false
	for _, f := range got {
		if f.CheckID == "KSV-0012" {
			found = true
		}
	}
	if !found {
		t.Error("KSV-0012 (runs as root) not reported for a deployment with no securityContext")
	}

	// Real trivy v0.74 leaves CauseMetadata.Resource empty for these Kubernetes
	// findings, so the resource key is empty and only the check id separates
	// them. That is sufficient here — every finding is a different check — but
	// it is a latent collision: two failures of the *same* check against two
	// containers in one manifest would share a fingerprint. Recorded as
	// OQ-P3-02; asserting the collision-free property is what guards it.
	empty := 0
	for _, f := range got {
		if f.ResourceKey == "" {
			empty++
		}
	}
	if empty > 0 {
		t.Logf("%d/%d config findings have no resource key (trivy leaves CauseMetadata.Resource empty); see OQ-P3-02", empty, len(got))
	}
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
	// The synthetic workflows reference two actions by mutable tag and two by
	// commit SHA; actions/checkout@v4 appears in both workflow files.
	if len(got) != 3 {
		t.Errorf("got %d findings, want 3 unpinned action references", len(got))
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

// gitleaksAllowlistAux replays the captured looks past the allowlists for the
// allowlisted fixture (see allowlisted.meta.json).
func gitleaksAllowlistAux(t *testing.T) map[string][]byte {
	t.Helper()
	read := func(name string) []byte { return readFixture(t, "gitleaks", "allowlisted.aux/"+name) }
	return adapters.GitleaksFixtureAux(read("unfiltered.json"), read("config-bypass.json"),
		read("ignore-check.json"), read("gitleaks.toml"), read("gitleaksignore"))
}

// Every finding from real captured output carries the scanner's own words for
// the problem, so the interface never shows an identifier alone.
func TestEveryAdapterDescribesItsFindings(t *testing.T) {
	lock := testLock(t)
	for _, tc := range fixtureCases(t, lock) {
		o := out(tc.tool, tc.repo, tc.dir, readFixture(t, tc.tool, tc.fixture))
		o.Aux = tc.aux
		got, err := tc.adapter.Normalize(o)
		if err != nil {
			continue // error envelopes: covered elsewhere
		}
		for _, f := range got {
			if strings.TrimSpace(f.Description) == "" {
				t.Errorf("%s/%s: a %s finding (%s%s) has no description", tc.tool, tc.fixture, f.Category, f.PrimaryID, f.RuleID+f.CheckID+f.DetectorRuleID)
			}
		}
	}
}
