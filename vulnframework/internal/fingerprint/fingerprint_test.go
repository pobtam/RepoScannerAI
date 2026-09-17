package fingerprint_test

import (
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
)

// depFinding is the running example from VM-AD §4.1.
func depFinding() model.RawFinding {
	return model.RawFinding{
		Repo:        "org/wanaware-api",
		Category:    model.CategoryDependency,
		PrimaryID:   "GO-2025-3106",
		Aliases:     []string{"CVE-2025-22869", "GHSA-hcg3-q754-cr77"},
		Module:      "golang.org/x/crypto",
		ModuleMajor: "v0",
	}
}

// codeFinding is what a real code-analysis tool produces.
//
// Package and Function are deliberately ABSENT. This fixture used to set both,
// and the Producer-Coverage Audit established that no pinned tool reports
// either — so every assertion made against it, including the golden value, was
// a statement about input the system never sees. A fixture that is more
// informative than its producer is the same defect as a fake that is kinder
// than production.
func codeFinding() model.RawFinding {
	return model.RawFinding{
		Repo:     "org/wanaware-api",
		Category: model.CategoryCode,
		Tool:     "gosec",
		RuleID:   "G401",
		File:     "internal/crypto/hash.go",
		Line:     42,
	}
}

func secretFinding() model.RawFinding {
	return model.RawFinding{
		Repo:           "org/wanaware-api",
		Category:       model.CategorySecret,
		DetectorRuleID: "aws-access-token",
		File:           "config/settings.yaml",
		Line:           17,
		CredentialType: "aws_access_key_id",
	}
}

func configFinding() model.RawFinding {
	return model.RawFinding{
		Repo:        "org/wanaware-api",
		Category:    model.CategoryConfig,
		CheckID:     "DS002",
		File:        "deploy/Dockerfile",
		ResourceKey: "USER",
	}
}

// --- Shape and determinism -------------------------------------------------

func TestComputeIsDeterministicAndWellFormed(t *testing.T) {
	for _, f := range []model.RawFinding{depFinding(), codeFinding(), secretFinding(), configFinding()} {
		fp := fingerprint.Compute(f)
		if len(fp) != fingerprint.Length {
			t.Errorf("category %s: fingerprint %q has length %d, want %d", f.Category, fp, len(fp), fingerprint.Length)
		}
		if strings.ToLower(fp) != fp {
			t.Errorf("category %s: fingerprint %q is not lowercase hex", f.Category, fp)
		}
		for i := 0; i < 100; i++ {
			if got := fingerprint.Compute(f); got != fp {
				t.Fatalf("category %s: fingerprint not deterministic: %q then %q", f.Category, fp, got)
			}
		}
	}
}

func TestDistinctCategoriesDoNotCollide(t *testing.T) {
	seen := map[string]model.Category{}
	for _, f := range []model.RawFinding{depFinding(), codeFinding(), secretFinding(), configFinding()} {
		fp := fingerprint.Compute(f)
		if prev, ok := seen[fp]; ok {
			t.Fatalf("categories %s and %s collide on fingerprint %s", prev, f.Category, fp)
		}
		seen[fp] = f.Category
	}
}

// --- Gate: stable across reformatting (VM-F-102, VM-ADR-04) ----------------

// TestStableAcrossReformatting is half the Phase 0 gate. Every mutation here is
// a change a reformat, a re-clone, or a different worker can produce without the
// underlying defect changing. Any of them altering the fingerprint would
// resurrect the finding, destroying delta reporting and MTTR and producing a
// duplicate ticket.
func TestStableAcrossReformatting(t *testing.T) {
	tests := []struct {
		name string
		base model.RawFinding
		mut  func(model.RawFinding) model.RawFinding
	}{
		{
			name: "code: line number moves",
			base: codeFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.Line = 9137; return f },
		},
		{
			name: "code: rule id case differs between tool versions",
			base: codeFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.RuleID = "g401"; return f },
		},
		{
			name: "code: tool name case differs",
			base: codeFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.Tool = "GoSec"; return f },
		},
		{
			name: "code: surrounding whitespace from a scanner's text output",
			base: codeFinding(),
			mut: func(f model.RawFinding) model.RawFinding {
				f.Tool, f.RuleID, f.Package, f.Function = " gosec ", "G401\n", "  github.com/org/wanaware-api/internal/crypto ", "\tHashPassword "
				return f
			},
		},
		{
			name: "dependency: patch bump within the vulnerable range",
			base: depFinding(),
			mut: func(f model.RawFinding) model.RawFinding {
				f.Versions = model.Versions{Current: "v0.35.1", Fixed: "v0.36.0"}
				return f
			},
		},
		{
			name: "dependency: advisory reported with a different alias ordering",
			base: depFinding(),
			mut: func(f model.RawFinding) model.RawFinding {
				f.Aliases = []string{"GHSA-hcg3-q754-cr77", "CVE-2025-22869"}
				return f
			},
		},
		{
			name: "dependency: advisory id lowercased by a tool",
			base: depFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.PrimaryID = "go-2025-3106"; return f },
		},
		{
			name: "dependency: classification changes after enrichment",
			base: depFinding(),
			mut: func(f model.RawFinding) model.RawFinding {
				f.Classification = model.Classification{
					Severity: model.SeverityCritical, CVSS: 9.8, KEV: true,
					Reachable: model.ReachableTrue, DepClass: model.DepProduction,
				}
				return f
			},
		},
		{
			name: "secret: credential moves down the file",
			base: secretFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.Line = 204; return f },
		},
		{
			name: "secret: path reported with a leading ./",
			base: secretFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.File = "./config/settings.yaml"; return f },
		},
		{
			name: "secret: path reported with windows separators",
			base: secretFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.File = `config\settings.yaml`; return f },
		},
		{
			name: "secret: path reported with duplicated separators",
			base: secretFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.File = "config//settings.yaml"; return f },
		},
		{
			name: "config: resource key case differs",
			base: configFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.ResourceKey = "user"; return f },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := fingerprint.Compute(tc.base)
			got := fingerprint.Compute(tc.mut(tc.base))
			if got != want {
				t.Errorf("fingerprint changed under a reformatting-class mutation:\n  before %s\n  after  %s", want, got)
			}
		})
	}
}

// TestRepoRootPrefixDoesNotAffectIdentity covers the clone-directory case: the
// same repository checked out at a different absolute path must not produce a
// different finding.
func TestRepoRootPrefixDoesNotAffectIdentity(t *testing.T) {
	base := secretFinding()
	relocated := secretFinding()
	relocated.File = fingerprint.StripRepoRoot("/tmp/scan-7f21a/clone/config/settings.yaml", "/tmp/scan-7f21a/clone")

	if got, want := fingerprint.Compute(relocated), fingerprint.Compute(base); got != want {
		t.Errorf("clone path leaked into the fingerprint: %s != %s (file=%q)", got, want, relocated.File)
	}
}

// --- Gate: unstable across genuine identity change --------------------------

// TestUnstableAcrossIdentityChange is the other half of the gate. Each mutation
// is a genuinely different defect and must land on a different fingerprint;
// collapsing any of them would silently merge two findings into one record.
func TestUnstableAcrossIdentityChange(t *testing.T) {
	tests := []struct {
		name string
		base model.RawFinding
		mut  func(model.RawFinding) model.RawFinding
	}{
		{
			name: "different repository (VM-F-103)",
			base: depFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.Repo = "org/wanaware-web"; return f },
		},
		{
			name: "different advisory",
			base: depFinding(),
			mut: func(f model.RawFinding) model.RawFinding {
				f.PrimaryID, f.Aliases = "GO-2025-9999", nil
				return f
			},
		},
		{
			name: "different module",
			base: depFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.Module = "golang.org/x/net"; return f },
		},
		{
			name: "different major version of the same module",
			base: depFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.ModuleMajor = "v2"; return f },
		},
		{
			name: "different rule from the same tool",
			base: codeFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.RuleID = "G404"; return f },
		},
		{
			name: "same rule id from a different tool",
			base: codeFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.Tool = "staticcheck"; return f },
		},
		{
			name: "different category",
			base: codeFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.Category = model.CategoryConfig; return f },
		},
		{
			name: "secret in a different file",
			base: secretFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.File = "config/production.yaml"; return f },
		},
		{
			name: "different secret detector in the same file",
			base: secretFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.DetectorRuleID = "github-pat"; return f },
		},
		{
			name: "config: different resource key in the same file",
			base: configFinding(),
			mut:  func(f model.RawFinding) model.RawFinding { f.ResourceKey = "HEALTHCHECK"; return f },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := fingerprint.Compute(tc.base)
			after := fingerprint.Compute(tc.mut(tc.base))
			if before == after {
				t.Errorf("two genuinely distinct defects collapsed to one fingerprint %s", before)
			}
		})
	}
}

// --- Gate: alias resolution collapses cross-tool duplicates (VM-F-106) -----

// TestAliasResolutionCollapsesCrossToolReports is the deduplication gate.
// govulncheck reports GO-2025-3106 and osv-scanner reports CVE-2025-22869 for
// one defect; without alias resolution these produce two fingerprints and
// VM-F-106 fails.
func TestAliasResolutionCollapsesCrossToolReports(t *testing.T) {
	govulncheck := model.RawFinding{
		Repo: "org/wanaware-api", Category: model.CategoryDependency,
		PrimaryID: "GO-2025-3106",
		Aliases:   []string{"CVE-2025-22869", "GHSA-hcg3-q754-cr77"},
		Module:    "golang.org/x/crypto", ModuleMajor: "v0",
		Tool: "govulncheck",
	}
	osvScanner := model.RawFinding{
		Repo: "org/wanaware-api", Category: model.CategoryDependency,
		PrimaryID: "CVE-2025-22869",
		Aliases:   []string{"GHSA-hcg3-q754-cr77", "GO-2025-3106"},
		Module:    "golang.org/x/crypto", ModuleMajor: "v0",
		Tool: "osv-scanner",
	}
	ghsaOnly := model.RawFinding{
		Repo: "org/wanaware-api", Category: model.CategoryDependency,
		PrimaryID: "GHSA-hcg3-q754-cr77",
		Aliases:   []string{"GO-2025-3106", "CVE-2025-22869"},
		Module:    "golang.org/x/crypto", ModuleMajor: "v0",
		Tool: "trivy",
	}

	a, b, c := fingerprint.Compute(govulncheck), fingerprint.Compute(osvScanner), fingerprint.Compute(ghsaOnly)
	if a != b || b != c {
		t.Errorf("one defect produced multiple fingerprints, deduplication (VM-F-106) fails:\n  govulncheck %s\n  osv-scanner %s\n  trivy       %s", a, b, c)
	}
}

func TestResolveAliasPrecedence(t *testing.T) {
	tests := []struct {
		name    string
		primary string
		aliases []string
		want    string
	}{
		{"go id wins over all", "CVE-2025-22869", []string{"GHSA-hcg3-q754-cr77", "GO-2025-3106"}, "GO-2025-3106"},
		{"ghsa wins over cve", "CVE-2025-22869", []string{"GHSA-hcg3-q754-cr77"}, "GHSA-HCG3-Q754-CR77"},
		{"cve wins over other osv", "PYSEC-2025-1", []string{"CVE-2025-22869"}, "CVE-2025-22869"},
		{"osv used when nothing better", "PYSEC-2025-1", nil, "PYSEC-2025-1"},
		{"tool rule id is the last resort", "my-tool-rule", nil, "MY-TOOL-RULE"},
		{"uppercased", "go-2025-3106", nil, "GO-2025-3106"},
		{"ties broken lexicographically not by input order", "CVE-2025-9999", []string{"CVE-2025-1111"}, "CVE-2025-1111"},
		{"empty aliases tolerated", "GO-2025-3106", []string{"", "  "}, "GO-2025-3106"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := fingerprint.ResolveAlias(tc.primary, tc.aliases); got != tc.want {
				t.Errorf("ResolveAlias(%q, %v) = %q, want %q", tc.primary, tc.aliases, got, tc.want)
			}
		})
	}
}

// TestAliasResolutionIsOrderIndependent guards the property directly: whichever
// order a tool lists the alias set in, the canonical identifier is the same.
func TestAliasResolutionIsOrderIndependent(t *testing.T) {
	ids := []string{"CVE-2025-22869", "GHSA-hcg3-q754-cr77", "GO-2025-3106"}
	want := fingerprint.ResolveAlias(ids[0], ids[1:])
	for i := range ids {
		rotated := append(append([]string{}, ids[i:]...), ids[:i]...)
		if got := fingerprint.ResolveAlias(rotated[0], rotated[1:]); got != want {
			t.Errorf("alias order changed the canonical id: %v gave %q, want %q", rotated, got, want)
		}
	}
}

// --- Line numbers are structurally excluded (VM-F-102) ---------------------

// TestLineNeverEntersTheHash asserts the property exhaustively rather than by
// example: for every category, sweeping the line number must never move the
// fingerprint.
func TestLineNeverEntersTheHash(t *testing.T) {
	for _, base := range []model.RawFinding{depFinding(), codeFinding(), secretFinding(), configFinding()} {
		want := fingerprint.Compute(base)
		for _, line := range []int{0, 1, 2, 17, 42, 1000, 999999, -1} {
			f := base
			f.Line = line
			if got := fingerprint.Compute(f); got != want {
				t.Errorf("category %s: line %d changed the fingerprint (%s != %s)", base.Category, line, got, want)
			}
		}
	}
}

// --- Fallback behaviour -----------------------------------------------------

func TestCodeFindingFallsBackToFileWithoutEnclosingFunction(t *testing.T) {
	f := codeFinding()
	f.Function = ""

	if got, want := fingerprint.Location(f), "internal/crypto/hash.go"; got != want {
		t.Errorf("Location fallback = %q, want %q", got, want)
	}
	// With no enclosing function the file path is load-bearing, so a move must
	// change identity — the opposite of the function-anchored case.
	moved := f
	moved.File = "internal/crypto/hashing_v2.go"
	if fingerprint.Compute(moved) == fingerprint.Compute(f) {
		t.Error("with no enclosing function, a file move must change the fingerprint")
	}
}

// --- Validation -------------------------------------------------------------

func TestValidateRejectsMissingFingerprintInputs(t *testing.T) {
	tests := []struct {
		name string
		f    model.RawFinding
	}{
		{"empty repo", model.RawFinding{Category: model.CategoryDependency, PrimaryID: "GO-1", Module: "m"}},
		{"invalid category", model.RawFinding{Repo: "r", Category: "made-up", PrimaryID: "GO-1"}},
		{"dependency without module", model.RawFinding{Repo: "r", Category: model.CategoryDependency, PrimaryID: "GO-1"}},
		{"dependency without identity", model.RawFinding{Repo: "r", Category: model.CategoryDependency, Module: "m"}},
		{"code without package or file", model.RawFinding{Repo: "r", Category: model.CategoryCode, Tool: "gosec", RuleID: "G1"}},
		{"code without identity", model.RawFinding{Repo: "r", Category: model.CategoryCode, Package: "p", Function: "F"}},
		{"secret without file", model.RawFinding{Repo: "r", Category: model.CategorySecret, DetectorRuleID: "d"}},
		{"config without file", model.RawFinding{Repo: "r", Category: model.CategoryConfig, CheckID: "c"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := fingerprint.Validate(tc.f); err == nil {
				t.Error("Validate accepted a finding missing a fingerprint input")
			}
		})
	}
}

func TestValidateAcceptsWellFormedFindings(t *testing.T) {
	for _, f := range []model.RawFinding{depFinding(), codeFinding(), secretFinding(), configFinding()} {
		if err := fingerprint.Validate(f); err != nil {
			t.Errorf("category %s: Validate rejected a well-formed finding: %v", f.Category, err)
		}
	}
}

func TestStripRepoRoot(t *testing.T) {
	tests := []struct{ path, root, want string }{
		{"/tmp/clone/internal/a.go", "/tmp/clone", "internal/a.go"},
		{"/tmp/clone/internal/a.go", "/tmp/clone/", "internal/a.go"},
		{"./internal/a.go", "", "internal/a.go"},
		{`C:\work\clone\internal\a.go`, `C:\work\clone`, "internal/a.go"},
		{"internal/a.go", "/other/root", "internal/a.go"},
	}
	for _, tc := range tests {
		if got := fingerprint.StripRepoRoot(tc.path, tc.root); got != tc.want {
			t.Errorf("StripRepoRoot(%q, %q) = %q, want %q", tc.path, tc.root, got, tc.want)
		}
	}
}

// --- Regression lock --------------------------------------------------------

// TestFingerprintGoldenValues locks the algorithm's output. The fingerprint is
// the primary key of the findings store: if these change, every finding in
// every deployment becomes a new finding, every ticket is orphaned and MTTR
// resets. A change here is only legitimate alongside a bumped Version and a
// migration (VM-AD §5).
func TestFingerprintGoldenValues(t *testing.T) {
	golden := map[string]struct {
		f    model.RawFinding
		want string
	}{
		// Independently verified against a from-scratch implementation of the
		// VM-AD §5 construction:
		//   sha256("v1" | repo | category | identity | location)[:16], \x1f-joined.
		"dependency": {depFinding(), "2b3f437df7c03666"},
		// Changed at OQ-AUDIT-02, and deliberately WITHOUT a Version bump or a
		// migration.
		//
		// The old value was computed from a fixture that set Package and
		// Function. No pinned tool reports either, so no fingerprint this
		// system has ever computed in production took the symbol branch — every
		// real code finding was already fingerprinted from its file path. The
		// algorithm's output for every PRODUCIBLE input is unchanged, so there
		// is nothing stored to migrate.
		//
		// Independently recomputed from scratch before being locked, as the
		// Phase 0 values were:
		//   sha256("v1" | "org/wanaware-api" | "code" | "gosec:g401" |
		//          "internal/crypto/hash.go")[:16]
		"code":   {codeFinding(), "dd152167d193b9ff"},
		"secret": {secretFinding(), "b863317fc8fa88eb"},
		"config": {configFinding(), "ebdccd46822d729b"},
	}
	for name, tc := range golden {
		t.Run(name, func(t *testing.T) {
			if got := fingerprint.Compute(tc.f); got != tc.want {
				t.Errorf("fingerprint algorithm changed for %s: got %s, want %s\n"+
					"If this is intended, bump fingerprint.Version and write a migration (VM-AD §5).", name, got, tc.want)
			}
		})
	}
}

// --- What file granularity gives up (OQ-AUDIT-02) ---------------------------
//
// Three cases used to live in the tables above, asserting symbol-level
// behaviour. They passed because each one SET Function or Package, and the
// Producer-Coverage Audit then established that no pinned tool ever does — so
// all three were statements about a branch no real input could reach.
//
// They are restated here as what the decision gives up, rather than deleted.
// A capability that was never real should not vanish from the record: the next
// person to want per-function granularity needs to find this, not rediscover
// it.

// TestFileGranularitySplitsAFindingWhenItsFileIsRenamed is the first loss.
//
// At symbol granularity, moving a function to another file in the same package
// kept one finding. At file granularity it becomes a new one: the old
// fingerprint stops being observed and verifies, and a new fingerprint appears
// with a fresh detection date and a fresh SLA clock.
//
// The consequence is an SLA reset on a refactor, and it is worth knowing
// before someone reports it as a bug.
func TestFileGranularitySplitsAFindingWhenItsFileIsRenamed(t *testing.T) {
	before := codeFinding()
	after := codeFinding()
	after.File = "internal/crypto/hashing_v2.go"

	if fingerprint.Compute(before) == fingerprint.Compute(after) {
		t.Fatal("the fingerprint survived a file rename, which requires symbol granularity that no " +
			"pinned tool supplies the input for")
	}
	// And the granularity says so, so a consumer can explain it.
	if !fingerprint.GranularityOf(before).MayHideResidual() {
		t.Error("file granularity does not declare its imprecision")
	}
}

// TestFileGranularityMergesTwoOccurrencesOfOneRule is the second and third
// loss together, and the one that matters for correctness rather than for
// bookkeeping.
//
// Two occurrences of one rule in one file — in different functions, or in
// different packages that happen to share a file path — are ONE finding. Fix
// the reported one and leave the other, and the finding can verify while a
// live twin remains.
//
// That is why MayHideResidual exists: the risk is not eliminated by this
// decision, it is made answerable.
func TestFileGranularityMergesTwoOccurrencesOfOneRule(t *testing.T) {
	first := codeFinding()
	second := codeFinding()
	second.Function = "ComparePassword"
	second.Line = 412

	if fingerprint.Compute(first) != fingerprint.Compute(second) {
		t.Fatal("two occurrences of one rule in one file produced different fingerprints; that is " +
			"symbol granularity, and no tool supplies the symbol")
	}
	if !fingerprint.GranularityOf(first).MayHideResidual() {
		t.Fatal("the merge is not declared as possibly hiding a residual occurrence, so a " +
			"verification of this finding could not know to warn that a twin may remain")
	}
}
