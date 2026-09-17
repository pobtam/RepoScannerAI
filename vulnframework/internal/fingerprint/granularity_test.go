package fingerprint_test

import (
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
)

// OQ-AUDIT-02: code findings are fingerprinted at FILE granularity, and the
// consequence is made visible.
//
// The Producer-Coverage Audit found that no pinned code-analysis tool reports
// the enclosing symbol — gosec, staticcheck and semgrep all emit file, line
// and column and nothing else. The fingerprint's `Package#Function` branch was
// therefore unreachable, and deriving a function name from a code snippet
// would be a guess feeding a fingerprint, which is the one place this system
// refuses to guess.
//
// So the branch is deleted and file granularity is accepted deliberately. What
// must not be accepted silently is its consequence: two occurrences of one
// rule in one file are ONE finding, so fixing one and leaving the other
// verifies the finding while a live twin remains. That is
// absence-is-not-resolution at fingerprint granularity, and it has to be
// visible.

func codeAt(file string, line int, rule string) model.RawFinding {
	return model.RawFinding{
		Repo: "org/api", Category: model.CategoryCode,
		RuleID: rule, Tool: "gosec", ToolVersion: "v2.22.9",
		File: file, Line: line,
		Classification: model.Classification{
			Severity: model.SeverityHigh, Reachable: model.ReachableUnknown,
			DepClass: model.DepNotApplicable,
		},
	}
}

// TestCodeFindingsAreFileGranularByDecision states the chosen behaviour so it
// cannot drift back into an accident.
func TestCodeFindingsAreFileGranularByDecision(t *testing.T) {
	first := codeAt("internal/handler/auth.go", 12, "G404")
	second := codeAt("internal/handler/auth.go", 88, "G404")

	if fingerprint.Compute(first) != fingerprint.Compute(second) {
		t.Fatal("two occurrences of one rule in one file fingerprint differently. That is " +
			"symbol-level granularity, which no pinned tool supplies the input for — so it can only " +
			"have come from a fabricated component")
	}

	// A different rule in the same file is a different finding.
	other := codeAt("internal/handler/auth.go", 12, "G401")
	if fingerprint.Compute(first) == fingerprint.Compute(other) {
		t.Error("two different rules in one file collapsed to one fingerprint")
	}
	// The same rule in a different file is a different finding.
	elsewhere := codeAt("internal/token/token.go", 12, "G404")
	if fingerprint.Compute(first) == fingerprint.Compute(elsewhere) {
		t.Error("the same rule in two files collapsed to one fingerprint")
	}
}

// TestFileGranularityIsDeclaredNotInferred is what makes the decision
// auditable. A consumer has to be able to ask the fingerprint what granularity
// it used, or "did this verification hide a twin" is unanswerable.
func TestFileGranularityIsDeclaredNotInferred(t *testing.T) {
	code := codeAt("internal/handler/auth.go", 12, "G404")
	g := fingerprint.GranularityOf(code)

	if g != fingerprint.GranularityFile {
		t.Errorf("granularity = %q for a code finding, want %q", g, fingerprint.GranularityFile)
	}
	if !g.MayHideResidual() {
		t.Error("file granularity does not report that it may hide a residual occurrence; a " +
			"verification at this granularity can leave a live twin, and nothing downstream could " +
			"know to say so")
	}

	// A dependency finding is module-granular and hides nothing: the module
	// either resolves to a fixed version or it does not.
	dep := model.RawFinding{
		Repo: "org/api", Category: model.CategoryDependency,
		PrimaryID: "GO-2025-3106", Module: "golang.org/x/crypto", ModuleMajor: "v0",
		Tool: "govulncheck", ToolVersion: "v1.8.0",
	}
	if dg := fingerprint.GranularityOf(dep); dg.MayHideResidual() {
		t.Errorf("dependency granularity %q claims it may hide a residual occurrence; a module "+
			"either resolves to the fixed version or it does not", dg)
	}

	// A secret is file-granular too, and for the same reason: two credentials
	// in one file are one finding, and rotating one leaves the other live.
	secret := model.RawFinding{
		Repo: "org/api", Category: model.CategorySecret,
		DetectorRuleID: "aws-access-token", Tool: "gitleaks", ToolVersion: "v8.30.1",
		File: "config/settings.yaml", Line: 17, CredentialType: "aws-access-token",
	}
	if sg := fingerprint.GranularityOf(secret); !sg.MayHideResidual() {
		t.Error("secret granularity does not report that it may hide a residual occurrence; two " +
			"credentials in one file are one finding, and rotating one leaves the other live")
	}
}

// TestTheDeadBranchIsGone is the deletion itself. A branch no input can reach
// is a claim about behaviour nobody can observe, and it invited exactly the
// fabricated-component fix the decision rejects.
func TestTheDeadBranchIsGone(t *testing.T) {
	// A finding carrying a function and package — which no tool produces, but
	// which a future adapter could set by mistake. The fingerprint must ignore
	// them rather than silently changing granularity for some findings and not
	// others, which would make two tools' reports of one defect collide or
	// not depending on which tool saw it.
	withSymbol := codeAt("internal/handler/auth.go", 12, "G404")
	withSymbol.Package = "github.com/org/api/internal/handler"
	withSymbol.Function = "NewSessionID"

	plain := codeAt("internal/handler/auth.go", 12, "G404")

	if fingerprint.Compute(withSymbol) != fingerprint.Compute(plain) {
		t.Error("a finding carrying a symbol fingerprints differently from one without. Granularity " +
			"would then depend on which tool observed the defect, so two tools reporting the same " +
			"finding would fail to merge (VM-F-106)")
	}
	if !strings.Contains(fingerprint.Location(plain), "auth.go") {
		t.Errorf("the code location is not the file: %q", fingerprint.Location(plain))
	}
}
