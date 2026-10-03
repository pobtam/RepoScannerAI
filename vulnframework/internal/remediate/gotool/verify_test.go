package gotool_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/remediate"
	"github.com/wanaware/vulnframework/internal/remediate/gotool"
)

// Verify is the only thing standing between "a change" and "a fix". Everything
// in this file is about a way it could report the second while having
// established only the first.

const (
	ourFinding   = "GHSA-fixture-0001"
	otherFinding = "GHSA-fixture-0002"
)

func TestVerifyPassesOnAGoodChange(t *testing.T) {
	dir := fixture(t, "clean")
	rescan := gotool.NewFakeRescan()
	tc := toolchainFor(t, dir, rescan)

	v, err := tc.Verify(context.Background(), dir, nil, []string{"govulncheck"}, []string{ourFinding})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !v.OK() {
		t.Fatalf("a clean repository with a clean re-scan did not verify: %+v\n%s", v, v.Output)
	}
}

// TestAFailedScannerIsNotACleanRescan is the most important assertion in this
// package.
//
// A scanner that could not be executed reports nothing. A repository whose
// vulnerability is genuinely gone also reports nothing. If the gate cannot
// tell those apart, then every repository where the scanner is missing,
// misconfigured or crashing verifies clean — and the system issues pull
// requests certifying fixes it never checked.
//
// Absence is not resolution (VM-F-205). This is that rule at the point where
// breaking it would be most expensive.
func TestAFailedScannerIsNotACleanRescan(t *testing.T) {
	dir := fixture(t, "clean")
	rescan := gotool.NewFakeRescan().
		ToolFails("govulncheck", "executable file not found in $PATH")
	tc := toolchainFor(t, dir, rescan)

	v, err := tc.Verify(context.Background(), dir, nil, []string{"govulncheck"}, []string{ourFinding})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if v.RescanClean {
		t.Fatal("a re-scan whose only scanner could not run was reported CLEAN. " +
			"Nothing was observed, and nothing observed is exactly what a fixed repository looks like")
	}
	if v.OK() {
		t.Fatal("the verification passed overall despite an incomplete re-scan")
	}
	if !strings.Contains(v.Output, "govulncheck") {
		t.Errorf("the output does not name the tool that failed, so an operator learns that "+
			"verification failed and not why:\n%s", v.Output)
	}
	if !strings.Contains(v.Output, "INCOMPLETE") {
		t.Errorf("the output does not say the re-scan was incomplete:\n%s", v.Output)
	}
}

// TestOneFailedScannerAmongSeveralStillFailsTheGate is the masking case.
//
// With three tools and one of them broken, the other two produce a confident
// clean answer. The finding the broken one reports is invisible, and the two
// that ran would cover for it.
func TestOneFailedScannerAmongSeveralStillFailsTheGate(t *testing.T) {
	dir := fixture(t, "clean")
	rescan := gotool.NewFakeRescan().ToolFails("gosec", "exit status 2: panic")
	tc := toolchainFor(t, dir, rescan)

	v, err := tc.Verify(context.Background(), dir, nil,
		[]string{"govulncheck", "gosec", "osv-scanner"}, []string{ourFinding})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.RescanClean {
		t.Fatal("two working scanners covered for a third that could not run. A finding only the " +
			"broken tool reports is invisible, and the gate passed anyway")
	}
}

// TestAGroupThatNamesNoToolsDoesNotVerifyClean closes the degenerate case.
//
// Re-scanning with no tools observes nothing at all. Reporting that as clean
// would make any group whose tool list was lost verify successfully.
func TestAGroupThatNamesNoToolsDoesNotVerifyClean(t *testing.T) {
	dir := fixture(t, "clean")
	tc := toolchainFor(t, dir, gotool.NewFakeRescan())

	v, err := tc.Verify(context.Background(), dir, nil, nil, []string{ourFinding})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.RescanClean {
		t.Fatal("a re-scan that ran no tools at all was reported clean")
	}
}

// TestVerifyFailsWhenTheGroupsFindingIsStillReported is the ordinary failure:
// the change built and did not fix anything.
func TestVerifyFailsWhenTheGroupsFindingIsStillReported(t *testing.T) {
	dir := fixture(t, "clean")
	rescan := gotool.NewFakeRescan().StillReports(ourFinding)
	tc := toolchainFor(t, dir, rescan)

	v, err := tc.Verify(context.Background(), dir, nil, []string{"govulncheck"}, []string{ourFinding})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.RescanClean {
		t.Fatal("the advisory is still reported and the re-scan was called clean")
	}
	if !contains(v.Remaining, ourFinding) {
		t.Fatalf("Remaining = %v, which does not name the advisory. A failure that does not name "+
			"the finding tells a reader only that something went wrong", v.Remaining)
	}
	if got := v.FailureReason(); got != "FIX_INEFFECTIVE" {
		t.Errorf("FailureReason = %q. A change that built and tested but did not close the defect "+
			"is not a build or test failure, and it must not be NO_UPSTREAM_FIX either — that would "+
			"pause the SLA clock on something a human could fix today (VM-NF-304)", got)
	}
}

// TestTheRescanIsScopedToTheGroup is OQ-AUDIT-06, which this build has already
// been bitten by once.
//
// A re-scan sees the WHOLE repository. A gate that failed on anything it found
// would make a repository with two vulnerable modules unremediable: the first
// group's verification would fail on the second group's finding, for ever,
// and the second group's on the first.
func TestTheRescanIsScopedToTheGroup(t *testing.T) {
	dir := fixture(t, "clean")
	rescan := gotool.NewFakeRescan().StillReports(otherFinding)
	tc := toolchainFor(t, dir, rescan)

	v, err := tc.Verify(context.Background(), dir, nil, []string{"govulncheck"}, []string{ourFinding})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !v.RescanClean {
		t.Fatalf("another group's finding failed this group's verification. A repository with two "+
			"vulnerable modules is then unremediable, each group blocking the other for ever "+
			"(OQ-AUDIT-06). Remaining = %v", v.Remaining)
	}
}

// TestScopingDoesNotHideThisGroupsOwnFinding is the companion that stops the
// scoping above from becoming a way to pass everything.
func TestScopingDoesNotHideThisGroupsOwnFinding(t *testing.T) {
	dir := fixture(t, "clean")
	rescan := gotool.NewFakeRescan().StillReports(ourFinding, otherFinding)
	tc := toolchainFor(t, dir, rescan)

	v, err := tc.Verify(context.Background(), dir, nil, []string{"govulncheck"}, []string{ourFinding})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.RescanClean {
		t.Fatal("scoping to the group hid the group's own finding")
	}
	if contains(v.Remaining, otherFinding) {
		t.Errorf("Remaining = %v reports another group's finding as this group's failure", v.Remaining)
	}
}

// TestTheRescanMatchesAnyNameTheGroupExpects keeps the two halves in step.
//
// remediate.Expect builds the expectation from the advisory id, the rule id,
// the fingerprint and every alias, because scanners report findings under
// different names. If the gate only matched one of those, every finding
// reported under another name would verify clean without anything having been
// checked.
func TestTheRescanMatchesAnyNameTheGroupExpects(t *testing.T) {
	dir := fixture(t, "clean")
	for _, name := range []string{
		"GHSA-fixture-0001",
		"CVE-2024-00001",
		"G402",
		"a3f9c1d2e4b50617a3f9c1d2e4b50617a3f9c1d2e4b50617a3f9c1d2e4b50617",
	} {
		t.Run(name, func(t *testing.T) {
			rescan := gotool.NewFakeRescan().StillReports(name)
			tc := toolchainFor(t, dir, rescan)

			v, err := tc.Verify(context.Background(), dir, nil, []string{"govulncheck"},
				[]string{"GHSA-fixture-0001", "CVE-2024-00001", "G402",
					"a3f9c1d2e4b50617a3f9c1d2e4b50617a3f9c1d2e4b50617a3f9c1d2e4b50617"})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if v.RescanClean {
				t.Fatalf("a finding still reported under %q verified clean. The group expects that "+
					"name, so the gate must recognise it", name)
			}
		})
	}
}

// TestARescannerThatCannotLookIsAnError separates the two failure kinds.
//
// A rescanner that cannot reach the tree at all is an operational failure of
// the worker, not a fact about the repository, and it must propagate rather
// than become a verification result.
func TestARescannerThatCannotLookIsAnError(t *testing.T) {
	dir := fixture(t, "clean")
	rescan := gotool.NewFakeRescan().FailWith(gotool.ErrRescanUnreachable)
	tc := toolchainFor(t, dir, rescan)

	_, err := tc.Verify(context.Background(), dir, nil, []string{"govulncheck"}, []string{ourFinding})
	if err == nil {
		t.Fatal("a rescanner that could not look at all produced a verification result rather than " +
			"an error. That converts a broken worker into a fact about somebody's repository")
	}
	if !errors.Is(err, gotool.ErrRescanUnreachable) {
		t.Errorf("the cause was not carried through: %v", err)
	}
}

// --- the build half ----------------------------------------------------------

func TestVerifyFailsOnABrokenBuild(t *testing.T) {
	dir := fixture(t, "brokenbuild")
	tc := toolchainFor(t, dir, gotool.NewFakeRescan())

	v, err := tc.Verify(context.Background(), dir, nil, []string{"govulncheck"}, []string{ourFinding})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.BuildOK {
		t.Fatal("a tree that does not compile verified its build")
	}
	if v.TestsOK {
		t.Fatal("a tree that does not compile reported passing tests. Nothing ran")
	}
	if got := v.FailureReason(); got != "BUILD_FAILED" {
		t.Errorf("FailureReason = %q, want BUILD_FAILED. A build failure explains a test failure, "+
			"so reporting the test one sends a reader looking in the wrong place", got)
	}
}

func TestVerifyFailsOnFailingTests(t *testing.T) {
	dir := fixture(t, "failingtests")
	tc := toolchainFor(t, dir, gotool.NewFakeRescan())

	v, err := tc.Verify(context.Background(), dir, nil, []string{"govulncheck"}, []string{ourFinding})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !v.BuildOK {
		t.Errorf("the fixture compiles: %+v\n%s", v, v.Output)
	}
	if v.TestsOK {
		t.Fatal("a repository whose tests fail verified its tests")
	}
}

// TestVetIsPartOfTheBuildGate covers a change that compiles and that the
// project's own CI would reject.
func TestVetIsPartOfTheBuildGate(t *testing.T) {
	dir := fixture(t, "clean")
	// Compiles; `go vet` objects to the format verb.
	body := "package clean\n\nimport \"fmt\"\n\n// Report is vet-unclean.\nfunc Report() string {" +
		" return fmt.Sprintf(\"%d\", \"not a number\") }\n"
	if err := os.WriteFile(filepath.Join(dir, "report.go"), []byte(body), 0o644); err != nil {
		t.Fatalf("writing the vet-unclean file: %v", err)
	}

	tc := toolchainFor(t, dir, gotool.NewFakeRescan())
	v, err := tc.Verify(context.Background(), dir, nil, []string{"govulncheck"}, []string{ourFinding})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.BuildOK {
		t.Fatalf("a change `go vet` rejects passed the build gate:\n%s", v.Output)
	}
}

// TestAnUntidyManifestFailsVerification covers the dependency-integrity half
// of VM-F-531.
func TestAnUntidyManifestFailsVerification(t *testing.T) {
	dir := fixture(t, "vulnerable")
	mod := readFile(t, filepath.Join(dir, "go.mod"))
	mod += "\nrequire example.com/breakmod v1.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatalf("writing the untidy go.mod: %v", err)
	}

	tc := toolchainFor(t, dir, gotool.NewFakeRescan())
	before := readFile(t, filepath.Join(dir, "go.mod"))

	v, err := tc.Verify(context.Background(), dir, nil, []string{"govulncheck"}, []string{ourFinding})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.TidyOK {
		t.Fatalf("a manifest with a requirement nothing imports passed the tidy check:\n%s", v.Output)
	}

	// And it REPORTED rather than repaired. This is the half that
	// TestVerifyDoesNotModifyTheTree cannot see: that test starts from an
	// already-tidy tree, so `go mod tidy` and `go mod tidy -diff` behave
	// identically there and the distinction is invisible. An untidy tree is
	// the only place the two differ, and it is exactly the case that matters
	// — a fixer that added an import without updating go.mod. Repairing it
	// here would put a go.mod change into the pull request that the guard,
	// which ran at step 6, never saw.
	if after := readFile(t, filepath.Join(dir, "go.mod")); after != before {
		t.Fatalf("verification TIDIED the manifest instead of reporting it untidy.\n"+
			"The guard inspected this tree at step 6 and verification runs at step 7, so this "+
			"change reaches a pull request unexamined.\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestVerifyDoesNotModifyTheTree is the ordering property, and it is not
// cosmetic.
//
// The deny-list guard inspects the working tree at step 6 and Verify runs at
// step 7 (worker.go). Anything Verify changed would therefore reach a pull
// request without the guard ever having seen it — which is the one thing the
// guard exists to make impossible.
//
// This is why the gate uses `-mod=readonly` and `go mod tidy -diff` rather
// than the obvious `go mod tidy`.
func TestVerifyDoesNotModifyTheTree(t *testing.T) {
	dir := fixture(t, "vulnerable")
	tc := toolchainFor(t, dir, gotool.NewFakeRescan())

	// Bump first, so the tree Verify sees is a changed one — which is the
	// state it is actually used in.
	if _, err := tc.Apply(context.Background(), dir, []remediate.Target{{
		Module: "example.com/vulnmod", From: "v1.0.0", To: "v1.2.0",
	}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	before := snapshot(t, dir)
	if _, err := tc.Verify(context.Background(), dir, nil, []string{"govulncheck"},
		[]string{ourFinding}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	after := snapshot(t, dir)

	for path, body := range before {
		switch got, present := after[path]; {
		case !present:
			t.Errorf("verification deleted %s", path)
		case got != body:
			t.Errorf("verification modified %s. The guard inspected this tree at step 6 and "+
				"verification runs at step 7, so anything changed here reaches a pull request "+
				"unexamined", path)
		}
	}
	for path := range after {
		if _, present := before[path]; !present {
			t.Errorf("verification created %s, which the guard never saw", path)
		}
	}
}

// TestVerifyOnARealBumpOfARealRepository is the end-to-end shape: a real
// dependency bump, a real build, a real test run, and a re-scan that stops
// reporting what the bump closed.
func TestVerifyOnARealBumpOfARealRepository(t *testing.T) {
	dir := fixture(t, "vulnerable")
	rescan := gotool.NewFakeRescan().StillReports(ourFinding)
	tc := toolchainFor(t, dir, rescan)

	target := remediate.Target{
		Module: "example.com/vulnmod", From: "v1.0.0", To: "v1.2.0",
		Closes: []string{ourFinding},
	}
	applied, err := tc.Apply(context.Background(), dir, []remediate.Target{target})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if applied.Bumped["example.com/vulnmod"] != "v1.2.0" {
		t.Fatalf("the bump did not happen: %+v", applied.Bumped)
	}

	// Before the catalogue is updated, the finding is still open: a change
	// that builds is not yet a fix.
	v, err := tc.Verify(context.Background(), dir, []remediate.Target{target},
		[]string{"govulncheck"}, []string{ourFinding})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.RescanClean {
		t.Fatal("the re-scan still reports the advisory and the gate called it clean")
	}
	if !v.BuildOK || !v.TestsOK {
		t.Fatalf("the bumped repository does not build and test:\n%s", v.Output)
	}

	// Now the re-scan agrees the finding is gone, which is the only evidence
	// that counts.
	rescan.Stops(ourFinding)
	v, err = tc.Verify(context.Background(), dir, []remediate.Target{target},
		[]string{"govulncheck"}, []string{ourFinding})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !v.OK() {
		t.Fatalf("a real bump that builds, tests and no longer reports the advisory did not "+
			"verify: %+v\n%s", v, v.Output)
	}
}
