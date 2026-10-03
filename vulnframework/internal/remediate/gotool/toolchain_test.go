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
	"github.com/wanaware/vulnframework/internal/sandbox"
)

// --- construction ------------------------------------------------------------

// TestNewRefusesWithoutASandbox is fail-closed at the only point where it can
// be enforced structurally.
//
// A repository's own build and test suite are arbitrary code execution: `go
// test` runs whatever the repository says, and `go build` will too through
// cgo. A toolchain that defaulted to running unconfined would pass every
// behavioural test in this package, because none of them are about isolation.
func TestNewRefusesWithoutASandbox(t *testing.T) {
	_, err := gotool.New(nil, gotool.NewFakeRescan())
	if err == nil {
		t.Fatal("a toolchain was built with no sandbox. Every command it runs is the repository's " +
			"own code, with the worker's environment and filesystem access")
	}
	var notIsolated *sandbox.ErrNotIsolated
	if !errors.As(err, &notIsolated) {
		t.Errorf("the refusal is not an *ErrNotIsolated, so a caller cannot tell it apart from a "+
			"configuration error: %v", err)
	}
}

// TestNewRefusesWithoutARescanner is the same refusal for the other half.
//
// Without a re-scan, Verify can only report on the build — and a change that
// builds is not a fix. Defaulting to "no re-scan, assume clean" is how a
// system starts certifying its own work.
func TestNewRefusesWithoutARescanner(t *testing.T) {
	sb := sandbox.NewFake(sandbox.Policy{CloneDir: t.TempDir()})
	if _, err := gotool.New(sb, nil); err == nil {
		t.Fatal("a toolchain was built with no rescanner. Verify would then pass on the build alone, " +
			"and the re-run of the scanners is the only evidence a change is a fix (VM-F-531)")
	}
}

// TestCommandsRefuseADirectoryTheSandboxDoesNotConfine catches a mismatch that
// would otherwise be silent and total.
//
// The sandbox decides the working directory. If the caller means a different
// one, every command runs somewhere other than where the caller believes, and
// the result — a clean build, a passing test suite — is recorded against a
// repository nothing looked at.
func TestCommandsRefuseADirectoryTheSandboxDoesNotConfine(t *testing.T) {
	confined := fixture(t, "clean")
	elsewhere := t.TempDir()

	tc := toolchainFor(t, confined, gotool.NewFakeRescan())

	_, err := tc.Baseline(context.Background(), elsewhere)
	if err == nil {
		t.Fatal("the toolchain accepted a directory the sandbox does not confine. The commands would " +
			"run in the sandbox's directory while the caller recorded the answer against this one")
	}
	if !strings.Contains(err.Error(), elsewhere) || !strings.Contains(err.Error(), confined) {
		t.Errorf("the refusal names neither directory, so nobody can see what the mismatch was: %v", err)
	}
}

// --- baseline ----------------------------------------------------------------

func TestBaselineOnACleanRepository(t *testing.T) {
	dir := fixture(t, "clean")
	tc := toolchainFor(t, dir, gotool.NewFakeRescan())

	check, err := tc.Baseline(context.Background(), dir)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	if !check.OK() {
		t.Fatalf("a clean repository did not produce a clean baseline: %+v\n%s", check, check.Output)
	}
}

// TestBaselineReportsFailingTestsVerbatim is VM-F-504 and VM-F-532 together.
//
// A repository whose tests already fail cannot be remediated: there is no
// signal to verify a fix against. And the pre-existing failure is reported as
// the tool emitted it — summarising away a failure is itself a defect.
func TestBaselineReportsFailingTestsVerbatim(t *testing.T) {
	dir := fixture(t, "failingtests")
	tc := toolchainFor(t, dir, gotool.NewFakeRescan())

	check, err := tc.Baseline(context.Background(), dir)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	if !check.BuildOK {
		t.Errorf("the fixture compiles, so BuildOK should be true: %+v", check)
	}
	if check.TestsOK {
		t.Fatal("a repository whose tests fail reported a passing baseline")
	}
	if !strings.Contains(check.Output, "FAIL") || !strings.Contains(check.Output, "Add(2, 3)") {
		t.Errorf("the failure was not carried through verbatim; a reader cannot see what failed:\n%s",
			check.Output)
	}
}

// TestBaselineOnABrokenBuildReportsNeitherGate is the ordering rule.
//
// Tests cannot pass in a tree that does not compile. Reporting TestsOK here
// would send a reader looking at the test suite for a problem that is in the
// code.
func TestBaselineOnABrokenBuildReportsNeitherGate(t *testing.T) {
	dir := fixture(t, "brokenbuild")
	tc := toolchainFor(t, dir, gotool.NewFakeRescan())

	check, err := tc.Baseline(context.Background(), dir)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	if check.BuildOK {
		t.Fatal("a repository that does not compile reported a successful build")
	}
	if check.TestsOK {
		t.Fatal("a repository that does not compile reported passing tests. Nothing ran: the tests " +
			"could not have been executed at all")
	}
	if !strings.Contains(check.Output, "cannot use") && !strings.Contains(check.Output, "sum") {
		t.Errorf("the compile error was not carried through:\n%s", check.Output)
	}
}

// --- confinement -------------------------------------------------------------

// TestTheRepositorysTestsDoNotSeeTheWorkerEnvironment is the confinement
// proof, and it is made by the repository's own code.
//
// The fixture's test fails if it can read a variable the worker holds and the
// sandbox's allowlist does not name. Asking the toolchain what it is
// configured to do would prove only that it is configured, which is a
// different claim.
//
// Its non-vacuity is established by the companion test below, not asserted
// here.
func TestTheRepositorysTestsDoNotSeeTheWorkerEnvironment(t *testing.T) {
	dir := fixture(t, "envcanary")
	t.Setenv("VF_LEAKED_SECRET", "a-value-the-repository-must-never-read")

	tc := toolchainFor(t, dir, gotool.NewFakeRescan())
	check, err := tc.Baseline(context.Background(), dir)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	if !check.TestsOK {
		t.Fatalf("the worker's environment reached the repository's own test process. "+
			"A test suite that can read the worker's environment can read whatever credentials the "+
			"runner was launched with:\n%s", check.Output)
	}
}

// TestTheLeakCanaryIsDetectableAtAll is the negative control for the test
// above, and without it that test proves nothing.
//
// A fixture that could not see the variable under any circumstances would
// produce a passing result whether or not the toolchain filtered anything.
// Here the variable IS allowlisted, so it should arrive — and the fixture
// should notice.
func TestTheLeakCanaryIsDetectableAtAll(t *testing.T) {
	dir := fixture(t, "envcanary")
	t.Setenv("VF_LEAKED_SECRET", "a-value-the-repository-must-never-read")

	// The one difference from the test above: the canary is on the allowlist.
	tc := toolchainFor(t, dir, gotool.NewFakeRescan(), "VF_LEAKED_SECRET")
	check, err := tc.Baseline(context.Background(), dir)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	if check.TestsOK {
		t.Fatal("the fixture did not notice a variable that was deliberately allowed through. " +
			"It is therefore blind to the leak it is supposed to detect, and the confinement test " +
			"that relies on it was passing for no reason")
	}
}

// --- apply -------------------------------------------------------------------

func TestApplyBumpsAModule(t *testing.T) {
	dir := fixture(t, "vulnerable")
	tc := toolchainFor(t, dir, gotool.NewFakeRescan())

	applied, err := tc.Apply(context.Background(), dir, []remediate.Target{{
		Module: "example.com/vulnmod", From: "v1.0.0", To: "v1.2.0",
		Closes: []string{"GHSA-fixture-0001"},
	}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := applied.Bumped["example.com/vulnmod"]; got != "v1.2.0" {
		t.Fatalf("Bumped = %q, want v1.2.0\n%s", got, applied.Output)
	}
	if mod := readFile(t, filepath.Join(dir, "go.mod")); !strings.Contains(mod, "v1.2.0") {
		t.Errorf("go.mod does not record the bump:\n%s", mod)
	}
	if !contains(applied.ChangedFiles, "go.mod") {
		t.Errorf("go.mod is not in ChangedFiles = %v. The guard inspects that list", applied.ChangedFiles)
	}
	if len(applied.Diff) == 0 {
		t.Error("the diff is empty, so the content guard would inspect nothing")
	}
}

// TestTheBumpedVersionComesFromTheModuleGraph is why Apply reads back rather
// than echoing.
//
// The target here is a version QUERY, not a version. A toolchain that recorded
// what it was asked for would report "v1", which is not a version anything was
// bumped to. The real resolution — v1.2.0, the highest the proxy publishes —
// is only knowable by asking the module graph afterwards.
//
// The same mechanism is what catches the case that actually matters in
// production: a proxy that has not mirrored a tag resolves LOWER than asked,
// and the pull request would otherwise claim a bump that did not happen.
func TestTheBumpedVersionComesFromTheModuleGraph(t *testing.T) {
	dir := fixture(t, "vulnerable")
	tc := toolchainFor(t, dir, gotool.NewFakeRescan())

	applied, err := tc.Apply(context.Background(), dir, []remediate.Target{{
		Module: "example.com/vulnmod", From: "v1.0.0", To: "v1",
	}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got := applied.Bumped["example.com/vulnmod"]
	if got == "v1" {
		t.Fatal("Apply reported the version it was ASKED for rather than the one the module graph " +
			"resolved. A proxy that has not mirrored a tag resolves lower, and this would report a " +
			"bump that did not happen")
	}
	if got != "v1.2.0" {
		t.Fatalf("resolved version = %q, want v1.2.0\n%s", got, applied.Output)
	}
}

// TestABumpThatCannotBeResolvedIsDroppedAndNamed covers the proxy that does
// not have what was asked for.
//
// It must not pass silently. A target that resolved to nothing and was not
// reported would leave a pull request that claims to close an advisory and
// changes nothing.
func TestABumpThatCannotBeResolvedIsDroppedAndNamed(t *testing.T) {
	dir := fixture(t, "vulnerable")
	tc := toolchainFor(t, dir, gotool.NewFakeRescan())

	applied, err := tc.Apply(context.Background(), dir, []remediate.Target{{
		Module: "example.com/vulnmod", From: "v1.0.0", To: "v9.9.9",
	}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if _, dropped := applied.Dropped["example.com/vulnmod"]; !dropped {
		t.Fatalf("a bump to a version the proxy does not publish was not reported as dropped: %+v\n%s",
			applied, applied.Output)
	}
	if got := applied.Bumped["example.com/vulnmod"]; got == "v9.9.9" {
		t.Fatal("a version that could not be resolved was reported as bumped")
	}
	if mod := readFile(t, filepath.Join(dir, "go.mod")); !strings.Contains(mod, "v1.0.0") {
		t.Errorf("the module was not left at its original version:\n%s", mod)
	}
}

// TestABatchThatDoesNotBuildIsBisected is VM-AD §11.3.
//
// Two bumps, one of which removes a function the repository calls. The batch
// fails. The correct outcome is the harmless bump applied, the breaking one
// dropped and named, and a tree that builds — not a whole group abandoned
// because one member of it was incompatible.
func TestABatchThatDoesNotBuildIsBisected(t *testing.T) {
	dir := fixture(t, "twomods")
	tc := toolchainFor(t, dir, gotool.NewFakeRescan())

	applied, err := tc.Apply(context.Background(), dir, []remediate.Target{
		{Module: "example.com/breakmod", From: "v1.0.0", To: "v1.1.0"},
		{Module: "example.com/vulnmod", From: "v1.0.0", To: "v1.2.0"},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	why, dropped := applied.Dropped["example.com/breakmod"]
	if !dropped {
		t.Fatalf("the bump that breaks the build was not dropped: %+v\n%s", applied, applied.Output)
	}
	if strings.TrimSpace(why) == "" {
		t.Error("the dropped bump carries no reason. A reviewer is then told a module is missing " +
			"from the pull request and not why")
	}
	if got := applied.Bumped["example.com/vulnmod"]; got != "v1.2.0" {
		t.Errorf("the harmless bump was not applied: vulnmod = %q. Bisection must drop the offender "+
			"and proceed with the remainder, not abandon the group\n%s", got, applied.Output)
	}

	// The tree the bisect left behind must be the one it claims.
	check, err := tc.Baseline(context.Background(), dir)
	if err != nil {
		t.Fatalf("Baseline after bisect: %v", err)
	}
	if !check.OK() {
		t.Fatalf("the tree left by the bisect does not build and test cleanly:\n%s", check.Output)
	}

	mod := readFile(t, filepath.Join(dir, "go.mod"))
	if !strings.Contains(mod, "breakmod v1.0.0") {
		t.Errorf("the dropped module was not left at its original version:\n%s", mod)
	}
	if !strings.Contains(mod, "vulnmod v1.2.0") {
		t.Errorf("the applied bump is not in go.mod:\n%s", mod)
	}
}

// --- collect -----------------------------------------------------------------

// TestCollectSeesAnAddedFile is the case a plain `git diff` misses entirely.
//
// A fixer that ADDS a file — a new test, a new source file — produces no diff
// at all until the file is at least intent-to-add. The content guard would
// then inspect nothing, which is the whole of its job not happening.
func TestCollectSeesAnAddedFile(t *testing.T) {
	dir := fixture(t, "clean")
	tc := toolchainFor(t, dir, gotool.NewFakeRescan())

	body := "package clean\n\n// Added by a fixer.\nfunc Sub(a, b int) int { return a - b }\n"
	if err := os.WriteFile(filepath.Join(dir, "sub.go"), []byte(body), 0o644); err != nil {
		t.Fatalf("writing the new file: %v", err)
	}

	applied, err := tc.Collect(context.Background(), dir)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !contains(applied.ChangedFiles, "sub.go") {
		t.Fatalf("an added file is not in ChangedFiles = %v", applied.ChangedFiles)
	}
	if !strings.Contains(string(applied.Diff), "func Sub") {
		t.Fatalf("an added file's content is not in the diff, so the content guard would inspect "+
			"nothing:\n%s", applied.Diff)
	}
}

func TestCollectSeesAnEditedFile(t *testing.T) {
	dir := fixture(t, "clean")
	tc := toolchainFor(t, dir, gotool.NewFakeRescan())

	path := filepath.Join(dir, "calc.go")
	body := strings.Replace(readFile(t, path), "return a + b", "return b + a", 1)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("editing calc.go: %v", err)
	}

	applied, err := tc.Collect(context.Background(), dir)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !contains(applied.ChangedFiles, "calc.go") {
		t.Fatalf("an edited file is not in ChangedFiles = %v", applied.ChangedFiles)
	}
	if !strings.Contains(string(applied.Diff), "return b + a") {
		t.Errorf("the edit is not in the diff:\n%s", applied.Diff)
	}
}
