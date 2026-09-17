package remediate

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/wanaware/vulnframework/internal/store"
)

// FakeToolchain is an offline toolchain that models a real one's WEAKEST
// permitted behaviour (the Phase 8 standing sentinel).
//
// The behaviours that matter, each because the framework has to handle it:
//
//	A bump can RESOLVE LOWER than asked. A proxy that has not yet mirrored a
//	tag is an everyday occurrence, and the result is a change that looks like a
//	fix and closes nothing. This is why verification re-runs the scanners
//	rather than trusting the bump.
//
//	A baseline can already be failing. Remediating such a repository is
//	meaningless, because there is no signal to verify against.
//
//	A build or test can fail AFTER the change, and a bump can touch files
//	nobody expected — which is what the guard is for.
//
// It also models a module registry, so "did the bump close the advisory" is
// answered by comparing the INSTALLED version against the version that actually
// closes it, rather than by the fake agreeing with whatever it was told.
type FakeToolchain struct {
	mu sync.Mutex

	modules map[string]string // module -> installed version
	// ceilings caps what the proxy will resolve to, standing in for a tag that
	// has not been mirrored.
	ceilings map[string]string
	// advisories maps an identifier to the module and the version at which it
	// closes. The re-scan consults this, not the caller's intent.
	advisories map[string]advisory

	tests          map[string]bool
	sourceFindings map[string]string
	closedSource   map[string]bool
	edited         []string
	addedLines     []string

	baselineFailure  *Check
	verifyBuildFails bool
	verifyTestsFails bool
	extraChanged     []string
	applyErr         error
}

type advisory struct {
	module   string
	fixedAt  string
	reported bool
}

// NewFakeToolchain builds a toolchain with no modules and a clean baseline.
func NewFakeToolchain() *FakeToolchain {
	return &FakeToolchain{
		modules: map[string]string{}, ceilings: map[string]string{},
		advisories: map[string]advisory{}, tests: map[string]bool{},
		sourceFindings: map[string]string{}, closedSource: map[string]bool{},
	}
}

// WithModule installs a module at a version.
func (f *FakeToolchain) WithModule(module, version string) *FakeToolchain {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.modules[module] = version
	return f
}

// WithAdvisory declares that id affects module until fixedAt.
func (f *FakeToolchain) WithAdvisory(id, module, fixedAt string) *FakeToolchain {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.advisories[id] = advisory{module: module, fixedAt: fixedAt}
	return f
}

// WithCeiling caps the version the proxy will resolve for a module.
func (f *FakeToolchain) WithCeiling(module, version string) *FakeToolchain {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ceilings[module] = version
	return f
}

// WithBaselineFailure makes the pre-change build or tests already fail.
func (f *FakeToolchain) WithBaselineFailure(kind, output string) *FakeToolchain {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := Check{BuildOK: true, TestsOK: true, Output: output}
	switch kind {
	case "build":
		c.BuildOK, c.TestsOK = false, false
	default:
		c.TestsOK = false
	}
	f.baselineFailure = &c
	return f
}

// WithVerifyFailure makes the post-change build or tests fail.
func (f *FakeToolchain) WithVerifyFailure(kind string) *FakeToolchain {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch kind {
	case "build":
		f.verifyBuildFails = true
	default:
		f.verifyTestsFails = true
	}
	return f
}

// WithExtraChangedFile makes a bump also touch a file nobody asked it to.
func (f *FakeToolchain) WithExtraChangedFile(path string) *FakeToolchain {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.extraChanged = append(f.extraChanged, path)
	return f
}

// WithApplyError makes the bump itself fail.
func (f *FakeToolchain) WithApplyError(err error) *FakeToolchain {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applyErr = err
	return f
}

// Version reports a module's installed version, for assertions.
func (f *FakeToolchain) Version(module string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.modules[module]
}

// --- the interface ----------------------------------------------------------

func (f *FakeToolchain) Baseline(_ context.Context, _ string) (Check, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.baselineFailure != nil {
		return *f.baselineFailure, nil
	}
	return Check{BuildOK: true, TestsOK: true, Output: "ok  \tbaseline\t0.4s\n"}, nil
}

func (f *FakeToolchain) Apply(_ context.Context, _ string, targets []Target) (Applied, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErr != nil {
		return Applied{}, f.applyErr
	}

	out := Applied{Bumped: map[string]string{}, Dropped: map[string]string{}}
	var log strings.Builder
	for _, t := range targets {
		resolved := t.To
		// A proxy that has not mirrored the tag resolves lower. The framework
		// is not told; it has to find out by re-scanning.
		if ceiling, ok := f.ceilings[t.Module]; ok && store.CompareVersions(resolved, ceiling) > 0 {
			resolved = ceiling
			fmt.Fprintf(&log, "go: %s@%s: not found in module cache, resolved %s\n", t.Module, t.To, ceiling)
		}
		f.modules[t.Module] = resolved
		out.Bumped[t.Module] = resolved
		fmt.Fprintf(&log, "go get %s@%s\n", t.Module, resolved)
	}

	out.ChangedFiles = append(out.ChangedFiles, "go.mod", "go.sum")
	out.ChangedFiles = append(out.ChangedFiles, f.extraChanged...)
	sort.Strings(out.ChangedFiles)

	var diff strings.Builder
	diff.WriteString("--- a/go.mod\n+++ b/go.mod\n")
	for module, version := range out.Bumped {
		fmt.Fprintf(&diff, "-\t%s v0.0.0\n+\t%s %s\n", module, module, version)
	}
	out.Diff = []byte(diff.String())
	out.Output = log.String()
	return out, nil
}

func (f *FakeToolchain) Verify(_ context.Context, _ string, targets []Target, tools []string) (Verification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	v := Verification{BuildOK: !f.verifyBuildFails, TestsOK: !f.verifyTestsFails, TidyOK: true}
	var log strings.Builder
	if !v.BuildOK {
		log.WriteString("# org/wanaware-api\n./client.go:42:2: undefined: crypto.OldAPI\n")
	}
	if !v.TestsOK {
		log.WriteString("--- FAIL: TestClient (0.02s)\n    client_test.go:88: unexpected signature\n")
	}

	// The re-scan. Ground truth is the INSTALLED version against the version
	// the advisory actually closes at — never the version the caller intended.
	var remaining []string
	for id, adv := range f.advisories {
		installed, present := f.modules[adv.module]
		if !present {
			continue
		}
		if store.CompareVersions(installed, adv.fixedAt) < 0 {
			remaining = append(remaining, id)
		}
	}
	// Source-level findings close only when the fixer actually closed them.
	// A fake that inferred a fix from a touched file would agree with any
	// change at all, and the re-scan would stop being evidence.
	for id := range f.sourceFindings {
		if !f.closedSource[id] {
			remaining = append(remaining, id)
		}
	}
	sort.Strings(remaining)
	v.Remaining = remaining
	v.RescanClean = len(remaining) == 0

	if !v.RescanClean {
		fmt.Fprintf(&log, "re-scan with %s still reports: %s\n",
			strings.Join(tools, ", "), strings.Join(remaining, ", "))
		for _, t := range targets {
			fmt.Fprintf(&log, "  %s is at %s (target was %s)\n", t.Module, f.modules[t.Module], t.To)
		}
	}
	v.Output = log.String()
	return v, nil
}

// --- Source-level state, for the agentic worker -----------------------------
//
// The fake models a tree well enough that the green-by-deletion check has
// something real to compare: a set of test names, and a set of findings that
// close only when the file carrying them is actually changed.

// WithTests declares the tests present before any change.
func (f *FakeToolchain) WithTests(names ...string) *FakeToolchain {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tests == nil {
		f.tests = map[string]bool{}
	}
	for _, n := range names {
		f.tests[n] = true
	}
	return f
}

// WithFinding declares a source-level finding that closes only when its file
// is changed AND the fixer says it closed it.
//
// Two conditions, deliberately. A fake that closed the finding merely because
// a file was touched would agree with any change at all, and the re-scan would
// stop being evidence of anything.
func (f *FakeToolchain) WithFinding(id, file string) *FakeToolchain {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sourceFindings == nil {
		f.sourceFindings = map[string]string{}
	}
	f.sourceFindings[id] = file
	return f
}

// TestInventory lists the tests currently in the tree.
func (f *FakeToolchain) TestInventory(_ context.Context, _ string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.tests))
	for name, present := range f.tests {
		if present {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Collect reports what the tree currently shows as changed.
func (f *FakeToolchain) Collect(_ context.Context, _ string) (Applied, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	changed := append([]string(nil), f.edited...)
	changed = append(changed, f.extraChanged...)
	sort.Strings(changed)
	changed = dedupe(changed)

	var diff strings.Builder
	diff.WriteString("--- a/tree\n+++ b/tree\n")
	for _, line := range f.addedLines {
		fmt.Fprintf(&diff, "+%s\n", line)
	}
	return Applied{
		Bumped: map[string]string{}, Dropped: map[string]string{},
		ChangedFiles: changed, Diff: []byte(diff.String()),
	}, nil
}

// --- what a fixer does to the tree, for fakes that edit source --------------

// EditFile records that a file was changed.
func (f *FakeToolchain) EditFile(paths ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.edited = append(f.edited, paths...)
}

// AddLine records a line added to the tree, which the content guard inspects.
func (f *FakeToolchain) AddLine(lines ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addedLines = append(f.addedLines, lines...)
}

// AddTest adds a test to the inventory.
func (f *FakeToolchain) AddTest(names ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tests == nil {
		f.tests = map[string]bool{}
	}
	for _, n := range names {
		f.tests[n] = true
	}
}

// RemoveTest deletes a test from the inventory — what a green-by-deletion
// change looks like from the tree's point of view. A skipped test is modelled
// the same way, because a test that always skips is a test that is gone.
func (f *FakeToolchain) RemoveTest(names ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range names {
		delete(f.tests, n)
	}
}

// CloseSourceFinding marks a source finding as genuinely fixed, which the
// re-scan then stops reporting.
func (f *FakeToolchain) CloseSourceFinding(ids ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closedSource == nil {
		f.closedSource = map[string]bool{}
	}
	for _, id := range ids {
		f.closedSource[id] = true
	}
}

func dedupe(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
