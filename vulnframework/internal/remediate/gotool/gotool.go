// Package gotool is the real Go toolchain behind remediate.Toolchain
// (VM-AD §11.3).
//
// Until this existed there was no real implementation at all: every
// remediation test ran against FakeToolchain, which means every one of them
// proved the harness and none of them proved the build. "This fix works" was
// the fake agreeing with itself.
//
// Three properties are worth reading before the code.
//
// **It is confined.** A repository's own build and test suite are arbitrary
// code execution — `go test` runs whatever the repository says, and `go build`
// will too, through cgo — so every command here is launched through
// sandbox.Sandbox, the same confinement the agent gets. A nil sandbox is
// refused rather than defaulted, exactly as agent.Client refuses one: a
// toolchain that silently ran unconfined would pass every behavioural test in
// this package.
//
// **Verification does not touch the tree.** The guard has already inspected
// the working tree by the time Verify runs (worker.go step 6, then step 7), so
// anything Verify changed would reach a pull request unexamined. Every command
// in Verify is therefore read-only with respect to the tree: `-mod=readonly`
// on build, vet and test, and `go mod tidy -diff`, which reports rather than
// rewrites. There is a test that snapshots the tree around Verify and compares
// it byte for byte.
//
// **A re-scan that did not happen is not a clean re-scan.** If a scanner could
// not be executed, RescanClean is false and the output names the tool. This is
// the tri-state rule at the point where it matters most: a tool that did not
// run reports nothing, and nothing is exactly what a fixed repository reports
// too.
package gotool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/wanaware/vulnframework/internal/remediate"
	"github.com/wanaware/vulnframework/internal/sandbox"
	"github.com/wanaware/vulnframework/internal/store"
)

// maxBisectAttempts bounds the batch retries in Apply.
//
// A bound rather than a loop that trusts its own termination argument: each
// attempt runs a full build of somebody else's repository, and a bisect that
// did not converge would otherwise spend a worker indefinitely while looking
// like progress.
const maxBisectAttempts = 24

// Toolchain is remediate.Toolchain for Go repositories.
type Toolchain struct {
	// Sandbox confines every command that executes repository code. Required:
	// New refuses to build a Toolchain without one.
	Sandbox sandbox.Sandbox

	// Go is the go binary to invoke. Empty means "go", resolved on PATH
	// inside the sandbox.
	Go string
	// Git is the git binary, used to read what the tree reports as changed.
	Git string

	// Rescan re-runs the scanners that produced a group's findings. Required
	// by Verify: without it the only evidence that a change is a FIX rather
	// than merely a change does not exist (VM-F-531).
	Rescan Rescanner
}

// New builds a Toolchain, refusing a configuration that could not be honest.
//
// Both refusals are fail-closed and neither is defaultable. A missing sandbox
// means repository code would run unconfined; a missing rescanner means
// Verify would have to either skip the re-scan — reporting a change as a fix —
// or fail every verification, and silently doing the first is how a build
// starts certifying itself.
func New(sb sandbox.Sandbox, rescan Rescanner) (*Toolchain, error) {
	if sb == nil {
		return nil, &sandbox.ErrNotIsolated{
			Reason: "the Go toolchain was given no sandbox, so `go build` and `go test` would run the " +
				"repository's own code with the worker's environment, network and filesystem access",
		}
	}
	if rescan == nil {
		return nil, fmt.Errorf(
			"gotool: no rescanner. Verify would then report a change as a fix on the strength of the " +
				"build alone, and the re-run of the scanners is the only thing that distinguishes the two " +
				"(VM-F-531)")
	}
	return &Toolchain{Sandbox: sb, Rescan: rescan}, nil
}

var _ remediate.Toolchain = (*Toolchain)(nil)

// --- Baseline ---------------------------------------------------------------

// Baseline establishes the pre-change build and test state (VM-F-504).
func (t *Toolchain) Baseline(ctx context.Context, dir string) (remediate.Check, error) {
	build, err := t.run(ctx, dir, t.goBin(), "build", "./...")
	if err != nil {
		return remediate.Check{}, err
	}
	if build.exit != 0 {
		// Tests cannot pass in a tree that does not compile, and reporting
		// TestsOK for one would send a reader looking in the wrong place.
		return remediate.Check{Output: build.text()}, nil
	}

	test, err := t.run(ctx, dir, t.goBin(), "test", "./...", "-count=1")
	if err != nil {
		return remediate.Check{}, err
	}
	return remediate.Check{
		BuildOK: true,
		TestsOK: test.exit == 0,
		Output:  build.text() + test.text(),
	}, nil
}

// --- Apply ------------------------------------------------------------------

// Apply performs the bumps, bisecting a batch that fails to build
// (VM-AD §11.3).
//
// The batch is applied and built ONCE, not per module: a repository with eight
// bumps would otherwise be built eight times for no extra information. Only
// when the batch fails does it cost anything to find out which bump is
// responsible.
func (t *Toolchain) Apply(ctx context.Context, dir string, targets []remediate.Target) (remediate.Applied, error) {
	out := remediate.Applied{Bumped: map[string]string{}, Dropped: map[string]string{}}
	if len(targets) == 0 {
		return out, nil
	}

	manifest, err := readManifest(dir)
	if err != nil {
		return out, err
	}

	var log strings.Builder
	candidates := append([]remediate.Target(nil), targets...)
	attempts := 0

	for {
		if attempts >= maxBisectAttempts {
			return out, fmt.Errorf(
				"gotool: the bump batch was still failing after %d attempts. Stopping rather than "+
					"continuing to build somebody else's repository indefinitely; the remaining targets "+
					"are %s", attempts, targetNames(candidates))
		}
		attempts++

		res, err := t.attempt(ctx, dir, manifest, candidates)
		if err != nil {
			return out, err
		}
		log.WriteString(res.output)

		if res.ok || len(candidates) == 0 {
			for module, version := range res.resolved {
				out.Bumped[module] = version
			}
			break
		}

		// The batch did not build. Find one bump that is implicated, drop it,
		// and retry the remainder.
		offender, attemptsUsed, err := t.findOffender(ctx, dir, manifest, candidates, maxBisectAttempts-attempts)
		if err != nil {
			return out, err
		}
		attempts += attemptsUsed

		out.Dropped[offender.Module] = fmt.Sprintf(
			"the batch failed to build with it included; isolated by bisection and left at %s",
			dash(offender.From))
		fmt.Fprintf(&log, "gotool: dropping %s %s → %s: the batch does not build with it\n",
			offender.Module, dash(offender.From), offender.To)
		candidates = without(candidates, offender.Module)
	}

	if err := t.markIntentToAdd(ctx, dir); err != nil {
		return out, err
	}
	changed, err := t.changedFiles(ctx, dir)
	if err != nil {
		return out, err
	}
	diff, err := t.diff(ctx, dir)
	if err != nil {
		return out, err
	}
	out.ChangedFiles, out.Diff, out.Output = changed, diff, log.String()
	return out, nil
}

// attemptResult is one batch application.
type attemptResult struct {
	ok bool
	// resolved is the version each module ACTUALLY ended up at, read back from
	// the module graph. It is not the version that was asked for: a proxy that
	// has not mirrored a tag resolves lower, and the difference is the whole
	// reason Verify re-runs the scanners rather than trusting the bump.
	resolved map[string]string
	output   string
}

// attempt restores the manifest, applies a candidate set, and builds it.
func (t *Toolchain) attempt(ctx context.Context, dir string, base manifest, targets []remediate.Target) (attemptResult, error) {
	res := attemptResult{resolved: map[string]string{}}
	var log strings.Builder

	if err := base.restore(dir); err != nil {
		return res, err
	}
	if len(targets) == 0 {
		res.ok = false
		res.output = "gotool: every bump in the batch was dropped; nothing left to apply\n"
		return res, nil
	}

	for _, target := range targets {
		got, err := t.run(ctx, dir, t.goBin(), "get", target.Module+"@"+target.To)
		if err != nil {
			return res, err
		}
		log.WriteString(got.text())
		if got.exit != 0 {
			// `go get` failing is not a build failure to be bisected around:
			// the module or version could not be resolved at all, which is an
			// operational fact about the proxy rather than about this
			// repository's code.
			res.output = log.String()
			return res, nil
		}
	}

	tidy, err := t.run(ctx, dir, t.goBin(), "mod", "tidy")
	if err != nil {
		return res, err
	}
	log.WriteString(tidy.text())

	resolved, resolveLog, err := t.resolvedVersions(ctx, dir, targets)
	if err != nil {
		return res, err
	}
	res.resolved = resolved
	log.WriteString(resolveLog)

	build, err := t.run(ctx, dir, t.goBin(), "build", "./...")
	if err != nil {
		return res, err
	}
	log.WriteString(build.text())

	res.ok = build.exit == 0
	res.output = log.String()
	return res, nil
}

// findOffender isolates one target whose presence makes the batch fail.
//
// Bisection rather than one-at-a-time, as VM-AD §11.3 says, because a batch of
// eight costs three builds this way and eight the other.
//
// Where two bumps fail only in combination — neither half fails alone — this
// returns a member of the half that was still failing when the search narrowed
// to one. Dropping it does unblock the remainder, which is what the caller
// needs; the recorded reason says "isolated by bisection" rather than
// "incompatible", because the second would be a claim this search cannot
// support.
func (t *Toolchain) findOffender(ctx context.Context, dir string, base manifest, set []remediate.Target, budget int) (remediate.Target, int, error) {
	used := 0
	for len(set) > 1 {
		if used >= budget {
			// Out of budget: name the first of what is left rather than
			// looping. An honest half-answer beats an unbounded search.
			return set[0], used, nil
		}
		mid := len(set) / 2
		left := set[:mid]

		res, err := t.attempt(ctx, dir, base, left)
		if err != nil {
			return remediate.Target{}, used, err
		}
		used++

		if !res.ok {
			set = left
		} else {
			set = set[mid:]
		}
	}
	return set[0], used, nil
}

// --- Collect ----------------------------------------------------------------

// Collect reports what the tree currently shows as changed, for a fixer that
// edits files directly.
func (t *Toolchain) Collect(ctx context.Context, dir string) (remediate.Applied, error) {
	out := remediate.Applied{Bumped: map[string]string{}, Dropped: map[string]string{}}

	if err := t.markIntentToAdd(ctx, dir); err != nil {
		return out, err
	}
	changed, err := t.changedFiles(ctx, dir)
	if err != nil {
		return out, err
	}
	diff, err := t.diff(ctx, dir)
	if err != nil {
		return out, err
	}
	out.ChangedFiles, out.Diff = changed, diff
	return out, nil
}

// --- Verify -----------------------------------------------------------------

// Verify runs the full post-change gate (VM-F-531).
//
// Nothing here writes to the tree. The guard has already passed on it, and a
// verification that modified what the guard inspected would put unexamined
// content into a pull request.
func (t *Toolchain) Verify(ctx context.Context, dir string, targets []remediate.Target, tools []string, expect []string) (remediate.Verification, error) {
	v := remediate.Verification{}
	var log strings.Builder

	build, err := t.run(ctx, dir, t.goBin(), "build", "-mod=readonly", "./...")
	if err != nil {
		return v, err
	}
	log.WriteString(build.text())
	v.BuildOK = build.exit == 0

	if v.BuildOK {
		vet, err := t.run(ctx, dir, t.goBin(), "vet", "-mod=readonly", "./...")
		if err != nil {
			return v, err
		}
		log.WriteString(vet.text())
		// `go vet` is part of the build gate: a vet failure is a build the
		// project's own CI would reject.
		v.BuildOK = vet.exit == 0

		if v.BuildOK {
			test, err := t.run(ctx, dir, t.goBin(), "test", "-mod=readonly", "-race", "-count=1", "./...")
			if err != nil {
				return v, err
			}
			log.WriteString(test.text())
			v.TestsOK = test.exit == 0
		}
	}

	// `-diff` reports rather than rewrites. `go mod tidy` without it would
	// edit go.mod and go.sum after the guard had already read them.
	tidy, err := t.run(ctx, dir, t.goBin(), "mod", "tidy", "-diff")
	if err != nil {
		return v, err
	}
	v.TidyOK = tidy.exit == 0
	if !v.TidyOK {
		log.WriteString("go mod tidy -diff reports the manifest is not tidy:\n")
		log.WriteString(tidy.text())
	}

	remaining, rescanLog, complete, err := t.rescan(ctx, dir, tools, expect)
	if err != nil {
		return v, err
	}
	log.WriteString(rescanLog)
	v.Remaining = remaining
	// Both conditions. A re-scan that did not complete cannot show that
	// anything is gone: the tool that would have reported the finding is also
	// the tool that did not run, and its silence is not evidence.
	v.RescanClean = complete && len(remaining) == 0

	if !v.RescanClean {
		for _, target := range targets {
			fmt.Fprintf(&log, "  %s was targeted at %s\n", target.Module, target.To)
		}
	}
	v.Output = log.String()
	return v, nil
}

// rescan re-runs the scanners and reports what the group still has open.
//
// The returned bool is whether the re-scan COMPLETED, reported separately from
// what it found. Collapsing the two is the defect this whole function exists
// to avoid: a scanner that could not be executed finds nothing, and so does a
// repository that is genuinely fixed.
func (t *Toolchain) rescan(ctx context.Context, dir string, tools, expect []string) ([]string, string, bool, error) {
	result, err := t.Rescan.Rescan(ctx, dir, tools)
	if err != nil {
		return nil, "", false, err
	}

	var log strings.Builder
	complete := true
	if len(result.Failed) > 0 {
		complete = false
		for _, name := range sortedKeys(result.Failed) {
			fmt.Fprintf(&log, "re-scan INCOMPLETE: %s could not run: %s\n", name, result.Failed[name])
		}
		log.WriteString("A scanner that did not run reports nothing, which is also what a fixed " +
			"repository reports. The verification therefore fails rather than treating the silence as a " +
			"clean result (VM-F-205).\n")
	}

	wanted := map[string]bool{}
	for _, id := range expect {
		wanted[id] = true
	}
	var remaining []string
	seen := map[string]bool{}
	for _, id := range result.Reported {
		// Scoped to what this group was asked to close (OQ-AUDIT-06). A
		// re-scan sees the whole repository, and failing on another group's
		// findings would make a repository with two vulnerable modules
		// unremediable, one group blocking the next for ever.
		if len(wanted) > 0 && !wanted[id] {
			continue
		}
		if !seen[id] {
			seen[id] = true
			remaining = append(remaining, id)
		}
	}
	sort.Strings(remaining)

	if len(remaining) > 0 {
		fmt.Fprintf(&log, "re-scan with %s still reports: %s\n",
			strings.Join(result.Ran, ", "), strings.Join(remaining, ", "))
	}
	return remaining, log.String(), complete, nil
}

// --- commands ---------------------------------------------------------------

// result is one command's outcome.
type result struct {
	cmdline string
	exit    int
	out     string
}

func (r result) text() string {
	if strings.TrimSpace(r.out) == "" {
		return "$ " + r.cmdline + "\n"
	}
	return "$ " + r.cmdline + "\n" + strings.TrimRight(r.out, "\n") + "\n"
}

// run executes one command inside the sandbox.
//
// A non-zero exit is a RESULT, not an error: `go build` exits non-zero
// because the repository does not compile, which is information the gate
// wants. An error means the command could not be executed at all, which is
// an operational failure of the worker rather than a fact about the
// repository, and the two must not be confused.
func (t *Toolchain) run(ctx context.Context, dir, name string, args ...string) (result, error) {
	res := result{cmdline: strings.TrimSpace(name + " " + strings.Join(args, " "))}

	if t.Sandbox == nil {
		return res, &sandbox.ErrNotIsolated{
			Reason: "the Go toolchain has no sandbox, so the repository's own build and test code " +
				"would run unconfined",
		}
	}
	// The sandbox decides the working directory, and it is the directory it
	// was built to confine. If the caller means a different one, the commands
	// would run somewhere other than where the caller believes — which for a
	// build-and-test is the difference between measuring this repository and
	// measuring whatever happens to be in the clone.
	if clone := t.Sandbox.Policy().CloneDir; clone != "" && !samePath(clone, dir) {
		return res, fmt.Errorf(
			"gotool: asked to work in %s but the sandbox confines %s. Refusing rather than running "+
				"there: the commands would execute in the sandbox's directory while the caller recorded "+
				"the result against this one", dir, clone)
	}

	cmd, err := t.Sandbox.Command(ctx, name, args...)
	if err != nil {
		return res, err
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf

	runErr := cmd.Run()
	res.out = buf.String()
	if runErr != nil {
		if code, ok := exitCode(runErr); ok {
			res.exit = code
			return res, nil
		}
		return res, fmt.Errorf("gotool: executing %s: %w: %s", res.cmdline, runErr, excerpt(res.out))
	}
	return res, nil
}

func (t *Toolchain) goBin() string {
	if t.Go != "" {
		return t.Go
	}
	return "go"
}

func (t *Toolchain) gitBin() string {
	if t.Git != "" {
		return t.Git
	}
	return "git"
}

// resolvedVersions reads back what each module actually ended up at.
//
// From `go list -m`, which reports the module graph, rather than from the
// target that was requested. A proxy that has not mirrored a tag resolves
// lower and says so only in passing; recording the requested version would
// produce a pull request claiming a bump that did not happen.
func (t *Toolchain) resolvedVersions(ctx context.Context, dir string, targets []remediate.Target) (map[string]string, string, error) {
	out := map[string]string{}
	var log strings.Builder

	for _, target := range targets {
		res, err := t.run(ctx, dir, t.goBin(), "list", "-m", "-f", "{{.Version}}", target.Module)
		if err != nil {
			return nil, "", err
		}
		if res.exit != 0 {
			// The module is not in the graph at all — `go mod tidy` pruned it
			// because nothing imports it. Recorded rather than guessed.
			fmt.Fprintf(&log, "gotool: %s is not in the module graph after tidy; nothing imports it\n",
				target.Module)
			continue
		}
		version := strings.TrimSpace(res.out)
		out[target.Module] = version
		if version != target.To && store.CompareVersions(version, target.To) < 0 {
			fmt.Fprintf(&log, "gotool: %s resolved to %s, lower than the requested %s\n",
				target.Module, version, target.To)
		}
	}
	return out, log.String(), nil
}

// markIntentToAdd makes untracked files visible to `git diff`.
//
// Without it a fixer that ADDS a file — a new test, a new source file —
// produces an empty diff, and the content guard inspects nothing. It touches
// the index only; the working tree is unchanged.
func (t *Toolchain) markIntentToAdd(ctx context.Context, dir string) error {
	res, err := t.run(ctx, dir, t.gitBin(), "add", "--intent-to-add", "--", ".")
	if err != nil {
		return err
	}
	if res.exit != 0 {
		return fmt.Errorf("gotool: git add --intent-to-add failed: %s", excerpt(res.out))
	}
	return nil
}

func (t *Toolchain) changedFiles(ctx context.Context, dir string) ([]string, error) {
	res, err := t.run(ctx, dir, t.gitBin(), "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return nil, err
	}
	if res.exit != 0 {
		return nil, fmt.Errorf("gotool: git status failed: %s", excerpt(res.out))
	}

	var out []string
	for _, line := range strings.Split(res.out, "\n") {
		if len(line) < 4 {
			continue
		}
		path := strings.TrimSpace(line[3:])
		// A rename reads "old -> new"; the new path is the one that exists.
		if i := strings.Index(path, " -> "); i >= 0 {
			path = path[i+4:]
		}
		out = append(out, strings.Trim(path, `"`))
	}
	sort.Strings(out)
	return out, nil
}

func (t *Toolchain) diff(ctx context.Context, dir string) ([]byte, error) {
	res, err := t.run(ctx, dir, t.gitBin(), "diff", "HEAD")
	if err != nil {
		return nil, err
	}
	if res.exit != 0 {
		return nil, fmt.Errorf("gotool: git diff failed: %s", excerpt(res.out))
	}
	return []byte(res.out), nil
}

// --- the manifest snapshot --------------------------------------------------

// manifest is go.mod and go.sum as they were before any bump.
//
// Held in memory rather than restored with git, so a bisect retry cannot
// discard a source change somebody else made to the tree. `git checkout -- .`
// would be shorter and would also silently revert an agent's work.
type manifest struct {
	mod []byte
	sum []byte
	// sumPresent distinguishes a repository with no go.sum from one whose
	// go.sum is empty. Restoring the wrong one of those leaves a file the
	// repository never had, which the guard then reports as an added file.
	sumPresent bool
}

func readManifest(dir string) (manifest, error) {
	var m manifest
	mod, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return m, fmt.Errorf("gotool: reading go.mod in %s: %w", dir, err)
	}
	m.mod = mod

	sum, err := os.ReadFile(filepath.Join(dir, "go.sum"))
	switch {
	case err == nil:
		m.sum, m.sumPresent = sum, true
	case os.IsNotExist(err):
	default:
		return m, fmt.Errorf("gotool: reading go.sum in %s: %w", dir, err)
	}
	return m, nil
}

func (m manifest) restore(dir string) error {
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), m.mod, 0o644); err != nil {
		return fmt.Errorf("gotool: restoring go.mod: %w", err)
	}
	sumPath := filepath.Join(dir, "go.sum")
	if !m.sumPresent {
		if err := os.Remove(sumPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("gotool: removing the go.sum this repository did not have: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(sumPath, m.sum, 0o644); err != nil {
		return fmt.Errorf("gotool: restoring go.sum: %w", err)
	}
	return nil
}

// --- helpers ----------------------------------------------------------------

func without(targets []remediate.Target, module string) []remediate.Target {
	out := make([]remediate.Target, 0, len(targets))
	for _, t := range targets {
		if t.Module != module {
			out = append(out, t)
		}
	}
	return out
}

func targetNames(targets []remediate.Target) string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.Module)
	}
	return strings.Join(out, ", ")
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// exitCode reports a command's exit status, and false if the command never
// ran at all.
//
// The distinction is the one run() rests on: "the repository does not compile"
// and "the toolchain is not installed" are both non-nil errors from exec, and
// treating the second as the first would record a worker's own broken
// deployment as a fact about somebody's code.
func exitCode(err error) (int, bool) {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), true
	}
	return 0, false
}

func samePath(a, b string) bool {
	ra, err := filepath.EvalSymlinks(a)
	if err != nil {
		ra = filepath.Clean(a)
	}
	rb, err := filepath.EvalSymlinks(b)
	if err != nil {
		rb = filepath.Clean(b)
	}
	return ra == rb
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func excerpt(s string) string {
	const limit = 400
	s = strings.TrimSpace(s)
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}
