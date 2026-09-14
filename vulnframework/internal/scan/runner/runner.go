// Package runner executes pinned scanner binaries (VM-AD §3, §8.3).
//
// Every scanner binary sits behind CommandRunner so the system builds, runs and
// passes its tests with no tools installed, no credentials and no network. Exec
// is the real implementation; Fake serves captured fixtures and is what the
// adapter tests use.
package runner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// Result is the outcome of running one command.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// CommandRunner executes a pinned tool in a directory.
//
// A non-zero exit code is reported in Result, not as an error: many scanners
// exit non-zero precisely because they found something. An error means the tool
// could not be executed at all, which is a coverage gap (VM-F-205).
type CommandRunner interface {
	Run(ctx context.Context, dir string, name string, args ...string) (Result, error)
}

// Exec runs real binaries.
type Exec struct{}

// Run executes name in dir.
func (Exec) Run(ctx context.Context, dir, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	err := cmd.Run()
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); ok {
			// The tool ran and reported findings or a soft failure.
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		// The tool could not be executed: not found, permission denied,
		// context cancelled. That is a coverage gap, and the caller must be
		// able to tell it apart from a clean scan.
		return res, fmt.Errorf("runner: executing %s: %w", name, err)
	}
	return res, nil
}

func asExitError(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

// FakeInvocation records one call made against a Fake.
type FakeInvocation struct {
	Dir  string
	Name string
	Args []string
}

// Command returns the invocation as a command line, for assertions.
func (i FakeInvocation) Command() string {
	return strings.TrimSpace(i.Name + " " + strings.Join(i.Args, " "))
}

// Fake is an offline CommandRunner. It returns canned results keyed by tool
// name and records what it was asked to run.
//
// This is the mechanism that keeps Phases 0–2 fully offline: an adapter under
// test never touches a binary, a network or a credential.
type Fake struct {
	// Results maps a tool name to the result it should return.
	Results map[string]Result
	// Errors maps a tool name to an execution failure, for exercising the
	// coverage-gap path (VM-F-204, VM-F-205).
	Errors map[string]error

	invocations []FakeInvocation
}

// NewFake builds an empty Fake.
func NewFake() *Fake {
	return &Fake{Results: map[string]Result{}, Errors: map[string]error{}}
}

// WithStdout registers stdout for a tool.
func (f *Fake) WithStdout(tool string, stdout []byte) *Fake {
	if f.Results == nil {
		f.Results = map[string]Result{}
	}
	f.Results[tool] = Result{Stdout: stdout}
	return f
}

// WithFailure registers an execution failure for a tool, so the caller records
// a coverage gap rather than a clean result.
func (f *Fake) WithFailure(tool string, err error) *Fake {
	if f.Errors == nil {
		f.Errors = map[string]error{}
	}
	f.Errors[tool] = err
	return f
}

// Run returns the canned result for the tool being invoked.
func (f *Fake) Run(_ context.Context, dir, name string, args ...string) (Result, error) {
	f.invocations = append(f.invocations, FakeInvocation{Dir: dir, Name: name, Args: args})

	key := toolKey(name, args)
	if err, ok := f.Errors[key]; ok {
		return Result{}, err
	}
	if res, ok := f.Results[key]; ok {
		return res, nil
	}
	return Result{}, fmt.Errorf("runner: fake has no result registered for %q (registered: %s)",
		key, strings.Join(f.registered(), ", "))
}

// toolKey derives the lookup key from an invocation. npm audit is the one tool
// whose identity is the subcommand rather than the binary.
func toolKey(name string, args []string) string {
	if name == "npm" && len(args) > 0 && args[0] == "audit" {
		return "npm-audit"
	}
	return name
}

func (f *Fake) registered() []string {
	var out []string
	for k := range f.Results {
		out = append(out, k)
	}
	for k := range f.Errors {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Invocations returns the calls made, in order.
func (f *Fake) Invocations() []FakeInvocation { return f.invocations }
