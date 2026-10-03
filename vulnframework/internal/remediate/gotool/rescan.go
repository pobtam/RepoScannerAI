package gotool

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
)

// Rescan is what a re-run of the scanners saw.
//
// Reported and Failed are separate fields, and that separation is the single
// most important thing in this file. A scanner that could not be executed
// reports nothing; a repository whose vulnerability is genuinely gone also
// reports nothing. One structure that could only say "nothing came back" would
// make the two indistinguishable, and the second is the only one that is
// evidence of a fix.
type Rescan struct {
	// Reported is every identifier the scanners still name, in any of the
	// forms a group may be expecting: advisory id, alias, rule id, fingerprint.
	// The gate matches on whichever one comes back.
	Reported []string
	// Ran names the tools that executed and produced a parseable result.
	Ran []string
	// Failed maps a tool that could NOT be executed, or whose output could not
	// be parsed, to why. A non-empty Failed means the re-scan is incomplete
	// and nothing can be concluded from its silence (VM-F-205).
	Failed map[string]string
}

// Rescanner re-runs the scanners that produced a fix group's findings.
//
// Behind an interface for the same reason every other external system in this
// build is: the package has to compile, run and pass its tests with no scanner
// installed.
type Rescanner interface {
	Rescan(ctx context.Context, dir string, tools []string) (Rescan, error)
}

// AdapterRescan re-runs the real scanner adapters.
type AdapterRescan struct {
	// Registry supplies the adapters, each pinned to its version from
	// config/tools.lock.
	Registry *scan.Registry
	// Profile is the repository the re-scan is of. The adapters consult it to
	// decide whether they apply.
	Profile scan.RepoProfile
	// Repo is the repository identity. Fingerprints incorporate it
	// (VM-F-103), so a re-scan computing fingerprints without it would compute
	// different ones and match nothing.
	Repo string
}

// Rescan runs each named tool and collects every identifier still reported.
func (a AdapterRescan) Rescan(ctx context.Context, dir string, tools []string) (Rescan, error) {
	out := Rescan{Failed: map[string]string{}}
	if a.Registry == nil {
		return out, fmt.Errorf("gotool: AdapterRescan has no registry; no scanner could be run")
	}
	if len(tools) == 0 {
		// Not an error and not a clean result. The caller asked for a re-scan
		// with no tools, which answers nothing about anything.
		out.Failed["(none named)"] = "the fix group named no tools to re-run, so nothing was re-scanned"
		return out, nil
	}

	seen := map[string]bool{}
	for _, name := range tools {
		if seen[name] {
			continue
		}
		seen[name] = true

		adapter, ok := a.Registry.Get(name)
		if !ok {
			out.Failed[name] = "no adapter is registered under this name"
			continue
		}

		raw, err := adapter.Run(ctx, dir, scan.RunOpts{Mode: scan.ModeFull})
		if err != nil {
			// The tool could not be executed. This is a coverage gap
			// (VM-F-205), not a clean scan.
			out.Failed[name] = err.Error()
			continue
		}
		raw.Repo, raw.Dir = a.Repo, dir

		findings, err := adapter.Normalize(raw)
		if err != nil {
			// The tool ran and its output could not be believed — typically a
			// format change on upgrade. Treating that as "found nothing"
			// would convert a broken adapter into a passing verification.
			out.Failed[name] = fmt.Sprintf("output could not be normalised: %v", err)
			continue
		}

		out.Ran = append(out.Ran, name)
		for _, f := range findings {
			out.Reported = append(out.Reported, identifiersOf(f)...)
		}
	}

	sort.Strings(out.Ran)
	out.Reported = dedupe(out.Reported)
	return out, nil
}

// identifiersOf returns every name a finding could be expecting to be matched
// under.
//
// It mirrors remediate.Expect, which builds the other side of the comparison.
// The two must agree: a group expecting a rule id and a re-scan reporting only
// fingerprints would never match, and the verification would pass on every
// code finding in the fleet without ever having checked one.
func identifiersOf(f model.RawFinding) []string {
	var out []string
	add := func(id string) {
		if id != "" {
			out = append(out, id)
		}
	}
	add(f.PrimaryID)
	for _, alias := range f.Aliases {
		add(alias)
	}
	add(f.RuleID)
	add(f.DetectorRuleID)
	add(f.CheckID)

	// The fingerprint, computed the same way the pipeline computes it, so a
	// group expecting one matches. Validate first: a finding missing an
	// identity input produces no fingerprint, and inventing one would put a
	// guessed value into an identity field.
	if err := fingerprint.Validate(f); err == nil {
		add(fingerprint.Compute(f))
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// --- Fake --------------------------------------------------------------------

// FakeRescan is an offline rescanner that models the WEAKEST permitted
// behaviour of a real one (the standing sentinel).
//
// What it can be made to do is what actually happens: a tool that is not
// installed, a tool whose output format changed under it, and a catalogue that
// still reports a finding the bump was supposed to close.
type FakeRescan struct {
	mu sync.Mutex

	reported map[string]bool
	failures map[string]string
	ran      []string
	err      error
	calls    [][]string
}

// NewFakeRescan builds a rescanner that reports nothing and fails at nothing.
func NewFakeRescan() *FakeRescan {
	return &FakeRescan{reported: map[string]bool{}, failures: map[string]string{}}
}

// StillReports makes the re-scan keep naming an identifier.
func (f *FakeRescan) StillReports(ids ...string) *FakeRescan {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range ids {
		f.reported[id] = true
	}
	return f
}

// Stops makes the re-scan stop naming an identifier, as a real fix does.
func (f *FakeRescan) Stops(ids ...string) *FakeRescan {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range ids {
		delete(f.reported, id)
	}
	return f
}

// ToolFails makes a tool impossible to execute, which must never read as a
// clean result.
func (f *FakeRescan) ToolFails(tool, why string) *FakeRescan {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures[tool] = why
	return f
}

// FailWith makes the re-scan itself fail, as a rescanner that cannot reach the
// clone does.
func (f *FakeRescan) FailWith(err error) *FakeRescan {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
	return f
}

// Calls returns the tool sets the rescanner was asked for, in order.
func (f *FakeRescan) Calls() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.calls))
	copy(out, f.calls)
	return out
}

// Rescan returns the configured result.
func (f *FakeRescan) Rescan(_ context.Context, _ string, tools []string) (Rescan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string(nil), tools...))

	if f.err != nil {
		return Rescan{}, f.err
	}

	out := Rescan{Failed: map[string]string{}}
	if len(tools) == 0 {
		// Conformance with AdapterRescan, which refuses the same case. A fake
		// that was kinder than production here would let a group whose tool
		// list was lost verify clean in every test, and only production would
		// find out.
		out.Failed["(none named)"] = "the fix group named no tools to re-run, so nothing was re-scanned"
		return out, nil
	}
	for _, tool := range tools {
		if why, bad := f.failures[tool]; bad {
			out.Failed[tool] = why
			continue
		}
		out.Ran = append(out.Ran, tool)
	}
	for id := range f.reported {
		out.Reported = append(out.Reported, id)
	}
	sort.Strings(out.Ran)
	sort.Strings(out.Reported)
	f.ran = out.Ran
	return out, nil
}

// ErrRescanUnreachable is what a rescanner returns when it cannot look at all.
var ErrRescanUnreachable = errors.New("gotool: the re-scan could not reach the working tree")
