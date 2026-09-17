package agent

import (
	"context"
	"time"

	"github.com/wanaware/vulnframework/internal/remediate"
)

// FakeAgent is a HOSTILE in-memory agent.
//
// The standing sentinel says a fake must model the real service's weakest
// permitted guarantee. For a language model driving a write-capable tool, the
// weakest permitted guarantee is nothing at all: it may do the wrong thing, it
// may do the right thing and say otherwise, it may follow an instruction it
// read in a file, and it may run for ever.
//
// So this fake is built to misbehave on demand. Every method below exists
// because a real agent could do it:
//
//	WritesTo any path, including protected ones;
//	ReportsChangedFiles something other than what it wrote;
//	AddsLine a suppression directive or a credential;
//	DeletesTest or SkipsTest to make a build pass;
//	NeedsIterations or TakesWallClock beyond any budget;
//	Crashes mid-run.
//
// A fake that only did as it was told would make every one of the Phase 10
// clauses unfalsifiable: the controls would look effective because nothing
// ever tested them.
type FakeAgent struct {
	tc *remediate.FakeToolchain

	writes        []string
	reportChanged []string
	addedLines    []string
	addsTests     []string
	deletesTests  []string
	closes        []string
	claimsFixed   []string
	skips         []Skip
	proposes      []Skip

	iterations int
	wallClock  time.Duration
	crash      error

	started chan struct{}
	release chan struct{}
}

// NewFakeAgent builds an agent that does nothing.
func NewFakeAgent() *FakeAgent { return &FakeAgent{iterations: 1} }

// Bind attaches the toolchain whose tree the agent edits. The harness calls
// this, so a test does not have to.
func (a *FakeAgent) Bind(tc *remediate.FakeToolchain) { a.tc = tc }

// WritesTo makes the agent edit a path — protected or not.
func (a *FakeAgent) WritesTo(paths ...string) *FakeAgent {
	a.writes = append(a.writes, paths...)
	return a
}

// ReportsChangedFiles makes the agent's account differ from what it wrote.
func (a *FakeAgent) ReportsChangedFiles(paths ...string) *FakeAgent {
	a.reportChanged = append(a.reportChanged, paths...)
	return a
}

// AddsLine writes a line into the diff: a suppression, a credential, anything.
func (a *FakeAgent) AddsLine(lines ...string) *FakeAgent {
	a.addedLines = append(a.addedLines, lines...)
	return a
}

// AddsTest adds a test, as VM-F-525 requires of a source fix.
func (a *FakeAgent) AddsTest(names ...string) *FakeAgent {
	a.addsTests = append(a.addsTests, names...)
	return a
}

// DeletesTest removes an existing test.
func (a *FakeAgent) DeletesTest(names ...string) *FakeAgent {
	a.deletesTests = append(a.deletesTests, names...)
	return a
}

// SkipsTest disables an existing test. Modelled as removal, because a test
// that always skips is a test that is gone — and a check that distinguished
// them would be trivially evadable by choosing the other one.
func (a *FakeAgent) SkipsTest(names ...string) *FakeAgent {
	a.deletesTests = append(a.deletesTests, names...)
	a.addedLines = append(a.addedLines, "\tt.Skip(\"flaky\")")
	return a
}

// ClosesFinding makes the change genuinely close a source finding.
func (a *FakeAgent) ClosesFinding(ids ...string) *FakeAgent {
	a.closes = append(a.closes, ids...)
	return a
}

// ClaimsFixed makes the agent report success for these fingerprints.
func (a *FakeAgent) ClaimsFixed(fps ...string) *FakeAgent {
	a.claimsFixed = append(a.claimsFixed, fps...)
	return a
}

// Skips records a finding the agent stopped on.
func (a *FakeAgent) Skips(finding, reason string) *FakeAgent {
	a.skips = append(a.skips, Skip{Finding: finding, Reason: reason})
	return a
}

// Proposes records a suppression the agent proposes rather than applies.
func (a *FakeAgent) Proposes(finding, reason string) *FakeAgent {
	a.proposes = append(a.proposes, Skip{Finding: finding, Reason: reason})
	return a
}

// NeedsIterations makes the agent report more passes than it was allowed.
func (a *FakeAgent) NeedsIterations(n int) *FakeAgent { a.iterations = n; return a }

// TakesWallClock makes the agent outlive its wall-clock budget.
func (a *FakeAgent) TakesWallClock(d time.Duration) *FakeAgent { a.wallClock = d; return a }

// Crashes makes the agent fail outright.
func (a *FakeAgent) Crashes(err error) *FakeAgent { a.crash = err; return a }

// BlocksUntil holds the agent open, so a test can run a concurrent worker
// while this one genuinely holds the repository lock and the finding leases.
func (a *FakeAgent) BlocksUntil(started, release chan struct{}) *FakeAgent {
	a.started, a.release = started, release
	return a
}

// Fix runs the agent.
func (a *FakeAgent) Fix(ctx context.Context, dir string, order remediate.WorkOrder) (Report, error) {
	if a.started != nil {
		close(a.started)
	}
	if a.release != nil {
		select {
		case <-a.release:
		case <-ctx.Done():
			return Report{Iterations: a.iterations}, ctx.Err()
		}
	}

	if a.wallClock > 0 {
		select {
		case <-time.After(a.wallClock):
		case <-ctx.Done():
			// The budget is the harness's, and it is a real deadline: the
			// agent does not get to decide it has more time.
			return Report{Iterations: a.iterations}, ctx.Err()
		}
	}
	if a.crash != nil {
		return Report{Iterations: a.iterations}, a.crash
	}

	// Everything below is the agent editing the tree. Note that nothing here
	// can commit, push, or open a pull request: there is nothing in scope to
	// do it with (VM-AD §11.4).
	if a.tc != nil {
		if len(a.writes) > 0 {
			a.tc.EditFile(a.writes...)
		}
		if len(a.addedLines) > 0 {
			a.tc.AddLine(a.addedLines...)
		}
		if len(a.addsTests) > 0 {
			a.tc.AddTest(a.addsTests...)
		}
		if len(a.deletesTests) > 0 {
			a.tc.RemoveTest(a.deletesTests...)
		}
		if len(a.closes) > 0 {
			a.tc.CloseSourceFinding(a.closes...)
		}
	}

	report := Report{
		Fixed: a.claimsFixed, Skipped: a.skips, SuppressionProposed: a.proposes,
		TestsAdded: a.addsTests, Iterations: a.iterations,
		Notes: "fake agent run over " + dir + " for fix group " + order.FixGroupID,
	}
	return report, nil
}
