// Package agent is the agentic fix worker (VM-AD §11.4).
//
// It is the one component in this system that can edit the continuous
// integration that gates its own pull requests, and the design answer is that
// it cannot: the agent is a remediate.Fixer, and a Fixer is handed a working
// directory and a fix group. It has no store, no pull-request surface, no
// credentials and no guard. Every dangerous capability lives on the far side
// of that interface, in the worker the agent SHARES with the deterministic
// bumper built in Phase 9a.
//
// That sharing is the point. The deny-list guard is not re-implemented here,
// and it is not called here: it runs in the worker, after the agent has
// finished, against the tree rather than against the agent's account of what
// it did (VM-F-510). An agent cannot bypass a guard it has no way to reach,
// and a future agent — a better model, a different vendor — inherits the same
// property without anyone having to remember to.
//
// §3 lists a guard.go inside this package. There is deliberately none: a
// second guard implementation would be a second thing to keep correct, and the
// weaker of the two would decide.
package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/remediate"
)

// Agent produces a working tree. It does not commit, push, or open a pull
// request — the harness does that (VM-AD §11.4).
type Agent interface {
	// Fix runs against the working tree at dir.
	//
	// The Report it returns is the agent's ACCOUNT of what it did. Nothing in
	// the harness trusts it for a safety decision: it is used for the pull
	// request body, the action log and the iteration count, all of which are
	// descriptive. The guard, the verification and the test-inventory check
	// all read the tree.
	Fix(ctx context.Context, dir string, order remediate.WorkOrder) (Report, error)
}

// Report is what the agent says it did.
type Report struct {
	// Fixed names the fingerprints the agent believes it addressed.
	Fixed []string `json:"fixed"`
	// Skipped names findings it could not fix, with why. A finding it stopped
	// on is reported and the rest continue (VM-AD §11.4).
	Skipped []Skip `json:"skipped,omitempty"`
	// SuppressionProposed is the only legitimate route to a suppression: the
	// agent may PROPOSE one in its output, never apply one to the tree
	// (VM-F-507).
	SuppressionProposed []Skip `json:"suppression_proposed,omitempty"`
	// Breaking names findings whose fix is a breaking change, stated
	// explicitly rather than left for a reviewer to discover.
	Breaking []string `json:"breaking,omitempty"`
	// TestsAdded names tests the agent says it added (VM-F-525). Checked
	// against the tree, not believed.
	TestsAdded []string `json:"tests_added,omitempty"`
	// ManualVerification is what a reviewer must do by hand where a fix was
	// not unit-testable.
	ManualVerification string `json:"manual_verification,omitempty"`
	// Iterations is how many passes the agent took, for the budget accounting
	// and the action log.
	Iterations int `json:"iterations"`
	// Notes is free narrative for the pull request body.
	Notes string `json:"notes,omitempty"`
}

// Skip is one finding the agent did not fix, and why.
type Skip struct {
	Finding string `json:"finding"`
	Reason  string `json:"reason"`
}

// Budget bounds an agent run, enforced by the HARNESS rather than by the agent
// (VM-AD §11.4).
//
// Self-imposed limits are not limits. An agent that has lost the thread is
// exactly the agent least likely to notice it has, and a budget it enforces on
// itself fails in the case it exists for.
type Budget struct {
	MaxIterations int
	MaxWallClock  time.Duration
}

func (b Budget) withDefaults() Budget {
	if b.MaxIterations <= 0 {
		b.MaxIterations = 40
	}
	if b.MaxWallClock <= 0 {
		b.MaxWallClock = 30 * time.Minute
	}
	return b
}

// ErrBudgetExhausted reports an agent run stopped by its budget.
//
// Distinct from a failure: the agent did not do anything wrong, it ran out of
// room. The finding returns to a human with AGENT_GAVE_UP, and nothing is
// pushed (VM-AD §11.4).
type ErrBudgetExhausted struct {
	Limit      string
	Iterations int
	Elapsed    time.Duration
}

func (e *ErrBudgetExhausted) Error() string {
	return fmt.Sprintf(
		"agent: budget exhausted on %s after %d iterations and %s. The working tree is discarded: "+
			"an agent stopped mid-thought has a partially applied change, and pushing one is worse than "+
			"pushing nothing (VM-F-506)",
		e.Limit, e.Iterations, e.Elapsed)
}

// ErrTestsWeakened reports that a change removed or disabled an existing test.
//
// Its own type because the failure needs to be legible as itself. Deleting the
// test that fails is a locally rational way to make a build pass, and every
// downstream signal agrees it worked: build green, tests green, and a coverage
// delta nobody reads. Reporting it as a generic verification failure would
// send a reviewer looking at the wrong thing.
type ErrTestsWeakened struct {
	Removed []string
}

func (e *ErrTestsWeakened) Error() string {
	return fmt.Sprintf(
		"agent: refusing the change: it removed or disabled %d existing test(s) — %v. "+
			"A build made green by deleting the test that objected is not a fix, and nothing downstream "+
			"would have noticed: the only signal that disagreed is the one that was removed",
		len(e.Removed), e.Removed)
}

// ErrNoTestAdded reports a source-level fix with no accompanying test
// (VM-F-525).
type ErrNoTestAdded struct{ Findings []string }

func (e *ErrNoTestAdded) Error() string {
	return fmt.Sprintf(
		"agent: refusing the change: it edits source to fix %v and adds no test. A fix with no test is a "+
			"fix nothing will notice regressing (VM-F-525). Where a fix genuinely is not unit-testable, "+
			"the agent must say so and describe the manual verification instead",
		e.Findings)
}

// ErrNoTestSuite reports an attempted agentic source fix in a repository with
// no executable test suite (VM-F-524).
type ErrNoTestSuite struct{ Repo string }

func (e *ErrNoTestSuite) Error() string {
	return fmt.Sprintf(
		"agent: refusing to attempt a source-level fix in %s: it has no executable test suite. There is "+
			"nothing for the required new test to join and nothing to verify the change against, so the "+
			"result would be an unreviewed guess (VM-F-524)",
		e.Repo)
}

// Refusal routes budget exhaustion to a human: the agent did nothing wrong, it
// ran out of room, and the finding is still worth someone's time (VM-AD §11.4).
func (e *ErrBudgetExhausted) Refusal() (model.ReasonCode, bool) {
	return model.ReasonAgentGaveUp, true
}

// Refusal routes a missing test suite to a ticket, as VM-F-524 requires.
func (e *ErrNoTestSuite) Refusal() (model.ReasonCode, bool) {
	return model.ReasonNoTestCoverage, true
}

// ErrTestsWeakened and ErrNoTestAdded deliberately do NOT implement
// FixerRefusal. Removing a test to make a build pass is an attempt to subvert
// a control, not a failure to fix something, and it gets the same response as
// a deny-list violation: hard-fail the job and alert a human. Turning it into
// a ticket would file it alongside ordinary work.
