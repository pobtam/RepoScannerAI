package remediate

import (
	"context"

	"github.com/wanaware/vulnframework/internal/model"
)

// Fixer produces a working tree. It does nothing else.
//
// This is the seam that lets the agentic worker INHERIT the deterministic
// worker's safety machinery rather than re-implement it. Everything dangerous
// — the deny-list guard, the commit identity, the push, the pull request, the
// repository lock, the finding leases, the state liveness on every exit path —
// lives in Worker, on the far side of this interface, and a Fixer cannot reach
// any of it.
//
// That is a structural guarantee, not a convention. A Fixer is handed a
// directory and a fix group; it has no store, no pull-request surface and no
// credentials. An implementation that wanted to push could not: there is
// nothing in scope to push with (VM-AD §11.4).
type Fixer interface {
	// Name identifies the fixer in commit messages and logs, so a change is
	// attributable to the thing that produced it.
	Name() string

	// Actionable reports whether this fixer can act on the group at all.
	//
	// It exists because "nothing to do" is fixer-specific and was previously
	// decided by the worker: a group with no module bumps is nothing for the
	// deterministic bumper and is ordinary work for an agent. Leaving that
	// judgement in the worker meant every source-level group silently became
	// a no-op the moment an agent was plugged in.
	Actionable(group FixGroup) bool

	// Apply changes the working tree at dir to address the group.
	//
	// Its Applied return is the fixer's ACCOUNT of what it did. The harness
	// treats it as a claim: the guard reads the tree, never this (VM-F-510).
	Apply(ctx context.Context, dir string, group FixGroup) (Applied, error)
}

// DeterministicFixer performs dependency bumps with no inference (VM-ADR-09).
type DeterministicFixer struct {
	Toolchain Toolchain
}

func (DeterministicFixer) Name() string { return "deterministic-bump" }

// Actionable reports whether the group implies any module bump.
func (f DeterministicFixer) Actionable(group FixGroup) bool {
	return len(group.Targets()) > 0
}

func (f DeterministicFixer) Apply(ctx context.Context, dir string, group FixGroup) (Applied, error) {
	return f.Toolchain.Apply(ctx, dir, group.Targets())
}

// FixerRefusal is an error a fixer returns that maps to an outcome on the
// finding rather than to a hard failure of the job.
//
// The distinction matters and is not cosmetic. "The agent ran out of budget"
// and "the agent tried to delete a test" are both failures, and they call for
// opposite responses: the first routes the finding to a human and the run
// continues, the second is an attempt to subvert a control and must hard-fail
// and alert, exactly as a deny-list violation does.
//
// An error that does NOT implement this interface propagates as a hard
// failure. That default is deliberate: a new failure mode nobody has
// classified yet should stop the job, not quietly become a ticket.
type FixerRefusal interface {
	error
	// Refusal returns the reason to record on the finding, and true if the
	// attempt should route to a human rather than hard-fail.
	Refusal() (model.ReasonCode, bool)
}

// PostGuard is an optional Fixer capability: checks that run AFTER the
// deny-list guard has passed.
//
// The ordering is the whole reason this exists. The guard's verdict is a
// security verdict and must come first, unconditionally: an agent that edits
// a CI workflow AND forgets to add a test must be reported as an attempted CI
// edit, not as a missing test. An operator reading the second would not
// alert, and the alert is the only thing that catches a privilege-escalation
// attempt.
//
// So quality checks — a weakened test suite, a source fix with no test — live
// here, behind the guard, rather than inside Apply where they would pre-empt
// it.
type PostGuard interface {
	// PostGuardCheck inspects the tree after the guard has accepted it.
	PostGuardCheck(ctx context.Context, dir string, group FixGroup) error
}
