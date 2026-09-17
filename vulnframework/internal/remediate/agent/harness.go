package agent

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/remediate"
)

// Harness runs an agent under a budget and reports what it changed.
//
// It is a remediate.Fixer and nothing more. The guard, the push, the pull
// request and the state machine are the worker's, shared with the
// deterministic bumper — so everything Phase 9a proved about those applies
// here without being restated (VM-AD §11.2 steps 5–9).
//
// What the harness adds is the two checks that only make sense for an agent:
// the budget, because an agent can run indefinitely; and the test-inventory
// comparison, because an agent can make a build green by removing the test
// that objected.
type Harness struct {
	Agent     Agent
	Toolchain remediate.Toolchain
	Budget    Budget

	// RequireTestSuite and HasTestSuite implement VM-F-524. They are separate
	// so the caller states the repository's fact rather than the harness
	// inferring it from an absent inventory, which would also be true of a
	// repository whose tests simply failed to list.
	RequireTestSuite bool
	HasTestSuite     bool

	// SecretPaths lists files in this repository that currently hold an
	// unresolved secret finding (VM-F-854). A function rather than a slice so
	// it is read at the moment of the check: a credential rotated during a
	// long agent run should free its file, and a snapshot taken at
	// construction would not know.
	SecretPaths func(ctx context.Context, repo string) ([]string, error)

	Clock func() time.Time

	mu                 sync.Mutex
	actions            []string
	lastReport         Report
	testsBefore        []string
	testsAfter         []string
	manualVerification string
}

func (h *Harness) Name() string { return "agentic-fix-worker" }

// Actionable is always true: an agent can attempt any group, which is the
// whole reason it exists. Whether it succeeds is what the guard, the
// verification and the re-scan decide.
func (h *Harness) Actionable(remediate.FixGroup) bool { return true }

func (h *Harness) now() time.Time {
	if h.Clock != nil {
		return h.Clock().UTC()
	}
	return time.Now().UTC()
}

// Actions returns everything the harness recorded about the run.
//
// Recovery must be loud, and so must autonomy: a change nobody can attribute
// is a change nobody can review, and an agent whose actions are not recorded
// cannot be audited afterwards — which is the only audit that matters for
// something that acts on its own.
func (h *Harness) Actions() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.actions...)
}

func (h *Harness) record(format string, args ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.actions = append(h.actions, fmt.Sprintf("[%s] %s", h.now().Format(time.RFC3339), fmt.Sprintf(format, args...)))
}

// LastReport is the agent's own account of the most recent run, for the pull
// request body. Descriptive only: nothing safety-bearing reads it.
func (h *Harness) LastReport() Report {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastReport
}

// Apply runs the agent against the working tree.
func (h *Harness) Apply(ctx context.Context, dir string, group remediate.FixGroup) (remediate.Applied, error) {
	budget := h.Budget.withDefaults()
	start := h.now()

	h.record("agent run starting for fix group %s (%d findings, budget %d iterations / %s)",
		group.ID, len(group.Findings), budget.MaxIterations, budget.MaxWallClock)

	// An offline agent edits the fake tree. A real one edits the filesystem;
	// either way the harness learns what changed by asking the toolchain
	// afterwards, never by asking the agent.
	if binder, ok := h.Agent.(interface {
		Bind(*remediate.FakeToolchain)
	}); ok {
		if tc, ok := h.Toolchain.(*remediate.FakeToolchain); ok {
			binder.Bind(tc)
		}
	}

	// VM-F-524, before anything runs. A source-level fix in a repository with
	// no test suite cannot satisfy VM-F-525 and cannot be verified.
	if h.RequireTestSuite && !h.HasTestSuite && touchesSource(group) {
		h.record("refused: %s has no executable test suite (VM-F-524)", group.Repo)
		return remediate.Applied{}, &ErrNoTestSuite{Repo: group.Repo}
	}

	// The test inventory BEFORE the agent touches anything. This is the
	// baseline the green-by-deletion check compares against, and it has to be
	// taken from the tree rather than from anything the agent says.
	before, err := h.Toolchain.TestInventory(ctx, dir)
	if err != nil {
		return remediate.Applied{}, err
	}
	h.record("test inventory before: %d tests", len(before))

	// The budget is the harness's, enforced with a context the agent cannot
	// extend. A self-imposed limit fails in exactly the case it exists for:
	// an agent that has lost the thread is the one least likely to notice.
	runCtx, cancel := context.WithTimeout(ctx, budget.MaxWallClock)
	defer cancel()

	report, err := h.Agent.Fix(runCtx, dir, h.order(group, budget))
	elapsed := h.now().Sub(start)

	if err != nil {
		if runCtx.Err() != nil {
			h.record("budget exhausted: wall clock after %s", elapsed)
			return remediate.Applied{}, &ErrBudgetExhausted{
				Limit: "wall clock", Iterations: report.Iterations, Elapsed: elapsed,
			}
		}
		h.record("agent failed after %d iterations: %v", report.Iterations, err)
		return remediate.Applied{}, fmt.Errorf("agent: %w", err)
	}
	if runCtx.Err() != nil {
		h.record("budget exhausted: wall clock after %s", elapsed)
		return remediate.Applied{}, &ErrBudgetExhausted{
			Limit: "wall clock", Iterations: report.Iterations, Elapsed: elapsed,
		}
	}
	if report.Iterations > budget.MaxIterations {
		h.record("budget exhausted: %d iterations exceeds %d", report.Iterations, budget.MaxIterations)
		return remediate.Applied{}, &ErrBudgetExhausted{
			Limit: "iteration count", Iterations: report.Iterations, Elapsed: elapsed,
		}
	}

	h.mu.Lock()
	h.lastReport = report
	h.mu.Unlock()

	h.record("agent finished in %d iterations (%s): claims %d fixed, %d skipped",
		report.Iterations, elapsed, len(report.Fixed), len(report.Skipped))
	for _, s := range report.Skipped {
		h.record("skipped %s: %s", s.Finding, s.Reason)
	}
	for _, s := range report.SuppressionProposed {
		// Proposed, never applied. The guard rejects an applied one
		// regardless, so this is the only route that reaches a human.
		h.record("suppression PROPOSED for %s: %s (not applied; VM-F-507)", s.Finding, s.Reason)
	}

	// The test inventory AFTER. Read from the tree: an agent that deleted a
	// test and did not mention it is the case this exists for.
	after, err := h.Toolchain.TestInventory(ctx, dir)
	if err != nil {
		return remediate.Applied{}, err
	}
	h.mu.Lock()
	h.testsBefore, h.testsAfter = before, after
	h.manualVerification = report.ManualVerification
	h.mu.Unlock()

	applied, err := h.Toolchain.Collect(ctx, dir)
	if err != nil {
		return remediate.Applied{}, err
	}

	h.record("changed %d file(s): %v", len(applied.ChangedFiles), applied.ChangedFiles)
	applied.Output = strings.Join(h.Actions(), "\n")
	return applied, nil
}

// PostGuardCheck runs the quality checks, AFTER the guard has accepted the
// tree (remediate.PostGuard).
//
// Deliberately not inside Apply. An agent that edited a CI workflow and also
// forgot to add a test must be reported as the first: "no test added" is a
// quality finding an operator triages tomorrow, and an attempted CI edit is an
// alert tonight. Running these first would relabel the second as the first.
func (h *Harness) PostGuardCheck(ctx context.Context, dir string, group remediate.FixGroup) error {
	h.mu.Lock()
	before, after, manual := h.testsBefore, h.testsAfter, h.manualVerification
	h.mu.Unlock()

	applied, err := h.Toolchain.Collect(ctx, dir)
	if err != nil {
		return err
	}
	changed := applied.ChangedFiles

	if removed := missing(before, after); len(removed) > 0 {
		h.record("REJECTED: the change removed or disabled %d existing test(s): %v", len(removed), removed)
		return &ErrTestsWeakened{Removed: removed}
	}

	// VM-F-854. Read from the tree's change set, and the secret paths read
	// fresh: a credential rotated during the run frees its file.
	if h.SecretPaths != nil {
		secret, err := h.SecretPaths(ctx, group.Repo)
		if err != nil {
			return err
		}
		if touched := intersect(changed, secret); len(touched) > 0 {
			h.record("REVERTED: the change touches %v, which hold unresolved secret findings (VM-F-854)", touched)
			return &ErrTouchedSecretPath{Repo: group.Repo, Paths: touched}
		}
	}
	added := missing(after, before)
	if touchesSource(group) && len(added) == 0 && manual == "" {
		h.record("REJECTED: source was changed and no test was added (VM-F-525)")
		return &ErrNoTestAdded{Findings: group.Fingerprints()}
	}
	if len(added) > 0 {
		h.record("tests added: %v", added)
	}
	return nil
}

// order builds the bounded instruction the agent consumes (VM-AD §11.1).
//
// The deny paths travel in the order for the agent's benefit — it should not
// waste a budget discovering them — but they are NOT the enforcement. The
// enforcement is the guard, after the fact, against the tree (VM-F-510).
func (h *Harness) order(group remediate.FixGroup, budget Budget) remediate.WorkOrder {
	return remediate.WorkOrder{
		Repo:       group.Repo,
		Mode:       "agentic",
		FixGroupID: group.ID,
		Branch:     group.Branch,
		Findings:   group.Findings,
		Policy: remediate.OrderPolicy{
			AllowMajor:       false,
			AllowSuppression: false,
			RequireTest:      true,
		},
		Budget: remediate.OrderBudget{
			MaxIterations:   budget.MaxIterations,
			MaxWallClockSec: int(budget.MaxWallClock.Seconds()),
		},
		BaselineRequired: true,
	}
}

// touchesSource reports whether the group requires a source-level change.
func touchesSource(group remediate.FixGroup) bool {
	for _, f := range group.Findings {
		if f.Category == model.CategoryCode {
			return true
		}
	}
	return false
}

// intersect returns the members of a that appear in b, normalised so a path
// spelled differently cannot slip past.
func intersect(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, s := range b {
		set[normalisePath(s)] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, s := range a {
		key := normalisePath(s)
		if set[key] && !seen[key] {
			seen[key] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// normalisePath matches the guard's normalisation, for the same reason: a
// check that compares raw strings is evaded by spelling the path differently.
func normalisePath(p string) string {
	s := strings.ReplaceAll(p, `\\`, "/")
	s = path.Clean(s)
	s = strings.TrimPrefix(s, "/")
	s = strings.TrimPrefix(s, "./")
	return strings.ToLower(s)
}

// missing returns entries of a that are absent from b.
func missing(a, b []string) []string {
	have := make(map[string]bool, len(b))
	for _, s := range b {
		have[s] = true
	}
	var out []string
	for _, s := range a {
		if !have[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
