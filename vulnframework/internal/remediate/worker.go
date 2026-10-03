package remediate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/remediate/guard"
	"github.com/wanaware/vulnframework/internal/store"
)

// Outcome is what one remediation attempt did.
type Outcome string

const (
	// OutcomePROpen — verified and pushed, pull request open.
	OutcomePROpen Outcome = "pr_open"
	// OutcomeAlreadyOpen — the fix group already has a pull request. Not a
	// failure: it is the idempotency guarantee working (VM-F-502).
	OutcomeAlreadyOpen Outcome = "already_open"
	// OutcomeDeferredLocked — another worker holds the repository. Not a
	// failure either: the repository is remediated next sweep. Treating it as a
	// failure would count correct serialisation as a coverage gap.
	OutcomeDeferredLocked Outcome = "deferred_locked"
	// OutcomeBaselineFailed — the repository was already broken (VM-F-504).
	OutcomeBaselineFailed Outcome = "baseline_failed"
	// OutcomeVerifyFailed — the change did not survive the gate; the branch was
	// discarded in full (VM-F-506).
	OutcomeVerifyFailed Outcome = "verify_failed"
	// OutcomeGuardViolation — the change touched a protected path or added a
	// suppression or a credential. Hard failure, alert (VM-F-508).
	OutcomeGuardViolation Outcome = "guard_violation"
	// OutcomePushRejected — the remote refused the push. Never forced.
	OutcomePushRejected Outcome = "push_rejected"
	// OutcomeNothingToDo — the group implied no bumps.
	OutcomeNothingToDo Outcome = "nothing_to_do"
	// OutcomeFixerRefused — the fixer declined the attempt for a reason that
	// belongs on the finding: an agent out of budget, a repository with no
	// test suite. The run continues; the finding goes to a human.
	OutcomeFixerRefused Outcome = "fixer_refused"
)

// Result is one attempt's outcome, with everything needed to explain it.
type Result struct {
	Group        FixGroup
	Outcome      Outcome
	Reason       *model.ReasonCode
	PullRequest  gh.PullRequest
	Applied      Applied
	Verification Verification
	Baseline     Check
}

// Worker is the deterministic remediation harness (VM-AD §11.2).
//
// The sequence is fixed and the guard's position in it is the point: steps 5
// and 6 run unconditionally, after the change and before any push, regardless
// of what the worker reports it did (principle P4).
type Worker struct {
	Store     store.Store
	PR        gh.PROps
	Guard     *guard.Guard
	Toolchain Toolchain

	// Fixer produces the working tree. Nil means the deterministic bumper.
	//
	// The agentic worker is a different Fixer behind this same Worker, which
	// is what makes "the agent inherits the guard" structural rather than a
	// promise: an agent cannot bypass a guard it has no way to reach.
	Fixer Fixer

	// Owner identifies this worker in the repository lock and finding leases.
	Owner string
	// LeaseTTL bounds how long a crashed worker can hold a repository or a
	// finding. Too long strands work; too short lets a second worker in while
	// the first is still running.
	LeaseTTL time.Duration

	Clock func() time.Time

	// Tools are the scanners re-run during verification. Empty means the tools
	// that produced the findings, derived from their provenance.
	Tools []string
}

func (w *Worker) now() time.Time {
	if w.Clock != nil {
		return w.Clock().UTC()
	}
	return time.Now().UTC()
}

// fixer returns the configured fixer, defaulting to the deterministic bumper.
func (w *Worker) fixer() Fixer {
	if w.Fixer != nil {
		return w.Fixer
	}
	return DeterministicFixer{Toolchain: w.Toolchain}
}

func (w *Worker) ttl() time.Duration {
	if w.LeaseTTL > 0 {
		return w.LeaseTTL
	}
	return 30 * time.Minute
}

// Remediate runs one fix group end to end.
//
// Acquisition order is repository lock OUTER, finding leases INNER, and the
// group's findings are leased under ONE repository acquisition (VM-AD §7.3).
// Fixed ordering makes deadlock impossible; batching holds the lock once per
// repository per attempt rather than once per finding.
func (w *Worker) Remediate(ctx context.Context, group FixGroup) (Result, error) {
	res := Result{Group: group}

	if group.Repo == "" || len(group.Findings) == 0 {
		return res, fmt.Errorf("remediate: refusing an empty fix group; it would push a branch with no change")
	}
	if w.Guard == nil {
		// Refusing to run without a guard is not defensive programming. A
		// worker that pushes with no guard installed is the privilege-
		// escalation loop the guard exists to prevent, and the absence is
		// invisible in any output.
		return res, fmt.Errorf("remediate: refusing to run with no guard installed (VM-F-508/510)")
	}

	now := w.now()

	// --- Repository lock, outer -------------------------------------------
	if err := w.Store.AcquireRepoLockAt(ctx, group.Repo, w.Owner, now.Add(w.ttl()), now); err != nil {
		if errors.Is(err, store.ErrRepoLocked) {
			res.Outcome = OutcomeDeferredLocked
			return res, nil
		}
		return res, err
	}
	defer func() {
		// Released on every path. A worker that finishes holding the lock
		// strands the repository until expiry, which looks like the repository
		// quietly dropping out of remediation.
		_ = w.Store.ReleaseRepoLock(ctx, group.Repo, w.Owner)
	}()

	// --- Idempotency: has this fix group already produced a pull request? ---
	//
	// Checked before any work. The branch name derives from the group identity,
	// so this is the mechanism for VM-F-502.
	if adopted, ok, err := w.adopt(ctx, group); err != nil {
		return res, err
	} else if ok {
		res.Outcome, res.PullRequest = OutcomeAlreadyOpen, adopted
		return res, nil
	}

	targets := group.Targets()
	if !w.fixer().Actionable(group) {
		// Fixer-specific: a group with no module bumps is nothing for the
		// deterministic bumper and ordinary work for an agent.
		res.Outcome = OutcomeNothingToDo
		return res, nil
	}

	base, err := w.PR.DefaultBranch(ctx, group.Repo)
	if err != nil {
		return res, err
	}
	dir := "/work/" + group.ID
	if err := w.PR.Clone(ctx, group.Repo, base, dir); err != nil {
		return res, err
	}
	defer func() { _ = w.PR.Discard(ctx, dir) }()

	// --- Step 2: baseline, BEFORE any change (VM-F-504) --------------------
	baseline, err := w.Toolchain.Baseline(ctx, dir)
	if err != nil {
		return res, err
	}
	res.Baseline = baseline
	if !baseline.OK() {
		// A repository whose tests already fail cannot be remediated: there is
		// no signal to verify a fix against, so a clean verification afterwards
		// would mean nothing. The pre-existing failure is reported verbatim
		// rather than absorbed (VM-F-532).
		reason := model.ReasonTestsFailed
		if !baseline.BuildOK {
			reason = model.ReasonBuildFailed
		}
		res.Outcome, res.Reason = OutcomeBaselineFailed, &reason
		res.Verification = Verification{Output: baseline.Output}
		if err := w.routeToHuman(ctx, group, reason,
			"the repository's build or tests were already failing before any change (VM-F-504)"); err != nil {
			return res, err
		}
		return res, nil
	}

	// --- Finding leases, inner, batched -----------------------------------
	leased, err := w.lease(ctx, group, now)
	if err != nil {
		return res, err
	}
	if len(leased) == 0 {
		res.Outcome = OutcomeNothingToDo
		return res, nil
	}
	// A failed attempt returns the work to the queue itself, rather than
	// relying on the lease sweeper.
	//
	// The sweeper only helps when a worker DIES: it reverts findings whose
	// lease lapsed. A worker that merely returns an error still runs its
	// deferred cleanup, so releasing the lease without reverting the state
	// would leave the finding in AUTO_REMEDIATING with no lease — and nothing
	// would ever move it, because policy rule 2 skips it as in progress and the
	// sweeper has no lease to find. It would drop out of remediation silently.
	completed := false
	defer func() {
		for _, fp := range leased {
			if !completed {
				current, err := w.Store.GetFinding(ctx, fp)
				if err == nil && current.State == model.AutoRemediating {
					_ = w.Store.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{
						Actor: model.ActorOrchestrator,
						Cause: "remediation attempt did not complete; returned to the queue",
						At:    w.now(),
					})
				}
			}
			_ = w.Store.ReleaseLease(ctx, fp)
		}
	}()

	// TRIAGED → AUTO_REMEDIATING. The intermediate state is what tells a
	// concurrent sweep the finding is already being worked on (policy rule 2);
	// without it, a second sweep would plan the same fix.
	for _, fp := range leased {
		if err := w.Store.ApplyTransition(ctx, fp, model.AutoRemediating, model.TransitionContext{
			Actor: model.ActorOrchestrator, Cause: "remediation started for fix group " + group.ID, At: now,
		}); err != nil {
			return res, err
		}
	}

	// --- Step 3–4: branch, then apply the change --------------------------
	if err := w.PR.CreateBranch(ctx, dir, group.Branch); err != nil {
		return res, err
	}
	applied, err := w.fixer().Apply(ctx, dir, group)
	if err != nil {
		// A refusal routes the finding to a human and the run continues. Any
		// other error hard-fails: a failure mode nobody has classified should
		// stop the job, not quietly become a ticket.
		var refusal FixerRefusal
		if errors.As(err, &refusal) {
			reason, toHuman := refusal.Refusal()
			res.Outcome, res.Reason = OutcomeFixerRefused, &reason
			res.Verification = Verification{Output: err.Error()}
			if toHuman {
				if rerr := w.routeToHuman(ctx, group, reason, err.Error()); rerr != nil {
					return res, rerr
				}
			}
			completed = true
			return res, nil
		}
		return res, err
	}
	res.Applied = applied

	// --- Steps 5–6: the guard, unconditionally, before any push -----------
	//
	// The paths and the diff come from the TREE, not from `applied`: a worker
	// that misreported its own change set — through a bug, or because an agent
	// wrote the report — must not be able to talk its way past the inspection
	// (VM-F-510).
	changed, err := w.PR.ChangedFiles(ctx, dir)
	if err != nil {
		return res, err
	}
	diff, err := w.PR.Diff(ctx, dir)
	if err != nil {
		return res, err
	}
	if len(changed) == 0 {
		changed = applied.ChangedFiles
	}
	if len(diff) == 0 {
		diff = applied.Diff
	}

	if err := w.Guard.Check(changed, diff); err != nil {
		// Hard failure. The branch is discarded in full and the error is
		// returned rather than recorded as an outcome, because the response is
		// to alert a human, not to retry.
		res.Outcome = OutcomeGuardViolation
		return res, err
	}

	// Quality checks come AFTER the guard, never before: an agent that edited
	// a workflow and also forgot a test must be reported as the first.
	if pg, ok := w.fixer().(PostGuard); ok {
		if err := pg.PostGuardCheck(ctx, dir, group); err != nil {
			var refusal FixerRefusal
			if errors.As(err, &refusal) {
				reason, toHuman := refusal.Refusal()
				res.Outcome, res.Reason = OutcomeFixerRefused, &reason
				res.Verification = Verification{Output: err.Error()}
				if toHuman {
					if rerr := w.routeToHuman(ctx, group, reason, err.Error()); rerr != nil {
						return res, rerr
					}
				}
				completed = true
				return res, nil
			}
			return res, err
		}
	}

	// --- Step 7: verify, including a re-run of the scanners ---------------
	verification, err := w.Toolchain.Verify(ctx, dir, targets, w.toolsFor(group), Expect(group))
	if err != nil {
		return res, err
	}
	res.Verification = verification

	// --- Step 8: any failure discards the branch entirely (VM-F-506) ------
	if !verification.OK() {
		reason := verification.FailureReason()
		res.Outcome, res.Reason = OutcomeVerifyFailed, &reason
		if err := w.routeToHuman(ctx, group, reason, w.explainVerification(verification)); err != nil {
			return res, err
		}
		completed = true
		return res, nil
	}

	// --- Step 9: commit, push, open the pull request ----------------------
	// One commit per logical fix (VM-F-505). For a bump that is one per
	// module; for a source change there are no modules, so it is one per
	// finding — the loop used to be targets-only, which meant an agentic
	// change produced no commits at all and the push failed with nothing
	// staged.
	for _, message := range commitMessages(group, targets, w.fixer().Name()) {
		if err := w.PR.Commit(ctx, dir, gh.Commit{
			Message:     message,
			AuthorName:  "wanaware-security[bot]",
			AuthorEmail: "security-bot@wanaware.invalid",
			Files:       changed,
		}); err != nil {
			return res, err
		}
	}

	if err := w.PR.Push(ctx, dir, group.Repo, group.Branch); err != nil {
		var conflict *gh.ErrConflict
		if errors.As(err, &conflict) {
			// Never forced. A force here would destroy whatever moved the
			// branch — another worker's commit, or a human's amendment.
			res.Outcome = OutcomePushRejected
			return res, err
		}
		return res, err
	}

	pr, err := w.openPR(ctx, group, targets, applied, verification, base)
	if err != nil {
		return res, err
	}
	res.PullRequest, res.Outcome = pr, OutcomePROpen

	if err := w.recordPR(ctx, group, pr, now); err != nil {
		return res, err
	}
	for _, fp := range leased {
		if err := w.Store.ApplyTransition(ctx, fp, model.PROpen, model.TransitionContext{
			Actor: model.ActorWorker, Cause: "pull request " + pr.URL, At: now,
		}); err != nil {
			return res, err
		}
	}
	completed = true
	return res, nil
}

// adopt returns an existing pull request for this fix group, if there is one.
//
// Three states are possible and all three are ordinary:
//
//	a recorded, open pull request — adopt it;
//	a branch on the remote with a pull request — adopt that;
//	a branch on the remote with NO pull request — a worker died between the
//	  push and the pull request, so open the pull request for the branch that
//	  is already there rather than pushing a second one.
func (w *Worker) adopt(ctx context.Context, group FixGroup) (gh.PullRequest, bool, error) {
	if rec, ok, err := w.Store.GetRemediationPR(ctx, group.Branch); err != nil {
		return gh.PullRequest{}, false, err
	} else if ok && rec.Open() {
		return gh.PullRequest{Number: rec.Number, URL: rec.URL, Head: group.Branch, State: "open"}, true, nil
	}

	exists, err := w.PR.BranchExists(ctx, group.Repo, group.Branch)
	if err != nil {
		return gh.PullRequest{}, false, err
	}
	if !exists {
		return gh.PullRequest{}, false, nil
	}

	pr, found, err := w.PR.FindPR(ctx, group.Repo, group.Branch)
	if err != nil {
		return gh.PullRequest{}, false, err
	}
	if !found {
		// The branch is pushed and nothing reviews it. Opening the pull request
		// is the recovery; pushing again would either be a no-op or a conflict,
		// and skipping would leave the fix invisible for ever.
		pr, err = w.PR.OpenPR(ctx, group.Repo, gh.OpenRequest{
			Head: group.Branch, Base: "", Title: w.title(group),
			Body:   "Recovered: this branch was pushed by a worker that did not complete. See the commits for the change.",
			Labels: prLabels(),
		})
		if err != nil {
			var exists *gh.ErrPRExists
			if errors.As(err, &exists) {
				pr = exists.Existing
			} else {
				return gh.PullRequest{}, false, err
			}
		}
	}
	if err := w.recordPR(ctx, group, pr, w.now()); err != nil {
		return gh.PullRequest{}, false, err
	}
	return pr, true, nil
}

// lease claims the group's findings. A finding already leased by someone else,
// or no longer in a remediable state, is skipped rather than forced.
func (w *Worker) lease(ctx context.Context, group FixGroup, now time.Time) ([]string, error) {
	var leased []string
	for _, f := range group.Findings {
		current, err := w.Store.GetFinding(ctx, f.Fingerprint)
		if err != nil {
			return nil, err
		}
		if current.State != model.Triaged {
			// Something else moved it — another worker, a human, or a scan that
			// verified it while this group was being planned.
			continue
		}
		if err := w.Store.AcquireLease(ctx, f.Fingerprint, w.Owner, now.Add(w.ttl())); err != nil {
			continue
		}
		leased = append(leased, f.Fingerprint)
	}
	return leased, nil
}

// routeToHuman records why automation stopped and moves the findings to
// NEEDS_HUMAN.
//
// The reason code is persisted before the transition, so a finding is never
// NEEDS_HUMAN with no explanation: that state without a reason is a queue entry
// nobody can action.
func (w *Worker) routeToHuman(ctx context.Context, group FixGroup, reason model.ReasonCode, cause string) error {
	now := w.now()
	for _, f := range group.Findings {
		current, err := w.Store.GetFinding(ctx, f.Fingerprint)
		if err != nil {
			return err
		}
		if model.PartitionOf(current.State) == model.PartitionResolved || current.State == model.NeedsHuman {
			continue
		}
		if err := w.Store.SetPriority(ctx, f.Fingerprint, current.Priority, &reason); err != nil {
			return err
		}
		// The actor comes from the table, not from a constant at the call
		// site. Enforcement (OQ-P10a-02) caught this claiming "orchestrator"
		// for a transition the table authorises for the worker: the audit
		// trail was naming the wrong party for every failed remediation, and
		// nothing would have noticed while the column was advisory.
		actor, ok := model.ActorFor(current.State, model.NeedsHuman)
		if !ok {
			actor = model.ActorOrchestrator
		}
		if err := w.Store.ApplyTransition(ctx, f.Fingerprint, model.NeedsHuman, model.TransitionContext{
			Actor: actor, Cause: cause, At: now,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) recordPR(ctx context.Context, group FixGroup, pr gh.PullRequest, now time.Time) error {
	return w.Store.SaveRemediationPR(ctx, store.RemediationPR{
		Branch: group.Branch, Repo: group.Repo, FixGroupID: group.ID,
		Number: pr.Number, URL: pr.URL, State: "open",
		OpenedAt: now, Findings: group.Fingerprints(),
	})
}

func (w *Worker) openPR(ctx context.Context, group FixGroup, targets []Target, applied Applied, v Verification, base string) (gh.PullRequest, error) {
	pr, err := w.PR.OpenPR(ctx, group.Repo, gh.OpenRequest{
		Head: group.Branch, Base: base,
		Title:  w.title(group),
		Body:   Body(group, targets, applied, v),
		Labels: prLabels(),
	})
	if err == nil {
		return pr, nil
	}
	// The remote answers 422 when a pull request already exists for this head.
	// That is an ordinary retry, not a failure.
	var exists *gh.ErrPRExists
	if errors.As(err, &exists) {
		return exists.Existing, nil
	}
	return gh.PullRequest{}, err
}

// commitMessages renders one message per logical fix (VM-F-505).
//
// Each carries the finding identifier, so `git log` answers "why did this
// change" without a round trip to the findings store, and the producer, so a
// change is attributable to the thing that made it — a deterministic bump and
// an agent are different claims about how much a reviewer should trust the
// diff.
func commitMessages(group FixGroup, targets []Target, producer string) []string {
	if len(targets) > 0 {
		out := make([]string, 0, len(targets))
		for _, t := range targets {
			out = append(out, fmt.Sprintf("security: bump %s to %s\n\nCloses %s\nFix group %s\nProduced by %s",
				t.Module, t.To, strings.Join(t.Closes, ", "), group.ID, producer))
		}
		return out
	}

	out := make([]string, 0, len(group.Findings))
	for _, f := range group.Findings {
		id := f.Identity.PrimaryID
		if id == "" {
			id = deref(f.Identity.RuleID)
		}
		if id == "" {
			id = f.Fingerprint
		}
		where := deref(f.Location.File)
		if where == "" {
			where = f.Repo
		}
		out = append(out, fmt.Sprintf("security: fix %s in %s\n\nCloses %s\nFingerprint %s\nFix group %s\nProduced by %s",
			id, where, id, f.Fingerprint, group.ID, producer))
	}
	return out
}

func (w *Worker) title(group FixGroup) string {
	if len(group.Findings) == 1 {
		f := group.Findings[0]
		id := f.Identity.PrimaryID
		if id == "" {
			id = "security finding"
		}
		if f.Location.Module != "" {
			return fmt.Sprintf("security: %s in %s", id, f.Location.Module)
		}
		return "security: " + id
	}
	return fmt.Sprintf("security: %d dependency fixes (%s)", len(group.Findings), group.ID)
}

// prLabels identifies the pull request as machine-generated (VM-F-542).
func prLabels() []string { return []string{"security", "automated", "vf-remediation"} }

func (w *Worker) toolsFor(group FixGroup) []string {
	if len(w.Tools) > 0 {
		return w.Tools
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range group.Findings {
		for _, tool := range f.Provenance.Tools {
			if !seen[tool] {
				seen[tool] = true
				out = append(out, tool)
			}
		}
	}
	return out
}

func (w *Worker) explainVerification(v Verification) string {
	switch {
	case !v.BuildOK:
		return "the change did not build; the branch was discarded in full (VM-F-506)"
	case !v.TestsOK:
		return "the change broke the tests; the branch was discarded in full (VM-F-506)"
	case !v.TidyOK:
		return "the dependency manifest was not tidy after the change"
	default:
		return "the change built and tested, but a re-run of the scanners still reports " +
			strings.Join(v.Remaining, ", ") + " — the bump did not close the defect (VM-F-531)"
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
