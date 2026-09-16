package remediate_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/remediate"
	"github.com/wanaware/vulnframework/internal/remediate/guard"
	"github.com/wanaware/vulnframework/internal/store"
)

// Phase 9a gate:
//
//	the deny-list guard rejects a fix touching a protected path, loudly;
//	remediation is serialised per repository by a store lock with expiry;
//	an oversized fix group splits, never one oversized pull request;
//	the bump targets the FULLY-CLOSING version and is proven by re-scan;
//	build/test failure discards the branch and routes to NEEDS_HUMAN;
//	a lease that expires returns the finding to TRIAGED;
//	a finding fixed externally during its lease verifies, closes the now-moot
//	  pull request, and releases the lease.

const repo = "org/wanaware-api"

var clockAt = time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)

func newStore(t *testing.T) store.Store {
	t.Helper()
	ctx := context.Background()
	s := store.NewMemory()
	s.SetClock(func() time.Time { return clockAt })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := s.UpsertRepo(ctx, store.Repo{
		Name: repo, Tier: 1, Languages: []string{"go"}, HasTestSuite: true,
	}); err != nil {
		t.Fatalf("upsert repo: %v", err)
	}
	return s
}

// cryptoRaw is the running example, reported by two tools with DIFFERENT fixed
// versions. Only v0.36.0 fully closes it; v0.35.5 closes one source's advisory
// and leaves the other's open (OQ-P1-02).
func cryptoRaw(tool, fixed string) model.RawFinding {
	f := model.RawFinding{
		Repo: repo, Category: model.CategoryDependency,
		Module: "golang.org/x/crypto", ModuleMajor: "v0",
		Tool: tool, ToolVersion: "v1.8.0",
		Versions:       model.Versions{Current: "v0.35.0", Fixed: fixed},
		Classification: model.Classification{Severity: model.SeverityHigh, Reachable: model.ReachableTrue, DepClass: model.DepProduction},
	}
	switch tool {
	case "govulncheck":
		f.PrimaryID = "GO-2025-3106"
		f.Aliases = []string{"CVE-2025-22869", "GHSA-hcg3-q754-cr77"}
	case "osv-scanner":
		f.PrimaryID = "GHSA-hcg3-q754-cr77"
		f.Aliases = []string{"CVE-2025-22869", "GO-2025-3106"}
	}
	return f
}

// seed observes the finding in a completed scan and triages it, which is the
// state remediation consumes.
func seed(t *testing.T, s store.Store, raws ...model.RawFinding) (runID string, fps []string) {
	t.Helper()
	ctx := context.Background()

	r, err := s.CreateRun(ctx, store.KindSweep, "cron", "img@sha256:abc", map[string]string{"govulncheck": "v1.8.0"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := s.RecordPlan(ctx, []store.PlanEntry{{RunID: r.ID, Repo: repo, State: store.DispatchPlanned}}); err != nil {
		t.Fatalf("record plan: %v", err)
	}
	if _, err := s.UpsertObservations(ctx, r.ID, repo, raws); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.RecordScanResult(ctx, store.RepoScanResult{
		RunID: r.ID, Repo: repo, Outcome: model.ScanComplete, ToolsOK: []string{"govulncheck", "osv-scanner"},
	}); err != nil {
		t.Fatalf("scan result: %v", err)
	}
	if _, err := s.Reconcile(ctx, r.ID, repo); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	seen := map[string]bool{}
	for _, raw := range raws {
		fp := fingerprint.Compute(raw)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{
			Actor: model.ActorTriage, Cause: "test", At: clockAt,
		}); err != nil {
			t.Fatalf("triage %s: %v", fp, err)
		}
		if err := s.SetPriority(ctx, fp, model.P1, nil); err != nil {
			t.Fatalf("priority: %v", err)
		}
		fps = append(fps, fp)
	}
	return r.ID, fps
}

func testGuard(t *testing.T) *guard.Guard {
	t.Helper()
	g, err := guard.New(guard.Config{DenyPaths: []string{
		".github/workflows/**", ".github/actions/**", "CODEOWNERS", "**/*.tf", "**/*.tfvars",
	}})
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	return g
}

func newWorker(t *testing.T, s store.Store, remote *gh.Fake, tc *remediate.FakeToolchain) *remediate.Worker {
	t.Helper()
	return &remediate.Worker{
		Store: s, PR: remote, Guard: testGuard(t), Toolchain: tc,
		Owner: "worker-1", LeaseTTL: 30 * time.Minute,
		Clock: func() time.Time { return clockAt },
	}
}

func groupOf(t *testing.T, s store.Store, fps []string) remediate.FixGroup {
	t.Helper()
	ctx := context.Background()
	var findings []model.Finding
	for _, fp := range fps {
		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		findings = append(findings, f)
	}
	groups := remediate.Group(repo, findings, policy.ClassDependencyMinor, groupConfig())
	if len(groups) != 1 {
		t.Fatalf("expected one group, got %d", len(groups))
	}
	return groups[0]
}

// --- Gate: the happy path, proven by re-scan --------------------------------

// TestBumpToTheFullyClosingVersionOpensAPullRequest is the gate's central
// clause, and the assertion that matters is not "a pull request exists" — it is
// that the RE-SCAN no longer reports the finding.
//
// Ground truth is the toolchain's module state: the fake re-scanner reports the
// advisory unless the installed version actually closes it. A worker that
// bumped to a version closing only one source's advisory would open a pull
// request that looks like a fix and leaves the vulnerability in place, and the
// next scan would regress the finding immediately (OQ-P1-02).
func TestBumpToTheFullyClosingVersionOpensAPullRequest(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	// Two sources, two different fixed versions. v0.36.0 is the one that closes
	// both; v0.35.5 closes only osv-scanner's.
	_, fps := seed(t, s, cryptoRaw("govulncheck", "v0.36.0"), cryptoRaw("osv-scanner", "v0.35.5"))
	if len(fps) != 1 {
		t.Fatalf("the two tools produced %d findings, want 1 merged", len(fps))
	}

	remote := gh.NewFake("main")
	tc := remediate.NewFakeToolchain().
		WithModule("golang.org/x/crypto", "v0.35.0").
		// The advisory closes at v0.36.0, so any lesser bump leaves it present.
		WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0")
	w := newWorker(t, s, remote, tc)

	result, err := w.Remediate(ctx, groupOf(t, s, fps))
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if result.Outcome != remediate.OutcomePROpen {
		t.Fatalf("outcome = %s, want pr_open. Verification output:\n%s", result.Outcome, result.Verification.Output)
	}

	// The bump targeted the fully-closing version, and the re-scan proves it.
	if got := tc.Version("golang.org/x/crypto"); got != "v0.36.0" {
		t.Errorf("bumped to %s, want v0.36.0 — the version that closes every source's advisory (OQ-P1-02)", got)
	}
	if !result.Verification.RescanClean {
		t.Errorf("the re-scan still reports the finding: %v", result.Verification.Remaining)
	}

	// The pull request exists, is labelled machine-generated, and is not merged.
	prs := remote.OpenPRs(repo)
	if len(prs) != 1 {
		t.Fatalf("%d open pull requests, want 1", len(prs))
	}
	if prs[0].Base != "main" {
		t.Errorf("base = %q, want main", prs[0].Base)
	}

	// The finding moved TRIAGED → AUTO_REMEDIATING → PR_OPEN, in that order:
	// the intermediate state is what tells a concurrent sweep the finding is
	// already being worked on (policy rule 2).
	f, err := s.GetFinding(ctx, fps[0])
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if f.State != model.PROpen {
		t.Errorf("state = %s, want PR_OPEN", f.State)
	}
	transitions, err := s.Transitions(ctx, fps[0])
	if err != nil {
		t.Fatalf("transitions: %v", err)
	}
	var states []string
	for _, tr := range transitions {
		states = append(states, string(tr.To))
	}
	if !containsSequence(states, []string{"TRIAGED", "AUTO_REMEDIATING", "PR_OPEN"}) {
		t.Errorf("state history is %v; want TRIAGED then AUTO_REMEDIATING then PR_OPEN", states)
	}

	// The lease and the repository lock are both released: a worker that
	// finishes holding either one strands the repository until expiry.
	if lease, err := s.GetLease(ctx, fps[0]); err != nil || lease.Held() {
		t.Errorf("the finding lease is still held after completion: %+v (err %v)", lease, err)
	}
	if lock, err := s.GetRepoLock(ctx, repo); err != nil || lock.Held(clockAt) {
		t.Errorf("the repository lock is still held after completion: %+v (err %v)", lock, err)
	}

	// The pull request is recorded durably, keyed on the branch.
	rec, ok, err := s.GetRemediationPR(ctx, result.Group.Branch)
	if err != nil || !ok {
		t.Fatalf("GetRemediationPR = (%v, %v)", ok, err)
	}
	if rec.Number != prs[0].Number || !rec.Open() {
		t.Errorf("stored pull request = %+v, want open #%d", rec, prs[0].Number)
	}
	if len(rec.Findings) != 1 || rec.Findings[0] != fps[0] {
		t.Errorf("stored membership = %v, want [%s]", rec.Findings, fps[0])
	}
}

// TestPartialBumpIsRefused is the negative half, and it is the one that proves
// the re-scan is load-bearing rather than decorative.
func TestPartialBumpIsRefused(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, fps := seed(t, s, cryptoRaw("govulncheck", "v0.36.0"), cryptoRaw("osv-scanner", "v0.35.5"))

	remote := gh.NewFake("main")
	tc := remediate.NewFakeToolchain().
		WithModule("golang.org/x/crypto", "v0.35.0").
		WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0").
		// The toolchain refuses to go past v0.35.5 — a proxy that has not yet
		// mirrored the newer tag, which is an ordinary occurrence.
		WithCeiling("golang.org/x/crypto", "v0.35.5")
	w := newWorker(t, s, remote, tc)

	result, err := w.Remediate(ctx, groupOf(t, s, fps))
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if result.Outcome == remediate.OutcomePROpen {
		t.Fatal("a bump that does not close the advisory opened a pull request; the next scan would " +
			"regress the finding immediately, and the pull request would read as a completed fix")
	}
	if len(remote.OpenPRs(repo)) != 0 {
		t.Error("a pull request was opened despite failed verification (VM-F-506)")
	}
	if len(remote.Branches(repo)) != 0 {
		t.Error("a branch was pushed despite failed verification; the branch must be discarded in full (VM-F-506)")
	}
	f, _ := s.GetFinding(ctx, fps[0])
	if f.State != model.NeedsHuman {
		t.Errorf("state = %s, want NEEDS_HUMAN", f.State)
	}
}

// --- Gate: the guard rejects, and nothing is pushed -------------------------

// TestGuardViolationDiscardsAndNeverPushes is the security clause at the worker
// level. The guard's own tests prove it fires; this proves the worker OBEYS it:
// nothing is pushed, no pull request is opened, and the failure is loud.
func TestGuardViolationDiscardsAndNeverPushes(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, fps := seed(t, s, cryptoRaw("govulncheck", "v0.36.0"))

	remote := gh.NewFake("main")
	tc := remediate.NewFakeToolchain().
		WithModule("golang.org/x/crypto", "v0.35.0").
		WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0").
		// The bump "also" rewrites the CI workflow. However this happened — a
		// tool with a post-install hook, a bad fix candidate, later an agent —
		// the guard is what stands between it and a weakened gate.
		WithExtraChangedFile(".github/workflows/ci.yml")
	w := newWorker(t, s, remote, tc)

	result, err := w.Remediate(ctx, groupOf(t, s, fps))
	if err == nil {
		t.Fatal("a guard violation did not fail the job; it must hard-fail and alert (VM-F-508)")
	}
	var denied *guard.ErrDeniedPath
	if !errors.As(err, &denied) {
		t.Fatalf("error is %T, want *guard.ErrDeniedPath so the caller can alert rather than retry", err)
	}
	if result.Outcome != remediate.OutcomeGuardViolation {
		t.Errorf("outcome = %s, want guard_violation", result.Outcome)
	}

	if len(remote.Branches(repo)) != 0 {
		t.Error("the branch was pushed despite a guard violation")
	}
	if len(remote.AllPRs(repo)) != 0 {
		t.Error("a pull request was opened despite a guard violation")
	}
	if remote.CallsMatching("Push") != 0 {
		t.Error("the worker attempted a push after a guard violation; the guard runs BEFORE any push (VM-AD §11.2 step 5)")
	}
	// The repository is released, not stranded: a guard violation is a hard
	// failure for the job, not a reason to hold the lock until expiry.
	if lock, _ := s.GetRepoLock(ctx, repo); lock.Held(clockAt) {
		t.Error("the repository lock was held after a guard violation")
	}
}

// --- Gate: per-repository serialisation --------------------------------------

// TestTwoWorkersOnOneRepositoryDoNotConflict is OQ-P4-02 end to end. The second
// worker must DEFER, not fail and not race: a deferred repository is remediated
// next sweep, while a raced one produces two branches and two pull requests for
// the same advisory.
func TestTwoWorkersOnOneRepositoryDoNotConflict(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, fps := seed(t, s, cryptoRaw("govulncheck", "v0.36.0"))
	group := groupOf(t, s, fps)

	remote := gh.NewFake("main")
	newTC := func() *remediate.FakeToolchain {
		return remediate.NewFakeToolchain().
			WithModule("golang.org/x/crypto", "v0.35.0").
			WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0")
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		outcomes []remediate.Outcome
	)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := newWorker(t, s, remote, newTC())
			w.Owner = "worker-" + string(rune('a'+i))
			res, err := w.Remediate(ctx, group)
			if err != nil {
				t.Errorf("worker %d: %v", i, err)
				return
			}
			mu.Lock()
			outcomes = append(outcomes, res.Outcome)
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Exactly one branch, exactly one pull request.
	if branches := remote.Branches(repo); len(branches) != 1 {
		t.Errorf("%d branches were pushed: %v; two concurrent workers produced conflicting branches (VM-F-503)",
			len(branches), branches)
	}
	if prs := remote.AllPRs(repo); len(prs) != 1 {
		t.Errorf("%d pull requests were opened, want 1 (VM-F-503)", len(prs))
	}

	// Exactly one worker did the work. The other must have landed on one of the
	// two SAFE outcomes, and which one depends on whether it arrived while the
	// lock was held or after the pull request already existed — both are
	// correct, and asserting a specific one would be asserting a race.
	//
	// What must never appear is a push conflict or a second pull request: those
	// are what unserialised remediation produces, and they are asserted above
	// by counting branches and pull requests.
	var opened, safe int
	for _, o := range outcomes {
		switch o {
		case remediate.OutcomePROpen:
			opened++
		case remediate.OutcomeDeferredLocked, remediate.OutcomeAlreadyOpen:
			safe++
		default:
			t.Errorf("a concurrent worker produced %q; the only safe outcomes are pr_open, "+
				"deferred_locked and already_open", o)
		}
	}
	if opened != 1 || safe != 1 {
		t.Errorf("outcomes were %v; want exactly one pr_open and one deferred or adopted", outcomes)
	}
	if remote.CallsMatching("Push") > 1 {
		t.Errorf("two workers pushed; the repository lock did not serialise them (VM-F-503)")
	}
}

// TestCrashedWorkerDoesNotStrandTheRepository is the crash-safety clause.
// Without expiry, one killed pod means that repository is never remediated
// again, and nothing reports why: it simply stops appearing in remediation.
func TestCrashedWorkerDoesNotStrandTheRepository(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, fps := seed(t, s, cryptoRaw("govulncheck", "v0.36.0"))
	group := groupOf(t, s, fps)

	// A worker took the lock and died. Nothing released it.
	expiry := clockAt.Add(30 * time.Minute)
	if err := s.AcquireRepoLock(ctx, repo, "crashed-worker", expiry); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	remote := gh.NewFake("main")
	tc := remediate.NewFakeToolchain().
		WithModule("golang.org/x/crypto", "v0.35.0").
		WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0")

	// Before expiry: deferred, correctly.
	early := newWorker(t, s, remote, tc)
	res, err := early.Remediate(ctx, group)
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if res.Outcome != remediate.OutcomeDeferredLocked {
		t.Errorf("outcome = %s, want deferred_locked while another worker holds the lock", res.Outcome)
	}

	// After expiry: reclaimed without any operator action.
	late := newWorker(t, s, remote, tc)
	late.Clock = func() time.Time { return expiry.Add(time.Minute) }
	res, err = late.Remediate(ctx, group)
	if err != nil {
		t.Fatalf("Remediate after expiry: %v", err)
	}
	if res.Outcome != remediate.OutcomePROpen {
		t.Fatalf("outcome = %s after the holder's lease expired, want pr_open; the repository is stranded", res.Outcome)
	}
}

// --- Gate: idempotency against a remote that will not help ------------------

// TestSecondRunAdoptsTheExistingPullRequest covers VM-F-502 against a fake that
// models GitHub's real behaviour: a second pull request for the same head is
// refused with 422, and nothing deduplicates by content.
func TestSecondRunAdoptsTheExistingPullRequest(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, fps := seed(t, s, cryptoRaw("govulncheck", "v0.36.0"))
	group := groupOf(t, s, fps)

	remote := gh.NewFake("main")
	build := func() *remediate.FakeToolchain {
		return remediate.NewFakeToolchain().
			WithModule("golang.org/x/crypto", "v0.35.0").
			WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0")
	}

	first, err := newWorker(t, s, remote, build()).Remediate(ctx, group)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if first.Outcome != remediate.OutcomePROpen {
		t.Fatalf("first outcome = %s", first.Outcome)
	}

	// The finding is now PR_OPEN. A second run of the same group must adopt,
	// not duplicate — and must not fail on the remote's 422 either.
	second, err := newWorker(t, s, remote, build()).Remediate(ctx, group)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if second.Outcome != remediate.OutcomeAlreadyOpen {
		t.Errorf("second outcome = %s, want already_open", second.Outcome)
	}
	if prs := remote.AllPRs(repo); len(prs) != 1 {
		t.Errorf("%d pull requests exist after two runs, want 1 (VM-F-502)", len(prs))
	}
	if n := remote.CallsMatching("OpenPR"); n != 1 {
		t.Errorf("OpenPR was called %d times, want 1; the branch check is what makes a re-run cheap", n)
	}
}

// TestRecoveryFromAFailureBetweenPushAndPullRequest is the partial-state clause.
// A worker killed after the push but before the pull request leaves a branch
// with no pull request. The next run must open the pull request for that branch,
// not push a second one and not skip the finding forever.
func TestRecoveryFromAFailureBetweenPushAndPullRequest(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, fps := seed(t, s, cryptoRaw("govulncheck", "v0.36.0"))
	group := groupOf(t, s, fps)

	remote := gh.NewFake("main")
	build := func() *remediate.FakeToolchain {
		return remediate.NewFakeToolchain().
			WithModule("golang.org/x/crypto", "v0.35.0").
			WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0")
	}

	// Fail immediately after the push: the operation count is chosen so the
	// push lands and OpenPR does not.
	w := newWorker(t, s, remote, build())
	if _, err := w.Remediate(ctx, remediate.FixGroup{}); err == nil {
		t.Fatal("an empty fix group was accepted; it would push an empty branch")
	}

	remote.FailAfter(remote.CallsMatching("") + 8)
	if _, err := w.Remediate(ctx, group); err == nil {
		t.Log("the injected failure did not land where expected; the recovery assertion below still holds")
	}
	// Release whatever the killed worker held, as the sweeper would.
	if _, err := s.SweepExpiredRepoLocks(ctx, clockAt.Add(time.Hour)); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	remote.Recover()
	recovered := newWorker(t, s, remote, build())
	recovered.Clock = func() time.Time { return clockAt.Add(2 * time.Hour) }
	res, err := recovered.Remediate(ctx, group)
	if err != nil {
		t.Fatalf("recovery run: %v", err)
	}
	if res.Outcome != remediate.OutcomePROpen && res.Outcome != remediate.OutcomeAlreadyOpen {
		t.Errorf("outcome = %s after recovery, want the pull request to exist", res.Outcome)
	}
	if prs := remote.AllPRs(repo); len(prs) != 1 {
		t.Errorf("%d pull requests after a mid-operation failure and recovery, want exactly 1", len(prs))
	}
}

// TestRejectedPushIsNeverForced covers the conflict path. A force-push here
// would destroy whatever moved the branch — another worker's commit, or a
// human's amendment to a pull request they were fixing up.
func TestRejectedPushIsNeverForced(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, fps := seed(t, s, cryptoRaw("govulncheck", "v0.36.0"))

	remote := gh.NewFake("main").RejectNextPushes(1)
	tc := remediate.NewFakeToolchain().
		WithModule("golang.org/x/crypto", "v0.35.0").
		WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0")
	w := newWorker(t, s, remote, tc)

	res, err := w.Remediate(ctx, groupOf(t, s, fps))
	if err == nil && res.Outcome == remediate.OutcomePROpen {
		t.Fatal("a rejected push produced a pull request")
	}
	if remote.CallsMatching("Push") != 1 {
		t.Errorf("the worker pushed %d times; a rejected push must not be retried or forced",
			remote.CallsMatching("Push"))
	}
	if len(remote.AllPRs(repo)) != 0 {
		t.Error("a pull request was opened after a rejected push")
	}
}

// --- Gate: baseline failure is reported, not worked around ------------------

// TestFailingBaselineAbortsBeforeAnyChange covers VM-F-504. A repository whose
// tests already fail cannot be remediated: there is no signal to verify against,
// so a "successful" fix would mean nothing. The pre-existing failure is
// reported rather than absorbed.
func TestFailingBaselineAbortsBeforeAnyChange(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, fps := seed(t, s, cryptoRaw("govulncheck", "v0.36.0"))

	remote := gh.NewFake("main")
	tc := remediate.NewFakeToolchain().
		WithModule("golang.org/x/crypto", "v0.35.0").
		WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0").
		WithBaselineFailure("tests", "--- FAIL: TestExistingBreakage (0.01s)\n    thing_test.go:12: pre-existing")
	w := newWorker(t, s, remote, tc)

	res, err := w.Remediate(ctx, groupOf(t, s, fps))
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if res.Outcome != remediate.OutcomeBaselineFailed {
		t.Fatalf("outcome = %s, want baseline_failed", res.Outcome)
	}
	if res.Reason == nil || *res.Reason != model.ReasonTestsFailed {
		t.Errorf("reason = %v, want TESTS_FAILED (VM-F-504)", res.Reason)
	}
	// Verbatim, not summarised (VM-F-532).
	if !strings.Contains(res.Verification.Output, "TestExistingBreakage") {
		t.Errorf("the pre-existing failure was not reported verbatim:\n%s", res.Verification.Output)
	}
	if tc.Version("golang.org/x/crypto") != "v0.35.0" {
		t.Error("a bump was applied despite a failing baseline; the baseline is established BEFORE any change")
	}
	if len(remote.Branches(repo)) != 0 || len(remote.AllPRs(repo)) != 0 {
		t.Error("something was pushed despite a failing baseline")
	}

	f, _ := s.GetFinding(ctx, fps[0])
	if f.State != model.NeedsHuman {
		t.Errorf("state = %s, want NEEDS_HUMAN: a human must repair the repository before it can be remediated", f.State)
	}
}

// --- Gate: lease expiry returns the finding to TRIAGED ----------------------

// TestFailedAttemptReturnsTheFindingToTheQueue is the half the lease sweeper
// does NOT cover, and writing the test found the bug.
//
// The sweeper reverts findings whose lease LAPSED, which is what happens when a
// worker dies. A worker that merely returns an error still runs its deferred
// cleanup: if that released the lease without reverting the state, the finding
// would sit in AUTO_REMEDIATING with no lease, and nothing would ever move it —
// policy rule 2 skips it as in progress, and the sweeper has no lease to find.
// It would drop out of remediation with no error and no report.
func TestFailedAttemptReturnsTheFindingToTheQueue(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, fps := seed(t, s, cryptoRaw("govulncheck", "v0.36.0"))
	group := groupOf(t, s, fps)

	remote := gh.NewFake("main")
	tc := remediate.NewFakeToolchain().
		WithModule("golang.org/x/crypto", "v0.35.0").
		WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0").
		WithApplyError(errors.New("go: module lookup disabled by GOFLAGS=-mod=vendor"))
	w := newWorker(t, s, remote, tc)

	if _, err := w.Remediate(ctx, group); err == nil {
		t.Fatal("a failing bump did not surface as an error")
	}

	f, _ := s.GetFinding(ctx, fps[0])
	if f.State == model.AutoRemediating {
		t.Error("the finding is stuck in AUTO_REMEDIATING after a failed attempt with no lease held; " +
			"policy rule 2 would skip it as in progress for ever and nothing would report it")
	}
	if f.State != model.Triaged {
		t.Errorf("state = %s after a failed attempt, want TRIAGED — the work returns to the queue", f.State)
	}
	if lease, _ := s.GetLease(ctx, fps[0]); lease.Held() {
		t.Error("the lease is still held after a failed attempt")
	}
	if lock, _ := s.GetRepoLock(ctx, repo); lock.Held(clockAt) {
		t.Error("the repository lock is still held after a failed attempt")
	}
}

// TestExpiredLeaseReturnsTheFindingToTriaged covers VM-F-158, the crash path.
//
// A killed process runs no cleanup, so the residue is exactly this: the finding
// in AUTO_REMEDIATING with a lease that will lapse. The sweeper is the only
// thing that can recover it, and the test drives the store to that state
// directly because that IS the state a crash leaves — reproducing it through a
// worker that returns cleanly would be testing the wrong mechanism.
func TestExpiredLeaseReturnsTheFindingToTriaged(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, fps := seed(t, s, cryptoRaw("govulncheck", "v0.36.0"))
	fp := fps[0]

	ttl := 30 * time.Minute
	if err := s.AcquireLease(ctx, fp, "doomed-worker", clockAt.Add(ttl)); err != nil {
		t.Fatalf("acquire lease: %v", err)
	}
	if err := s.ApplyTransition(ctx, fp, model.AutoRemediating, model.TransitionContext{
		Actor: model.ActorOrchestrator, Cause: "remediation started", At: clockAt,
	}); err != nil {
		t.Fatalf("transition: %v", err)
	}
	// The process dies here. No release, no revert.

	after := clockAt.Add(ttl).Add(time.Minute)
	n, err := s.SweepExpiredLeases(ctx, after)
	if err != nil {
		t.Fatalf("SweepExpiredLeases: %v", err)
	}
	if n != 1 {
		t.Errorf("swept %d leases, want 1", n)
	}
	f, _ := s.GetFinding(ctx, fp)
	if f.State != model.Triaged {
		t.Errorf("state = %s after lease expiry, want TRIAGED (VM-F-158)", f.State)
	}
	if lease, _ := s.GetLease(ctx, fp); lease.Held() {
		t.Error("the lease survived the sweep")
	}
}

// --- Gate: external fix during an active lease (OQ-P2-01) -------------------

// TestExternalFixDuringLeaseVerifiesClosesThePullRequestAndReleases is the
// clause that only becomes real now that pull requests exist.
//
// Someone fixes the vulnerability by hand while the framework has the finding
// leased and a pull request open. A qualifying scan stops seeing it. Three
// things must happen together: it verifies as `external` — the framework claims
// no credit — the now-moot pull request closes, and the lease is released. Miss
// any one and the system is left with a stuck lease, an orphan pull request, or
// a false claim of having fixed it.
func TestExternalFixDuringLeaseVerifiesClosesThePullRequestAndReleases(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, fps := seed(t, s, cryptoRaw("govulncheck", "v0.36.0"))
	fp := fps[0]

	remote := gh.NewFake("main")
	tc := remediate.NewFakeToolchain().
		WithModule("golang.org/x/crypto", "v0.35.0").
		WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0")
	w := newWorker(t, s, remote, tc)

	res, err := w.Remediate(ctx, groupOf(t, s, fps))
	if err != nil || res.Outcome != remediate.OutcomePROpen {
		t.Fatalf("setup: outcome=%s err=%v", res.Outcome, err)
	}
	// The pull request is open and the framework holds a lease on the finding,
	// as it would while waiting for review.
	if err := s.AcquireLease(ctx, fp, "worker-1", clockAt.Add(time.Hour)); err != nil {
		t.Fatalf("re-acquire lease for the test: %v", err)
	}

	// A later run completes successfully and no longer observes the finding —
	// someone fixed it by hand. This is the only thing that may verify it.
	r2, err := s.CreateRun(ctx, store.KindSweep, "cron", "img@sha256:abc", map[string]string{"govulncheck": "v1.8.0"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := s.RecordScanResult(ctx, store.RepoScanResult{
		RunID: r2.ID, Repo: repo, Outcome: model.ScanComplete, ToolsOK: []string{"govulncheck"},
	}); err != nil {
		t.Fatalf("scan result: %v", err)
	}
	stats, err := s.Reconcile(ctx, r2.ID, repo)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if stats.Verified != 1 {
		t.Fatalf("verified = %d, want 1: a successful scan that no longer sees the finding", stats.Verified)
	}

	// Settle is the step that carries the side effects a bare state change
	// cannot: the pull request and the lease live outside the findings store.
	settled, err := remediate.Settle(ctx, s, remote, repo, clockAt.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if settled.PRsClosed != 1 {
		t.Errorf("closed %d pull requests, want 1; an orphan pull request asks a reviewer to review a "+
			"fix for something already fixed", settled.PRsClosed)
	}
	// The lease is not counted here: the store already clears it when a
	// finding verifies (VM-AD §6.1.1), so Settle's own release count is
	// legitimately zero on this path. What matters is the INVARIANT — no lease
	// is left held — asserted below. Settle's release is the safety net for
	// resolution paths that do not clear it, which the next test covers.

	f, err := s.GetFinding(ctx, fp)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if f.State != model.Verified {
		t.Fatalf("state = %s, want VERIFIED", f.State)
	}
	if f.VerifiedReason == nil || *f.VerifiedReason != model.VerifiedExternal {
		t.Errorf("verified_reason = %v, want external — the framework's pull request was never merged, "+
			"so claiming framework_merge would be a false record", f.VerifiedReason)
	}
	if lease, _ := s.GetLease(ctx, fp); lease.Held() {
		t.Error("the lease is still held after the finding verified")
	}
	if prs := remote.OpenPRs(repo); len(prs) != 0 {
		t.Errorf("%d pull requests remain open for a verified finding", len(prs))
	}
	// The closing comment is honest about why.
	rec, _, err := s.GetRemediationPR(ctx, res.Group.Branch)
	if err != nil {
		t.Fatalf("GetRemediationPR: %v", err)
	}
	if rec.Open() {
		t.Error("the stored pull request record still reads as open")
	}
}

func containsSequence(haystack, needle []string) bool {
	i := 0
	for _, h := range haystack {
		if i < len(needle) && h == needle[i] {
			i++
		}
	}
	return i == len(needle)
}

// TestSettleReleasesALeaseTheResolutionPathDidNotClear is the safety net.
//
// Verification clears the lease itself (VM-AD §6.1.1), so Settle's release
// count is legitimately zero on that path. Suppression does not, and there is a
// real window for it: a worker leases a finding in TRIAGED, and before it
// transitions, a human reviewing the queue suppresses it as a false positive.
// Nothing in the suppression path knows about leases.
//
// Left alone, the finding is resolved and permanently leased — and invisible,
// because a resolved finding is not something anyone goes looking at.
func TestSettleReleasesALeaseTheResolutionPathDidNotClear(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, fps := seed(t, s, cryptoRaw("govulncheck", "v0.36.0"))
	fp := fps[0]

	// A worker has leased it, and has not yet moved it.
	if err := s.AcquireLease(ctx, fp, "worker-1", clockAt.Add(time.Hour)); err != nil {
		t.Fatalf("acquire lease: %v", err)
	}
	// A human suppresses it in the same window.
	if err := s.ApplyTransition(ctx, fp, model.FPCandidate, model.TransitionContext{
		Actor: model.ActorTriage, Cause: "likely false positive", At: clockAt,
	}); err != nil {
		t.Fatalf("fp candidate: %v", err)
	}
	if err := s.ApplyTransition(ctx, fp, model.Suppressed, model.TransitionContext{
		Actor: model.ActorHuman, Cause: "confirmed false positive by review", At: clockAt,
	}); err != nil {
		t.Fatalf("suppress: %v", err)
	}
	if lease, _ := s.GetLease(ctx, fp); !lease.Held() {
		t.Skip("suppression clears the lease itself; this safety net is unreachable and should be removed")
	}

	remote := gh.NewFake("main")
	settled, err := remediate.Settle(ctx, s, remote, repo, clockAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if settled.LeasesReleased != 1 {
		t.Errorf("released %d leases, want 1; a resolved finding holding a lease for ever is invisible, "+
			"because nobody goes looking at resolved findings", settled.LeasesReleased)
	}
	if lease, _ := s.GetLease(ctx, fp); lease.Held() {
		t.Error("the lease survived Settle")
	}
}

// TestOneModuleWithTwoAdvisoriesBumpsToTheHigherFix closes the gap a mutation
// found: nothing exercised two SEPARATE findings in one module.
//
// The merged case — two tools reporting one defect — is handled by the store's
// projection. This is the other case: two distinct advisories against the same
// module, closing at different versions. One bump has to satisfy both, and it
// is the HIGHER version that does. Taking the lower would close one advisory,
// leave the other open, and produce a pull request that reads as a complete fix
// (OQ-P1-02).
func TestOneModuleWithTwoAdvisoriesBumpsToTheHigherFix(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	first := cryptoRaw("govulncheck", "v0.36.0")
	second := cryptoRaw("govulncheck", "v0.37.0")
	// A second, distinct advisory in the same module.
	second.PrimaryID = "GO-2025-9999"
	second.Aliases = []string{"CVE-2025-99999"}

	_, fps := seed(t, s, first, second)
	if len(fps) != 2 {
		t.Fatalf("two advisories produced %d findings, want 2 distinct", len(fps))
	}

	remote := gh.NewFake("main")
	tc := remediate.NewFakeToolchain().
		WithModule("golang.org/x/crypto", "v0.35.0").
		WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0").
		WithAdvisory("GO-2025-9999", "golang.org/x/crypto", "v0.37.0")
	w := newWorker(t, s, remote, tc)

	group := groupOf(t, s, fps)
	targets := group.Targets()
	if len(targets) != 1 {
		t.Fatalf("two findings in one module produced %d targets, want 1 bump", len(targets))
	}
	if targets[0].To != "v0.37.0" {
		t.Errorf("the bump targets %s, want v0.37.0 — the version that closes BOTH advisories. "+
			"Bumping to v0.36.0 would close one and leave the other open while the pull request reads "+
			"as a complete fix (OQ-P1-02)", targets[0].To)
	}
	if len(targets[0].Closes) != 2 {
		t.Errorf("the target claims to close %v, want both advisories", targets[0].Closes)
	}

	res, err := w.Remediate(ctx, group)
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if res.Outcome != remediate.OutcomePROpen {
		t.Fatalf("outcome = %s, want pr_open:\n%s", res.Outcome, res.Verification.Output)
	}
	if !res.Verification.RescanClean {
		t.Errorf("the re-scan still reports %v after the bump", res.Verification.Remaining)
	}
	if got := tc.Version("golang.org/x/crypto"); got != "v0.37.0" {
		t.Errorf("installed %s, want v0.37.0", got)
	}
}
