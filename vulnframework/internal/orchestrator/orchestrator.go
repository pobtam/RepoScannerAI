package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
)

// Job is one repository's scan assignment.
type Job struct {
	RunID      string
	Repo       string
	Profile    scan.RepoProfile
	Opts       scan.RunOpts
	APICredits int
}

// Dispatcher starts a scan worker for a job.
//
// It is an interface so the orchestrator is exercisable with no cluster, no
// credentials and no network: Fake is the offline implementation used by the
// tests.
type Dispatcher interface {
	Dispatch(ctx context.Context, job Job) (scan.Result, error)
}

// Config parameterises a run.
type Config struct {
	// MaxConcurrentScans caps parallelism across repositories (VM-AD §7.3).
	MaxConcurrentScans int
	// CreditsPerScan is the API budget one repository's scan is expected to
	// need (VM-AD §7.2).
	CreditsPerScan int
	// ScannerImage and ToolVersions are recorded on the run so a change in
	// finding counts is interpretable (VM-F-202).
	ScannerImage string
	ToolVersions map[string]string
	// LeaseDuration is how long a remediation claim is held before the sweeper
	// reclaims it (VM-AD §6.2).
	LeaseDuration time.Duration

	// EscalationThreshold is how many consecutive runs without a qualifying
	// scan trigger escalation (VM-F-215, VM-OQ-10's working default of 2).
	EscalationThreshold int

	// PR is the pull-request surface. When set, every sweep reconciles open
	// remediation pull requests against the remote and recovers stranded
	// findings — neither of which any human has to trigger.
	PR gh.PROps

	// SLAWindows are the remediation windows per tier and priority
	// (VM-NF-301). Nil uses the working defaults; VM-OQ-02 is still open.
	SLAWindows score.SLAWindows
}

func (c Config) withDefaults() Config {
	if c.MaxConcurrentScans <= 0 {
		c.MaxConcurrentScans = 20
	}
	if c.CreditsPerScan <= 0 {
		c.CreditsPerScan = 1
	}
	if c.LeaseDuration <= 0 {
		c.LeaseDuration = 30 * time.Minute
	}
	if c.EscalationThreshold <= 0 {
		c.EscalationThreshold = 2
	}
	return c
}

// Orchestrator plans and drives runs.
type Orchestrator struct {
	Store      store.Store
	Dispatcher Dispatcher
	Budget     *RateBudget
	Config     Config
	Clock      func() time.Time

	// Recovery accumulates every self-healing action taken.
	//
	// Always non-nil after New, and nil-safe regardless: a recovery nobody
	// records is the observability gap that lets a repeating fault present as
	// reliability (OQ-P9b-02).
	Recovery *RecoveryLog
}

// New builds an orchestrator.
func New(s store.Store, d Dispatcher, b *RateBudget, cfg Config) *Orchestrator {
	return &Orchestrator{
		Store: s, Dispatcher: d, Budget: b,
		Config:   cfg.withDefaults(),
		Clock:    func() time.Time { return time.Now().UTC() },
		Recovery: &RecoveryLog{},
	}
}

// Selector decides fleet membership (VM-FR §4 repo_selector).
type Selector func(store.Repo) (include bool, reason string)

// DefaultSelector includes every non-archived repository.
func DefaultSelector(r store.Repo) (bool, string) {
	if r.Archived {
		return false, store.SkipArchived
	}
	return true, ""
}

// RunStats summarises a sweep.
type RunStats struct {
	RunID      string
	Planned    int
	Dispatched int
	Skipped    int
	Close      store.CloseStats
	Reconcile  map[string]store.ReconcileStats

	// PlanOrder is the order repositories were planned in, most-stale coverage
	// first. Retained so the ordering is inspectable rather than merely
	// asserted (OQ-P4-01).
	PlanOrder []string

	// Staleness is the coverage-age distribution after the run, reported
	// alongside the gap count rather than instead of it: a flat gap count with a
	// growing maximum age is precisely the starvation a count cannot show.
	Staleness store.StalenessReport

	// Escalations are repositories whose streak without a qualifying scan has
	// crossed the threshold, whatever the cause (VM-F-215).
	Escalations []store.Escalation

	// PRSync is what reconciling against the remote found: pull requests a
	// human merged or closed since the last sweep (VM-F-545).
	PRSync SyncStats
	// Stranded is what the recovery sweep found. A non-zero Recovered is worth
	// reading as a signal, not just an outcome: it means something upstream
	// left findings in a state nothing could move.
	Stranded StrandStats
}

// Sweep plans, dispatches, closes and reconciles one run.
//
// The shape matters as much as the steps: the planned scope is recorded *before*
// anything is dispatched, and the run is closed against that plan. A repository
// that is skipped, never picked up, or dispatched to a worker that dies still
// leaves a row — coverage is measured against what was planned, never against
// what happened to report (OQ-P2-02).
func (o *Orchestrator) Sweep(ctx context.Context, kind store.RunKind, trigger string, repos []store.Repo, sel Selector) (RunStats, error) {
	if sel == nil {
		sel = DefaultSelector
	}
	stats := RunStats{Reconcile: map[string]store.ReconcileStats{}}

	run, err := o.Store.CreateRun(ctx, kind, trigger, o.Config.ScannerImage, o.Config.ToolVersions)
	if err != nil {
		return stats, err
	}
	stats.RunID = run.ID

	// 1. Record the planned scope, with a reason for anything excluded, ordered
	//    so the longest-uncovered repository is dispatched first.
	plan, err := o.plan(ctx, run.ID, kind, repos, sel)
	if err != nil {
		return stats, err
	}
	stats.Planned = len(plan)
	for _, e := range plan {
		stats.PlanOrder = append(stats.PlanOrder, e.Repo)
	}

	// 2. Dispatch what the budget and concurrency cap allow.
	dispatched, skipped, err := o.dispatch(ctx, run.ID, plan, repos)
	if err != nil {
		return stats, err
	}
	stats.Dispatched, stats.Skipped = dispatched, skipped

	// 3. Close the run against the plan: every planned repository that produced
	//    no result gets an explicit row.
	closeStats, err := o.Store.CloseRun(ctx, run.ID)
	if err != nil {
		return stats, err
	}
	stats.Close = closeStats

	// 4. Reconcile every planned repository, including the ones that never ran.
	//    Their findings are retained and flagged, never verified.
	for _, e := range plan {
		rs, err := o.Store.Reconcile(ctx, run.ID, e.Repo)
		if err != nil {
			return stats, fmt.Errorf("reconciling %s: %w", e.Repo, err)
		}
		stats.Reconcile[e.Repo] = rs
	}

	// 5. Coverage age across the in-scope fleet, and any escalations. Computed
	//    after close so deferrals and losses are already recorded.
	inScope := make([]string, 0, len(plan))
	for _, e := range plan {
		inScope = append(inScope, e.Repo)
	}
	coverage, err := o.Store.FleetCoverage(ctx, kind, inScope)
	if err != nil {
		return stats, err
	}
	stats.Staleness = store.Staleness(coverage, o.clock())
	stats.Escalations = store.Escalations(coverage, o.Config.EscalationThreshold)

	// 6. Reconcile the remediation side against the remote, and recover
	//    anything stranded.
	//
	//    Both run every sweep and neither needs a human. A pull request a
	//    reviewer closed, and a finding whose mechanism disappeared, are both
	//    invisible until something asks: they present as a repository with
	//    nothing to do (VM-F-545, VM-AD §6.1.2).
	if o.Config.PR != nil {
		for _, e := range plan {
			sync, err := o.SyncPullRequests(ctx, o.Config.PR, e.Repo)
			if err != nil {
				return stats, fmt.Errorf("syncing pull requests for %s: %w", e.Repo, err)
			}
			stats.PRSync.Examined += sync.Examined
			stats.PRSync.Merged += sync.Merged
			stats.PRSync.Declined += sync.Declined

			strands, err := o.SweepStranded(ctx, StrandSweep{Repo: e.Repo, PR: o.Config.PR})
			if err != nil {
				return stats, fmt.Errorf("sweeping stranded findings in %s: %w", e.Repo, err)
			}
			stats.Stranded.Examined += strands.Examined
			stats.Stranded.Recovered += strands.Recovered
		}
	}

	failed := closeStats.NotDispatched + closeStats.NoResult
	if err := o.Store.FinishRun(ctx, run.ID, len(plan), closeStats.Produced, failed); err != nil {
		return stats, err
	}
	return stats, nil
}

// plan records the in-scope set before any work starts, ordered by coverage
// staleness.
//
// Ordering is the starvation guard (OQ-P4-01). Planning in a fixed order lets a
// repository at the end of the fleet be deferred indefinitely whenever the
// budget is short, while the gap *count* stays flat and nothing looks wrong.
// Planning most-stale-first bounds the worst case instead: a repository deferred
// this run rises to the front of the next.
func (o *Orchestrator) plan(ctx context.Context, runID string, kind store.RunKind, repos []store.Repo, sel Selector) ([]store.PlanEntry, error) {
	now := o.clock()

	var inScope []string
	var excluded []store.PlanEntry
	for _, r := range repos {
		include, reason := sel(r)
		if !include {
			// Out of scope entirely: recorded so the decision is auditable, but
			// not counted as planned coverage.
			excluded = append(excluded, store.PlanEntry{
				RunID: runID, Repo: r.Name, State: store.DispatchSkipped,
				SkipReason: reason, PlannedAt: now,
			})
			continue
		}
		inScope = append(inScope, r.Name)
	}

	coverage, err := o.Store.FleetCoverage(ctx, kind, inScope)
	if err != nil {
		return nil, err
	}

	entries := make([]store.PlanEntry, 0, len(inScope))
	for _, c := range store.ByCoverageStaleness(coverage) {
		entries = append(entries, store.PlanEntry{
			RunID: runID, Repo: c.Repo, State: store.DispatchPlanned, PlannedAt: now,
		})
	}

	// The stored plan is sorted by name — it is a set, not an order — while the
	// returned slice carries the dispatch order.
	all := append(append([]store.PlanEntry{}, entries...), excluded...)
	sort.Slice(all, func(i, j int) bool { return all[i].Repo < all[j].Repo })
	if err := o.Store.RecordPlan(ctx, all); err != nil {
		return nil, err
	}
	return entries, nil
}

// dispatch starts workers for the planned set, recording a reason for anything
// it cannot start.
func (o *Orchestrator) dispatch(ctx context.Context, runID string, plan []store.PlanEntry, repos []store.Repo) (int, int, error) {
	byName := map[string]store.Repo{}
	for _, r := range repos {
		byName[r.Name] = r
	}

	var (
		mu         sync.Mutex
		dispatched int
		skipped    int
		firstErr   error
	)

	sem := make(chan struct{}, o.Config.MaxConcurrentScans)
	var wg sync.WaitGroup

	for _, e := range plan {
		// The budget is consulted before the worker starts. Exhaustion is a
		// recorded skip, never a silent omission: a repository deferred for
		// budget must appear in the gaps view with its reason, or the fleet
		// looks smaller than it is (OQ-P2-02).
		if err := o.Budget.Acquire(o.Config.CreditsPerScan); err != nil {
			var exhausted *ErrBudgetExhausted
			if !errors.As(err, &exhausted) {
				return dispatched, skipped, err
			}
			if err := o.Store.MarkSkipped(ctx, runID, e.Repo, store.SkipBudgetExhausted); err != nil {
				return dispatched, skipped, err
			}
			skipped++
			continue
		}

		if err := o.Store.MarkDispatched(ctx, runID, e.Repo); err != nil {
			o.Budget.Release(o.Config.CreditsPerScan)
			return dispatched, skipped, err
		}
		dispatched++

		wg.Add(1)
		sem <- struct{}{}
		go func(entry store.PlanEntry) {
			defer wg.Done()
			defer func() { <-sem }()
			defer o.Budget.Consume(o.Config.CreditsPerScan)

			repo := byName[entry.Repo]
			job := Job{
				RunID: runID, Repo: entry.Repo,
				Profile: scan.RepoProfile{
					Repo: entry.Repo, Tier: repo.Tier,
					Languages: languagesOf(repo), HasTestSuite: repo.HasTestSuite,
				},
				Opts:       scan.RunOpts{Mode: scan.ModeFull, APICredits: o.Config.CreditsPerScan},
				APICredits: o.Config.CreditsPerScan,
			}

			result, err := o.Dispatcher.Dispatch(ctx, job)
			if err != nil {
				// A worker that could not be started leaves no scan result. The
				// run close records it as no_result: dispatched and lost, which
				// is a different problem from never dispatched.
				return
			}
			if err := o.record(ctx, result); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(e)
	}

	wg.Wait()
	return dispatched, skipped, firstErr
}

// record persists one worker's result.
func (o *Orchestrator) record(ctx context.Context, res scan.Result) error {
	// The dependency manifest, before the findings. Without this the
	// reverse-dependency index is empty and the entire first-party wave design
	// is inert — a consumer reading a field no producer wrote, which is the
	// defect Phase 11 found three times (OQ-P11-01).
	if len(res.Deps) > 0 {
		deps := make([]store.ModuleDep, 0, len(res.Deps))
		for _, d := range res.Deps {
			deps = append(deps, store.ModuleDep{
				Module: d.Module, Version: d.Version, Direct: d.Direct, Replaced: d.Replaced,
			})
		}
		if err := o.Store.RecordDeps(ctx, res.RunID, res.Repo, deps); err != nil {
			return err
		}
	}

	if _, err := o.Store.UpsertObservations(ctx, res.RunID, res.Repo, res.Findings); err != nil {
		return fmt.Errorf("recording findings for %s: %w", res.Repo, err)
	}

	scanResult := store.RepoScanResult{
		RunID: res.RunID, Repo: res.Repo, Outcome: res.Outcome,
		ToolsOK: res.ToolsOK, ToolsFailed: res.ToolsFailed,
		DurationSec: res.DurationSec,
	}
	if len(res.Gaps) > 0 {
		g := res.Gaps[0]
		scanResult.FailureCause = g.Cause
		scanResult.FailureDetail = g.Detail
		scanResult.FailureOwner = string(g.Owner)
	}
	return o.Store.RecordScanResult(ctx, scanResult)
}

// SweepLeases reverts findings whose remediation claim has lapsed
// (VM-AD §6.2, VM-F-158).
//
// Run every 60 seconds. This is the only thing preventing a crashed worker from
// stranding a finding in AUTO_REMEDIATING permanently.
func (o *Orchestrator) SweepLeases(ctx context.Context) (int, error) {
	now := o.clock()
	n, err := o.Store.SweepExpiredLeases(ctx, now)
	if n > 0 {
		// Loud, even though the sweep is routine. A lease reclaimed once is
		// the machinery working; leases reclaimed every cycle mean workers are
		// dying, and nothing else in the system would say so.
		o.Recovery.Record(RecoveryEvent{
			Kind:   RecoveryLeaseExpired,
			Reason: fmt.Sprintf("%d finding leases lapsed and were reclaimed; their findings returned to the queue", n),
			At:     now,
		})
	}
	return n, err
}

// SweepRepoLocks reclaims repository locks whose holder died.
func (o *Orchestrator) SweepRepoLocks(ctx context.Context) (int, error) {
	now := o.clock()
	n, err := o.Store.SweepExpiredRepoLocks(ctx, now)
	if n > 0 {
		o.Recovery.Record(RecoveryEvent{
			Kind:   RecoveryRepoLockExpired,
			Reason: fmt.Sprintf("%d repository remediation locks outlived their holders and were reclaimed", n),
			At:     now,
		})
	}
	return n, err
}

// RunLeaseSweeper sweeps on an interval until the context is cancelled.
func (o *Orchestrator) RunLeaseSweeper(ctx context.Context, every time.Duration, onErr func(error)) {
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := o.SweepLeases(ctx); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}

// Lease claims a finding for remediation and moves it to AUTO_REMEDIATING.
//
// The lease is acquired FIRST. AUTO_REMEDIATING is lease-bound and the store
// refuses to enter it unleased (VM-AD §6.1.5), so the other order would fail —
// and would be wrong even if it did not, because it would publish a state that
// claims a worker holds the finding a moment before one does.
func (o *Orchestrator) Lease(ctx context.Context, fingerprint, owner string) error {
	now := o.clock()
	if err := o.Store.AcquireLease(ctx, fingerprint, owner, now.Add(o.Config.LeaseDuration)); err != nil {
		return err
	}
	if err := o.Store.ApplyTransition(ctx, fingerprint, model.AutoRemediating, model.TransitionContext{
		Actor: model.ActorOrchestrator, Cause: "dispatched to " + owner, At: now,
	}); err != nil {
		// Do not leave a lease behind for a claim that did not happen: the
		// finding would then be unclaimable until the sweeper expired it.
		_ = o.Store.ReleaseLease(ctx, fingerprint)
		return err
	}
	return nil
}

func (o *Orchestrator) clock() time.Time {
	if o.Clock != nil {
		return o.Clock()
	}
	return time.Now().UTC()
}

func languagesOf(r store.Repo) []scan.Language {
	out := make([]scan.Language, 0, len(r.Languages))
	for _, l := range r.Languages {
		out = append(out, scan.Language(l))
	}
	return out
}
