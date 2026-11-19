package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/nuguardopt"
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

	// PR is the pull-request surface. When set, every sweep RECONCILES the
	// pull requests nothing has vouched for and recovers stranded findings —
	// neither of which any human has to trigger.
	PR gh.PROps

	// FirstParty is the module registry. When set, every finding is classified
	// as it is recorded, which is what makes the first-party defer and the
	// wave view reachable (VM-F-601, OQ-AUDIT-09).
	FirstParty *firstparty.Registry

	// ReconcileHorizon, WebhookSilence and ReconcileChecks tune the fallback
	// reconciliation (OQ-P12-01). Zero uses the defaults, which are chosen so
	// that a live webhook costs nothing and a dead one is noticed within one
	// sweep.
	ReconcileHorizon time.Duration
	WebhookSilence   time.Duration
	ReconcileChecks  int

	// SLAWindows are the remediation windows per tier and priority
	// (VM-NF-301). Nil uses the working defaults; VM-OQ-02 is still open.
	SLAWindows score.SLAWindows

	// SBOMMaxBytes caps an AI-SBOM a scan asked to keep
	// (-nuguard-sbom-max-bytes). A larger one is not stored, and the row
	// says why. Zero means 4 MiB.
	SBOMMaxBytes int64
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
	if c.SBOMMaxBytes <= 0 {
		c.SBOMMaxBytes = 4 << 20
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
	return o.SweepWith(ctx, kind, trigger, repos, sel, SweepOptions{})
}

// SweepOptions are per-repository options a sweep passes on each job.
type SweepOptions struct {
	// NuGuard is each repository's resolved NuGuard options, by name. A
	// repository not in the map has none, and the adapter's own
	// configuration applies.
	NuGuard map[string]*nuguardopt.Effective
}

// SweepWith is Sweep with per-repository options.
func (o *Orchestrator) SweepWith(ctx context.Context, kind store.RunKind, trigger string, repos []store.Repo, sel Selector, opts SweepOptions) (RunStats, error) {
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
	dispatched, skipped, err := o.dispatch(ctx, run.ID, plan, repos, opts)
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
			sync, err := o.ReconcilePullRequests(ctx, ReconcileConfig{
				PR: o.Config.PR, Repo: e.Repo,
				Horizon: o.Config.ReconcileHorizon, Silence: o.Config.WebhookSilence,
				MaxChecks: o.Config.ReconcileChecks,
			})
			if err != nil {
				return stats, fmt.Errorf("reconciling pull requests for %s: %w", e.Repo, err)
			}
			stats.PRSync.Examined += sync.Examined
			stats.PRSync.Merged += sync.Merged
			stats.PRSync.Declined += sync.Declined
			stats.PRSync.Confirmed += sync.Confirmed
			stats.PRSync.Deferred += sync.Deferred
			stats.PRSync.Lost += sync.Lost
			stats.PRSync.WebhookLive = sync.WebhookLive

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
func (o *Orchestrator) dispatch(ctx context.Context, runID string, plan []store.PlanEntry, repos []store.Repo, opts SweepOptions) (int, int, error) {
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
					HasLockfile: repo.HasLockfile,
				},
				Opts: scan.RunOpts{Mode: scan.ModeFull, APICredits: o.Config.CreditsPerScan,
					NuGuard: opts.NuGuard[entry.Repo]},
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

	// First-party classification, before the findings are stored (VM-F-601).
	//
	// This is the step that was missing. The registry could classify, the
	// adapters wrote the import path it reads, policy rule 6 read the result —
	// and NOTHING CALLED IT, so Classification.FirstPartyPath was never
	// written by the running pipeline, the first-party defer could never fire,
	// and the wave view had nothing to show. The same defect as the eight the
	// Producer-Coverage Audit found, in a different shape: not a field with no
	// producer, but a producer nothing invokes (OQ-AUDIT-09).
	//
	// Here rather than in the scan worker because the registry is
	// orchestration configuration: a scan worker holds no credential and no
	// fleet-wide policy, and giving it the registry would put a
	// fleet-ownership decision inside a per-repository job.
	findings := res.Findings
	if o.Config.FirstParty != nil {
		findings = o.Config.FirstParty.ClassifyAll(findings)
	}
	if _, err := o.Store.UpsertObservations(ctx, res.RunID, res.Repo, findings); err != nil {
		return fmt.Errorf("recording findings for %s: %w", res.Repo, err)
	}

	// Secrets the repository's own allowlist hid. They were observed — they
	// are in the files — and the allowlist is a proposal for a human, never a
	// fix. Recorded after the observations so a new finding exists to
	// propose against.
	if err := o.ApplyAllowlist(ctx, res.RunID, res.Repo, findings); err != nil {
		return fmt.Errorf("recording allowlist evidence for %s: %w", res.Repo, err)
	}

	scanResult := store.RepoScanResult{
		RunID: res.RunID, Repo: res.Repo, Outcome: res.Outcome,
		ToolsOK: res.ToolsOK, ToolsFailed: res.ToolsFailed,
		DurationSec: res.DurationSec, CommitSHA: res.CommitSHA,
		EffectiveNuGuard: res.EffectiveNuGuard, ToolsNotRequested: res.ToolsNotRequested,
	}
	if res.AISBOM != nil {
		if err := o.keepSBOM(ctx, res); err != nil {
			return fmt.Errorf("keeping the AI-SBOM of %s: %w", res.Repo, err)
		}
	}
	if res.AIInventory != nil {
		inv, err := json.Marshal(res.AIInventory)
		if err != nil {
			return fmt.Errorf("encoding the AI inventory for %s: %w", res.Repo, err)
		}
		scanResult.AIInventory = inv
	}
	if len(res.Gaps) > 0 {
		g := res.Gaps[0]
		scanResult.FailureCause = g.Cause
		scanResult.FailureDetail = g.Detail
		scanResult.FailureOwner = string(g.Owner)
	}
	return o.Store.RecordScanResult(ctx, scanResult)
}

// keepSBOM stores the AI-SBOM a scan asked to keep, or, over the cap, the
// reason it was not kept: never a truncated document.
func (o *Orchestrator) keepSBOM(ctx context.Context, res scan.Result) error {
	doc := res.AISBOM.Document
	sum := sha256.Sum256(doc)
	s := store.AISBOM{
		RunID: res.RunID, Repo: res.Repo, CommitSHA: res.CommitSHA, NuGuardVersion: res.AISBOM.Version,
		SizeBytes: int64(len(doc)), SHA256: hex.EncodeToString(sum[:]), StoredAt: o.clock(),
	}
	if s.SizeBytes > o.Config.SBOMMaxBytes {
		s.Withheld = fmt.Sprintf("the AI-SBOM is %d bytes, over the %d-byte cap (-nuguard-sbom-max-bytes); it was not stored",
			s.SizeBytes, o.Config.SBOMMaxBytes)
	} else {
		s.Document = doc
	}
	return o.Store.PutAISBOM(ctx, s)
}

// ApplyAllowlist splits a scan's secrets into those the ordinary scan reported
// and those only an allowlist hid, and hands both to the store. Called for
// every recorded scan result; exported so a caller recording observations
// itself applies the same step.
//
// A secret reported by the ordinary scan is not allowlisted, whatever else
// says so: the allowlist demonstrably did not hide it.
func (o *Orchestrator) ApplyAllowlist(ctx context.Context, runID, repo string, findings []model.RawFinding) error {
	allowlisted := map[string]model.Allowlist{}
	seen := map[string]bool{}
	var observed []string
	for _, f := range findings {
		if f.Category != model.CategorySecret {
			continue
		}
		fp := fingerprint.Compute(f)
		if f.Allowlisted != nil {
			allowlisted[fp] = *f.Allowlisted
			continue
		}
		if !seen[fp] {
			seen[fp] = true
			observed = append(observed, fp)
		}
	}
	for fp := range seen {
		delete(allowlisted, fp)
	}
	if len(allowlisted) == 0 && len(observed) == 0 {
		return nil
	}
	_, err := o.Store.ApplyAllowlist(ctx, runID, repo, allowlisted, observed)
	return err
}

// EscalateOverdueProposals escalates suppression proposals nobody reviewed
// within the secret SLA window: back to NEEDS_HUMAN, still decidable, marked
// overdue. A proposal is a secret someone wants to stop hearing about; one
// that sits unread is a secret nobody is looking at.
//
// The window is the P0 window for the repository's tier — secrets take
// maximum priority (VM-F-851) — measured from when the proposal was made.
func (o *Orchestrator) EscalateOverdueProposals(ctx context.Context, repo store.Repo) (int, error) {
	open, err := o.Store.ListFindings(ctx, store.Query{
		Scope: store.ScopeOpen, Repo: repo.Name, States: []model.State{model.FPCandidate},
	})
	if err != nil {
		return 0, err
	}
	now := o.clock()
	window := o.SLAWindows().Window(repo.Tier, model.P0)
	n := 0
	for _, f := range open {
		p := f.SuppressionProposal
		if p == nil || p.Status != model.ProposalPending || now.Sub(p.ProposedAt) <= window {
			continue
		}
		cause := fmt.Sprintf("suppression proposal (allowlisted by %s) unreviewed for %s, past the %s secret SLA window: escalated again",
			p.Path, now.Sub(p.ProposedAt).Round(time.Hour), window)
		if err := o.Store.EscalateProposal(ctx, f.Fingerprint, now, cause); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
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
