package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/store"
)

// The scan worker: it drains the scan queue (migration 0017).
//
// Requests come from the interface, vfctl or the daily timer; the API only
// inserts them. The worker claims one request (or one batch) at a time and
// runs it through Sweep, the same path a scheduled sweep takes, so the
// results are recorded exactly as a sweep records them. It never invents an
// outcome: every request ends finished, failed, timed out, refused or
// interrupted, with the run that scanned it or the reason it was not.

// CauseScanTimedOut is the coverage-gap cause recorded when a scan exceeds
// its time limit. A timed-out scan is a gap, never a clean result.
const CauseScanTimedOut = "scan_timed_out"

// TimeoutDispatcher bounds each repository's scan.
type TimeoutDispatcher struct {
	Inner Dispatcher
	Limit time.Duration
}

var _ Dispatcher = (*TimeoutDispatcher)(nil)

// Dispatch runs the inner dispatch under the time limit. When the limit is
// hit, the result is a failed scan with cause scan_timed_out, owned by the
// platform, whatever partial output the inner dispatcher returned.
func (d *TimeoutDispatcher) Dispatch(ctx context.Context, job Job) (scan.Result, error) {
	if d.Limit <= 0 {
		return d.Inner.Dispatch(ctx, job)
	}
	tctx, cancel := context.WithTimeout(ctx, d.Limit)
	defer cancel()
	res, err := d.Inner.Dispatch(tctx, job)
	if errors.Is(tctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		return scan.Result{
			RunID: job.RunID, Repo: job.Repo, Dir: res.Dir,
			Outcome:     model.ScanFailed,
			ToolsFailed: []string{"time limit"},
			Gaps: []scan.CoverageGap{{
				Tool: "time limit", Classification: scan.GapTotal, Cause: CauseScanTimedOut,
				Detail: fmt.Sprintf("the scan of %s exceeded its %s time limit and was stopped; nothing it found is recorded as clean", job.Repo, d.Limit),
				Owner:  scan.OwnerPlatform,
			}},
		}, nil
	}
	return res, err
}

// ScanWorker drains the scan queue.
type ScanWorker struct {
	Orch *Orchestrator
	// ID names this worker in the queue; a restarted worker is a new ID.
	ID string
	// Credits is the rate budget each run starts with.
	Credits int
	// Heartbeat is how often a running request's heartbeat is renewed, and
	// StaleAfter how old a heartbeat must be before a request is treated as
	// orphaned by a worker that died. Zero means 15s and 2m.
	Heartbeat  time.Duration
	StaleAfter time.Duration
	// Poll is how long to wait when the queue is empty. Zero means 5s.
	Poll time.Duration
	// AfterRun is the post-sweep pass (enrich, triage, score, route), run
	// for the repositories a run scanned. Optional.
	AfterRun func(ctx context.Context, runID string, repos []store.Repo) error
	Log      *slog.Logger
}

// Recover marks requests orphaned by a worker that died as interrupted, so
// they can be retried. Called at start-up.
func (w *ScanWorker) Recover(ctx context.Context) (int, error) {
	now := w.Orch.clock()
	return w.Orch.Store.InterruptStaleScans(ctx, now.Add(-w.staleAfter()),
		"the scan worker stopped or restarted during the scan; nothing from it is recorded as done", now)
}

// Run drains the queue until ctx is cancelled. Requests this worker is
// running when it stops are marked interrupted, never left running or
// marked done.
func (w *ScanWorker) Run(ctx context.Context) error {
	if _, err := w.Recover(ctx); err != nil {
		return err
	}
	for {
		did, err := w.RunOnce(ctx)
		if ctx.Err() != nil {
			return w.stop()
		}
		if err != nil {
			w.log().Error("scan request", "error", err)
		}
		if did {
			continue
		}
		select {
		case <-ctx.Done():
			return w.stop()
		case <-time.After(w.poll()):
		}
	}
}

func (w *ScanWorker) stop() error {
	// The run's own context is gone; record the interruption regardless.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := w.Orch.Store.InterruptWorkerScans(ctx, w.ID,
		"the scan worker was stopped during the scan; retry it", w.Orch.clock())
	return err
}

// RunOnce claims and runs the next request or batch. did is false when the
// queue was empty.
func (w *ScanWorker) RunOnce(ctx context.Context) (did bool, err error) {
	st := w.Orch.Store
	claimed, ok, err := st.ClaimScans(ctx, w.ID, w.Orch.clock())
	if err != nil || !ok {
		return false, err
	}

	hbCtx, stopHB := context.WithCancel(ctx)
	defer stopHB()
	go w.heartbeat(hbCtx, claimed)

	// Refuse what may not be scanned, with the reason; keep the rest.
	var (
		repos  []store.Repo
		byRepo = map[string]store.ScanRequest{}
	)
	for _, r := range claimed {
		repo, why, err := w.eligible(ctx, r.Repo)
		if err != nil {
			return true, err
		}
		if why != "" {
			if err := st.FinishScan(ctx, r.ID, w.ID, store.ScanRefused, why, "", w.Orch.clock()); err != nil {
				return true, err
			}
			continue
		}
		repos = append(repos, repo)
		byRepo[repo.Name] = r
	}
	if len(repos) == 0 {
		return true, nil
	}

	kind, trigger := store.KindManual, "scan request "+claimed[0].ID
	if claimed[0].BatchID != "" {
		trigger = "scan batch " + claimed[0].BatchID
	}
	if claimed[0].Source == store.SourceTimer {
		kind = store.KindSweep
	}

	if w.Credits > 0 {
		w.Orch.Budget.Refresh(w.Credits)
	}
	stats, sweepErr := w.Orch.Sweep(ctx, kind, trigger, repos, DefaultSelector)
	if ctx.Err() != nil {
		// Stopped mid-run: stop() marks these interrupted.
		return true, ctx.Err()
	}
	if sweepErr == nil && w.AfterRun != nil && stats.RunID != "" {
		if err := w.AfterRun(ctx, stats.RunID, repos); err != nil {
			w.log().Error("post-sweep pass", "run", stats.RunID, "error", err)
		}
	}

	for name, r := range byRepo {
		status, reason := w.outcome(ctx, name, stats.RunID, sweepErr)
		if err := st.FinishScan(ctx, r.ID, w.ID, status, reason, stats.RunID, w.Orch.clock()); err != nil {
			return true, err
		}
	}
	return true, nil
}

// eligible returns the registered repository, or why it may not be scanned.
func (w *ScanWorker) eligible(ctx context.Context, name string) (store.Repo, string, error) {
	why, err := store.ScanRefusal(ctx, w.Orch.Store, name)
	if err != nil || why != "" {
		return store.Repo{}, why, err
	}
	repo, err := w.Orch.Store.GetRepo(ctx, name)
	return repo, "", err
}

// outcome reads what the run recorded for a repository.
func (w *ScanWorker) outcome(ctx context.Context, repo, runID string, sweepErr error) (store.ScanStatus, string) {
	if sweepErr != nil {
		return store.ScanFailed, "the run failed: " + sweepErr.Error()
	}
	results, err := w.Orch.Store.ScanResults(ctx, repo, 1)
	if err != nil {
		return store.ScanFailed, "the scan result could not be read: " + err.Error()
	}
	if len(results) == 0 || results[0].RunID != runID {
		return store.ScanFailed, "the run recorded no result for this repository"
	}
	r := results[0]
	switch {
	case r.FailureCause == CauseScanTimedOut:
		return store.ScanTimedOut, r.FailureDetail
	case r.Outcome == model.ScanComplete:
		return store.ScanFinished, ""
	case r.Outcome == model.ScanPartial:
		return store.ScanFinished, "partial: " + causeText(r)
	default:
		return store.ScanFailed, causeText(r)
	}
}

// causeText is a scan result's cause and detail, for the request's reason.
// The outcome itself is not repeated: the request's status already says it.
func causeText(r store.RepoScanResult) string {
	var parts []string
	if r.FailureCause != "" {
		parts = append(parts, r.FailureCause)
	}
	if r.FailureDetail != "" {
		parts = append(parts, r.FailureDetail)
	}
	if len(parts) == 0 {
		return string(r.Outcome)
	}
	return strings.Join(parts, ": ")
}

func (w *ScanWorker) heartbeat(ctx context.Context, claimed []store.ScanRequest) {
	ids := make([]string, len(claimed))
	for i, r := range claimed {
		ids[i] = r.ID
	}
	t := time.NewTicker(w.heartbeatEvery())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := w.Orch.Store.HeartbeatScans(ctx, w.ID, ids, w.Orch.clock()); err != nil && ctx.Err() == nil {
				w.log().Error("scan heartbeat", "error", err)
			}
		}
	}
}

func (w *ScanWorker) heartbeatEvery() time.Duration {
	if w.Heartbeat > 0 {
		return w.Heartbeat
	}
	return 15 * time.Second
}

func (w *ScanWorker) staleAfter() time.Duration {
	if w.StaleAfter > 0 {
		return w.StaleAfter
	}
	return 2 * time.Minute
}

func (w *ScanWorker) poll() time.Duration {
	if w.Poll > 0 {
		return w.Poll
	}
	return 5 * time.Second
}

func (w *ScanWorker) log() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.Default()
}
