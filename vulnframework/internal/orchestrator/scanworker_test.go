package orchestrator_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/store"
)

// funcDispatcher scans by calling fn.
type funcDispatcher func(ctx context.Context, job orchestrator.Job) (scan.Result, error)

func (f funcDispatcher) Dispatch(ctx context.Context, job orchestrator.Job) (scan.Result, error) {
	return f(ctx, job)
}

// cleanScan completes every repository with no findings.
func cleanScan(_ context.Context, job orchestrator.Job) (scan.Result, error) {
	return scan.Result{RunID: job.RunID, Repo: job.Repo, Outcome: model.ScanComplete, ToolsOK: []string{"probe"}}, nil
}

// hangingScan blocks until its context ends, like a scanner that never returns.
func hangingScan(ctx context.Context, job orchestrator.Job) (scan.Result, error) {
	<-ctx.Done()
	return scan.Result{RunID: job.RunID, Repo: job.Repo}, ctx.Err()
}

func queued(t *testing.T, s store.Store, id, repo, batch string, source store.ScanSource, at time.Time) {
	t.Helper()
	_, _, err := s.EnqueueScan(context.Background(), store.ScanRequest{
		ID: id, Repo: repo, BatchID: batch, Source: source, RequestedBy: "pat", RequestedAt: at, Status: store.ScanQueued,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func worker(s store.Store, d orchestrator.Dispatcher, id string) *orchestrator.ScanWorker {
	o := newOrchestrator(s, d, orchestrator.NewRateBudget(10), orchestrator.Config{MaxConcurrentScans: 2, CreditsPerScan: 1})
	return &orchestrator.ScanWorker{Orch: o, ID: id, Credits: 10, Heartbeat: 10 * time.Millisecond}
}

func get(t *testing.T, s store.Store, id string) store.ScanRequest {
	t.Helper()
	r, ok, err := s.GetScanRequest(context.Background(), id)
	if err != nil || !ok {
		t.Fatalf("scan request %s: ok=%v err=%v", id, ok, err)
	}
	return r
}

func TestScanWorkerRunsARequestThroughTheSweepPath(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fleet(t, s, "org/api")
		queued(t, s, "sr_1", "org/api", "", store.SourceWeb, at)

		var afterRun atomic.Int32
		w := worker(s, funcDispatcher(cleanScan), "w1")
		w.AfterRun = func(context.Context, string, []store.Repo) error { afterRun.Add(1); return nil }
		did, err := w.RunOnce(ctx)
		if err != nil || !did {
			t.Fatalf("RunOnce: did=%v err=%v", did, err)
		}

		r := get(t, s, "sr_1")
		if r.Status != store.ScanFinished || r.RunID == "" || r.FinishedAt == nil {
			t.Fatalf("request after the run: %+v", r)
		}
		if !strings.HasPrefix(r.RunID, store.KindManual.Prefix()) {
			t.Errorf("a web request ran as %s; want a manual run", r.RunID)
		}
		res, _ := s.ScanResults(ctx, "org/api", 1)
		if len(res) != 1 || res[0].RunID != r.RunID || res[0].Outcome != model.ScanComplete {
			t.Errorf("the run's recorded result: %+v", res)
		}
		if afterRun.Load() != 1 {
			t.Errorf("the post-sweep pass ran %d times, want 1", afterRun.Load())
		}

		if did, _ := w.RunOnce(ctx); did {
			t.Error("RunOnce did work on an empty queue")
		}
	})
}

func TestScanWorkerRefusesWhatMayNotBeScanned(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api", "org/old")
		old := repos[1]
		old.Archived = true
		if err := s.UpsertRepo(ctx, old); err != nil {
			t.Fatal(err)
		}
		if err := s.SetExclusion(ctx, store.RepoExclusion{Name: "org/old", Reason: "a vendored mirror", ExcludedBy: "pat", ExcludedAt: at}); err != nil {
			t.Fatal(err)
		}
		queued(t, s, "sr_x", "org/old", "", store.SourceWeb, at)
		queued(t, s, "sr_u", "org/unknown", "", store.SourceWeb, at.Add(time.Second))

		var scanned atomic.Int32
		w := worker(s, funcDispatcher(func(ctx context.Context, j orchestrator.Job) (scan.Result, error) {
			scanned.Add(1)
			return cleanScan(ctx, j)
		}), "w1")
		for i := 0; i < 2; i++ {
			if _, err := w.RunOnce(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if r := get(t, s, "sr_x"); r.Status != store.ScanRefused || !strings.Contains(r.Reason, "excluded by pat: a vendored mirror") {
			t.Errorf("excluded repository: %+v", r)
		}
		if r := get(t, s, "sr_u"); r.Status != store.ScanRefused || !strings.Contains(r.Reason, "not a registered repository") {
			t.Errorf("unregistered repository: %+v", r)
		}
		if scanned.Load() != 0 {
			t.Errorf("%d refused repositories were scanned", scanned.Load())
		}
	})
}

// A timed-out scan is recorded as a coverage gap with its cause, and the
// request says it timed out. Never clean.
func TestATimedOutScanIsAGapNeverClean(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fleet(t, s, "org/slow")
		queued(t, s, "sr_t", "org/slow", "", store.SourceWeb, at)

		d := &orchestrator.TimeoutDispatcher{Inner: funcDispatcher(hangingScan), Limit: 50 * time.Millisecond}
		w := worker(s, d, "w1")
		if _, err := w.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}

		r := get(t, s, "sr_t")
		if r.Status != store.ScanTimedOut || !strings.Contains(r.Reason, "time limit") || r.RunID == "" {
			t.Fatalf("timed-out request: %+v", r)
		}
		res, _ := s.ScanResults(ctx, "org/slow", 1)
		if len(res) != 1 || res[0].Outcome != model.ScanFailed || res[0].FailureCause != orchestrator.CauseScanTimedOut {
			t.Fatalf("recorded result: %+v; want failed with cause %s", res, orchestrator.CauseScanTimedOut)
		}
		if res[0].Outcome.Succeeded() {
			t.Error("a timed-out scan counts as a successful one")
		}
	})
}

// A worker that dies leaves its requests running; the next worker marks them
// interrupted, and they can be retried. A worker that is stopped marks its
// own.
func TestInterruptedScansAreRetryableNeverLostOrDone(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fleet(t, s, "org/api", "org/web")

		// A worker claims and dies: its heartbeat is never renewed.
		queued(t, s, "sr_d", "org/api", "", store.SourceWeb, at)
		if _, _, err := s.ClaimScans(ctx, "w-dead", at); err != nil {
			t.Fatal(err)
		}
		w := worker(s, funcDispatcher(cleanScan), "w-new")
		w.Orch.Clock = func() time.Time { return at.Add(10 * time.Minute) }
		if n, err := w.Recover(ctx); err != nil || n != 1 {
			t.Fatalf("Recover: n=%d err=%v", n, err)
		}
		dead := get(t, s, "sr_d")
		if dead.Status != store.ScanInterrupted || dead.Reason == "" || dead.RunID != "" {
			t.Fatalf("orphaned request: %+v", dead)
		}
		// Retry: a new request pointing at the old one, which runs normally.
		if _, merged, err := s.EnqueueScan(ctx, store.ScanRequest{ID: "sr_d2", Repo: "org/api", Source: store.SourceWeb,
			RequestedBy: "pat", RequestedAt: at.Add(11 * time.Minute), Status: store.ScanQueued, RetryOf: "sr_d"}); err != nil || merged {
			t.Fatalf("retry: merged=%v err=%v", merged, err)
		}
		if _, err := w.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if r := get(t, s, "sr_d2"); r.Status != store.ScanFinished || r.RetryOf != "sr_d" {
			t.Errorf("retried request: %+v", r)
		}

		// A worker stopped mid-scan marks its request interrupted.
		queued(t, s, "sr_s", "org/web", "", store.SourceWeb, at.Add(12*time.Minute))
		started := make(chan struct{})
		stopping := worker(s, funcDispatcher(func(ctx context.Context, j orchestrator.Job) (scan.Result, error) {
			close(started)
			return hangingScan(ctx, j)
		}), "w-stop")
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- stopping.Run(runCtx) }()
		<-started
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run returned %v", err)
		}
		if r := get(t, s, "sr_s"); r.Status != store.ScanInterrupted || !strings.Contains(r.Reason, "stopped") {
			t.Errorf("request of a stopped worker: %+v", r)
		}
	})
}

// "Scan all included repositories" from the interface or vfctl is a fleet run
// like the timer's: one sweep run, so it is drawn on the trend.
func TestAScanAllBatchIsOneSweepRun(t *testing.T) {
	for _, source := range []store.ScanSource{store.SourceWeb, store.SourceVfctl} {
		t.Run(string(source), func(t *testing.T) {
			run(t, func(t *testing.T, s store.Store) {
				ctx := context.Background()
				fleet(t, s, "org/a", "org/b")
				queued(t, s, "sr_a", "org/a", "batch-all", source, at)
				queued(t, s, "sr_b", "org/b", "batch-all", source, at.Add(time.Millisecond))
				w := worker(s, funcDispatcher(cleanScan), "w1")
				if _, err := w.RunOnce(ctx); err != nil {
					t.Fatal(err)
				}
				a, b := get(t, s, "sr_a"), get(t, s, "sr_b")
				if a.Status != store.ScanFinished || b.Status != store.ScanFinished || a.RunID != b.RunID {
					t.Fatalf("the batch did not run as one run: %+v / %+v", a, b)
				}
				if !strings.HasPrefix(a.RunID, store.KindSweep.Prefix()) {
					t.Errorf("a %s batch ran as %s; want a sweep run", source, a.RunID)
				}
				runs, err := s.Runs(ctx, store.RunQuery{Kind: store.KindSweep, Limit: 5})
				if err != nil || len(runs) != 1 || runs[0].ID != a.RunID || runs[0].TriggerDetail != "scan batch batch-all" {
					t.Errorf("sweep runs: %+v, %v", runs, err)
				}
			})
		})
	}
}

// The daily timer uses the same queue: its batch is one sweep run over every
// repository in it.
func TestATimerBatchIsOneSweepRun(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fleet(t, s, "org/a", "org/b", "org/c")
		for i, repo := range []string{"org/a", "org/b", "org/c"} {
			queued(t, s, "sr_t"+repo[len(repo)-1:], repo, "batch-1", store.SourceTimer, at.Add(time.Duration(i)*time.Millisecond))
		}
		w := worker(s, funcDispatcher(cleanScan), "w1")
		if _, err := w.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		var runs = map[string]bool{}
		for _, id := range []string{"sr_ta", "sr_tb", "sr_tc"} {
			r := get(t, s, id)
			if r.Status != store.ScanFinished {
				t.Errorf("%s: %+v", id, r)
			}
			runs[r.RunID] = true
		}
		if len(runs) != 1 {
			t.Fatalf("the batch ran as %d runs, want 1", len(runs))
		}
		for id := range runs {
			if !strings.HasPrefix(id, store.KindSweep.Prefix()) {
				t.Errorf("the timer's run %s is not a sweep run", id)
			}
		}
	})
}
