package orchestrator

import (
	"context"
	"fmt"
	"sync"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
)

// LocalDispatcher runs scans in-process, for a single-node deployment and for
// end-to-end tests that want the real scan path without a cluster.
type LocalDispatcher struct {
	Worker  *scan.Worker
	WorkDir func(repo string) string
}

// Dispatch scans the repository in-process.
func (d *LocalDispatcher) Dispatch(ctx context.Context, job Job) (scan.Result, error) {
	dir := job.Repo
	if d.WorkDir != nil {
		dir = d.WorkDir(job.Repo)
	}
	return d.Worker.Scan(ctx, job.RunID, job.Repo, dir, job.Profile, job.Opts)
}

// FakeDispatcher is the offline dispatcher. It returns canned results and
// records what it was asked to run, so the orchestrator's planning, budgeting,
// lease and close behaviour can be exercised with no cluster and no scanners.
type FakeDispatcher struct {
	mu sync.Mutex

	// Results maps a repository to the result it should produce.
	Results map[string]scan.Result
	// Errors maps a repository to a dispatch failure — a worker that could not
	// be started, or that died before reporting.
	Errors map[string]error
	// Silent lists repositories whose worker starts and never reports. The
	// dispatch succeeds and no result is recorded, which is what run close must
	// see as no_result rather than as a clean scan.
	Silent map[string]bool

	dispatched []Job
}

// NewFakeDispatcher builds an empty fake.
func NewFakeDispatcher() *FakeDispatcher {
	return &FakeDispatcher{
		Results: map[string]scan.Result{},
		Errors:  map[string]error{},
		Silent:  map[string]bool{},
	}
}

// WithFindings registers a successful complete scan for a repository.
func (f *FakeDispatcher) WithFindings(repo string, tools []string, findings ...model.RawFinding) *FakeDispatcher {
	f.Results[repo] = scan.Result{
		Repo: repo, Outcome: model.ScanComplete,
		Findings: findings, ToolsOK: tools,
	}
	return f
}

// WithOutcome registers a scan that completed with a given outcome.
func (f *FakeDispatcher) WithOutcome(repo string, outcome model.ScanOutcome, toolsOK, toolsFailed []string) *FakeDispatcher {
	f.Results[repo] = scan.Result{
		Repo: repo, Outcome: outcome,
		ToolsOK: toolsOK, ToolsFailed: toolsFailed,
	}
	return f
}

// WithSilentWorker registers a repository whose worker never reports.
func (f *FakeDispatcher) WithSilentWorker(repo string) *FakeDispatcher {
	f.Silent[repo] = true
	return f
}

// WithDispatchError registers a repository whose worker cannot be started.
func (f *FakeDispatcher) WithDispatchError(repo string, err error) *FakeDispatcher {
	f.Errors[repo] = err
	return f
}

// Dispatch returns the canned result for a job.
func (f *FakeDispatcher) Dispatch(_ context.Context, job Job) (scan.Result, error) {
	f.mu.Lock()
	f.dispatched = append(f.dispatched, job)
	f.mu.Unlock()

	if err, ok := f.Errors[job.Repo]; ok {
		return scan.Result{}, err
	}
	if f.Silent[job.Repo] {
		return scan.Result{}, fmt.Errorf("worker for %s produced no result", job.Repo)
	}
	res, ok := f.Results[job.Repo]
	if !ok {
		return scan.Result{}, fmt.Errorf("fake dispatcher has no result registered for %q", job.Repo)
	}
	res.RunID = job.RunID
	res.Repo = job.Repo
	return res, nil
}

// Dispatched returns the jobs the fake was asked to run.
func (f *FakeDispatcher) Dispatched() []Job {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Job, len(f.dispatched))
	copy(out, f.dispatched)
	return out
}

// DispatchedRepos returns the repositories dispatched, in call order.
func (f *FakeDispatcher) DispatchedRepos() []string {
	jobs := f.Dispatched()
	out := make([]string, len(jobs))
	for i, j := range jobs {
		out[i] = j.Repo
	}
	return out
}
