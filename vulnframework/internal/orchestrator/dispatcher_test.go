package orchestrator_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/scan"
)

// optsRecorder is an adapter that records the options it ran with.
type optsRecorder struct{ got *scan.RunOpts }

func (optsRecorder) Name() string                   { return "recorder" }
func (optsRecorder) Version() string                { return "1" }
func (optsRecorder) Supports(scan.RepoProfile) bool { return true }
func (r optsRecorder) Run(_ context.Context, _ string, opts scan.RunOpts) (scan.RawOutput, error) {
	*r.got = opts
	return scan.RawOutput{Tool: "recorder"}, nil
}
func (optsRecorder) Normalize(scan.RawOutput) ([]model.RawFinding, error) { return nil, nil }

// A local clone's GitHub origin and working-tree state reach the scan only
// when the dispatcher is asked to read them (run.sh --real --nuguard), and
// the job keeps its registered name for everything else.
func TestTheLocalDispatcherReadsTheCloneOnlyWhenAsked(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+t.TempDir(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "first")
	run("remote", "add", "origin", "https://github.com/acme/agent.git")
	if err := os.WriteFile(filepath.Join(dir, "wip.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, read := range []bool{false, true} {
		var got scan.RunOpts
		reg, err := scan.NewRegistry(optsRecorder{&got})
		if err != nil {
			t.Fatal(err)
		}
		d := &orchestrator.LocalDispatcher{Worker: scan.NewWorker(reg), WorkDir: func(string) string { return dir }, ReadClone: read}
		res, err := d.Dispatch(context.Background(), orchestrator.Job{RunID: "S-1", Repo: "local/agent",
			Profile: scan.RepoProfile{Repo: "local/agent"}, Opts: scan.RunOpts{Mode: scan.ModeFull}})
		if err != nil {
			t.Fatal(err)
		}
		if got.Repo != "local/agent" || res.Repo != "local/agent" || len(got.CommitSHA) != 40 {
			t.Errorf("read=%v: repo %q / %q, commit %q", read, got.Repo, res.Repo, got.CommitSHA)
		}
		switch {
		case !read && got.LocalClone != nil:
			t.Errorf("the clone was read without being asked: %+v", got.LocalClone)
		case read && (got.LocalClone == nil || *got.LocalClone != scan.LocalClone{GitHubRepo: "acme/agent", WorkTree: scan.WorkTreeDirty}):
			t.Errorf("read: %+v, want acme/agent, dirty", got.LocalClone)
		}
	}
}
