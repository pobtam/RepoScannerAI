package orchestrator_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/nuguard"
	"github.com/wanaware/vulnframework/internal/nuguard/nuguardfake"
	"github.com/wanaware/vulnframework/internal/nuguardopt"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
	"github.com/wanaware/vulnframework/internal/store"
)

// The scan worker honours stored NuGuard settings (VM-UI-F-1203/1204), with
// the real scan worker, the real NuGuard adapter and the fake service.

const ngKey = "worker-test-nuguard-key"

func fullCeiling() nuguardopt.Ceiling {
	return nuguardopt.Ceiling{Configured: true, AllowTools: []string{"nga-rules", "atlas", "semgrep"}, AllowPosture: true,
		MaxTimeoutS: 600, Defaults: nuguardopt.Fleet{Enabled: true, Tools: []string{"nga-rules", "atlas", "semgrep"}, TimeoutS: 600}}
}

type ngRig struct {
	fake *nuguardfake.Server
	w    *orchestrator.ScanWorker
}

// nuguardWorker is a scan worker whose scans run the real NuGuard adapter
// against a fake service serving a captured result with code findings from
// all three of NuGuard's AI tools.
func nuguardWorker(t *testing.T, s store.Store, c nuguardopt.Ceiling) ngRig {
	t.Helper()
	result, err := os.ReadFile("../../testdata/fixtures/nuguard/ai-code.json")
	if err != nil {
		t.Fatal(err)
	}
	fake := nuguardfake.New(ngKey, "0.9.15")
	t.Cleanup(fake.Close)
	fake.Default = &nuguardfake.Script{Result: result}
	fake.Narrow = true
	ng := adapters.NewNuGuard(&nuguard.Client{BaseURL: fake.URL, APIKey: func() (string, error) { return ngKey, nil }}, "0.9.15", nil)
	reg, err := scan.NewRegistry(ng)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("5d0c7e9a1b2c3d4e5f60718293a4b5c6d7e8f901\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &orchestrator.LocalDispatcher{Worker: scan.NewWorker(reg), WorkDir: func(string) string { return dir }}
	w := worker(s, d, "w1")
	w.NuGuard = &orchestrator.NuGuardControl{Ceiling: c, Pinned: "0.9.15", Probe: func(ctx context.Context) orchestrator.NuGuardProbe {
		p := ng.Probe(ctx)
		return orchestrator.NuGuardProbe{Reachable: p.Reachable, ServiceVersion: p.ServiceVersion, ToolsAllowed: p.ToolsAllowed, Err: p.Err}
	}}
	return ngRig{fake: fake, w: w}
}

// scanOnce queues a request for repo with opts and runs it.
func (r ngRig) scanOnce(t *testing.T, s store.Store, id, repo string, opts *nuguardopt.Request) store.RepoScanResult {
	t.Helper()
	ctx := context.Background()
	if _, _, err := s.EnqueueScan(ctx, store.ScanRequest{ID: id, Repo: repo, Source: store.SourceWeb, RequestedBy: "pat",
		RequestedAt: at, Status: store.ScanQueued, NuGuard: opts}); err != nil {
		t.Fatal(err)
	}
	if did, err := r.w.RunOnce(ctx); err != nil || !did {
		t.Fatalf("RunOnce: did=%v err=%v", did, err)
	}
	req := get(t, s, id)
	if req.Status != store.ScanFinished {
		t.Fatalf("request %s ended %s: %s", id, req.Status, req.Reason)
	}
	res, err := s.ScanResults(ctx, repo, 1)
	if err != nil || len(res) != 1 || res[0].RunID != req.RunID {
		t.Fatalf("scan result: %+v, %v", res, err)
	}
	return res[0]
}

// nuguardFindings are the repository's open NuGuard findings.
func nuguardFindings(t *testing.T, s store.Store, repo string) []model.Finding {
	t.Helper()
	all, err := s.ListFindings(context.Background(), store.Query{Scope: store.ScopeOpen, Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	var out []model.Finding
	for _, f := range all {
		for _, tool := range f.Provenance.Tools {
			if tool == "nuguard" {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

func triageAll(t *testing.T, s store.Store, fs []model.Finding) {
	t.Helper()
	for _, f := range fs {
		if err := s.ApplyTransition(context.Background(), f.Fingerprint, model.Triaged,
			model.TransitionContext{Actor: model.ActorTriage, Cause: "test"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNuGuardOffForARepositoryIsNotRunAndClosesNothing(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fleet(t, s, "org/api")
		rig := nuguardWorker(t, s, fullCeiling())

		first := rig.scanOnce(t, s, "sr_1", "org/api", nil)
		if first.EffectiveNuGuard == nil || !first.EffectiveNuGuard.Enabled || first.EffectiveNuGuard.From != "worker default" {
			t.Fatalf("first scan's NuGuard options = %+v, want on from the worker default", first.EffectiveNuGuard)
		}
		found := nuguardFindings(t, s, "org/api")
		if len(found) == 0 {
			t.Fatal("the first scan recorded no NuGuard finding; the test would prove nothing")
		}
		triageAll(t, s, found)

		if _, err := s.SetNuGuardRepoOverride(ctx, "org/api", &nuguardopt.RepoOverride{Mode: nuguardopt.RepoOff},
			"owner", "pilot over", at); err != nil {
			t.Fatal(err)
		}
		submitted := len(rig.fake.Submissions())
		second := rig.scanOnce(t, s, "sr_2", "org/api", nil)

		if len(rig.fake.Submissions()) != submitted {
			t.Error("NuGuard was asked to scan a repository it is off for")
		}
		want := []store.ToolNotRequested{{Tool: "nuguard", Reason: "off for this repository"}}
		if !reflect.DeepEqual(second.ToolsNotRequested, want) {
			t.Errorf("not requested = %+v, want %+v", second.ToolsNotRequested, want)
		}
		if second.EffectiveNuGuard == nil || second.EffectiveNuGuard.Enabled || second.EffectiveNuGuard.From != "repository" {
			t.Errorf("effective = %+v, want off, from the repository", second.EffectiveNuGuard)
		}
		for _, tool := range append(second.ToolsOK, second.ToolsFailed...) {
			if tool == "nuguard" || strings.HasPrefix(tool, "nuguard/") {
				t.Errorf("%s is listed as ok or failed in a scan that did not ask for it", tool)
			}
		}
		// The ground rule: turning NuGuard off never resolves its findings.
		after := nuguardFindings(t, s, "org/api")
		if len(after) != len(found) {
			t.Fatalf("open NuGuard findings %d -> %d after a scan with NuGuard off", len(found), len(after))
		}
		for _, f := range after {
			if f.State != model.Triaged || !f.Derived.NotReobserved {
				t.Errorf("%s: state %s, not re-observed %v; want TRIAGED and flagged", f.Fingerprint, f.State, f.Derived.NotReobserved)
			}
		}
	})
}

func TestAScanWithFewerToolsAsksForThemAndRecordsTheRest(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		fleet(t, s, "org/api")
		rig := nuguardWorker(t, s, fullCeiling())
		res := rig.scanOnce(t, s, "sr_1", "org/api", &nuguardopt.Request{Mode: nuguardopt.RequestOn, Tools: []string{"atlas"}})

		subs := rig.fake.Submissions()
		if len(subs) != 1 || !reflect.DeepEqual(subs[0].Options["tools"], []any{"atlas"}) {
			t.Fatalf("NuGuard was asked for %v, want [atlas]", subs[len(subs)-1].Options["tools"])
		}
		if !reflect.DeepEqual(res.EffectiveNuGuard.Tools, []string{"atlas"}) || res.EffectiveNuGuard.From != "scan" {
			t.Errorf("effective = %+v, want atlas, from the scan", res.EffectiveNuGuard)
		}
		var notReq []string
		for _, n := range res.ToolsNotRequested {
			notReq = append(notReq, n.Tool)
		}
		if !reflect.DeepEqual(notReq, []string{"nuguard/nga-rules", "nuguard/semgrep"}) {
			t.Errorf("not requested = %v, want nga-rules and semgrep", notReq)
		}
		if !contains(res.ToolsOK, "nuguard/atlas") || contains(res.ToolsOK, "nuguard/semgrep") {
			t.Errorf("tools ok = %v, want nuguard/atlas and not semgrep", res.ToolsOK)
		}
	})
}

func TestAStoredSettingAboveTheCeilingIsClippedAndSaysSo(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fleet(t, s, "org/api")
		// Stored when the ceiling allowed semgrep; the operator has since
		// lowered it.
		if _, err := s.SetNuGuardSettings(ctx, nuguardopt.Fleet{Enabled: true, Tools: []string{"nga-rules", "semgrep"},
			TimeoutS: 900}, "owner", "", at); err != nil {
			t.Fatal(err)
		}
		c := fullCeiling()
		c.AllowTools = []string{"nga-rules", "atlas"}
		rig := nuguardWorker(t, s, c)
		res := rig.scanOnce(t, s, "sr_1", "org/api", nil)

		if got := rig.fake.Submissions()[0].Options["tools"]; !reflect.DeepEqual(got, []any{"nga-rules"}) {
			t.Errorf("NuGuard was asked for %v; a tool above the ceiling was honoured", got)
		}
		clips := res.EffectiveNuGuard.Clips
		if len(clips) != 2 || clips[0].Field != "tools" || clips[0].Asked != "semgrep" || clips[1].Field != "timeout_s" {
			t.Errorf("clip notes = %+v, want semgrep left out and the timeout capped", clips)
		}
	})
}

func TestTheWorkerPublishesNuGuardStatus(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		rig := nuguardWorker(t, s, fullCeiling())
		rig.fake.ToolsAllowed = []string{"nga-rules", "atlas"}
		if err := rig.w.PublishNuGuardStatus(ctx); err != nil {
			t.Fatal(err)
		}
		st, ok, err := s.NuGuardStatus(ctx)
		if err != nil || !ok {
			t.Fatalf("status: ok=%v err=%v", ok, err)
		}
		if !st.Configured || !st.Reachable || !st.VersionOK || st.ServiceVersion != "0.9.15" || st.CheckedAt.IsZero() {
			t.Errorf("status = %+v", st)
		}
		if !reflect.DeepEqual(st.Ceiling.ServiceTools, []string{"nga-rules", "atlas"}) {
			t.Errorf("ceiling's service tools = %v, want the service's own list", st.Ceiling.ServiceTools)
		}

		rig.fake.Close()
		if err := rig.w.PublishNuGuardStatus(ctx); err != nil {
			t.Fatal(err)
		}
		st, _, _ = s.NuGuardStatus(ctx)
		if st.Reachable || st.LastError == "" {
			t.Errorf("with the service down: %+v, want unreachable with the reason", st)
		}
		if strings.Contains(st.LastError, ngKey) {
			t.Errorf("the status quotes a credential: %q", st.LastError)
		}
	})
}

// A service down at start-up is re-checked soon, not in five minutes: the
// worker's status follows it as it comes up.
func TestAnUnreachableServiceIsRecheckedSoon(t *testing.T) {
	s := store.NewMemory()
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig := nuguardWorker(t, s, fullCeiling())
	rig.fake.NotReady = true
	rig.w.NuGuard.RetryEvery = 20 * time.Millisecond
	rig.w.NuGuard.Every = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rig.w.PublishNuGuardStatus(ctx); err != nil {
		t.Fatal(err)
	}
	go rig.w.Run(ctx)
	rig.fake.SetNotReady(false)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, ok, _ := s.NuGuardStatus(ctx); ok && st.Reachable {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the status still says unreachable after the service came up; a one-hour re-check was used")
}

func TestWithoutNuGuardTheWorkerRecordsNothingNew(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fleet(t, s, "org/api")
		queued(t, s, "sr_1", "org/api", "", store.SourceWeb, at)
		w := worker(s, funcDispatcher(cleanScan), "w1")
		w.NuGuard = &orchestrator.NuGuardControl{Pinned: "0.9.15"} // no -nuguard-url
		if err := w.PublishNuGuardStatus(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := w.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		res, _ := s.ScanResults(ctx, "org/api", 1)
		if len(res) != 1 || res[0].EffectiveNuGuard != nil || res[0].ToolsNotRequested != nil {
			t.Errorf("result = %+v; with NuGuard not configured nothing new is recorded", res)
		}
		st, ok, _ := s.NuGuardStatus(ctx)
		if !ok || st.Configured {
			t.Errorf("status = %+v (ok=%v), want one row saying not configured", st, ok)
		}
	})
}

func contains(l []string, x string) bool {
	for _, y := range l {
		if y == x {
			return true
		}
	}
	return false
}

// A sweep no request started (run.sh --real's start-of-run sweep, the daily
// timer) honours the stored settings as a requested scan does: a repository
// switched off in the interface is not scanned by NuGuard.
func TestASweepHonoursTheStoredSettings(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api", "org/web")
		if _, err := s.SetNuGuardRepoOverride(ctx, "org/api", &nuguardopt.RepoOverride{Mode: nuguardopt.RepoOff},
			"owner", "pilot over", at); err != nil {
			t.Fatal(err)
		}
		opts, err := orchestrator.ResolveSweepNuGuard(ctx, s, fullCeiling(), repos)
		if err != nil {
			t.Fatal(err)
		}
		api, web := opts.NuGuard["org/api"], opts.NuGuard["org/web"]
		if api == nil || api.Enabled || api.From != "repository" {
			t.Errorf("org/api = %+v, want off, from the repository", api)
		}
		if web == nil || !web.Enabled || len(web.Tools) != 3 {
			t.Errorf("org/web = %+v, want on with the defaults", web)
		}

		// Without NuGuard configured, nothing is resolved: the sweep runs as
		// it did before options existed.
		none, err := orchestrator.ResolveSweepNuGuard(ctx, s, nuguardopt.Ceiling{}, repos)
		if err != nil || none.NuGuard != nil {
			t.Errorf("unconfigured: %+v, %v", none, err)
		}
	})
}
