package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

// quietTool is a local adapter that always runs and finds nothing, so a
// repository with NuGuard off still has a scan to record.
type quietTool struct{}

func (quietTool) Name() string                   { return "local-check" }
func (quietTool) Version() string                { return "1" }
func (quietTool) Supports(scan.RepoProfile) bool { return true }
func (quietTool) Run(context.Context, string, scan.RunOpts) (scan.RawOutput, error) {
	return scan.RawOutput{Tool: "local-check", ToolVersion: "1", Stdout: []byte("[]")}, nil
}
func (quietTool) Normalize(scan.RawOutput) ([]model.RawFinding, error) { return nil, nil }

// TestNuGuardViewsFromTheRealServer drives the NuGuard controls end to end
// (the real API, the real scan worker, the real adapter against the fake
// service) and checks every view the interface reads. With
// UPDATE_UI_FIXTURES=1 it writes the responses as the interface's test
// fixtures, so the interface is tested against what this server sends.
func TestNuGuardViewsFromTheRealServer(t *testing.T) {
	e := newScanEnv(t, scanBackends(t)["memory"](t), true)
	ctx := context.Background()
	for _, name := range []string{"octo/api", "octo/web"} {
		if err := e.st.UpsertRepo(ctx, store.Repo{Name: name, Tier: 2, Languages: []string{"go"}}); err != nil {
			t.Fatal(err)
		}
	}
	capture := func(name, method, path string, c caller, body string, want int) []byte {
		t.Helper()
		var status int
		var raw []byte
		if method == http.MethodGet {
			status, _, raw = e.do(t, method, path, c, "", nil)
		} else {
			status, _, raw = e.do(t, method, path, c, body, map[string]string{
				"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": e.csrf(t, c), "Content-Type": "application/json"})
		}
		if status != want {
			t.Fatalf("%s %s = %d %s; want %d", method, path, status, raw, want)
		}
		if name != "" {
			saveUIFixture(t, name, raw)
		}
		return raw
	}

	capture("nuguard-not-configured.json", http.MethodGet, "/v1/nuguard", owner, "", 200)

	result, err := os.ReadFile("../../testdata/fixtures/nuguard/ai-code.json")
	if err != nil {
		t.Fatal(err)
	}
	const key = "fixture-nuguard-key"
	fake := nuguardfake.New(key, "0.9.15")
	t.Cleanup(fake.Close)
	fake.Default = &nuguardfake.Script{Result: result}
	fake.ToolsAllowed = []string{"nga-rules", "atlas"}
	fake.Narrow = true
	ng := adapters.NewNuGuard(&nuguard.Client{BaseURL: fake.URL, APIKey: func() (string, error) { return key, nil }}, "0.9.15", nil)
	reg, err := scan.NewRegistry(quietTool{}, ng)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("5d0c7e9a1b2c3d4e5f60718293a4b5c6d7e8f901\n"), 0o644)
	o := orchestrator.New(e.st, &orchestrator.LocalDispatcher{Worker: scan.NewWorker(reg), WorkDir: func(string) string { return dir }},
		orchestrator.NewRateBudget(10), orchestrator.Config{MaxConcurrentScans: 1, CreditsPerScan: 1})
	o.Clock = func() time.Time { return e.now }
	w := &orchestrator.ScanWorker{Orch: o, ID: "w1", Credits: 10, NuGuard: &orchestrator.NuGuardControl{
		Ceiling: nuguardopt.Ceiling{Configured: true, AllowTools: []string{"nga-rules", "atlas", "semgrep"}, AllowPosture: true,
			MaxTimeoutS: 600, Defaults: nuguardopt.Fleet{Enabled: true, Tools: []string{"nga-rules", "atlas", "semgrep"}, TimeoutS: 600}},
		Pinned: "0.9.15",
		Probe: func(ctx context.Context) orchestrator.NuGuardProbe {
			p := ng.Probe(ctx)
			return orchestrator.NuGuardProbe{Reachable: p.Reachable, ServiceVersion: p.ServiceVersion, ToolsAllowed: p.ToolsAllowed, Err: p.Err}
		}}}
	if err := w.PublishNuGuardStatus(ctx); err != nil {
		t.Fatal(err)
	}

	capture("", http.MethodPut, "/v1/nuguard/settings", owner,
		`{"enabled":true,"tools":["nga-rules","atlas"],"include_posture":true,"timeout_s":300,"reason":"AI rules on for the fleet"}`, 200)
	capture("", http.MethodPut, "/v1/repos/octo/web/nuguard", owner, `{"mode":"off","reason":"vendored SDK, no AI code"}`, 200)
	capture("nuguard-422.json", http.MethodPut, "/v1/nuguard/settings", owner,
		`{"enabled":true,"tools":["nga-rules"],"include_posture":false,"timeout_s":900}`, 422)
	q := url.Values{"repo": {"octo/api"}, "nuguard": {"on"}, "tools": {"nga-rules,atlas,semgrep"}, "keep_sbom": {"true"}}
	capture("nuguard-preview.json", http.MethodGet, "/v1/nuguard/preview?"+q.Encode(), owner, "", 200)

	capture("", http.MethodPost, "/v1/scans", owner,
		`{"repo":"octo/api","nuguard":{"mode":"on","tools":["nga-rules","atlas","semgrep"],"keep_sbom":true}}`, 201)
	if did, err := w.RunOnce(ctx); err != nil || !did {
		t.Fatalf("RunOnce: did=%v err=%v", did, err)
	}
	capture("", http.MethodPost, "/v1/scans", owner, `{"repo":"octo/web"}`, 201)
	if did, err := w.RunOnce(ctx); err != nil || !did {
		t.Fatalf("RunOnce: did=%v err=%v", did, err)
	}

	capture("nuguard-page.json", http.MethodGet, "/v1/nuguard", owner, "", 200)
	capture("nuguard-page-engineer.json", http.MethodGet, "/v1/nuguard", engineer, "", 200)
	capture("nuguard-audit.json", http.MethodGet, "/v1/nuguard/audit", engineer, "", 200)
	capture("repo-nuguard.json", http.MethodGet, "/v1/repos/octo/api/nuguard", owner, "", 200)
	capture("repo-nuguard-off.json", http.MethodGet, "/v1/repos/octo/web/nuguard", engineer, "", 200)
	capture("repo-detail-nuguard.json", http.MethodGet, "/v1/repos/octo/api", owner, "", 200)
	capture("scans-nuguard.json", http.MethodGet, "/v1/scans?limit=10", owner, "", 200)
	capture("coverage-nuguard.json", http.MethodGet, "/v1/coverage", owner, "", 200)

	reqs, _ := e.st.ScanRequests(ctx, store.ScanQuery{Repo: "octo/api", Limit: 1})
	if len(reqs) != 1 || reqs[0].RunID == "" {
		t.Fatalf("octo/api's request = %+v", reqs)
	}
	capture("overview-nuguard.json", http.MethodGet, "/v1/runs/"+reqs[0].RunID, owner, "", 200)
	capture("", http.MethodGet, "/v1/repos/octo/api/ai-sbom/"+reqs[0].RunID, engineer, "", 200)

	raw := capture("findings-nuguard.json", http.MethodGet, "/v1/findings?scope=open&found_by=nuguard&limit=50", owner, "", 200)
	var page struct {
		Findings []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &page); err != nil || len(page.Findings) == 0 {
		t.Fatalf("no NuGuard finding to show: %s", raw)
	}
	capture("finding-nuguard.json", http.MethodGet, "/v1/findings/"+page.Findings[0].Fingerprint, owner, "", 200)

	e.now = e.now.Add(20 * time.Minute)
	capture("nuguard-page-stale.json", http.MethodGet, "/v1/nuguard", engineer, "", 200)
}

// saveUIFixture writes a response captured from this real server as one of
// the interface's test fixtures, when UPDATE_UI_FIXTURES=1.
func saveUIFixture(t *testing.T, name string, raw []byte) {
	t.Helper()
	if os.Getenv("UPDATE_UI_FIXTURES") != "1" {
		return
	}
	var pretty any
	if err := json.Unmarshal(raw, &pretty); err != nil {
		t.Fatalf("fixture %s is not JSON: %v", name, err)
	}
	b, _ := json.MarshalIndent(pretty, "", "  ")
	if err := os.WriteFile(filepath.Join("../../../reportui/src/test-fixtures", name), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
