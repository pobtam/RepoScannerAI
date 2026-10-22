package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	vfapi "github.com/wanaware/vulnframework/internal/api"
	"github.com/wanaware/vulnframework/internal/gh/ghfake"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/store/storetest"
)

// A click, end to end: "Scan now" through the real API (role, same-origin and
// CSRF checks), a scan request in Postgres, the compiled orchestrator in
// -worker -github mode claiming it, downloading the repository from a local
// fake GitHub, scanning and recording it, and the request ending finished with
// the run that scanned it. The API never sees the token; only the worker
// process has it in its environment. Stopping the worker leaves nothing
// running.
func TestScanNowClickToWorkerToResults(t *testing.T) {
	dsn := storetest.FreshDSN(t, "cmd_scan_now_e2e")
	bin := filepath.Join(t.TempDir(), "orchestrator")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "-dsn", dsn, "-migrate").CombinedOutput(); err != nil {
		t.Fatalf("migrate: %v\n%s", err, out)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := store.NewPostgres(db)
	ctx := context.Background()

	// The repository GitHub will serve, registered as discovery would.
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module example.com/api\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := ghfake.New("octo", "fake-token",
		ghfake.Repo{FullName: "octo/api", SizeKB: 4, Language: "Go", Dir: src},
		ghfake.Repo{FullName: "octo/slow", SizeKB: 4, Language: "Go", Dir: src},
		ghfake.Repo{FullName: "octo/web", SizeKB: 4, Language: "Go", Dir: src},
	)
	defer fake.Close()
	for _, r := range []store.Repo{
		{Name: "octo/api", Tier: 2, Languages: []string{"go"}},
		{Name: "octo/slow", Tier: 3, Languages: []string{"go"}},
		{Name: "octo/old", Tier: 3, Archived: true},
		{Name: "octo/web", Tier: 3},
	} {
		if err := st.UpsertRepo(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetExclusion(ctx, store.RepoExclusion{Name: "octo/old", Reason: "a vendored mirror", ExcludedBy: "pat", ExcludedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	// The API, as the deployment runs it: header identity from the proxy,
	// scan requests on.
	cal, err := score.LoadCalibration("../../config/calibration.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.LoadConfig("../../config/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := vfapi.New(vfapi.Config{
		Store: st, Calibration: cal, Policy: pol, ScanRequests: true,
		Auth:   vfapi.HeaderAuth{UserHeader: "X-Auth-User", LevelHeader: "X-Auth-Level", ReposHeader: "X-Auth-Repos"},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(srv.Handler())
	defer web.Close()
	call := func(method, path, body, token string) (int, []byte) {
		req, _ := http.NewRequest(method, web.URL+path, strings.NewReader(body))
		req.Header.Set("X-Auth-User", "pat")
		req.Header.Set("X-Auth-Level", "security_owner")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		if token != "" {
			req.Header.Set(vfapi.CSRFHeader, token)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, raw
	}

	// The click.
	_, raw := call(http.MethodGet, "/v1/csrf", "", "")
	var tok struct{ Token string }
	_ = json.Unmarshal(raw, &tok)
	status, raw := call(http.MethodPost, "/v1/scans", `{"repo":"octo/api"}`, tok.Token)
	if status != http.StatusCreated {
		t.Fatalf("Scan now = %d %s", status, raw)
	}
	var res struct {
		Request struct{ ID, Status string }
	}
	_ = json.Unmarshal(raw, &res)
	if res.Request.Status != "queued" {
		t.Fatalf("request = %s", raw)
	}
	saveUIFixture(t, "scan-request.json", raw)
	{
		// What a caller below the security-owner level is told.
		req, _ := http.NewRequest(http.MethodPost, web.URL+"/v1/scans", strings.NewReader(`{"repo":"octo/api"}`))
		req.Header.Set("X-Auth-User", "eng")
		req.Header.Set("X-Auth-Level", "engineer")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		forbidden, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("engineer Scan now = %d %s", res.StatusCode, forbidden)
		}
		saveUIFixture(t, "scan-forbidden.json", forbidden)
	}
	_, health := call(http.MethodGet, "/v1/health", "", "")
	saveUIFixture(t, "health-scans.json", health)

	// The worker: the only process with the token.
	worker := exec.Command(bin, "-dsn", dsn, "-worker", "-github", "-github-api", fake.URL,
		"-tools", "../../config/tools.lock", "-post-sweep=false", "-scan-timeout", "2m")
	worker.Env = append(os.Environ(), githubTokenEnv+"=fake-token")
	var logs strings.Builder
	worker.Stdout, worker.Stderr = &logs, &logs
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = worker.Process.Kill() }()

	deadline := time.Now().Add(90 * time.Second)
	var got store.ScanRequest
	for time.Now().Before(deadline) {
		got, _, _ = st.GetScanRequest(ctx, res.Request.ID)
		if !got.Status.Active() {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if got.Status != store.ScanFinished || got.RunID == "" {
		t.Fatalf("request after the worker: %+v\nworker log:\n%s", got, logs.String())
	}
	scans, _ := st.ScanResults(ctx, "octo/api", 1)
	if len(scans) != 1 || scans[0].RunID != got.RunID {
		t.Fatalf("scan result for the request's run: %+v", scans)
	}

	// The list the interface polls shows it finished, with the run.
	_, raw = call(http.MethodGet, "/v1/scans?repo=octo/api", "", "")
	if !strings.Contains(string(raw), `"status":"finished"`) || !strings.Contains(string(raw), got.RunID) {
		t.Errorf("GET /v1/scans = %s", raw)
	}

	// Stopping the worker is clean, and leaves nothing running.
	_ = worker.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- worker.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the worker did not stop on SIGTERM")
	}
	if strings.Contains(logs.String(), "fake-token") {
		t.Error("the token appears in the worker's output")
	}
	if len(fake.Refused()) != 0 {
		t.Errorf("the worker tried to write to GitHub: %v", fake.Refused())
	}

	// A scan that exceeds its time limit, through the real binary: recorded
	// as a coverage gap, and the request says it timed out.
	_, raw = call(http.MethodGet, "/v1/csrf", "", "")
	_ = json.Unmarshal(raw, &tok)
	if status, raw := call(http.MethodPost, "/v1/scans", `{"repo":"octo/slow"}`, tok.Token); status != http.StatusCreated {
		t.Fatalf("Scan now octo/slow = %d %s", status, raw)
	}
	slow := exec.Command(bin, "-dsn", dsn, "-worker", "-github", "-github-api", fake.URL,
		"-tools", "../../config/tools.lock", "-post-sweep=false", "-scan-timeout", "1ms")
	slow.Env = append(os.Environ(), githubTokenEnv+"=fake-token")
	if err := slow.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = slow.Process.Kill() }()
	var timedOut store.ScanRequest
	for end := time.Now().Add(60 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		list, _ := st.ScanRequests(ctx, store.ScanQuery{Repo: "octo/slow", Limit: 1})
		if len(list) == 1 && !list[0].Status.Active() {
			timedOut = list[0]
			break
		}
	}
	_ = slow.Process.Signal(syscall.SIGTERM)
	_ = slow.Wait()
	if timedOut.Status != store.ScanTimedOut {
		t.Fatalf("octo/slow with a 1ms limit: %+v; want timed_out", timedOut)
	}
	if res, _ := st.ScanResults(ctx, "octo/slow", 1); len(res) != 1 || res[0].FailureCause != "scan_timed_out" || res[0].Outcome.Succeeded() {
		t.Errorf("octo/slow's recorded result: %+v; want a scan_timed_out gap", res)
	}

	// A refused request (an excluded repository) and an interrupted one (a
	// worker that died), so every status the interface shows is real.
	if status, _ := call(http.MethodPost, "/v1/scans", `{"repo":"octo/old"}`, tok.Token); status != http.StatusConflict {
		t.Errorf("excluded repository = %d; want 409", status)
	}
	if status, _ := call(http.MethodPost, "/v1/scans", `{"repo":"octo/web"}`, tok.Token); status != http.StatusCreated {
		t.Errorf("octo/web = %d", status)
	}
	if _, _, err := st.ClaimScans(ctx, "a-worker-that-died", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.InterruptStaleScans(ctx, time.Now().Add(-2*time.Minute),
		"the scan worker stopped or restarted during the scan; nothing from it is recorded as done", time.Now()); n != 1 {
		t.Errorf("interrupted %d, want 1", n)
	}

	_, raw = call(http.MethodGet, "/v1/scans?limit=10", "", "")
	for _, want := range []string{`"finished"`, `"timed_out"`, `"refused"`, `"interrupted"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("GET /v1/scans lacks %s: %s", want, raw)
		}
	}
	saveUIFixture(t, "scans.json", raw)
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
