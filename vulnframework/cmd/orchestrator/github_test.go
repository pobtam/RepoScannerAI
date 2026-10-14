package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/gh/ghfake"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/store/storetest"
)

// Account mode through the real entry point: the compiled orchestrator, given
// -github and a token in the environment, discovers the fake account's
// repositories, registers them, downloads and scans each, and records the
// results, against Postgres. The scanners themselves are not installed on a
// developer machine, so they fail and are recorded as gaps; what this proves
// is the wiring from flag to store, which is what "built but never called"
// would break.
func TestGitHubAccountModeRunsFromTheCommandLine(t *testing.T) {
	dsn := storetest.FreshDSN(t, "cmd_orchestrator_github")

	bin := filepath.Join(t.TempDir(), "orchestrator")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "-dsn", dsn, "-migrate").CombinedOutput(); err != nil {
		t.Fatalf("migrate: %v\n%s", err, out)
	}

	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module example.com/api\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := ghfake.New("octo", "fake-token",
		ghfake.Repo{FullName: "octo/api", SizeKB: 4, Language: "Go", Dir: src},
		ghfake.Repo{FullName: "octo/old", SizeKB: 4, Archived: true, Dir: src},
	)
	defer fake.Close()

	cmd := exec.Command(bin,
		"-dsn", dsn, "-github", "-github-api", fake.URL,
		"-tools", "../../config/tools.lock", "-post-sweep=false",
	)
	cmd.Env = append(os.Environ(), githubTokenEnv+"=fake-token")
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("orchestrator -github: %v\nstderr:\n%s", err, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "fake-token") {
		t.Fatal("the token appears in the program's output")
	}

	var out struct {
		Discovery struct {
			Account  string         `json:"account"`
			Seen     int            `json:"seen"`
			Included int            `json:"included"`
			Skipped  map[string]int `json:"skipped"`
		} `json:"discovery"`
		Sweep struct {
			Planned int `json:"Planned"`
			Close   struct {
				Produced int `json:"Produced"`
			} `json:"Close"`
		} `json:"sweep"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &out); err != nil {
		t.Fatalf("output is not the run record: %v\n%s", err, stdout.String())
	}
	if out.Discovery.Account != "octo" || out.Discovery.Seen != 2 || out.Discovery.Included != 1 || out.Discovery.Skipped["archived"] != 1 {
		t.Errorf("discovery = %+v", out.Discovery)
	}
	if out.Sweep.Planned != 1 || out.Sweep.Close.Produced != 1 {
		t.Errorf("sweep = %+v", out.Sweep)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := store.NewPostgres(db)
	res, err := st.ScanResults(context.Background(), "octo/api", 1)
	if err != nil || len(res) != 1 {
		t.Fatalf("scan results for octo/api: %v, %v", res, err)
	}
	if len(fake.Refused()) != 0 {
		t.Errorf("the program tried to write to GitHub: %v", fake.Refused())
	}
}

func TestGitHubAccountModeRefusesToRunWithoutAToken(t *testing.T) {
	dsn := storetest.FreshDSN(t, "cmd_orchestrator_github_notoken")
	bin := filepath.Join(t.TempDir(), "orchestrator")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "-dsn", dsn, "-migrate").CombinedOutput(); err != nil {
		t.Fatalf("migrate: %v\n%s", err, out)
	}
	cmd := exec.Command(bin, "-dsn", dsn, "-github", "-github-api", "http://127.0.0.1:1",
		"-tools", "../../config/tools.lock", "-post-sweep=false")
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, githubTokenEnv+"=") {
			env = append(env, kv)
		}
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), githubTokenEnv) {
		t.Errorf("ran without a token, or did not say which variable is missing: %v\n%s", err, out)
	}
}
