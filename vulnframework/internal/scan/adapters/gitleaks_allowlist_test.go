package adapters_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

// scriptedRunner answers gitleaks by the flags it was given, and records
// every invocation.
type scriptedRunner struct {
	mu    sync.Mutex
	calls [][]string
	reply func(args []string) (runner.Result, error)
}

func (r *scriptedRunner) Run(_ context.Context, _ string, name string, args ...string) (runner.Result, error) {
	r.mu.Lock()
	r.calls = append(r.calls, append([]string{name}, args...))
	r.mu.Unlock()
	return r.reply(args)
}

func has(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func hit(dir, file, rule string, line int) string {
	return `{"File":"` + filepath.Join(dir, file) + `","RuleID":"` + rule + `","StartLine":` +
		strconv.Itoa(line) + `,"Secret":"REDACTED","Match":"REDACTED"}`
}

func TestGitleaksLooksPastEachAllowlistMechanism(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".gitleaks.toml", "[extend]\nuseDefault = true\n[allowlist]\ndescription = \"fixtures\"\npaths = ['''^testdata/''']\n")
	write(".gitleaksignore", strings.Join([]string{
		"# comment",
		"config/app.yaml:aws-access-token:3",        // live entry
		"config/stale.yaml:aws-access-token:9",      // stale: nothing there now
		"../../etc/passwd:generic-api-key:1",        // outside the clone: never scanned
		"abc123:config/app.yaml:aws-access-token:3", // history entry: not this run's business
	}, "\n"))

	r := &scriptedRunner{reply: func(args []string) (runner.Result, error) {
		var out []string
		switch {
		case has(args, "--source"):
			// The single-file ignore check.
			if strings.Contains(strings.Join(args, " "), "config/app.yaml") {
				out = append(out, hit(dir, "config/app.yaml", "aws-access-token", 3))
			}
		case has(args, "--ignore-gitleaks-allow"):
			out = append(out, hit(dir, "testdata/fixture.yaml", "generic-api-key", 2),
				hit(dir, "deploy/boot.env", "aws-access-token", 1),
				hit(dir, "src/live.go", "github-pat", 5))
		case has(args, "--config"):
			out = append(out, hit(dir, "testdata/fixture.yaml", "generic-api-key", 2),
				hit(dir, "src/live.go", "github-pat", 5))
		default:
			out = append(out, hit(dir, "src/live.go", "github-pat", 5))
		}
		return runner.Result{Stdout: []byte("[" + strings.Join(out, ",") + "]"), ExitCode: 1}, nil
	}}

	a := adapters.NewGitleaks(r, "v8.30.1")
	raw, err := a.Run(context.Background(), dir, scan.RunOpts{Mode: scan.ModeFull})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, c := range r.calls {
		if !has(c, "--redact") {
			t.Errorf("an invocation ran without --redact: %v", c)
		}
		if has(c, "--source") && !strings.Contains(strings.Join(c, " "), "config/") {
			t.Errorf("an ignore check scanned something outside the named files: %v", c)
		}
		for _, a := range c {
			if strings.Contains(a, "etc/passwd") {
				t.Errorf("an ignore entry outside the clone was scanned: %v", c)
			}
		}
	}

	raw.Repo = "org/api"
	findings, err := a.Normalize(raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	got := map[string]*model.Allowlist{}
	for _, f := range findings {
		got[f.File] = f.Allowlisted
	}
	if a, ok := got["src/live.go"]; !ok || a != nil {
		t.Errorf("the ordinarily reported secret: present=%v allowlisted=%+v", ok, a)
	}
	if a := got["testdata/fixture.yaml"]; a == nil || a.Mechanism != model.AllowlistConfig || a.Description != "fixtures" || a.ConfigSHA256 == "" {
		t.Errorf("config-allowlisted evidence = %+v", a)
	}
	if a := got["deploy/boot.env"]; a == nil || a.Mechanism != model.AllowlistInline || a.Path != "deploy/boot.env" {
		t.Errorf("inline evidence = %+v", a)
	}
	if a := got["config/app.yaml"]; a == nil || a.Mechanism != model.AllowlistIgnoreFile ||
		a.Description != "entry config/app.yaml:aws-access-token:3" {
		t.Errorf("ignore-file evidence = %+v", a)
	}
	if _, ok := got["config/stale.yaml"]; ok {
		t.Error("a stale .gitleaksignore entry produced a proposal; only entries still hiding a secret may")
	}
	if len(findings) != 4 {
		t.Errorf("%d findings, want 4", len(findings))
	}
}

// If the look past the allowlists fails, the run fails: an allowlisted secret
// must never be silently read as removed.
func TestGitleaksFailsLoudlyWhenItCannotLookPastAllowlists(t *testing.T) {
	r := &scriptedRunner{reply: func(args []string) (runner.Result, error) {
		if has(args, "--config") {
			return runner.Result{}, errors.New("signal: killed")
		}
		return runner.Result{Stdout: []byte("[]")}, nil
	}}
	_, err := adapters.NewGitleaks(r, "v8.30.1").Run(context.Background(), t.TempDir(), scan.RunOpts{Mode: scan.ModeFull})
	if err == nil || !strings.Contains(err.Error(), "allowlists") {
		t.Fatalf("err = %v; a failed second look must fail the tool", err)
	}
}
