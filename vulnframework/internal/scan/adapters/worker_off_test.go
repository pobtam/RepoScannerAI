package adapters_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

// workerOffGolden is the result document of one scan through every adapter
// that existed before the NuGuard adapter, captured from the code as it was
// before that adapter was written.
const workerOffGolden = "../../../testdata/worker/no-nuguard.golden.json"

// TestNoNuGuardMeansAnUnchangedResult proves that an optional adapter left
// unconfigured changes nothing (VM-NF-502): with NuGuard not registered, the
// scan result is byte-for-byte what it was before NuGuard existed, apart
// from the scanned commit, which every scan now records.
//
// The golden is deliberately not rewritten by -update: a change here is a
// change to every scan's output and must be made on purpose. Re-bless only
// with VF_BLESS_WORKER_GOLDEN=1, and say why in the commit.
func TestNoNuGuardMeansAnUnchangedResult(t *testing.T) {
	lock := testLock(t)
	fake := runner.NewFake()
	for tool, fixture := range map[string]string{
		"govulncheck": "go-api.json", "gosec": "go-api.json", "staticcheck": "go-api.json",
		"osv-scanner": "go-api.json", "gitleaks": "go-api.json", "trivy": "go-api.json",
		"semgrep": "payments-web.json", "npm-audit": "payments-web.json",
	} {
		fake.WithStdout(tool, readFixture(t, tool, fixture))
	}

	reg, err := scan.NewRegistry(adapters.All(fake, lock)...)
	if err != nil {
		t.Fatal(err)
	}
	w := scan.NewWorker(reg)
	w.Clock = func() time.Time { return time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC) }
	profile := scan.RepoProfile{
		Repo:      goAPIRepo,
		Languages: []scan.Language{scan.LangGo, scan.LangJavaScript},
	}
	res, err := w.Scan(context.Background(), "S-000001", goAPIRepo, goAPIDir, profile, scan.RunOpts{Mode: scan.ModeFull})
	if err != nil {
		t.Fatal(err)
	}

	got := canonicalWithout(t, res, "commit_sha")
	if os.Getenv("VF_BLESS_WORKER_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(workerOffGolden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(workerOffGolden, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("blessed %s", workerOffGolden)
		return
	}
	want, err := os.ReadFile(workerOffGolden)
	if err != nil {
		t.Fatalf("reading %s: %v", workerOffGolden, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("with NuGuard not configured, the scan result changed.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// canonicalWithout renders v as indented JSON with the named top-level keys
// removed, keys sorted, so two results compare byte-for-byte.
func canonicalWithout(t *testing.T, v any, drop ...string) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range drop {
		delete(m, k)
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}
