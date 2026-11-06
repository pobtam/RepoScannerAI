package adapters_test

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/nuguard"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
)

// TestNuGuardEndToEnd scans a pinned public repository through a REAL NuGuard
// service, twice, and requires the same fingerprints and the same
// result_sha256 both times: a result that moves between identical scans
// cannot support a delta report.
//
// Opt-in, because it needs a running service and the network:
//
//	VF_NUGUARD_E2E=1 VF_NUGUARD_URL=https://... VF_NUGUARD_API_KEY=... \
//	  go test ./internal/scan/adapters -run NuGuardEndToEnd -v
//
// No GitHub token is sent: the repository is public.
func TestNuGuardEndToEnd(t *testing.T) {
	if os.Getenv("VF_NUGUARD_E2E") != "1" {
		t.Skip("set VF_NUGUARD_E2E=1, VF_NUGUARD_URL and VF_NUGUARD_API_KEY to scan through a real NuGuard service")
	}
	url, key := os.Getenv("VF_NUGUARD_URL"), os.Getenv("VF_NUGUARD_API_KEY")
	if url == "" || key == "" {
		t.Fatal("VF_NUGUARD_E2E=1 needs VF_NUGUARD_URL and VF_NUGUARD_API_KEY")
	}
	const (
		repo   = "openai/openai-quickstart-python"
		commit = "ec8890d101bdc17d66512d94a76b5e7131d188a1"
	)
	a := adapters.NewNuGuard(&nuguard.Client{BaseURL: url, APIKey: func() (string, error) { return key, nil }},
		testLock(t).MustVersion("nuguard"), nil)

	scanOnce := func(runID string) ([]string, string) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		out, err := a.Run(ctx, "", scan.RunOpts{RunID: runID, Repo: repo, CommitSHA: commit})
		if err != nil {
			t.Fatalf("%s: %v", runID, err)
		}
		out.Repo = repo
		got, err := a.Normalize(out)
		if err != nil {
			t.Fatalf("%s: normalise: %v", runID, err)
		}
		res, err := nuguard.ParseResult(out.Stdout)
		if err != nil {
			t.Fatal(err)
		}
		var fps []string
		for _, f := range got {
			fps = append(fps, fingerprint.Compute(f))
		}
		sort.Strings(fps)
		t.Logf("%s: job %s %s, %d findings, %d code findings kept", runID, res.Job.ID, res.Job.Status, len(res.Findings), len(got))
		return fps, res.ResultSHA256
	}
	// Two run ids, so two idempotency keys and two real scans.
	fps1, sha1 := scanOnce("E2E-000001")
	fps2, sha2 := scanOnce("E2E-000002")
	if strings.Join(fps1, ",") != strings.Join(fps2, ",") {
		t.Errorf("fingerprints differ between identical scans:\n%v\n%v", fps1, fps2)
	}
	if sha1 != sha2 {
		t.Errorf("result_sha256 differs between identical scans: %s vs %s", sha1, sha2)
	}
}
