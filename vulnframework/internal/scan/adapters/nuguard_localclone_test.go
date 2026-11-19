package adapters_test

import (
	"context"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/nuguard/nuguardfake"
	"github.com/wanaware/vulnframework/internal/nuguardopt"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
)

// NuGuard over a local clone (real mode, run.sh --real --nuguard): it scans
// the clone's GitHub origin at the clone's commit, says so when the tree on
// disk differs, and turns what GitHub cannot serve into the repository's gap.

// The registered name in real mode need not be the GitHub owner/name.
const registered = "local/agent-clone"

func ngScanClone(t *testing.T, a *adapters.NuGuard, lc *scan.LocalClone, e *nuguardopt.Effective) scan.Result {
	t.Helper()
	reg, err := scan.NewRegistry(a, localTool{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := scan.NewWorker(reg).Scan(context.Background(), "S-000044", registered, t.TempDir(),
		scan.RepoProfile{Repo: registered, Languages: []scan.Language{scan.LangJavaScript}},
		scan.RunOpts{Mode: scan.ModeFull, CommitSHA: ngCommit, LocalClone: lc, NuGuard: e})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestALocalCloneIsScannedAtItsGitHubOrigin(t *testing.T) {
	fake := ngFake(t, &nuguardfake.Script{Result: readFixture(t, "nuguard", "ai-code.json")})
	res := ngScanClone(t, ngAdapter(fake.URL), &scan.LocalClone{GitHubRepo: ngRepo, WorkTree: scan.WorkTreeClean}, nil)

	sub := fake.Submissions()
	if len(sub) != 1 || sub[0].RepoURL != ngURL || sub[0].Ref != ngCommit {
		t.Fatalf("NuGuard was asked %+v; want %s at %s, the origin rather than the registered name", sub, ngURL, ngCommit)
	}
	if !contains(res.ToolsOK, "nuguard") || res.AIInventory == nil {
		t.Errorf("tools ok %v, inventory %v", res.ToolsOK, res.AIInventory)
	}
	for _, f := range res.Findings {
		if f.Tool != "nuguard" {
			continue
		}
		if f.Repo != registered {
			t.Errorf("a finding filed under %s, not the registered %s", f.Repo, registered)
		}
		for k := range f.Annotations {
			if strings.HasSuffix(k, "/scanned") {
				t.Errorf("a clean clone's finding carries %s", k)
			}
		}
	}
}

func TestALocalCloneWithNoGitHubOriginIsNotRequested(t *testing.T) {
	fake := ngFake(t, &nuguardfake.Script{Result: readFixture(t, "nuguard", "ai-code.json")})
	for name, e := range map[string]*nuguardopt.Effective{
		"flags only":       nil,
		"resolved options": {Enabled: true, Tools: []string{"atlas"}, TimeoutS: 120, From: "fleet"},
	} {
		t.Run(name, func(t *testing.T) {
			res := ngScanClone(t, ngAdapter(fake.URL), &scan.LocalClone{WorkTree: scan.WorkTreeClean}, e)
			want := []scan.NotRequested{{Tool: "nuguard", Reason: adapters.NoGitHubOrigin}}
			if len(res.ToolsNotRequested) != 1 || res.ToolsNotRequested[0] != want[0] {
				t.Errorf("not requested = %+v, want %+v", res.ToolsNotRequested, want)
			}
			if contains(res.ToolsFailed, "nuguard") || contains(res.ToolsOK, "nuguard") || len(res.Gaps) != 0 {
				t.Errorf("not requested, yet ok %v failed %v gaps %+v", res.ToolsOK, res.ToolsFailed, res.Gaps)
			}
		})
	}
	if n := len(fake.Submissions()); n != 0 {
		t.Errorf("NuGuard was asked %d times about a clone GitHub does not have", n)
	}

	// Switched off by the scan's options, that reason stands.
	off := &nuguardopt.Effective{From: "scan", Reason: "off for this scan",
		NotRequested: []nuguardopt.NotRequested{{Tool: "nuguard", Reason: "off for this scan"}}}
	res := ngScanClone(t, ngAdapter(fake.URL), &scan.LocalClone{WorkTree: scan.WorkTreeClean}, off)
	if len(res.ToolsNotRequested) != 1 || res.ToolsNotRequested[0].Reason != "off for this scan" {
		t.Errorf("not requested = %+v", res.ToolsNotRequested)
	}
}

func TestACommitNotOnGitHubIsTheRepositorysGap(t *testing.T) {
	fake := ngFake(t, &nuguardfake.Script{ErrorCode: "ref_not_found", ErrorDetail: "the ref was not found"})
	res := ngScanClone(t, ngAdapter(fake.URL), &scan.LocalClone{GitHubRepo: ngRepo, WorkTree: scan.WorkTreeClean}, nil)
	g := nuguardGapOf(t, res)
	if g.Cause != "commit_not_on_github" || g.Owner != scan.OwnerRepo ||
		!strings.Contains(g.Detail, ngCommit) || !strings.Contains(g.Detail, "not on GitHub") {
		t.Errorf("gap = %+v; want the repository's, naming the commit as not on GitHub", g)
	}
	if !contains(res.ToolsFailed, "nuguard") {
		t.Errorf("failed = %v", res.ToolsFailed)
	}

	// Downloaded from GitHub at the commit (account mode), the same answer
	// is still a failed download, the platform's.
	acct := ngScan(t, ngAdapter(fake.URL), ngCommit)
	if g := nuguardGapOf(t, acct); g.Cause != "download_failed" || g.Owner != scan.OwnerPlatform {
		t.Errorf("account mode's gap = %+v", g)
	}
}

func TestADirtyCloneSaysNuGuardScannedTheCommit(t *testing.T) {
	fake := ngFake(t, &nuguardfake.Script{Result: readFixture(t, "nuguard", "ai-code.json")})
	for state, want := range map[string]string{
		scan.WorkTreeDirty:   "NuGuard scanned the committed state, not the working tree",
		scan.WorkTreeUnknown: "NuGuard scanned the committed state; working-tree state unknown",
	} {
		t.Run(state, func(t *testing.T) {
			res := ngScanClone(t, ngAdapter(fake.URL), &scan.LocalClone{GitHubRepo: ngRepo, WorkTree: state}, nil)
			n := 0
			for _, f := range res.Findings {
				if f.Tool != "nuguard" {
					continue
				}
				n++
				if got := f.Annotations["nuguard/0.9.15/scanned"]; got != want {
					t.Errorf("%s: scanned = %q, want %q", f.RuleID, got, want)
				}
				if f.Annotations["nuguard/0.9.15/fingerprint"] == "" {
					t.Errorf("%s lost its other annotations: %v", f.RuleID, f.Annotations)
				}
			}
			if n == 0 {
				t.Fatal("no NuGuard findings to check")
			}
		})
	}
}
