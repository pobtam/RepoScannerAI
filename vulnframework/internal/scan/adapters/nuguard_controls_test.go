package adapters_test

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/nuguard/nuguardfake"
	"github.com/wanaware/vulnframework/internal/nuguardopt"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
)

// The adapter under user control (VM-UI-F-1203/1204): it takes a scan's
// resolved options from RunOpts, not its constructor; it is not run when the
// scan resolved it off; it keeps the AI-SBOM only when asked.

func ngScanWith(t *testing.T, a *adapters.NuGuard, e *nuguardopt.Effective) scan.Result {
	t.Helper()
	reg, err := scan.NewRegistry(a, localTool{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := scan.NewWorker(reg).Scan(context.Background(), "S-000043", ngRepo, t.TempDir(),
		scan.RepoProfile{Repo: ngRepo, Languages: []scan.Language{scan.LangJavaScript}},
		scan.RunOpts{Mode: scan.ModeFull, CommitSHA: ngCommit, NuGuard: e})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestTheScanOptionsReachNuGuard(t *testing.T) {
	fake := ngFake(t, &nuguardfake.Script{Result: readFixture(t, "nuguard", "ai-code.json")})
	fake.Narrow = true
	e := &nuguardopt.Effective{Enabled: true, Tools: []string{"atlas"}, IncludePosture: true, TimeoutS: 120, KeepSBOM: true,
		From: "scan", NotRequested: []nuguardopt.NotRequested{{Tool: "nuguard/nga-rules", Reason: "not chosen"}, {Tool: "nuguard/semgrep", Reason: "not chosen"}}}
	res := ngScanWith(t, ngAdapter(fake.URL), e)

	sub := fake.Submissions()[0]
	if !reflect.DeepEqual(sub.Options["tools"], []any{"atlas"}) || sub.Options["include_posture"] != true || sub.Options["include_sbom"] != true {
		t.Errorf("NuGuard was asked %v; want the scan's options", sub.Options)
	}
	if !reflect.DeepEqual(res.EffectiveNuGuard, e) {
		t.Errorf("the result records %+v, want the options it ran with", res.EffectiveNuGuard)
	}
	if len(res.ToolsNotRequested) != 2 {
		t.Errorf("not requested = %+v", res.ToolsNotRequested)
	}
	for _, g := range res.Gaps {
		if strings.HasPrefix(g.Tool, "nuguard/") {
			t.Errorf("a tool not asked for became a gap: %+v", g)
		}
	}
	if res.AISBOM == nil || res.AISBOM.Tool != "nuguard" || res.AISBOM.Version != "0.9.15" || len(res.AISBOM.Document) == 0 {
		t.Errorf("kept AI-SBOM = %+v", res.AISBOM)
	}
	for _, f := range res.Findings {
		if f.Tool == "nuguard" && f.SubTool != "atlas" {
			t.Errorf("a %s finding from a scan that asked for atlas only", f.SubTool)
		}
	}
}

func TestNuGuardOffForTheScanIsNotRun(t *testing.T) {
	fake := ngFake(t, &nuguardfake.Script{Result: readFixture(t, "nuguard", "ai-code.json")})
	e := &nuguardopt.Effective{From: "scan", Reason: "off for this scan", Tools: []string{},
		NotRequested: []nuguardopt.NotRequested{{Tool: "nuguard", Reason: "off for this scan"}}}
	res := ngScanWith(t, ngAdapter(fake.URL), e)
	if n := len(fake.Submissions()); n != 0 {
		t.Errorf("NuGuard was asked %d times for a scan it is off for", n)
	}
	if _, ran := res.ToolVersions["nuguard"]; ran || contains(res.ToolsOK, "nuguard") || contains(res.ToolsFailed, "nuguard") {
		t.Errorf("an adapter not run is recorded as run: versions %v ok %v failed %v", res.ToolVersions, res.ToolsOK, res.ToolsFailed)
	}
	if !reflect.DeepEqual(res.ToolsNotRequested, e.NotRequested) {
		t.Errorf("not requested = %+v", res.ToolsNotRequested)
	}
	if res.AISBOM != nil || res.AIInventory != nil {
		t.Error("an inventory or AI-SBOM from a NuGuard that did not run")
	}
}

func TestWithoutScanOptionsTheFlagsApply(t *testing.T) {
	fake := ngFake(t, &nuguardfake.Script{Result: readFixture(t, "nuguard", "ai-code.json")})
	a := ngAdapter(fake.URL)
	a.Tools = a.Tools[:2] // -nuguard-tools nga-rules,atlas
	res := ngScanWith(t, a, nil)
	if got := fake.Submissions()[0].Options["include_sbom"]; got != false {
		t.Errorf("include_sbom = %v without a scan asking to keep it", got)
	}
	want := []nuguardopt.NotRequested{{Tool: "nuguard/semgrep", Reason: "not in -nuguard-tools"}}
	if !reflect.DeepEqual(res.ToolsNotRequested, want) {
		t.Errorf("not requested = %+v, want %+v", res.ToolsNotRequested, want)
	}
	if res.EffectiveNuGuard != nil || res.AISBOM != nil {
		t.Error("options or an AI-SBOM recorded for a scan that resolved none")
	}
}

func TestTheCeilingFlagsRefuseADefaultAboveThem(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string // "" is accepted
	}{
		{[]string{"-nuguard-url=https://ng.example"}, ""},
		{[]string{}, ""}, // not configured: nothing to check
		{[]string{"-nuguard-url=https://ng.example", "-nuguard-allow-tools=nga-rules,atlas"}, "-nuguard-tools"},
		{[]string{"-nuguard-url=https://ng.example", "-nuguard-allow-tools=nga-rules,osv"}, "not a tool users may choose"},
		{[]string{"-nuguard-url=https://ng.example", "-nuguard-allow-posture=false", "-nuguard-include-posture"}, "-nuguard-include-posture"},
		{[]string{"-nuguard-url=https://ng.example", "-nuguard-max-timeout=5m"}, "-nuguard-timeout"},
		{[]string{"-nuguard-url=https://ng.example", "-nuguard-tools=atlas", "-nuguard-allow-tools=atlas", "-nuguard-max-timeout=10m"}, ""},
	} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		f := adapters.RegisterNuGuardFlags(fs)
		if err := fs.Parse(tc.args); err != nil {
			t.Fatal(err)
		}
		c, err := f.Ceiling()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%v refused: %v", tc.args, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%v: err %v, want one naming %q", tc.args, err, tc.want)
		case tc.want == "" && len(tc.args) == 0 && c.Configured:
			t.Error("no URL, yet the ceiling says configured")
		}
		if tc.want != "" {
			// Build refuses to start on the same grounds.
			if _, err := f.Build(context.Background(), testLock(t), nil, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
				t.Errorf("%v: Build started with a default above the ceiling", tc.args)
			}
		}
	}
}

// A service that runs more than it was asked for (here, a captured result
// replayed whatever the request) does not make the extra tools ok sources:
// the scan records them as not requested, and their silence verifies nothing.
func TestAToolRunButNotAskedForIsNotAnOkSource(t *testing.T) {
	fake := ngFake(t, &nuguardfake.Script{Result: readFixture(t, "nuguard", "ai-code.json")})
	e := &nuguardopt.Effective{Enabled: true, Tools: []string{"atlas"}, TimeoutS: 120, From: "scan",
		NotRequested: []nuguardopt.NotRequested{{Tool: "nuguard/nga-rules", Reason: "not chosen"}, {Tool: "nuguard/semgrep", Reason: "not chosen"}}}
	res := ngScanWith(t, ngAdapter(fake.URL), e)
	if !contains(res.ToolsOK, "nuguard/atlas") {
		t.Errorf("tools ok %v lack the tool asked for", res.ToolsOK)
	}
	for _, unasked := range []string{"nuguard/nga-rules", "nuguard/semgrep"} {
		if contains(res.ToolsOK, unasked) {
			t.Errorf("%s is listed ok and not requested at once: %v", unasked, res.ToolsOK)
		}
	}
}
