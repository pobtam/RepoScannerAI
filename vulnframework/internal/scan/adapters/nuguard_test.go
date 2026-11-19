package adapters_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/nuguard"
	"github.com/wanaware/vulnframework/internal/nuguard/nuguardfake"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
	"github.com/wanaware/vulnframework/internal/store"
)

// Credentials for the fake, assembled at run time so no key-like string is
// committed, and recognisable so a leak is unmistakable.
var (
	ngKey   = strings.Join([]string{"ngkey", "LEAKCANARY", "7f3a"}, "-")
	ngToken = strings.Join([]string{"ghtoken", "LEAKCANARY", "c91e"}, "-")
)

const (
	ngCommit = "5d0c7e9a1b2c3d4e5f60718293a4b5c6d7e8f901"
	ngRepo   = agentRepo
	ngURL    = "https://github.com/" + agentRepo
)

func ngToken_() (string, error) { return ngToken, nil }

func ngAdapter(baseURL string) *adapters.NuGuard {
	c := &nuguard.Client{
		BaseURL: baseURL, APIKey: func() (string, error) { return ngKey, nil },
		Sleep:        func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
		MaxRetryWait: 3 * time.Second,
	}
	return adapters.NewNuGuard(c, "0.9.15", ngToken_)
}

// localTool is a stand-in for the local adapters: it always runs and finds
// nothing, so a scan with NuGuard failing is partial, as it would be.
type localTool struct{}

func (localTool) Name() string                   { return "local" }
func (localTool) Version() string                { return "1" }
func (localTool) Supports(scan.RepoProfile) bool { return true }
func (localTool) Run(context.Context, string, scan.RunOpts) (scan.RawOutput, error) {
	return scan.RawOutput{Tool: "local", Stdout: []byte("[]")}, nil
}
func (localTool) Normalize(scan.RawOutput) ([]model.RawFinding, error) { return nil, nil }

func ngScan(t *testing.T, a *adapters.NuGuard, commit string) scan.Result {
	t.Helper()
	reg, err := scan.NewRegistry(a, localTool{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := scan.NewWorker(reg).Scan(context.Background(), "S-000042", ngRepo, t.TempDir(),
		scan.RepoProfile{Repo: ngRepo, Languages: []scan.Language{scan.LangJavaScript}},
		scan.RunOpts{Mode: scan.ModeFull, CommitSHA: commit})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func ngFake(t *testing.T, sc *nuguardfake.Script) *nuguardfake.Server {
	t.Helper()
	fake := nuguardfake.New(ngKey, "0.9.15")
	t.Cleanup(fake.Close)
	fake.Default = sc
	return fake
}

func nuguardGapOf(t *testing.T, res scan.Result) scan.CoverageGap {
	t.Helper()
	for _, g := range res.Gaps {
		if g.Tool == "nuguard" {
			return g
		}
	}
	t.Fatalf("no nuguard gap in %+v", res.Gaps)
	return scan.CoverageGap{}
}

// mutateFixture edits a captured result as a document.
func mutateFixture(t *testing.T, name string, f func(map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(readFixture(t, "nuguard", name), &doc); err != nil {
		t.Fatal(err)
	}
	f(doc)
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every way a NuGuard scan can end without a result is a gap with the right
// cause and owner, never an empty finding list that reads as clean
// (VM-F-204, VM-F-205, VM-F-214).
func TestNuGuardJobFailuresAreAttributedGaps(t *testing.T) {
	for _, tc := range []struct {
		code, status string
		cause        string
		owner        scan.GapOwner
	}{
		{"job_timeout", "", "execution_failed", scan.OwnerPlatform},
		{"worker_lost", "", "execution_failed", scan.OwnerPlatform},
		{"analysis_crashed", "", "execution_failed", scan.OwnerPlatform},
		{"sbom_failed", "", "execution_failed", scan.OwnerPlatform},
		{"subpath_not_found", "", "execution_failed", scan.OwnerPlatform},
		{"auth_failed", "", "credential_failed", scan.OwnerPlatform},
		{"repo_not_found_or_no_access", "", "credential_failed", scan.OwnerPlatform},
		{"credential_unavailable", "", "credential_failed", scan.OwnerPlatform},
		{"ref_not_found", "", "download_failed", scan.OwnerPlatform},
		{"clone_failed", "", "download_failed", scan.OwnerPlatform},
		{"clone_timeout", "", "download_failed", scan.OwnerPlatform},
		{"repo_too_large", "", "repo_too_large", scan.OwnerRepo},
		{"cancelled", "cancelled", "execution_failed", scan.OwnerPlatform},
		{"expired", "expired", "execution_failed", scan.OwnerPlatform},
	} {
		t.Run(tc.code, func(t *testing.T) {
			sc := &nuguardfake.Script{ErrorCode: tc.code, Status: tc.status, Polls: 1}
			sc.Then = sc // a released key fails the same way again
			fake := ngFake(t, sc)
			res := ngScan(t, ngAdapter(fake.URL), ngCommit)
			g := nuguardGapOf(t, res)
			if g.Cause != tc.cause || g.Owner != tc.owner {
				t.Errorf("gap %s/%s, want %s/%s (%s)", g.Cause, g.Owner, tc.cause, tc.owner, g.Detail)
			}
			if res.Outcome != model.ScanPartial || !contains(res.ToolsFailed, "nuguard") || contains(res.ToolsOK, "nuguard") {
				t.Errorf("outcome %s, ok %v, failed %v", res.Outcome, res.ToolsOK, res.ToolsFailed)
			}
			if len(res.Findings) != 0 {
				t.Errorf("%d findings from a failed scan", len(res.Findings))
			}
		})
	}
}

func TestNuGuardServiceFailuresAreAttributedGaps(t *testing.T) {
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()

	status := func(code int, retryAfter string) string {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"type":"x","title":"x","status":0,"code":"not_ready"}`))
		}))
		t.Cleanup(s.Close)
		return s.URL
	}
	for name, tc := range map[string]struct {
		url   string
		cause string
	}{
		"unreachable":              {downURL, "execution_failed"},
		"5xx":                      {status(500, ""), "execution_failed"},
		"not ready past the retry": {status(503, "1"), "execution_failed"},
		"key refused":              {status(401, ""), "credential_failed"},
	} {
		t.Run(name, func(t *testing.T) {
			res := ngScan(t, ngAdapter(tc.url), ngCommit)
			if g := nuguardGapOf(t, res); g.Cause != tc.cause || g.Owner != scan.OwnerPlatform {
				t.Errorf("gap %+v, want %s", g, tc.cause)
			}
			if res.Outcome != model.ScanPartial {
				t.Errorf("outcome %s", res.Outcome)
			}
		})
	}
}

// A NuGuard tool that did not run is a gap of its own, named nuguard/<tool>,
// and makes the scan partial; the tools that ran still count.
func TestNuGuardLostToolsAreGaps(t *testing.T) {
	result := mutateFixture(t, "ai-code.json", func(d map[string]any) {
		d["job"].(map[string]any)["status"] = "partial"
		runs := d["coverage"].(map[string]any)["tool_runs"].([]any)
		runs[1].(map[string]any)["status"] = "timeout" // atlas
		runs[2].(map[string]any)["status"] = "failed"  // semgrep
		runs[2].(map[string]any)["reason"] = "rules did not load"
		runs = append(runs, map[string]any{"tool": "grype", "status": "skipped", "reason": "network disabled", "findings": 0})
		d["coverage"].(map[string]any)["tool_runs"] = runs
	})
	fake := ngFake(t, &nuguardfake.Script{Result: result})
	a := ngAdapter(fake.URL)
	a.Tools = append(a.Tools, nuguard.ToolGrype)
	res := ngScan(t, a, ngCommit)

	got := map[string]string{}
	for _, g := range res.Gaps {
		got[g.Tool] = g.Cause + "/" + string(g.Owner)
	}
	want := map[string]string{
		"nuguard/atlas": "tool_timeout/platform", "nuguard/semgrep": "tool_failed/platform",
		"nuguard/grype": "tool_skipped/platform",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("gap for %s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	if res.Outcome != model.ScanPartial {
		t.Errorf("outcome %s, want partial", res.Outcome)
	}
	if !contains(res.ToolsOK, "nuguard") || !contains(res.ToolsOK, "nuguard/nga-rules") ||
		!contains(res.ToolsFailed, "nuguard/semgrep") {
		t.Errorf("ok %v failed %v", res.ToolsOK, res.ToolsFailed)
	}
	if len(res.Findings) == 0 {
		t.Error("the tools that ran lost their findings")
	}
}

// The captured result: osv failed, so the job is partial; semgrep was asked
// for and never mentioned. Its findings are all posture: none become
// findings, all are counted in the inventory.
func TestNuGuardCapturedPartialResult(t *testing.T) {
	fake := ngFake(t, &nuguardfake.Script{Result: readFixture(t, "nuguard", "quickstart-partial.json")})
	res := ngScan(t, ngAdapter(fake.URL), ngCommit)

	gaps := map[string]string{}
	for _, g := range res.Gaps {
		gaps[g.Tool] = g.Cause
	}
	if gaps["nuguard/osv"] != "tool_failed" || gaps["nuguard/semgrep"] != "tool_skipped" {
		t.Errorf("gaps %v", gaps)
	}
	if len(res.Findings) != 0 {
		t.Errorf("%d findings; posture observations are not findings", len(res.Findings))
	}
	inv := res.AIInventory
	if inv == nil {
		t.Fatal("no inventory")
	}
	total := 0
	for _, n := range inv.PostureObservations {
		total += n
	}
	if total != 14 || inv.PostureObservations["ATLAS-NC-001"] != 1 || inv.NodeCounts["AGENT"] != 1 ||
		inv.Source != "nuguard 0.9.15" || len(inv.ModelProviders) != 1 {
		t.Errorf("inventory %+v", inv)
	}
	if res.ToolVersions["nuguard"] != "0.9.15" || res.ToolVersions["nuguard/rulepack"] == "" {
		t.Errorf("tool versions %v", res.ToolVersions)
	}
	if _, ok := res.ToolVersions["nuguard/image"]; ok {
		t.Error("an image digest was recorded where the service reported none")
	}
}

func TestNuGuardRequestsTheDefaultsAtTheScannedCommit(t *testing.T) {
	fake := ngFake(t, &nuguardfake.Script{Result: readFixture(t, "nuguard", "ai-code.json")})
	res := ngScan(t, ngAdapter(fake.URL), ngCommit)
	if res.Outcome != model.ScanComplete || res.CommitSHA != ngCommit {
		t.Fatalf("outcome %s commit %q gaps %+v", res.Outcome, res.CommitSHA, res.Gaps)
	}
	subs := fake.Submissions()
	if len(subs) != 1 {
		t.Fatalf("%d submissions", len(subs))
	}
	s := subs[0]
	if s.RepoURL != ngURL || s.Ref != ngCommit || s.ClientRef != "S-000042" ||
		s.IdempotencyKey != nuguard.IdempotencyKey("S-000042", ngRepo, ngCommit) {
		t.Errorf("submission %+v", s)
	}
	opts, _ := json.Marshal(s.Options)
	want := `{"include_posture":false,"include_sbom":false,"min_severity":"low","network":false,"tools":["nga-rules","atlas","semgrep"],"use_llm":false}`
	if string(opts) != want {
		t.Errorf("options %s\nwant    %s", opts, want)
	}
}

func TestNuGuardRefusesAnotherVersion(t *testing.T) {
	fake := ngFake(t, &nuguardfake.Script{Result: readFixture(t, "nuguard", "ai-code.json"), Version: "0.9.16"})
	res := ngScan(t, ngAdapter(fake.URL), ngCommit)
	g := nuguardGapOf(t, res)
	if g.Cause != "version_mismatch" || g.Owner != scan.OwnerPlatform || len(res.Findings) != 0 {
		t.Errorf("gap %+v, %d findings", g, len(res.Findings))
	}
}

func TestNuGuardRefusesAnotherCommit(t *testing.T) {
	other := strings.Repeat("e", 40)
	fake := ngFake(t, &nuguardfake.Script{Result: readFixture(t, "nuguard", "ai-code.json"), CommitSHA: other})
	res := ngScan(t, ngAdapter(fake.URL), ngCommit)
	g := nuguardGapOf(t, res)
	if g.Cause != "commit_mismatch" || len(res.Findings) != 0 || !strings.Contains(g.Detail, other) {
		t.Errorf("gap %+v, %d findings", g, len(res.Findings))
	}
}

func TestNuGuardNeedsTheCommit(t *testing.T) {
	fake := ngFake(t, &nuguardfake.Script{Result: readFixture(t, "nuguard", "ai-code.json")})
	res := ngScan(t, ngAdapter(fake.URL), "")
	if g := nuguardGapOf(t, res); g.Cause != "execution_failed" || !strings.Contains(g.Detail, "no commit") {
		t.Errorf("gap %+v", g)
	}
	if n := len(fake.Submissions()); n != 0 {
		t.Errorf("%d scans submitted with no commit to pin them to", n)
	}
}

func TestNuGuardRefusesWhatItDidNotAskFor(t *testing.T) {
	a := adapters.NewNuGuard(nil, "0.9.15", nil)
	for name, doc := range map[string][]byte{
		"an unrequested kind": mutateFixture(t, "ai-code.json", func(d map[string]any) {
			d["findings"].([]any)[0].(map[string]any)["kind"] = "dependency"
		}),
		"posture not asked for": mutateFixture(t, "ai-code.json", func(d map[string]any) {
			d["findings"].([]any)[0].(map[string]any)["kind"] = "posture"
		}),
		"an absolute path": mutateFixture(t, "ai-code.json", func(d map[string]any) {
			d["findings"].([]any)[0].(map[string]any)["locations"].([]any)[0].(map[string]any)["path"] = "/srv/clone/src/agent/chat.ts"
		}),
		"a path out of the tree": mutateFixture(t, "ai-code.json", func(d map[string]any) {
			d["findings"].([]any)[0].(map[string]any)["locations"].([]any)[0].(map[string]any)["path"] = "src/../../etc/passwd"
		}),
		"a failed job": mutateFixture(t, "ai-code.json", func(d map[string]any) {
			d["job"].(map[string]any)["status"] = "failed"
		}),
	} {
		if got, err := a.Normalize(scan.RawOutput{Tool: "nuguard", Repo: agentRepo, Stdout: doc}); err == nil {
			t.Errorf("%s was accepted: %d findings", name, len(got))
		}
	}
}

// Identity is this project's own: NuGuard's fingerprint is an annotation, and
// moving every line leaves every fingerprint where it was (VM-F-102,
// VM-ADR-04).
func TestNuGuardFingerprintsIgnoreLinesAndNuGuardsOwnIdentity(t *testing.T) {
	a := adapters.NewNuGuard(nil, "0.9.15", nil)
	fps := func(doc []byte) []string {
		got, err := a.Normalize(scan.RawOutput{Tool: "nuguard", Repo: agentRepo, Stdout: doc})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, f := range got {
			out = append(out, fingerprint.Compute(f))
		}
		sort.Strings(out)
		return out
	}
	base := fps(readFixture(t, "nuguard", "ai-code.json"))
	shifted := fps(mutateFixture(t, "ai-code.json", func(d map[string]any) {
		for _, f := range d["findings"].([]any) {
			fm := f.(map[string]any)
			fm["fingerprint"] = "nf1_" + strings.Repeat("0", 32) // NuGuard's own changes too
			for _, l := range fm["locations"].([]any) {
				lm := l.(map[string]any)
				lm["start_line"] = lm["start_line"].(float64) + 40
				lm["end_line"] = lm["end_line"].(float64) + 40
			}
		}
	}))
	if strings.Join(base, ",") != strings.Join(shifted, ",") || len(base) != 3 {
		t.Errorf("fingerprints moved:\n%v\n%v", base, shifted)
	}
}

// Neither credential reaches anything this project returns or stores: not
// the result, its gaps, its raw output or the store, on any path, including
// a service that echoes the token back.
func TestNuGuardCredentialsReachNothingStored(t *testing.T) {
	scripts := map[string]*nuguardfake.Script{
		"success":           {Result: readFixture(t, "nuguard", "ai-code.json")},
		"partial":           {Result: readFixture(t, "nuguard", "quickstart-partial.json")},
		"echoed in a gap":   {ErrorCode: "auth_failed", EchoToken: true},
		"echoed in result":  {Result: readFixture(t, "nuguard", "ai-code.json"), EchoToken: true},
		"version mismatch":  {Result: readFixture(t, "nuguard", "ai-code.json"), Version: "9.9.9"},
		"commit mismatch":   {Result: readFixture(t, "nuguard", "ai-code.json"), CommitSHA: strings.Repeat("a", 40)},
		"worker lost twice": {ErrorCode: "worker_lost", EchoToken: true},
	}
	scripts["worker lost twice"].Then = scripts["worker lost twice"]
	for name, sc := range scripts {
		t.Run(name, func(t *testing.T) {
			fake := ngFake(t, sc)
			res := ngScan(t, ngAdapter(fake.URL), ngCommit)

			st := store.NewMemory()
			ctx := context.Background()
			if err := st.UpsertRepo(ctx, store.Repo{Name: ngRepo, Tier: 2}); err != nil {
				t.Fatal(err)
			}
			run, err := st.CreateRun(ctx, store.KindSweep, "test", "img", res.ToolVersions)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.UpsertObservations(ctx, run.ID, ngRepo, res.Findings); err != nil {
				t.Fatal(err)
			}
			rec := store.RepoScanResult{RunID: run.ID, Repo: ngRepo, Outcome: res.Outcome,
				ToolsOK: res.ToolsOK, ToolsFailed: res.ToolsFailed}
			for _, g := range res.Gaps {
				rec.FailureCause, rec.FailureDetail = g.Cause, g.Detail
			}
			if err := st.RecordScanResult(ctx, rec); err != nil {
				t.Fatal(err)
			}
			findings, _ := st.ListFindings(ctx, store.Query{Scope: store.ScopeAll, Repo: ngRepo})
			stored, _ := st.ScanResults(ctx, ngRepo, 10)

			for what, v := range map[string]any{"result": res, "findings": findings, "scan results": stored} {
				b, _ := json.Marshal(v)
				if strings.Contains(string(b), "LEAKCANARY") {
					t.Errorf("a credential reached the stored %s", what)
				}
			}
			if strings.Contains(name, "echoed") {
				if g := nuguardGapOf(t, res); g.Cause == "" {
					t.Errorf("an echoing service produced no gap")
				}
			}
		})
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// The start-up check stops the program for a disagreement that would fail
// every scan, and tolerates a service that is merely not there yet.
func TestNuGuardStartUpCheck(t *testing.T) {
	ctx := context.Background()
	t.Run("agrees", func(t *testing.T) {
		fake := ngFake(t, nil)
		if err := ngAdapter(fake.URL).CheckService(ctx); err != nil {
			t.Errorf("CheckService: %v", err)
		}
	})
	t.Run("another version", func(t *testing.T) {
		fake := ngFake(t, nil)
		fake.Version = "0.9.16"
		var refused *adapters.ErrNuGuardRefused
		if err := ngAdapter(fake.URL).CheckService(ctx); !errors.As(err, &refused) || !strings.Contains(err.Error(), "0.9.16") {
			t.Errorf("err = %v, want a refusal naming the version", err)
		}
	})
	t.Run("a tool it does not allow", func(t *testing.T) {
		fake := ngFake(t, nil)
		fake.ToolsAllowed = []string{"nga-rules", "atlas"}
		var refused *adapters.ErrNuGuardRefused
		if err := ngAdapter(fake.URL).CheckService(ctx); !errors.As(err, &refused) || !strings.Contains(err.Error(), "semgrep") {
			t.Errorf("err = %v, want a refusal naming semgrep", err)
		}
	})
	t.Run("the key refused", func(t *testing.T) {
		fake := ngFake(t, nil)
		fake.APIKey = "another"
		var refused *adapters.ErrNuGuardRefused
		if err := ngAdapter(fake.URL).CheckService(ctx); !errors.As(err, &refused) {
			t.Errorf("err = %v, want a refusal", err)
		}
	})
	t.Run("not ready or unreachable is tolerated", func(t *testing.T) {
		fake := ngFake(t, nil)
		fake.NotReady = true
		var refused *adapters.ErrNuGuardRefused
		if err := ngAdapter(fake.URL).CheckService(ctx); err == nil || errors.As(err, &refused) {
			t.Errorf("not ready: %v", err)
		}
		down := httptest.NewServer(http.NotFoundHandler())
		down.Close()
		if err := ngAdapter(down.URL).CheckService(ctx); err == nil || errors.As(err, &refused) {
			t.Errorf("unreachable: %v", err)
		}
	})
}

func TestNuGuardConfiguration(t *testing.T) {
	key := func() (string, error) { return ngKey, nil }
	if a, err := adapters.NewNuGuardFromConfig(adapters.NuGuardConfig{}, "0.9.15"); a != nil || err != nil {
		t.Errorf("no URL: %v %v, want off", a, err)
	}
	for _, url := range []string{"http://nuguard.internal:8080", "https://user:pw@nuguard.internal", "ftp://x"} {
		if _, err := adapters.NewNuGuardFromConfig(adapters.NuGuardConfig{URL: url, APIKey: key}, "0.9.15"); err == nil {
			t.Errorf("%s was accepted", url)
		}
	}
	a, err := adapters.NewNuGuardFromConfig(adapters.NuGuardConfig{
		URL: "http://127.0.0.1:8080", Tools: "nga-rules, semgrep", IncludePosture: true, Timeout: time.Minute, APIKey: key,
	}, "0.9.15")
	if err != nil || len(a.Tools) != 2 || !a.IncludePosture || a.Timeout != time.Minute {
		t.Errorf("%+v %v", a, err)
	}
	if _, err := adapters.ParseNuGuardTools("nga-rules,osv-scanner"); err == nil {
		t.Error("an unknown tool name was accepted")
	}
	if tools, _ := adapters.ParseNuGuardTools(""); len(tools) != 3 {
		t.Errorf("defaults %v", tools)
	}

	// Off means not registered: the registry, and so the run's tool list,
	// is the one there was before NuGuard.
	lock := testLock(t)
	off := adapters.AllWith(nil, lock, adapters.Optional{})
	on := adapters.AllWith(nil, lock, adapters.Optional{NuGuard: adapters.NewNuGuard(nil, "0.9.15", nil)})
	if len(off) != len(adapters.All(nil, lock)) || len(on) != len(off)+1 {
		t.Errorf("off %d, on %d", len(off), len(on))
	}
	for _, a := range off {
		if a.Name() == "nuguard" {
			t.Error("NuGuard is registered while off")
		}
	}
}
