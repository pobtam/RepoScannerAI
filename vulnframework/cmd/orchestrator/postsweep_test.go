package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/feed"
	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/triage"
)

var (
	api    = store.Repo{Name: "org/api", Tier: 1, Languages: []string{"go"}, HasTestSuite: true}
	jobs   = store.Repo{Name: "org/jobs", Tier: 2, Languages: []string{"go"}}
	silent = store.Repo{Name: "org/silent", Tier: 3, Languages: []string{"go"}}
)

func depFinding(repo, advisory string) model.RawFinding {
	return model.RawFinding{
		Repo: repo, Category: model.CategoryDependency,
		PrimaryID: advisory, Aliases: []string{"CVE-2025-22869"},
		Tool: "govulncheck", ToolVersion: "v1.8.0",
		Module: "golang.org/x/crypto", ModuleMajor: "v0",
		Versions: model.Versions{Current: "v0.30.0", Fixed: "v0.35.0"},
		Classification: model.Classification{
			Severity: model.SeverityHigh, CVSS: 7.5, Reachable: model.ReachableTrue,
			DepClass: model.DepProduction,
		},
	}
}

// sweptStore runs one sweep over api and jobs (each with one finding) and
// silent (a worker that never reports), and returns what the pass needs.
func sweptStore(t *testing.T) (*store.Memory, *orchestrator.Orchestrator, string, []store.Repo) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	repos := []store.Repo{api, jobs, silent}
	for _, r := range repos {
		if err := st.UpsertRepo(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	d := orchestrator.NewFakeDispatcher()
	d.WithFindings(api.Name, []string{"govulncheck"}, depFinding(api.Name, "GO-2025-3487"))
	d.WithFindings(jobs.Name, []string{"govulncheck"}, depFinding(jobs.Name, "GO-2025-3487"))
	d.WithSilentWorker(silent.Name)

	o := orchestrator.New(st, d, orchestrator.NewRateBudget(10), orchestrator.Config{CreditsPerScan: 1})
	stats, err := o.Sweep(ctx, store.KindSweep, "test", repos, nil)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	return st, o, stats.RunID, repos
}

func newPass(t *testing.T, st store.Store, o *orchestrator.Orchestrator, tr *triage.Triager, feeds feed.Multi) *postSweep {
	t.Helper()
	cal, err := score.LoadCalibration("../../config/calibration.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.LoadConfig("../../config/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &postSweep{
		Orch: o, Feeds: feeds, Triager: tr, Scorer: score.New(cal), Policy: policy.New(pol),
		View: storeView{ctx: context.Background(), st: st, log: log}, Log: log,
	}
}

func openFindings(t *testing.T, st store.Store, repo string) []model.Finding {
	t.Helper()
	fs, err := st.ListFindings(context.Background(), store.Query{Scope: store.ScopeOpen, Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// Without a key the pass must still decide every finding — and must not write
// anything in place of the narrative it could not get.
func TestWithNoKeyFindingsAreScoredAndRoutedWithoutANarrative(t *testing.T) {
	st, o, runID, repos := sweptStore(t)
	t.Setenv("ANTHROPIC_API_KEY", "")
	tr := triager("claude-sonnet-5-5", 8192)
	if !strings.Contains(tr.Unavailable, "ANTHROPIC_API_KEY") {
		t.Fatalf("triager with a model and no key: Unavailable = %q", tr.Unavailable)
	}

	kev := feed.NewFakeKEV().WithKEV("CVE-2025-22869", time.Now())
	epss := feed.NewFakeEPSS().WithEPSS("CVE-2025-22869", 0.42, time.Now())
	stats, err := newPass(t, st, o, tr, feed.Multi{Sources: []feed.Source{kev, epss}}).Run(context.Background(), runID, repos)
	if err != nil {
		t.Fatalf("pass: %v", err)
	}

	if len(stats.Repos) != 2 {
		t.Fatalf("pass covered %d repositories, want the 2 scanned this run", len(stats.Repos))
	}
	if len(stats.NotScanned) != 1 || stats.NotScanned[0] != silent.Name {
		t.Errorf("NotScanned = %v, want [%s]", stats.NotScanned, silent.Name)
	}
	for _, rp := range stats.Repos {
		if rp.NarrativeUnavailable != tr.Unavailable {
			t.Errorf("%s: NarrativeUnavailable = %q; the run must say why there is no narrative", rp.Repo, rp.NarrativeUnavailable)
		}
		if rp.Enrich.Answered == 0 {
			t.Errorf("%s: enrichment answered nothing: %+v", rp.Repo, rp.Enrich)
		}
		if rp.Triage.Scored != 1 || rp.Triage.SLAComputed != 1 {
			t.Errorf("%s: triage stats %+v; want one finding scored with an SLA", rp.Repo, rp.Triage)
		}
	}

	for _, repo := range []string{api.Name, jobs.Name} {
		for _, f := range openFindings(t, st, repo) {
			if f.State == model.Detected {
				t.Errorf("%s %s is still DETECTED", repo, f.Fingerprint)
			}
			if f.Triage != nil {
				t.Errorf("%s %s has a narrative %+v; none was available, so none may be written", repo, f.Fingerprint, f.Triage)
			}
			if f.Priority == "" {
				t.Errorf("%s %s has no priority", repo, f.Fingerprint)
			}
			if !f.Classification.KEVAvailable || !f.Classification.KEV || !f.Classification.EPSSAvailable {
				t.Errorf("%s %s: feeds did not reach the finding: %+v", repo, f.Fingerprint, f.Classification)
			}
		}
	}
}

// A live client that fails must not stop the run either.
func TestAFailingTriageClientFallsBackRatherThanFailingTheRun(t *testing.T) {
	st, o, runID, repos := sweptStore(t)
	client := triage.NewFakeClient()
	client.Respond = func(triage.Request) ([]triage.Verdict, error) {
		return nil, errors.New("401 invalid x-api-key")
	}
	tr := &triage.Triager{Client: client, Cache: triage.NewMemoryCache(), Model: "m"}

	stats, err := newPass(t, st, o, tr, feed.Multi{}).Run(context.Background(), runID, repos)
	if err != nil {
		t.Fatalf("a failing triage client failed the pass: %v", err)
	}
	for _, rp := range stats.Repos {
		if !strings.Contains(rp.NarrativeUnavailable, "401 invalid x-api-key") {
			t.Errorf("%s: NarrativeUnavailable = %q; want the failure named", rp.Repo, rp.NarrativeUnavailable)
		}
		if rp.Triage.Scored != 1 {
			t.Errorf("%s: %d scored after fallback, want 1", rp.Repo, rp.Triage.Scored)
		}
	}
	for _, f := range openFindings(t, st, api.Name) {
		if f.State == model.Detected || f.Triage != nil {
			t.Errorf("after fallback: state %s, narrative %+v", f.State, f.Triage)
		}
	}
}

// With a working client the narrative is persisted.
func TestAWorkingTriageClientPersistsTheNarrative(t *testing.T) {
	st, o, runID, repos := sweptStore(t)
	tr := &triage.Triager{Client: triage.NewFakeClient(), Cache: triage.NewMemoryCache(), Model: "m"}
	stats, err := newPass(t, st, o, tr, feed.Multi{}).Run(context.Background(), runID, repos)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Repos[0].NarrativeUnavailable != "" {
		t.Errorf("NarrativeUnavailable = %q with a working client", stats.Repos[0].NarrativeUnavailable)
	}
	for _, f := range openFindings(t, st, api.Name) {
		if f.Triage == nil || f.Triage.Description == "" {
			t.Errorf("%s has no narrative", f.Fingerprint)
		}
	}
}

// The pass decides and stops there: nothing reaches a tracker or a remote.
func TestThePassOpensNoTicketAndNoPullRequest(t *testing.T) {
	st, o, runID, repos := sweptStore(t)
	t.Setenv("ANTHROPIC_API_KEY", "")
	if _, err := newPass(t, st, o, triager("", 0), feed.Multi{}).Run(context.Background(), runID, repos); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, repo := range []string{api.Name, jobs.Name} {
		prs, err := st.OpenRemediationPRs(ctx, repo)
		if err != nil {
			t.Fatal(err)
		}
		if len(prs) != 0 {
			t.Errorf("%s: %d pull requests recorded", repo, len(prs))
		}
		for _, f := range openFindings(t, st, repo) {
			switch f.State {
			case model.AutoRemediating, model.PROpen, model.Merged:
				t.Errorf("%s %s reached %s; the pass must stop at the decision", repo, f.Fingerprint, f.State)
			}
		}
	}
}

func TestTriagerIsOffUnlessAModelIsNamed(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test-not-a-real-key")
	if tr := triager("", 8192); tr.Client != nil || !strings.Contains(tr.Unavailable, "-triage-model") {
		t.Errorf("a key alone enabled AI triage: %+v", tr)
	}
	if tr := triager("m", 8192); tr.Client == nil || tr.Unavailable != "" {
		t.Errorf("model and key did not enable AI triage: %+v", tr)
	}
}

func TestFeedsWithNoURLsAreNotConfigured(t *testing.T) {
	if n := len(feeds("", "").Sources); n != 0 {
		t.Errorf("%d feed sources with no URLs; a deployment must not acquire one by omission", n)
	}
	if n := len(feeds("https://kev.example", "").Sources); n != 1 {
		t.Errorf("%d sources for one URL", n)
	}
}

func TestEachFeedIsDownloadedOncePerRun(t *testing.T) {
	var hits, fails atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/flaky" && fails.Add(1) == 1 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		hits.Add(1)
		io.WriteString(w, "catalogue for "+r.URL.Path)
	}))
	defer srv.Close()

	client := newFeedClient()
	get := func(path string) (int, string) {
		resp, err := client.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	for i := 0; i < 3; i++ {
		if code, body := get("/kev"); code != 200 || body != "catalogue for /kev" {
			t.Fatalf("request %d: %d %q", i, code, body)
		}
	}
	if hits.Load() != 1 {
		t.Errorf("three lookups made %d downloads, want 1", hits.Load())
	}

	if code, _ := get("/flaky"); code != http.StatusServiceUnavailable {
		t.Fatalf("first flaky request: %d", code)
	}
	if code, _ := get("/flaky"); code != 200 {
		t.Errorf("a failure was cached: the second request got %d", code)
	}
}

func TestMain(m *testing.M) {
	// The triager reads the key from the environment; no test may inherit a
	// real one from the developer's shell.
	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Exit(m.Run())
}

func TestFirstPartyOwnershipComesFromTheRegistry(t *testing.T) {
	reg, err := firstparty.ParseRegistry([]byte(
		"version: 1\nwave2_trigger: tag\nmodules:\n  github.com/acme/common: acme/common\n"))
	if err != nil {
		t.Fatal(err)
	}
	v := storeView{ctx: context.Background(), st: store.NewMemory(), registry: reg,
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	cases := []struct {
		repo, path string
		want       bool
	}{
		{"acme/common", "github.com/acme/common", true},
		{"acme/common", "github.com/acme/common/hash", true},
		{"acme/api", "github.com/acme/common", false},
		{"acme/common", "github.com/acme/commonwealth", false},
	}
	for _, c := range cases {
		if got := v.IsFirstPartyOwner(c.repo, c.path); got != c.want {
			t.Errorf("IsFirstPartyOwner(%s, %s) = %v, want %v", c.repo, c.path, got, c.want)
		}
	}
	if (storeView{}).IsFirstPartyOwner("acme/common", "github.com/acme/common") {
		t.Error("with no registry, nothing is first-party")
	}
}
