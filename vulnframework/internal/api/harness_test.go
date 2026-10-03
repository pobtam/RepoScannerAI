package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/api"
	"github.com/wanaware/vulnframework/internal/feed"
	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/remediate"
	"github.com/wanaware/vulnframework/internal/remediate/guard"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/tracker"
	"github.com/wanaware/vulnframework/internal/triage"
)

// The API's test harness runs the REAL pipeline behind the server.
//
// Not fixtures: a corpus assembled by hand would let an endpoint return a field
// the pipeline never writes, which is the defect class the Producer-Coverage
// Audit exists for, arriving at the last layer where it looks like a feature
// nobody has used yet. So the server under test is backed by a store that a
// real sweep, a real triage pass, a real enrichment pass, a real ticket pass
// and a real remediation dispatch have written.

var apiNow = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

// theCredential is a plausible AWS key, seeded where a credential could
// realistically leak: a triage narrative that quoted the matched line.
//
// It is the string the disclosure tests look for. It matches
// model.CredentialPatterns, which is the shared definition of "looks like a
// secret" used by every other boundary.
const theCredential = "REDACTED-AWS-EXAMPLE-KEY-ID"

type harness struct {
	Store  store.Store
	Server *api.Server
	HTTP   *httptest.Server
	RunID  string
	// Fingers are every finding the pipeline produced.
	Fingers []string
	// SecretFP is a secret finding's fingerprint.
	SecretFP string
	// DepFP is a dependency finding with a pull request.
	DepFP string
	// WebFP is the blocked first-party consumer, in the repository whose
	// second scan was partial.
	WebFP string
	Cal   score.Calibration
}

func (h *harness) get(t *testing.T, path string) (int, []byte) {
	t.Helper()
	res, err := h.HTTP.Client().Get(h.HTTP.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return res.StatusCode, body
}

// getJSON fetches and decodes, failing on a non-200.
func (h *harness) getJSON(t *testing.T, path string, into any) {
	t.Helper()
	status, body := h.get(t, path)
	if status != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, status, body)
	}
	if into != nil {
		if err := json.Unmarshal(body, into); err != nil {
			t.Fatalf("decoding %s: %v\n%s", path, err, body)
		}
	}
}

// newHarness builds the server over a pipeline-populated store.
func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()

	s := store.NewMemory()
	s.SetClock(func() time.Time { return apiNow })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cal, err := score.LoadCalibration("../../config/calibration.yaml")
	if err != nil {
		t.Fatalf("calibration: %v", err)
	}
	pol, err := policy.LoadConfig("../../config/policy.yaml")
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	registry, err := firstparty.ParseRegistry([]byte(
		"version: 1\nwave2_trigger: tag\nmodules:\n  github.com/wanaware/common: org/common\n"))
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	h := &harness{Store: s, Cal: cal}
	h.seed(t, s, cal, pol, registry)

	srv, err := api.New(api.Config{
		Store: s, Calibration: cal, Policy: pol, Registry: registry,
		Auth:                     api.DemoAuth{Level: report.LevelSecurityOwner},
		UnavailableScoringInputs: nil,
		Wave2Trigger:             "tag",
		Logger:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:                    func() time.Time { return apiNow },
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	h.Server = srv
	h.HTTP = httptest.NewServer(srv.Handler())
	t.Cleanup(h.HTTP.Close)
	return h
}

// seed runs the pipeline.
func (h *harness) seed(t *testing.T, s *store.Memory, cal score.Calibration, pol policy.Config, registry *firstparty.Registry) {
	t.Helper()
	ctx := context.Background()

	repos := []store.Repo{
		{Name: "org/api", Tier: 1, Languages: []string{"go"}, HasTestSuite: true,
			ModuleTopology: "single", Codeowners: []string{"team-api"}},
		{Name: "org/common", Tier: 1, Languages: []string{"go"}, HasTestSuite: true},
		{Name: "org/web", Tier: 2, Languages: []string{"javascript", "go"}},
		// Deliberately never scanned successfully: the coverage view has to
		// have a real gap to describe.
		{Name: "org/legacy", Tier: 3, Languages: []string{"go"}},
	}
	for _, r := range repos {
		if err := s.UpsertRepo(ctx, r); err != nil {
			t.Fatalf("UpsertRepo: %v", err)
		}
	}

	raws := map[string][]model.RawFinding{
		"org/api": {
			depRaw("org/api", "GO-2023-2402", "CVE-2023-48795", "golang.org/x/crypto", "v0.16.0", "v0.17.0",
				model.SeverityHigh, model.ReachableTrue),
			depRaw("org/api", "GO-2025-3487", "CVE-2025-22869", "golang.org/x/net", "v0.17.0", "v0.23.0",
				model.SeverityCritical, model.ReachableUnknown),
			codeRaw("org/api", "G401", "internal/auth/token.go"),
			secretRaw("org/api", "config/staging.yaml"),
			// An advisory with NO fixed version: policy defers it and records
			// NO_UPSTREAM_FIX, which is the only real producer of a reason
			// code on a finding.
			noFixRaw("org/api", "GO-2026-4444", "CVE-2026-4444", "github.com/legacy/parser"),
		},
		"org/common": {
			depRaw("org/common", "GO-2024-0001", "CVE-2024-1111", "gopkg.in/yaml.v3", "v3.0.0", "v3.0.1",
				model.SeverityMedium, model.ReachableTrue),
		},
		"org/web": {
			depRaw("org/web", "GHSA-web-0001", "CVE-2026-2222", "github.com/wanaware/common", "v1.4.0", "v1.5.0",
				model.SeverityHigh, model.ReachableTrue),
		},
	}

	d := orchestrator.NewFakeDispatcher()
	for repo, rs := range raws {
		d.WithFindings(repo, []string{"govulncheck", "gosec", "gitleaks"}, rs...)
	}
	// The consumer's manifest, so the reverse-dependency index is populated by
	// the scanner rather than by this test.
	d.WithDeps("org/web", scanDeps{{"github.com/wanaware/common", "v1.4.0", true, false}}.toScan())
	d.WithDeps("org/api", scanDeps{{"github.com/wanaware/common", "v1.4.0", true, false},
		{"golang.org/x/crypto", "v0.16.0", true, false}}.toScan())
	// The legacy repository's worker starts and never reports.
	d.WithSilentWorker("org/legacy")

	// ONE remote for the whole harness. Two fakes would be two different
	// GitHubs: the reconciliation pass would not find the pull request the
	// remediation worker opened, and the stranding sweep would correctly
	// revert every finding it had just moved — a fixture bug that looks like a
	// framework bug.
	remote := gh.NewFake("main")

	o := orchestrator.New(s, d, orchestrator.NewRateBudget(500), orchestrator.Config{
		ScannerImage: "vulnframework-scanner@sha256:dead", CreditsPerScan: 1,
		ToolVersions: map[string]string{"govulncheck": "v1.8.0", "gosec": "v2.22.9"},
		PR:           remote,
		// The registry, so first-party classification happens where it does in
		// production: as the findings are recorded (OQ-AUDIT-09).
		FirstParty: registry,
	})
	o.Clock = func() time.Time { return apiNow }

	stats, err := o.Sweep(ctx, store.KindSweep, "cron", repos, nil)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	h.RunID = stats.RunID

	// Exploitation intelligence, from the fake feeds, before scoring.
	kev := feed.NewFakeKEV().WithKEV("CVE-2025-22869", apiNow.Add(-24*time.Hour)).
		WithNotKEV("CVE-2023-48795", apiNow.Add(-24*time.Hour))
	epss := feed.NewFakeEPSS().WithEPSS("CVE-2025-22869", 0.87, apiNow.Add(-12*time.Hour)).
		WithEPSS("CVE-2023-48795", 0.04, apiNow.Add(-12*time.Hour))
	// CVE-2024-1111 and CVE-2026-2222 are in neither catalogue, so their
	// findings must render with the inputs ABSENT rather than zero.

	engine := policy.New(pol)
	tr := &triage.Triager{Client: triage.NewFakeClient(), Cache: triage.NewMemoryCache(),
		Model: "claude-sonnet-5", Clock: func() time.Time { return apiNow }}

	for _, repo := range repos {
		if _, err := o.EnrichPass(ctx, feed.Multi{
			Sources: []feed.Source{kev, epss}, Clock: func() time.Time { return apiNow },
		}, repo.Name); err != nil {
			t.Fatalf("EnrichPass: %v", err)
		}
		if _, err := o.TriageAndRoute(ctx, repo, tr, score.New(cal), engine, apiView{}); err != nil {
			t.Fatalf("TriageAndRoute %s: %v", repo.Name, err)
		}
	}

	// Tickets, so Refs.Ticket has a real producer.
	fakeTracker := tracker.NewFake("github")
	svc := &tracker.Service{Tracker: fakeTracker, Store: s, Clock: func() time.Time { return apiNow }}
	for _, repo := range repos {
		if _, err := o.TicketPass(ctx, orchestrator.TicketRequest{
			Repo: repo, RunID: stats.RunID, Service: svc, Policy: engine,
			View: apiView{}, ReportURL: "https://reports.example/runs/" + stats.RunID + "/fleet.md",
		}); err != nil {
			t.Fatalf("TicketPass: %v", err)
		}
	}

	// Remediation, so Refs.PullRequest and the attempt history have real
	// producers.
	tc := remediate.NewFakeToolchain().
		WithModule("golang.org/x/crypto", "v0.16.0").
		WithAdvisory("GO-2023-2402", "golang.org/x/crypto", "v0.17.0").
		WithModule("gopkg.in/yaml.v3", "v3.0.0").
		WithAdvisory("GO-2024-0001", "gopkg.in/yaml.v3", "v3.0.1")
	g, err := guard.New(guard.Config{DenyPaths: []string{
		".github/workflows/**", "CODEOWNERS", "**/*.tf"}})
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	for _, repo := range []store.Repo{repos[0], repos[1]} {
		if _, err := o.RemediationPass(ctx, orchestrator.RemediationRequest{
			Repo: repo, RunID: stats.RunID, Policy: engine, View: apiView{},
			Groups: remediate.GroupConfig{MaxPerPR: 4, MaxPerPRCode: 1},
			Worker: &remediate.Worker{
				Store: s, PR: remote, Guard: g, Toolchain: tc,
				Owner: "fixworker-1", LeaseTTL: 30 * time.Minute,
				Clock: func() time.Time { return apiNow },
			},
		}); err != nil {
			t.Fatalf("RemediationPass %s: %v", repo.Name, err)
		}
	}

	// A first-party block, so the wave view has a wave: the consumer waits on
	// the owner's finding.
	commonFP := fingerprintOf(t, s, "org/common", "GO-2024-0001")
	webFP := fingerprintOf(t, s, "org/web", "GHSA-web-0001")
	h.WebFP = webFP
	if webFP != "" && commonFP != "" {
		if err := s.SetUpstreamFinding(ctx, webFP, commonFP); err != nil {
			t.Fatalf("SetUpstreamFinding: %v", err)
		}
		if f, err := s.GetFinding(ctx, webFP); err == nil && f.State == model.Triaged {
			if err := s.ApplyTransition(ctx, webFP, model.BlockedUpstream, model.TransitionContext{
				Actor: model.ActorOrchestrator, Cause: "waiting on the upstream first-party fix",
				At: apiNow,
			}); err != nil {
				t.Fatalf("to BLOCKED_UPSTREAM: %v", err)
			}
		}
	}

	// A second run, so history, deltas and trends have more than one point,
	// and so one finding is NOT re-observed while another regresses.
	later := apiNow.Add(24 * time.Hour)
	o.Clock = func() time.Time { return later }
	s.SetClock(func() time.Time { return later })
	second := raws
	// org/api's code finding disappears from a COMPLETE scan: it verifies.
	second["org/api"] = []model.RawFinding{raws["org/api"][0], raws["org/api"][1],
		raws["org/api"][3], raws["org/api"][4]}
	for repo, rs := range second {
		d.WithFindings(repo, []string{"govulncheck", "gosec", "gitleaks"}, rs...)
	}
	// org/web's scan FAILS this run, so its findings are not re-observed for a
	// reason that is a coverage gap rather than a fix.
	// PARTIAL, not failed: one tool survived. A partial gap has to say which
	// signals remain current and which were lost (VM-F-212), and a fixture
	// where everything fails never exercises that.
	d.WithOutcome("org/web", model.ScanPartial, []string{"gitleaks"},
		[]string{"govulncheck", "gosec"})
	run2, err := o.Sweep(ctx, store.KindSweep, "cron", repos, nil)
	if err != nil {
		t.Fatalf("second Sweep: %v", err)
	}

	// The second run's triage and scoring pass. Every run re-scores, which is
	// what gives a finding a non-zero age.
	for _, repo := range repos {
		if _, err := o.TriageAndRoute(ctx, repo, tr, score.New(cal), engine, apiView{}); err != nil {
			t.Fatalf("second TriageAndRoute %s: %v", repo.Name, err)
		}
	}

	// An issued, immutable report for the FIRST run, so the snapshot endpoint
	// has a record and the overview can be historical rather than live.
	gen := report.NewGenerator(s, cal)
	gen.Clock = func() time.Time { return later }
	gen.UnavailableScoringInputs = nil
	rep, err := gen.Generate(ctx, report.Query{
		Kind: report.KindFleet, AnchorRun: stats.RunID, Scope: store.ScopeAll, Template: "fleet.v1",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	issued, err := report.Issue(rep)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	first, err := report.Record(ctx, s, issued, "orchestrator")
	if err != nil {
		t.Fatalf("report.Record: %v", err)
	}

	// A SECOND report for the same run, replacing the first.
	//
	// It is here so that the lineage has a real producer in the fixture the
	// producer-coverage audit walks. Both ReportSummary.Supersedes and
	// SupersededBy would otherwise be fields the interface reads and nothing
	// writes — which is the defect class this build found eleven times, and
	// the one store.Report.Supersedes itself was instance ten of.
	//
	// It is anchored to the same run, which is what a correction looks like:
	// the same population, re-issued. Anchoring it elsewhere would be a
	// different report, not a replacement.
	superseding, err := gen.Generate(ctx, report.Query{
		Kind: report.KindFleet, AnchorRun: stats.RunID, Scope: store.ScopeAll,
		Template: "fleet.v1",
		// The relationship travels on the query, which is what gives the
		// replacement its own identifier: a report's id derives from its
		// query, so without this the re-issue would collide with the report
		// it replaces.
		Supersedes: first.ID,
	})
	if err != nil {
		t.Fatalf("Generate superseding: %v", err)
	}
	reissued, err := report.Issue(superseding)
	if err != nil {
		t.Fatalf("Issue superseding: %v", err)
	}
	if _, err := report.Record(ctx, s, reissued, "orchestrator"); err != nil {
		t.Fatalf("recording the superseding report: %v", err)
	}
	_ = run2

	// Every fingerprint, and the two the tests address by name.
	all, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	for _, f := range all {
		h.Fingers = append(h.Fingers, f.Fingerprint)
		if f.Category == model.CategorySecret && h.SecretFP == "" {
			h.SecretFP = f.Fingerprint
		}
		if f.Refs.PullRequest != nil && h.DepFP == "" {
			h.DepFP = f.Fingerprint
		}
	}
	if len(h.Fingers) == 0 {
		t.Fatal("the pipeline produced no findings; every test below would be vacuous")
	}
	if h.SecretFP == "" {
		t.Fatal("the pipeline produced no secret finding; the disclosure tests need one")
	}
	if h.DepFP == "" {
		t.Fatal("the pipeline opened no pull request; the attempt tests need one")
	}
}

// --- fixtures ----------------------------------------------------------------

func depRaw(repo, id, cve, module, current, fixed string, sev model.Severity, reach model.Reachable) model.RawFinding {
	return model.RawFinding{
		Repo: repo, Category: model.CategoryDependency, PrimaryID: id,
		Aliases: []string{cve}, Tool: "govulncheck", ToolVersion: "v1.8.0",
		Module: module, ModuleMajor: "v0", ImportPath: []string{repo, module},
		Versions: model.Versions{Current: current, Fixed: fixed},
		Classification: model.Classification{
			Severity: sev, CVSS: 7.5, Reachable: reach, DepClass: model.DepProduction,
		},
		AdvisoryURL: "https://pkg.go.dev/vuln/" + id,
	}
}

// noFixRaw is an advisory with no fixed version, which is the ordinary case
// for a stale or abandoned dependency.
func noFixRaw(repo, id, cve, module string) model.RawFinding {
	f := depRaw(repo, id, cve, module, "v1.2.0", "", model.SeverityHigh, model.ReachableTrue)
	f.Versions.Fixed = ""
	return f
}

func codeRaw(repo, rule, file string) model.RawFinding {
	return model.RawFinding{
		Repo: repo, Category: model.CategoryCode, Tool: "gosec", ToolVersion: "v2.22.9",
		RuleID: rule, PrimaryID: rule, File: file, Line: 42,
		Classification: model.Classification{Severity: model.SeverityMedium,
			Reachable: model.ReachableUnknown},
	}
}

// secretRaw is a gitleaks-shaped secret finding.
//
// It carries the credential CLASS and the file, and no value: the record has
// nowhere to put one (VM-F-263). The tests then prove the API cannot leak what
// the model cannot hold, and separately prove the response guard catches
// material arriving through a free-text field.
func secretRaw(repo, file string) model.RawFinding {
	return model.RawFinding{
		Repo: repo, Category: model.CategorySecret, Tool: "gitleaks", ToolVersion: "v8.28.0",
		DetectorRuleID: "aws-access-token", PrimaryID: "aws-access-token",
		File: file, Line: 12, CredentialType: "aws_access_key",
		Classification: model.Classification{Severity: model.SeverityCritical,
			Reachable: model.ReachableUnknown},
	}
}

type scanModuleDep = scan.ModuleDep

type scanDep struct {
	module   string
	version  string
	direct   bool
	replaced bool
}

type scanDeps []scanDep

func (ds scanDeps) toScan() []scanModuleDep {
	out := make([]scanModuleDep, 0, len(ds))
	for _, d := range ds {
		out = append(out, scanModuleDep{Module: d.module, Version: d.version,
			Direct: d.direct, Replaced: d.replaced})
	}
	return out
}

func fingerprintOf(t *testing.T, s store.Store, repo, id string) string {
	t.Helper()
	all, err := s.ListFindings(context.Background(), store.Query{Scope: store.ScopeAll, Repo: repo})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	for _, f := range all {
		if f.Identity.PrimaryID == id {
			return f.Fingerprint
		}
		// By alias too: the alias table promotes a canonical identifier, so
		// the name a fixture used may not be the primary one afterwards —
		// which is the merge working (VM-F-106).
		for _, alias := range f.Identity.Aliases {
			if alias == id {
				return f.Fingerprint
			}
		}
	}
	return ""
}

// apiView is the policy store view: nothing in progress, no first-party
// ownership claims beyond the registry's.
type apiView struct{}

func (apiView) HasOpenPullRequest(string) bool        { return false }
func (apiView) IsFirstPartyOwner(string, string) bool { return false }

var _ policy.StoreView = apiView{}

func init() {
	// Keep the test output quiet unless something fails.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	})))
}

var _ = fmt.Sprintf

// replaceAuth rebuilds the server over the same store with a different
// principal, so the privilege tests exercise the real handlers rather than the
// authenticator in isolation.
func replaceAuth(t *testing.T, h *harness, level report.Level, repos []string) {
	t.Helper()
	srv, err := api.New(api.Config{
		Store: h.Store, Calibration: h.Cal,
		Auth:   api.DemoAuth{Level: level, Repos: repos},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:  func() time.Time { return apiNow },
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	h.HTTP.Close()
	h.Server = srv
	h.HTTP = httptest.NewServer(srv.Handler())
	t.Cleanup(h.HTTP.Close)
}

// replaceAuthWith rebuilds the server with a specific authenticator.
func replaceAuthWith(t *testing.T, h *harness, auth api.Authenticator) {
	t.Helper()
	srv, err := api.New(api.Config{
		Store: h.Store, Calibration: h.Cal, Auth: auth,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:  func() time.Time { return apiNow },
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	h.HTTP.Close()
	h.Server = srv
	h.HTTP = httptest.NewServer(srv.Handler())
	t.Cleanup(h.HTTP.Close)
}
