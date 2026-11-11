package audit_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/audit"
	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/nuguard"
	"github.com/wanaware/vulnframework/internal/nuguard/nuguardfake"
	"github.com/wanaware/vulnframework/internal/nuguardopt"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/remediate"
	"github.com/wanaware/vulnframework/internal/remediate/guard"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/tracker"
	"github.com/wanaware/vulnframework/internal/triage"
)

// OQ-AUDIT-04: the Producer-Coverage Audit over the STORE types.
//
// The first two censuses covered RawFinding and Finding. Everything else the
// store holds — runs, scan results, reports, tickets, pull requests,
// dependency manifests, coverage — went unaudited, and the recurrence rate so
// far (eight instances in twelve phases) said that is where the next one is.
//
// It was. The audit could find no real producer for store.RemediationPR or
// store.RepoLock at all, because nothing dispatched remediation: policy routed
// findings for auto-remediation and the remediation worker claimed findings
// from TRIAGED, with no step in between (OQ-AUDIT-05).
//
// Same method as before: run the real producers, record what comes out, and
// name the producer for anything exempt.

// storeRun is one pipeline exercised end to end, with every store-type
// producer run and the values they wrote captured.
type storeRun struct {
	Store store.Store
	// RunID is the first run; SecondRunID the follow-up sweep, which is what
	// makes coverage streaks and re-observation real rather than asserted.
	RunID        string
	SecondRunID  string
	Repo         store.Repo
	DeferredRepo store.Repo
	Fingers      []string
	Branch       string
	// LockDuringAttempt is the repository lock as it stood while the
	// remediation worker held it. Captured mid-attempt because the worker
	// releases it before returning: a census taken afterwards would see the
	// type unwritten and wrongly report a producer gap.
	LockDuringAttempt store.RepoLock
	// LeaseDuringAttempt is a finding's lease as it stood while the worker held
	// it, for the same reason as the lock: the claim is released before the
	// attempt returns.
	LeaseDuringAttempt store.Lease
	// Close is the run-close accounting from both sweeps.
	Close []store.CloseStats
}

// exerciseEveryStoreProducer runs the real producers of every store type.
//
// Deliberately one function: a census assembled from several disconnected
// setups would let a type look covered because some other test happened to
// populate it. This is one pipeline, and every field the censuses below find
// was written by the code that writes it in production.
func exerciseEveryStoreProducer(t *testing.T) storeRun {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)

	s := store.NewMemory()
	s.SetClock(func() time.Time { return now })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// --- the fleet ---------------------------------------------------------
	//
	// Four repositories, each describing a different real outcome, because the
	// coverage types exist to tell them apart and a fleet where everything
	// succeeds cannot exercise them.
	repo := store.Repo{
		Name: "org/wanaware-api", Tier: 1, Languages: []string{"go"},
		HasTestSuite: true, ModuleTopology: "single", Codeowners: []string{"team-api"},
	}
	// A worker that starts and never reports: no_result, not a clean scan.
	silent := store.Repo{Name: "org/wanaware-jobs", Tier: 2, Languages: []string{"go"}}
	// A scan where one tool ran and one died: partial, with tools_failed.
	partial := store.Repo{Name: "org/wanaware-edge", Tier: 2, Languages: []string{"go"}, HasTestSuite: true}
	// Funded out of the second sweep: not_dispatched, a deferral streak.
	deferred := store.Repo{Name: "org/wanaware-batch", Tier: 3, Languages: []string{"go"}}
	fleet := []store.Repo{repo, silent, partial, deferred}
	for _, r := range fleet {
		if err := s.UpsertRepo(ctx, r); err != nil {
			t.Fatalf("upsert repo %s: %v", r.Name, err)
		}
	}

	raws := realAdapterOutput(t)
	for i := range raws {
		raws[i].Repo = repo.Name
	}

	// --- sweep 1: Run, RepoScanResult, PlanEntry, CloseStats, ModuleDep ----
	fake := orchestrator.NewFakeDispatcher()
	fake.WithFindings(repo.Name, []string{"govulncheck", "gosec", "gitleaks"}, raws...)
	deps, err := scan.ReadGoManifest(writeGoModFor(t))
	if err != nil {
		t.Fatalf("ReadGoManifest: %v", err)
	}
	fake.WithDeps(repo.Name, deps)
	fake.WithSilentWorker(silent.Name)
	fake.WithFindings(deferred.Name, []string{"govulncheck"})

	d := &routedDispatcher{fake: fake, real: map[string]realScan{
		// The REAL scan worker for this one. ToolsFailed, FailureDetail and
		// DurationSec have exactly one producer — internal/scan.Worker, when a
		// tool dies under it — and a fake dispatcher that simply returned the
		// fields would prove nothing about whether that code still writes them.
		// Likewise CommitSHA (the real LocalDispatcher reading the checkout's
		// .git) and AIInventory (the real NuGuard adapter, against the fake
		// service).
		partial.Name: {Worker: partialScanWorker(t), Dir: withGitHead(t, writeGoModFor(t))},
	}}

	o := orchestrator.New(s, d, orchestrator.NewRateBudget(500), orchestrator.Config{
		ScannerImage:   "vulnframework-scanner@sha256:abc",
		ToolVersions:   map[string]string{"govulncheck": "v1.8.0", "gosec": "v2.22.9"},
		CreditsPerScan: 1,
		PR:             gh.NewFake("main"),
	})
	o.Clock = func() time.Time { return now }

	// The NuGuard repository's options, through the real resolution the
	// scan worker runs: a fleet setting the operator has since narrowed the
	// ceiling under (a clip), and a scan that asks for posture and to keep the
	// AI-SBOM. The
	// only producers of EffectiveNuGuard, ToolsNotRequested and AISBOM.
	ceiling := nuguardopt.Ceiling{Configured: true, AllowTools: []string{"nga-rules", "atlas"}, AllowPosture: true,
		MaxTimeoutS: 600, Defaults: nuguardopt.Fleet{Enabled: true, Tools: []string{"nga-rules", "atlas"}, TimeoutS: 600}}
	if _, err := s.SetNuGuardSettings(ctx, nuguardopt.Fleet{Enabled: true, Tools: []string{"nga-rules", "atlas", "semgrep"},
		TimeoutS: 600}, "census", "", now); err != nil {
		t.Fatal(err)
	}
	posture := true
	eff, _, err := store.ResolveNuGuard(ctx, s, ceiling, partial.Name,
		&nuguardopt.Request{Mode: nuguardopt.RequestOn, IncludePosture: &posture, KeepSBOM: true})
	if err != nil {
		t.Fatal(err)
	}
	stats, err := o.SweepWith(ctx, store.KindSweep, "cron", fleet, nil,
		orchestrator.SweepOptions{NuGuard: map[string]*nuguardopt.Effective{partial.Name: &eff}})
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	// --- triage, scoring, policy ------------------------------------------
	cal, err := score.LoadCalibration("../../config/calibration.yaml")
	if err != nil {
		t.Fatalf("calibration: %v", err)
	}
	pol, err := policy.LoadConfig("../../config/policy.yaml")
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	engine := policy.New(pol)
	tr := &triage.Triager{Client: triage.NewFakeClient(), Cache: triage.NewMemoryCache(),
		Model: "claude-sonnet-5", Clock: func() time.Time { return now }}
	if _, err := o.TriageAndRoute(ctx, repo, tr, score.New(cal), engine, auditView{}); err != nil {
		t.Fatalf("TriageAndRoute: %v", err)
	}

	// --- tickets: Ticket, RunTicket ---------------------------------------
	fakeTracker := tracker.NewFake("github")
	svc := &tracker.Service{Tracker: fakeTracker, Store: s, Clock: func() time.Time { return now }}
	if _, err := o.TicketPass(ctx, orchestrator.TicketRequest{
		Repo: repo, RunID: stats.RunID, Service: svc, Policy: engine,
		View: auditView{}, ReportURL: "https://reports.example/runs/" + stats.RunID + "/fleet.md",
	}); err != nil {
		t.Fatalf("TicketPass: %v", err)
	}

	// --- remediation: RemediationPR, RepoLock -----------------------------
	//
	// Through the dispatch pass, not by hand. That is the point of OQ-AUDIT-05:
	// these two types had no producer in a full run, and a census that reached
	// into the worker to make one would have hidden the hole it exists to find.
	remote := gh.NewFake("main")
	tc := remediate.NewFakeToolchain()
	open, err := s.ListFindings(ctx, store.Query{
		Scope: store.ScopeOpen, Repo: repo.Name, Categories: []model.Category{model.CategoryDependency},
	})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	for _, f := range open {
		if f.Location.Module == "" || f.Versions.Fixed == "" {
			continue
		}
		tc.WithModule(f.Location.Module, f.Versions.Current)
		if f.Identity.PrimaryID != "" {
			tc.WithAdvisory(f.Identity.PrimaryID, f.Location.Module, f.Versions.Fixed)
		}
	}
	g, err := guard.New(guard.Config{DenyPaths: []string{
		".github/workflows/**", ".github/actions/**", "CODEOWNERS", "**/*.tf", "**/*.tfvars",
	}})
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	var lockDuring store.RepoLock
	var leaseDuring store.Lease
	w := &remediate.Worker{
		Store: s, PR: remote, Guard: g, Toolchain: tc,
		Owner: "fixworker-1", LeaseTTL: 30 * time.Minute,
		Clock: func() time.Time { return now },
		// The repository lock is held only for the duration of an attempt, so
		// it is read from inside one. The value still comes from the worker's
		// own AcquireRepoLockAt — this only decides WHEN the census looks.
		Fixer: observingFixer{
			inner: remediate.DeterministicFixer{Toolchain: tc},
			observe: func(ctx context.Context) {
				lock, err := s.GetRepoLock(ctx, repo.Name)
				if err == nil && lock.Owner != "" {
					lockDuring = lock
				}
				leased, err := s.ListFindings(ctx, store.Query{
					Scope: store.ScopeOpen, Repo: repo.Name,
					States: []model.State{model.AutoRemediating},
				})
				if err != nil {
					return
				}
				for _, f := range leased {
					if l, err := s.GetLease(ctx, f.Fingerprint); err == nil && l.Held() {
						leaseDuring = l
						return
					}
				}
			},
		},
	}
	remStats, err := o.RemediationPass(ctx, orchestrator.RemediationRequest{
		Repo: repo, RunID: stats.RunID, Worker: w, Policy: engine, View: auditView{},
		Groups: remediate.GroupConfig{MaxPerPR: 8, MaxPerPRCode: 1},
	})
	if err != nil {
		t.Fatalf("RemediationPass: %v", err)
	}
	if remStats.PROpened == 0 {
		t.Fatalf("the pipeline opened no pull request (outcomes=%v); store.RemediationPR would "+
			"have no producer and the census below would be vacuous", remStats.Outcomes)
	}
	var branch string
	if prs, err := s.OpenRemediationPRs(ctx, repo.Name); err == nil && len(prs) > 0 {
		branch = prs[0].Branch
		// The App reports the pull request the worker just opened. This is the
		// producer of ConfirmedAt and of the webhook health record: with the
		// webhook live, reconciliation stops asking the remote about pull
		// requests it has vouched for (OQ-P12-01).
		if _, err := o.ApplyWebhook(ctx, gh.Event{
			Kind: gh.EventPullRequestOpened, Repo: repo.Name,
			Number: prs[0].Number, Branch: branch,
		}); err != nil {
			t.Fatalf("ApplyWebhook: %v", err)
		}
	}

	// --- sweep 2: a deferral, a new finding, and a tracker outage ----------
	//
	// The second run is not decoration. A coverage streak needs more than one
	// run to count, a ticket operation queue needs an outage to have anything
	// in it, and both are fields no single-run census can reach.
	later := now.Add(24 * time.Hour)
	o.Clock = func() time.Time { return later }
	s.SetClock(func() time.Time { return later })

	// A credential committed since the last scan. A secret is ticketed
	// immediately whatever its priority (VM-F-852), which is what gives the
	// outage below something to fail at: every other finding in this fleet is
	// aggregated into the run ticket and needs no call to the tracker at all.
	newRaw := newSecretSince(t, raws)
	fake.WithFindings(repo.Name, []string{"govulncheck", "gosec", "gitleaks"}, append(raws, newRaw)...)
	fake.WithDeps(repo.Name, deps)

	// One credit funds the first repository only; the second is deferred with
	// its reason recorded (VM-F-216).
	o.Budget = orchestrator.NewRateBudget(1)
	second, err := o.Sweep(ctx, store.KindSweep, "cron", []store.Repo{repo, deferred}, nil)
	if err != nil {
		t.Fatalf("second Sweep: %v", err)
	}
	if _, err := o.TriageAndRoute(ctx, repo, tr, score.New(cal), engine, auditView{}); err != nil {
		t.Fatalf("second TriageAndRoute: %v", err)
	}

	// The tracker is down during this pass. TicketOp's only producer is the
	// failure path, so a census taken over a healthy system never sees the
	// type written at all.
	down := tracker.NewFake("github")
	down.FailWith(errTrackerDown)
	downSvc := &tracker.Service{Tracker: down, Store: s, Clock: func() time.Time { return later }}
	if _, err := o.TicketPass(ctx, orchestrator.TicketRequest{
		Repo: repo, RunID: second.RunID, Service: downSvc, Policy: engine,
		View: auditView{}, ReportURL: "https://reports.example/runs/" + second.RunID + "/fleet.md",
	}); err != nil {
		t.Fatalf("TicketPass during outage: %v", err)
	}

	// --- first-party: the reverse-dependency index ------------------------
	reg, err := firstparty.ParseRegistry([]byte(
		"version: 1\nmodules:\n  github.com/wanaware/common: org/wanaware-common\n"))
	if err != nil {
		t.Fatalf("ParseRegistry: %v", err)
	}
	if _, err := firstparty.LoadIndex(ctx, s, reg); err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}

	// --- reports: store.Report --------------------------------------------
	gen := report.NewGenerator(s, cal)
	gen.Clock = func() time.Time { return later }
	for _, q := range []report.Query{
		{Kind: report.KindFleet, AnchorRun: second.RunID, Scope: store.ScopeAll, Template: "fleet.v1"},
		{Kind: report.KindRepo, AnchorRun: second.RunID, Repo: repo.Name, Scope: store.ScopeAll, Template: "repo.v1"},
	} {
		rep, err := gen.Generate(ctx, q)
		if err != nil {
			t.Fatalf("Generate %s: %v", q.Kind, err)
		}
		issued, err := report.Issue(rep)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if err := report.PublishRun(ctx, report.NewFakePublisher(), issued, nil); err != nil {
			t.Fatalf("PublishRun: %v", err)
		}
		// report.Record is what makes a report citable years later
		// (VM-ADR-15). It did not exist when this census was written: the
		// generator issued reports, the publisher delivered the artifacts, and
		// nothing wrote the record — so store.Report had no producer outside
		// tests at all (OQ-AUDIT-04).
		recorded, err := report.Record(ctx, s, issued, "orchestrator")
		if err != nil {
			t.Fatalf("report.Record: %v", err)
		}

		// And a re-issue that REPLACES it, so store.Report.Supersedes has a
		// real producer in the census.
		//
		// It was instance ten of this build's recurring defect and the last
		// one still open: the column existed, VM-UI-F-1108 required the
		// relationship, and nothing wrote it. The exemption below used to
		// record that gap. Filling the census with a report that supersedes
		// another is what closes it — and it closes it the way the census
		// demands, by running the producer rather than by constructing the
		// value.
		reissue := q
		reissue.Supersedes = recorded.ID
		corrected, err := gen.Generate(ctx, reissue)
		if err != nil {
			t.Fatalf("Generate the superseding %s report: %v", q.Kind, err)
		}
		correctedIssued, err := report.Issue(corrected)
		if err != nil {
			t.Fatalf("Issue the superseding report: %v", err)
		}
		if _, err := report.Record(ctx, s, correctedIssued, "orchestrator"); err != nil {
			t.Fatalf("recording the superseding report: %v", err)
		}
	}

	var fps []string
	all, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	for _, f := range all {
		fps = append(fps, f.Fingerprint)
	}
	if len(fps) == 0 {
		t.Fatal("the run produced no findings; every census below would trivially pass")
	}
	return storeRun{
		Store: s, RunID: stats.RunID, SecondRunID: second.RunID,
		Repo: repo, DeferredRepo: deferred, Fingers: fps,
		Branch: branch, LockDuringAttempt: lockDuring, LeaseDuringAttempt: leaseDuring,
		Close: []store.CloseStats{stats.Close, second.Close},
	}
}

// --- the producers that need composing ---------------------------------------

// routedDispatcher sends some repositories to the REAL scan worker and the
// rest to the offline fake.
//
// Both are real implementations of the same interface; this only chooses
// between them per repository, so a census can cover the fields only the real
// worker writes without giving up the fake's canned adapter output for the
// rest of the fleet.
type routedDispatcher struct {
	fake *orchestrator.FakeDispatcher
	real map[string]realScan
}

// realScan pairs a real scan worker with the checkout it should read.
type realScan struct {
	Worker *scan.Worker
	Dir    string
}

func (d *routedDispatcher) Dispatch(ctx context.Context, job orchestrator.Job) (scan.Result, error) {
	if real, ok := d.real[job.Repo]; ok {
		local := &orchestrator.LocalDispatcher{Worker: real.Worker, WorkDir: func(string) string { return real.Dir }}
		return local.Dispatch(ctx, job)
	}
	return d.fake.Dispatch(ctx, job)
}

// withGitHead makes dir a checkout at a commit, as a clone is.
func withGitHead(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir+"/.git", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/.git/HEAD", []byte("5d0c7e9a1b2c3d4e5f60718293a4b5c6d7e8f901\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// partialScanWorker is a real scan worker over one adapter that works and one
// that dies, which is the only way tools_failed, failure_detail and
// duration_sec come to be written.
func partialScanWorker(t *testing.T) *scan.Worker {
	t.Helper()
	// The real NuGuard adapter, against the fake service serving a captured
	// result: the only producer of an AI inventory.
	result, err := os.ReadFile("../../testdata/fixtures/nuguard/ai-code.json")
	if err != nil {
		t.Fatal(err)
	}
	fake := nuguardfake.New("census-key", "0.9.15")
	t.Cleanup(fake.Close)
	fake.Default = &nuguardfake.Script{Result: result}
	fake.Narrow = true
	ng := adapters.NewNuGuard(&nuguard.Client{BaseURL: fake.URL, APIKey: func() (string, error) { return "census-key", nil }},
		"0.9.15", nil)
	reg, err := scan.NewRegistry(quietAdapter{}, dyingAdapter{}, ng)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	// An advancing clock, because a duration measured between two reads of a
	// frozen clock is zero, and zero is indistinguishable from unwritten.
	ticks := 0
	return &scan.Worker{Registry: reg, Clock: func() time.Time {
		ticks++
		return time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC).Add(time.Duration(ticks*7) * time.Second)
	}}
}

// quietAdapter runs cleanly and reports nothing, which is an ordinary result.
type quietAdapter struct{}

func (quietAdapter) Name() string                     { return "govulncheck" }
func (quietAdapter) Version() string                  { return "v1.8.0" }
func (quietAdapter) Supports(_ scan.RepoProfile) bool { return true }
func (quietAdapter) Run(_ context.Context, _ string, _ scan.RunOpts) (scan.RawOutput, error) {
	return scan.RawOutput{Tool: "govulncheck", ToolVersion: "v1.8.0", Stdout: []byte("{}")}, nil
}
func (quietAdapter) Normalize(_ scan.RawOutput) ([]model.RawFinding, error) { return nil, nil }

// dyingAdapter cannot be executed, which is a coverage gap and not a failed
// scan (VM-F-204).
type dyingAdapter struct{}

func (dyingAdapter) Name() string                     { return "gosec" }
func (dyingAdapter) Version() string                  { return "v2.22.9" }
func (dyingAdapter) Supports(_ scan.RepoProfile) bool { return true }
func (dyingAdapter) Run(_ context.Context, _ string, _ scan.RunOpts) (scan.RawOutput, error) {
	return scan.RawOutput{}, fmt.Errorf("exec: gosec: signal: killed (container out of memory)")
}
func (dyingAdapter) Normalize(_ scan.RawOutput) ([]model.RawFinding, error) { return nil, nil }

// observingFixer reads state while the remediation harness holds it, and is
// otherwise the deterministic bumper.
type observingFixer struct {
	inner   remediate.Fixer
	observe func(ctx context.Context)
}

func (f observingFixer) Name() string { return f.inner.Name() }

func (f observingFixer) Actionable(g remediate.FixGroup) bool { return f.inner.Actionable(g) }

func (f observingFixer) Apply(ctx context.Context, dir string, g remediate.FixGroup) (remediate.Applied, error) {
	f.observe(ctx)
	return f.inner.Apply(ctx, dir, g)
}

// newSecretSince derives a NEW secret finding from a real adapter's output by
// moving it to a file nobody has scanned before.
//
// Derived rather than constructed: the shape, the rule, the classification and
// the absent value all come from the gitleaks adapter, so the finding the
// pipeline ticketes is one a real scanner could have produced.
func newSecretSince(t *testing.T, raws []model.RawFinding) model.RawFinding {
	t.Helper()
	for _, raw := range raws {
		if raw.Category != model.CategorySecret {
			continue
		}
		out := raw
		out.File = "internal/config/rotated_credentials.go"
		out.Line = 12
		return out
	}
	t.Fatal("the real adapters produced no secret finding, so the ticket path cannot be exercised")
	return model.RawFinding{}
}

func osWriteFile(t *testing.T, path, body string) error {
	t.Helper()
	return os.WriteFile(path, []byte(body), 0o644)
}

func writeGoModFor(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	body := `module github.com/wanaware/api

go 1.24

require (
	github.com/wanaware/common v1.4.0
	golang.org/x/crypto v0.35.0
)

require golang.org/x/net v0.17.0 // indirect

replace github.com/wanaware/common => ../common
`
	if err := osWriteFile(t, dir+"/go.mod", body); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	return dir
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

var errTrackerDown = errTracker("503 service unavailable")

type errTracker string

func (e errTracker) Error() string { return string(e) }

// --- the censuses -------------------------------------------------------------

// storeCensus is one type's audit: where the values come from, the schema they
// must cover, and the reviewed exemptions with their producers named.
type storeCensus struct {
	name   string
	typ    reflect.Type
	sample func(t *testing.T, r storeRun) []any
	exempt map[audit.FieldPath]audit.Exemption
}

func storeCensuses(ctx context.Context) []storeCensus {
	return []storeCensus{
		{
			name: "store.Run",
			typ:  reflect.TypeOf(store.Run{}),
			sample: func(t *testing.T, r storeRun) []any {
				var out []any
				for _, id := range []string{r.RunID, r.SecondRunID} {
					run, err := r.Store.GetRun(ctx, id)
					if err != nil {
						t.Fatalf("GetRun: %v", err)
					}
					out = append(out, run)
				}
				return out
			},
		},
		{
			name: "store.RepoScanResult",
			typ:  reflect.TypeOf(store.RepoScanResult{}),
			exempt: map[audit.FieldPath]audit.Exemption{
				"EffectiveNuGuard.Reason": {
					Producer: "internal/nuguardopt.ResolveNuGuardOptions via orchestrator.ScanWorker",
					Why:      "written only when NuGuard is off for the scan; this run has it on, which the inventory and the AI-SBOM need",
				},
			},
			sample: func(t *testing.T, r storeRun) []any {
				var out []any
				names, err := r.Store.RepoNames(ctx)
				if err != nil {
					t.Fatalf("RepoNames: %v", err)
				}
				for _, name := range names {
					results, err := r.Store.ScanResults(ctx, name, 10)
					if err != nil {
						t.Fatalf("ScanResults: %v", err)
					}
					for _, res := range results {
						out = append(out, res)
					}
				}
				return out
			},
		},
		{
			name: "store.AISBOM",
			typ:  reflect.TypeOf(store.AISBOM{}),
			sample: func(t *testing.T, r storeRun) []any {
				var out []any
				for _, id := range []string{r.RunID, r.SecondRunID} {
					names, err := r.Store.RepoNames(ctx)
					if err != nil {
						t.Fatalf("RepoNames: %v", err)
					}
					for _, name := range names {
						if s, ok, err := r.Store.GetAISBOM(ctx, id, name); err != nil {
							t.Fatalf("GetAISBOM: %v", err)
						} else if ok {
							out = append(out, s)
						}
					}
				}
				return out
			},
			exempt: map[audit.FieldPath]audit.Exemption{
				"Withheld": {
					Producer: "internal/orchestrator.keepSBOM",
					Why:      "written only for an AI-SBOM over -nuguard-sbom-max-bytes; this one is under it",
				},
			},
		},
		{
			name: "store.PlanEntry",
			typ:  reflect.TypeOf(store.PlanEntry{}),
			sample: func(t *testing.T, r storeRun) []any {
				var out []any
				for _, id := range []string{r.RunID, r.SecondRunID} {
					entries, err := r.Store.PlanEntries(ctx, id)
					if err != nil {
						t.Fatalf("PlanEntries: %v", err)
					}
					for _, e := range entries {
						out = append(out, e)
					}
				}
				return out
			},
		},
		{
			name: "store.CoverageState",
			typ:  reflect.TypeOf(store.CoverageState{}),
			sample: func(t *testing.T, r storeRun) []any {
				names, err := r.Store.RepoNames(ctx)
				if err != nil {
					t.Fatalf("RepoNames: %v", err)
				}
				states, err := r.Store.FleetCoverage(ctx, store.KindSweep, names)
				if err != nil {
					t.Fatalf("FleetCoverage: %v", err)
				}
				var out []any
				for _, st := range states {
					out = append(out, st)
				}
				return out
			},
		},
		{
			name: "store.Escalation",
			typ:  reflect.TypeOf(store.Escalation{}),
			sample: func(t *testing.T, r storeRun) []any {
				names, err := r.Store.RepoNames(ctx)
				if err != nil {
					t.Fatalf("RepoNames: %v", err)
				}
				states, err := r.Store.FleetCoverage(ctx, store.KindSweep, names)
				if err != nil {
					t.Fatalf("FleetCoverage: %v", err)
				}
				var out []any
				for _, e := range store.Escalations(states, 1) {
					out = append(out, e)
				}
				return out
			},
		},
		{
			name: "store.ModuleDep",
			typ:  reflect.TypeOf(store.ModuleDep{}),
			sample: func(t *testing.T, r storeRun) []any {
				deps, err := r.Store.AllDeps(ctx)
				if err != nil {
					t.Fatalf("AllDeps: %v", err)
				}
				var out []any
				for _, d := range deps {
					out = append(out, d)
				}
				return out
			},
		},
		{
			name: "store.Ticket",
			typ:  reflect.TypeOf(store.Ticket{}),
			sample: func(t *testing.T, r storeRun) []any {
				var out []any
				for _, fp := range r.Fingers {
					tkt, ok, err := r.Store.GetTicket(ctx, fp)
					if err != nil {
						t.Fatalf("GetTicket: %v", err)
					}
					if ok {
						out = append(out, tkt)
					}
				}
				return out
			},
			exempt: map[audit.FieldPath]audit.Exemption{
				"MirrorBackend": {
					Producer: "internal/tracker.Mirror via tracker.Service",
					Why:      "written only where a secondary backend is configured (VM-F-803); none is in this run",
				},
				"MirrorRef": {Producer: "internal/tracker.Mirror via tracker.Service", Why: "as above"},
				"ClosedAt": {
					Producer: "internal/store.CloseTicket via tracker.Service.CloseVerified",
					Why:      "written when a finding verifies (VM-F-811); nothing verified in these two runs",
				},
				"Reopened": {
					Producer: "internal/tracker.Service.Reopen",
					Why:      "a write-only flag, never read back (VM-F-806)",
				},
			},
		},
		{
			name: "store.RunTicket",
			typ:  reflect.TypeOf(store.RunTicket{}),
			sample: func(t *testing.T, r storeRun) []any {
				var out []any
				for _, id := range []string{r.RunID, r.SecondRunID} {
					tkt, ok, err := r.Store.GetRunTicket(ctx, id)
					if err != nil {
						t.Fatalf("GetRunTicket: %v", err)
					}
					if ok {
						out = append(out, tkt)
					}
				}
				return out
			},
		},
		{
			name: "store.TicketOp",
			typ:  reflect.TypeOf(store.TicketOp{}),
			sample: func(t *testing.T, r storeRun) []any {
				ops, err := r.Store.DueTicketOps(ctx, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), 500)
				if err != nil {
					t.Fatalf("DueTicketOps: %v", err)
				}
				var out []any
				for _, op := range ops {
					out = append(out, op)
				}
				return out
			},
			exempt: map[audit.FieldPath]audit.Exemption{
				"Attempts": {
					Producer: "internal/store.RetryTicketOp via tracker.Service.Drain",
					Why:      "zero on first enqueue; incremented only by a drain that fails again",
				},
			},
		},
		{
			name: "store.RemediationPR",
			typ:  reflect.TypeOf(store.RemediationPR{}),
			sample: func(t *testing.T, r storeRun) []any {
				if r.Branch == "" {
					return nil
				}
				pr, ok, err := r.Store.GetRemediationPR(ctx, r.Branch)
				if err != nil {
					t.Fatalf("GetRemediationPR: %v", err)
				}
				if !ok {
					return nil
				}
				return []any{pr}
			},
			exempt: map[audit.FieldPath]audit.Exemption{
				"ClosedAt": {
					Producer: "internal/store.CloseRemediationPR via orchestrator.applyPRClosure",
					Why:      "written when the pull request closes; it is open at the end of this run",
				},
				"Merged": {
					Producer: "internal/store.CloseRemediationPR via orchestrator.applyPRClosure",
					Why:      "false while open; a boolean whose zero is indistinguishable from unwritten",
				},
				"TicketRef": {
					Producer: "internal/orchestrator.ensurePRTickets",
					Why: "the pull request's own ticket (VM-AD §13.3 row 2), written by the next " +
						"ticket pass: the pull request does not exist when this run's pass runs",
				},
				"TicketURL": {Producer: "internal/orchestrator.ensurePRTickets", Why: "as above"},
			},
		},
		{
			name: "store.WebhookHealth",
			typ:  reflect.TypeOf(store.WebhookHealth{}),
			sample: func(t *testing.T, r storeRun) []any {
				h, err := r.Store.WebhookHealth(ctx)
				if err != nil {
					t.Fatalf("WebhookHealth: %v", err)
				}
				return []any{h}
			},
		},
		{
			name: "store.RepoLock",
			typ:  reflect.TypeOf(store.RepoLock{}),
			sample: func(t *testing.T, r storeRun) []any {
				return []any{r.LockDuringAttempt}
			},
		},
		{
			name: "store.Lease",
			typ:  reflect.TypeOf(store.Lease{}),
			sample: func(t *testing.T, r storeRun) []any {
				return []any{r.LeaseDuringAttempt}
			},
		},
		{
			name: "store.CloseStats",
			typ:  reflect.TypeOf(store.CloseStats{}),
			sample: func(t *testing.T, r storeRun) []any {
				var out []any
				for _, c := range r.Close {
					out = append(out, c)
				}
				return out
			},
		},
		{
			name: "store.StalenessReport",
			typ:  reflect.TypeOf(store.StalenessReport{}),
			sample: func(t *testing.T, r storeRun) []any {
				names, err := r.Store.RepoNames(ctx)
				if err != nil {
					t.Fatalf("RepoNames: %v", err)
				}
				states, err := r.Store.FleetCoverage(ctx, store.KindSweep, names)
				if err != nil {
					t.Fatalf("FleetCoverage: %v", err)
				}
				return []any{store.Staleness(states, time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC))}
			},
		},
		{
			name: "store.Repo",
			typ:  reflect.TypeOf(store.Repo{}),
			sample: func(t *testing.T, r storeRun) []any {
				names, err := r.Store.RepoNames(ctx)
				if err != nil {
					t.Fatalf("RepoNames: %v", err)
				}
				var out []any
				for _, n := range names {
					repo, err := r.Store.GetRepo(ctx, n)
					if err != nil {
						t.Fatalf("GetRepo: %v", err)
					}
					out = append(out, repo)
				}
				return out
			},
			exempt: map[audit.FieldPath]audit.Exemption{
				"Archived": {
					Producer: "internal/orchestrator.SyncFleet",
					Why: "set when the fleet source stops listing a repository (VM-F-104); " +
						"nothing is archived in this run",
				},
				"HasLockfile": {
					Producer: "cmd/vfctl repo add -lockfile",
					Why: "false for every repository here: this fleet is all Go, and the flag " +
						"describes a JavaScript lockfile; cmd/vfctl's TestWhatVfctlRegistersIsWhatTheSweepScans " +
						"proves the write reaches the sweep's scan profile",
				},
			},
		},
		{
			name: "store.Report",
			typ:  reflect.TypeOf(store.Report{}),
			sample: func(t *testing.T, r storeRun) []any {
				reports, err := r.Store.ReportsForRun(ctx, r.SecondRunID)
				if err != nil {
					t.Fatalf("ReportsForRun: %v", err)
				}
				var out []any
				for _, rep := range reports {
					out = append(out, rep)
				}
				return out
			},
			exempt: map[audit.FieldPath]audit.Exemption{
				"Redacted": {
					Producer: "internal/report.Redact via report.Generate",
					Why:      "false for an unredacted report; a boolean whose zero is indistinguishable from unwritten",
				},
				"WithheldCount": {
					Producer: "internal/report.Redact via report.Generate",
					Why:      "zero when nothing was withheld",
				},
			},
		},
	}
}

// TestEveryStoreTypeFieldHasAProducer is OQ-AUDIT-04.
//
// One pipeline, thirteen types. A field nothing wrote is either a projection
// drop, a writer gap, or a field that should not exist — and the exemption
// naming its producer is what makes the third answer reviewable instead of
// convenient.
func TestEveryStoreTypeFieldHasAProducer(t *testing.T) {
	r := exerciseEveryStoreProducer(t)

	for _, c := range storeCensuses(context.Background()) {
		t.Run(c.name, func(t *testing.T) {
			samples := c.sample(t, r)
			if len(samples) == 0 {
				t.Fatalf("no %s was produced by a real pipeline run. A type nothing produces "+
					"cannot be audited, and an unaudited type is where the next unwritten field "+
					"will be (OQ-AUDIT-04)", c.name)
			}

			written := map[audit.FieldPath]bool{}
			for _, sample := range samples {
				for f := range audit.Populated(sample) {
					written[f] = true
				}
			}
			census := audit.Census{
				Schema: audit.Fields(c.typ), Written: written,
				Exempt: c.exempt,
			}
			if census.Exempt == nil {
				census.Exempt = map[audit.FieldPath]audit.Exemption{}
			}

			if un := census.Unwritten(); len(un) > 0 {
				t.Errorf("%d %s field(s) written by NO real producer:\n\n%s",
					len(un), c.name, census.Report())
			}
			if len(census.StaleExemptions()) > 0 {
				t.Errorf("%s: exemptions that are no longer true — the producer DOES write the "+
					"field, so the exemption is hiding nothing and must go:\n%s", c.name, census.Report())
			}
			if len(census.UnknownExemptions()) > 0 {
				t.Errorf("%s: exemptions naming fields the schema no longer has:\n%s", c.name, census.Report())
			}
			t.Logf("%s: %d fields, %d written, %d exempt",
				c.name, len(census.Schema), len(written), len(census.Exempt))
		})
	}
}
