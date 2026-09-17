package audit_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/audit"
	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/tracker"
	"github.com/wanaware/vulnframework/internal/triage"
)

// The Producer-Coverage Audit, layer two: what the FULL PIPELINE writes onto
// the finding the UI will read.
//
// This is the layer that matters most for the frontend. A field the pipeline
// never populates renders as an always-empty column, and an empty column looks
// exactly like a feature nobody has used yet — the Phase 6 bug arriving at the
// last layer, where it is hardest to see.
//
// Ground truth is a real run: real adapter output through the real store, the
// real triage, scoring and policy passes, and the real ticket and remediation
// producers. Nothing constructs a Finding.

var runAt = time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)

// pipelineOutput runs the whole pipeline and returns the findings as the
// interface would read them.
func pipelineOutput(t *testing.T) []model.Finding {
	t.Helper()
	ctx := context.Background()

	s := store.NewMemory()
	s.SetClock(func() time.Time { return runAt })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := store.Repo{
		Name: "org/wanaware-api", Tier: 1, Languages: []string{"go"},
		HasTestSuite: true, Codeowners: []string{"team-api"},
	}
	if err := s.UpsertRepo(ctx, repo); err != nil {
		t.Fatalf("upsert repo: %v", err)
	}

	// REAL adapter output, from the captured fixtures.
	raws := realAdapterOutput(t)
	// Re-homed onto the one repository so the whole pipeline applies.
	for i := range raws {
		raws[i].Repo = repo.Name
	}

	run, err := s.CreateRun(ctx, store.KindSweep, "cron", "img@sha256:abc",
		map[string]string{"govulncheck": "v1.8.0"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := s.RecordPlan(ctx, []store.PlanEntry{
		{RunID: run.ID, Repo: repo.Name, State: store.DispatchPlanned},
	}); err != nil {
		t.Fatalf("record plan: %v", err)
	}
	if _, err := s.UpsertObservations(ctx, run.ID, repo.Name, raws); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.RecordScanResult(ctx, store.RepoScanResult{
		RunID: run.ID, Repo: repo.Name, Outcome: model.ScanComplete,
		ToolsOK: []string{"govulncheck", "gosec", "gitleaks"},
	}); err != nil {
		t.Fatalf("scan result: %v", err)
	}
	if _, err := s.Reconcile(ctx, run.ID, repo.Name); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// The real triage, scoring and policy passes.
	cal, err := score.LoadCalibration("../../config/calibration.yaml")
	if err != nil {
		t.Fatalf("calibration: %v", err)
	}
	pol, err := policy.LoadConfig("../../config/policy.yaml")
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	o := orchestrator.New(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(500),
		orchestrator.Config{})
	o.Clock = func() time.Time { return runAt }

	tr := &triage.Triager{
		Client: triage.NewFakeClient(), Cache: triage.NewMemoryCache(),
		Model: "claude-sonnet-5", Clock: func() time.Time { return runAt },
	}
	if _, err := o.TriageAndRoute(ctx, repo, tr, score.New(cal), policy.New(pol), auditView{}); err != nil {
		t.Fatalf("TriageAndRoute: %v", err)
	}

	// The real ticket producer, so Refs.Ticket is written by what writes it in
	// production rather than by this test.
	fake := tracker.NewFake("github")
	svc := &tracker.Service{Tracker: fake, Store: s, Clock: func() time.Time { return runAt }}
	if _, err := o.TicketPass(ctx, orchestrator.TicketRequest{
		Repo: repo, RunID: run.ID, Service: svc, Policy: policy.New(pol),
		View: auditView{}, ReportURL: "https://reports.example/runs/" + run.ID + "/fleet.md",
	}); err != nil {
		t.Fatalf("TicketPass: %v", err)
	}

	// The real remediation pull request producer, for Refs.PullRequest.
	open, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeOpen, Repo: repo.Name})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(open) > 0 {
		if err := s.SaveRemediationPR(ctx, store.RemediationPR{
			Branch: "security/fix-audit", Repo: repo.Name, FixGroupID: "audit",
			Number: 1, URL: "https://github.com/org/wanaware-api/pull/1", State: "open",
			OpenedAt: runAt, Findings: []string{open[0].Fingerprint},
		}); err != nil {
			t.Fatalf("SaveRemediationPR: %v", err)
		}
	}
	// And the upstream reference, written by the first-party wave driver.
	for _, f := range open {
		if f.Classification.FirstPartyPath != nil {
			if err := s.SetUpstreamFinding(ctx, f.Fingerprint, "upstream-fp"); err != nil {
				t.Fatalf("SetUpstreamFinding: %v", err)
			}
			break
		}
	}

	all, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("the pipeline produced no findings; the audit would trivially pass")
	}
	return all
}

type auditView struct{}

func (auditView) HasOpenPullRequest(string) bool        { return false }
func (auditView) IsFirstPartyOwner(string, string) bool { return false }

// findingExemptions are the Finding fields the pipeline does not populate in
// this run, each naming what does.
var findingExemptions = map[audit.FieldPath]audit.Exemption{
	"Classification.FirstPartyPath": {
		Producer: "internal/firstparty.Registry.Classify",
		Why: "requires config/firstparty.yaml, which does not ship — populating it is an " +
			"organisational act. Covered end-to-end by internal/firstparty's scan-to-decision test",
	},
	"Classification.EPSS": {Producer: "nothing — VM-OQ-07 open", Why: "see OQ-AUDIT-01"},
	"Classification.KEV":  {Producer: "nothing — no KEV feed wired", Why: "see OQ-AUDIT-01"},
	"Classification.Transitive": {
		Producer: "internal/scan/adapters (govulncheck)",
		Why:      "boolean; its false value is indistinguishable from unwritten",
	},
	"Location.Function": {Producer: "nothing — no pinned tool reports it", Why: "see OQ-AUDIT-02"},
	"Location.Package":  {Producer: "nothing — no pinned tool reports it", Why: "see OQ-AUDIT-02"},
	"Refs.UpstreamFinding": {
		Producer: "internal/firstparty.Driver.ApplyWaveOne",
		Why:      "written only for a finding blocked upstream, which needs the first-party registry",
	},
	"Derived.GapRepoScan": {
		Producer: "internal/store.Reconcile",
		Why:      "written only when a scan did not complete; this run completed",
	},
	"Derived.NotReobserved": {
		Producer: "internal/store.Reconcile",
		Why:      "boolean, written false on a complete scan",
	},
	"Derived.SLABreachDays": {
		Producer: "internal/score.SLA via orchestrator.TriageAndRoute",
		Why:      "zero unless breached; these findings were detected in this run",
	},
	"Derived.AgeDays": {
		Producer: "internal/score.SLA",
		Why:      "zero for a finding first seen in this run",
	},
	"ResolvedAt": {
		Producer: "internal/store.Reconcile / ApplyTransition",
		Why:      "written on resolution; nothing resolved in this run",
	},
	"VerifiedReason": {
		Producer: "internal/store.Reconcile",
		Why:      "written on verification; nothing verified in this run",
	},
	"Derived.ResidualPossible": {
		Producer: "internal/store.PlanReconcile via model.ResidualWarning",
		Why: "written on verification (OQ-AUDIT-02); nothing verified in this run. Covered by " +
			"internal/store's residual clause across both backends",
	},
	"Derived.ResidualDetail": {
		Producer: "internal/store.PlanReconcile via model.ResidualWarning",
		Why:      "as above",
	},
	"Triage.FPReasoning": {
		Producer: "internal/triage",
		Why:      "written only for a false-positive candidate",
	},
	"Triage.FalsePositiveCandidate": {
		Producer: "internal/triage",
		Why:      "boolean, false for an ordinary finding",
	},
	"Provenance.ToolVersions": {
		Producer: "internal/store (run record)",
		Why: "recorded per RUN rather than per finding; the per-finding copy is unpopulated and " +
			"read by nothing — see OQ-AUDIT-03",
	},
}

// TestEveryFindingFieldHasAProducer is the audit at the layer the UI reads.
func TestEveryFindingFieldHasAProducer(t *testing.T) {
	findings := pipelineOutput(t)

	written := map[audit.FieldPath]bool{}
	for _, f := range findings {
		for path := range audit.Populated(f) {
			written[path] = true
		}
	}

	census := audit.Census{
		Schema:  audit.Fields(reflect.TypeOf(model.Finding{})),
		Written: written,
		Exempt:  findingExemptions,
	}

	if un := census.Unwritten(); len(un) > 0 {
		t.Errorf("%d Finding field(s) are never populated by a real pipeline run.\n\n"+
			"Each will render as an always-empty column in the interface, which looks exactly like a "+
			"feature nobody has used yet — the hardest place to notice this defect and the most "+
			"expensive to find.\n\n%s", len(un), census.Report())
	}
	if len(census.StaleExemptions()) > 0 {
		t.Errorf("exemptions that are no longer true:\n%s", census.Report())
	}
	if len(census.UnknownExemptions()) > 0 {
		t.Errorf("exemptions naming fields the schema no longer has:\n%s", census.Report())
	}
	t.Logf("Finding: %d fields, %d written by a real run, %d exempt",
		len(census.Schema), len(written), len(census.Exempt))
}

// TestFingerprintIsWrittenForEveryCategory is a targeted check on the one
// field whose absence would be catastrophic and silent: a finding with no
// fingerprint cannot be deduplicated, ticketed, leased or verified.
func TestFingerprintIsWrittenForEveryCategory(t *testing.T) {
	raws := realAdapterOutput(t)

	seen := map[model.Category]bool{}
	for _, raw := range raws {
		seen[raw.Category] = true
		if err := fingerprint.Validate(raw); err != nil {
			t.Errorf("%s finding from %s does not carry the inputs its fingerprint needs: %v",
				raw.Category, raw.Tool, err)
		}
		if fingerprint.Compute(raw) == "" {
			t.Errorf("%s finding from %s fingerprints to the empty string", raw.Category, raw.Tool)
		}
	}
	// Every category the tools actually produce must be represented, or the
	// check above passed by never meeting one.
	for _, c := range []model.Category{model.CategoryDependency, model.CategoryCode, model.CategorySecret} {
		if !seen[c] {
			t.Errorf("no real adapter produced a %s finding; the fingerprint check never met that "+
				"category and proves nothing about it", c)
		}
	}
}
