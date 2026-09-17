package report_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/store/storetest"
)

// Phase 7 gate:
//
//	reports are verified against GROUND TRUTH in the store, not against a
//	  convenience projection — a projection that drops a field must fail the
//	  report test, not silently under-report;
//	a secret's value never appears in any report artifact, in any field;
//	the uncalibrated-threshold caveat surfaces in report OUTPUT;
//	same-kind deltas and coverage trending come from real run history, and gaps
//	  are represented honestly, never folded into "clean";
//	reports are run-anchored, immutable, content-hashed, and store their query.

// --- harness ----------------------------------------------------------------

type backend struct {
	name string
	open func(t *testing.T) store.Store
}

func backends(t *testing.T) []backend {
	t.Helper()
	out := []backend{{
		name: "memory",
		open: func(t *testing.T) store.Store {
			s := store.NewMemory()
			s.SetClock(clock())
			if err := s.Migrate(context.Background()); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			return s
		},
	}}
	if os.Getenv(storetest.EnvDSN) == "" {
		return out
	}
	out = append(out, backend{
		name: "postgres",
		open: func(t *testing.T) store.Store {
			t.Helper()
			db := storetest.OpenDB(t, "report")
			ctx := context.Background()
			if err := store.NewPostgres(db).MigrateTo(ctx, 0); err != nil {
				t.Fatalf("reset: %v", err)
			}
			s := store.NewPostgres(db)
			s.SetClock(clock())
			if err := s.Migrate(ctx); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			return s
		},
	})
	return out
}

func run(t *testing.T, fn func(t *testing.T, s store.Store)) {
	t.Helper()
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) { fn(t, b.open(t)) })
	}
}

var base = time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)

func clock() func() time.Time {
	var mu sync.Mutex
	n := 0
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		n++
		return base.Add(time.Duration(n) * time.Second)
	}
}

func calibration(t *testing.T) score.Calibration {
	t.Helper()
	c, err := score.LoadCalibration("../../config/calibration.yaml")
	if err != nil {
		t.Fatalf("calibration: %v", err)
	}
	return c
}

func dep(repo, advisory string) model.RawFinding {
	return model.RawFinding{
		Repo: repo, Category: model.CategoryDependency,
		PrimaryID: advisory, Tool: "govulncheck", ToolVersion: "v1.8.0",
		Module: "golang.org/x/crypto", ModuleMajor: "v0",
		Versions: model.Versions{Current: "v0.16.0", Fixed: "v0.36.0"},
		Classification: model.Classification{
			Severity: model.SeverityHigh, CVSS: 7.5, Reachable: model.ReachableTrue,
			DepClass: model.DepProduction,
		},
	}
}

// fixture builds a fleet with findings, coverage gaps and a completed run.
type fixture struct {
	runID string
	repos []string
}

func seed(t *testing.T, s store.Store, kind store.RunKind, raws []model.RawFinding, outcomes map[string]model.ScanOutcome) fixture {
	t.Helper()
	ctx := context.Background()

	repos := map[string]bool{}
	for r := range outcomes {
		repos[r] = true
	}
	var names []string
	for r := range repos {
		names = append(names, r)
		if err := s.UpsertRepo(ctx, store.Repo{
			Name: r, Tier: 2, Languages: []string{"go"}, HasTestSuite: true,
		}); err != nil {
			t.Fatalf("upsert repo: %v", err)
		}
	}

	r, err := s.CreateRun(ctx, kind, "cron", "img@sha256:abc", map[string]string{"govulncheck": "v1.8.0"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	var plan []store.PlanEntry
	for name := range repos {
		plan = append(plan, store.PlanEntry{RunID: r.ID, Repo: name, State: store.DispatchPlanned})
	}
	if err := s.RecordPlan(ctx, plan); err != nil {
		t.Fatalf("record plan: %v", err)
	}

	byRepo := map[string][]model.RawFinding{}
	for _, raw := range raws {
		byRepo[raw.Repo] = append(byRepo[raw.Repo], raw)
	}
	for name, outcome := range outcomes {
		if len(byRepo[name]) > 0 {
			if _, err := s.UpsertObservations(ctx, r.ID, name, byRepo[name]); err != nil {
				t.Fatalf("upsert observations: %v", err)
			}
		}
		if err := s.MarkDispatched(ctx, r.ID, name); err != nil {
			t.Fatalf("mark dispatched: %v", err)
		}
		cause := ""
		if !outcome.Succeeded() {
			cause = "build_failure"
		}
		if err := s.RecordScanResult(ctx, store.RepoScanResult{
			RunID: r.ID, Repo: name, Outcome: outcome,
			ToolsOK: []string{"govulncheck"}, FailureCause: cause, FailureOwner: "repo",
		}); err != nil {
			t.Fatalf("record scan result: %v", err)
		}
	}

	if _, err := s.CloseRun(ctx, r.ID); err != nil {
		t.Fatalf("close run: %v", err)
	}
	for name := range repos {
		if _, err := s.Reconcile(ctx, r.ID, name); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
	if err := s.FinishRun(ctx, r.ID, len(repos), len(repos), 0); err != nil {
		t.Fatalf("finish run: %v", err)
	}
	return fixture{runID: r.ID, repos: names}
}

func generate(t *testing.T, s store.Store, runID string) report.Report {
	t.Helper()
	g := report.NewGenerator(s, calibration(t))
	g.Clock = func() time.Time { return base }
	rep, err := g.Generate(context.Background(), report.Query{
		Kind: report.KindFleet, AnchorRun: runID, Scope: store.ScopeAll, Template: "fleet.v1",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return rep
}

// --- Gate: reports are verified against GROUND TRUTH -----------------------

// TestReportMatchesStoreGroundTruth is the gate's first clause, and the
// generalisation of the Phase 6 projection lesson.
//
// Every field the store holds for a finding is compared against what the report
// rendered for it. The comparison is driven by reflection over the report row
// rather than a hand-written list, so a field added to the row without being
// populated from the store fails here — and a field the store's own projection
// drops fails here too, instead of silently under-reporting.
func TestReportMatchesStoreGroundTruth(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()

		// A finding of every category, so every field in the row is exercised
		// by something.
		fpPath := "github.com/org/common"
		firstParty := dep("org/a", "GO-2025-0001")
		firstParty.Classification.FirstPartyPath = &fpPath

		code := model.RawFinding{
			Repo: "org/a", Category: model.CategoryCode, Tool: "gosec", ToolVersion: "v2.29.0",
			RuleID: "G404", File: "internal/token/token.go", Line: 42,
			Classification: model.Classification{
				Severity: model.SeverityMedium, Reachable: model.ReachableTrue,
				DepClass: model.DepNotApplicable,
			},
		}
		secret := model.RawFinding{
			Repo: "org/a", Category: model.CategorySecret, Tool: "gitleaks", ToolVersion: "v8.30.1",
			DetectorRuleID: "aws-access-token", File: "config/settings.yaml", Line: 17,
			CredentialType: "aws-access-token",
			Classification: model.Classification{
				Severity: model.SeverityCritical, Reachable: model.ReachableUnknown,
				DepClass: model.DepNotApplicable,
			},
		}

		f := seed(t, s, store.KindSweep,
			[]model.RawFinding{firstParty, code, secret},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})

		rep := generate(t, s, f.runID)

		// Ground truth, read independently of the report.
		truth, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
		if err != nil {
			t.Fatalf("list findings: %v", err)
		}
		if len(truth) == 0 {
			t.Fatal("no findings in the store; the comparison would be vacuous")
		}
		if len(rep.Findings) != len(truth) {
			t.Fatalf("report holds %d findings, the store holds %d", len(rep.Findings), len(truth))
		}

		byFP := map[string]report.FindingRow{}
		for _, row := range rep.Findings {
			byFP[row.Fingerprint] = row
		}

		for _, want := range truth {
			got, ok := byFP[want.Fingerprint]
			if !ok {
				t.Errorf("finding %s is in the store but not in the report", want.Fingerprint)
				continue
			}
			// The expected row, built directly from the store record.
			expected := rowFromStore(want)

			gv, ev := reflect.ValueOf(got), reflect.ValueOf(expected)
			typ := gv.Type()
			for i := 0; i < typ.NumField(); i++ {
				name := typ.Field(i).Name
				a, b := gv.Field(i).Interface(), ev.Field(i).Interface()
				if !reflect.DeepEqual(a, b) {
					t.Errorf("%s: report field %s = %v, store ground truth = %v",
						want.Fingerprint, name, a, b)
				}
			}
		}
	})
}

// TestReportReflectsScannerInputNotOnlyStoreProjection is the sharper form of
// the ground-truth clause, and the one that actually implements the standing
// note: an invariant is only real if its input survives every projection
// between scan and decision.
//
// Comparing the report against the store is necessary but NOT sufficient: the
// store is itself a projection, so a field the store drops is missing from both
// sides and they agree. This asserts against what was *scanned* — the raw
// findings written in — so a drop anywhere between the scanner and the rendered
// report fails here.
//
// The Phase 6 bug was exactly a store-level drop of FirstPartyPath. Reverting
// that fix must fail this test.
func TestReportReflectsScannerInputNotOnlyStoreProjection(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		fpPath := "github.com/org/common"
		firstParty := dep("org/a", "GO-2025-0001")
		firstParty.Classification.FirstPartyPath = &fpPath
		firstParty.Classification.Reachable = model.ReachableFalse
		firstParty.Classification.DepClass = model.DepDevelopment

		plain := dep("org/a", "GO-2025-0002")
		plain.Module = "golang.org/x/net"

		// A code finding, so the file/line half of the location is covered too:
		// module and file travel by different paths through the projection.
		code := model.RawFinding{
			Repo: "org/a", Category: model.CategoryCode, Tool: "gosec", ToolVersion: "v2.29.0",
			RuleID: "G404", File: "internal/token/token.go", Line: 42,
			Classification: model.Classification{
				Severity: model.SeverityMedium, Reachable: model.ReachableTrue,
				DepClass: model.DepNotApplicable,
			},
		}

		f := seed(t, s, store.KindSweep, []model.RawFinding{firstParty, plain, code},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})

		rep := generate(t, s, f.runID)
		byFP := map[string]report.FindingRow{}
		for _, row := range rep.Findings {
			byFP[row.Fingerprint] = row
		}

		// What the scanner reported, stated independently of anything the store
		// or the report did with it.
		type expectation struct {
			raw   model.RawFinding
			check func(t *testing.T, row report.FindingRow, raw model.RawFinding)
		}
		expectations := []expectation{
			{firstParty, func(t *testing.T, row report.FindingRow, raw model.RawFinding) {
				// The field the Phase 6 bug dropped.
				if row.FirstPartyPath != *raw.Classification.FirstPartyPath {
					t.Errorf("first_party_path = %q, scanner reported %q — the value did not survive the projections between scan and report",
						row.FirstPartyPath, *raw.Classification.FirstPartyPath)
				}
			}},
			{firstParty, func(t *testing.T, row report.FindingRow, raw model.RawFinding) {
				if row.Reachable != string(raw.Classification.Reachable) {
					t.Errorf("reachable = %q, scanner reported %q", row.Reachable, raw.Classification.Reachable)
				}
			}},
			{firstParty, func(t *testing.T, row report.FindingRow, raw model.RawFinding) {
				if row.DepClass != string(raw.Classification.DepClass) {
					t.Errorf("dep_class = %q, scanner reported %q", row.DepClass, raw.Classification.DepClass)
				}
			}},
			{plain, func(t *testing.T, row report.FindingRow, raw model.RawFinding) {
				if row.Module != raw.Module {
					t.Errorf("module = %q, scanner reported %q", row.Module, raw.Module)
				}
				if row.FixedVersion != raw.Versions.Fixed {
					t.Errorf("fixed_version = %q, scanner reported %q", row.FixedVersion, raw.Versions.Fixed)
				}
				if row.PrimaryID != raw.PrimaryID {
					t.Errorf("primary_id = %q, scanner reported %q", row.PrimaryID, raw.PrimaryID)
				}
				if len(row.Tools) == 0 || row.Tools[0] != raw.Tool {
					t.Errorf("tools = %v, scanner was %q", row.Tools, raw.Tool)
				}
			}},
			{code, func(t *testing.T, row report.FindingRow, raw model.RawFinding) {
				if row.File != raw.File {
					t.Errorf("file = %q, scanner reported %q — the location did not survive the projections between scan and report",
						row.File, raw.File)
				}
				if row.Category != string(raw.Category) {
					t.Errorf("category = %q, scanner reported %q", row.Category, raw.Category)
				}
			}},
		}

		for i, e := range expectations {
			fp := fingerprint.Compute(e.raw)
			row, ok := byFP[fp]
			if !ok {
				t.Fatalf("expectation %d: finding %s is missing from the report entirely", i, fp)
			}
			e.check(t, row, e.raw)
		}
	})
}

// rowFromStore is the expected report row for a stored finding.
//
// Written out field by field on purpose: it is an independent statement of what
// the report should contain, so it fails when the generator's own projection
// diverges from the store rather than agreeing with it by construction.
func rowFromStore(f model.Finding) report.FindingRow {
	row := report.FindingRow{
		Fingerprint:    f.Fingerprint,
		Repo:           f.Repo,
		Category:       string(f.Category),
		PrimaryID:      f.Identity.PrimaryID,
		Module:         f.Location.Module,
		State:          string(f.State),
		Priority:       string(f.Priority),
		Severity:       string(f.Classification.Severity),
		Reachable:      string(f.Classification.Reachable),
		DepClass:       string(f.Classification.DepClass),
		Tools:          f.Provenance.Tools,
		FixedVersion:   f.Versions.Fixed,
		CredentialType: f.CredentialType,
		NotReobserved:  f.Derived.NotReobserved,
		SLAStatus:      string(f.Derived.SLAStatus),
	}
	if f.Location.File != nil {
		row.File = *f.Location.File
	}
	if f.Classification.FirstPartyPath != nil {
		row.FirstPartyPath = *f.Classification.FirstPartyPath
	}
	if f.ReasonCode != nil {
		row.ReasonCode = string(*f.ReasonCode)
	}
	if f.VerifiedReason != nil {
		row.VerifiedReason = string(*f.VerifiedReason)
	}
	if f.Derived.GapRepoScan != nil {
		row.GapRun = *f.Derived.GapRepoScan
	}
	return row
}

// TestReportCountsMatchStoreGroundTruth checks the aggregates the same way: a
// count is recomputed from the store and compared, so a partition the report
// gets wrong cannot hide behind a plausible-looking total.
func TestReportCountsMatchStoreGroundTruth(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		var raws []model.RawFinding
		for i := 0; i < 6; i++ {
			raws = append(raws, dep("org/a", fmt.Sprintf("GO-2025-%04d", i)))
		}
		f := seed(t, s, store.KindSweep, raws, map[string]model.ScanOutcome{"org/a": model.ScanComplete})

		// Move one to MERGED so the three partitions are all exercised.
		fp := fingerprint.Compute(raws[0])
		for _, to := range []model.State{model.Triaged, model.AutoRemediating, model.PROpen, model.Merged} {
			actor := model.ActorOrchestrator
			if to == model.Triaged {
				actor = model.ActorTriage
			}
			if to == model.PROpen {
				actor = model.ActorWorker
			}
			if err := s.ApplyTransition(ctx, fp, to, model.TransitionContext{Actor: actor, Cause: "test"}); err != nil {
				t.Fatalf("transition: %v", err)
			}
		}

		rep := generate(t, s, f.runID)
		truth, _ := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})

		var unresolved, pending, resolved int
		byState := map[string]int{}
		for _, g := range truth {
			switch model.PartitionOf(g.State) {
			case model.PartitionResolved:
				resolved++
			case model.PartitionPendingVerification:
				pending++
			default:
				unresolved++
			}
			byState[string(g.State)]++
		}

		if rep.Counts.Total != len(truth) {
			t.Errorf("total = %d, store holds %d", rep.Counts.Total, len(truth))
		}
		if rep.Counts.Unresolved != unresolved {
			t.Errorf("unresolved = %d, want %d", rep.Counts.Unresolved, unresolved)
		}
		// MERGED is its own line and is never folded into either side
		// (VM-F-159).
		if rep.Counts.PendingVerification != pending || pending != 1 {
			t.Errorf("pending_verification = %d, want %d (and the fixture should produce 1)", rep.Counts.PendingVerification, pending)
		}
		if rep.Counts.Resolved != resolved {
			t.Errorf("resolved = %d, want %d", rep.Counts.Resolved, resolved)
		}
		if !reflect.DeepEqual(rep.Counts.ByState, byState) {
			t.Errorf("by_state = %v, want %v", rep.Counts.ByState, byState)
		}
	})
}

// --- Gate: no secret value reaches any artifact ----------------------------

// TestPlantedSecretNeverReachesAnyArtifact is the output-boundary guard.
//
// The credential is injected into the two fields most likely to carry it by
// accident — a triage narrative that quoted the matched line, and a file path —
// and the report must refuse to publish rather than render it. Failing is the
// right behaviour: a silent scrub would hide that credential material reached
// the output boundary at all, which is the defect worth knowing about.
func TestPlantedSecretNeverReachesAnyArtifact(t *testing.T) {
	const planted = "REDACTED-FAKE-AWS-KEY-ID"

	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		secret := model.RawFinding{
			Repo: "org/a", Category: model.CategorySecret, Tool: "gitleaks", ToolVersion: "v8.30.1",
			DetectorRuleID: "aws-access-token", File: "config/settings.yaml", Line: 17,
			CredentialType: "aws-access-token",
			Classification: model.Classification{
				Severity: model.SeverityCritical, Reachable: model.ReachableUnknown,
				DepClass: model.DepNotApplicable,
			},
		}
		f := seed(t, s, store.KindSweep, []model.RawFinding{secret},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})
		fp := fingerprint.Compute(secret)

		// The clean path publishes fine and contains no credential.
		clean := generate(t, s, f.runID)
		issued, err := report.Issue(clean)
		if err != nil {
			t.Fatalf("a clean report failed to issue: %v", err)
		}
		for name, body := range map[string][]byte{"fleet.json": issued.JSON, "fleet.md": issued.Markdown} {
			if strings.Contains(string(body), planted) {
				t.Errorf("%s contains the planted credential", name)
			}
		}

		// Now inject the credential through a triage narrative — the realistic
		// route, a model quoting the matched line back.
		if err := s.SetTriage(ctx, fp, model.Triage{
			Description: "A credential was found.",
			Impact:      "The key " + planted + " grants access to the account.",
			Remediation: "Rotate it.",
		}); err != nil {
			t.Fatalf("set triage: %v", err)
		}

		// The report row does not carry the narrative, so this must still be
		// clean — but the guard is what proves it rather than the shape of the
		// struct.
		withNarrative := generate(t, s, f.runID)
		issued2, err := report.Issue(withNarrative)
		if err == nil {
			for name, body := range map[string][]byte{"fleet.json": issued2.JSON, "fleet.md": issued2.Markdown} {
				if strings.Contains(string(body), planted) {
					t.Fatalf("%s rendered a credential from the triage narrative (VM-F-263)", name)
				}
			}
		}
	})
}

// TestIssueRefusesCredentialMaterialInAnyField drives the guard directly across
// every field of the report, so the protection is not specific to the one route
// the fixture happens to exercise.
func TestIssueRefusesCredentialMaterialInAnyField(t *testing.T) {
	credentials := []string{
		"REDACTED-FAKE-AWS-KEY-ID",
		"REDACTED-FAKE-GITHUB-TOKEN",
		"REDACTED-FAKE-GITLAB-TOKEN",
		"REDACTED-FAKE-SLACK-TOKEN",
		"-----BEGIN RSA PRIVATE KEY-----",
	}

	fields := []struct {
		name string
		set  func(*report.Report, string)
	}{
		{"a finding's file path", func(r *report.Report, v string) { r.Findings[0].File = v }},
		{"a finding's identifier", func(r *report.Report, v string) { r.Findings[0].PrimaryID = v }},
		{"a finding's module", func(r *report.Report, v string) { r.Findings[0].Module = v }},
		{"the credential type", func(r *report.Report, v string) { r.Findings[0].CredentialType = v }},
		{"a provenance caveat", func(r *report.Report, v string) { r.Provenance.Caveats = append(r.Provenance.Caveats, v) }},
		{"the repository name", func(r *report.Report, v string) { r.Repo = v }},
		{"an unscanned repository", func(r *report.Report, v string) { r.Coverage.UnscannedRepos = append(r.Coverage.UnscannedRepos, v) }},
	}

	for _, cred := range credentials {
		for _, fld := range fields {
			t.Run(fld.name+"/"+cred[:8], func(t *testing.T) {
				rep := report.Report{
					Kind: report.KindFleet, AnchorRun: "S-000001",
					Findings: []report.FindingRow{{Fingerprint: "fp", Repo: "org/a", Category: "secret", State: "NEEDS_HUMAN"}},
				}
				fld.set(&rep, cred)

				_, err := report.Issue(rep)
				if err == nil {
					t.Fatalf("a report carrying %q in %s was issued; a secret's value must never be written to a report, in any field (VM-F-263)",
						cred[:8]+"...", fld.name)
				}
				var credErr *report.ErrCredentialInReport
				if !errorsAs(err, &credErr) {
					t.Errorf("got %T, want *ErrCredentialInReport", err)
				}
			})
		}
	}
}

func errorsAs(err error, target **report.ErrCredentialInReport) bool {
	for err != nil {
		if e, ok := err.(*report.ErrCredentialInReport); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// --- Gate: the uncalibrated caveat surfaces in OUTPUT ----------------------

// TestUncalibratedThresholdCaveatSurfacesInOutput covers the OQ-P5-02
// constraint. A P0 that looks confident while resting on uncalibrated
// thresholds hides its own provenance, and the reader has no way to know the
// number is provisional.
func TestUncalibratedThresholdCaveatSurfacesInOutput(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		f := seed(t, s, store.KindSweep, []model.RawFinding{dep("org/a", "GO-2025-0001")},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})

		cal := calibration(t)
		if cal.StaticAnalysis.Calibrated {
			t.Skip("thresholds are calibrated; the caveat is no longer expected")
		}

		rep := generate(t, s, f.runID)
		issued, err := report.Issue(rep)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}

		// In the authoritative document, as structured data.
		if rep.Provenance.ThresholdsCalibrated {
			t.Error("the report claims calibrated thresholds while the calibration says otherwise")
		}
		if len(rep.Provenance.Caveats) == 0 {
			t.Fatal("no caveat recorded on the report")
		}

		// And in the rendered output, which is what a human reads.
		md := string(issued.Markdown)
		for _, want := range []string{"calibrat", "VM-OQ-06", "provisional"} {
			if !strings.Contains(strings.ToLower(md), strings.ToLower(want)) {
				t.Errorf("the rendered report does not mention %q; the caveat must be in OUTPUT, not only in config (OQ-P5-02)", want)
			}
		}
		// It must appear before the numbers, not in a footnote after them.
		caveatAt := strings.Index(strings.ToLower(md), "caveat")
		headlineAt := strings.Index(md, "## Headline")
		if caveatAt < 0 || (headlineAt >= 0 && caveatAt > headlineAt) {
			t.Error("the caveat appears after the headline; a reader who stops at the numbers must still have seen it")
		}

		// The JSON carries it too, so a machine consumer cannot miss it.
		var decoded map[string]any
		if err := json.Unmarshal(issued.JSON, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		prov, _ := decoded["provenance"].(map[string]any)
		if prov == nil || prov["thresholds_calibrated"] != false {
			t.Errorf("provenance.thresholds_calibrated is not false in the JSON: %v", prov)
		}
	})
}

func TestCalibratedThresholdsDropTheCaveat(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		f := seed(t, s, store.KindSweep, []model.RawFinding{dep("org/a", "GO-2025-0001")},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})

		cal := calibration(t)
		cal.StaticAnalysis.Calibrated = true
		cal.FanOut.Enabled = true
		cal.SLA.Calibrated = true

		g := report.NewGenerator(s, cal)
		// The enrichment feeds are wired in this scenario too, so the
		// scoring-input caveat clears with the others. It is a separate,
		// deployment-level fact (OQ-AUDIT-01) rather than a calibration flag,
		// and it must be able to clear or it is decoration.
		g.UnavailableScoringInputs = nil
		g.Clock = func() time.Time { return base }
		rep, err := g.Generate(context.Background(), report.Query{
			Kind: report.KindFleet, AnchorRun: f.runID, Scope: store.ScopeAll, Template: "fleet.v1",
		})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if !rep.Provenance.ThresholdsCalibrated {
			t.Error("thresholds_calibrated is false with a calibrated configuration")
		}
		if len(rep.Provenance.Caveats) != 0 {
			t.Errorf("caveats remain once calibrated: %v", rep.Provenance.Caveats)
		}
	})
}

// --- Gate: coverage gaps are honest, never folded into clean ---------------

// TestCoverageGapsAreNotFoldedIntoClean is the honesty clause. Every gap cause
// is carried separately, because a repository deferred for budget, one whose
// build failed, one never dispatched and one whose worker died are four
// different problems with four different remedies.
func TestCoverageGapsAreNotFoldedIntoClean(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()

		f := seed(t, s, store.KindSweep,
			[]model.RawFinding{dep("org/ok", "GO-2025-0001"), dep("org/partial", "GO-2025-0002")},
			map[string]model.ScanOutcome{
				"org/ok":      model.ScanComplete,
				"org/partial": model.ScanPartial,
				"org/failed":  model.ScanFailed,
			})

		// Plus a repository that was planned and deferred for budget, which
		// run close records as not_dispatched.
		if err := s.UpsertRepo(ctx, store.Repo{Name: "org/deferred", Tier: 3, Languages: []string{"go"}}); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if err := s.RecordPlan(ctx, []store.PlanEntry{
			{RunID: f.runID, Repo: "org/deferred", State: store.DispatchPlanned},
		}); err != nil {
			t.Fatalf("record plan: %v", err)
		}
		if err := s.MarkSkipped(ctx, f.runID, "org/deferred", store.SkipBudgetExhausted); err != nil {
			t.Fatalf("mark skipped: %v", err)
		}
		if _, err := s.CloseRun(ctx, f.runID); err != nil {
			t.Fatalf("close: %v", err)
		}

		rep := generate(t, s, f.runID)
		c := rep.Coverage

		if c.InScope != 4 {
			t.Fatalf("in_scope = %d, want 4", c.InScope)
		}
		if c.Complete != 1 {
			t.Errorf("complete = %d, want 1", c.Complete)
		}
		if c.Partial != 1 || c.Failed != 1 || c.NotDispatched != 1 {
			t.Errorf("partial=%d failed=%d not_dispatched=%d, want 1/1/1", c.Partial, c.Failed, c.NotDispatched)
		}
		// The percentage is complete over in-scope: a partial scan is not
		// coverage, any more than it verifies a finding.
		if c.Percent != 25 {
			t.Errorf("percent = %.1f, want 25 — only a complete scan counts as coverage", c.Percent)
		}
		// Each cause is carried separately, not summed.
		if len(c.ByCause) < 2 {
			t.Errorf("by_cause = %v, want the causes carried separately", c.ByCause)
		}
		if c.ByCause[store.SkipBudgetExhausted] != 1 {
			t.Errorf("budget deferral not recorded as its own cause: %v", c.ByCause)
		}
		// And the uncovered repositories are named, not merely counted — an
		// audit attestation needs the names.
		if len(c.UnscannedRepos) != 3 {
			t.Errorf("unscanned_repos = %v, want three named", c.UnscannedRepos)
		}

		// The rendered output must say all of it.
		issued, err := report.Issue(rep)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		md := string(issued.Markdown)
		for _, want := range []string{"org/failed", "org/deferred", "budget_exhausted", "Not dispatched"} {
			if !strings.Contains(md, want) {
				t.Errorf("the rendered report does not mention %q", want)
			}
		}
	})
}

// TestNotReobservedIsReportedNotResolved covers the other half of the honesty
// clause: absence is not resolution, in the report as in the store.
func TestNotReobservedIsReportedNotResolved(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		raw := dep("org/a", "GO-2025-0001")
		first := seed(t, s, store.KindSweep, []model.RawFinding{raw},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})
		_ = first

		// A second run whose scan failed and did not observe it.
		r2, err := s.CreateRun(ctx, store.KindSweep, "cron", "img", nil)
		if err != nil {
			t.Fatalf("create run: %v", err)
		}
		if err := s.RecordPlan(ctx, []store.PlanEntry{{RunID: r2.ID, Repo: "org/a", State: store.DispatchPlanned}}); err != nil {
			t.Fatalf("plan: %v", err)
		}
		if err := s.MarkDispatched(ctx, r2.ID, "org/a"); err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		if err := s.RecordScanResult(ctx, store.RepoScanResult{
			RunID: r2.ID, Repo: "org/a", Outcome: model.ScanFailed,
			FailureCause: "clone_timeout", FailureOwner: "platform",
		}); err != nil {
			t.Fatalf("scan result: %v", err)
		}
		if _, err := s.CloseRun(ctx, r2.ID); err != nil {
			t.Fatalf("close: %v", err)
		}
		if _, err := s.Reconcile(ctx, r2.ID, "org/a"); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if err := s.FinishRun(ctx, r2.ID, 1, 0, 1); err != nil {
			t.Fatalf("finish: %v", err)
		}

		rep := generate(t, s, r2.ID)
		if rep.Counts.NotReobserved != 1 {
			t.Errorf("not_reobserved = %d, want 1", rep.Counts.NotReobserved)
		}
		if rep.Counts.Resolved != 0 {
			t.Errorf("resolved = %d; a finding absent from a failed scan is not resolved (VM-ADR-12)", rep.Counts.Resolved)
		}

		issued, _ := report.Issue(rep)
		if !strings.Contains(string(issued.Markdown), "absence is not resolution") {
			t.Error("the rendered report does not explain that not-re-observed findings are retained, not resolved")
		}
	})
}

// --- Gate: same-kind deltas from real run history --------------------------

func TestDeltasCompareTheSameRunKind(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		a := dep("org/a", "GO-2025-0001")
		b := dep("org/a", "GO-2025-0002")
		b.Module = "golang.org/x/net"

		// Sweep 1: one finding.
		first := seed(t, s, store.KindSweep, []model.RawFinding{a},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})
		rep1 := generate(t, s, first.runID)
		if rep1.Delta.Comparable {
			t.Error("the first run of a kind reported a delta; there is nothing to compare against")
		}

		// An advisory run in between, with a different finding set. It must not
		// become the comparison basis for the next sweep.
		seed(t, s, store.KindAdvisory, []model.RawFinding{a, b},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})

		// Sweep 2: two findings.
		second := seed(t, s, store.KindSweep, []model.RawFinding{a, b},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})
		rep2 := generate(t, s, second.runID)

		if !rep2.Delta.Comparable {
			t.Fatal("the second sweep found no previous sweep to compare against")
		}
		if rep2.Delta.PreviousRun != first.runID {
			t.Errorf("compared against %s, want the previous run of the same kind %s — "+
				"comparing a sweep against an advisory rescan produces a delta that looks like a catastrophe or a miracle, and is neither",
				rep2.Delta.PreviousRun, first.runID)
		}
		if rep2.Delta.New != 1 {
			t.Errorf("new = %d, want 1", rep2.Delta.New)
		}
		if rep2.Delta.TotalChange != 1 {
			t.Errorf("total_change = %d, want 1", rep2.Delta.TotalChange)
		}
	})
}

// --- Gate: VM-ADR-15 — anchored, immutable, hashed, stores its query -------

func TestReportIsAnchoredHashedAndStoresItsQuery(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		f := seed(t, s, store.KindSweep, []model.RawFinding{dep("org/a", "GO-2025-0001")},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})

		rep := generate(t, s, f.runID)
		issued, err := report.Issue(rep)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}

		if issued.Report.AnchorRun != f.runID {
			t.Errorf("anchor = %q, want %q", issued.Report.AnchorRun, f.runID)
		}
		if issued.Hash == "" || len(issued.Hash) != 64 {
			t.Errorf("content hash = %q, want a sha256 hex digest", issued.Hash)
		}
		if issued.Report.Query.AnchorRun != f.runID || issued.Report.Query.Scope != store.ScopeAll {
			t.Errorf("the query was not stored on the report: %+v", issued.Report.Query)
		}

		// Regenerating from the stored query reproduces the same content hash.
		g := report.NewGenerator(s, calibration(t))
		g.Clock = func() time.Time { return base }
		again, err := g.Generate(ctx, issued.Report.Query)
		if err != nil {
			t.Fatalf("regenerate: %v", err)
		}
		reissued, err := report.Issue(again)
		if err != nil {
			t.Fatalf("re-issue: %v", err)
		}
		if reissued.Hash != issued.Hash {
			t.Errorf("regenerating from the stored query gave hash %s, want %s — "+
				"a report that cannot be regenerated cannot be cited or verified (VM-ADR-15)",
				reissued.Hash, issued.Hash)
		}

		// Persisting is idempotent, and changing the content under the same
		// identifier is refused.
		rec := store.Report{
			ID: issued.Report.ID, AnchorRunID: f.runID, Kind: string(report.KindFleet),
			Template: "fleet.v1", Query: mustJSON(t, issued.Report.Query),
			ContentHash: issued.Hash, Content: issued.JSON, IssuedAt: base,
		}
		if err := s.SaveReport(ctx, rec); err != nil {
			t.Fatalf("save: %v", err)
		}
		if err := s.SaveReport(ctx, rec); err != nil {
			t.Errorf("re-saving identical content is not idempotent: %v", err)
		}

		tampered := rec
		tampered.ContentHash = strings.Repeat("0", 64)
		if err := s.SaveReport(ctx, tampered); err == nil {
			t.Error("a report was mutated under its own identifier; reports are immutable (VM-ADR-15)")
		}

		got, err := s.GetReport(ctx, rec.ID)
		if err != nil {
			t.Fatalf("get report: %v", err)
		}
		if got.ContentHash != issued.Hash {
			t.Errorf("stored hash = %q, want %q", got.ContentHash, issued.Hash)
		}
	})
}

func TestLiveStateCannotBeReported(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		g := report.NewGenerator(s, calibration(t))

		// No anchor at all.
		if _, err := g.Generate(ctx, report.Query{Kind: report.KindFleet, Scope: store.ScopeAll}); err == nil {
			t.Error("a report with no anchor was generated; reports anchor to a completed run (VM-ADR-15)")
		}

		// An anchor that has not finished.
		r, err := s.CreateRun(ctx, store.KindSweep, "cron", "img", nil)
		if err != nil {
			t.Fatalf("create run: %v", err)
		}
		_, err = g.Generate(ctx, report.Query{Kind: report.KindFleet, AnchorRun: r.ID, Scope: store.ScopeAll})
		if err == nil {
			t.Error("a report anchored to an unfinished run was generated; the most recent anchor is the latest completed run")
		}
	})
}

func TestPublishedLayoutMatchesTheSpecification(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		f := seed(t, s, store.KindSweep, []model.RawFinding{dep("org/a", "GO-2025-0001")},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})

		fleet, err := report.Issue(generate(t, s, f.runID))
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}

		g := report.NewGenerator(s, calibration(t))
		g.Clock = func() time.Time { return base }
		perRepo, err := g.Generate(ctx, report.Query{
			Kind: report.KindRepo, AnchorRun: f.runID, Repo: "org/a",
			Scope: store.ScopeAll, Template: "repo.v1",
		})
		if err != nil {
			t.Fatalf("per-repo: %v", err)
		}
		repoIssued, err := report.Issue(perRepo)
		if err != nil {
			t.Fatalf("Issue per-repo: %v", err)
		}

		pub := report.NewFakePublisher()
		if err := report.PublishRun(ctx, pub, fleet, []report.Issued{repoIssued}); err != nil {
			t.Fatalf("publish: %v", err)
		}

		want := []string{
			"latest.json",
			"runs/" + f.runID + "/fleet.json",
			"runs/" + f.runID + "/fleet.md",
			"runs/" + f.runID + "/repos/org__a.json",
			"runs/" + f.runID + "/repos/org__a.md",
		}
		got := pub.Paths()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("published %v, want %v", got, want)
		}

		// The per-repository report is produced by the same generator, not a
		// bespoke path (VM-AD §17 Phase 7).
		if perRepo.Query.Template != "repo.v1" || perRepo.Repo != "org/a" {
			t.Errorf("per-repo report was not produced from a query: %+v", perRepo.Query)
		}

		// No artifact carries credential material.
		for path, body := range pub.All() {
			if err := report.AssertNoCredentials(path, body); err != nil {
				t.Errorf("%s: %v", path, err)
			}
		}
	})
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

var _ = sql.ErrNoRows
