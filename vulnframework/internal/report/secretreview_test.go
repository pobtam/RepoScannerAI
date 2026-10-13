package report_test

import (
	"context"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/store"
)

// Secrets waiting on a human are figures in every report, never only rows in
// a finding list — and stated even when zero.
func TestReportsCountSecretsAwaitingAHuman(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		const repo = "org/api"
		if err := s.UpsertRepo(ctx, store.Repo{Name: repo, Tier: 1, Languages: []string{"go"}}); err != nil {
			t.Fatal(err)
		}
		secret := func(file string) model.RawFinding {
			return model.RawFinding{
				Repo: repo, Category: model.CategorySecret, DetectorRuleID: "aws-access-token",
				Tool: "gitleaks", ToolVersion: "v8.30.1", File: file, Line: 1, CredentialType: "aws-access-token",
				Classification: model.Classification{Severity: model.SeverityCritical,
					Reachable: model.ReachableUnknown, DepClass: model.DepNotApplicable},
			}
		}
		sweep := func(observed []model.RawFinding, allowlisted []string) string {
			r, err := s.CreateRun(ctx, store.KindSweep, "test", "img", nil)
			if err != nil {
				t.Fatal(err)
			}
			raws := append([]model.RawFinding{}, observed...)
			byFP := map[string]model.Allowlist{}
			for _, file := range allowlisted {
				raws = append(raws, secret(file))
				byFP[fingerprint.Compute(secret(file))] = model.Allowlist{Mechanism: model.AllowlistInline, Path: file}
			}
			var seen []string
			for _, o := range observed {
				seen = append(seen, fingerprint.Compute(o))
			}
			if _, err := s.UpsertObservations(ctx, r.ID, repo, raws); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ApplyAllowlist(ctx, r.ID, repo, byFP, seen); err != nil {
				t.Fatal(err)
			}
			if err := s.RecordScanResult(ctx, store.RepoScanResult{RunID: r.ID, Repo: repo, Outcome: model.ScanComplete, ToolsOK: []string{"gitleaks"}}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Reconcile(ctx, r.ID, repo); err != nil {
				t.Fatal(err)
			}
			if err := s.FinishRun(ctx, r.ID, 1, 1, 0); err != nil {
				t.Fatal(err)
			}
			return r.ID
		}

		gen := report.NewGenerator(s, calibration(t))
		generate := func(runID string) report.Report {
			rep, err := gen.Generate(ctx, report.Query{Kind: report.KindFleet, AnchorRun: runID, Scope: store.ScopeOpen, Template: "fleet.v1"})
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			return rep
		}

		first := sweep([]model.RawFinding{secret("config/old.yaml")}, nil)
		rendered := string(report.Render(generate(first)))
		for _, want := range []string{"Secret suppressions awaiting review:** 0 pending, 0 overdue", "Secrets removed, rotation unconfirmed:** 0"} {
			if !strings.Contains(rendered, want) {
				t.Errorf("a report with nothing waiting does not say so (%q)", want)
			}
		}

		second := sweep(nil, []string{"testdata/a.yaml", "testdata/b.yaml"})
		if err := s.EscalateProposal(ctx, fingerprint.Compute(secret("testdata/b.yaml")), base, "overdue"); err != nil {
			t.Fatal(err)
		}
		rep := generate(second)
		c := rep.Counts
		if c.SuppressionProposalsPending != 1 || c.SuppressionProposalsOverdue != 1 || c.SecretsRemovedRotationUnconfirmed != 1 {
			t.Fatalf("counts = pending %d, overdue %d, removed %d; want 1, 1, 1",
				c.SuppressionProposalsPending, c.SuppressionProposalsOverdue, c.SecretsRemovedRotationUnconfirmed)
		}
		rendered = string(report.Render(rep))
		for _, want := range []string{"1 pending, 1 overdue and escalated", "Secrets removed, rotation unconfirmed:** 1"} {
			if !strings.Contains(rendered, want) {
				t.Errorf("rendered report lacks %q", want)
			}
		}
	})
}
