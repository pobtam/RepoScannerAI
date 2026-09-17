package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// OQ-AUDIT-02's required condition: a VERIFIED that can hide a live same-file
// twin must not pass silently.
//
// File granularity is the chosen behaviour, and the risk it carries is not
// eliminated by choosing it — it is made answerable. A code or secret finding
// verifies when a successful scan stops reporting it, and at file granularity
// "stops reporting it" can mean the reported occurrence was fixed while
// another in the same file was not flagged, or was flagged as the same
// finding.
//
// This is absence-is-not-resolution one level down: VM-ADR-12 asks whether the
// scan looked, and this asks whether what the scan looked AT was one thing.

func TestVerifyingAFileGranularFindingFlagsAPossibleResidual(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)

		code := model.RawFinding{
			Repo: testRepo, Category: model.CategoryCode,
			RuleID: "G404", Tool: "gosec", ToolVersion: "v2.22.9",
			File: "internal/token/token.go", Line: 13,
			Classification: model.Classification{
				Severity: model.SeverityHigh, Reachable: model.ReachableUnknown,
				DepClass: model.DepNotApplicable,
			},
		}

		r1 := newRun(t, s, store.KindSweep)
		if _, err := s.UpsertObservations(ctx, r1.ID, testRepo, []model.RawFinding{code}); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		fp := fingerprintOf(code)
		if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{
			Actor: model.ActorTriage, Cause: "test",
		}); err != nil {
			t.Fatalf("triage: %v", err)
		}
		scanned(t, s, r1.ID, model.ScanComplete, []string{"gosec"}, nil)

		// A later successful scan no longer reports it.
		r2 := newRun(t, s, store.KindSweep)
		scanned(t, s, r2.ID, model.ScanComplete, []string{"gosec"}, nil)
		stats, err := s.Reconcile(ctx, r2.ID, testRepo)
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if stats.Verified != 1 {
			t.Fatalf("verified = %d, want 1", stats.Verified)
		}

		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		if f.State != model.Verified {
			t.Fatalf("state = %s, want VERIFIED", f.State)
		}

		// THE REQUIRED CONDITION.
		if !f.Derived.ResidualPossible {
			t.Fatal("a file-granular finding verified with no residual flag. Two occurrences of one " +
				"rule in one file are ONE finding, so this VERIFIED can be hiding a live twin — and " +
				"nothing downstream would say so (OQ-AUDIT-02)")
		}
		if f.Derived.ResidualDetail == "" {
			t.Error("the residual flag carries no explanation; a reader cannot act on a boolean")
		}
		for _, want := range []string{"file", "same"} {
			if !strings.Contains(strings.ToLower(f.Derived.ResidualDetail), want) {
				t.Errorf("the residual detail does not mention %q: %q", want, f.Derived.ResidualDetail)
			}
		}
	})
}

// TestVerifyingAModuleGranularFindingDoesNotFlagAResidual is the negative
// half, and it is what stops the flag becoming noise.
//
// A dependency finding is located to a module and major version. The module
// either resolves to the fixed version or it does not; there is no second
// occurrence to hide. A flag on every verification would be filtered out
// within a week, taking the real ones with it.
func TestVerifyingAModuleGranularFindingDoesNotFlagAResidual(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		fp := cryptoFP()

		r1 := newRun(t, s, store.KindSweep)
		mustUpsert(t, s, r1.ID, cryptoFinding("govulncheck"))
		if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{
			Actor: model.ActorTriage, Cause: "test",
		}); err != nil {
			t.Fatalf("triage: %v", err)
		}
		scanned(t, s, r1.ID, model.ScanComplete, []string{"govulncheck"}, nil)

		r2 := newRun(t, s, store.KindSweep)
		scanned(t, s, r2.ID, model.ScanComplete, []string{"govulncheck"}, nil)
		if _, err := s.Reconcile(ctx, r2.ID, testRepo); err != nil {
			t.Fatalf("reconcile: %v", err)
		}

		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		if f.State != model.Verified {
			t.Fatalf("state = %s, want VERIFIED", f.State)
		}
		if f.Derived.ResidualPossible {
			t.Error("a module-granular verification flagged a possible residual. The module either " +
				"resolves to the fixed version or it does not, and a flag on every verification is " +
				"filtered out within a week — taking the real ones with it")
		}
	})
}

func fingerprintOf(raw model.RawFinding) string { return fingerprint.Compute(raw) }
