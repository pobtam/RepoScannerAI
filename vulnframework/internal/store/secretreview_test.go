package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// Secrets are never closed by disappearing, and a repository allowlist is a
// proposal for a human, never a fix. These run on both backends.

func secretRaw(file string) model.RawFinding {
	return model.RawFinding{
		Repo: testRepo, Category: model.CategorySecret,
		DetectorRuleID: "aws-access-token", Tool: "gitleaks", ToolVersion: "v8.30.1",
		File: file, Line: 7, CredentialType: "aws-access-token",
		Classification: model.Classification{
			Severity: model.SeverityCritical, Reachable: model.ReachableUnknown,
			DepClass: model.DepNotApplicable,
		},
	}
}

var (
	tomlEvidence = model.Allowlist{
		Mechanism: model.AllowlistConfig, Path: ".gitleaks.toml",
		ConfigSHA256: "aaaa", Description: "test fixtures",
	}
	changedToml = model.Allowlist{
		Mechanism: model.AllowlistConfig, Path: ".gitleaks.toml",
		ConfigSHA256: "bbbb", Description: "test fixtures",
	}
)

// sweepSecret records one complete scan: observed are reported normally,
// allowlisted only past an allowlist.
func sweepSecret(t *testing.T, s store.Store, outcome store.ScanOutcome, observed []model.RawFinding, allowlisted map[string]model.Allowlist) string {
	t.Helper()
	ctx := context.Background()
	r := newRun(t, s, store.KindSweep)
	var raws []model.RawFinding
	raws = append(raws, observed...)
	for file := range allowlisted {
		raws = append(raws, secretRaw(file))
	}
	if len(raws) > 0 {
		mustUpsert(t, s, r.ID, raws...)
	}
	byFP := map[string]model.Allowlist{}
	for file, a := range allowlisted {
		byFP[fingerprint.Compute(secretRaw(file))] = a
	}
	var seen []string
	for _, o := range observed {
		seen = append(seen, fingerprint.Compute(o))
	}
	if _, err := s.ApplyAllowlist(ctx, r.ID, testRepo, byFP, seen); err != nil {
		t.Fatalf("ApplyAllowlist: %v", err)
	}
	scanned(t, s, r.ID, outcome, []string{"gitleaks"}, nil)
	if _, err := s.Reconcile(ctx, r.ID, testRepo); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return r.ID
}

func finding(t *testing.T, s store.Store, fp string) model.Finding {
	t.Helper()
	f, err := s.GetFinding(context.Background(), fp)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	return f
}

func lastCause(t *testing.T, s store.Store, fp string) model.StateTransition {
	t.Helper()
	ts, err := s.Transitions(context.Background(), fp)
	if err != nil || len(ts) == 0 {
		t.Fatalf("Transitions: %v (%d)", err, len(ts))
	}
	return ts[len(ts)-1]
}

func TestARemovedSecretStaysOpenUntilRotationIsConfirmed(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		seedRepo(t, s)
		ctx := context.Background()
		raw := secretRaw("config/settings.yaml")
		fp := fingerprint.Compute(raw)
		sweepSecret(t, s, model.ScanComplete, []model.RawFinding{raw}, nil)

		// Rotation cannot be confirmed for a secret still in the files.
		if err := s.ConfirmRotation(ctx, fp, "pat", time.Now()); err == nil {
			t.Fatal("confirmed rotation of a secret still in the files")
		}

		// A partial scan that misses it proves nothing.
		sweepSecret(t, s, model.ScanPartial, nil, nil)
		if f := finding(t, s, fp); f.RemovedUnrotated != nil {
			t.Fatalf("a partial scan recorded a removal: %+v", f.RemovedUnrotated)
		}

		// A complete scan that misses it records the removal and does NOT verify.
		removedRun := sweepSecret(t, s, model.ScanComplete, nil, nil)
		f := finding(t, s, fp)
		if model.PartitionOf(f.State) == model.PartitionResolved {
			t.Fatalf("a secret that left the files is %s; removal is not remediation (VM-F-856)", f.State)
		}
		if f.RemovedUnrotated == nil || f.RemovedUnrotated.Run != removedRun {
			t.Fatalf("RemovedUnrotated = %+v, want run %s", f.RemovedUnrotated, removedRun)
		}
		if !f.Derived.NotReobserved {
			t.Error("a removed secret is not flagged as not re-observed")
		}

		// Seen again: the removal is no longer true.
		sweepSecret(t, s, model.ScanComplete, []model.RawFinding{raw}, nil)
		if f := finding(t, s, fp); f.RemovedUnrotated != nil {
			t.Fatalf("a secret back in the files still reads as removed: %+v", f.RemovedUnrotated)
		}

		// Gone again, then a human attests rotation.
		sweepSecret(t, s, model.ScanComplete, nil, nil)
		if err := s.ConfirmRotation(ctx, fp, "", time.Now()); err == nil {
			t.Fatal("a rotation was recorded with nobody named")
		}
		if err := s.ConfirmRotation(ctx, fp, "pat", time.Now()); err != nil {
			t.Fatalf("ConfirmRotation: %v", err)
		}
		f = finding(t, s, fp)
		if f.State != model.Verified || f.VerifiedReason == nil || *f.VerifiedReason != model.VerifiedRotationConfirmed {
			t.Fatalf("after confirmation: state %s, reason %v; want VERIFIED by rotation_confirmed", f.State, f.VerifiedReason)
		}
		if f.RemovedUnrotated != nil {
			t.Error("a confirmed rotation still reads as unconfirmed")
		}
		if tr := lastCause(t, s, fp); tr.Actor != model.ActorHuman || !strings.Contains(tr.Cause, "pat") {
			t.Errorf("the verification is recorded as %s / %q; it must name the human", tr.Actor, tr.Cause)
		}
	})
}

func TestRotationIsOnlyForSecrets(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		seedRepo(t, s)
		r := newRun(t, s, store.KindSweep)
		mustUpsert(t, s, r.ID, cryptoFinding("govulncheck"))
		if err := s.ConfirmRotation(context.Background(), cryptoFP(), "pat", time.Now()); err == nil {
			t.Fatal("rotation was confirmed for a dependency finding")
		}
	})
}

func TestAnAllowlistedSecretIsAProposalThatComesBack(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		seedRepo(t, s)
		file := "testdata/fixture.yaml"
		fp := fingerprint.Compute(secretRaw(file))

		// First seen allowlisted: a proposal, with its evidence, awaiting a human.
		proposedRun := sweepSecret(t, s, model.ScanComplete, nil, map[string]model.Allowlist{file: tomlEvidence})
		f := finding(t, s, fp)
		if f.State != model.FPCandidate {
			t.Fatalf("an allowlisted secret is %s, want FALSE_POSITIVE_CANDIDATE", f.State)
		}
		p := f.SuppressionProposal
		if p == nil || p.Status != model.ProposalPending || p.Allowlist != tomlEvidence || p.ProposedRun != proposedRun {
			t.Fatalf("proposal = %+v", p)
		}
		if f.RemovedUnrotated != nil {
			t.Error("an allowlisted secret — still in the files — was recorded as removed")
		}
		if tr := lastCause(t, s, fp); !strings.Contains(tr.Cause, ".gitleaks.toml") || !strings.Contains(tr.Cause, proposedRun) {
			t.Errorf("the transition cause %q does not name the allowlist file and run", tr.Cause)
		}

		// Allowlisted again with the same evidence: nothing new.
		sweepSecret(t, s, model.ScanComplete, nil, map[string]model.Allowlist{file: tomlEvidence})
		if f := finding(t, s, fp); f.SuppressionProposal.ProposedRun != proposedRun {
			t.Error("an unchanged allowlist re-proposed")
		}

		// The allowlist entry is removed: the ordinary scan reports it again.
		withdrawnRun := sweepSecret(t, s, model.ScanComplete, []model.RawFinding{secretRaw(file)}, nil)
		f = finding(t, s, fp)
		if f.State != model.NeedsHuman {
			t.Fatalf("after the allowlist was withdrawn the secret is %s, want NEEDS_HUMAN", f.State)
		}
		if p := f.SuppressionProposal; p.Status != model.ProposalWithdrawn || p.WithdrawnRun != withdrawnRun {
			t.Errorf("proposal after withdrawal = %+v", p)
		}

		// Allowlisted once more: a fresh proposal.
		again := sweepSecret(t, s, model.ScanComplete, nil, map[string]model.Allowlist{file: tomlEvidence})
		if f := finding(t, s, fp); f.State != model.FPCandidate || f.SuppressionProposal.ProposedRun != again ||
			f.SuppressionProposal.Status != model.ProposalPending {
			t.Errorf("re-allowlisting: state %s, proposal %+v", f.State, f.SuppressionProposal)
		}
	})
}

func TestAConfirmedSuppressionIsUndoneWhenTheAllowlistIs(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		seedRepo(t, s)
		ctx := context.Background()
		file := "testdata/fixture.yaml"
		fp := fingerprint.Compute(secretRaw(file))
		sweepSecret(t, s, model.ScanComplete, nil, map[string]model.Allowlist{file: tomlEvidence})

		if err := s.DecideSuppression(ctx, fp, true, "", time.Now()); err == nil {
			t.Fatal("a suppression was confirmed with nobody named")
		}
		if err := s.DecideSuppression(ctx, fp, true, "pat", time.Now()); err != nil {
			t.Fatalf("confirm: %v", err)
		}
		f := finding(t, s, fp)
		if f.State != model.Suppressed || f.ResolvedAt == nil || f.SuppressionProposal.DecidedBy != "pat" ||
			f.SuppressionProposal.Status != model.ProposalConfirmed {
			t.Fatalf("after confirmation: state %s, resolved %v, proposal %+v", f.State, f.ResolvedAt, f.SuppressionProposal)
		}
		if err := s.DecideSuppression(ctx, fp, false, "pat", time.Now()); err == nil {
			t.Error("a decided proposal was decided again")
		}

		// Still allowlisted: stays suppressed. Allowlist removed: back.
		sweepSecret(t, s, model.ScanComplete, nil, map[string]model.Allowlist{file: tomlEvidence})
		if stateOf(t, s, fp) != model.Suppressed {
			t.Fatal("a confirmed suppression moved while the allowlist still held")
		}
		sweepSecret(t, s, model.ScanComplete, []model.RawFinding{secretRaw(file)}, nil)
		f = finding(t, s, fp)
		if f.State != model.NeedsHuman || f.ResolvedAt != nil {
			t.Fatalf("after the allowlist was removed: state %s, resolved %v; it must come back", f.State, f.ResolvedAt)
		}
	})
}

func TestARejectionHoldsUntilTheAllowlistChanges(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		seedRepo(t, s)
		file := "testdata/fixture.yaml"
		fp := fingerprint.Compute(secretRaw(file))
		sweepSecret(t, s, model.ScanComplete, nil, map[string]model.Allowlist{file: tomlEvidence})
		if err := s.DecideSuppression(context.Background(), fp, false, "pat", time.Now()); err != nil {
			t.Fatalf("reject: %v", err)
		}
		if f := finding(t, s, fp); f.State != model.Triaged || f.SuppressionProposal.Status != model.ProposalRejected {
			t.Fatalf("after rejection: state %s, proposal %+v", f.State, f.SuppressionProposal)
		}

		sweepSecret(t, s, model.ScanComplete, nil, map[string]model.Allowlist{file: tomlEvidence})
		if f := finding(t, s, fp); f.State == model.FPCandidate {
			t.Fatal("the same allowlist re-proposed a rejected suppression")
		}
		sweepSecret(t, s, model.ScanComplete, nil, map[string]model.Allowlist{file: changedToml})
		if f := finding(t, s, fp); f.State != model.FPCandidate || f.SuppressionProposal.Status != model.ProposalPending ||
			f.SuppressionProposal.ConfigSHA256 != "bbbb" {
			t.Fatalf("a changed allowlist did not re-propose: state %s, proposal %+v", f.State, f.SuppressionProposal)
		}
	})
}

func TestAnOverdueProposalEscalatesAndStaysDecidable(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		seedRepo(t, s)
		ctx := context.Background()
		file := "testdata/fixture.yaml"
		fp := fingerprint.Compute(secretRaw(file))
		sweepSecret(t, s, model.ScanComplete, nil, map[string]model.Allowlist{file: tomlEvidence})

		at := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
		if err := s.EscalateProposal(ctx, fp, at, "unreviewed past the window"); err != nil {
			t.Fatalf("EscalateProposal: %v", err)
		}
		f := finding(t, s, fp)
		if f.State != model.NeedsHuman || f.SuppressionProposal.Status != model.ProposalOverdue ||
			f.SuppressionProposal.EscalatedAt == nil || !f.SuppressionProposal.EscalatedAt.Equal(at) {
			t.Fatalf("after escalation: state %s, proposal %+v", f.State, f.SuppressionProposal)
		}
		if tr := lastCause(t, s, fp); tr.Actor != model.ActorOrchestrator {
			t.Errorf("escalation recorded as %s, want orchestrator", tr.Actor)
		}
		if err := s.EscalateProposal(ctx, fp, at, "again"); err == nil {
			t.Error("an overdue proposal escalated twice")
		}
		if err := s.DecideSuppression(ctx, fp, true, "pat", at); err != nil {
			t.Fatalf("an overdue proposal could not be confirmed: %v", err)
		}
		if stateOf(t, s, fp) != model.Suppressed {
			t.Error("confirming an overdue proposal did not suppress")
		}
	})
}

func TestAHumanSuppressionIsNotReopenedByAScanner(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		seedRepo(t, s)
		ctx := context.Background()
		raw := secretRaw("config/settings.yaml")
		fp := fingerprint.Compute(raw)
		sweepSecret(t, s, model.ScanComplete, []model.RawFinding{raw}, nil)
		// A triage nomination a human approved: no allowlist involved.
		for _, step := range []struct {
			to    model.State
			actor model.Actor
		}{{model.Triaged, model.ActorTriage}, {model.FPCandidate, model.ActorTriage}, {model.Suppressed, model.ActorHuman}} {
			if err := s.ApplyTransition(ctx, fp, step.to, model.TransitionContext{Actor: step.actor, Cause: "test", At: time.Now()}); err != nil {
				t.Fatalf("-> %s: %v", step.to, err)
			}
		}
		sweepSecret(t, s, model.ScanComplete, []model.RawFinding{raw}, nil)
		sweepSecret(t, s, model.ScanComplete, nil, map[string]model.Allowlist{"config/settings.yaml": tomlEvidence})
		if f := finding(t, s, fp); f.State != model.Suppressed || f.SuppressionProposal != nil {
			t.Fatalf("a human suppression became %s with proposal %+v", f.State, f.SuppressionProposal)
		}
	})
}
