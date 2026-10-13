package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

const secretRepo = "org/api"

func secret(file string) model.RawFinding {
	return model.RawFinding{
		Repo: secretRepo, Category: model.CategorySecret,
		DetectorRuleID: "aws-access-token", Tool: "gitleaks", ToolVersion: "v8.30.1",
		File: file, Line: 3, CredentialType: "aws-access-token",
		Classification: model.Classification{
			Severity: model.SeverityCritical, Reachable: model.ReachableUnknown, DepClass: model.DepNotApplicable,
		},
	}
}

// scanOnce records one complete gitleaks scan of secretRepo.
func scanOnce(t *testing.T, st *store.Memory, observed []model.RawFinding, allowlisted map[string]model.Allowlist) {
	t.Helper()
	ctx := context.Background()
	r, err := st.CreateRun(ctx, store.KindSweep, "test", "img", nil)
	if err != nil {
		t.Fatal(err)
	}
	raws := append([]model.RawFinding{}, observed...)
	byFP := map[string]model.Allowlist{}
	for file, a := range allowlisted {
		raws = append(raws, secret(file))
		byFP[fingerprint.Compute(secret(file))] = a
	}
	var seen []string
	for _, o := range observed {
		seen = append(seen, fingerprint.Compute(o))
	}
	if len(raws) > 0 {
		if _, err := st.UpsertObservations(ctx, r.ID, secretRepo, raws); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.ApplyAllowlist(ctx, r.ID, secretRepo, byFP, seen); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordScanResult(ctx, store.RepoScanResult{RunID: r.ID, Repo: secretRepo, Outcome: model.ScanComplete, ToolsOK: []string{"gitleaks"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Reconcile(ctx, r.ID, secretRepo); err != nil {
		t.Fatal(err)
	}
}

func secretStore(t *testing.T) *store.Memory {
	t.Helper()
	st := store.NewMemory()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	mustExec(t, st, "repo", "add", secretRepo, "-languages", "go")
	currentUser = func() string { return "pat" }
	now = func() time.Time { return time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC) }
	return st
}

func TestFindingCommandsDecideAndRecordTheHuman(t *testing.T) {
	st := secretStore(t)
	ctx := context.Background()
	proposed := fingerprint.Compute(secret("testdata/fixture.yaml"))
	removed := fingerprint.Compute(secret("config/old.yaml"))

	scanOnce(t, st, []model.RawFinding{secret("config/old.yaml")}, nil)
	scanOnce(t, st, nil, map[string]model.Allowlist{
		"testdata/fixture.yaml": {Mechanism: model.AllowlistConfig, Path: ".gitleaks.toml", Description: "fixtures"},
	})

	out := mustExec(t, st, "finding", "pending")
	for _, want := range []string{proposed, "suppression pending", ".gitleaks.toml (fixtures)", removed, "rotation unconfirmed"} {
		if !strings.Contains(out, want) {
			t.Errorf("pending list lacks %q:\n%s", want, out)
		}
	}

	if out := mustExec(t, st, "finding", "confirm-suppression", proposed); !strings.Contains(out, "recorded as pat") {
		t.Errorf("confirm printed %q", out)
	}
	f, _ := st.GetFinding(ctx, proposed)
	if f.State != model.Suppressed || f.SuppressionProposal.DecidedBy != "pat" {
		t.Errorf("after confirm: %s, decided by %q", f.State, f.SuppressionProposal.DecidedBy)
	}

	if out := mustExec(t, st, "finding", "confirm-rotation", removed, "-as", "sam"); !strings.Contains(out, "sam") {
		t.Errorf("confirm-rotation printed %q", out)
	}
	f, _ = st.GetFinding(ctx, removed)
	if f.State != model.Verified || *f.VerifiedReason != model.VerifiedRotationConfirmed {
		t.Errorf("after rotation: %s, %v", f.State, f.VerifiedReason)
	}

	if out := mustExec(t, st, "finding", "pending"); !strings.Contains(out, "nothing is waiting") {
		t.Errorf("after both decisions, pending printed:\n%s", out)
	}
}

func TestFindingCommandsRefuseWhatTheyCannotDo(t *testing.T) {
	st := secretStore(t)
	live := fingerprint.Compute(secret("config/live.yaml"))
	scanOnce(t, st, []model.RawFinding{secret("config/live.yaml")}, nil)

	cases := map[string][]string{
		"rotation of a secret still in the files": {"finding", "confirm-rotation", live},
		"suppression with no proposal":            {"finding", "reject-suppression", live},
		"unknown fingerprint":                     {"finding", "confirm-suppression", "nope"},
		"no fingerprint":                          {"finding", "confirm-rotation"},
		"unknown subcommand":                      {"finding", "delete", live},
	}
	for name, args := range cases {
		if _, err := exec(t, st, args...); err == nil {
			t.Errorf("%s: vfctl %v succeeded", name, args)
		}
	}

	currentUser = func() string { return "" }
	if _, err := exec(t, st, "finding", "confirm-rotation", live); err == nil || !strings.Contains(err.Error(), "-as") {
		t.Errorf("with no identity: %v; a decision must be recorded against a person", err)
	}
}
