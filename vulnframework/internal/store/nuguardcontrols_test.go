package store_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/nuguardopt"
	"github.com/wanaware/vulnframework/internal/store"
)

// Conformance for migration 0019: both backends store NuGuard's settings,
// overrides, audit, status, scan options and AI-SBOMs identically.

var ngT0 = time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)

func TestNuGuardFleetSettingsAreStoredAndAudited(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		if _, ok, err := s.NuGuardSettings(ctx); err != nil || ok {
			t.Fatalf("a fresh store has fleet settings (ok=%v, err=%v); never-set must read as never set", ok, err)
		}
		first := nuguardopt.Fleet{Enabled: true, Tools: []string{"nga-rules", "atlas"}, TimeoutS: 300}
		e1, err := s.SetNuGuardSettings(ctx, first, "alice", "", ngT0)
		if err != nil {
			t.Fatal(err)
		}
		if e1.Before != nil || e1.Scope != "fleet" || e1.ChangedBy != "alice" {
			t.Errorf("first change = %+v, want fleet, no before, by alice", e1)
		}
		second := nuguardopt.Fleet{Enabled: false, Tools: []string{"atlas"}, TimeoutS: 120}
		if _, err := s.SetNuGuardSettings(ctx, second, "bob", "AI rules too noisy this week", ngT0.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		rec, ok, err := s.NuGuardSettings(ctx)
		if err != nil || !ok {
			t.Fatalf("settings: ok=%v err=%v", ok, err)
		}
		if !reflect.DeepEqual(rec.Settings, second) || rec.ChangedBy != "bob" || !rec.ChangedAt.Equal(ngT0.Add(time.Hour)) {
			t.Errorf("settings = %+v, want the second, by bob", rec)
		}

		audit, err := s.NuGuardAudit(ctx, "", 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(audit) != 2 || audit[0].ChangedBy != "bob" || audit[0].Reason != "AI rules too noisy this week" {
			t.Fatalf("audit = %+v, want bob's change first, with its reason", audit)
		}
		var before, after nuguardopt.Fleet
		if err := json.Unmarshal(audit[0].Before, &before); err != nil || !reflect.DeepEqual(before, first) {
			t.Errorf("before = %s, want the first setting", audit[0].Before)
		}
		if err := json.Unmarshal(audit[0].After, &after); err != nil || !reflect.DeepEqual(after, second) {
			t.Errorf("after = %s, want the second setting", audit[0].After)
		}
		older, err := s.NuGuardAudit(ctx, "", audit[0].ID, 10)
		if err != nil || len(older) != 1 || older[0].ChangedBy != "alice" {
			t.Errorf("paging before %d = %+v, %v; want alice's change", audit[0].ID, older, err)
		}
		if n, err := s.CountNuGuardChanges(ctx, "bob", ngT0.Add(30*time.Minute)); err != nil || n != 1 {
			t.Errorf("bob's changes in the window = %d, %v; want 1", n, err)
		}
	})
}

func TestNuGuardRepoOverridesSetClearAndAudit(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		off := &nuguardopt.RepoOverride{Mode: nuguardopt.RepoOff}
		if _, err := s.SetNuGuardRepoOverride(ctx, "org/b", off, "alice", "", ngT0); err != nil {
			t.Fatal(err)
		}
		yes := true
		on := &nuguardopt.RepoOverride{Mode: nuguardopt.RepoOn, Tools: []string{"semgrep"}, IncludePosture: &yes}
		if _, err := s.SetNuGuardRepoOverride(ctx, "org/a", on, "alice", "pilot", ngT0); err != nil {
			t.Fatal(err)
		}
		rec, ok, err := s.NuGuardRepoOverride(ctx, "org/a")
		if err != nil || !ok || !reflect.DeepEqual(rec.Override, *on) {
			t.Fatalf("override of org/a = %+v, %v, %v", rec, ok, err)
		}
		all, err := s.NuGuardRepoOverrides(ctx)
		if err != nil || len(all) != 2 || all[0].Repo != "org/a" || all[1].Repo != "org/b" {
			t.Fatalf("overrides = %+v, %v; want org/a and org/b, by name", all, err)
		}

		// Inherit with nothing of its own is no override: the row goes, the
		// audit keeps what it was.
		e, err := s.SetNuGuardRepoOverride(ctx, "org/b", &nuguardopt.RepoOverride{Mode: nuguardopt.RepoInherit}, "bob", "back to fleet", ngT0.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if e.After != nil || e.Before == nil {
			t.Errorf("clearing = %+v, want a before and no after", e)
		}
		if _, ok, _ := s.NuGuardRepoOverride(ctx, "org/b"); ok {
			t.Error("org/b still has an override after it was cleared")
		}
		hist, err := s.NuGuardAudit(ctx, "org/b", 0, 10)
		if err != nil || len(hist) != 2 || hist[0].Reason != "back to fleet" || hist[0].Scope != "repository" {
			t.Errorf("org/b's history = %+v, %v", hist, err)
		}
	})
}

func TestNuGuardStatusRoundTrips(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		if _, ok, err := s.NuGuardStatus(ctx); err != nil || ok {
			t.Fatalf("a fresh store has a NuGuard status (ok=%v, err=%v)", ok, err)
		}
		st := store.NuGuardStatus{
			Configured: true, Reachable: true, CheckedAt: ngT0,
			ServiceVersion: "0.9.15", PinnedVersion: "0.9.15", VersionOK: true,
			ToolsAllowedByService: []string{"nga-rules", "atlas"},
			Ceiling: nuguardopt.Ceiling{Configured: true, AllowTools: []string{"atlas"}, AllowPosture: true, MaxTimeoutS: 600,
				Defaults: nuguardopt.Fleet{Enabled: true, Tools: []string{"atlas"}, TimeoutS: 600}},
		}
		if err := s.PutNuGuardStatus(ctx, st); err != nil {
			t.Fatal(err)
		}
		st.Reachable, st.LastError, st.CheckedAt = false, "nuguard: connection refused", ngT0.Add(5*time.Minute)
		if err := s.PutNuGuardStatus(ctx, st); err != nil {
			t.Fatal(err)
		}
		got, ok, err := s.NuGuardStatus(ctx)
		if err != nil || !ok || !reflect.DeepEqual(got, st) {
			t.Errorf("status = %+v (ok=%v, err=%v), want the latest %+v", got, ok, err, st)
		}
	})
}

func TestAScanRequestKeepsItsNuGuardOptions(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		no := false
		asked := &nuguardopt.Request{Mode: nuguardopt.RequestOn, Tools: []string{"atlas"}, IncludePosture: &no, KeepSBOM: true}
		r, _, err := s.EnqueueScan(ctx, store.ScanRequest{ID: "sr_1", Repo: "org/a", Source: store.SourceWeb,
			RequestedBy: "alice", RequestedAt: ngT0, Status: store.ScanQueued, NuGuard: asked})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.EnqueueScan(ctx, store.ScanRequest{ID: "sr_2", Repo: "org/b", Source: store.SourceWeb,
			RequestedBy: "alice", RequestedAt: ngT0, Status: store.ScanQueued}); err != nil {
			t.Fatal(err)
		}
		got, ok, err := s.GetScanRequest(ctx, r.ID)
		if err != nil || !ok || !reflect.DeepEqual(got.NuGuard, asked) {
			t.Errorf("request's NuGuard options = %+v, want %+v", got.NuGuard, asked)
		}
		plain, _, err := s.GetScanRequest(ctx, "sr_2")
		if err != nil || plain.NuGuard != nil {
			t.Errorf("a request that asked nothing reads back %+v; nil is today's behaviour", plain.NuGuard)
		}
		claimed, _, err := s.ClaimScans(ctx, "w1", ngT0)
		if err != nil || len(claimed) != 1 || !reflect.DeepEqual(claimed[0].NuGuard, asked) {
			t.Errorf("claimed = %+v, %v; the worker must see what was asked", claimed, err)
		}
	})
}

func TestAScanResultKeepsItsEffectiveNuGuardOptions(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		r := newRun(t, s, store.KindSweep)
		eff := &nuguardopt.Effective{Enabled: true, Tools: []string{"atlas"}, TimeoutS: 120, From: "repository",
			Clips:        []nuguardopt.ClipNote{{Field: "timeout_s", Asked: "600", Used: "120", Why: "above the operator's maximum"}},
			NotRequested: []nuguardopt.NotRequested{{Tool: "nuguard/semgrep", Reason: "not chosen"}}}
		res := store.RepoScanResult{RunID: r.ID, Repo: testRepo, Outcome: model.ScanComplete,
			ToolsOK: []string{"gosec", "nuguard", "nuguard/atlas"}, EffectiveNuGuard: eff,
			ToolsNotRequested: eff.NotRequested}
		if err := s.RecordScanResult(ctx, res); err != nil {
			t.Fatal(err)
		}
		got, err := s.ScanResults(ctx, testRepo, 1)
		if err != nil || len(got) != 1 {
			t.Fatalf("results = %+v, %v", got, err)
		}
		if !reflect.DeepEqual(got[0].EffectiveNuGuard, eff) || !reflect.DeepEqual(got[0].ToolsNotRequested, eff.NotRequested) {
			t.Errorf("read back %+v / %+v, want %+v", got[0].EffectiveNuGuard, got[0].ToolsNotRequested, eff)
		}

		r2 := newRun(t, s, store.KindSweep)
		if err := s.RecordScanResult(ctx, store.RepoScanResult{RunID: r2.ID, Repo: testRepo, Outcome: model.ScanComplete,
			ToolsOK: []string{"gosec"}}); err != nil {
			t.Fatal(err)
		}
		got, _ = s.ScanResults(ctx, testRepo, 1)
		if got[0].EffectiveNuGuard != nil || got[0].ToolsNotRequested != nil {
			t.Errorf("a scan with no NuGuard options reads back %+v / %+v; want nil (not recorded)",
				got[0].EffectiveNuGuard, got[0].ToolsNotRequested)
		}
	})
}

func TestAnAISBOMIsKeptOrWithheldWithAReason(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		r := newRun(t, s, store.KindSweep)
		doc := json.RawMessage(`{"components":[{"name":"openai","type":"model-provider"}]}`)
		kept := store.AISBOM{RunID: r.ID, Repo: testRepo, CommitSHA: "5d0c7e9", NuGuardVersion: "0.9.15",
			SizeBytes: int64(len(doc)), SHA256: "abc", Document: doc, StoredAt: ngT0}
		if err := s.PutAISBOM(ctx, kept); err != nil {
			t.Fatal(err)
		}
		got, ok, err := s.GetAISBOM(ctx, r.ID, testRepo)
		if err != nil || !ok {
			t.Fatalf("get: ok=%v err=%v", ok, err)
		}
		var a, b any
		_ = json.Unmarshal(got.Document, &a)
		_ = json.Unmarshal(doc, &b)
		if !reflect.DeepEqual(a, b) || got.SHA256 != "abc" || got.Withheld != "" {
			t.Errorf("kept = %+v", got)
		}

		r2 := newRun(t, s, store.KindSweep)
		if err := s.PutAISBOM(ctx, store.AISBOM{RunID: r2.ID, Repo: testRepo, CommitSHA: "5d0c7e9", NuGuardVersion: "0.9.15",
			SizeBytes: 9 << 20, SHA256: "def", Withheld: "9437184 bytes, over the 4194304-byte cap", StoredAt: ngT0}); err != nil {
			t.Fatal(err)
		}
		got, ok, _ = s.GetAISBOM(ctx, r2.ID, testRepo)
		if !ok || got.Document != nil || got.Withheld == "" {
			t.Errorf("withheld = %+v, want no document and the reason", got)
		}
		if err := s.PutAISBOM(ctx, store.AISBOM{RunID: r2.ID, Repo: testRepo, StoredAt: ngT0}); err == nil {
			t.Error("an AI-SBOM with neither a document nor a reason was accepted")
		}
		if _, ok, _ := s.GetAISBOM(ctx, "S-999999", testRepo); ok {
			t.Error("an AI-SBOM for a run that kept none")
		}
	})
}
