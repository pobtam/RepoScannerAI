package orchestrator_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/store"
)

// A scan's commit and AI inventory reach the store, and a scan without an
// inventory stores none (not an empty one).
func TestRecordKeepsTheCommitAndTheInventory(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/agent", "org/plain")
		commit := "5d0c7e9a1b2c3d4e5f60718293a4b5c6d7e8f901"
		d := orchestrator.NewFakeDispatcher()
		d.Results["org/agent"] = scan.Result{
			Outcome: model.ScanComplete, ToolsOK: []string{"nuguard"}, CommitSHA: commit,
			AIInventory: &scan.AIInventory{Source: "nuguard 0.9.15", NodeCounts: map[string]int{"AGENT": 1},
				Frameworks: []string{}, ModelProviders: []string{"openai"}},
		}
		d.Results["org/plain"] = scan.Result{Outcome: model.ScanComplete, ToolsOK: []string{"gosec"}}
		o := newOrchestrator(s, d, orchestrator.NewRateBudget(10), orchestrator.Config{MaxConcurrentScans: 1, CreditsPerScan: 1})
		if _, err := o.Sweep(ctx, store.KindSweep, "test", repos, orchestrator.DefaultSelector); err != nil {
			t.Fatal(err)
		}

		agent, _ := s.ScanResults(ctx, "org/agent", 1)
		if len(agent) != 1 || agent[0].CommitSHA != commit {
			t.Fatalf("org/agent: %+v", agent)
		}
		var inv scan.AIInventory
		if err := json.Unmarshal(agent[0].AIInventory, &inv); err != nil || inv.Source != "nuguard 0.9.15" || inv.NodeCounts["AGENT"] != 1 {
			t.Errorf("inventory %s: %v", agent[0].AIInventory, err)
		}
		plain, _ := s.ScanResults(ctx, "org/plain", 1)
		if len(plain) != 1 || plain[0].AIInventory != nil || plain[0].CommitSHA != "" {
			t.Errorf("org/plain: %+v", plain)
		}
	})
}
