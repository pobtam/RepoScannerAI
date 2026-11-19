package store_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/wanaware/vulnframework/internal/store"
)

// A scan result keeps the commit it read and the AI inventory it found, and
// an absent inventory stays absent ("not measured"), on both backends.
func TestScanResultsKeepTheirCommitAndInventory(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		inv := json.RawMessage(`{"source":"nuguard 0.9.15","node_counts":{"AGENT":2},"edge_count":3,` +
			`"frameworks":["LangChain.js"],"model_providers":["openai"]}`)
		measured := newRun(t, s, store.KindSweep)
		if err := s.RecordScanResult(ctx, store.RepoScanResult{
			RunID: measured.ID, Repo: testRepo, Outcome: "complete",
			CommitSHA: "5d0c7e9a1b2c3d4e5f60718293a4b5c6d7e8f901", AIInventory: inv,
		}); err != nil {
			t.Fatal(err)
		}
		unmeasured := newRun(t, s, store.KindSweep)
		if err := s.RecordScanResult(ctx, store.RepoScanResult{
			RunID: unmeasured.ID, Repo: testRepo, Outcome: "complete", AIInventory: json.RawMessage("null"),
		}); err != nil {
			t.Fatal(err)
		}

		got, err := s.ScanResults(ctx, testRepo, 10)
		if err != nil || len(got) != 2 {
			t.Fatalf("ScanResults: %v %+v", err, got)
		}
		byRun := map[string]store.RepoScanResult{got[0].RunID: got[0], got[1].RunID: got[1]}

		m := byRun[measured.ID]
		if m.CommitSHA != "5d0c7e9a1b2c3d4e5f60718293a4b5c6d7e8f901" {
			t.Errorf("commit %q", m.CommitSHA)
		}
		var want, have any
		_ = json.Unmarshal(inv, &want)
		if err := json.Unmarshal(m.AIInventory, &have); err != nil || !reflect.DeepEqual(want, have) {
			t.Errorf("inventory %s, want %s", m.AIInventory, inv)
		}

		u := byRun[unmeasured.ID]
		if u.CommitSHA != "" || u.AIInventory != nil {
			t.Errorf("an unmeasured scan came back as %+v; absent must stay absent", u)
		}
	})
}
