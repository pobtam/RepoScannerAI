package api_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/api"
	"github.com/wanaware/vulnframework/internal/store"
)

// The AI inventory is said to be "not measured" where no scan reported one,
// never shown as zero; where one did, it is shown with what produced it, and
// labelled as a signal rather than findings.
func TestAIComponentsAreMeasuredOrSaidNotToBe(t *testing.T) {
	h := newHarness(t)
	const repo = "org/api"

	var before api.RepoDetail
	h.getJSON(t, "/v1/repos/"+repo, &before)
	ai := before.AIComponents
	if ai.Measured || !strings.Contains(ai.Note, "not measured") || ai.NodeCounts != nil || ai.EdgeCount != nil {
		t.Errorf("with no inventory recorded: %+v", ai)
	}

	ctx := context.Background()
	run, err := h.Store.CreateRun(ctx, store.KindSweep, "test", "img", nil)
	if err != nil {
		t.Fatal(err)
	}
	commit := "5d0c7e9a1b2c3d4e5f60718293a4b5c6d7e8f901"
	if err := h.Store.RecordScanResult(ctx, store.RepoScanResult{
		RunID: run.ID, Repo: repo, Outcome: "complete", CommitSHA: commit,
		AIInventory: json.RawMessage(`{"source":"nuguard 0.9.15","rulepack_sha256":"397f","node_counts":{"AGENT":1,"MODEL":2},` +
			`"edge_count":0,"frameworks":["LangChain"],"model_providers":["openai"],"posture_observations":{"NGA-001":3}}`),
	}); err != nil {
		t.Fatal(err)
	}

	var after api.RepoDetail
	h.getJSON(t, "/v1/repos/"+repo, &after)
	ai = after.AIComponents
	if !ai.Measured || ai.RunID != run.ID || ai.Source != "nuguard 0.9.15" || ai.NodeCounts["MODEL"] != 2 ||
		ai.EdgeCount == nil || *ai.EdgeCount != 0 || ai.PostureObservations["NGA-001"] != 3 ||
		!strings.Contains(ai.Note, "not findings") {
		t.Errorf("with an inventory recorded: %+v", ai)
	}
	if after.Repo.LastCommitSHA != commit {
		t.Errorf("last commit %q", after.Repo.LastCommitSHA)
	}
}
