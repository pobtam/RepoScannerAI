package api_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/api"
	"github.com/wanaware/vulnframework/internal/store"
)

func TestGitHubViewShowsTheAccountAndEveryDecision(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	var empty api.GitHubView
	h.getJSON(t, "/v1/github", &empty)
	if len(empty.Connections) != 0 || empty.Summary.LastDiscoveredAt != nil {
		t.Errorf("before any connection: %+v", empty)
	}

	exp := apiNow.Add(10 * 24 * time.Hour)
	if err := h.Store.SaveGitHubConnection(ctx, store.GitHubConnection{
		Account: "octo", Kind: "fine_grained", ExpiresAt: &exp, ReadOnly: "fine-grained; GET only",
		CheckedAt: apiNow, CheckedBy: "pat",
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.Store.ReplaceDiscovery(ctx, "octo", []store.DiscoveredRepo{
		{Name: "octo/api", Account: "octo", Affiliation: "owner", SizeKB: 10, DefaultBranch: "main", Included: true, DiscoveredAt: apiNow},
		{Name: "octo/fork", Account: "octo", Affiliation: "owner", Fork: true, SizeKB: 10, DefaultBranch: "main",
			Reason: "fork", Detail: "a fork; opt in with -include-forks", DiscoveredAt: apiNow},
	}); err != nil {
		t.Fatal(err)
	}

	var v api.GitHubView
	h.getJSON(t, "/v1/github", &v)
	if len(v.Connections) != 1 || v.Connections[0].ExpiresInDays == nil || *v.Connections[0].ExpiresInDays != 10 {
		t.Errorf("connections = %+v", v.Connections)
	}
	if v.Summary.Seen != 2 || v.Summary.Included != 1 || v.Summary.Skipped["fork"] != 1 {
		t.Errorf("summary = %+v", v.Summary)
	}
	if len(v.Discovered) != 2 || v.Discovered[1].Detail == "" {
		t.Errorf("discovered = %+v", v.Discovered)
	}

	_, body := h.get(t, "/v1/github")
	if strings.Contains(strings.ToLower(string(body)), "token\":") {
		t.Errorf("the response has a token field: %s", body)
	}
}
