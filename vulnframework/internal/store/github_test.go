package store_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/store"
)

func TestGitHubDiscoveryRoundTripsOnEveryBackend(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	exp := at.Add(30 * 24 * time.Hour)

	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			s := b.open(t)

			// Discovery for an account nobody connected is refused: the list
			// would have no record of which token produced it.
			err := s.ReplaceDiscovery(ctx, "ghost", []store.DiscoveredRepo{{
				Name: "ghost/a", Account: "ghost", Affiliation: "owner", Included: true, DiscoveredAt: at,
			}})
			if !errors.Is(err, store.ErrNotConnected) {
				t.Fatalf("discovery for an unconnected account: %v, want ErrNotConnected", err)
			}

			conn := store.GitHubConnection{
				Account: "octo", Kind: "fine_grained", ExpiresAt: &exp,
				ReadOnly: "fine-grained", CheckedAt: at, CheckedBy: "pat",
			}
			if err := s.SaveGitHubConnection(ctx, conn); err != nil {
				t.Fatal(err)
			}
			conns, err := s.GitHubConnections(ctx)
			if err != nil || len(conns) != 1 {
				t.Fatalf("connections = %v, %v", conns, err)
			}
			if !conns[0].ExpiresAt.Equal(exp) || conns[0].Kind != "fine_grained" {
				t.Errorf("connection read back as %+v", conns[0])
			}

			repos := []store.DiscoveredRepo{
				{Name: "octo/api", Account: "octo", Affiliation: "owner", SizeKB: 120, DefaultBranch: "main",
					Language: "Go", Included: true, DiscoveredAt: at},
				{Name: "octo/old", Account: "octo", Affiliation: "owner", Archived: true, SizeKB: 10,
					DefaultBranch: "main", Reason: "archived", Detail: "archived on GitHub", DiscoveredAt: at},
			}
			if err := s.ReplaceDiscovery(ctx, "octo", repos); err != nil {
				t.Fatal(err)
			}
			got, err := s.Discovery(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, repos) {
				t.Errorf("discovery read back as\n%+v\nwant\n%+v", got, repos)
			}

			// A second discovery REPLACES the first: a repository GitHub no
			// longer lists is not kept as if it still existed.
			if err := s.ReplaceDiscovery(ctx, "octo", repos[:1]); err != nil {
				t.Fatal(err)
			}
			if got, _ := s.Discovery(ctx); len(got) != 1 || got[0].Name != "octo/api" {
				t.Errorf("after replacement: %+v", got)
			}

			// Included-with-a-reason is refused, on both backends alike.
			bad := repos[0]
			bad.Reason = "fork"
			if err := s.ReplaceDiscovery(ctx, "octo", []store.DiscoveredRepo{bad}); err == nil {
				t.Error("an included repository with a skip reason was accepted")
			}

			ex := store.RepoExclusion{Name: "octo/api", Reason: "vendored mirror", ExcludedBy: "pat", ExcludedAt: at}
			if err := s.SetExclusion(ctx, ex); err != nil {
				t.Fatal(err)
			}
			exs, _ := s.Exclusions(ctx)
			if !reflect.DeepEqual(exs, []store.RepoExclusion{ex}) {
				t.Errorf("exclusions = %+v", exs)
			}
			if ok, _ := s.RemoveExclusion(ctx, "octo/api"); !ok {
				t.Error("removing an existing exclusion reported none")
			}
			if ok, _ := s.RemoveExclusion(ctx, "octo/api"); ok {
				t.Error("removing it twice reported one")
			}
		})
	}
}
