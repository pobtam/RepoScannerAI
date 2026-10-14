package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/gh/ghfake"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/store"
)

// withFakeGitHub points vfctl's GitHub client at a local fake for one test.
func withFakeGitHub(t *testing.T, fake *ghfake.Server) {
	t.Helper()
	prevGH, prevUser, prevNow := newGitHub, currentUser, now
	newGitHub = func() orchestrator.GitHubAccount {
		return &gh.TokenClient{BaseURL: fake.URL, HTTP: fake.Client(),
			Token: func() (string, error) { return "fake-token", nil }}
	}
	currentUser = func() string { return "pat" }
	now = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { newGitHub, currentUser, now = prevGH, prevUser, prevNow })
}

func migrated(t *testing.T) store.Store {
	t.Helper()
	st := store.NewMemory()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestGitHubConnectRecordsTheAccountNotTheToken(t *testing.T) {
	fake := ghfake.New("octo", "fake-token")
	defer fake.Close()
	fake.Expiry = time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	withFakeGitHub(t, fake)
	st := migrated(t)

	out := mustExec(t, st, "github", "connect")
	if !strings.Contains(out, "connected octo (fine-grained token)") {
		t.Errorf("connect said:\n%s", out)
	}
	if !strings.Contains(out, "rotate it soon") {
		t.Errorf("a token expiring in a week was not flagged:\n%s", out)
	}
	if strings.Contains(out, "fake-token") {
		t.Fatal("connect printed the token")
	}
	conns, _ := st.GitHubConnections(context.Background())
	if len(conns) != 1 || conns[0].CheckedBy != "pat" {
		t.Errorf("connections = %+v", conns)
	}
}

func TestGitHubConnectRefusesAWriteCapableClassicToken(t *testing.T) {
	fake := ghfake.New("octo", "fake-token")
	defer fake.Close()
	fake.Classic = []string{"repo"}
	withFakeGitHub(t, fake)
	st := migrated(t)

	if _, err := exec(t, st, "github", "connect"); err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("err = %v, want a refusal naming write access", err)
	}
	if conns, _ := st.GitHubConnections(context.Background()); len(conns) != 0 {
		t.Errorf("a refused token was recorded: %+v", conns)
	}
}

func TestGitHubDiscoverListsEveryRepositoryWithItsDecision(t *testing.T) {
	fake := ghfake.New("octo", "fake-token",
		ghfake.Repo{FullName: "octo/api", SizeKB: 10},
		ghfake.Repo{FullName: "octo/fork", SizeKB: 10, Fork: true},
		ghfake.Repo{FullName: "octo/empty", SizeKB: 0},
	)
	defer fake.Close()
	withFakeGitHub(t, fake)
	st := migrated(t)

	out := mustExec(t, st, "github", "discover")
	for _, want := range []string{"octo/api", "scan", "octo/fork", "a fork", "octo/empty", "empty",
		"3 repositories, 1 to scan, 2 skipped", "1 added"} {
		if !strings.Contains(out, want) {
			t.Errorf("discover output lacks %q:\n%s", want, out)
		}
	}
	if r, err := st.GetRepo(context.Background(), "octo/api"); err != nil || r.Archived {
		t.Errorf("octo/api not registered active: %+v, %v", r, err)
	}

	out = mustExec(t, st, "github", "discover", "-include-forks")
	if !strings.Contains(out, "2 to scan") {
		t.Errorf("-include-forks did not include the fork:\n%s", out)
	}

	status := mustExec(t, st, "github", "status")
	if !strings.Contains(status, "3 repositories, 2 to scan, 1 skipped") {
		t.Errorf("status:\n%s", status)
	}
}

func TestRepoExcludeNeedsAReasonAndArchivesAtOnce(t *testing.T) {
	fake := ghfake.New("octo", "fake-token", ghfake.Repo{FullName: "octo/api", SizeKB: 10})
	defer fake.Close()
	withFakeGitHub(t, fake)
	st := migrated(t)
	mustExec(t, st, "github", "discover")

	if _, err := exec(t, st, "repo", "exclude", "octo/api"); err == nil || !strings.Contains(err.Error(), "-reason") {
		t.Fatalf("an exclusion without a reason was accepted: %v", err)
	}
	mustExec(t, st, "repo", "exclude", "octo/api", "-reason", "a vendored mirror")
	if r, _ := st.GetRepo(context.Background(), "octo/api"); !r.Archived {
		t.Error("an excluded repository is still active")
	}
	out := mustExec(t, st, "github", "discover")
	if !strings.Contains(out, "excluded by a person: a vendored mirror") {
		t.Errorf("rediscovery did not keep the exclusion:\n%s", out)
	}

	mustExec(t, st, "repo", "include", "octo/api")
	mustExec(t, st, "github", "discover")
	if r, _ := st.GetRepo(context.Background(), "octo/api"); r.Archived {
		t.Error("an included repository was not restored by the next discovery")
	}
	if _, err := exec(t, st, "repo", "include", "octo/api"); err == nil {
		t.Error("including a repository that is not excluded succeeded")
	}
}

func TestGitHubCommandsTakeNoTokenArgument(t *testing.T) {
	st := migrated(t)
	if _, err := exec(t, st, "github", "connect", "ghp_something"); err == nil {
		t.Error("connect accepted a token as an argument, where it would land in shell history")
	}
}
