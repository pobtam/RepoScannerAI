package gh_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/gh/ghfake"
)

// The token used against the fake. Not key-shaped: the fake checks equality,
// not format.
const fakeToken = "fake-token-for-tests"

func tokenClient(s *ghfake.Server) *gh.TokenClient {
	return &gh.TokenClient{
		BaseURL: s.URL,
		Token:   func() (string, error) { return fakeToken, nil },
		HTTP:    s.Client(),
		Sleep:   func(context.Context, time.Duration) error { return nil },
	}
}

func TestConnectDescribesAFineGrainedToken(t *testing.T) {
	s := ghfake.New("octo", fakeToken)
	defer s.Close()
	s.Expiry = time.Date(2026, 12, 1, 9, 30, 0, 0, time.UTC)

	conn, err := tokenClient(s).Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if conn.Account != "octo" || conn.Kind != "fine_grained" || len(conn.Scopes) != 0 {
		t.Errorf("connection = %+v", conn)
	}
	if conn.ExpiresAt == nil || !conn.ExpiresAt.Equal(s.Expiry) {
		t.Errorf("expiry = %v, want %v", conn.ExpiresAt, s.Expiry)
	}
	if !strings.Contains(conn.ReadOnly, "GET") {
		t.Errorf("the read-only statement does not say how it is enforced: %q", conn.ReadOnly)
	}
}

func TestConnectRefusesAClassicTokenThatCanWrite(t *testing.T) {
	s := ghfake.New("octo", fakeToken)
	defer s.Close()
	s.Classic = []string{"read:org", "repo"}

	_, err := tokenClient(s).Connect(context.Background())
	var write *gh.ErrWriteCapableToken
	if !errors.As(err, &write) || len(write.Scopes) != 1 || write.Scopes[0] != "repo" {
		t.Fatalf("err = %v, want ErrWriteCapableToken naming repo", err)
	}
}

func TestConnectAcceptsAClassicTokenWithOnlyReadScopes(t *testing.T) {
	s := ghfake.New("octo", fakeToken)
	defer s.Close()
	s.Classic = []string{"read:org"}

	conn, err := tokenClient(s).Connect(context.Background())
	if err != nil || conn.Kind != "classic" || len(conn.Scopes) != 1 {
		t.Fatalf("conn = %+v, err = %v", conn, err)
	}
}

func TestAWrongTokenIsAnErrorThatDoesNotCarryTheToken(t *testing.T) {
	s := ghfake.New("octo", "the-right-one")
	defer s.Close()

	_, err := tokenClient(s).Connect(context.Background())
	if err == nil {
		t.Fatal("a wrong token connected")
	}
	if strings.Contains(err.Error(), fakeToken) {
		t.Fatalf("the error carries the token: %v", err)
	}
}

func TestAccountReposFollowsEveryPage(t *testing.T) {
	var repos []ghfake.Repo
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		repos = append(repos, ghfake.Repo{FullName: "octo/" + n, SizeKB: 1})
	}
	s := ghfake.New("octo", fakeToken, repos...)
	defer s.Close()
	s.PageSize = 2

	got, err := tokenClient(s).AccountRepos(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d repositories across pages, want 5", len(got))
	}
	pages := 0
	for _, r := range s.Requests() {
		if r == "GET /user/repos" {
			pages++
		}
	}
	if pages != 3 {
		t.Errorf("fetched %d pages, want 3", pages)
	}
}

func TestARateLimitIsWaitedOutThenRetried(t *testing.T) {
	s := ghfake.New("octo", fakeToken)
	defer s.Close()
	s.RateLimitOnce = 30 * time.Second

	var waited []time.Duration
	c := tokenClient(s)
	c.Sleep = func(_ context.Context, d time.Duration) error { waited = append(waited, d); return nil }

	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(waited) != 1 || waited[0] <= 0 || waited[0] > 31*time.Second {
		t.Errorf("waited %v, want one wait of about 30s", waited)
	}
}

func TestARateLimitLongerThanTheBoundIsAnError(t *testing.T) {
	s := ghfake.New("octo", fakeToken)
	defer s.Close()
	s.RateLimitOnce = time.Hour

	c := tokenClient(s)
	c.MaxRateWait = time.Minute
	var limited *gh.ErrRateLimited
	if _, err := c.Connect(context.Background()); !errors.As(err, &limited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
}

// The client is read-only in code: whatever a caller asks, nothing but GET
// and HEAD leaves the process.
func TestTheClientRefusesEveryWriteBeforeTheNetwork(t *testing.T) {
	s := ghfake.New("octo", fakeToken)
	defer s.Close()

	client := gh.ReadOnlyHTTPClient(s.Client())
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req, _ := http.NewRequest(method, s.URL+"/repos/octo/a/pulls", nil)
		if _, err := client.Do(req); !errors.Is(err, gh.ErrWriteRefused) {
			t.Errorf("%s: err = %v, want ErrWriteRefused", method, err)
		}
	}
	if len(s.Requests()) != 0 {
		t.Errorf("writes reached the server: %v", s.Requests())
	}
}

func TestDownloadRefusesATarballOverTheLimit(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "big.txt", strings.Repeat("x", 4<<20))
	s := ghfake.New("octo", fakeToken, ghfake.Repo{FullName: "octo/big", SizeKB: 4096, Dir: dir})
	defer s.Close()

	var buf bytes.Buffer
	if _, err := tokenClient(s).Download(context.Background(), "octo/big", "", &buf, 1024); err == nil {
		t.Fatal("an oversized tarball was accepted")
	}
}

func TestDownloadRefusesANameThatIsNotOwnerSlashRepo(t *testing.T) {
	s := ghfake.New("octo", fakeToken)
	defer s.Close()
	for _, name := range []string{"../etc", "octo", "octo/a/b", "octo/..", ""} {
		if _, err := tokenClient(s).Download(context.Background(), name, "", &bytes.Buffer{}, 1<<20); err == nil {
			t.Errorf("%q was accepted", name)
		}
	}
	if len(s.Requests()) != 0 {
		t.Errorf("a malformed name reached the server: %v", s.Requests())
	}
}

func TestClassifyGivesEverySkippedRepositoryAReason(t *testing.T) {
	repo := func(name, ownerType string, mut func(*gh.AccountRepo)) gh.AccountRepo {
		r := gh.AccountRepo{FullName: name, SizeKB: 100}
		r.Owner.Login, _, _ = strings.Cut(name, "/")
		r.Owner.Type = ownerType
		if mut != nil {
			mut(&r)
		}
		return r
	}
	in := []gh.AccountRepo{
		repo("octo/api", "User", nil),
		repo("acme/web", "Organization", nil),
		repo("friend/tool", "User", nil),
		repo("octo/fork", "User", func(r *gh.AccountRepo) { r.Fork = true }),
		repo("octo/old", "User", func(r *gh.AccountRepo) { r.Archived = true }),
		repo("octo/empty", "User", func(r *gh.AccountRepo) { r.SizeKB = 0 }),
		repo("octo/huge", "User", func(r *gh.AccountRepo) { r.SizeKB = 5 << 20 }),
		repo("octo/mirror", "User", nil),
	}
	got := gh.Classify("octo", in, gh.DiscoverOptions{Excluded: map[string]string{"octo/mirror": "a vendored mirror"}})

	want := map[string]string{
		"acme/web": "", "octo/api": "", "friend/tool": gh.SkipCollaborator, "octo/fork": gh.SkipFork,
		"octo/old": gh.SkipArchived, "octo/empty": gh.SkipEmpty, "octo/huge": gh.SkipTooLarge,
		"octo/mirror": gh.SkipExcluded,
	}
	for _, d := range got {
		if d.Reason != want[d.Repo.FullName] {
			t.Errorf("%s: reason %q, want %q", d.Repo.FullName, d.Reason, want[d.Repo.FullName])
		}
		if d.Included != (d.Reason == "") || (!d.Included && d.Detail == "") {
			t.Errorf("%s: included=%v reason=%q detail=%q", d.Repo.FullName, d.Included, d.Reason, d.Detail)
		}
	}
	if len(got) != len(in) {
		t.Errorf("classified %d of %d: a repository was dropped instead of skipped", len(got), len(in))
	}

	opted := gh.Classify("octo", in, gh.DiscoverOptions{IncludeCollaborator: true, IncludeForks: true})
	for _, d := range opted {
		if (d.Repo.FullName == "friend/tool" || d.Repo.FullName == "octo/fork") && !d.Included {
			t.Errorf("%s still skipped after opting in: %s", d.Repo.FullName, d.Reason)
		}
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHeadCommitIsReadAndChecked(t *testing.T) {
	commit := strings.Repeat("ab12", 10)
	fake := ghfake.New("octo", "fake-token", ghfake.Repo{FullName: "octo/api", Commit: commit})
	defer fake.Close()
	c := &gh.TokenClient{BaseURL: fake.URL, HTTP: fake.Client(), Token: func() (string, error) { return "fake-token", nil }}
	got, err := c.HeadCommit(context.Background(), "octo/api")
	if err != nil || got != commit {
		t.Errorf("HeadCommit = %q, %v", got, err)
	}
	if _, err := c.HeadCommit(context.Background(), "octo/missing"); err == nil {
		t.Error("an unknown repository resolved")
	}
	if _, err := c.HeadCommit(context.Background(), "../etc"); err == nil {
		t.Error("a name that is not owner/repo was sent")
	}
	fake.Repos[0].Commit = "not-a-commit"
	if _, err := c.HeadCommit(context.Background(), "octo/api"); err == nil {
		t.Error("an answer that is not a commit id was accepted")
	}
}
