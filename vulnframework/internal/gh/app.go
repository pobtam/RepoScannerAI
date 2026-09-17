package gh

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// RemoteRepo is a repository as GitHub describes it.
type RemoteRepo struct {
	FullName      string   `json:"full_name"`
	DefaultBranch string   `json:"default_branch"`
	Languages     []string `json:"languages"`
	Archived      bool     `json:"archived"`
	Private       bool     `json:"private"`
	Codeowners    []string `json:"codeowners,omitempty"`
}

// Tag is a published release tag.
type Tag struct {
	Name string    `json:"name"`
	At   time.Time `json:"at"`
}

// App is the installed GitHub App surface (VM-AD §3: app auth, installation
// tokens, PR ops).
//
// The fleet comes from here rather than from the store, which is A18's whole
// point: coverage is measured against planned scope, planned scope comes from
// the registry, and a registry that is only ever read from itself cannot
// discover a repository it has never seen. The fleet would report full
// coverage while never having looked.
type App interface {
	// Repositories lists every repository the App is installed on.
	Repositories(ctx context.Context) ([]RemoteRepo, error)
	// Tags lists a repository's tags, newest first. Wave 2 waits on these
	// where wave2_trigger is tag (VM-AD §12.3).
	Tags(ctx context.Context, repo string) ([]Tag, error)
	// InstallationToken returns a short-lived token for a repository.
	InstallationToken(ctx context.Context, repo string) (string, time.Time, error)
}

// FakeApp is an in-memory App that models GitHub's WEAKEST permitted
// behaviour, per the standing sentinel.
//
// The behaviours it can be made to exhibit are the ones that actually happen:
// an outage returns an error, a permissions change returns an EMPTY list that
// is indistinguishable from "you have no repositories", pagination truncates,
// and a token expires between being issued and being used.
type FakeApp struct {
	mu       sync.Mutex
	repos    []RemoteRepo
	tags     map[string][]Tag
	failure  error
	truncate int
	calls    []string
}

// NewFakeApp builds an App installed on nothing.
func NewFakeApp() *FakeApp { return &FakeApp{tags: map[string][]Tag{}} }

// WithRepo installs the App on a repository.
func (a *FakeApp) WithRepo(r RemoteRepo) *FakeApp {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.repos = append(a.repos, r)
	return a
}

// WithTag publishes a tag.
func (a *FakeApp) WithTag(repo, name string, at time.Time) *FakeApp {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tags[repo] = append(a.tags[repo], Tag{Name: name, At: at})
	return a
}

// FailWith makes every call fail, as an outage or a revoked installation does.
func (a *FakeApp) FailWith(err error) *FakeApp {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failure = err
	return a
}

// Truncate returns only the first n repositories, as a paginated listing whose
// second page was lost would. The result is a plausible short list rather than
// an error, which is what makes it dangerous.
func (a *FakeApp) Truncate(n int) *FakeApp {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.truncate = n
	return a
}

func (a *FakeApp) Repositories(context.Context) ([]RemoteRepo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "Repositories")
	if a.failure != nil {
		return nil, a.failure
	}
	out := append([]RemoteRepo(nil), a.repos...)
	sort.Slice(out, func(i, j int) bool { return out[i].FullName < out[j].FullName })
	if a.truncate > 0 && len(out) > a.truncate {
		out = out[:a.truncate]
	}
	return out, nil
}

func (a *FakeApp) Tags(_ context.Context, repo string) ([]Tag, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "Tags "+repo)
	if a.failure != nil {
		return nil, a.failure
	}
	out := append([]Tag(nil), a.tags[repo]...)
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out, nil
}

func (a *FakeApp) InstallationToken(_ context.Context, repo string) (string, time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "InstallationToken "+repo)
	if a.failure != nil {
		return "", time.Time{}, a.failure
	}
	// Short-lived, as real installation tokens are.
	return "ghs_fake_token_for_" + strings.ReplaceAll(repo, "/", "_"), time.Now().Add(time.Hour), nil
}

// Calls returns every call made, for assertions about fan-out.
func (a *FakeApp) Calls() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.calls...)
}

// ErrEmptyFleet reports a listing that returned nothing.
//
// Its own error because the correct response is to do nothing at all. An empty
// list is what a revoked installation, an expired credential and a lost
// pagination page all look like, and it is indistinguishable from a genuinely
// empty organisation — so it is refused rather than acted on. Acting on it
// would archive the entire fleet, and the next sweep would find nothing to
// scan and report complete coverage.
type ErrEmptyFleet struct{ Known int }

func (e *ErrEmptyFleet) Error() string {
	return fmt.Sprintf(
		"gh: the App reported no repositories while the registry holds %d. An empty listing is what a "+
			"revoked installation, an expired credential and a lost pagination page all look like, and "+
			"it cannot be told apart from a genuinely empty organisation. Refusing: acting on it would "+
			"archive the whole fleet, and the next sweep would find nothing to scan and report complete "+
			"coverage", e.Known)
}
