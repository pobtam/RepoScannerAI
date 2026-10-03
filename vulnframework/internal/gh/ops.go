package gh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// RESTOps is the live gh.PROps: GitHub's REST API for pull requests, and git
// for everything that touches a working tree.
//
// Split that way because the two halves have different failure modes and
// different credentials. The REST half authenticates with an installation
// token; the git half needs that token only at the moment of a push, and
// holds it nowhere else.
//
// Not wired up. Installing the App, holding its key and deciding what it may
// write to are D4.
type RESTOps struct {
	// BaseURL is the REST root. Empty means api.github.com.
	BaseURL string
	// HTTP is the client. Nil uses a bounded-timeout client.
	HTTP *http.Client
	// Token supplies an installation token.
	//
	// A function rather than a string, for the reason agent.Client uses the
	// same shape: "was a credential ever fetched" becomes an observable fact
	// rather than an inference about field access. It is also how a
	// short-lived token gets refreshed without this type caching one past its
	// expiry.
	Token func(ctx context.Context, repo string) (string, error)

	// CloneURL builds the URL to clone and push to, given a repository and a
	// token. Empty uses GitHub's HTTPS form.
	CloneURL func(repo, token string) string

	// Git is the git binary. Empty means "git".
	Git string
}

var _ PROps = (*RESTOps)(nil)

// --- the REST half -----------------------------------------------------------

// DefaultBranch is the base for every remediation branch (VM-F-501).
func (o *RESTOps) DefaultBranch(ctx context.Context, repo string) (string, error) {
	token, err := o.token(ctx, repo)
	if err != nil {
		return "", err
	}
	var body struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := o.do(ctx, http.MethodGet, "/repos/"+repo, token, nil, &body); err != nil {
		return "", err
	}
	if body.DefaultBranch == "" {
		// Never defaulted to "main". A repository whose default branch is
		// something else would have remediation branches cut from a base that
		// does not exist, and the failure would surface as a confusing push
		// error rather than as the missing field it is.
		return "", fmt.Errorf("gh: %s reported no default branch", repo)
	}
	return body.DefaultBranch, nil
}

// BranchExists reports whether a branch is already present on the remote.
//
// This is the idempotency check behind VM-F-502: a fix group's branch name is
// derived from its identity, so re-running remediation finds the branch rather
// than opening a second pull request for work already in review.
func (o *RESTOps) BranchExists(ctx context.Context, repo, branch string) (bool, error) {
	token, err := o.token(ctx, repo)
	if err != nil {
		return false, err
	}
	err = o.do(ctx, http.MethodGet, "/repos/"+repo+"/git/ref/heads/"+branch, token, nil, nil)
	if err == nil {
		return true, nil
	}
	if statusOf(err) == http.StatusNotFound {
		return false, nil
	}
	// Any other failure is NOT "the branch does not exist". Returning false
	// here would make a rate limit or a permissions error read as a fresh
	// branch, and remediation would push over work in review.
	return false, err
}

// FindPR returns the open pull request for a head branch, if any.
func (o *RESTOps) FindPR(ctx context.Context, repo, head string) (PullRequest, bool, error) {
	token, err := o.token(ctx, repo)
	if err != nil {
		return PullRequest{}, false, err
	}

	owner := repo
	if i := strings.IndexByte(repo, '/'); i >= 0 {
		owner = repo[:i]
	}
	path := fmt.Sprintf("/repos/%s/pulls?state=all&head=%s:%s&per_page=100", repo, owner, head)

	var list []pullPayload
	if err := o.do(ctx, http.MethodGet, path, token, nil, &list); err != nil {
		return PullRequest{}, false, err
	}
	if len(list) == 0 {
		return PullRequest{}, false, nil
	}
	// Newest first: a branch reused after a previous pull request was closed
	// has more than one, and the current one is the one that matters.
	sort.Slice(list, func(i, j int) bool { return list[i].Number > list[j].Number })
	return list[0].toPullRequest(), true, nil
}

// GetPR returns a pull request by number, whatever its state.
func (o *RESTOps) GetPR(ctx context.Context, repo string, number int) (PullRequest, bool, error) {
	token, err := o.token(ctx, repo)
	if err != nil {
		return PullRequest{}, false, err
	}
	var payload pullPayload
	err = o.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/pulls/%d", repo, number), token, nil, &payload)
	if err != nil {
		if statusOf(err) == http.StatusNotFound {
			return PullRequest{}, false, nil
		}
		return PullRequest{}, false, err
	}
	return payload.toPullRequest(), true, nil
}

// OpenPR opens a pull request (VM-F-541: never auto-merged).
func (o *RESTOps) OpenPR(ctx context.Context, repo string, req OpenRequest) (PullRequest, error) {
	token, err := o.token(ctx, repo)
	if err != nil {
		return PullRequest{}, err
	}

	var payload pullPayload
	err = o.do(ctx, http.MethodPost, "/repos/"+repo+"/pulls", token, map[string]any{
		"title": req.Title,
		"head":  req.Head,
		"base":  req.Base,
		"body":  req.Body,
		"draft": req.Draft,
	}, &payload)

	if err != nil {
		// GitHub answers 422 for a duplicate and does NOT return the existing
		// pull request, so a caller that assumed success would fail on an
		// ordinary retry. The existing one is fetched and carried on the
		// error, which is what lets the worker adopt it.
		if statusOf(err) == http.StatusUnprocessableEntity && mentionsExistingPR(err) {
			existing, found, findErr := o.FindPR(ctx, repo, req.Head)
			if findErr != nil {
				return PullRequest{}, fmt.Errorf(
					"gh: a pull request already exists for head %s and it could not be fetched: %w",
					req.Head, findErr)
			}
			if found {
				return PullRequest{}, &ErrPRExists{Existing: existing}
			}
		}
		return PullRequest{}, err
	}

	pr := payload.toPullRequest()
	if len(req.Labels) > 0 {
		// Labels are a separate call in GitHub's API. A failure here is NOT
		// fatal to the pull request, which already exists — but it is not
		// silent either: VM-F-542 requires the pull request to be identifiable
		// as machine-generated, and one that is not must be visible.
		if err := o.do(ctx, http.MethodPost,
			fmt.Sprintf("/repos/%s/issues/%d/labels", repo, pr.Number), token,
			map[string]any{"labels": req.Labels}, nil); err != nil {
			return pr, fmt.Errorf(
				"gh: pull request #%d was opened but could not be labelled %s: %w. "+
					"VM-F-542 requires a machine-generated pull request to be identifiable as one",
				pr.Number, strings.Join(req.Labels, ", "), err)
		}
	}
	return pr, nil
}

// ClosePR closes a pull request, leaving a comment saying why.
func (o *RESTOps) ClosePR(ctx context.Context, repo string, number int, comment string) error {
	token, err := o.token(ctx, repo)
	if err != nil {
		return err
	}
	if strings.TrimSpace(comment) != "" {
		// The comment first. A pull request closed with no explanation is one
		// whose author has to guess, and if the close succeeds and the
		// comment does not, the explanation is the thing worth having.
		if err := o.do(ctx, http.MethodPost,
			fmt.Sprintf("/repos/%s/issues/%d/comments", repo, number), token,
			map[string]any{"body": comment}, nil); err != nil {
			return err
		}
	}
	return o.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/pulls/%d", repo, number), token,
		map[string]any{"state": "closed"}, nil)
}

// pullPayload is GitHub's pull request representation.
type pullPayload struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	State   string `json:"state"`
	Merged  bool   `json:"merged"`
	// MergedAt is the fallback. The pulls LIST endpoint omits `merged`
	// entirely, so a merged pull request read from a list would come back as
	// merely closed — and closed-without-merge is DECLINED while merged is
	// MERGED (VM-F-545). Two different outcomes from one missing field.
	MergedAt *time.Time `json:"merged_at"`
	Head     struct {
		Ref string `json:"ref"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
}

func (p pullPayload) toPullRequest() PullRequest {
	return PullRequest{
		Number: p.Number,
		URL:    p.HTMLURL,
		Head:   p.Head.Ref,
		Base:   p.Base.Ref,
		State:  p.State,
		Merged: p.Merged || p.MergedAt != nil,
	}
}

func mentionsExistingPR(err error) bool {
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		return false
	}
	text := strings.ToLower(apiErr.Message + " " + string(apiErr.Body))
	return strings.Contains(text, "pull request already exists") ||
		strings.Contains(text, "a pull request already exists")
}

func statusOf(err error) int {
	var apiErr *apiError
	if errors.As(err, &apiErr) {
		return apiErr.Status
	}
	return 0
}

// --- the git half ------------------------------------------------------------

// Clone places a repository at a ref into dir.
func (o *RESTOps) Clone(ctx context.Context, repo, ref, dir string) error {
	token, err := o.token(ctx, repo)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("gh: creating the clone directory: %w", err)
	}

	args := []string{"clone", "--depth", "50", "--no-tags", "--single-branch"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, o.cloneURL(repo, token), dir)

	// Run from the parent: the clone directory does not yet contain a
	// repository, so git has nothing to work in.
	if _, err := o.git(ctx, ".", args...); err != nil {
		return err
	}
	return nil
}

// Discard removes a working copy.
func (o *RESTOps) Discard(_ context.Context, dir string) error {
	if dir == "" || dir == "/" {
		return fmt.Errorf("gh: refusing to discard %q", dir)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("gh: discarding %s: %w", dir, err)
	}
	return nil
}

// CreateBranch cuts a branch in the working copy.
func (o *RESTOps) CreateBranch(ctx context.Context, dir, branch string) error {
	_, err := o.git(ctx, dir, "checkout", "-b", branch)
	return err
}

// ChangedFiles reports what the TREE shows as changed (VM-F-510).
//
// `--untracked-files=all` is what makes a file a fixer ADDED visible here.
// Note that Diff needs an extra step for the same files and this does not:
// `git status` reports an untracked file, `git diff` does not show one until
// it is at least intent-to-add. Doing it in both places would be a redundant
// index write, and a check that cannot fail.
func (o *RESTOps) ChangedFiles(ctx context.Context, dir string) ([]string, error) {
	out, err := o.git(ctx, dir, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return nil, err
	}

	var files []string
	for _, line := range strings.Split(out, "\n") {
		if len(line) < 4 {
			continue
		}
		path := strings.TrimSpace(line[3:])
		if i := strings.Index(path, " -> "); i >= 0 {
			path = path[i+4:]
		}
		files = append(files, strings.Trim(path, `"`))
	}
	sort.Strings(files)
	return files, nil
}

// Diff returns the change for the content guard to inspect.
func (o *RESTOps) Diff(ctx context.Context, dir string) ([]byte, error) {
	// Intent-to-add first, and this is where it is load-bearing. `git diff`
	// shows nothing at all for an untracked file, so a fixer that ADDED one —
	// a new source file, a new workflow — would present the content guard
	// with an empty diff and the guard would pass it without having seen it.
	// It touches the index only; the working tree is unchanged.
	if _, err := o.git(ctx, dir, "add", "--intent-to-add", "--", "."); err != nil {
		return nil, err
	}
	out, err := o.git(ctx, dir, "diff", "HEAD")
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

// Commit records one logical fix under the framework's own identity
// (VM-F-505, VM-F-544).
func (o *RESTOps) Commit(ctx context.Context, dir string, c Commit) error {
	args := []string{"add", "--"}
	if len(c.Files) == 0 {
		args = append(args, ".")
	} else {
		args = append(args, c.Files...)
	}
	if _, err := o.git(ctx, dir, args...); err != nil {
		return err
	}

	// The identity is passed per-invocation rather than configured into the
	// repository, so a machine change can never be attributed to whatever
	// identity happens to be in the runner's git config. `git log` is most
	// often asked exactly one question — who did this — and it has to be
	// answerable (VM-F-544).
	_, err := o.git(ctx, dir,
		"-c", "user.name="+c.AuthorName,
		"-c", "user.email="+c.AuthorEmail,
		"commit", "--no-verify", "-m", c.Message)
	return err
}

// Push sends the branch to the remote.
//
// Never forced. A rejected push means another worker or a human moved the
// branch, and a force here would destroy whatever moved it.
func (o *RESTOps) Push(ctx context.Context, dir, repo, branch string) error {
	token, err := o.token(ctx, repo)
	if err != nil {
		return err
	}

	out, err := o.git(ctx, dir, "push", o.cloneURL(repo, token), branch+":"+branch)
	if err == nil {
		return nil
	}
	if isNonFastForward(out + " " + err.Error()) {
		return &ErrConflict{Repo: repo, Branch: branch}
	}
	return err
}

// isNonFastForward recognises a rejected push.
//
// Matched on git's own words because there is no exit code that distinguishes
// it: git exits 1 for a rejected push and for a dozen other things, and
// treating them alike would either abandon branches that could be pushed or
// retry ones that never will be.
func isNonFastForward(text string) bool {
	lower := strings.ToLower(text)
	for _, marker := range []string{
		"non-fast-forward",
		"failed to push some refs",
		"fetch first",
		"updates were rejected",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// git runs one git command and returns its combined output.
func (o *RESTOps) git(ctx context.Context, dir string, args ...string) (string, error) {
	bin := o.Git
	if bin == "" {
		bin = "git"
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	if dir != "" && dir != "." {
		cmd.Dir = dir
	}
	// A terminal prompt would hang a worker for ever on a credential git
	// cannot find, and the framework must fail rather than wait. The config
	// files are neutralised so that whatever is on the runner cannot change
	// how a commit is attributed.
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	)

	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	out := buf.String()
	if err != nil {
		return out, fmt.Errorf("gh: git %s: %w: %s", strings.Join(redactArgs(args), " "), err, excerpt(out))
	}
	return out, nil
}

// cloneURL builds the remote URL, with the token embedded for git to use.
func (o *RESTOps) cloneURL(repo, token string) string {
	if o.CloneURL != nil {
		return o.CloneURL(repo, bare(token))
	}
	return fmt.Sprintf("https://x-access-token:%s@github.com/%s.git", bare(token), repo)
}

// bare strips the "token " prefix the REST half carries.
func bare(token string) string {
	return strings.TrimPrefix(strings.TrimPrefix(token, "token "), "Bearer ")
}

// redactArgs removes anything credential-shaped before an error is rendered.
//
// A push URL carries the installation token, and an error message is the one
// part of a failed command that reliably reaches a log. This is the third
// layer rather than the only one — nothing is supposed to put a credential
// here — and it is present because the cost of being wrong is a token in a log
// file nobody reads until it matters.
func redactArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		switch {
		case strings.Contains(a, "x-access-token:"):
			out[i] = "https://x-access-token:REDACTED@…"
		case strings.HasPrefix(a, "user.email=") || strings.HasPrefix(a, "user.name="):
			out[i] = a
		case strings.Contains(a, "://") && strings.Contains(a, "@"):
			out[i] = "REDACTED-URL"
		default:
			out[i] = a
		}
	}
	return out
}

func (o *RESTOps) token(ctx context.Context, repo string) (string, error) {
	if o.Token == nil {
		return "", fmt.Errorf("gh: no installation-token source is configured. Refusing rather " +
			"than attempting an unauthenticated write: an anonymous push fails in a way that reads " +
			"like a missing branch")
	}
	token, err := o.Token(ctx, repo)
	if err != nil {
		return "", fmt.Errorf("gh: obtaining an installation token for %s: %w", repo, err)
	}
	if strings.TrimSpace(token) == "" {
		return "", fmt.Errorf("gh: the installation token for %s was empty", repo)
	}
	return token, nil
}

func (o *RESTOps) base() string {
	if o.BaseURL != "" {
		return strings.TrimSuffix(o.BaseURL, "/")
	}
	return defaultAPIBase
}

func (o *RESTOps) client() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (o *RESTOps) do(ctx context.Context, method, path, token string, in, out any) error {
	return request(ctx, o.client(), method, o.base()+path, token, in, out)
}
