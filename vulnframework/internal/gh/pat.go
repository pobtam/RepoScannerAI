package gh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The personal-access-token client: discovery and download for ONE account,
// read-only.
//
// Read-only is enforced here, not hoped for. The token's own permissions are
// the first line (a fine-grained token with Contents: read and Metadata:
// read cannot write), but GitHub exposes no API that reports a fine-grained
// token's permissions, so the client cannot verify them. What it can do is
// never ask: every request goes through readOnlyTransport, which refuses any
// method but GET and HEAD before it reaches the network. A classic token
// does report its scopes, and Connect refuses one that grants write.
//
// The token itself is never stored, logged or returned. It is read from the
// environment (or a prompt) by whoever constructs the client, held in the
// Token function, and sent only in the Authorization header.

// TokenClient talks to GitHub as one account, with a personal access token.
type TokenClient struct {
	// BaseURL is the REST root. Empty means api.github.com.
	BaseURL string
	// Token returns the token. A function so the caller decides where it
	// lives (environment, secret manager), and so it is never a struct field
	// a %+v could print.
	Token func() (string, error)
	// HTTP is the client. Nil uses a bounded-timeout client. Whatever is
	// supplied, its transport is wrapped read-only.
	HTTP *http.Client
	// Now and Sleep are injectable for the rate-limit tests.
	Now   func() time.Time
	Sleep func(context.Context, time.Duration) error
	// MaxRateWait is the longest the client will wait out a rate limit
	// before giving up. Zero means two minutes.
	MaxRateWait time.Duration
}

// Connection is what GitHub says about the token's account: everything
// recorded on connect, and nothing secret.
type Connection struct {
	Account string `json:"account"`
	// Kind is fine_grained, classic, or unknown (GitHub reports no scopes
	// header for fine-grained tokens and does for classic ones).
	Kind string `json:"kind"`
	// Scopes lists a classic token's OAuth scopes. Empty for fine-grained.
	Scopes []string `json:"scopes,omitempty"`
	// ExpiresAt is the token's expiry, when GitHub reports one.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// ReadOnly says how read-only access is assured, in words for a person.
	ReadOnly string `json:"read_only"`
}

// ErrWriteCapableToken refuses a classic token whose scopes grant write.
type ErrWriteCapableToken struct{ Scopes []string }

func (e *ErrWriteCapableToken) Error() string {
	return fmt.Sprintf("gh: this classic token grants write access (scopes: %s). The scanner runs "+
		"read-only and refuses it. Create a fine-grained personal access token with only "+
		"Contents: read-only and Metadata: read-only", strings.Join(e.Scopes, ", "))
}

// writeScopes are the classic OAuth scopes that permit any write. "repo"
// grants full read/write to private repositories; there is no classic scope
// for read-only private code, which is why fine-grained tokens are asked for.
var writeScopes = map[string]bool{
	"repo": true, "public_repo": true, "repo:status": true, "repo_deployment": true,
	"workflow": true, "write:packages": true, "delete_repo": true, "admin:org": true,
	"write:org": true, "admin:repo_hook": true, "write:repo_hook": true, "admin:org_hook": true,
	"write:discussion": true, "admin:public_key": true, "admin:gpg_key": true, "user": true,
	"admin:enterprise": true, "project": true, "codespace": true, "gist": true,
	"delete:packages": true, "admin:ssh_signing_key": true,
}

// Connect checks the token and describes its account.
func (c *TokenClient) Connect(ctx context.Context) (Connection, error) {
	var user struct {
		Login string `json:"login"`
	}
	hdr, err := c.getJSON(ctx, "/user", &user)
	if err != nil {
		return Connection{}, err
	}
	conn := Connection{Account: user.Login, Kind: "fine_grained"}

	if raw, ok := hdr["X-Oauth-Scopes"]; ok {
		conn.Kind = "classic"
		for _, s := range strings.Split(strings.Join(raw, ","), ",") {
			if s = strings.TrimSpace(s); s != "" {
				conn.Scopes = append(conn.Scopes, s)
			}
		}
		sort.Strings(conn.Scopes)
		var write []string
		for _, s := range conn.Scopes {
			if writeScopes[s] {
				write = append(write, s)
			}
		}
		if len(write) > 0 {
			return conn, &ErrWriteCapableToken{Scopes: write}
		}
		conn.ReadOnly = "classic token with no write scope; every request is also limited to GET by the client"
	} else {
		conn.ReadOnly = "fine-grained token: GitHub does not report its permissions, so grant only " +
			"Contents and Metadata read-only; every request is also limited to GET by the client"
	}

	if exp := http.Header(hdr).Get("Github-Authentication-Token-Expiration"); exp != "" {
		if t, err := parseTokenExpiry(exp); err == nil {
			conn.ExpiresAt = &t
		}
	}
	return conn, nil
}

// parseTokenExpiry reads GitHub's expiry header, which is not RFC 3339:
// "2026-11-30 12:00:00 UTC" or "2026-11-30 12:00:00 -0800".
func parseTokenExpiry(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05 -0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("gh: unrecognised token expiry %q", s)
}

// AccountRepo is one repository the token can reach, as GitHub lists it.
type AccountRepo struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
	Fork          bool   `json:"fork"`
	// SizeKB is GitHub's own size estimate. Zero means an empty repository.
	SizeKB   int    `json:"size"`
	Language string `json:"language"`
	Owner    struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"owner"`
	PushedAt *time.Time `json:"pushed_at"`
}

// AccountRepos lists every repository the token's account can reach: owned,
// organisation, and collaborator. Which of them are scanned is decided by
// Classify, so the skipped ones are visible with a reason instead of never
// fetched.
//
// Paged by GitHub's Link header. /user/repos has no total count, so the
// header is the only signal; a page that fails ends the listing with an
// error rather than a short list, because a short list reads exactly like a
// complete one.
func (c *TokenClient) AccountRepos(ctx context.Context) ([]AccountRepo, error) {
	next := "/user/repos?per_page=100&affiliation=owner,collaborator,organization_member&sort=full_name"
	var out []AccountRepo
	for pages := 0; next != ""; pages++ {
		if pages > 1000 {
			return nil, fmt.Errorf("gh: more than 1000 pages of repositories; refusing to continue")
		}
		var page []AccountRepo
		hdr, err := c.getJSON(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		next = nextLink(http.Header(hdr).Get("Link"), c.base())
	}
	return out, nil
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// nextLink extracts the rel="next" URL from a Link header, as a path relative
// to the API root. A next link pointing anywhere else is refused (returns
// "") rather than followed with the token attached.
func nextLink(header, base string) string {
	m := linkNext.FindStringSubmatch(header)
	if m == nil {
		return ""
	}
	if !strings.HasPrefix(m[1], base+"/") {
		return ""
	}
	return strings.TrimPrefix(m[1], base)
}

// Download streams a repository's tarball at ref (empty for the default
// branch) into w, reading at most maxBytes. It returns the number of bytes
// read. A tarball larger than maxBytes is an error, never a truncated tree:
// a truncated tree scans as a smaller, cleaner repository.
func (c *TokenClient) Download(ctx context.Context, repo, ref string, w io.Writer, maxBytes int64) (int64, error) {
	if !validRepoName(repo) {
		return 0, fmt.Errorf("gh: %q is not an owner/name repository", repo)
	}
	path := "/repos/" + repo + "/tarball"
	if ref != "" {
		path += "/" + url.PathEscape(ref)
	}
	resp, err := c.get(ctx, path, "application/vnd.github+json")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(w, io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return n, fmt.Errorf("gh: downloading %s: %w", repo, err)
	}
	if n > maxBytes {
		return n, fmt.Errorf("gh: %s is larger than the %d MB download limit", repo, maxBytes>>20)
	}
	return n, nil
}

// HeadCommit returns the commit at the head of a repository's default
// branch. Resolved before the download, so the tarball is fetched at exactly
// this commit and every adapter, local or remote, scans the same one.
//
// One read: GET /repos/{repo}/commits/HEAD with GitHub's SHA media type,
// which answers the bare commit id.
func (c *TokenClient) HeadCommit(ctx context.Context, repo string) (string, error) {
	if !validRepoName(repo) {
		return "", fmt.Errorf("gh: %q is not an owner/name repository", repo)
	}
	resp, err := c.get(ctx, "/repos/"+repo+"/commits/HEAD", "application/vnd.github.sha")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", fmt.Errorf("gh: reading the head commit of %s: %w", repo, err)
	}
	sha := strings.ToLower(strings.TrimSpace(string(b)))
	if !commitSHA.MatchString(sha) {
		return "", fmt.Errorf("gh: the head commit of %s is not a commit id", repo)
	}
	return sha, nil
}

// commitSHA is a full commit id: SHA-1, or SHA-256 for a repository that
// uses it.
var commitSHA = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

var repoName = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func validRepoName(s string) bool {
	return repoName.MatchString(s) && !strings.Contains(s, "..")
}

// getJSON GETs path and decodes the body into out, returning the headers.
func (c *TokenClient) getJSON(ctx context.Context, path string, out any) (map[string][]string, error) {
	resp, err := c.get(ctx, path, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("gh: reading GET %s: %w", path, err)
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return nil, fmt.Errorf("gh: the response to GET %s did not parse: %w", path, err)
	}
	return resp.Header, nil
}

// get performs one GET, waiting out a rate limit up to MaxRateWait. A non-2xx
// answer is an *apiError; the caller closes the body of a success.
func (c *TokenClient) get(ctx context.Context, path, accept string) (*http.Response, error) {
	token, err := c.token()
	if err != nil {
		return nil, err
	}
	waited := time.Duration(0)
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base()+path, nil)
		if err != nil {
			return nil, fmt.Errorf("gh: building GET %s: %w", path, err)
		}
		req.Header.Set("Accept", accept)
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "wanaware-vulnframework/1.0")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := c.client().Do(req)
		if err != nil {
			return nil, fmt.Errorf("gh: GET %s: %w", path, scrub(err, token))
		}
		if wait, limited := rateLimit(resp); limited {
			resp.Body.Close()
			if waited+wait > c.maxRateWait() {
				return nil, &ErrRateLimited{RetryAfter: wait}
			}
			if err := c.sleep(ctx, wait); err != nil {
				return nil, err
			}
			waited += wait
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			payload, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			return nil, &apiError{
				Status: resp.StatusCode, Method: http.MethodGet, URL: path,
				Message: message(payload), Body: payload,
			}
		}
		return resp, nil
	}
}

func (c *TokenClient) token() (string, error) {
	if c.Token == nil {
		return "", errors.New("gh: no GitHub token configured")
	}
	t, err := c.Token()
	if err != nil {
		return "", err
	}
	t = strings.TrimSpace(t)
	if t == "" {
		return "", errors.New("gh: the GitHub token is empty")
	}
	return t, nil
}

// scrub removes the token from an error's text, in case a transport ever
// echoes a header.
func scrub(err error, token string) error {
	if token == "" || !strings.Contains(err.Error(), token) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), token, "[redacted]"))
}

func (c *TokenClient) base() string {
	if c.BaseURL != "" {
		return strings.TrimSuffix(c.BaseURL, "/")
	}
	return defaultAPIBase
}

func (c *TokenClient) client() *http.Client {
	base := c.HTTP
	if base == nil {
		base = &http.Client{Timeout: 10 * time.Minute}
	}
	return ReadOnlyHTTPClient(base)
}

// ReadOnlyHTTPClient returns a copy of base whose transport refuses every
// method but GET and HEAD. A redirect to another host does not carry the
// token: Go drops the Authorization header on a cross-host redirect.
func ReadOnlyHTTPClient(base *http.Client) *http.Client {
	wrapped := *base
	wrapped.Transport = readOnlyTransport{next: base.Transport}
	return &wrapped
}

func (c *TokenClient) maxRateWait() time.Duration {
	if c.MaxRateWait > 0 {
		return c.MaxRateWait
	}
	return 2 * time.Minute
}

func (c *TokenClient) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ErrWriteRefused is what readOnlyTransport returns for any method but GET
// or HEAD.
var ErrWriteRefused = errors.New("gh: refused: this client is read-only and sends only GET and HEAD")

// readOnlyTransport refuses every request that could change anything.
type readOnlyTransport struct{ next http.RoundTripper }

func (t readOnlyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return nil, ErrWriteRefused
	}
	next := t.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(r)
}
