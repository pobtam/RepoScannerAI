package gh

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The live GitHub client.
//
// Everything in this file is WRITTEN and TESTED and nothing is WIRED. There is
// no App installed, no private key, no webhook secret and no endpoint reachable
// from outside the process; creating those and deciding what the App may write
// to is D4, and it is a human's.
//
// The tests drive this against a local server returning recorded responses, so
// the package still builds, runs and passes with no credential and no network.
// What they establish is that the real client maps GitHub's awkward answers to
// the SAME errors the hostile fake produces — because every caller in this
// repository was written against the fake, and a real client that reported a
// rate limit as a generic failure, or a 422 as success, would be correct in
// isolation and wrong everywhere it is used.
//
// The four that matter, each because the framework has a specific response to
// it:
//
//	422 on opening a pull request  → *ErrPRExists, carrying the existing one.
//	                                 GitHub does not return the existing PR on
//	                                 a duplicate, so a caller that assumed
//	                                 success would crash on an ordinary retry.
//	403/429 with rate-limit headers → *ErrRateLimited, with how long to wait.
//	an empty repository listing     → *ErrEmptyFleet, refused rather than acted
//	                                 on, because acting on it archives the
//	                                 whole fleet and the next sweep reports
//	                                 complete coverage of nothing.
//	a non-fast-forward push         → *ErrConflict, and never a force.

// maxResponseBytes bounds a response body, so a runaway or wedged endpoint
// cannot consume the worker.
const maxResponseBytes = 64 << 20

// defaultAPIBase is GitHub's REST root. It is a default rather than a constant
// because GitHub Enterprise is a different host, and because the tests point
// it at a local server.
const defaultAPIBase = "https://api.github.com"

// AppCredentials is what an installed GitHub App authenticates with.
//
// The private key is held here and nowhere else in the process. Nothing in
// this struct is logged, rendered or returned: the one thing that leaves is a
// short-lived installation token, and it leaves only to the git invocation
// that needs it.
type AppCredentials struct {
	// AppID is the App's numeric identifier.
	AppID string
	// InstallationID identifies this installation of the App.
	InstallationID string
	// PrivateKeyPEM is the App's RSA private key.
	PrivateKeyPEM []byte
}

// AppClient is the live gh.App, over GitHub's REST API.
type AppClient struct {
	// BaseURL is the REST root. Empty means api.github.com.
	BaseURL string
	// HTTP is the client. Nil uses a bounded-timeout client.
	HTTP *http.Client
	// Creds authenticates as the App.
	Creds AppCredentials
	// Now supplies the current time, for JWT claims.
	Now func() time.Time
	// KnownRepos is how many repositories the registry already holds.
	//
	// It is here because an empty listing cannot be judged without it: zero
	// repositories is a legitimate answer for a new installation and a
	// catastrophe for an established one, and the client cannot tell which
	// without being told what was there before.
	KnownRepos int
}

var _ App = (*AppClient)(nil)

// Repositories lists every repository the App is installed on.
func (c *AppClient) Repositories(ctx context.Context) ([]RemoteRepo, error) {
	token, _, err := c.appToken(ctx)
	if err != nil {
		return nil, err
	}

	var out []RemoteRepo
	// Pagination by explicit page number, with the server's own total
	// consulted below. Following `Link: rel=next` would be more idiomatic and
	// would also make a LOST page invisible: the header simply stops, and a
	// short list is indistinguishable from a complete one.
	for page := 1; ; page++ {
		var body struct {
			TotalCount   int `json:"total_count"`
			Repositories []struct {
				FullName      string `json:"full_name"`
				DefaultBranch string `json:"default_branch"`
				Archived      bool   `json:"archived"`
				Private       bool   `json:"private"`
				Language      string `json:"language"`
			} `json:"repositories"`
		}
		path := fmt.Sprintf("/installation/repositories?per_page=100&page=%d", page)
		if err := c.do(ctx, http.MethodGet, path, token, nil, &body); err != nil {
			return nil, err
		}

		for _, r := range body.Repositories {
			repo := RemoteRepo{
				FullName:      r.FullName,
				DefaultBranch: r.DefaultBranch,
				Archived:      r.Archived,
				Private:       r.Private,
			}
			if r.Language != "" {
				repo.Languages = []string{strings.ToLower(r.Language)}
			}
			out = append(out, repo)
		}

		if len(body.Repositories) == 0 || len(out) >= body.TotalCount {
			// The server's own count is what makes a lost page detectable.
			// Without it, pagination that stopped early produces a plausible
			// short list, which is the dangerous shape: every repository
			// beyond the cut looks archived, and nothing was scanned.
			if body.TotalCount > 0 && len(out) < body.TotalCount {
				return nil, fmt.Errorf(
					"gh: the installation declares %d repositories and pagination yielded %d. "+
						"A short list cannot be told apart from a complete one, and acting on it "+
						"would silently drop %d repositories out of scope",
					body.TotalCount, len(out), body.TotalCount-len(out))
			}
			break
		}
		if page > 200 {
			return nil, fmt.Errorf("gh: pagination did not terminate after %d pages", page)
		}
	}

	if len(out) == 0 {
		// Refused rather than returned. An empty list is what a revoked
		// installation, an expired credential and a lost first page all look
		// like, and it cannot be told apart from a genuinely empty
		// organisation.
		return nil, &ErrEmptyFleet{Known: c.KnownRepos}
	}
	return out, nil
}

// Tags lists a repository's tags, newest first.
func (c *AppClient) Tags(ctx context.Context, repo string) ([]Tag, error) {
	token, _, err := c.appToken(ctx)
	if err != nil {
		return nil, err
	}

	var tags []struct {
		Name   string `json:"name"`
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := c.do(ctx, http.MethodGet, "/repos/"+repo+"/tags?per_page=100", token, nil, &tags); err != nil {
		return nil, err
	}

	out := make([]Tag, 0, len(tags))
	for _, t := range tags {
		// The tag listing carries no date. Rather than inventing one — a
		// zero time would sort as 1 January year 1, and time.Now() would
		// claim every tag was published this instant — each tag's commit date
		// is fetched. VM-AD §12.3 waits on these, so a wrong date delays or
		// triggers a wave.
		at, err := c.commitDate(ctx, token, repo, t.Commit.SHA)
		if err != nil {
			return nil, err
		}
		out = append(out, Tag{Name: t.Name, At: at})
	}
	sortTagsNewestFirst(out)
	return out, nil
}

func (c *AppClient) commitDate(ctx context.Context, token, repo, sha string) (time.Time, error) {
	if sha == "" {
		return time.Time{}, fmt.Errorf("gh: a tag in %s carries no commit sha, so its date cannot "+
			"be established; wave 2 triggers on tag dates and a guessed one would fire a wave", repo)
	}
	var body struct {
		Commit struct {
			Committer struct {
				Date time.Time `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if err := c.do(ctx, http.MethodGet, "/repos/"+repo+"/commits/"+sha, token, nil, &body); err != nil {
		return time.Time{}, err
	}
	return body.Commit.Committer.Date.UTC(), nil
}

// InstallationToken returns a short-lived token for a repository.
func (c *AppClient) InstallationToken(ctx context.Context, repo string) (string, time.Time, error) {
	return c.appToken(ctx)
}

// appToken exchanges the App JWT for an installation token.
func (c *AppClient) appToken(ctx context.Context) (string, time.Time, error) {
	jwt, err := c.signJWT()
	if err != nil {
		return "", time.Time{}, err
	}

	var body struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	path := "/app/installations/" + c.Creds.InstallationID + "/access_tokens"
	if err := c.do(ctx, http.MethodPost, path, "Bearer "+jwt, nil, &body); err != nil {
		return "", time.Time{}, err
	}
	if body.Token == "" {
		return "", time.Time{}, fmt.Errorf("gh: the installation token response carried no token")
	}
	return "token " + body.Token, body.ExpiresAt.UTC(), nil
}

// signJWT builds the App's authentication assertion (RS256).
func (c *AppClient) signJWT() (string, error) {
	if c.Creds.AppID == "" {
		return "", fmt.Errorf("gh: no App ID is configured")
	}
	if len(c.Creds.PrivateKeyPEM) == 0 {
		return "", fmt.Errorf("gh: no App private key is configured")
	}

	key, err := parseRSAKey(c.Creds.PrivateKeyPEM)
	if err != nil {
		return "", err
	}

	now := c.now()
	// Backdated by a minute, as GitHub's own documentation advises, because a
	// JWT whose iat is in the future by even a second is rejected and clocks
	// drift. Expiry is short: this assertion exists only to be exchanged.
	claims := map[string]any{
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": c.Creds.AppID,
	}

	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("gh: signing the App assertion: %w", err)
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

func parseRSAKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("gh: the App private key is not PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("gh: the App private key is neither PKCS#1 nor PKCS#8: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("gh: the App private key is a %T; GitHub Apps sign with RSA", parsed)
	}
	return key, nil
}

func (c *AppClient) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c *AppClient) base() string {
	if c.BaseURL != "" {
		return strings.TrimSuffix(c.BaseURL, "/")
	}
	return defaultAPIBase
}

func (c *AppClient) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (c *AppClient) do(ctx context.Context, method, path, auth string, in, out any) error {
	return request(ctx, c.client(), method, c.base()+path, auth, in, out)
}

// --- the shared request path -------------------------------------------------

// request performs one API call and maps the answer.
//
// The error mapping is the substance of this file. Every caller in this
// repository was written against the hostile fake, so a real client that
// reported a rate limit as a generic failure would be correct in isolation and
// would break the backoff everywhere it is used.
func request(ctx context.Context, client *http.Client, method, url, auth string, in, out any) error {
	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("gh: encoding the request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("gh: building the request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "wanaware-vulnframework/1.0")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("gh: %s %s: %w", method, redactURL(url), err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("gh: reading the response to %s %s: %w", method, redactURL(url), err)
	}

	if wait, limited := rateLimit(resp); limited {
		return &ErrRateLimited{RetryAfter: wait}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &apiError{
			Status:  resp.StatusCode,
			Method:  method,
			URL:     redactURL(url),
			Message: message(payload),
			Body:    payload,
		}
	}

	if out == nil || len(payload) == 0 {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("gh: the response to %s %s did not parse: %w", method, redactURL(url), err)
	}
	return nil
}

// rateLimit reports whether the response is a rate limit, and how long to wait.
//
// GitHub expresses this three ways and the framework has to recognise all of
// them: a 429 with Retry-After, a 403 with x-ratelimit-remaining at zero and a
// reset timestamp, and a 403 with Retry-After for a secondary limit. Missing
// one means hammering an endpoint that has already said no.
func rateLimit(resp *http.Response) (time.Duration, bool) {
	status := resp.StatusCode
	if status != http.StatusTooManyRequests && status != http.StatusForbidden {
		return 0, false
	}

	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second, true
		}
	}

	remaining := strings.TrimSpace(resp.Header.Get("X-RateLimit-Remaining"))
	if remaining != "0" {
		// A 403 that is not a rate limit is a permissions problem, and
		// retrying it after a wait would hide a revoked installation behind a
		// backoff loop.
		return 0, false
	}
	reset := strings.TrimSpace(resp.Header.Get("X-RateLimit-Reset"))
	if reset == "" {
		// Rate limited with no reset time. A short wait rather than none:
		// the server has said stop, and the absence of a hint is not
		// permission to continue.
		return time.Minute, true
	}
	epoch, err := strconv.ParseInt(reset, 10, 64)
	if err != nil {
		return time.Minute, true
	}
	wait := time.Until(time.Unix(epoch, 0))
	if wait < 0 {
		wait = 0
	}
	return wait, true
}

// apiError is a non-2xx answer.
type apiError struct {
	Status  int
	Method  string
	URL     string
	Message string
	Body    []byte
}

func (e *apiError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("gh: %s %s: HTTP %d: %s", e.Method, e.URL, e.Status, e.Message)
	}
	return fmt.Sprintf("gh: %s %s: HTTP %d", e.Method, e.URL, e.Status)
}

// Status exposes the code for callers that distinguish on it.
func (e *apiError) StatusCode() int { return e.Status }

// message pulls GitHub's own error text out of a response.
func message(payload []byte) string {
	var body struct {
		Message string `json:"message"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return strings.TrimSpace(excerpt(string(payload)))
	}
	parts := []string{}
	if body.Message != "" {
		parts = append(parts, body.Message)
	}
	for _, e := range body.Errors {
		if e.Message != "" {
			parts = append(parts, e.Message)
		}
	}
	return strings.Join(parts, "; ")
}

// redactURL strips any query string before an error is rendered.
//
// Nothing in this client puts a credential in a query string, and this is here
// so that nothing later can: an error message is the one piece of a failed
// request that reliably reaches a log.
func redactURL(url string) string {
	if i := strings.IndexByte(url, '?'); i >= 0 {
		return url[:i]
	}
	return url
}

func excerpt(s string) string {
	const limit = 240
	s = strings.TrimSpace(s)
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}

func sortTagsNewestFirst(tags []Tag) {
	for i := 1; i < len(tags); i++ {
		for j := i; j > 0 && tags[j].At.After(tags[j-1].At); j-- {
			tags[j], tags[j-1] = tags[j-1], tags[j]
		}
	}
}
