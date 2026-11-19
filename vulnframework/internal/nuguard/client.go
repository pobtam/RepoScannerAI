package nuguard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client talks to one NuGuard service.
//
// Two credentials pass through it and neither is ever a field: the API key
// comes from APIKey, and the GitHub token from the function handed to Scan,
// each read at the moment a request is written, so no %+v of a Client or a
// request can print them (the pattern gh.TokenClient.Token set). The API key
// is sent only as a bearer token; the GitHub token only in the github_token
// field of a scan submission. Both are scrubbed from every error this client
// returns.
type Client struct {
	// BaseURL is the service root, without /v1. It must be https, or plain
	// http to a loopback host only: the API key and a GitHub token cross this
	// connection.
	BaseURL string
	APIKey  func() (string, error)
	// HTTP is the client. Nil uses one with bounded timeouts. Redirects are
	// refused whatever is supplied: a scan submission carries a token, and
	// the API never redirects.
	HTTP *http.Client

	// Wait is the Prefer: wait=N on submission, in seconds; zero means 30,
	// and the service caps it at 120.
	Wait int
	// FirstPoll and MaxPoll bound the polling backoff; zero means 1s and 15s.
	FirstPoll, MaxPoll time.Duration
	// MaxRetryWait bounds the total time spent honouring Retry-After on one
	// request; zero means two minutes.
	MaxRetryWait time.Duration

	// Sleep and Jitter are injectable for tests.
	Sleep  func(context.Context, time.Duration) error
	Jitter func() float64
}

// APIError is a non-success HTTP answer.
type APIError struct {
	Method  string
	Path    string
	Status  int
	Problem *ProblemDetail
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("nuguard: %s %s answered %d", e.Method, e.Path, e.Status)
	if e.Problem != nil {
		msg += " " + e.Problem.Code
		if e.Problem.Detail != nil && *e.Problem.Detail != "" {
			msg += ": " + *e.Problem.Detail
		}
	}
	return msg
}

// Code is the problem code, or "" where the answer carried none.
func (e *APIError) Code() string {
	if e.Problem == nil {
		return ""
	}
	return e.Problem.Code
}

// JobError is a scan that ended without a result: failed, cancelled or
// expired, with the service's code for why.
type JobError struct {
	JobID  string
	Status ScanStatus
	Code   string
	Detail string
}

func (e *JobError) Error() string {
	msg := fmt.Sprintf("nuguard: scan %s ended %s", e.JobID, e.Status)
	if e.Code != "" {
		msg += " (" + e.Code + ")"
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// IdempotencyKey is the key a scan of one repository at one commit is
// submitted under in one run, so a retry after a lost answer finds the same
// job instead of starting a second scan.
func IdempotencyKey(runID, repo, commit string) string {
	sum := sha256.Sum256([]byte(repo + "@" + commit))
	return "vf-" + runID + "-" + hex.EncodeToString(sum[:])[:16]
}

// Scan submits a scan, waits for it to end, and returns the job and, for a
// succeeded or partial job, the result exactly as received.
//
// A job that fails because the service lost it (worker_lost) or lost its
// credential on a restart (credential_unavailable) is resubmitted once under
// the same key, which the service releases for exactly those two codes. If
// ctx ends first, the job is cancelled, best effort, and ctx's error is
// returned.
func (c *Client) Scan(ctx context.Context, req ScanCreateRequest, key string, githubToken func() (string, error)) (ScanJob, []byte, error) {
	resubmitted := false
	for {
		job, err := c.Submit(ctx, req, key, githubToken)
		if err != nil {
			return ScanJob{}, nil, err
		}
		job, err = c.waitFor(ctx, job)
		if err != nil {
			return job, nil, err
		}
		switch job.Status {
		case StatusSucceeded, StatusPartial:
			res, err := c.Result(ctx, job.ID)
			return job, res, err
		}
		jerr := jobError(job)
		if !resubmitted && (jerr.Code == "worker_lost" || jerr.Code == "credential_unavailable") {
			resubmitted = true
			continue
		}
		return job, nil, jerr
	}
}

func jobError(job ScanJob) *JobError {
	e := &JobError{JobID: job.ID, Status: job.Status}
	if job.Error != nil {
		e.Code = job.Error.Code
		if job.Error.Detail != nil {
			e.Detail = *job.Error.Detail
		}
	}
	if e.Code == "" && job.Status == StatusExpired {
		e.Code = "expired"
	}
	return e
}

// waitFor polls a job until it is terminal, with capped exponential backoff
// and jitter, cancelling it if ctx ends first.
func (c *Client) waitFor(ctx context.Context, job ScanJob) (ScanJob, error) {
	delay := c.firstPoll()
	for !job.Status.Terminal() {
		if err := c.sleep(ctx, c.jittered(delay)); err != nil {
			c.cancelQuietly(job.ID)
			return job, err
		}
		next, err := c.Get(ctx, job.ID)
		if err != nil {
			if ctx.Err() != nil {
				c.cancelQuietly(job.ID)
				return job, ctx.Err()
			}
			return job, err
		}
		job = next
		if delay *= 2; delay > c.maxPoll() {
			delay = c.maxPoll()
		}
	}
	return job, nil
}

// cancelQuietly asks the service to stop a job whose caller has gone, on a
// fresh short context because the caller's has ended. Best effort: a cancel
// that fails leaves a job the service's own timeout ends.
func (c *Client) cancelQuietly(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = c.Cancel(ctx, id)
}

// Submit posts a scan. A job already submitted under key is returned as it
// stands.
func (c *Client) Submit(ctx context.Context, req ScanCreateRequest, key string, githubToken func() (string, error)) (ScanJob, error) {
	wire := struct {
		ScanCreateRequest
		GitHubToken string `json:"github_token,omitempty"`
	}{ScanCreateRequest: req}
	var secrets []string
	if githubToken != nil {
		t, err := githubToken()
		if err != nil {
			return ScanJob{}, fmt.Errorf("nuguard: no GitHub token for the scan: %w", err)
		}
		wire.GitHubToken = strings.TrimSpace(t)
		secrets = append(secrets, wire.GitHubToken)
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return ScanJob{}, fmt.Errorf("nuguard: encoding the scan request: %w", err)
	}
	headers := map[string]string{"Prefer": "wait=" + strconv.Itoa(c.wait())}
	if key != "" {
		headers["Idempotency-Key"] = key
	}
	var job ScanJob
	if err := c.do(ctx, http.MethodPost, "/v1/scans", body, headers, &job, secrets); err != nil {
		return ScanJob{}, err
	}
	return job, nil
}

// Get reads a job's status.
func (c *Client) Get(ctx context.Context, id string) (ScanJob, error) {
	var job ScanJob
	err := c.do(ctx, http.MethodGet, "/v1/scans/"+url.PathEscape(id), nil, nil, &job, nil)
	return job, err
}

// Result returns a finished job's result exactly as the service sent it, so
// the bytes stored are the bytes its result_sha256 describes. It is checked
// to decode before it is returned.
func (c *Client) Result(ctx context.Context, id string) ([]byte, error) {
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/v1/scans/"+url.PathEscape(id)+"/result", nil, nil, &raw, nil); err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == http.StatusGone {
			return nil, &JobError{JobID: id, Status: StatusExpired, Code: "expired", Detail: "the result passed its retention time"}
		}
		return nil, err
	}
	if _, err := ParseResult(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// Cancel asks the service to stop a job.
func (c *Client) Cancel(ctx context.Context, id string) (ScanJob, error) {
	var job ScanJob
	err := c.do(ctx, http.MethodPost, "/v1/scans/"+url.PathEscape(id)+"/cancel", nil, nil, &job, nil)
	return job, err
}

// Ready reports the service's readiness. A 503 is an answer, not an error:
// the status says not_ready and names the failing checks.
func (c *Client) Ready(ctx context.Context) (HealthStatus, error) {
	var h HealthStatus
	err := c.do(ctx, http.MethodGet, "/v1/readyz", nil, nil, &h, nil)
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == http.StatusServiceUnavailable {
		return HealthStatus{Status: "not_ready"}, nil
	}
	return h, err
}

// Capabilities reads what the service can do and which versions it runs.
func (c *Client) Capabilities(ctx context.Context) (Capabilities, error) {
	var caps Capabilities
	err := c.do(ctx, http.MethodGet, "/v1/capabilities", nil, nil, &caps, nil)
	return caps, err
}

// do performs one request, honouring Retry-After on 429 and 503 up to
// MaxRetryWait, and decodes a success into out.
func (c *Client) do(ctx context.Context, method, path string, body []byte, headers map[string]string, out any, secrets []string) error {
	base, err := c.base()
	if err != nil {
		return err
	}
	key, err := c.apiKey()
	if err != nil {
		return err
	}
	secrets = append(secrets, key)

	waited := time.Duration(0)
	for {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
		if err != nil {
			return scrub(fmt.Errorf("nuguard: building %s %s: %w", method, path, err), secrets)
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "wanaware-vulnframework/1.0")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return scrub(fmt.Errorf("nuguard: %s %s: %w", method, path, err), secrets)
		}
		payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if err != nil {
			return scrub(fmt.Errorf("nuguard: reading %s %s: %w", method, path, err), secrets)
		}

		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) &&
			path != "/v1/readyz" {
			wait := retryAfter(resp.Header.Get("Retry-After"), time.Now())
			if waited+wait <= c.maxRetryWait() {
				if err := c.sleep(ctx, wait); err != nil {
					return err
				}
				waited += wait
				continue
			}
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			ae := &APIError{Method: method, Path: path, Status: resp.StatusCode}
			var p ProblemDetail
			if json.Unmarshal(payload, &p) == nil && p.Code != "" {
				ae.Problem = &p
			}
			return scrub(ae, secrets)
		}
		if err := json.Unmarshal(payload, out); err != nil {
			return scrub(fmt.Errorf("nuguard: the answer to %s %s does not parse: %w", method, path, err), secrets)
		}
		return nil
	}
}

// retryAfter reads a Retry-After header: seconds, or an HTTP date. Absent or
// unreadable, it waits five seconds.
func retryAfter(h string, now time.Time) time.Duration {
	h = strings.TrimSpace(h)
	if s, err := strconv.Atoi(h); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
		return 0
	}
	return 5 * time.Second
}

// scrub removes credentials from an error's text. The error keeps its type
// where the text holds none, so callers can still inspect an APIError.
func scrub(err error, secrets []string) error {
	text := err.Error()
	clean := text
	for _, s := range secrets {
		if s != "" {
			clean = strings.ReplaceAll(clean, s, "[redacted]")
		}
	}
	if clean == text {
		return err
	}
	return errors.New(clean)
}

// CheckURL reports whether the configured service URL is one this client
// will use, without contacting it.
func (c *Client) CheckURL() error {
	_, err := c.base()
	return err
}

// base checks the configured root: https, or http to a loopback host, and no
// userinfo. The error never echoes the URL, which may hold a password.
func (c *Client) base() (string, error) {
	u, err := url.Parse(strings.TrimSpace(c.BaseURL))
	if err != nil || u.Host == "" {
		return "", errors.New("nuguard: the service URL is not an absolute URL")
	}
	if u.User != nil {
		return "", errors.New("nuguard: the service URL must not carry a user or password")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopback(u.Hostname()) {
			return "", errors.New("nuguard: plain http is allowed only to a loopback host; " +
				"the API key and a GitHub token cross this connection")
		}
	default:
		return "", fmt.Errorf("nuguard: the service URL scheme must be https, not %q", u.Scheme)
	}
	return strings.TrimSuffix(u.Scheme+"://"+u.Host+u.Path, "/"), nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) apiKey() (string, error) {
	if c.APIKey == nil {
		return "", errors.New("nuguard: no API key configured")
	}
	k, err := c.APIKey()
	if err != nil {
		return "", err
	}
	if k = strings.TrimSpace(k); k == "" {
		return "", errors.New("nuguard: the API key is empty")
	}
	return k, nil
}

func (c *Client) client() *http.Client {
	base := c.HTTP
	if base == nil {
		// Long enough for a submission held open by Prefer: wait=120.
		base = &http.Client{Timeout: 3 * time.Minute}
	}
	cl := *base
	cl.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("nuguard: refusing a redirect")
	}
	return &cl
}

func (c *Client) wait() int {
	switch {
	case c.Wait <= 0:
		return 30
	case c.Wait > 120:
		return 120
	default:
		return c.Wait
	}
}

func (c *Client) firstPoll() time.Duration {
	if c.FirstPoll > 0 {
		return c.FirstPoll
	}
	return time.Second
}

func (c *Client) maxPoll() time.Duration {
	if c.MaxPoll > 0 {
		return c.MaxPoll
	}
	return 15 * time.Second
}

func (c *Client) maxRetryWait() time.Duration {
	if c.MaxRetryWait > 0 {
		return c.MaxRetryWait
	}
	return 2 * time.Minute
}

// jittered spreads d by up to a fifth either way, so many workers polling one
// service do not arrive together.
func (c *Client) jittered(d time.Duration) time.Duration {
	j := rand.Float64
	if c.Jitter != nil {
		j = c.Jitter
	}
	return time.Duration(float64(d) * (0.8 + 0.4*j()))
}

func (c *Client) sleep(ctx context.Context, d time.Duration) error {
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
