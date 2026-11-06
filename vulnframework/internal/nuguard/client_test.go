package nuguard_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/nuguard"
	"github.com/wanaware/vulnframework/internal/nuguard/nuguardfake"
)

const fixture = "../../testdata/fixtures/nuguard/quickstart-partial.json"

// Credentials for the fake, assembled at run time (no key-like string is
// committed). Neither is shaped like a real NuGuard key or GitHub token.
var (
	testKey   = strings.Join([]string{"fake", "nuguard", "key", "4f1c"}, "-")
	testToken = strings.Join([]string{"fake", "github", "token", "9d2e7a"}, "-")
)

func token() (string, error) { return testToken, nil }

func readFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// noSleep records waits instead of taking them.
type noSleep struct{ waits []time.Duration }

func (n *noSleep) sleep(ctx context.Context, d time.Duration) error {
	n.waits = append(n.waits, d)
	return ctx.Err()
}

func client(fake *nuguardfake.Server, ns *noSleep) *nuguard.Client {
	return &nuguard.Client{
		BaseURL: fake.URL, APIKey: func() (string, error) { return testKey, nil },
		Sleep: ns.sleep, Jitter: func() float64 { return 0.5 },
	}
}

func request(repo, ref string) nuguard.ScanCreateRequest {
	return nuguard.ScanCreateRequest{
		RepoURL: "https://github.com/" + repo, Ref: ref, ClientReference: "S-000001",
		Options: nuguard.ScanOptions{Tools: []nuguard.ToolName{nuguard.ToolNGARules}, MinSeverity: nuguard.SeverityLow},
	}
}

func TestScanWaitsForTheResultAndSendsTheContract(t *testing.T) {
	fake := nuguardfake.New(testKey, "0.9.15")
	defer fake.Close()
	fake.Default = &nuguardfake.Script{Result: readFixture(t), Polls: 2}
	ns := &noSleep{}
	c := client(fake, ns)
	c.Wait = 45

	key := nuguard.IdempotencyKey("S-000001", "acme/app", "abc123")
	job, raw, err := c.Scan(context.Background(), request("acme/app", "abc123"), key, token)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != nuguard.StatusPartial || job.CommitSHA == nil || *job.CommitSHA != "abc123" {
		t.Errorf("job: %+v", job)
	}
	res, err := nuguard.ParseResult(raw)
	if err != nil || res.Job.ID != job.ID {
		t.Fatalf("result: %v %+v", err, res.Job)
	}

	subs := fake.Submissions()
	if len(subs) != 1 {
		t.Fatalf("%d submissions", len(subs))
	}
	s := subs[0]
	if s.Prefer != "wait=45" || s.IdempotencyKey != key || s.Ref != "abc123" || s.ClientRef != "S-000001" {
		t.Errorf("submission: %+v", s)
	}
	if s.GitHubToken != testToken {
		t.Error("the GitHub token did not arrive in the github_token field")
	}
	// The token is only in the body; the key only in Authorization.
	for _, h := range fake.Headers() {
		for name, vals := range h {
			for _, v := range vals {
				if strings.Contains(v, testToken) {
					t.Errorf("the GitHub token was sent in the %s header", name)
				}
				if strings.Contains(v, testKey) && name != "Authorization" {
					t.Errorf("the API key was sent in the %s header", name)
				}
			}
		}
	}
	// Two reads answer running and the third finds it finished: polled with
	// doubling backoff, 1s, 2s, 4s (jitter fixed at the midpoint).
	if fmt.Sprint(ns.waits) != "[1s 2s 4s]" {
		t.Errorf("poll waits: %v", ns.waits)
	}
	if !strings.HasPrefix(key, "vf-S-000001-") || len(key) != len("vf-S-000001-")+16 {
		t.Errorf("idempotency key %q", key)
	}
}

func TestTheSameKeyReturnsTheSameJob(t *testing.T) {
	fake := nuguardfake.New(testKey, "0.9.15")
	defer fake.Close()
	fake.Default = &nuguardfake.Script{Result: readFixture(t), Polls: 5}
	c := client(fake, &noSleep{})
	a, err := c.Submit(context.Background(), request("acme/app", "abc"), "k1", token)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Submit(context.Background(), request("acme/app", "abc"), "k1", token)
	if err != nil || b.ID != a.ID {
		t.Errorf("resubmitting under the same key started %q, want the original %q (%v)", b.ID, a.ID, err)
	}
}

// worker_lost and credential_unavailable release the key: the scan is
// resubmitted once, under the same key, and its result used.
func TestALostJobIsResubmittedOnceUnderTheSameKey(t *testing.T) {
	for _, code := range []string{"worker_lost", "credential_unavailable"} {
		t.Run(code, func(t *testing.T) {
			fake := nuguardfake.New(testKey, "0.9.15")
			defer fake.Close()
			fake.Default = &nuguardfake.Script{ErrorCode: code, Polls: 1, Then: &nuguardfake.Script{Result: readFixture(t)}}
			c := client(fake, &noSleep{})
			_, raw, err := c.Scan(context.Background(), request("acme/app", "abc"), "k1", token)
			if err != nil || raw == nil {
				t.Fatalf("Scan: %v", err)
			}
			subs := fake.Submissions()
			if len(subs) != 2 || subs[0].IdempotencyKey != "k1" || subs[1].IdempotencyKey != "k1" {
				t.Errorf("submissions: %+v", subs)
			}
		})
	}
	t.Run("only once", func(t *testing.T) {
		fake := nuguardfake.New(testKey, "0.9.15")
		defer fake.Close()
		lost := &nuguardfake.Script{ErrorCode: "worker_lost"}
		lost.Then = lost
		fake.Default = lost
		_, _, err := client(fake, &noSleep{}).Scan(context.Background(), request("acme/app", "abc"), "k1", token)
		var je *nuguard.JobError
		if !errors.As(err, &je) || je.Code != "worker_lost" {
			t.Fatalf("err = %v, want the second worker_lost", err)
		}
		if n := len(fake.Submissions()); n != 2 {
			t.Errorf("%d submissions, want 2", n)
		}
	})
}

func TestAFailedJobCarriesItsCode(t *testing.T) {
	fake := nuguardfake.New(testKey, "0.9.15")
	defer fake.Close()
	fake.Default = &nuguardfake.Script{ErrorCode: "repo_too_large"}
	_, raw, err := client(fake, &noSleep{}).Scan(context.Background(), request("acme/app", "abc"), "k", token)
	var je *nuguard.JobError
	if !errors.As(err, &je) || je.Code != "repo_too_large" || je.Status != nuguard.StatusFailed || raw != nil {
		t.Fatalf("err = %v raw=%d", err, len(raw))
	}
}

func TestRetryAfterIsHonoured(t *testing.T) {
	fake := nuguardfake.New(testKey, "0.9.15")
	defer fake.Close()
	fake.Default = &nuguardfake.Script{Result: readFixture(t)}
	fake.RateLimitOnce = 7
	ns := &noSleep{}
	if _, _, err := client(fake, ns).Scan(context.Background(), request("acme/app", "abc"), "k", token); err != nil {
		t.Fatal(err)
	}
	if len(ns.waits) == 0 || ns.waits[0] != 7*time.Second {
		t.Errorf("waits %v, want the 7s Retry-After first", ns.waits)
	}
}

// A caller that stops waiting cancels the job, on a context of its own.
func TestStoppingCancelsTheJob(t *testing.T) {
	fake := nuguardfake.New(testKey, "0.9.15")
	defer fake.Close()
	fake.Default = &nuguardfake.Script{Hang: true}
	ctx, cancel := context.WithCancel(context.Background())
	polls := 0
	c := client(fake, nil)
	c.Sleep = func(ctx context.Context, _ time.Duration) error {
		if polls++; polls == 3 {
			cancel()
		}
		return ctx.Err()
	}
	_, _, err := c.Scan(ctx, request("acme/app", "abc"), "k", token)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got := fake.Cancels(); len(got) != 1 {
		t.Errorf("cancels: %v, want the one job", got)
	}
}

func TestPlainHTTPOnlyToLoopback(t *testing.T) {
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"http://127.0.0.1:1", true}, {"http://localhost:1", true}, {"http://[::1]:1", true},
		{"https://nuguard.internal:8443", true},
		{"http://nuguard.internal:8080", false}, {"http://10.0.0.5:8080", false},
		{"ftp://127.0.0.1", false}, {"https://user:hunter2-secret@nuguard.internal", false},
	} {
		c := &nuguard.Client{BaseURL: tc.url, APIKey: func() (string, error) { return testKey, nil },
			HTTP: &http.Client{Transport: refuseAll{}}}
		_, err := c.Capabilities(context.Background())
		refusedByPolicy := err != nil && !strings.Contains(err.Error(), "test transport")
		if tc.ok == refusedByPolicy {
			t.Errorf("%s: err = %v", tc.url, err)
		}
		if err != nil && strings.Contains(err.Error(), "hunter2-secret") {
			t.Errorf("%s: the error echoes the URL's password: %v", tc.url, err)
		}
	}
}

type refuseAll struct{}

func (refuseAll) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("test transport: not sent")
}

// leakyTransport fails every request with an error that quotes the request
// in full, as a careless proxy library might. Nothing the client returns may
// carry either credential.
type leakyTransport struct{}

func (leakyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body := ""
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}
	return nil, fmt.Errorf("proxy refused %s %s auth=%q body=%s", r.Method, r.URL, r.Header.Get("Authorization"), body)
}

func TestNoErrorCarriesACredential(t *testing.T) {
	c := &nuguard.Client{BaseURL: "http://127.0.0.1:9", APIKey: func() (string, error) { return testKey, nil },
		HTTP: &http.Client{Transport: leakyTransport{}}}
	_, err := c.Submit(context.Background(), request("acme/app", "abc"), "k", token)
	if err == nil {
		t.Fatal("no error")
	}
	if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), testKey) {
		t.Errorf("an error carries a credential: %v", err)
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Errorf("the error was not scrubbed (did the transport see the credentials?): %v", err)
	}
	if _, err := c.Capabilities(context.Background()); err == nil || strings.Contains(err.Error(), testKey) {
		t.Errorf("capabilities: %v", err)
	}
}

func TestEnumsAreStrictAndFieldsTolerated(t *testing.T) {
	base := readFixture(t)
	if _, err := nuguard.ParseResult(base); err != nil {
		t.Fatalf("the captured result does not parse: %v", err)
	}
	mutate := func(f func(map[string]any)) []byte {
		var doc map[string]any
		if err := json.Unmarshal(base, &doc); err != nil {
			t.Fatal(err)
		}
		f(doc)
		b, _ := json.Marshal(doc)
		return b
	}
	for name, doc := range map[string][]byte{
		"job status":   mutate(func(d map[string]any) { d["job"].(map[string]any)["status"] = "half_done" }),
		"finding kind": mutate(func(d map[string]any) { d["findings"].([]any)[0].(map[string]any)["kind"] = "vibes" }),
		"severity":     mutate(func(d map[string]any) { d["findings"].([]any)[0].(map[string]any)["severity"] = "spicy" }),
		"tool run status": mutate(func(d map[string]any) {
			d["coverage"].(map[string]any)["tool_runs"].([]any)[0].(map[string]any)["status"] = "meh"
		}),
		"schema version": mutate(func(d map[string]any) { d["schema_version"] = "2.0" }),
	} {
		if _, err := nuguard.ParseResult(doc); err == nil {
			t.Errorf("an unknown %s was accepted", name)
		}
	}
	if _, err := nuguard.ParseResult(mutate(func(d map[string]any) { d["brand_new_field"] = 1 })); err != nil {
		t.Errorf("a new field was rejected: %v", err)
	}
}

func TestReadinessAndCapabilities(t *testing.T) {
	fake := nuguardfake.New(testKey, "0.9.15")
	defer fake.Close()
	c := client(fake, &noSleep{})
	if h, err := c.Ready(context.Background()); err != nil || h.Status != "ok" {
		t.Errorf("ready: %+v %v", h, err)
	}
	fake.NotReady = true
	if h, err := c.Ready(context.Background()); err != nil || h.Status != "not_ready" {
		t.Errorf("not ready: %+v %v", h, err)
	}
	caps, err := c.Capabilities(context.Background())
	if err != nil || caps.NuGuardVersion != "0.9.15" || len(caps.ToolsAllowed) == 0 {
		t.Errorf("capabilities: %+v %v", caps, err)
	}
	bad := &nuguard.Client{BaseURL: fake.URL, APIKey: func() (string, error) { return "wrong", nil }}
	_, err = bad.Capabilities(context.Background())
	var ae *nuguard.APIError
	if !errors.As(err, &ae) || ae.Status != 401 || ae.Code() != "unauthorized" {
		t.Errorf("a wrong key: %v", err)
	}
}
