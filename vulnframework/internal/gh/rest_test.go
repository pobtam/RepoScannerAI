package gh_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/gh"
)

// The live GitHub client, driven against a local server.
//
// These tests are not about whether the happy path parses. They are about
// whether the real client maps GitHub's awkward answers to the SAME errors the
// hostile fake produces — because every caller in this repository was written
// against the fake, and a real client that reported a rate limit as a generic
// failure, or a 422 as a success, would be correct in isolation and wrong
// everywhere it is used.

// testKey is generated per run. No real key exists anywhere in this build, and
// none should be issued to a machine where the sandbox probe (D2) has not
// passed.
func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the test key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// route is a tiny handler that answers by path.
type route struct {
	status  int
	body    string
	headers map[string]string
}

func api(t *testing.T, routes map[string]route) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		seen = append(seen, key+queryOf(r))

		// Most specific first, so a test can answer page 2 differently from
		// page 1 — which is the only way a lost page is expressible.
		res, ok := routes[key+queryOf(r)]
		if !ok {
			res, ok = routes[key]
		}
		if !ok {
			if res, ok = routes[r.URL.Path]; !ok {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintf(w, `{"message":"no route for %s"}`, key)
				return
			}
		}
		for k, v := range res.headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		if res.status == 0 {
			res.status = http.StatusOK
		}
		w.WriteHeader(res.status)
		_, _ = w.Write([]byte(res.body))
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func queryOf(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return ""
	}
	return "?" + r.URL.RawQuery
}

const tokenRoute = "POST /app/installations/42/access_tokens"

func tokenResponse() route {
	return route{body: `{"token":"ghs_test_installation_token","expires_at":"2026-10-02T18:00:00Z"}`}
}

func appClient(t *testing.T, srv *httptest.Server, known int) *gh.AppClient {
	t.Helper()
	return &gh.AppClient{
		BaseURL:    srv.URL,
		KnownRepos: known,
		Creds: gh.AppCredentials{
			AppID: "123", InstallationID: "42", PrivateKeyPEM: testKey(t),
		},
	}
}

// --- authentication ----------------------------------------------------------

// TestTheAppAssertionIsASignedRS256JWT checks the shape GitHub requires.
//
// Not the signature's cryptographic validity, which crypto/rsa is responsible
// for, but the three things an App JWT is rejected for in practice: the wrong
// algorithm, an issuer that is not the App id, and an `iat` in the future —
// which happens from ordinary clock drift and produces an authentication
// failure that looks like a bad key.
func TestTheAppAssertionIsASignedRS256JWT(t *testing.T) {
	var assertion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertion = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"ghs_x","expires_at":"2026-10-02T18:00:00Z"}`))
	}))
	t.Cleanup(srv.Close)

	c := appClient(t, srv, 0)
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }

	if _, _, err := c.InstallationToken(context.Background(), "org/api"); err != nil {
		t.Fatalf("InstallationToken: %v", err)
	}

	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("the assertion is not a three-part JWT: %q", assertion)
	}

	var header struct{ Alg, Typ string }
	decodeSegment(t, parts[0], &header)
	if header.Alg != "RS256" {
		t.Errorf("alg = %q, want RS256; GitHub rejects anything else", header.Alg)
	}

	var claims struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	decodeSegment(t, parts[1], &claims)
	if claims.Iss != "123" {
		t.Errorf("iss = %q, want the App id", claims.Iss)
	}
	if claims.Iat >= now.Unix() {
		t.Errorf("iat is not backdated (iat=%d, now=%d). An assertion issued even a second into "+
			"the future is rejected, and clocks drift — the failure then looks like a bad key",
			claims.Iat, now.Unix())
	}
	if claims.Exp <= claims.Iat {
		t.Errorf("exp %d does not follow iat %d", claims.Exp, claims.Iat)
	}
	if claims.Exp-now.Unix() > 600 {
		t.Errorf("the assertion is valid for %ds; GitHub's maximum is 600", claims.Exp-now.Unix())
	}
}

func decodeSegment(t *testing.T, segment string, into any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decoding the JWT segment: %v", err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("parsing the JWT segment: %v", err)
	}
}

func TestAMissingKeyIsRefusedRatherThanAttempted(t *testing.T) {
	c := &gh.AppClient{BaseURL: "http://127.0.0.1:1", Creds: gh.AppCredentials{AppID: "1", InstallationID: "42"}}
	if _, err := c.Repositories(context.Background()); err == nil {
		t.Fatal("a client with no private key attempted a call")
	}
}

// --- the fleet listing -------------------------------------------------------

func TestRepositoriesListsTheInstallation(t *testing.T) {
	srv, _ := api(t, map[string]route{
		tokenRoute: tokenResponse(),
		"GET /installation/repositories?per_page=100&page=1": {body: `{"total_count":2,"repositories":[
			{"full_name":"org/api","default_branch":"main","language":"Go","archived":false,"private":true},
			{"full_name":"org/web","default_branch":"trunk","language":"JavaScript","archived":true,"private":false}]}`},
	})

	got, err := appClient(t, srv, 2).Repositories(context.Background())
	if err != nil {
		t.Fatalf("Repositories: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d repositories, want 2", len(got))
	}
	if got[0].FullName != "org/api" || got[0].DefaultBranch != "main" {
		t.Errorf("first repository = %+v", got[0])
	}
	if !got[1].Archived {
		t.Error("an archived repository did not come back archived; it would be scanned")
	}
	if len(got[0].Languages) != 1 || got[0].Languages[0] != "go" {
		t.Errorf("languages = %v, want [go] — adapter selection reads this", got[0].Languages)
	}
}

// TestAnEmptyListingIsRefusedNotActedOn is the one with the largest blast
// radius in this file.
//
// An empty list is what a revoked installation, an expired credential and a
// lost first page all look like, and it is indistinguishable from a genuinely
// empty organisation. Acting on it archives the entire fleet — and the next
// sweep then finds nothing to scan and reports complete coverage.
func TestAnEmptyListingIsRefusedNotActedOn(t *testing.T) {
	srv, _ := api(t, map[string]route{
		tokenRoute:                       tokenResponse(),
		"GET /installation/repositories": {body: `{"total_count":0,"repositories":[]}`},
	})

	_, err := appClient(t, srv, 57).Repositories(context.Background())
	if err == nil {
		t.Fatal("an empty installation listing was returned as a successful answer. Acting on it " +
			"archives the whole fleet, and the next sweep reports complete coverage of nothing")
	}
	var empty *gh.ErrEmptyFleet
	if !errors.As(err, &empty) {
		t.Fatalf("the refusal is not an *ErrEmptyFleet, so the caller cannot recognise it: %v", err)
	}
	if empty.Known != 57 {
		t.Errorf("Known = %d, want 57: the error must say how many the registry holds, or a reader "+
			"cannot judge how serious the empty answer is", empty.Known)
	}
}

// TestALostPageIsDetectedRatherThanAccepted is the quieter half of the same
// hazard.
//
// A truncated listing is a plausible SHORT list rather than an error, which is
// exactly what makes it dangerous: every repository past the cut silently
// leaves scope, and nothing reports the loss.
func TestALostPageIsDetectedRatherThanAccepted(t *testing.T) {
	srv, _ := api(t, map[string]route{
		tokenRoute: tokenResponse(),
		// The server declares five, hands back two on the first page, and
		// then an empty second page: a page was lost in between. This is what
		// makes it dangerous rather than merely wrong — the transfer looks
		// complete from every angle except the declared total.
		"GET /installation/repositories?per_page=100&page=1": {body: `{"total_count":5,"repositories":[
			{"full_name":"org/api","default_branch":"main"},
			{"full_name":"org/web","default_branch":"main"}]}`},
		"GET /installation/repositories?per_page=100&page=2": {body: `{"total_count":5,"repositories":[]}`},
	})

	_, err := appClient(t, srv, 5).Repositories(context.Background())
	if err == nil {
		t.Fatal("a listing carrying two of a declared five was accepted. The other three silently " +
			"leave scope and nothing reports the loss")
	}
	if !strings.Contains(err.Error(), "5") || !strings.Contains(err.Error(), "2") {
		t.Errorf("the error does not say how many were expected and how many arrived: %v", err)
	}
}

// --- the error mappings ------------------------------------------------------

// TestRateLimitsAreRecognisedInEveryFormGitHubUsesThem matters because the
// framework has a specific response — back off for a stated time — and it only
// fires if the error is recognised as a rate limit rather than as a generic
// failure.
func TestRateLimitsAreRecognisedInEveryFormGitHubUsesThem(t *testing.T) {
	reset := time.Now().Add(90 * time.Second).Unix()

	for _, tc := range []struct {
		name    string
		status  int
		headers map[string]string
		wantMin time.Duration
	}{
		{"429 with Retry-After", http.StatusTooManyRequests,
			map[string]string{"Retry-After": "30"}, 30 * time.Second},
		{"403 secondary limit with Retry-After", http.StatusForbidden,
			map[string]string{"Retry-After": "60"}, 60 * time.Second},
		{"403 primary limit with reset", http.StatusForbidden,
			map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": fmt.Sprint(reset)},
			60 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := api(t, map[string]route{
				tokenRoute: tokenResponse(),
				"GET /installation/repositories": {
					status: tc.status, headers: tc.headers, body: `{"message":"rate limit"}`},
			})

			_, err := appClient(t, srv, 1).Repositories(context.Background())
			wait, limited := gh.IsRateLimited(err)
			if !limited {
				t.Fatalf("a rate limit was not recognised as one, so the backoff never fires "+
					"and the framework keeps hammering an endpoint that has said no: %v", err)
			}
			if wait < tc.wantMin-5*time.Second {
				t.Errorf("RetryAfter = %s, want at least about %s", wait, tc.wantMin)
			}
		})
	}
}

// TestAPermissionsFailureIsNotMistakenForARateLimit is the companion, and it
// is the one that keeps the test above from being satisfied by treating every
// 403 as a rate limit.
//
// A revoked installation answers 403. Retrying it on a backoff loop would hide
// a permissions problem behind a delay for ever.
func TestAPermissionsFailureIsNotMistakenForARateLimit(t *testing.T) {
	srv, _ := api(t, map[string]route{
		tokenRoute: tokenResponse(),
		"GET /installation/repositories": {
			status:  http.StatusForbidden,
			headers: map[string]string{"X-RateLimit-Remaining": "4987"},
			body:    `{"message":"Resource not accessible by integration"}`},
	})

	_, err := appClient(t, srv, 1).Repositories(context.Background())
	if err == nil {
		t.Fatal("a 403 was returned as success")
	}
	if _, limited := gh.IsRateLimited(err); limited {
		t.Fatal("a permissions failure was reported as a rate limit. Retrying it on a backoff " +
			"loop hides a revoked installation behind a delay for ever")
	}
	if !strings.Contains(err.Error(), "not accessible") {
		t.Errorf("GitHub's own explanation was dropped: %v", err)
	}
}

// --- pull requests -----------------------------------------------------------

func opsFor(t *testing.T, srv *httptest.Server) *gh.RESTOps {
	t.Helper()
	return &gh.RESTOps{
		BaseURL: srv.URL,
		Token:   func(context.Context, string) (string, error) { return "token ghs_test", nil },
	}
}

func TestOpenPRReturnsTheOpenedPullRequest(t *testing.T) {
	srv, seen := api(t, map[string]route{
		"POST /repos/org/api/pulls": {status: http.StatusCreated, body: `{
			"number":17,"html_url":"https://github.com/org/api/pull/17","state":"open",
			"head":{"ref":"security/fix-ab12cd"},"base":{"ref":"main"}}`},
		"POST /repos/org/api/issues/17/labels": {status: http.StatusOK, body: `[]`},
	})

	pr, err := opsFor(t, srv).OpenPR(context.Background(), "org/api", gh.OpenRequest{
		Head: "security/fix-ab12cd", Base: "main", Title: "Fix", Body: "body",
		Labels: []string{"security", "automated"},
	})
	if err != nil {
		t.Fatalf("OpenPR: %v", err)
	}
	if pr.Number != 17 || pr.Head != "security/fix-ab12cd" {
		t.Fatalf("pull request = %+v", pr)
	}

	// VM-F-542: a machine-generated pull request must be identifiable as one.
	if !containsCall(*seen, "POST /repos/org/api/issues/17/labels") {
		t.Error("the pull request was never labelled, so nothing on it says it was machine-generated")
	}
}

// TestADuplicatePullRequestIsAdoptedNotCrashedOn is an ordinary retry, and
// GitHub makes it awkward.
//
// A 422 is the answer, and the existing pull request is NOT in it. A caller
// that assumed success would fail on the most common re-run there is: the same
// fix group, scheduled twice.
func TestADuplicatePullRequestIsAdoptedNotCrashedOn(t *testing.T) {
	srv, _ := api(t, map[string]route{
		"POST /repos/org/api/pulls": {
			status: http.StatusUnprocessableEntity,
			body: `{"message":"Validation Failed","errors":[
				{"message":"A pull request already exists for org:security/fix-ab12cd."}]}`},
		"GET /repos/org/api/pulls": {body: `[{
			"number":17,"html_url":"https://github.com/org/api/pull/17","state":"open",
			"head":{"ref":"security/fix-ab12cd"},"base":{"ref":"main"}}]`},
	})

	_, err := opsFor(t, srv).OpenPR(context.Background(), "org/api", gh.OpenRequest{
		Head: "security/fix-ab12cd", Base: "main", Title: "Fix",
	})
	if err == nil {
		t.Fatal("a duplicate pull request was reported as newly opened")
	}

	var exists *gh.ErrPRExists
	if !errors.As(err, &exists) {
		t.Fatalf("a 422 duplicate is not an *ErrPRExists, so the worker cannot adopt the existing "+
			"pull request and VM-F-502's idempotency is lost: %v", err)
	}
	if exists.Existing.Number != 17 {
		t.Errorf("the error carries pull request #%d; the existing one is #17. GitHub does not "+
			"return it, so it has to be fetched — an error carrying nothing is unusable",
			exists.Existing.Number)
	}
}

// TestAnUnrelated422IsNotTreatedAsADuplicate stops the check above from
// swallowing every validation failure.
//
// "base branch does not exist" is also a 422, and adopting a non-existent
// pull request for it would report success for work that never happened.
func TestAnUnrelated422IsNotTreatedAsADuplicate(t *testing.T) {
	srv, _ := api(t, map[string]route{
		"POST /repos/org/api/pulls": {
			status: http.StatusUnprocessableEntity,
			body:   `{"message":"Validation Failed","errors":[{"message":"base is invalid"}]}`},
		// A pull request for this head DOES exist — a stale one from an
		// earlier run. That is what makes the case sharp: a client that
		// treated every 422 as a duplicate would find this, adopt it, and
		// report the invalid base as work completed. Without this route the
		// lookup simply fails and the distinction is untested.
		"GET /repos/org/api/pulls": {body: `[{
			"number":4,"html_url":"https://github.com/org/api/pull/4","state":"closed",
			"head":{"ref":"security/fix-ab12cd"},"base":{"ref":"main"}}]`},
	})

	_, err := opsFor(t, srv).OpenPR(context.Background(), "org/api", gh.OpenRequest{
		Head: "security/fix-ab12cd", Base: "nonexistent", Title: "Fix",
	})
	if err == nil {
		t.Fatal("an invalid base was reported as success")
	}
	var exists *gh.ErrPRExists
	if errors.As(err, &exists) {
		t.Fatal("an unrelated 422 was treated as a duplicate pull request. The worker would adopt " +
			"a pull request that does not exist and report work that never happened")
	}
}

// TestAMergedPullRequestIsDistinguishableFromAClosedOne is VM-F-545.
//
// "closed" cannot express the difference, and the difference decides between
// MERGED and DECLINED — two different outcomes for the finding. GitHub's pulls
// LIST endpoint omits `merged` entirely, so reading only that field would make
// every merged pull request found by reconciliation look declined.
func TestAMergedPullRequestIsDistinguishableFromAClosedOne(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		wantMerged bool
	}{
		{"merged, with the flag", `{"number":1,"state":"closed","merged":true,
			"merged_at":"2026-09-30T10:00:00Z","head":{"ref":"h"},"base":{"ref":"main"}}`, true},
		{"merged, flag omitted as the list endpoint does", `{"number":1,"state":"closed",
			"merged_at":"2026-09-30T10:00:00Z","head":{"ref":"h"},"base":{"ref":"main"}}`, true},
		{"closed without merging", `{"number":1,"state":"closed","merged":false,
			"head":{"ref":"h"},"base":{"ref":"main"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := api(t, map[string]route{"GET /repos/org/api/pulls/1": {body: tc.body}})

			pr, found, err := opsFor(t, srv).GetPR(context.Background(), "org/api", 1)
			if err != nil || !found {
				t.Fatalf("GetPR: %v (found=%v)", err, found)
			}
			if pr.Merged != tc.wantMerged {
				t.Fatalf("Merged = %v, want %v. A merged pull request read as merely closed becomes "+
					"DECLINED instead of MERGED, which is a different outcome for the finding "+
					"(VM-F-545)", pr.Merged, tc.wantMerged)
			}
		})
	}
}

// TestAFailedBranchLookupIsNotAMissingBranch is fail-closed where the default
// is dangerous.
//
// BranchExists is the idempotency check behind VM-F-502. A rate limit or a
// permissions error that came back as "no such branch" would have remediation
// cut a fresh branch over work already in review.
func TestAFailedBranchLookupIsNotAMissingBranch(t *testing.T) {
	srv, _ := api(t, map[string]route{
		"GET /repos/org/api/git/ref/heads/security/fix-ab12cd": {
			status: http.StatusInternalServerError, body: `{"message":"server error"}`},
	})

	exists, err := opsFor(t, srv).BranchExists(context.Background(), "org/api", "security/fix-ab12cd")
	if err == nil {
		t.Fatal("a server error was reported as a successful lookup")
	}
	if exists {
		t.Fatal("a failed lookup reported the branch as present")
	}
}

func TestAGenuinelyMissingBranchIsReportedAsMissing(t *testing.T) {
	srv, _ := api(t, map[string]route{})

	exists, err := opsFor(t, srv).BranchExists(context.Background(), "org/api", "security/fix-new")
	if err != nil {
		t.Fatalf("a 404 should be a clean negative, not an error: %v", err)
	}
	if exists {
		t.Fatal("a branch that does not exist was reported as present")
	}
}

func TestDefaultBranchIsNeverGuessed(t *testing.T) {
	srv, _ := api(t, map[string]route{
		"GET /repos/org/api": {body: `{"full_name":"org/api"}`},
	})

	_, err := opsFor(t, srv).DefaultBranch(context.Background(), "org/api")
	if err == nil {
		t.Fatal("a repository reporting no default branch produced one anyway. Defaulting to " +
			"\"main\" would cut remediation branches from a base that does not exist, and the " +
			"failure would surface as a confusing push error rather than the missing field it is")
	}
}

func TestAnUnauthenticatedWriteIsRefusedRatherThanAttempted(t *testing.T) {
	srv, _ := api(t, map[string]route{})
	ops := &gh.RESTOps{BaseURL: srv.URL} // no Token source

	if _, err := ops.OpenPR(context.Background(), "org/api", gh.OpenRequest{Head: "h", Base: "main"}); err == nil {
		t.Fatal("a write was attempted with no credential source. An anonymous call fails in a " +
			"way that reads like a missing resource")
	}
}

func containsCall(calls []string, want string) bool {
	for _, c := range calls {
		if strings.HasPrefix(c, want) {
			return true
		}
	}
	return false
}
