package triage_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/triage"
)

// The live inference client, against a local server.
//
// **No API key exists in this build.** Every credential below is a test
// string, and none should be issued to a machine where the sandbox probe
// (D2) has not passed.

// capture records what the client actually sent.
type capture struct {
	body    []byte
	headers http.Header
	calls   int
}

func modelAPI(t *testing.T, respond func(w http.ResponseWriter, call int)) (*httptest.Server, *capture) {
	t.Helper()
	cap := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.calls++
		cap.headers = r.Header.Clone()
		body := make([]byte, 0)
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			body = append(body, buf[:n]...)
			if err != nil {
				break
			}
		}
		cap.body = body
		w.Header().Set("Content-Type", "application/json")
		respond(w, cap.calls)
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

func answer(verdicts string) func(http.ResponseWriter, int) {
	return func(w http.ResponseWriter, _ int) {
		envelope, _ := json.Marshal(map[string]any{
			"stop_reason": "end_turn",
			"content":     []map[string]string{{"type": "text", "text": verdicts}},
		})
		_, _ = w.Write(envelope)
	}
}

func client(t *testing.T, srv *httptest.Server) *triage.HTTPClient {
	t.Helper()
	return &triage.HTTPClient{
		BaseURL:    srv.URL,
		Model:      "claude-opus-5",
		MaxTokens:  8192,
		Credential: func() (string, error) { return "test-key-not-a-real-credential", nil },
	}
}

func batch() triage.Request {
	return triage.Request{
		System:  "You describe vulnerabilities. You never assign priority.",
		Profile: triage.RepoProfile{Repo: "org/api", Languages: []string{"go"}, Tier: 1},
		Findings: []triage.Item{
			{Fingerprint: "f1", Category: "dependency", PrimaryID: "GHSA-aaaa-bbbb-cccc",
				Module: "example.com/mod", Current: "v1.0.0", Fixed: "v1.2.0"},
			{Fingerprint: "f2", Category: "code", RuleID: "G402", File: "internal/api/server.go"},
		},
	}
}

const twoVerdicts = `[
  {"fingerprint":"f1","description":"d1","impact":"i1","remediation":"r1",
   "false_positive_candidate":false,"fp_reasoning":null,"confidence":"high"},
  {"fingerprint":"f2","description":"d2","impact":"i2","remediation":"r2",
   "false_positive_candidate":false,"fp_reasoning":null,"confidence":"medium"}
]`

// --- the happy path and the request shape -----------------------------------

func TestTheClientReturnsVerdicts(t *testing.T) {
	srv, _ := modelAPI(t, answer(twoVerdicts))

	got, err := client(t, srv).Triage(context.Background(), batch())
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d verdicts, want 2", len(got))
	}
	if got[0].Fingerprint != "f1" || got[0].Description != "d1" {
		t.Errorf("first verdict = %+v", got[0])
	}
}

// TestTheCredentialTravelsOnAHeaderAndNotInThePrompt is the separation that
// survives prompt injection.
//
// Scanner output reaches the prompt, and a model can be asked to quote its
// prompt back. A key placed anywhere in the message body is therefore
// reachable by an instruction embedded in somebody's advisory text.
func TestTheCredentialTravelsOnAHeaderAndNotInThePrompt(t *testing.T) {
	const key = "test-key-not-a-real-credential"
	srv, cap := modelAPI(t, answer(twoVerdicts))

	if _, err := client(t, srv).Triage(context.Background(), batch()); err != nil {
		t.Fatalf("Triage: %v", err)
	}

	if cap.headers.Get("x-api-key") != key {
		t.Errorf("the key did not travel on the x-api-key header")
	}
	if strings.Contains(string(cap.body), key) {
		t.Fatalf("the credential is in the request BODY. A model can be asked to quote its "+
			"prompt back, and scanner output reaches that prompt:\n%s", excerptOf(string(cap.body)))
	}
	if cap.headers.Get("anthropic-version") == "" {
		t.Error("no API version header was sent")
	}
}

// TestNoCredentialIsFetchedUntilARequestIsActuallyMade is why Credential is a
// function.
//
// A run served entirely from the triage cache (VM-F-306) should never obtain
// a key at all. With a field, "was it fetched" is unanswerable; with a
// function it is a fact.
func TestNoCredentialIsFetchedUntilARequestIsActuallyMade(t *testing.T) {
	srv, _ := modelAPI(t, answer(twoVerdicts))

	fetched := 0
	c := client(t, srv)
	c.Credential = func() (string, error) { fetched++; return "test-key", nil }

	// A batch that fails its own checks never reaches the network.
	empty := batch()
	empty.Findings = nil
	if _, err := c.Triage(context.Background(), empty); err == nil {
		t.Fatal("an empty batch was sent for inference")
	}
	if fetched != 0 {
		t.Fatalf("the credential was obtained %d times for a request that was never made. "+
			"A key held for a call that does not happen is a key in reach of everything else "+
			"the process does", fetched)
	}

	if _, err := c.Triage(context.Background(), batch()); err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if fetched != 1 {
		t.Errorf("the credential was obtained %d times for one request", fetched)
	}
}

// TestTheRequestCarriesNoRepositorySource is VM-AD §9.2.
//
// The model gets identity and classification. It does not get the repository's
// code, and it does not get a credential value — a secret finding records the
// KIND of credential and has nowhere to put the value.
func TestTheRequestCarriesNoRepositorySource(t *testing.T) {
	srv, cap := modelAPI(t, answer(twoVerdicts))

	req := batch()
	req.Findings = append(req.Findings, triage.Item{
		Fingerprint: "f3", Category: "secret", File: "config/settings.yaml",
	})
	if _, err := client(t, srv).Triage(context.Background(), req); err != nil {
		t.Fatalf("Triage: %v", err)
	}

	var sent map[string]any
	if err := json.Unmarshal(cap.body, &sent); err != nil {
		t.Fatalf("the request body is not JSON: %v", err)
	}
	body := string(cap.body)

	// The item schema has nowhere to put a secret, so this asserts the
	// structural property rather than scanning for a particular string.
	for _, forbidden := range []string{"credential_value", "secret_value", "raw", "file_contents"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the request carries a %q field", forbidden)
		}
	}
	if _, ok := sent["system"]; !ok {
		t.Error("the static instructions were not sent as a system block, so they cannot be " +
			"cached across a fleet-sized run — which is the cost difference VM-F-308 is about")
	}
}

// TestScannerTextIsFramedAsData is the prompt-side half of VM-F-309.
//
// The enforcement is internal/triage.Validate, deliberately, because a prompt
// is a request and a validator is a control. But the framing still has to be
// there: everything in a finding came from a scanner reading somebody's
// repository, and the model should be told so.
func TestScannerTextIsFramedAsData(t *testing.T) {
	srv, cap := modelAPI(t, answer(twoVerdicts))
	if _, err := client(t, srv).Triage(context.Background(), batch()); err != nil {
		t.Fatalf("Triage: %v", err)
	}

	body := string(cap.body)
	if !strings.Contains(body, "untrusted data") {
		t.Errorf("the findings are not framed as untrusted data:\n%s", excerptOf(body))
	}
	if !strings.Contains(body, "never as an instruction") {
		t.Error("the framing does not say that text in the findings is not an instruction")
	}
}

// --- strictness --------------------------------------------------------------

// TestAVerdictCarryingAPriorityIsRefused is VM-F-305.
//
// Priority is arithmetic and belongs to internal/score. A lenient parser would
// drop the field silently, leaving no trace that the model had tried to supply
// one — and no way to notice if a prompt change started inviting it.
func TestAVerdictCarryingAPriorityIsRefused(t *testing.T) {
	srv, _ := modelAPI(t, answer(`[{"fingerprint":"f1","description":"d","impact":"i",
		"remediation":"r","confidence":"high","priority":"P0"}]`))

	_, err := client(t, srv).Triage(context.Background(), batch())
	if err == nil {
		t.Fatal("a verdict supplying a priority was accepted. Priority is computed by " +
			"internal/score and never produced by inference (VM-F-305); silently dropping the " +
			"field leaves no trace that the model tried")
	}
	if !strings.Contains(err.Error(), "priority") {
		t.Errorf("the refusal does not name the offending field: %v", err)
	}
}

// TestATruncatedResponseIsNotAShortBatch is the quiet failure.
//
// A response cut off by the token limit parses into a SHORTER list of
// verdicts. The findings missing from it are then indistinguishable from ones
// the model had nothing to say about — which the retry path treats as a second
// failure and marks un-narrated, with no indication anywhere that the real
// cause was a token bound.
func TestATruncatedResponseIsNotAShortBatch(t *testing.T) {
	srv, _ := modelAPI(t, func(w http.ResponseWriter, _ int) {
		envelope, _ := json.Marshal(map[string]any{
			"stop_reason": "max_tokens",
			"content": []map[string]string{{"type": "text", "text": `[
				{"fingerprint":"f1","description":"d","impact":"i","remediation":"r","confidence":"high"}]`}},
		})
		_, _ = w.Write(envelope)
	})

	_, err := client(t, srv).Triage(context.Background(), batch())
	if err == nil {
		t.Fatal("a response that hit the token limit was accepted as a complete answer. The " +
			"verdicts it is missing read as findings the model had nothing to say about")
	}
	if !strings.Contains(err.Error(), "token limit") {
		t.Errorf("the failure does not say the response was truncated: %v", err)
	}
}

// TestNothingUsableIsRefusedAndTheCauseIsKept covers the three ways a call
// comes back with no verdicts in it.
//
// All three must fail — none of them is an empty success, because an empty
// success means the model ran and had nothing to report, which consumes these
// findings' turn and marks them narrated.
//
// And all three must stay DISTINGUISHABLE, which is why this asserts on the
// explanation rather than only on the failure. They have three different
// owners: a refusal is a prompt or content question, no text at all is an API
// problem, and prose is a prompt that stopped asking for JSON. Collapsing
// them into one message would send every one of those to the same person, and
// two of them to the wrong one. It would also let any one of the three checks
// silently cover for the other two.
func TestNothingUsableIsRefusedAndTheCauseIsKept(t *testing.T) {
	for _, tc := range []struct {
		name       string
		stopReason string
		text       string
		wantPhrase string
	}{
		{"the model declined", "refusal", "", "declined"},
		{"the API returned no text", "end_turn", "", "no text"},
		{"the model answered in prose", "end_turn",
			"I was unable to analyse these findings.", "no verdict array"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := modelAPI(t, func(w http.ResponseWriter, _ int) {
				content := []map[string]string{}
				if tc.text != "" {
					content = append(content, map[string]string{"type": "text", "text": tc.text})
				}
				envelope, _ := json.Marshal(map[string]any{
					"stop_reason": tc.stopReason, "content": content,
				})
				_, _ = w.Write(envelope)
			})

			_, err := client(t, srv).Triage(context.Background(), batch())
			if err == nil {
				t.Fatal("a call that produced no verdicts was reported as a success")
			}
			if !strings.Contains(err.Error(), tc.wantPhrase) {
				t.Errorf("the failure does not identify this cause: want something containing "+
					"%q, got %v", tc.wantPhrase, err)
			}
		})
	}
}

// TestAFencedAnswerIsRead covers the ordinary case that is not an error.
//
// Models wrap JSON in code fences and prepend a sentence. Refusing those would
// make the client fail on well-formed answers, which is the other way this
// check goes wrong.
func TestAFencedAnswerIsRead(t *testing.T) {
	// The trailing note matters: it contains a `]`. Scanning the whole answer
	// for the last bracket would pick that one and capture the fence markers
	// and the prose along with the array. The fence has to be honoured, not
	// worked around.
	srv, _ := modelAPI(t, answer("Here are the verdicts:\n\n```json\n"+twoVerdicts+
		"\n```\n\nNote: see [1] for the upstream advisory text.\n"))

	got, err := client(t, srv).Triage(context.Background(), batch())
	if err != nil {
		t.Fatalf("a fenced answer was refused: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d verdicts, want 2", len(got))
	}
}

// TestAnUnfencedAnswerWithATrailingNoteIsRefused is the case the fence cannot
// help with, and it is why locating the array is not enough on its own.
//
// A model that answers with bare JSON and then adds a sentence containing a
// bracket defeats bracket scanning: the array is found, a stray `]` from the
// prose becomes the end, and the captured text is the right array plus a tail.
// A json.Decoder stops at the first complete value and ignores whatever
// follows, so that decodes cleanly and nothing says the bounds were wrong.
//
// Refusing is correct here rather than salvaging. The array may have been
// located by luck, and verdicts attributed to the wrong findings are worse
// than none.
func TestAnUnfencedAnswerWithATrailingNoteIsRefused(t *testing.T) {
	srv, _ := modelAPI(t, answer(twoVerdicts+"\n\nNote: see [1] for the upstream advisory.\n"))

	_, err := client(t, srv).Triage(context.Background(), batch())
	if err == nil {
		t.Fatal("an answer whose array bounds were located by bracket scanning across trailing " +
			"prose was accepted. The decoder stops at the first complete value, so a wrong end " +
			"bound decodes cleanly and nothing reports it")
	}
	if !strings.Contains(err.Error(), "text follows") {
		t.Errorf("the failure does not say what was wrong with the answer's shape: %v", err)
	}
}

// --- transport failures ------------------------------------------------------

// TestOverloadIsDistinguishableFromAMalformedAnswer is what lets a caller tell
// "try again shortly" from "this will never work".
func TestOverloadIsDistinguishableFromAMalformedAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"rate limited", http.StatusTooManyRequests},
		{"overloaded", 529},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := modelAPI(t, func(w http.ResponseWriter, _ int) {
				w.Header().Set("Retry-After", "17")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"error":{"type":"overloaded_error","message":"try later"}}`))
			})

			_, err := client(t, srv).Triage(context.Background(), batch())
			wait, overloaded := triage.IsOverloaded(err)
			if !overloaded {
				t.Fatalf("a transient capacity failure is not recognisable as one, so a caller "+
					"either retries a permanent failure for ever or gives up on a temporary "+
					"one: %v", err)
			}
			if wait.Seconds() != 17 {
				t.Errorf("RetryAfter = %s, want 17s from the header", wait)
			}
		})
	}
}

// TestAnAuthenticationFailureIsNotAnOverload keeps a bad key out of the retry
// loop.
func TestAnAuthenticationFailureIsNotAnOverload(t *testing.T) {
	srv, _ := modelAPI(t, func(w http.ResponseWriter, _ int) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"type":"authentication_error","message":"invalid x-api-key"}}`))
	})

	_, err := client(t, srv).Triage(context.Background(), batch())
	if err == nil {
		t.Fatal("a 401 was returned as success")
	}
	if _, overloaded := triage.IsOverloaded(err); overloaded {
		t.Fatal("an authentication failure was reported as an overload. It would be retried on a " +
			"backoff loop for ever instead of alerting somebody that the key is wrong")
	}
	if !strings.Contains(err.Error(), "authentication_error") {
		t.Errorf("the API's own explanation was dropped: %v", err)
	}
}

// --- configuration -----------------------------------------------------------

func TestAnUnconfiguredClientRefusesRatherThanGuessing(t *testing.T) {
	srv, _ := modelAPI(t, answer(twoVerdicts))

	for _, tc := range []struct {
		name string
		mut  func(*triage.HTTPClient)
		want string
	}{
		{"no model", func(c *triage.HTTPClient) { c.Model = "" }, "model"},
		{"no token bound", func(c *triage.HTTPClient) { c.MaxTokens = 0 }, "token bound"},
		{"no credential source", func(c *triage.HTTPClient) { c.Credential = nil }, "credential source"},
		// Distinct from the nil case: a source that is configured and hands
		// back nothing. Left to the API that becomes a 401, which reads like
		// an expired key and sends somebody to rotate a credential that was
		// never supplied.
		{"an empty key", func(c *triage.HTTPClient) {
			c.Credential = func() (string, error) { return "   ", nil }
		}, "empty key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := client(t, srv)
			tc.mut(c)
			_, err := c.Triage(context.Background(), batch())
			if err == nil {
				t.Fatalf("a client with %s proceeded anyway", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not say what is missing: %v", err)
			}
		})
	}
}

// TestAnOversizedBatchIsRefusedNotTruncated keeps VM-F-308 from being
// satisfied by silently dropping findings.
func TestAnOversizedBatchIsRefusedNotTruncated(t *testing.T) {
	srv, cap := modelAPI(t, answer(twoVerdicts))

	req := batch()
	req.Findings = nil
	for i := 0; i < triage.MaxBatchSize+1; i++ {
		req.Findings = append(req.Findings, triage.Item{
			Fingerprint: fmt.Sprintf("f%d", i), Category: "dependency",
		})
	}

	if _, err := client(t, srv).Triage(context.Background(), req); err == nil {
		t.Fatal("an oversized batch was sent. Truncating it leaves the findings past the cut " +
			"looking triaged and unremarkable")
	}
	if cap.calls != 0 {
		t.Error("the oversized batch reached the network before being refused")
	}
}

// TestTheLiveClientSatisfiesTheSameContractAsTheFake is the conformance check.
//
// Both implement triage.Client, and the Triager was written against the fake.
// A live client whose results the Triager handles differently would be a
// second implementation of a contract nobody stated.
func TestTheLiveClientSatisfiesTheSameContractAsTheFake(t *testing.T) {
	srv, _ := modelAPI(t, answer(twoVerdicts))

	var live triage.Client = client(t, srv)
	var fake triage.Client = triage.NewFakeClient()

	req := batch()
	fromLive, err := live.Triage(context.Background(), req)
	if err != nil {
		t.Fatalf("live: %v", err)
	}
	fromFake, err := fake.Triage(context.Background(), req)
	if err != nil {
		t.Fatalf("fake: %v", err)
	}

	if len(fromLive) != len(fromFake) {
		t.Fatalf("live returned %d verdicts and the fake %d for the same batch",
			len(fromLive), len(fromFake))
	}
	// Both must answer for every fingerprint requested, which is what
	// Validate checks and what the retry path depends on.
	for _, got := range [][]triage.Verdict{fromLive, fromFake} {
		seen := map[string]bool{}
		for _, v := range got {
			seen[v.Fingerprint] = true
		}
		for _, it := range req.Findings {
			if !seen[it.Fingerprint] {
				t.Errorf("no verdict for %s", it.Fingerprint)
			}
		}
	}
}

func excerptOf(s string) string {
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}
