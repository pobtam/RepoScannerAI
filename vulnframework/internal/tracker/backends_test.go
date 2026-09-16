package tracker_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/tracker"
)

// Clause 5: every real backend sits behind the interface, with a fake.
//
// The three backends differ only in how they carry the fingerprint (VM-AD
// §13.2), and that carrier is the whole of the idempotency guarantee. These
// tests run the real request-building code against a recorded transport: no
// network, no credentials, and the assertions are about what would be sent.

// recorder is a fake HTTP transport. It records every request and replays
// canned responses in order.
type recorder struct {
	requests  []recorded
	responses []canned
	n         int
	err       error
}

type recorded struct {
	Method string
	URL    string
	Body   string
	Header http.Header
}

type canned struct {
	status int
	body   string
}

func (r *recorder) Do(req *http.Request) (*http.Response, error) {
	var body string
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		body = string(b)
	}
	r.requests = append(r.requests, recorded{
		Method: req.Method, URL: req.URL.String(), Body: body, Header: req.Header.Clone(),
	})
	if r.err != nil {
		return nil, r.err
	}
	if r.n >= len(r.responses) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	}
	c := r.responses[r.n]
	r.n++
	return &http.Response{StatusCode: c.status, Body: io.NopCloser(strings.NewReader(c.body))}, nil
}

func (r *recorder) all() string {
	var b strings.Builder
	for _, req := range r.requests {
		b.WriteString(req.Method + " " + req.URL + "\n" + req.Body + "\n")
	}
	return b.String()
}

const fp = "a3f9c21e8b7d4056"

func demoSpec() tracker.Spec {
	return tracker.Spec{
		Fingerprint: fp,
		Title:       "GO-2025-3106 in golang.org/x/crypto",
		Body:        "A dependency vulnerability.",
		Severity:    "P1",
		Repo:        repo,
		Assignee:    "team-api",
		Labels:      []string{"security"},
		ReportURL:   "https://reports.example/runs/S-000001/fleet.md",
	}
}

// TestEveryBackendSatisfiesTheInterface is the pluggability requirement
// (VM-F-801): one interface, three implementations, selectable by configuration
// without code change (VM-F-802).
func TestEveryBackendSatisfiesTheInterface(t *testing.T) {
	var _ tracker.Tracker = tracker.NewGitHub(&recorder{}, tracker.GitHubConfig{Owner: "org", Repo: "wanaware-api"})
	var _ tracker.Tracker = tracker.NewJira(&recorder{}, tracker.JiraConfig{BaseURL: "https://j.example", Project: "SEC", FingerprintField: "customfield_10042"})
	var _ tracker.Tracker = tracker.NewLinear(&recorder{}, tracker.LinearConfig{TeamID: "TEAM"})
	var _ tracker.Tracker = tracker.NewFake("fake")

	for _, name := range []string{"github", "jira", "linear"} {
		tr, err := tracker.Open(name, tracker.Options{
			GitHub: tracker.GitHubConfig{Owner: "org", Repo: "wanaware-api"},
			Jira:   tracker.JiraConfig{BaseURL: "https://j.example", Project: "SEC", FingerprintField: "customfield_10042"},
			Linear: tracker.LinearConfig{TeamID: "TEAM"},
			HTTP:   &recorder{},
		})
		if err != nil {
			t.Errorf("Open(%q): %v", name, err)
			continue
		}
		if tr.Name() != name {
			t.Errorf("Open(%q).Name() = %q", name, tr.Name())
		}
	}
	if _, err := tracker.Open("bugzilla", tracker.Options{}); err == nil {
		t.Error("an unconfigured backend name was accepted; a typo in configuration would silently disable ticketing")
	}
}

// TestFingerprintCarrierPerBackend covers VM-AD §13.2 and VM-F-805. Each
// backend must put the fingerprint somewhere queryable, and must look it up
// there — never by title. Title matching breaks the moment a title is edited,
// and the first symptom is a duplicate ticket.
func TestFingerprintCarrierPerBackend(t *testing.T) {
	ctx := context.Background()

	t.Run("github", func(t *testing.T) {
		rec := &recorder{responses: []canned{
			{200, `{"number":41,"html_url":"https://github.com/org/wanaware-api/issues/41"}`},
		}}
		gh := tracker.NewGitHub(rec, tracker.GitHubConfig{Owner: "org", Repo: "wanaware-api"})
		if _, err := gh.Create(ctx, demoSpec()); err != nil {
			t.Fatalf("Create: %v", err)
		}
		var sent struct {
			Body   string   `json:"body"`
			Labels []string `json:"labels"`
		}
		if err := json.Unmarshal([]byte(rec.requests[0].Body), &sent); err != nil {
			t.Fatalf("the create request is not JSON: %v", err)
		}
		body := sent.Body + strings.Join(sent.Labels, ",")
		if !strings.Contains(sent.Body, "<!-- vf:fp:"+fp+" -->") {
			t.Errorf("the issue body carries no fingerprint marker:\n%s", body)
		}
		if !strings.Contains(body, "vf-fp-") {
			t.Errorf("the issue carries no fingerprint label:\n%s", body)
		}

		rec2 := &recorder{responses: []canned{
			{200, `{"total_count":1,"items":[{"number":41,"html_url":"https://github.com/org/wanaware-api/issues/41"}]}`},
		}}
		gh2 := tracker.NewGitHub(rec2, tracker.GitHubConfig{Owner: "org", Repo: "wanaware-api"})
		ref, ok, err := gh2.Find(ctx, fp)
		if err != nil || !ok {
			t.Fatalf("Find = (%v, %v)", ok, err)
		}
		if ref.ID == "" || ref.URL == "" {
			t.Errorf("Find returned an unusable ref: %+v", ref)
		}
		if !strings.Contains(rec2.requests[0].URL, fp) {
			t.Errorf("the search does not query the fingerprint: %s", rec2.requests[0].URL)
		}
		if strings.Contains(strings.ToLower(rec2.requests[0].URL), "in%3atitle") {
			t.Error("the search matches on title; VM-F-805 forbids text matching")
		}
	})

	t.Run("jira", func(t *testing.T) {
		rec := &recorder{responses: []canned{{200, `{"key":"SEC-9","self":"https://j.example/rest/api/3/issue/SEC-9"}`}}}
		j := tracker.NewJira(rec, tracker.JiraConfig{
			BaseURL: "https://j.example", Project: "SEC", FingerprintField: "customfield_10042",
		})
		if _, err := j.Create(ctx, demoSpec()); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if !strings.Contains(rec.requests[0].Body, `"customfield_10042":"`+fp+`"`) {
			t.Errorf("the issue does not set the indexed fingerprint field:\n%s", rec.requests[0].Body)
		}

		rec2 := &recorder{responses: []canned{{200, `{"issues":[{"key":"SEC-9","self":"https://j.example/browse/SEC-9"}]}`}}}
		j2 := tracker.NewJira(rec2, tracker.JiraConfig{
			BaseURL: "https://j.example", Project: "SEC", FingerprintField: "customfield_10042",
		})
		if _, ok, err := j2.Find(ctx, fp); err != nil || !ok {
			t.Fatalf("Find = (%v, %v)", ok, err)
		}
		q := rec2.requests[0].Body + rec2.requests[0].URL
		if !strings.Contains(q, "customfield_10042") || !strings.Contains(q, fp) {
			t.Errorf("the JQL does not query the fingerprint field: %s", q)
		}
		if strings.Contains(strings.ToLower(q), "summary~") {
			t.Error("the JQL matches on summary text; VM-F-805 forbids it")
		}
	})

	t.Run("linear", func(t *testing.T) {
		rec := &recorder{responses: []canned{
			{200, `{"data":{"issueCreate":{"issue":{"id":"iss_1","identifier":"SEC-9","url":"https://linear.app/x/issue/SEC-9"}}}}`},
		}}
		l := tracker.NewLinear(rec, tracker.LinearConfig{TeamID: "TEAM"})
		if _, err := l.Create(ctx, demoSpec()); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if !strings.Contains(rec.requests[0].Body, "vf:"+fp) {
			t.Errorf("the issue carries no fingerprint label:\n%s", rec.requests[0].Body)
		}
		if !strings.Contains(rec.requests[0].Body, "vf:fp:"+fp) {
			t.Errorf("the issue body carries no fingerprint marker:\n%s", rec.requests[0].Body)
		}

		rec2 := &recorder{responses: []canned{
			{200, `{"data":{"issues":{"nodes":[{"id":"iss_1","identifier":"SEC-9","url":"https://linear.app/x/issue/SEC-9"}]}}}`},
		}}
		l2 := tracker.NewLinear(rec2, tracker.LinearConfig{TeamID: "TEAM"})
		if _, ok, err := l2.Find(ctx, fp); err != nil || !ok {
			t.Fatalf("Find = (%v, %v)", ok, err)
		}
		if !strings.Contains(rec2.requests[0].Body, fp) {
			t.Errorf("the GraphQL filter does not query the fingerprint:\n%s", rec2.requests[0].Body)
		}
	})
}

// TestBackendsNeverSendCredentialMaterial carries the no-value invariant to the
// wire. The spec builder guards the content; this guards the transport, so a
// backend that renders extra text of its own cannot reintroduce a secret.
func TestBackendsNeverSendCredentialMaterial(t *testing.T) {
	ctx := context.Background()
	spec := demoSpec()
	spec.Body = "REDACTED-AWS-EXAMPLE-KEY-ID"

	backends := map[string]func(*recorder) tracker.Tracker{
		"github": func(r *recorder) tracker.Tracker {
			return tracker.NewGitHub(r, tracker.GitHubConfig{Owner: "org", Repo: "wanaware-api"})
		},
		"jira": func(r *recorder) tracker.Tracker {
			return tracker.NewJira(r, tracker.JiraConfig{BaseURL: "https://j.example", Project: "SEC", FingerprintField: "customfield_10042"})
		},
		"linear": func(r *recorder) tracker.Tracker {
			return tracker.NewLinear(r, tracker.LinearConfig{TeamID: "TEAM"})
		},
	}
	for name, build := range backends {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{}
			if _, err := build(rec).Create(ctx, spec); err == nil {
				t.Error("a spec carrying credential material was sent")
			}
			if strings.Contains(rec.all(), "REDACTED-AWS-EXAMPLE-KEY-ID") {
				t.Error("credential material reached the transport")
			}
		})
	}
}

// --- Mirroring (VM-AD §13.4, VM-F-803) -------------------------------------

// TestMirrorIsOneWay covers the whole of §13.4: primary to secondary, never
// back. Two-way synchronisation is explicitly out of scope, and a mirror that
// reads state from the secondary would make the secondary a second source of
// truth for closure — at which point two systems disagree about whether a
// vulnerability is fixed.
func TestMirrorIsOneWay(t *testing.T) {
	ctx := context.Background()
	primary := tracker.NewFake("github")
	secondary := tracker.NewFake("jira")
	m := tracker.NewMirror(primary, secondary, "P1")

	ref, err := m.Create(ctx, demoSpec())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ref.Backend != "github" {
		t.Errorf("the mirror returned the secondary's ref: %+v", ref)
	}
	if secondary.CreateCount() != 1 {
		t.Fatalf("the secondary received %d creates, want 1", secondary.CreateCount())
	}
	// The secondary links back to the primary, so a reader in the mirror can
	// reach the system of record.
	if !strings.Contains(secondary.Everything(), ref.URL) {
		t.Error("the mirrored ticket does not link back to the primary")
	}

	// Find, and every read, consults only the primary.
	if _, _, err := m.Find(ctx, fp); err != nil {
		t.Fatalf("Find: %v", err)
	}
	if secondary.FindCount() != 0 {
		t.Error("the mirror read state from the secondary; mirroring is one-way (VM-AD §13.4)")
	}

	// Transitions propagate outward.
	if err := m.Transition(ctx, ref, tracker.StateClosed); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if secondary.OpenCount() != 0 {
		t.Error("closing the primary left the mirrored ticket open")
	}
}

// TestMirrorBelowThresholdIsNotMirrored covers VM-F-803: only high-severity
// tickets are mirrored, so the planning tool is not flooded with P3 noise.
func TestMirrorBelowThresholdIsNotMirrored(t *testing.T) {
	ctx := context.Background()
	primary := tracker.NewFake("github")
	secondary := tracker.NewFake("jira")
	m := tracker.NewMirror(primary, secondary, "P1")

	spec := demoSpec()
	spec.Severity = "P3"
	if _, err := m.Create(ctx, spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if secondary.CreateCount() != 0 {
		t.Error("a P3 was mirrored despite the P1 threshold")
	}
}

// TestMirrorFailureDoesNotFailThePrimary is failure isolation at the mirror
// boundary. The secondary is a convenience; losing it must not lose the ticket
// that carries the actual remediation (VM-F-812).
func TestMirrorFailureDoesNotFailThePrimary(t *testing.T) {
	ctx := context.Background()
	primary := tracker.NewFake("github")
	secondary := tracker.NewFake("jira")
	secondary.FailWith(errors.New("jira is down"))
	m := tracker.NewMirror(primary, secondary, "P1")

	ref, err := m.Create(ctx, demoSpec())
	if err != nil {
		t.Fatalf("a secondary failure failed the primary create: %v", err)
	}
	if ref.Backend != "github" {
		t.Errorf("ref = %+v", ref)
	}
	if primary.CreateCount() != 1 {
		t.Errorf("primary creates = %d, want 1", primary.CreateCount())
	}
	if n := len(m.MirrorErrors()); n != 1 {
		t.Errorf("the mirror recorded %d errors, want 1; a silent mirror failure is indistinguishable from a working mirror", n)
	}
}
