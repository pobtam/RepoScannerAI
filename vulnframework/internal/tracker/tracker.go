// Package tracker creates and maintains the tickets a finding produces
// (VM-AD §13).
//
// Three things make this more than an API wrapper:
//
// Idempotency is the whole point. A finding produces exactly one ticket for its
// lifetime, and the mechanism is the fingerprint — carried in the local record
// as the fast path, and in a queryable field on the ticket itself as the
// reconciliation path after data loss (VM-F-804, VM-F-805). Nothing matches on
// title text, because titles get edited and the first symptom is a duplicate.
//
// The no-value invariant reaches further here than anywhere else. A ticket is
// the artifact that travels into inboxes, notification services and mobile
// clients; a secret's value must never be in one (VM-F-263, VM-F-703).
//
// Every backend sits behind one interface with a fake, so the system builds,
// runs and passes its tests with no credentials and no network.
package tracker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/policy"
)

// TicketState is the closed enumeration of ticket states this system sets.
//
// It is deliberately two-valued. Backends model many more, but the framework
// only ever asserts "this is outstanding" or "this is done"; mapping richer
// workflows is the backend's business, and a wider enumeration here would
// invite the framework to make judgements about someone else's process.
type TicketState string

const (
	StateOpen   TicketState = "open"
	StateClosed TicketState = "closed"
)

// Ref identifies a ticket in a backend.
type Ref struct {
	Backend string `json:"backend"`
	ID      string `json:"id"`
	URL     string `json:"url"`
}

// Zero reports whether the ref names nothing.
func (r Ref) Zero() bool { return r.Backend == "" && r.ID == "" && r.URL == "" }

func (r Ref) String() string {
	if r.ID == "" {
		return ""
	}
	return r.Backend + ":" + r.ID
}

// Spec is the ticket to create (VM-AD §13.1).
type Spec struct {
	Fingerprint string         `json:"fingerprint"`
	Title       string         `json:"title"`
	Body        string         `json:"body"`
	Severity    model.Priority `json:"severity"`
	Repo        string         `json:"repo"`
	Assignee    string         `json:"assignee,omitempty"`
	Labels      []string       `json:"labels,omitempty"`
	Parent      *Ref           `json:"parent,omitempty"`
	ReportURL   string         `json:"report_url"`
}

// ErrNoReportLink is returned for a spec with no report link.
var ErrNoReportLink = errors.New(
	"tracker: a ticket must link to the report it came from (VM-F-809); " +
		"without it the reader has no way to reach the evidence, and the ticket outlives the dashboard that explained it")

// ErrNoFingerprint is returned for a spec with no fingerprint.
var ErrNoFingerprint = errors.New(
	"tracker: a ticket must carry its finding's fingerprint (VM-F-804/805); " +
		"it is the only idempotency key, and without it every run creates a new ticket")

// Validate checks a spec before anything is sent.
//
// The credential scan runs here rather than in each backend so that all three
// enforce the same rule, and it scans the composed text rather than the model:
// the model cannot represent a secret value, but a caller can still compose one
// into a title or body from a commit message, a log line or a triage narrative.
func (s Spec) Validate() error {
	if strings.TrimSpace(s.Fingerprint) == "" {
		return ErrNoFingerprint
	}
	if strings.TrimSpace(s.Title) == "" {
		return errors.New("tracker: a ticket needs a title")
	}
	if strings.TrimSpace(s.ReportURL) == "" {
		return ErrNoReportLink
	}
	composed := strings.Join(append([]string{s.Title, s.Body, s.Repo, s.Assignee}, s.Labels...), "\n")
	return model.AssertNoCredential("ticket for "+s.Fingerprint, []byte(composed))
}

// Tracker is one ticket backend (VM-AD §13.1).
//
// Every method is expressed in terms of the fingerprint or an opaque Ref, never
// in terms of ticket text, so no implementation can quietly come to depend on
// matching titles.
type Tracker interface {
	Name() string
	// Find locates an existing ticket by fingerprint. It is the reconciliation
	// path after the local record is lost, and it must query a structured
	// carrier — a marker, a label, an indexed field — never title text.
	Find(ctx context.Context, fingerprint string) (Ref, bool, error)
	Create(ctx context.Context, spec Spec) (Ref, error)
	Comment(ctx context.Context, ref Ref, body string) error
	Transition(ctx context.Context, ref Ref, st TicketState) error
	Link(ctx context.Context, child, parent Ref) error
}

// Doer is the HTTP surface every real backend uses.
//
// Injecting it is what lets the backends be exercised, in full, with no network
// and no credentials: the request-building code is the part that can be wrong,
// and it is the part these tests reach.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Options configures the available backends.
type Options struct {
	GitHub GitHubConfig
	Jira   JiraConfig
	Linear LinearConfig
	HTTP   Doer
}

// Open returns the named backend (VM-F-802: selectable by configuration).
//
// An unknown name is an error rather than a fallback. A typo that silently
// disabled ticketing would present as "the scanner stopped finding things".
func Open(name string, opts Options) (Tracker, error) {
	doer := opts.HTTP
	if doer == nil {
		doer = http.DefaultClient
	}
	switch name {
	case "github":
		return NewGitHub(doer, opts.GitHub), nil
	case "jira":
		return NewJira(doer, opts.Jira), nil
	case "linear":
		return NewLinear(doer, opts.Linear), nil
	case "fake":
		return NewFake("fake"), nil
	default:
		return nil, fmt.Errorf("tracker: unknown backend %q; configured backends are github, jira, linear (VM-F-801)", name)
	}
}

// NeedsOwnTicket implements the granularity table (VM-AD §13.3).
//
// The rule that carries the most weight is the last one: P2 and P3 findings
// that are not remediated are aggregated into the run parent and never
// individually ticketed (VM-F-808). Individual tickets for low-priority
// findings are how a backlog becomes unreadable, and an unreadable backlog is
// indistinguishable from no backlog at all.
func NeedsOwnTicket(f model.Finding, outcome policy.Outcome) bool {
	// A secret is ticketed immediately, whatever the routing outcome: the
	// remediation is credential rotation by a human, and batching delays it
	// (VM-F-852).
	if f.Category == model.CategorySecret {
		return true
	}
	switch outcome {
	case policy.OpenTicket, policy.EscalateP0:
		return f.Priority == model.P0 || f.Priority == model.P1
	default:
		// Auto-remediation produces a pull request ticket instead; the skip and
		// defer outcomes are decisions not to act now, and a ticket for each
		// would be a queue of things nobody intends to do.
		return false
	}
}
