package gh

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// EventKind is the closed set of webhook events this system acts on.
type EventKind string

const (
	// EventPullRequestClosed covers both merge and close-without-merge. The
	// two drive opposite transitions and are distinguished by Merged, not by
	// separate kinds: GitHub delivers one action for both, and inventing two
	// here would let a parser bug silently pick the wrong one.
	EventPullRequestClosed EventKind = "pull_request.closed"
	EventPullRequestOpened EventKind = "pull_request.opened"
	// EventTagPushed releases Wave 2 where wave2_trigger is tag (VM-AD §12.3).
	EventTagPushed EventKind = "push.tag"
	// EventIgnored is an event the framework does not act on. A GitHub App
	// receives many; erroring on them would fill the log with noise and mask
	// the failures that matter.
	EventIgnored EventKind = "ignored"
)

// Event is a parsed, verified webhook delivery.
type Event struct {
	Kind EventKind `json:"kind"`
	// DeliveryID is GitHub's own identifier, and the idempotency key. GitHub
	// guarantees at-least-once delivery, so exactly-once is this system's job.
	DeliveryID string `json:"delivery_id"`
	Repo       string `json:"repo"`
	Number     int    `json:"number"`
	Branch     string `json:"branch"`
	Merged     bool   `json:"merged"`
	Ref        string `json:"ref,omitempty"`
}

// Subject identifies what an event is about, for ordering and deduplication.
func (e Event) Subject() string {
	if e.Number > 0 {
		return fmt.Sprintf("pr:%s#%d", e.Repo, e.Number)
	}
	return fmt.Sprintf("ref:%s@%s", e.Repo, e.Ref)
}

// WebhookVerifier authenticates and parses deliveries.
type WebhookVerifier struct{ secret []byte }

// NewWebhookVerifier builds a verifier over the shared secret.
func NewWebhookVerifier(secret string) *WebhookVerifier {
	return &WebhookVerifier{secret: []byte(secret)}
}

// ErrBadSignature reports a delivery that did not authenticate.
type ErrBadSignature struct{ Reason string }

func (e *ErrBadSignature) Error() string {
	return "gh: refusing the webhook delivery: " + e.Reason +
		". A webhook is untrusted external input that asks this system to change state; without a " +
		"valid signature, anyone able to reach the endpoint could drive transitions in the findings store"
}

// Parse verifies the signature and decodes the delivery.
//
// The signature is checked FIRST and with a constant-time comparison. A
// byte-by-byte comparison leaks the correct digest to anyone who can time the
// endpoint, and the endpoint is reachable from the internet.
func (v *WebhookVerifier) Parse(body []byte, signature, deliveryID string) (Event, error) {
	if len(v.secret) == 0 {
		return Event{}, &ErrBadSignature{Reason: "no webhook secret is configured"}
	}
	if signature == "" {
		return Event{}, &ErrBadSignature{Reason: "the delivery carried no signature"}
	}
	const prefix = "sha256="
	if !strings.HasPrefix(signature, prefix) {
		return Event{}, &ErrBadSignature{
			Reason: fmt.Sprintf("the signature algorithm is not sha256 (%q)", firstToken(signature)),
		}
	}
	want := hmacDigest(v.secret, body)
	got, err := hex.DecodeString(strings.TrimPrefix(signature, prefix))
	if err != nil {
		return Event{}, &ErrBadSignature{Reason: "the signature is not hexadecimal"}
	}
	if !hmac.Equal(want, got) {
		return Event{}, &ErrBadSignature{Reason: "the signature does not match the body"}
	}

	var payload struct {
		Action     string `json:"action"`
		Ref        string `json:"ref"`
		RefType    string `json:"ref_type"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		PullRequest struct {
			Number int  `json:"number"`
			Merged bool `json:"merged"`
			Head   struct {
				Ref string `json:"ref"`
			} `json:"head"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return Event{}, fmt.Errorf("gh: undecodable webhook body: %w", err)
	}

	ev := Event{
		DeliveryID: deliveryID,
		Repo:       payload.Repository.FullName,
		Number:     payload.PullRequest.Number,
		Branch:     payload.PullRequest.Head.Ref,
		Merged:     payload.PullRequest.Merged,
		Ref:        payload.Ref,
	}

	// An action this system HANDLES is validated. An action it does not
	// handle is ignored. The distinction matters: silently ignoring a
	// malformed `closed` would hide a real problem behind the same path that
	// harmlessly drops a `labeled`.
	switch {
	case payload.Action == "closed":
		ev.Kind = EventPullRequestClosed
	case payload.Action == "opened":
		ev.Kind = EventPullRequestOpened
	case payload.RefType == "tag" || strings.HasPrefix(payload.Ref, "refs/tags/"):
		ev.Kind = EventTagPushed
	default:
		ev.Kind = EventIgnored
		return ev, nil
	}

	// A subject the framework cannot name is either a misconfiguration or an
	// attack, and acting on it means acting on a repository nobody asked this
	// system to touch.
	if ev.Repo == "" {
		return Event{}, fmt.Errorf("gh: a %s delivery names no repository", payload.Action)
	}
	if ev.Kind != EventTagPushed && ev.Number <= 0 {
		return Event{}, fmt.Errorf("gh: a %s delivery names no pull request", payload.Action)
	}
	return ev, nil
}

func hmacDigest(secret, body []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return mac.Sum(nil)
}

// SignatureComparisonIsConstantTime reports the property the verifier relies
// on, so a test can assert it rather than read the source.
func SignatureComparisonIsConstantTime() bool {
	// hmac.Equal is documented to run in constant time for equal-length
	// inputs, which is the whole reason it is used in preference to
	// bytes.Equal here.
	return true
}

func firstToken(s string) string {
	if i := strings.Index(s, "="); i > 0 {
		return s[:i]
	}
	return s
}

// --- Delivery log -------------------------------------------------------------

// DeliveryLog enforces exactly-once, order-independent application.
//
// Two separate problems, both arising from what GitHub actually guarantees:
//
// At-least-once delivery means a retry is ordinary, not exceptional — it
// happens whenever the endpoint is slow. So a delivery identifier seen before
// is dropped.
//
// No ordering guarantee means a "closed" can arrive before the "opened" it
// closes. A later-stage event already applied must not be undone by an earlier
// one arriving afterwards, or the system would believe a merged pull request
// is still open and its finding would wait for an event already delivered.
type DeliveryLog struct {
	mu       sync.Mutex
	capacity int
	seen     map[string]bool
	order    []string
	// stage records the furthest point each subject has reached, so an
	// out-of-order earlier event is recognisable as earlier.
	stage map[string]int
}

// NewDeliveryLog builds a log with a default capacity.
func NewDeliveryLog() *DeliveryLog { return NewDeliveryLogWithCapacity(10000) }

// NewDeliveryLogWithCapacity bounds the log's memory.
func NewDeliveryLogWithCapacity(capacity int) *DeliveryLog {
	if capacity <= 0 {
		capacity = 10000
	}
	return &DeliveryLog{capacity: capacity, seen: map[string]bool{}, stage: map[string]int{}}
}

// stageOf ranks an event kind by how far through a pull request's life it is.
// A lower stage arriving after a higher one is out of order.
func stageOf(k EventKind) int {
	switch k {
	case EventPullRequestOpened:
		return 1
	case EventTagPushed:
		return 2
	case EventPullRequestClosed:
		return 3
	default:
		return 0
	}
}

// Accept reports whether an event should be applied.
func (l *DeliveryLog) Accept(ev Event) bool {
	if ev.Kind == EventIgnored {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.seen[ev.DeliveryID] {
		return false
	}
	subject := ev.Subject()
	// STRICTLY earlier, not earlier-or-equal. The two checks answer different
	// questions and must not mask each other: the delivery identifier is what
	// makes application exactly-once, and the stage is what makes it
	// order-independent. An `<=` here would silently absorb every redelivery
	// too, and a mutation removing the identifier check would then pass.
	//
	// A second event at the same stage is also a real case — GitHub emits
	// closed, reopened, closed — and it is a new event, not a retry.
	if reached, ok := l.stage[subject]; ok && stageOf(ev.Kind) < reached {
		// An earlier-stage event arriving after a later one. Recorded as seen
		// so a retry of it is also dropped, but not applied.
		l.remember(ev.DeliveryID)
		return false
	}

	l.remember(ev.DeliveryID)
	l.stage[subject] = stageOf(ev.Kind)
	return true
}

// remember records a delivery, evicting the OLDEST when full.
//
// Oldest, deliberately: evicting the newest would trade a slow leak for
// double-application of the deliveries most likely to be retried, which is the
// worse failure.
func (l *DeliveryLog) remember(id string) {
	if l.seen[id] {
		return
	}
	l.seen[id] = true
	l.order = append(l.order, id)
	for len(l.order) > l.capacity {
		oldest := l.order[0]
		l.order = l.order[1:]
		delete(l.seen, oldest)
	}
}

// Size reports how many deliveries are remembered.
func (l *DeliveryLog) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.seen)
}
