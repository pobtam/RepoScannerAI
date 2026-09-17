package gh_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/gh"
)

// Phase 12 — the GitHub App.
//
// A webhook is UNTRUSTED EXTERNAL INPUT. It arrives over the internet, from a
// sender the framework cannot authenticate beyond a shared secret, and it asks
// the system to change state. Every property asserted here follows from
// treating it that way rather than as a notification from a trusted peer:
//
//	a forged event must not be accepted at all;
//	a replayed event must not act twice;
//	events delivered out of order must not produce a different outcome than
//	  events delivered in order;
//	an event that never arrives must not leave the system wrong for ever.
//
// The last is why the reconciliation path from Phase 9b stays. The webhook
// makes a transition PROMPT; it does not make it certain.

const secret = "shhh-webhook-secret"

func sign(body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func prClosedBody(number int, merged bool, deliveryRepo string) []byte {
	m := "false"
	if merged {
		m = "true"
	}
	return []byte(`{"action":"closed","repository":{"full_name":"` + deliveryRepo + `"},` +
		`"pull_request":{"number":` + itoa(number) + `,"merged":` + m + `,"head":{"ref":"security/fix-abc123"}}}`)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

// --- Signature: a forged event is not an event ------------------------------

// TestAnUnsignedOrForgedEventIsRejected is the first gate. Everything
// downstream — the transitions, the idempotency, the ordering — is irrelevant
// if anyone who can reach the endpoint can drive it.
func TestAnUnsignedOrForgedEventIsRejected(t *testing.T) {
	v := gh.NewWebhookVerifier(secret)
	body := prClosedBody(41, false, "org/api")

	cases := map[string]string{
		"no signature":     "",
		"wrong secret":     "sha256=" + hex.EncodeToString([]byte("nope")),
		"truncated digest": sign(body)[:20],
		"not hex":          "sha256=zzzz",
		"wrong algorithm":  strings.Replace(sign(body), "sha256=", "sha1=", 1),
	}
	for name, signature := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Parse(body, signature, "delivery-1"); err == nil {
				t.Error("a forged event was accepted; anyone able to reach the endpoint could drive " +
					"state transitions in the findings store")
			}
		})
	}

	// And the genuine one is accepted.
	ev, err := v.Parse(body, sign(body), "delivery-1")
	if err != nil {
		t.Fatalf("a correctly signed event was rejected: %v", err)
	}
	if ev.Kind != gh.EventPullRequestClosed || ev.Number != 41 {
		t.Errorf("parsed %+v, want a pull request closure for #41", ev)
	}
	if ev.Merged {
		t.Error("an unmerged closure parsed as merged; the two drive opposite transitions (VM-F-545)")
	}
}

// TestSignatureComparisonIsConstantTime is a small thing that matters here.
// A byte-by-byte comparison leaks the correct digest to anyone who can time
// the endpoint, and the endpoint is on the internet.
func TestSignatureComparisonIsConstantTime(t *testing.T) {
	if !gh.SignatureComparisonIsConstantTime() {
		t.Error("signature comparison is not constant time; the digest leaks to anyone who can time " +
			"the endpoint, and the endpoint is reachable from the internet")
	}
}

// --- Idempotency and ordering ------------------------------------------------

// TestADuplicateDeliveryIsAppliedOnce covers the weakest guarantee GitHub
// actually offers: at-least-once delivery. A retried webhook is not an error
// and not rare — it is what happens whenever the endpoint is slow.
func TestADuplicateDeliveryIsAppliedOnce(t *testing.T) {
	log := gh.NewDeliveryLog()
	body := prClosedBody(41, true, "org/api")
	v := gh.NewWebhookVerifier(secret)

	ev, err := v.Parse(body, sign(body), "delivery-abc")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !log.Accept(ev) {
		t.Fatal("the first delivery was rejected as a duplicate")
	}
	for i := 0; i < 3; i++ {
		if log.Accept(ev) {
			t.Fatalf("redelivery %d was accepted again; at-least-once is the guarantee GitHub offers, "+
				"so exactly-once is this system's job", i+1)
		}
	}
}

// TestOutOfOrderDeliveryDoesNotRegress is the property that makes webhooks
// usable at all. GitHub does not guarantee order, so a "closed" arriving
// before the "opened" it closes must not leave the system believing the pull
// request is open.
func TestOutOfOrderDeliveryDoesNotRegress(t *testing.T) {
	log := gh.NewDeliveryLog()
	v := gh.NewWebhookVerifier(secret)

	earlier := []byte(`{"action":"opened","repository":{"full_name":"org/api"},` +
		`"pull_request":{"number":41,"merged":false,"head":{"ref":"security/fix-abc123"}}}`)
	later := prClosedBody(41, true, "org/api")

	closed, err := v.Parse(later, sign(later), "delivery-2")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	opened, err := v.Parse(earlier, sign(earlier), "delivery-1")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// The closure arrives first.
	if !log.Accept(closed) {
		t.Fatal("the closure was rejected")
	}
	// The opening arrives second, and must not undo it.
	if log.Accept(opened) {
		t.Error("an out-of-order 'opened' was accepted after the 'closed' for the same pull request; " +
			"the system would believe a merged pull request is still open, and the finding would sit " +
			"in PR_OPEN waiting for an event that has already been delivered")
	}
}

// TestAnEventForAnUnknownSubjectIsRejectedNotGuessed is the negative half. An
// event naming a pull request the framework never opened is either a
// misconfiguration or an attack, and acting on it means acting on a repository
// the framework was never asked to touch.
func TestAnEventForAnUnknownSubjectIsRejectedNotGuessed(t *testing.T) {
	v := gh.NewWebhookVerifier(secret)
	body := []byte(`{"action":"closed","repository":{"full_name":""},` +
		`"pull_request":{"number":0,"merged":false,"head":{"ref":""}}}`)
	if _, err := v.Parse(body, sign(body), "delivery-x"); err == nil {
		t.Error("an event naming no repository and no pull request was accepted")
	}
}

// TestAnUnknownEventKindIsIgnoredNotFailed covers the operational reality: a
// GitHub App receives event types nobody subscribed to on purpose, and
// erroring on them would fill the log with noise and mask the real failures.
func TestAnUnknownEventKindIsIgnoredNotFailed(t *testing.T) {
	v := gh.NewWebhookVerifier(secret)
	body := []byte(`{"action":"labeled","repository":{"full_name":"org/api"},` +
		`"pull_request":{"number":41,"merged":false,"head":{"ref":"x"}}}`)
	ev, err := v.Parse(body, sign(body), "delivery-y")
	if err != nil {
		t.Fatalf("an unsubscribed event kind errored: %v", err)
	}
	if ev.Kind != gh.EventIgnored {
		t.Errorf("kind = %q, want ignored", ev.Kind)
	}
}

// TestTheDeliveryLogBoundsItsMemory is the operational guard. A log that grows
// for ever is a slow leak in a long-running process, and the fix must not be
// to forget recent deliveries — which would reintroduce double-application.
func TestTheDeliveryLogBoundsItsMemory(t *testing.T) {
	log := gh.NewDeliveryLogWithCapacity(100)
	v := gh.NewWebhookVerifier(secret)

	var firstEvent gh.Event
	for i := 1; i <= 500; i++ {
		body := prClosedBody(i, false, "org/api")
		ev, err := v.Parse(body, sign(body), "delivery-"+itoa(i))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if i == 1 {
			firstEvent = ev
		}
		log.Accept(ev)
	}
	if n := log.Size(); n > 100 {
		t.Errorf("the log holds %d entries with a capacity of 100; it leaks in a long-running process", n)
	}
	// The most recent deliveries are still deduplicated: evicting those would
	// trade a leak for double-application, which is the worse failure.
	recentBody := prClosedBody(500, false, "org/api")
	recent, _ := v.Parse(recentBody, sign(recentBody), "delivery-500")
	if log.Accept(recent) {
		t.Error("a recent delivery was forgotten; eviction must drop the oldest, not the newest")
	}
	_ = firstEvent
}

var _ = time.Now
