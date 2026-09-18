package api_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/api"
	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/store"
)

// OQ-P12-02 — the webhook endpoint.
//
// Until this existed the primary path was code-complete and unreachable from
// outside the process: deliveries could be verified and applied, and nothing
// could receive one. The bounded fallback carried everything.

const webhookSecret = "a-webhook-secret-that-is-long-enough"

// deliver posts a signed delivery, as GitHub would.
func deliver(t *testing.T, h *harness, deliveryID string, payload map[string]any) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest(http.MethodPost, h.HTTP.URL+"/v1/webhooks/github", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-GitHub-Delivery", deliveryID)
	req.Header.Set("X-Hub-Signature-256", sig)

	res, err := h.HTTP.Client().Do(req)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	defer res.Body.Close()
	out := make([]byte, 4096)
	n, _ := res.Body.Read(out)
	return res.StatusCode, out[:n]
}

// withWebhook rebuilds the harness's server with the endpoint registered.
func withWebhook(t *testing.T, h *harness) *orchestrator.Orchestrator {
	t.Helper()
	o := orchestrator.New(h.Store, orchestrator.NewFakeDispatcher(),
		orchestrator.NewRateBudget(50), orchestrator.Config{})
	o.Clock = func() time.Time { return apiNow }

	if err := h.Server.RegisterWebhook(api.WebhookConfig{
		Verifier: gh.NewWebhookVerifier(webhookSecret), Applier: o,
		Log: gh.NewDeliveryLogWithCapacity(100),
	}); err != nil {
		t.Fatalf("RegisterWebhook: %v", err)
	}
	return o
}

// openPRFor finds the fixture's open pull request and its finding.
func openPRFor(t *testing.T, h *harness) store.RemediationPR {
	t.Helper()
	prs, err := h.Store.RemediationPRsForFinding(context.Background(), h.DepFP)
	if err != nil {
		t.Fatalf("RemediationPRsForFinding: %v", err)
	}
	for _, pr := range prs {
		if pr.Open() {
			return pr
		}
	}
	t.Fatal("the fixture has no open pull request")
	return store.RemediationPR{}
}

func TestAVerifiedDeliveryDrivesTheTransitionPromptly(t *testing.T) {
	h := newHarness(t)
	withWebhook(t, h)
	pr := openPRFor(t, h)
	ctx := context.Background()

	before, err := h.Store.GetFinding(ctx, h.DepFP)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if before.State != model.PROpen {
		t.Skipf("the fixture's finding is %s rather than PR_OPEN", before.State)
	}

	status, body := deliver(t, h, "delivery-1", map[string]any{
		"action": "closed",
		"pull_request": map[string]any{
			"number": pr.Number, "merged": true,
			"head": map[string]any{"ref": pr.Branch},
			"base": map[string]any{"ref": "main"},
		},
		"repository": map[string]any{"full_name": pr.Repo},
	})
	if status != http.StatusOK {
		t.Fatalf("delivery = %d: %s", status, body)
	}
	if !bytes.Contains(body, []byte(`"applied":true`)) {
		t.Errorf("the delivery was accepted without being applied: %s", body)
	}

	after, err := h.Store.GetFinding(ctx, h.DepFP)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	// MERGED, never VERIFIED: a merge is a claim about intent, and only a scan
	// that no longer observes the finding is evidence (VM-F-533, VM-ADR-12).
	if after.State != model.Merged {
		t.Errorf("state = %s after a merge webhook, want MERGED", after.State)
	}

	// And the pull request is now CONFIRMED, which is what stops the fallback
	// asking the remote about it (OQ-P12-01).
	rec, ok, err := h.Store.GetRemediationPR(ctx, pr.Branch)
	if err != nil || !ok {
		t.Fatalf("GetRemediationPR: %v %v", ok, err)
	}
	if rec.ConfirmedAt == nil {
		t.Error("a verified delivery about a pull request did not confirm it, so reconciliation " +
			"will still spend an API call re-learning what the webhook just said")
	}
}

func TestAForgedDeliveryIsRefusedWithoutBeingInterpreted(t *testing.T) {
	h := newHarness(t)
	withWebhook(t, h)
	pr := openPRFor(t, h)
	ctx := context.Background()

	before, err := h.Store.GetFinding(ctx, h.DepFP)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}

	// The right shape, the wrong signature.
	body, _ := json.Marshal(map[string]any{
		"action": "closed",
		"pull_request": map[string]any{
			"number": pr.Number, "merged": true,
			"head": map[string]any{"ref": pr.Branch},
			"base": map[string]any{"ref": "main"},
		},
		"repository": map[string]any{"full_name": pr.Repo},
	})
	req, _ := http.NewRequest(http.MethodPost, h.HTTP.URL+"/v1/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-GitHub-Delivery", "forged-1")
	req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(make([]byte, 32)))
	res, err := h.HTTP.Client().Do(req)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("a forged delivery got %d, want 401", res.StatusCode)
	}

	after, err := h.Store.GetFinding(ctx, h.DepFP)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if after.State != before.State {
		t.Errorf("a forged delivery moved %s from %s to %s. The signature is the only thing "+
			"distinguishing GitHub from anyone who found the endpoint", h.DepFP, before.State, after.State)
	}
}

func TestARedeliveryIsIdempotent(t *testing.T) {
	h := newHarness(t)
	withWebhook(t, h)
	pr := openPRFor(t, h)

	payload := map[string]any{
		"action": "closed",
		"pull_request": map[string]any{
			"number": pr.Number, "merged": false,
			"head": map[string]any{"ref": pr.Branch},
			"base": map[string]any{"ref": "main"},
		},
		"repository": map[string]any{"full_name": pr.Repo},
	}
	if status, body := deliver(t, h, "delivery-2", payload); status != http.StatusOK {
		t.Fatalf("first delivery = %d: %s", status, body)
	}
	status, body := deliver(t, h, "delivery-2", payload)
	if status != http.StatusOK {
		t.Errorf("a redelivery got %d; returning a failure makes GitHub retry for ever", status)
	}
	if !bytes.Contains(body, []byte(`"applied":false`)) {
		t.Errorf("a redelivery was applied a second time: %s", body)
	}
}

// TestNoWebhookEndpointWithoutAnAppRegistered is the fail-closed half: a
// deployment with no GitHub App must have no endpoint, rather than one that
// accepts deliveries and discards them — the sender would record success.
func TestNoWebhookEndpointWithoutAnAppRegistered(t *testing.T) {
	h := newHarness(t)

	res, err := h.HTTP.Client().Post(h.HTTP.URL+"/v1/webhooks/github", "application/json",
		bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Error("a server with no webhook registered accepted a delivery. GitHub would record " +
			"success and stop retrying, and the state change would be carried only by the " +
			"fallback — silently")
	}
}

var _ = fmt.Sprintf
