package api

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/orchestrator"
)

// The webhook endpoint (VM-AD §7.4, OQ-P12-02).
//
// This is what makes the webhook the primary path REACHABLE. Until it existed,
// gh.WebhookVerifier could authenticate a delivery and ApplyWebhook could
// drive it, and nothing in the running system could receive one — so the
// bounded fallback carried everything, which is exactly the shape of gap the
// build log exists to name.
//
// It is deliberately NOT behind the interface's authenticator: GitHub does not
// authenticate as a user. It authenticates with an HMAC over the body, which
// is verified in constant time, and a delivery that fails verification is
// refused without being interpreted.

// WebhookConfig wires the endpoint.
type WebhookConfig struct {
	Verifier *gh.WebhookVerifier
	// Applier drives the transitions a verified delivery implies. The
	// orchestrator satisfies it.
	Applier interface {
		ApplyWebhook(ctx context.Context, ev gh.Event) (orchestrator.SyncStats, error)
	}
	// Log records deliveries for exactly-once handling. Shared with the
	// verifier's own log so a redelivery is recognised across both.
	Log *gh.DeliveryLog
}

// RegisterWebhook adds the endpoint. Separate from New so a deployment without
// a GitHub App has no endpoint at all rather than one that accepts and
// discards — a silently accepted delivery is worse than a 404, because the
// sender records success.
func (s *Server) RegisterWebhook(cfg WebhookConfig) error {
	if cfg.Verifier == nil || cfg.Applier == nil {
		return errors.New("api: a webhook endpoint needs a verifier and an applier")
	}
	s.webhook = cfg
	s.mux.HandleFunc("POST /v1/webhooks/github", s.handleWebhook)
	return nil
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "unreadable body", err.Error(),
			"GitHub retries deliveries; nothing was applied")
		return
	}

	ev, err := s.webhook.Verifier.Parse(body,
		r.Header.Get("X-Hub-Signature-256"), r.Header.Get("X-GitHub-Delivery"))
	if err != nil {
		// A delivery that cannot be verified is refused WITHOUT being
		// interpreted: the signature is what distinguishes GitHub from anyone
		// who found the endpoint, and a forged event could otherwise drive a
		// state transition (VM-F-611).
		s.log.Warn("api: refused a webhook delivery", "error", err, "remote", r.RemoteAddr)
		s.fail(w, r, http.StatusUnauthorized, "delivery not verified", err.Error(),
			"check the webhook secret; nothing was applied")
		return
	}

	// Exactly-once by delivery identifier, and order-independent by stage.
	// GitHub redelivers, and a redelivery must not drive a second transition
	// (VM-F-612); an out-of-order delivery must not undo a later one.
	if s.webhook.Log != nil && !s.webhook.Log.Accept(ev) {
		// 200, not an error: from GitHub's point of view the delivery arrived,
		// and a failure would make it retry for ever.
		s.write(w, r, http.StatusOK, map[string]any{
			"applied": false,
			"reason": "this delivery was already applied, or arrived after a later stage of the " +
				"same pull request; either way applying it again would move state backwards",
		})
		return
	}

	stats, err := s.webhook.Applier.ApplyWebhook(r.Context(), ev)
	if err != nil {
		s.log.Error("api: applying a webhook", "error", err, "kind", ev.Kind)
		s.fail(w, r, http.StatusInternalServerError, "could not apply", err.Error(),
			"the delivery was verified but could not be applied; the reconciliation pass will "+
				"catch the state change within one sweep")
		return
	}
	s.write(w, r, http.StatusOK, map[string]any{
		"applied":   true,
		"kind":      string(ev.Kind),
		"examined":  stats.Examined,
		"merged":    stats.Merged,
		"declined":  stats.Declined,
		"confirmed": stats.Confirmed,
	})
}
