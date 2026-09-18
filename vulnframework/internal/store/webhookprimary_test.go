package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/store"
)

// OQ-P12-01, the store's half: asking about the unconfirmed instead of about
// everything.
//
// Three properties, each load-bearing, each with its own failing mutation:
// only unconfirmed pull requests are returned, the OLDEST confirmation comes
// first (so a bounded batch cannot starve the tail), and the bound is honoured.
// Both backends, because a selection rule that holds on one and not the other
// means the fallback polls one deployment and not the next.

var whNow = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

func seedPR(t *testing.T, s store.Store, branch string, number int, confirmed *time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := s.SaveRemediationPR(ctx, store.RemediationPR{
		Branch: branch, Repo: testRepo, FixGroupID: branch, Number: number,
		URL: "https://github.com/org/wanaware-api/pull/" + branch, State: "open", OpenedAt: whNow.Add(-48 * time.Hour),
	}); err != nil {
		t.Fatalf("SaveRemediationPR: %v", err)
	}
	if confirmed != nil {
		if err := s.ConfirmRemediationPR(ctx, branch, *confirmed); err != nil {
			t.Fatalf("ConfirmRemediationPR: %v", err)
		}
	}
}

func at(d time.Duration) *time.Time {
	t := whNow.Add(d)
	return &t
}

func TestOnlyUnconfirmedPullRequestsAreSelected(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)

		seedPR(t, s, "fresh", 1, at(-5*time.Minute)) // vouched for just now
		seedPR(t, s, "stale", 2, at(-9*time.Hour))   // vouched for long ago
		seedPR(t, s, "never", 3, nil)                // never vouched for

		due, err := s.UnconfirmedRemediationPRs(ctx, testRepo, whNow.Add(-6*time.Hour), 10)
		if err != nil {
			t.Fatalf("UnconfirmedRemediationPRs: %v", err)
		}
		got := map[string]bool{}
		for _, pr := range due {
			got[pr.Branch] = true
		}
		if got["fresh"] {
			t.Error("a pull request confirmed five minutes ago is due for a query; that is the " +
				"poll, re-learning what the webhook just said (OQ-P12-01)")
		}
		if !got["stale"] || !got["never"] {
			t.Errorf("the stale and never-confirmed pull requests must be asked about: got %v", got)
		}

		// A confirmation moves it out of the set — the point of recording one.
		if err := s.ConfirmRemediationPR(ctx, "stale", whNow); err != nil {
			t.Fatalf("ConfirmRemediationPR: %v", err)
		}
		due, err = s.UnconfirmedRemediationPRs(ctx, testRepo, whNow.Add(-6*time.Hour), 10)
		if err != nil {
			t.Fatalf("UnconfirmedRemediationPRs: %v", err)
		}
		for _, pr := range due {
			if pr.Branch == "stale" {
				t.Error("a freshly confirmed pull request is still due")
			}
		}
	})
}

func TestTheOldestConfirmationIsAskedAboutFirst(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)

		// Deliberately inserted newest-first, so an implementation that
		// returned insertion or branch order would pass by accident.
		seedPR(t, s, "b-recent", 1, at(-7*time.Hour))
		seedPR(t, s, "a-ancient", 2, at(-40*time.Hour))
		seedPR(t, s, "c-never", 3, nil)

		due, err := s.UnconfirmedRemediationPRs(ctx, testRepo, whNow.Add(-6*time.Hour), 2)
		if err != nil {
			t.Fatalf("UnconfirmedRemediationPRs: %v", err)
		}
		if len(due) != 2 {
			t.Fatalf("got %d pull requests with a limit of 2", len(due))
		}
		if due[0].Branch != "c-never" {
			t.Errorf("first due = %q, want the never-confirmed one: nothing has EVER vouched for "+
				"it, so it is the least known state in the set", due[0].Branch)
		}
		if due[1].Branch != "a-ancient" {
			t.Errorf("second due = %q, want the oldest confirmation. A bounded batch in the wrong "+
				"order starves the tail for ever: the same pull requests are asked about every "+
				"sweep and the rest are never reached", due[1].Branch)
		}
	})
}

func TestAClosedPullRequestIsNeverDue(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		seedPR(t, s, "settled", 1, nil)
		if err := s.CloseRemediationPR(ctx, "settled", whNow, true); err != nil {
			t.Fatalf("CloseRemediationPR: %v", err)
		}

		due, err := s.UnconfirmedRemediationPRs(ctx, testRepo, whNow, 10)
		if err != nil {
			t.Fatalf("UnconfirmedRemediationPRs: %v", err)
		}
		if len(due) != 0 {
			t.Errorf("a closed pull request is due for a query: %+v. Its state is settled; asking "+
				"again spends a call to learn nothing", due)
		}
	})
}

// TestWebhookHealthDistinguishesQuietFromBroken is the tri-state discipline
// applied to the delivery path: no deliveries is not the same fact as no
// events, and the zero value must not read as "live since the epoch".
func TestWebhookHealthDistinguishesQuietFromBroken(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()

		h, err := s.WebhookHealth(ctx)
		if err != nil {
			t.Fatalf("WebhookHealth: %v", err)
		}
		if !h.LastDeliveryAt.IsZero() || h.Deliveries != 0 {
			t.Errorf("a store that has received no delivery reports %+v", h)
		}
		if h.Live(whNow, time.Hour) {
			t.Error("a webhook that has NEVER delivered reads as live; the fallback would then " +
				"trust a path that has never worked — an unconfigured endpoint would look healthy")
		}

		if err := s.RecordWebhookDelivery(ctx, whNow.Add(-10*time.Minute)); err != nil {
			t.Fatalf("RecordWebhookDelivery: %v", err)
		}
		if err := s.RecordWebhookDelivery(ctx, whNow.Add(-2*time.Minute)); err != nil {
			t.Fatalf("RecordWebhookDelivery: %v", err)
		}
		h, err = s.WebhookHealth(ctx)
		if err != nil {
			t.Fatalf("WebhookHealth: %v", err)
		}
		if h.Deliveries != 2 {
			t.Errorf("deliveries = %d, want 2", h.Deliveries)
		}
		if !h.Live(whNow, 30*time.Minute) {
			t.Errorf("a delivery two minutes ago does not read as live: %+v", h)
		}
		if h.Live(whNow, time.Minute) {
			t.Error("a delivery two minutes ago reads as live inside a one-minute window")
		}

		// An out-of-order delivery must not move the clock backwards: a
		// retried delivery carrying an older timestamp would otherwise make a
		// live path look silent.
		if err := s.RecordWebhookDelivery(ctx, whNow.Add(-6*time.Hour)); err != nil {
			t.Fatalf("RecordWebhookDelivery: %v", err)
		}
		h, err = s.WebhookHealth(ctx)
		if err != nil {
			t.Fatalf("WebhookHealth: %v", err)
		}
		if !h.Live(whNow, 30*time.Minute) {
			t.Errorf("a late redelivery made the path look silent: %+v", h)
		}
	})
}
