package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// Phase 8 store surface: the local ticket record.
//
// The record is the primary idempotency mechanism (VM-AD §13.2) — the backend
// query is only the reconciliation fallback — so it is held to the conformance
// suite like everything else. A memory backend that remembered tickets
// differently from Postgres would make every tracker test a statement about
// the fake.

func ticketFixture(t *testing.T, s store.Store) string {
	t.Helper()
	ctx := context.Background()
	seedRepo(t, s)
	r := newRun(t, s, store.KindSweep)
	if _, err := s.UpsertObservations(ctx, r.ID, testRepo, []model.RawFinding{cryptoFinding("govulncheck")}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	return cryptoFP()
}

func TestTicketRecordRoundTrips(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fp := ticketFixture(t, s)

		if _, ok, err := s.GetTicket(ctx, fp); err != nil || ok {
			t.Fatalf("GetTicket on a finding with no ticket = (%v, %v), want (false, nil)", ok, err)
		}

		want := store.Ticket{
			Fingerprint: fp, Backend: "github", Ref: "org/wanaware-api#41",
			URL:       "https://github.com/org/wanaware-api/issues/41",
			CreatedAt: time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC),
		}
		if err := s.SaveTicket(ctx, want); err != nil {
			t.Fatalf("SaveTicket: %v", err)
		}
		got, ok, err := s.GetTicket(ctx, fp)
		if err != nil || !ok {
			t.Fatalf("GetTicket = (%v, %v), want (true, nil)", ok, err)
		}
		if got.Backend != want.Backend || got.Ref != want.Ref || got.URL != want.URL {
			t.Errorf("ticket round-trip = %+v, want %+v", got, want)
		}
		if !got.CreatedAt.Equal(want.CreatedAt) {
			t.Errorf("created_at = %v, want %v", got.CreatedAt, want.CreatedAt)
		}
		if got.ClosedAt != nil {
			t.Errorf("a new ticket is closed: %v", got.ClosedAt)
		}

		// Saving again is an update, not a second ticket: the record is keyed on
		// the fingerprint, which is what makes creation idempotent (VM-F-804).
		second := want
		second.MirrorBackend, second.MirrorRef = "jira", "SEC-9"
		if err := s.SaveTicket(ctx, second); err != nil {
			t.Fatalf("second SaveTicket: %v", err)
		}
		got, _, err = s.GetTicket(ctx, fp)
		if err != nil {
			t.Fatalf("GetTicket: %v", err)
		}
		if got.MirrorRef != "SEC-9" {
			t.Errorf("mirror_ref = %q, want SEC-9", got.MirrorRef)
		}
	})
}

func TestCloseTicketRecordsWhenAndDeleteRemoves(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fp := ticketFixture(t, s)

		at := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
		if err := s.SaveTicket(ctx, store.Ticket{
			Fingerprint: fp, Backend: "github", Ref: "#41", URL: "u", CreatedAt: at.Add(-time.Hour),
		}); err != nil {
			t.Fatalf("SaveTicket: %v", err)
		}
		if err := s.CloseTicket(ctx, fp, at); err != nil {
			t.Fatalf("CloseTicket: %v", err)
		}
		got, _, err := s.GetTicket(ctx, fp)
		if err != nil {
			t.Fatalf("GetTicket: %v", err)
		}
		if got.ClosedAt == nil || !got.ClosedAt.Equal(at) {
			t.Errorf("closed_at = %v, want %v", got.ClosedAt, at)
		}

		// Deletion is the data-loss simulation the reconciliation gate needs.
		if err := s.DeleteTicket(ctx, fp); err != nil {
			t.Fatalf("DeleteTicket: %v", err)
		}
		if _, ok, err := s.GetTicket(ctx, fp); err != nil || ok {
			t.Fatalf("GetTicket after delete = (%v, %v), want (false, nil)", ok, err)
		}
	})
}

// TestTicketReferenceSurvivesReprojection is the standing-lens clause at the
// store boundary.
//
// The ticket reference is surfaced on the finding, and the finding document is
// rebuilt from observations on every scan. If the reference lived in that
// document it would be silently erased by the next run, and the system would
// open a second ticket for a finding that already had one — the exact failure
// the idempotency record exists to prevent, arriving one run later.
func TestTicketReferenceSurvivesReprojection(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fp := ticketFixture(t, s)

		if err := s.SaveTicket(ctx, store.Ticket{
			Fingerprint: fp, Backend: "github", Ref: "org/wanaware-api#41",
			URL: "https://github.com/org/wanaware-api/issues/41", CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("SaveTicket: %v", err)
		}

		before, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("GetFinding: %v", err)
		}
		if before.Refs.Ticket == nil {
			t.Fatal("the finding does not carry its ticket reference; a consumer cannot find the ticket from the finding (VM-F-809)")
		}

		// A later run observes the same finding again, which reprojects it.
		r2 := newRun(t, s, store.KindSweep)
		if _, err := s.UpsertObservations(ctx, r2.ID, testRepo, []model.RawFinding{
			cryptoFinding("govulncheck"), cryptoFinding("osv-scanner"),
		}); err != nil {
			t.Fatalf("second upsert: %v", err)
		}

		after, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("GetFinding after reprojection: %v", err)
		}
		if after.Refs.Ticket == nil {
			t.Fatal("reprojection dropped the ticket reference; the next run would open a duplicate ticket")
		}
		if *after.Refs.Ticket != *before.Refs.Ticket {
			t.Errorf("ticket reference changed across reprojection: %q -> %q", *before.Refs.Ticket, *after.Refs.Ticket)
		}

		// And through the list path, which reports and the interface read.
		list, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
		if err != nil {
			t.Fatalf("ListFindings: %v", err)
		}
		var seen bool
		for _, f := range list {
			if f.Fingerprint == fp {
				seen = true
				if f.Refs.Ticket == nil {
					t.Error("ListFindings drops the ticket reference that GetFinding carries")
				}
			}
		}
		if !seen {
			t.Fatal("the finding is missing from ListFindings")
		}
	})
}

// --- Failure isolation queue (VM-F-812, VM-AD §13.5) -----------------------

// TestTicketOpsQueueIsDurableAndRetried covers the requirement that tracker
// unavailability never fails a run. The queue has to be durable and to hold
// enough to replay the operation: an op that records only "something failed"
// cannot be retried, and the ticket is lost with no trace.
func TestTicketOpsQueueIsDurableAndRetried(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		fp := ticketFixture(t, s)
		now := time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)

		payload, _ := json.Marshal(map[string]string{"title": "x"})
		if err := s.EnqueueTicketOp(ctx, store.TicketOp{
			Fingerprint: fp, Kind: "create", Payload: payload, NextAttemptAt: now,
		}); err != nil {
			t.Fatalf("EnqueueTicketOp: %v", err)
		}

		due, err := s.DueTicketOps(ctx, now, 10)
		if err != nil {
			t.Fatalf("DueTicketOps: %v", err)
		}
		if len(due) != 1 {
			t.Fatalf("due ops = %d, want 1", len(due))
		}
		if string(due[0].Payload) != string(payload) {
			t.Errorf("payload = %s, want %s; an op that cannot be replayed is not a retry queue", due[0].Payload, payload)
		}

		// A failed attempt backs off rather than spinning.
		later := now.Add(5 * time.Minute)
		if err := s.RetryTicketOp(ctx, due[0].ID, later, "502 from backend"); err != nil {
			t.Fatalf("RetryTicketOp: %v", err)
		}
		if got, err := s.DueTicketOps(ctx, now, 10); err != nil || len(got) != 0 {
			t.Fatalf("op is still due before its backoff expires: %d ops, err=%v", len(got), err)
		}
		got, err := s.DueTicketOps(ctx, later, 10)
		if err != nil {
			t.Fatalf("DueTicketOps: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("op did not become due again: %d", len(got))
		}
		if got[0].Attempts != 1 {
			t.Errorf("attempts = %d, want 1", got[0].Attempts)
		}
		if got[0].LastError == "" {
			t.Error("the queue records no reason for the retry; an operator cannot tell a broken token from a rate limit")
		}

		if err := s.CompleteTicketOp(ctx, got[0].ID); err != nil {
			t.Fatalf("CompleteTicketOp: %v", err)
		}
		if remaining, err := s.DueTicketOps(ctx, later, 10); err != nil || len(remaining) != 0 {
			t.Fatalf("a completed op is still due: %d, err=%v", len(remaining), err)
		}
	})
}
