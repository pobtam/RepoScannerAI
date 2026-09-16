package tracker_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/tracker"
)

// --- Failure isolation (VM-F-812, VM-AD §13.5) ------------------------------

// TestTrackerUnavailabilityDoesNotFailTheRun is the availability invariant. A
// run that aborts because the ticket tracker is down converts a third-party
// outage into a coverage gap: no scan, no findings, no report. The ticket is
// queued instead, and the queue is durable so the work survives a restart.
func TestTrackerUnavailabilityDoesNotFailTheRun(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	fake := tracker.NewFake("github")
	fake.FailWith(errors.New("503 service unavailable"))
	svc := service(s, fake)

	fp := fingerprint.Compute(depFinding())
	observeIn(t, s, []model.RawFinding{depFinding()})

	ref, created, err := svc.Ensure(ctx, specFor(t, s, fp))
	if err != nil {
		t.Fatalf("a tracker outage failed the run: %v", err)
	}
	if created || !ref.Zero() {
		t.Errorf("Ensure reported a ticket that was never created: ref=%+v created=%v", ref, created)
	}

	// The work is durably queued, with enough to replay it.
	ops, err := s.DueTicketOps(ctx, time.Now().UTC().Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("DueTicketOps: %v", err)
	}
	if len(ops) != 1 {
		t.Fatalf("queued ops = %d, want 1; the ticket was dropped, not deferred", len(ops))
	}
	if ops[0].Fingerprint != fp || ops[0].Kind != "create" {
		t.Errorf("queued op = %+v, want a create for %s", ops[0], fp)
	}

	// When the backend recovers, the drain creates exactly one ticket.
	fake.FailWith(nil)
	drained, err := svc.Drain(ctx, time.Now().UTC().Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if drained != 1 {
		t.Errorf("drained %d ops, want 1", drained)
	}
	if fake.CreateCount() != 1 {
		t.Errorf("backend creates = %d, want 1", fake.CreateCount())
	}
	if _, ok, err := s.GetTicket(ctx, fp); err != nil || !ok {
		t.Error("the drained op left no local record; the next run would create a duplicate")
	}
	// And the queue is empty, so the drain is not itself a duplicate source.
	if ops, err := s.DueTicketOps(ctx, time.Now().UTC().Add(time.Hour), 10); err != nil || len(ops) != 0 {
		t.Errorf("queue still holds %d ops after a successful drain", len(ops))
	}
}

// TestQueuedOperationCarriesNoCredentialMaterial closes the obvious hole in a
// durable queue: the payload is written to the database and read back later, so
// it is one more place a secret could come to rest.
func TestQueuedOperationCarriesNoCredentialMaterial(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	fake := tracker.NewFake("github")
	fake.FailWith(errors.New("down"))
	svc := service(s, fake)

	fp := fingerprint.Compute(depFinding())
	observeIn(t, s, []model.RawFinding{depFinding()})
	spec := specFor(t, s, fp)
	if _, _, err := svc.Ensure(ctx, spec); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	ops, err := s.DueTicketOps(ctx, time.Now().UTC().Add(time.Hour), 10)
	if err != nil || len(ops) != 1 {
		t.Fatalf("DueTicketOps = (%d, %v)", len(ops), err)
	}
	if err := model.AssertNoCredential("queued ticket op", ops[0].Payload); err != nil {
		t.Errorf("the durable queue holds credential material: %v", err)
	}
}

// --- Granularity (VM-AD §13.3, VM-F-807/808/852) ---------------------------

// TestTicketGranularity covers the table in §13.3. The rule that matters most
// is the last one: P2 and P3 findings that are not remediated are aggregated
// into the run parent, never individually ticketed (VM-F-808). Individual
// tickets for low-priority findings are how a backlog becomes unreadable, and
// an unreadable backlog is indistinguishable from no backlog.
func TestTicketGranularity(t *testing.T) {
	cases := []struct {
		name     string
		category model.Category
		priority model.Priority
		outcome  policy.Outcome
		want     bool
	}{
		{"secret always gets its own ticket", model.CategorySecret, model.P0, policy.EscalateP0, true},
		{"P0 not auto-remediable", model.CategoryDependency, model.P0, policy.OpenTicket, true},
		{"P1 not auto-remediable", model.CategoryDependency, model.P1, policy.OpenTicket, true},
		{"P2 not fixed is aggregated", model.CategoryDependency, model.P2, policy.OpenTicket, false},
		{"P3 not fixed is aggregated", model.CategoryDependency, model.P3, policy.OpenTicket, false},
		{"auto-remediable gets a PR, not a finding ticket", model.CategoryDependency, model.P1, policy.AutoRemediate, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := model.Finding{Category: tc.category, Priority: tc.priority}
			if got := tracker.NeedsOwnTicket(f, tc.outcome); got != tc.want {
				t.Errorf("NeedsOwnTicket = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSecretTicketIsNeverBatched covers VM-F-852 explicitly: a secret is
// ticketed immediately whatever its routing outcome, because the remediation is
// credential rotation by a human and batching delays it.
func TestSecretTicketIsNeverBatched(t *testing.T) {
	for _, outcome := range policy.AllOutcomes {
		f := model.Finding{Category: model.CategorySecret, Priority: model.P0}
		if !tracker.NeedsOwnTicket(f, outcome) {
			t.Errorf("a secret finding routed %q would be batched (VM-F-852)", outcome)
		}
	}
}

// TestRunParentAggregatesTheRest covers VM-F-808's other half: the findings
// that do not get their own ticket must still appear, in the run parent. An
// aggregation rule that drops them is not aggregation, it is silence.
func TestRunParentAggregatesTheRest(t *testing.T) {
	body := tracker.RunParentBody(tracker.RunSummary{
		RunID:     "S-000001",
		ReportURL: "https://reports.example/runs/S-000001/fleet.md",
		Aggregated: []tracker.AggregateRow{
			{Repo: repo, Priority: model.P2, Count: 7},
			{Repo: repo, Priority: model.P3, Count: 12},
		},
	})
	for _, want := range []string{"S-000001", "reports.example", "7", "12", "P2", "P3", repo} {
		if !strings.Contains(body, want) {
			t.Errorf("the run parent does not mention %q:\n%s", want, body)
		}
	}
}

var _ = store.Ticket{}
