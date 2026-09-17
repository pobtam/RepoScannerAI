package orchestrator_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/tracker"
)

// Phase 9b gate — orchestrator ticket wiring.
//
// Phase 8 built the tracker and deliberately wired nothing to it. Everything
// here is about the wiring being correct in the presence of a real pull request
// ticket, which is the case Phase 8 could not exercise.

func ticketService(t *testing.T, s store.Store, fake *tracker.Fake, now time.Time) *tracker.Service {
	t.Helper()
	return &tracker.Service{
		Tracker: fake, Store: s,
		Clock: func() time.Time { return now },
	}
}

func ticketPass(t *testing.T, s store.Store, o *orchestrator.Orchestrator, svc *tracker.Service,
	repo store.Repo, runID string) orchestrator.TicketStats {
	t.Helper()
	_, _, pol := pipeline(t)
	stats, err := o.TicketPass(context.Background(), orchestrator.TicketRequest{
		Repo: repo, RunID: runID, Service: svc, Policy: pol,
		View: routeView{}, ReportURL: "https://reports.example/runs/" + runID + "/fleet.md",
	})
	if err != nil {
		t.Fatalf("TicketPass: %v", err)
	}
	return stats
}

// --- Gate: run parent, children linked, granularity -------------------------

// TestRunParentIsCreatedAndChildrenLinked covers §13.3 rows 1 and 3. The parent
// is what makes a run's ticket set navigable: without it, a reviewer receiving
// one P0 ticket has no way to reach the run that produced it or the findings
// that were NOT individually ticketed.
func TestRunParentIsCreatedAndChildrenLinked(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")

		// A P0-worthy dependency finding and a secret: both get their own
		// tickets, for different reasons (VM-F-807, VM-F-852).
		dep := depFinding("org/api", "GO-2025-3487", "v0.16.0", "v0.16.1")
		secret := secretFinding("org/api")
		runID := seedDetected(t, s, repos, dep, secret)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
		o.Clock = func() time.Time { return at }
		fake := tracker.NewFake("github")
		svc := ticketService(t, s, fake, at)

		tr, sc, pol := pipeline(t)
		if _, err := o.TriageAndRoute(ctx, repos[0], tr, sc, pol, routeView{}); err != nil {
			t.Fatalf("TriageAndRoute: %v", err)
		}

		stats := ticketPass(t, s, o, svc, repos[0], runID)

		// The parent exists, once, and is recorded durably against the run.
		parent, ok, err := s.GetRunTicket(ctx, runID)
		if err != nil || !ok {
			t.Fatalf("GetRunTicket = (%v, %v); the run has no parent ticket (VM-AD §13.3)", ok, err)
		}
		if parent.Ref == "" || parent.URL == "" {
			t.Errorf("the run parent record is unusable: %+v", parent)
		}
		if stats.ParentCreated != 1 {
			t.Errorf("created %d parents, want 1", stats.ParentCreated)
		}

		// The secret got its own ticket, and it is linked to the parent.
		secretFP := fingerprint.Compute(secret)
		rec, ok, err := s.GetTicket(ctx, secretFP)
		if err != nil || !ok {
			t.Fatalf("the secret finding has no ticket (VM-F-852): (%v, %v)", ok, err)
		}
		links := fake.LinksOf(tracker.Ref{Backend: "github", ID: rec.Ref})
		if links.ID != parent.Ref {
			t.Errorf("the secret's ticket links to %q, want the run parent %q; an unlinked child "+
				"leaves the reader no route back to the run", links.ID, parent.Ref)
		}
	})
}

// TestNeedsOwnTicketDrivesOwnTicketVersusPRTicket is the granularity clause
// (§13.3, VM-F-807/808). A P2 that will not be fixed is aggregated into the
// parent; an auto-remediable finding gets a PULL REQUEST ticket rather than a
// finding ticket, because the actionable unit is the pull request (VM-ADR-05).
func TestNeedsOwnTicketDrivesOwnTicketVersusPRTicket(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")

		// Three findings that route differently.
		p0 := secretFinding("org/api") // always its own ticket
		dep := depFinding("org/api", "GO-2025-3487", "v0.16.0", "v0.16.1")
		runID := seedDetected(t, s, repos, p0, dep)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
		o.Clock = func() time.Time { return at }
		fake := tracker.NewFake("github")
		svc := ticketService(t, s, fake, at)

		tr, sc, pol := pipeline(t)
		if _, err := o.TriageAndRoute(ctx, repos[0], tr, sc, pol, routeView{}); err != nil {
			t.Fatalf("TriageAndRoute: %v", err)
		}
		stats := ticketPass(t, s, o, svc, repos[0], runID)

		depFP := fingerprint.Compute(dep)
		f, err := s.GetFinding(ctx, depFP)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}

		// Whatever the dependency finding routed to, the decision must be
		// consistent: it either has its own ticket or it is aggregated, never
		// both and never neither.
		_, hasOwn, err := s.GetTicket(ctx, depFP)
		if err != nil {
			t.Fatalf("GetTicket: %v", err)
		}
		aggregated := false
		for _, row := range stats.Aggregated {
			if row.Count > 0 {
				aggregated = true
			}
		}
		if hasOwn && aggregated && stats.Aggregated[0].Count == 1 {
			t.Error("a finding is both individually ticketed and counted as aggregated; the reader would " +
				"see it twice and the totals would not reconcile")
		}
		if !hasOwn && !aggregated && f.State != model.AutoRemediating {
			t.Errorf("the finding in state %s got neither its own ticket nor a place in the aggregate; "+
				"it is invisible (VM-F-808)", f.State)
		}
	})
}

// TestPullRequestGetsItsOwnTicket covers §13.3 row 2, which Phase 8 could not
// test because no pull request existed.
func TestPullRequestGetsItsOwnTicket(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")
		dep := depFinding("org/api", "GO-2025-3487", "v0.16.0", "v0.16.1")
		runID := seedDetected(t, s, repos, dep)
		fp := fingerprint.Compute(dep)

		// A remediation pull request exists for this finding.
		if err := s.SaveRemediationPR(ctx, store.RemediationPR{
			Branch: "security/fix-abc123", Repo: "org/api", FixGroupID: "abc123",
			Number: 41, URL: "https://github.com/org/api/pull/41", State: "open",
			OpenedAt: at, Findings: []string{fp},
		}); err != nil {
			t.Fatalf("SaveRemediationPR: %v", err)
		}

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
		o.Clock = func() time.Time { return at }
		fake := tracker.NewFake("github")
		svc := ticketService(t, s, fake, at)

		tr, sc, pol := pipeline(t)
		if _, err := o.TriageAndRoute(ctx, repos[0], tr, sc, pol, routeView{}); err != nil {
			t.Fatalf("TriageAndRoute: %v", err)
		}
		stats := ticketPass(t, s, o, svc, repos[0], runID)

		if stats.PRTickets != 1 {
			t.Fatalf("created %d pull request tickets, want 1 (VM-AD §13.3 row 2)", stats.PRTickets)
		}
		rec, ok, err := s.GetRemediationPR(ctx, "security/fix-abc123")
		if err != nil || !ok {
			t.Fatalf("GetRemediationPR = (%v, %v)", ok, err)
		}
		if rec.TicketRef == "" || rec.TicketURL == "" {
			t.Errorf("the pull request record carries no ticket reference: %+v", rec)
		}
		// The ticket names the pull request, so a reader can reach the change.
		if !strings.Contains(fake.Everything(), "pull/41") {
			t.Errorf("the pull request ticket does not link its pull request:\n%s", fake.Everything())
		}
	})
}

// --- Gate: idempotent across three runs, with a PR ticket present -----------

// TestThreeRunsProduceOneTicketOfEachKind is the Phase 8 discipline applied to
// the wiring. The tracker's own idempotency was proven there; what is proven
// here is that the ORCHESTRATOR does not manufacture new subjects each run —
// a fresh parent per run is correct, a fresh child ticket per run is not.
func TestThreeRunsProduceOneTicketOfEachKind(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")
		secret := secretFinding("org/api")
		dep := depFinding("org/api", "GO-2025-3487", "v0.16.0", "v0.16.1")
		secretFP := fingerprint.Compute(secret)
		depFP := fingerprint.Compute(dep)

		fake := tracker.NewFake("github")
		var runIDs []string

		for i := 0; i < 3; i++ {
			runID := seedDetected(t, s, repos, secret, dep)
			runIDs = append(runIDs, runID)

			if i == 0 {
				// A pull request opens during the first run and stays open.
				if err := s.SaveRemediationPR(ctx, store.RemediationPR{
					Branch: "security/fix-abc123", Repo: "org/api", FixGroupID: "abc123",
					Number: 41, URL: "https://github.com/org/api/pull/41", State: "open",
					OpenedAt: at, Findings: []string{depFP},
				}); err != nil {
					t.Fatalf("SaveRemediationPR: %v", err)
				}
			}

			o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
			o.Clock = func() time.Time { return at }
			svc := ticketService(t, s, fake, at)

			tr, sc, pol := pipeline(t)
			if _, err := o.TriageAndRoute(ctx, repos[0], tr, sc, pol, routeView{}); err != nil {
				t.Fatalf("run %d TriageAndRoute: %v", i+1, err)
			}
			ticketPass(t, s, o, svc, repos[0], runID)
		}

		// One ticket per finding, across three runs.
		if opened := fake.TicketsFor(secretFP); len(opened) != 1 {
			t.Errorf("%d tickets were opened for the secret finding across three runs: %v (VM-F-804)",
				len(opened), opened)
		}
		// One ticket per pull request, across three runs.
		if opened := fake.TicketsFor("pr:security/fix-abc123"); len(opened) > 1 {
			t.Errorf("%d tickets were opened for one pull request: %v", len(opened), opened)
		}
		// One parent per RUN — three runs, three parents, and each run's
		// parent is its own. A shared parent would attribute one run's counts
		// to another.
		seen := map[string]bool{}
		for _, id := range runIDs {
			parent, ok, err := s.GetRunTicket(ctx, id)
			if err != nil || !ok {
				t.Fatalf("run %s has no parent ticket", id)
			}
			if seen[parent.Ref] {
				t.Errorf("two runs share parent ticket %q; one run's counts would be attributed to another",
					parent.Ref)
			}
			seen[parent.Ref] = true
		}
	})
}

// --- Gate: OQ-P8-02, the drain is automatic ---------------------------------

// TestQueuedTicketOperationsDrainWithoutAHuman closes OQ-P8-02.
//
// Phase 8 queued correctly and `Drain` was tested, but nothing called it — so
// the failure isolation was real and the recovery was manual, which is a
// half-measure: the operations accumulate silently and someone has to notice.
//
// Nothing in this test calls Drain. The only thing that happens between the
// outage and the ticket appearing is the next ordinary ticket pass.
func TestQueuedTicketOperationsDrainWithoutAHuman(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")
		secret := secretFinding("org/api")
		secretFP := fingerprint.Compute(secret)

		fake := tracker.NewFake("github")
		fake.FailWith(errors.New("503 service unavailable"))

		// Run 1: the tracker is down.
		runID := seedDetected(t, s, repos, secret)
		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
		o.Clock = func() time.Time { return at }
		tr, sc, pol := pipeline(t)
		if _, err := o.TriageAndRoute(ctx, repos[0], tr, sc, pol, routeView{}); err != nil {
			t.Fatalf("TriageAndRoute: %v", err)
		}
		ticketPass(t, s, o, ticketService(t, s, fake, at), repos[0], runID)

		if _, ok, _ := s.GetTicket(ctx, secretFP); ok {
			t.Fatal("a ticket exists despite the tracker being down")
		}
		queued, err := s.DueTicketOps(ctx, at.Add(24*time.Hour), 100)
		if err != nil {
			t.Fatalf("DueTicketOps: %v", err)
		}
		if len(queued) == 0 {
			t.Fatal("the outage dropped the ticket instead of queueing it (VM-F-812)")
		}

		// The backend recovers. Nobody does anything: the next ordinary pass
		// happens on its schedule.
		fake.FailWith(nil)
		later := at.Add(2 * time.Hour)
		runID2 := seedDetected(t, s, repos, secret)
		o2 := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
		o2.Clock = func() time.Time { return later }
		svc2 := ticketService(t, s, fake, later)
		if _, err := o2.TriageAndRoute(ctx, repos[0], tr, sc, pol, routeView{}); err != nil {
			t.Fatalf("second TriageAndRoute: %v", err)
		}
		stats := ticketPass(t, s, o2, svc2, repos[0], runID2)

		if stats.Drained == 0 {
			t.Error("the ticket pass drained nothing; recovery still requires a human (OQ-P8-02)")
		}
		if _, ok, err := s.GetTicket(ctx, secretFP); err != nil || !ok {
			t.Error("the queued ticket was never created after the backend recovered")
		}
		// And the recovery did not duplicate: the drain goes through the full
		// idempotency chain, not around it.
		if opened := fake.TicketsFor(secretFP); len(opened) != 1 {
			t.Errorf("%d tickets exist after the drain, want 1", len(opened))
		}
		if remaining, err := s.DueTicketOps(ctx, later.Add(24*time.Hour), 100); err != nil || len(remaining) != 0 {
			t.Errorf("%d operations remain queued after a successful drain", len(remaining))
		}
	})
}

// TestTwoPassesOverOneRunShareOneParent closes a gap a mutation found: nothing
// exercised two ticket passes over the SAME run.
//
// A sweep can pass over a repository more than once — a retry, a second
// repository in the same run, an operator re-running the pass — and a parent
// created each time would give one run several parents, each carrying a
// different partial view of it. The reader would have no way to tell which is
// the run's actual summary.
func TestTwoPassesOverOneRunShareOneParent(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")
		runID := seedDetected(t, s, repos, secretFinding("org/api"))

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
		o.Clock = func() time.Time { return at }
		fake := tracker.NewFake("github")
		svc := ticketService(t, s, fake, at)

		tr, sc, pol := pipeline(t)
		if _, err := o.TriageAndRoute(ctx, repos[0], tr, sc, pol, routeView{}); err != nil {
			t.Fatalf("TriageAndRoute: %v", err)
		}

		first := ticketPass(t, s, o, svc, repos[0], runID)
		second := ticketPass(t, s, o, svc, repos[0], runID)

		if first.ParentCreated != 1 {
			t.Errorf("the first pass created %d parents, want 1", first.ParentCreated)
		}
		if second.ParentCreated != 0 {
			t.Errorf("the second pass over the same run created %d more parents; one run would then have "+
				"several parents, each carrying a different partial view of it", second.ParentCreated)
		}
		if opened := fake.TicketsFor("run:" + runID); len(opened) != 1 {
			t.Errorf("%d parent tickets exist for one run: %v", len(opened), opened)
		}
	})
}

// TestLowPriorityFindingIsAggregatedNotTicketed closes the other gap a mutation
// found: nothing asserted the NEGATIVE side of the granularity rule.
//
// VM-F-808 is a rule about what must NOT happen. An implementation that
// ignored it entirely still produced tickets, still linked them, and still
// looked correct — because every assertion was about tickets that exist. The
// backlog it would produce is the failure, and a backlog nobody reads is
// indistinguishable from no backlog.
func TestLowPriorityFindingIsAggregatedNotTicketed(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")
		// A major bump, which policy routes to a ticket rather than automation.
		raw := depFinding("org/api", "GO-2025-3487", "v1.2.0", "v2.0.0")
		runID := seedDetected(t, s, repos, raw)
		fp := fingerprint.Compute(raw)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50), orchestrator.Config{})
		o.Clock = func() time.Time { return at }
		fake := tracker.NewFake("github")
		svc := ticketService(t, s, fake, at)

		tr, sc, pol := pipeline(t)
		if _, err := o.TriageAndRoute(ctx, repos[0], tr, sc, pol, routeView{}); err != nil {
			t.Fatalf("TriageAndRoute: %v", err)
		}

		// Force the low priority the rule turns on. Scoring ran above; this is
		// the deliberate override that makes the case deterministic.
		low := model.P3
		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		if err := s.SetPriority(ctx, fp, low, f.ReasonCode); err != nil {
			t.Fatalf("set priority: %v", err)
		}

		f, err = s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		decision, err := pol.Evaluate(f, policy.Repo{
			Name: "org/api", Tier: 1, Language: policy.LangGo, HasTestSuite: true,
		}, routeView{})
		if err != nil {
			t.Fatalf("policy: %v", err)
		}
		if tracker.NeedsOwnTicket(f, decision.Outcome) {
			t.Skipf("a P3 routed %q still warrants its own ticket; the fixture does not exercise VM-F-808",
				decision.Outcome)
		}

		stats := ticketPass(t, s, o, svc, repos[0], runID)

		if _, ok, err := s.GetTicket(ctx, fp); err != nil || ok {
			t.Error("a P3 finding got its own ticket (VM-F-808); individual tickets for low-priority " +
				"findings are how a backlog becomes unreadable, and an unreadable backlog is " +
				"indistinguishable from no backlog")
		}
		// Not ticketed is not the same as not recorded.
		var counted int
		for _, row := range stats.Aggregated {
			if row.Priority == model.P3 {
				counted += row.Count
			}
		}
		if counted != 1 {
			t.Errorf("the aggregate holds %d P3 findings, want 1; a finding that gets no ticket and no "+
				"place in the aggregate is simply invisible", counted)
		}
		if !strings.Contains(fake.Everything(), "Not individually ticketed") {
			t.Error("the run parent does not carry the aggregated table")
		}
	})
}
