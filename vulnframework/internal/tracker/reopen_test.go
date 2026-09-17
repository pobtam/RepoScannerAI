package tracker_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/tracker"
)

// OQ-P8-03 (VM-F-806) and OQ-P8-01, tested together as instructed.
//
// The coupling is the point. Reopening the ORIGINAL ticket is only meaningful
// if it works from the durable record — a test that passes because an
// in-process cache happens to be warm proves nothing about a process that has
// just restarted, which is exactly when a regression is most likely to be
// noticed by a fresh pod.

// TestRegressedFindingReopensItsOriginalTicketWithAColdIndex is the gate.
//
// Everything in-process is discarded between the close and the regression: a
// new Service, a new Mirror, a new index. The only thing that survives is the
// store and the backend, which is precisely what survives a restart.
func TestRegressedFindingReopensItsOriginalTicketWithAColdIndex(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	fake := tracker.NewFake("github")

	fp := fingerprint.Compute(depFinding())
	observeIn(t, s, []model.RawFinding{depFinding()})

	// A ticket is opened, then the finding verifies and the ticket closes.
	original, _, err := service(s, fake).Ensure(ctx, specFor(t, s, fp))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	walk(t, s, fp, []model.State{model.Triaged})
	observeIn(t, s, nil) // a successful scan no longer sees it

	verified, err := s.GetFinding(ctx, fp)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if verified.State != model.Verified {
		t.Fatalf("state = %s, want VERIFIED", verified.State)
	}
	if err := service(s, fake).CloseVerified(ctx, verified); err != nil {
		t.Fatalf("CloseVerified: %v", err)
	}
	if fake.State(original) != tracker.StateClosed {
		t.Fatalf("the ticket did not close")
	}

	// --- the restart ---
	//
	// Every in-process structure is thrown away. A fresh Service holds no
	// memory of the ticket it did not create.
	cold := &tracker.Service{
		Tracker: fake, Store: s,
		Clock: func() time.Time { return time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC) },
	}

	// The finding is observed again by a later scan: REGRESSED (VM-F-105).
	observeIn(t, s, []model.RawFinding{depFinding()})
	regressed, err := s.GetFinding(ctx, fp)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if regressed.State != model.Regressed {
		t.Fatalf("state = %s, want REGRESSED", regressed.State)
	}

	before := fake.CreateCount()
	reopened, err := cold.Reopen(ctx, regressed)
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}

	// The ORIGINAL ticket, not a new one (VM-F-806).
	if reopened != original {
		t.Errorf("reopened %+v, want the original %+v; a new ticket loses the whole history of the "+
			"first occurrence, which is the context a reviewer needs most on a regression", reopened, original)
	}
	if fake.CreateCount() != before {
		t.Errorf("Reopen created a ticket (%d → %d); it must reopen, never create (VM-F-806)",
			before, fake.CreateCount())
	}
	if fake.State(original) != tracker.StateOpen {
		t.Errorf("the original ticket is %q, want open", fake.State(original))
	}

	// The reopening comment says what happened, and says that a scan is what
	// observed it — not an inference.
	body := strings.Join(fake.Comments(original), "\n")
	for _, want := range []string{"regress", "scan"} {
		if !strings.Contains(strings.ToLower(body), want) {
			t.Errorf("the reopening comment does not mention %q:\n%s", want, body)
		}
	}

	// And the durable record reflects the reopening, so the NEXT cold start
	// does not think the ticket is still closed.
	rec, ok, err := s.GetTicket(ctx, fp)
	if err != nil || !ok {
		t.Fatalf("GetTicket = (%v, %v)", ok, err)
	}
	if rec.ClosedAt != nil {
		t.Error("the local record still reads as closed after the ticket was reopened")
	}
}

// TestReopenResolvesThroughTheDurablePathWhenTheRecordIsAlsoLost is the harder
// half. A restart loses the cache; a restore can lose the local record too.
// Reopen must then reach the backend by fingerprint, exactly as Ensure does.
func TestReopenResolvesThroughTheDurablePathWhenTheRecordIsAlsoLost(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	fake := tracker.NewFake("github")

	fp := fingerprint.Compute(depFinding())
	observeIn(t, s, []model.RawFinding{depFinding()})
	original, _, err := service(s, fake).Ensure(ctx, specFor(t, s, fp))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	// Both the cache and the local record are gone.
	if err := s.DeleteTicket(ctx, fp); err != nil {
		t.Fatalf("DeleteTicket: %v", err)
	}
	cold := &tracker.Service{Tracker: fake, Store: s,
		Clock: func() time.Time { return time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC) }}

	walk(t, s, fp, []model.State{model.Triaged})
	observeIn(t, s, nil)
	observeIn(t, s, []model.RawFinding{depFinding()})
	regressed, err := s.GetFinding(ctx, fp)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}

	before := fake.CreateCount()
	reopened, err := cold.Reopen(ctx, regressed)
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	if reopened != original {
		t.Errorf("reopened %+v, want %+v — found through the backend by fingerprint", reopened, original)
	}
	if fake.CreateCount() != before {
		t.Error("a lost local record caused Reopen to create a duplicate ticket (VM-F-805)")
	}
	if fake.LastFindQuery() != fp {
		t.Errorf("the backend was queried with %q, want the fingerprint", fake.LastFindQuery())
	}
}

// TestReopenRefusesAFindingThatHasNotRegressed is the symmetric guard to
// CloseVerified's. Reopening a ticket for a finding that is merely open again
// in someone's opinion would reopen closed work on no evidence.
func TestReopenRefusesAFindingThatHasNotRegressed(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	fake := tracker.NewFake("github")
	svc := service(s, fake)

	fp := fingerprint.Compute(depFinding())
	observeIn(t, s, []model.RawFinding{depFinding()})
	if _, _, err := svc.Ensure(ctx, specFor(t, s, fp)); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	f, _ := s.GetFinding(ctx, fp)
	if f.State == model.Regressed {
		t.Fatal("fixture is already regressed")
	}
	if _, err := svc.Reopen(ctx, f); err == nil {
		t.Errorf("Reopen accepted a finding in state %s; only a REGRESSED finding reopens its ticket "+
			"(VM-F-806), and regression means a scan observed it again", f.State)
	}
}

// --- OQ-P8-01: the mirror's miss path never skips ---------------------------

// TestMirrorMissFallsBackToTheBackendRatherThanSkipping closes OQ-P8-01.
//
// The mirror kept a primary-ref → fingerprint map in process. On a miss it
// returned silently, which is a SILENT AUDIT-TRAIL GAP: the ticket in the
// planning tool simply stops receiving updates, and nothing anywhere says so.
// After a restart every ref misses, so the mirror would go quiet permanently
// and look healthy.
//
// A cache miss must degrade to a slower correct operation, not a dropped
// comment.
func TestMirrorMissFallsBackToTheBackendRatherThanSkipping(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	primary := tracker.NewFake("github")
	secondary := tracker.NewFake("jira")

	fp := fingerprint.Compute(depFinding())
	observeIn(t, s, []model.RawFinding{depFinding()})
	spec := specFor(t, s, fp)
	spec.Severity = model.P0

	warm := tracker.NewMirror(primary, secondary, model.P1)
	warm.Resolver = tracker.StoreResolver(s)
	ref, err := warm.Create(ctx, spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if secondary.CreateCount() != 1 {
		t.Fatalf("the secondary received %d creates, want 1", secondary.CreateCount())
	}
	// The local record is what makes the reverse lookup possible after a
	// restart, so the mirror has to have written it.
	if err := s.SaveTicket(ctx, store.Ticket{
		Fingerprint: fp, Backend: ref.Backend, Ref: ref.ID, URL: ref.URL,
		CreatedAt: time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("SaveTicket: %v", err)
	}

	// --- the restart: a mirror with an empty index ---
	cold := tracker.NewMirror(primary, secondary, model.P1)
	cold.Resolver = tracker.StoreResolver(s)

	if err := cold.Comment(ctx, ref, "a later note that must reach both"); err != nil {
		t.Fatalf("Comment: %v", err)
	}

	secondaryRef, found, err := secondary.Find(ctx, fp)
	if err != nil || !found {
		t.Fatalf("the secondary has no ticket: (%v, %v)", found, err)
	}
	notes := secondary.Comments(secondaryRef)
	if len(notes) == 0 {
		t.Error("the comment did not reach the mirrored ticket after a restart; a cold index must fall " +
			"back to the durable record, never skip — a silently one-sided audit trail looks healthy (OQ-P8-01)")
	}
	if len(cold.MirrorErrors()) != 0 {
		t.Errorf("the fallback reported errors: %v", cold.MirrorErrors())
	}
}

// TestMirrorRecordsAMissItCannotResolve is the honesty half. If neither the
// cache nor the store can name the fingerprint, the mirror must SAY so rather
// than return nil: a silent skip and a successful mirror are indistinguishable
// from outside.
func TestMirrorRecordsAMissItCannotResolve(t *testing.T) {
	ctx := context.Background()
	primary := tracker.NewFake("github")
	secondary := tracker.NewFake("jira")

	m := tracker.NewMirror(primary, secondary, model.P1)
	// No resolver at all: nothing can map the ref back to a fingerprint.
	if err := m.Comment(ctx, tracker.Ref{Backend: "github", ID: "999"}, "orphan"); err != nil {
		t.Fatalf("Comment returned an error to the caller: %v", err)
	}
	if len(m.MirrorErrors()) == 0 {
		t.Error("an unresolvable mirror target was skipped silently; the planning tool's copy diverges " +
			"and nothing reports it")
	}
}
