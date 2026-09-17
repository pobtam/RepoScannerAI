package report_test

import (
	"context"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/store"
)

// VM-F-704: not-fixed counts broken down by reason code.
//
// The clause that made this urgent is the FIX_INEFFECTIVE amendment. A reason
// code that collapses into "other" in the one place people read has not
// actually been distinguished, however carefully it is distinguished in the
// model.

// TestNotFixedBreakdownSeparatesTriedAndFailedFromNothingToDo is the gate.
//
// FIX_INEFFECTIVE and NO_UPSTREAM_FIX sit next to each other in any table and
// mean opposite things: one is work somebody owns today, the other is work
// nobody can do yet, and only the second pauses the SLA clock. A breakdown that
// let them read as neighbours would present a queue of actionable failures as a
// queue of blocked ones.
func TestNotFixedBreakdownSeparatesTriedAndFailedFromNothingToDo(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()

		tried := dep("org/a", "GO-2025-0001")   // FIX_INEFFECTIVE
		blocked := dep("org/a", "GO-2025-0002") // NO_UPSTREAM_FIX
		unexplained := dep("org/a", "GO-2025-0003")

		f := seed(t, s, store.KindSweep, []model.RawFinding{tried, blocked, unexplained},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})

		fps := fingerprintsOf(t, s)
		if len(fps) != 3 {
			t.Fatalf("seeded %d findings, want 3", len(fps))
		}
		ineffective := model.ReasonFixIneffective
		noUpstream := model.ReasonNoUpstreamFix
		if err := s.SetPriority(ctx, fps[0], model.P1, &ineffective); err != nil {
			t.Fatalf("set reason: %v", err)
		}
		if err := s.SetPriority(ctx, fps[1], model.P1, &noUpstream); err != nil {
			t.Fatalf("set reason: %v", err)
		}
		// The third gets no reason at all.

		rep := generate(t, s, f.runID)

		if got := rep.Counts.NotFixedByReason["FIX_INEFFECTIVE"]; got != 1 {
			t.Errorf("FIX_INEFFECTIVE count = %d, want 1; it must appear distinctly, not folded into "+
				"NO_UPSTREAM_FIX or an 'other' bucket", got)
		}
		if got := rep.Counts.NotFixedByReason["NO_UPSTREAM_FIX"]; got != 1 {
			t.Errorf("NO_UPSTREAM_FIX count = %d, want 1", got)
		}
		if rep.Counts.NotFixedUnexplained != 1 {
			t.Errorf("unexplained = %d, want 1; a finding that is unresolved with no reason recorded is a "+
				"gap in the pipeline and must not be folded into a risk category", rep.Counts.NotFixedUnexplained)
		}

		// And in the rendered output, where the distinction has to survive.
		md := string(report.Render(rep))
		if !strings.Contains(md, "FIX_INEFFECTIVE") {
			t.Fatalf("the rendered report does not mention FIX_INEFFECTIVE:\n%s", md)
		}
		section := sectionOf(md, "Why findings are not fixed")
		for _, want := range []string{"Tried and failed", "Nothing to do", "clock keeps running", "paused"} {
			if !strings.Contains(section, want) {
				t.Errorf("the breakdown does not say %q, so the two reasons read as neighbours:\n%s", want, section)
			}
		}
	})
}

// TestResolvedFindingsAreNotInTheNotFixedBreakdown is the obvious error to
// avoid: counting a verified finding's stale reason code as a reason it is not
// fixed would inflate every bucket over time and never shrink.
func TestResolvedFindingsAreNotInTheNotFixedBreakdown(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		raw := dep("org/a", "GO-2025-0001")
		f := seed(t, s, store.KindSweep, []model.RawFinding{raw},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})

		fps := fingerprintsOf(t, s)
		// Triaged first: an untriaged finding cannot verify by disappearance,
		// because DETECTED has no edge into VERIFIED (VM-AD §6.1.1).
		if err := s.ApplyTransition(ctx, fps[0], model.Triaged, model.TransitionContext{
			Actor: model.ActorTriage, Cause: "test",
		}); err != nil {
			t.Fatalf("triage: %v", err)
		}
		reason := model.ReasonFixIneffective
		if err := s.SetPriority(ctx, fps[0], model.P1, &reason); err != nil {
			t.Fatalf("set reason: %v", err)
		}

		rep := generate(t, s, f.runID)
		if rep.Counts.NotFixedByReason["FIX_INEFFECTIVE"] != 1 {
			t.Fatalf("fixture is wrong: the unresolved finding is not counted")
		}

		// It verifies on a later successful scan.
		r2, err := s.CreateRun(ctx, store.KindSweep, "cron", "img@sha256:abc", map[string]string{"govulncheck": "v1.8.0"})
		if err != nil {
			t.Fatalf("create run: %v", err)
		}
		if err := s.RecordPlan(ctx, []store.PlanEntry{{RunID: r2.ID, Repo: "org/a", State: store.DispatchPlanned}}); err != nil {
			t.Fatalf("record plan: %v", err)
		}
		if err := s.RecordScanResult(ctx, store.RepoScanResult{
			RunID: r2.ID, Repo: "org/a", Outcome: model.ScanComplete, ToolsOK: []string{"govulncheck"},
		}); err != nil {
			t.Fatalf("scan result: %v", err)
		}
		if _, err := s.Reconcile(ctx, r2.ID, "org/a"); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if err := s.FinishRun(ctx, r2.ID, 1, 1, 0); err != nil {
			t.Fatalf("finish run: %v", err)
		}

		rep2 := generate(t, s, r2.ID)
		if got := rep2.Counts.NotFixedByReason["FIX_INEFFECTIVE"]; got != 0 {
			t.Errorf("a verified finding is still counted as not fixed (%d); the buckets would grow for "+
				"ever and never shrink", got)
		}
	})
}

func fingerprintsOf(t *testing.T, s store.Store) []string {
	t.Helper()
	list, err := s.ListFindings(context.Background(), store.Query{Scope: store.ScopeAll})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	var out []string
	for _, f := range list {
		out = append(out, f.Fingerprint)
	}
	return out
}
