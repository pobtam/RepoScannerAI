package report_test

import (
	"context"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/store"
)

// Report supersession (VM-ADR-15's lineage, VM-UI-F-1108, D10).
//
// store.Report.Supersedes was instance ten of this build's recurring defect:
// a field a consumer reads and no producer writes. The producer-coverage audit
// recorded it with an exemption rather than filling it with a plausible value,
// and these tests are the producer that replaces the exemption.
//
// What supersession MEANS operationally is not decided here — a corrected
// figure, a re-issue after a redaction change, a regeneration against a
// late-arriving scan are all plausible and all policy (D10). What is decided
// here is that a relationship, once asserted, is one a reader can follow.

func supersedeStore(t *testing.T) store.Store {
	t.Helper()
	return store.NewMemory()
}

// issue generates, issues and records a report, returning the record.
func issue(t *testing.T, s store.Store, q report.Query, rep report.Report) store.Report {
	t.Helper()
	rep.Query = q
	rep.Kind = q.Kind
	rep.AnchorRun = q.AnchorRun
	rep.Repo = q.Repo
	rep.ID = report.IDFor(rep)

	issued, err := report.Issue(rep)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rec, err := report.Record(context.Background(), s, issued, "test")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	return rec
}

func fleetQuery(run string) report.Query {
	return report.Query{
		Kind: report.KindFleet, AnchorRun: run, Scope: store.ScopeAll, Template: "fleet.v1",
	}
}

// TestASupersedingReportRecordsTheRelationship is the requirement.
func TestASupersedingReportRecordsTheRelationship(t *testing.T) {
	s := supersedeStore(t)
	ctx := context.Background()

	first := issue(t, s, fleetQuery("run-1"), report.Report{})

	q := fleetQuery("run-1")
	q.Supersedes = first.ID
	second := issue(t, s, q, report.Report{})

	if second.Supersedes != first.ID {
		t.Fatalf("the replacement records Supersedes = %q, want %q", second.Supersedes, first.ID)
	}
	if second.ID == first.ID {
		t.Fatal("the replacement has the same identifier as the report it replaces. A report's id " +
			"derives from its query, so the relationship has to participate in it — otherwise a " +
			"re-issue collides with its own original and supersession is unexpressible")
	}

	// VM-UI-F-1108: the superseded report is not deleted.
	original, err := s.GetReport(ctx, first.ID)
	if err != nil {
		t.Fatalf("the superseded report is no longer readable: %v", err)
	}
	if original.ContentHash != first.ContentHash {
		t.Fatal("the superseded report was modified. A corrected figure is only meaningful beside " +
			"the figure it corrected")
	}

	// And the relationship is followable from the older one, which is the
	// direction that matters: somebody quoting a stale figure has the old
	// identifier in their hand, not the replacement's.
	replacement, found, err := s.SupersededBy(ctx, first.ID)
	if err != nil {
		t.Fatalf("SupersededBy: %v", err)
	}
	if !found {
		t.Fatal("the superseded report does not know it was replaced. A reader arriving from a " +
			"quoted identifier would see no sign that the figure had been corrected")
	}
	if replacement.ID != second.ID {
		t.Errorf("SupersededBy returned %s, want %s", replacement.ID, second.ID)
	}
}

// TestALineageAReaderCouldNotFollowIsRefused covers each validation
// separately, because each is an independent decision.
func TestALineageAReaderCouldNotFollowIsRefused(t *testing.T) {
	t.Run("the superseded report does not exist", func(t *testing.T) {
		s := supersedeStore(t)
		q := fleetQuery("run-1")
		q.Supersedes = "R-run-0-deadbeef"

		rep := report.Report{Query: q, Kind: q.Kind, AnchorRun: q.AnchorRun}
		rep.ID = report.IDFor(rep)
		issued, err := report.Issue(rep)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		_, err = report.Record(context.Background(), s, issued, "test")
		if err == nil {
			t.Fatal("a report superseding one that does not exist was recorded. The interface " +
				"would state a relationship that cannot be followed")
		}
		if !strings.Contains(err.Error(), "R-run-0-deadbeef") {
			t.Errorf("the refusal does not name the missing report: %v", err)
		}
		// The explanation, not only the failure. These checks were found
		// covering for one another: with the existence check disabled, the
		// superseded report reads as a zero value, and the KIND comparison
		// then refuses it for the wrong reason. A reader told "different
		// populations" about a report that simply is not there goes looking
		// in the wrong place.
		if !strings.Contains(err.Error(), "could not be read") {
			t.Errorf("the refusal does not say the original is missing: %v", err)
		}
	})

	// A report superseding itself has no case of its own, and that is the
	// finding rather than an omission. Supersedes participates in IDFor, so a
	// report naming itself carries an identifier its own query does not
	// produce — which TestAnIdentifierThatItsQueryDoesNotProduceIsRefused
	// covers for a much better reason. Mutating a dedicated self-check away
	// changed nothing observable, which is how it was found to be a special
	// case of something stronger.

	t.Run("a fleet report superseding a repository one", func(t *testing.T) {
		s := supersedeStore(t)
		repoQ := report.Query{
			Kind: report.KindRepo, AnchorRun: "run-1", Repo: "org/api",
			Scope: store.ScopeAll, Template: "repo.v1",
		}
		first := issue(t, s, repoQ, report.Report{})

		q := fleetQuery("run-1")
		q.Supersedes = first.ID
		rep := report.Report{Query: q, Kind: q.Kind, AnchorRun: q.AnchorRun}
		rep.ID = report.IDFor(rep)
		issued, err := report.Issue(rep)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}

		err = nil
		if _, err = report.Record(context.Background(), s, issued, "test"); err == nil {
			t.Fatal("a fleet report replaced a repository report. That is a claim about scope " +
				"nothing downstream checks, and a reader comparing the two would be comparing " +
				"different populations")
		}
		if !strings.Contains(err.Error(), "different populations") {
			t.Errorf("the refusal does not explain the scope mismatch, so it is indistinguishable "+
				"from the repository check that follows it: %v", err)
		}
	})

	t.Run("an identifier its query does not produce", func(t *testing.T) {
		s := supersedeStore(t)
		rep := report.Report{Query: fleetQuery("run-1"), Kind: report.KindFleet, AnchorRun: "run-1"}
		rep.ID = "R-run-1-handwritten"

		issued, err := report.Issue(rep)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if _, err := report.Record(context.Background(), s, issued, "test"); err == nil {
			t.Fatal("a report whose identifier is not derived from its query was recorded. " +
				"Regenerating it would land under a different identifier, so a citation points " +
				"at something that cannot be reproduced")
		}
	})

	t.Run("two reports superseding the same original", func(t *testing.T) {
		s := supersedeStore(t)
		ctx := context.Background()
		first := issue(t, s, fleetQuery("run-1"), report.Report{})

		q := fleetQuery("run-1")
		q.Supersedes = first.ID
		issue(t, s, q, report.Report{})

		// A second replacement for the same original, distinguished only by
		// its template so it gets a different identifier.
		forked := fleetQuery("run-1")
		forked.Supersedes = first.ID
		forked.Template = "fleet.v2"
		rep := report.Report{Query: forked, Kind: forked.Kind, AnchorRun: forked.AnchorRun}
		rep.ID = report.IDFor(rep)
		issued, err := report.Issue(rep)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}

		if _, err := report.Record(ctx, s, issued, "test"); err == nil {
			t.Fatal("two reports were allowed to supersede the same original. The lineage has " +
				"forked with no defined winner, and VM-UI-F-1108 requires THE relationship to be " +
				"stated — which cannot be done when there are two of them")
		}
	})
}

// TestAChainOfCorrectionsIsAllowed is the non-vacuity partner for the
// fork refusal.
//
// A refusal that rejected every second supersession would also satisfy the
// test above. A correction being corrected is ordinary.
func TestAChainOfCorrectionsIsAllowed(t *testing.T) {
	s := supersedeStore(t)
	ctx := context.Background()

	first := issue(t, s, fleetQuery("run-1"), report.Report{})

	q2 := fleetQuery("run-1")
	q2.Supersedes = first.ID
	second := issue(t, s, q2, report.Report{})

	q3 := fleetQuery("run-1")
	q3.Supersedes = second.ID
	third := issue(t, s, q3, report.Report{})

	for _, step := range []struct{ from, to string }{{first.ID, second.ID}, {second.ID, third.ID}} {
		got, found, err := s.SupersededBy(ctx, step.from)
		if err != nil {
			t.Fatalf("SupersededBy(%s): %v", step.from, err)
		}
		if !found || got.ID != step.to {
			t.Fatalf("%s is superseded by %q, want %s", step.from, got.ID, step.to)
		}
	}

	// The end of the chain is not superseded, which is how a reader knows it
	// is the current one.
	if _, found, err := s.SupersededBy(ctx, third.ID); err != nil || found {
		t.Fatalf("the newest report reports itself superseded (found=%v, err=%v)", found, err)
	}
}

// TestAnOrdinaryReportAssertsNoLineage is assert-the-negative.
func TestAnOrdinaryReportAssertsNoLineage(t *testing.T) {
	s := supersedeStore(t)
	rec := issue(t, s, fleetQuery("run-1"), report.Report{})

	if rec.Supersedes != "" {
		t.Fatalf("a report that replaces nothing recorded Supersedes = %q", rec.Supersedes)
	}
	_, found, err := s.SupersededBy(context.Background(), rec.ID)
	if err != nil {
		t.Fatalf("SupersededBy: %v", err)
	}
	if found {
		t.Fatal("a report nothing replaces was reported as superseded")
	}
}

// TestTheStoredQueryCarriesTheLineage is what makes a replacement
// regenerable.
//
// The query is stored verbatim so a report can be regenerated rather than
// reconstructed from memory. A regeneration that had forgotten what it was a
// correction TO would produce a different identifier and lose the lineage.
func TestTheStoredQueryCarriesTheLineage(t *testing.T) {
	s := supersedeStore(t)
	first := issue(t, s, fleetQuery("run-1"), report.Report{})

	q := fleetQuery("run-1")
	q.Supersedes = first.ID
	second := issue(t, s, q, report.Report{})

	if !strings.Contains(string(second.Query), first.ID) {
		t.Fatalf("the stored query does not carry the supersession, so regenerating this report "+
			"would produce a different identifier and lose the relationship:\n%s", second.Query)
	}
}
