package report_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/store"
)

// OQ-AUDIT-04 — a report nobody can look up is not citable.
//
// The producer-coverage audit went looking for the code that writes
// store.Report and found none: Generate produced reports, Issue hashed them,
// PublishRun delivered the artifacts, and the RECORD — the thing VM-ADR-15
// exists for — was written only by test fixtures. Every report test passed,
// because every report test built the record it then asserted on.

func issuedFixture(t *testing.T, s store.Store) (report.Issued, string) {
	t.Helper()
	f := seed(t, s, store.KindSweep, []model.RawFinding{dep("org/a", "GO-2025-0001")},
		map[string]model.ScanOutcome{"org/a": model.ScanComplete})
	rep := generate(t, s, f.runID)
	issued, err := report.Issue(rep)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return issued, f.runID
}

func TestAnIssuedReportIsRecordedSoItCanBeCitedLater(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		issued, runID := issuedFixture(t, s)

		rec, err := report.Record(ctx, s, issued, "orchestrator")
		if err != nil {
			t.Fatalf("Record: %v", err)
		}

		got, err := s.ReportsForRun(ctx, runID)
		if err != nil {
			t.Fatalf("ReportsForRun: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("%d reports anchored to the run, want 1", len(got))
		}
		if got[0].ID != rec.ID || got[0].ContentHash != issued.Hash {
			t.Errorf("the stored record does not match what was issued: %+v", got[0])
		}
		if got[0].AnchorRunID != runID {
			t.Errorf("anchor run = %q, want %q: a report is anchored to a run, never to "+
				"'now' (VM-ADR-15)", got[0].AnchorRunID, runID)
		}
		if got[0].IssuedBy != "orchestrator" {
			t.Errorf("issued_by = %q; a record with no author cannot be questioned", got[0].IssuedBy)
		}

		// The stored query is the one that produced it, and it round-trips:
		// this is what lets someone regenerate the report years later and see
		// whether a quoted number is still the number the run produced.
		var q report.Query
		if err := json.Unmarshal(got[0].Query, &q); err != nil {
			t.Fatalf("the stored query does not decode: %v", err)
		}
		if q != issued.Report.Query {
			t.Errorf("stored query = %+v, want %+v", q, issued.Report.Query)
		}

		// And the stored body is the SEALED body — the one carrying the hash —
		// rather than a re-render that might differ from what was published.
		var body struct {
			ContentHash string `json:"content_hash"`
			ID          string `json:"id"`
		}
		if err := json.Unmarshal(got[0].Content, &body); err != nil {
			t.Fatalf("the stored content does not decode: %v", err)
		}
		if body.ContentHash != got[0].ContentHash {
			t.Errorf("the stored content declares hash %q while the record says %q; a copy of "+
				"the body found later would not check out", body.ContentHash, got[0].ContentHash)
		}
		if body.ID != got[0].ID {
			t.Errorf("the stored content is a different report (%q) from the record (%q)", body.ID, got[0].ID)
		}
	})
}

func TestRecordingTheSameReportTwiceIsIdempotent(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		issued, runID := issuedFixture(t, s)

		if _, err := report.Record(ctx, s, issued, "orchestrator"); err != nil {
			t.Fatalf("first Record: %v", err)
		}
		if _, err := report.Record(ctx, s, issued, "orchestrator"); err != nil {
			t.Fatalf("re-recording an identical report must be idempotent, not an error: %v", err)
		}
		got, err := s.ReportsForRun(ctx, runID)
		if err != nil {
			t.Fatalf("ReportsForRun: %v", err)
		}
		if len(got) != 1 {
			t.Errorf("%d records for one report; a re-run must not duplicate a citation", len(got))
		}
	})
}

// TestARecordedReportCannotBeRewritten is the immutability clause seen from the
// producer: a citation whose meaning can change silently is worse than none.
func TestARecordedReportCannotBeRewritten(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		issued, _ := issuedFixture(t, s)
		if _, err := report.Record(ctx, s, issued, "orchestrator"); err != nil {
			t.Fatalf("Record: %v", err)
		}

		// Same identifier, different content: a second pass over a changed
		// store, recorded under the identifier someone has already quoted.
		tampered := issued
		tampered.JSON = append([]byte(nil), issued.JSON...)
		tampered.Hash = strings.Repeat("0", 64)
		if _, err := report.Record(ctx, s, tampered, "orchestrator"); err == nil {
			t.Fatal("a report was rewritten under an identifier already issued; a citation to it " +
				"would silently change meaning (VM-ADR-15)")
		}
	})
}

func TestRecordRefusesAReportItCannotMakeCitable(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		issued, _ := issuedFixture(t, s)

		noID := issued
		noID.Report.ID = ""
		if _, err := report.Record(ctx, s, noID, "orchestrator"); err == nil {
			t.Error("a report with no identifier was recorded; nothing could ever cite it")
		}

		noHash := issued
		noHash.Hash = ""
		if _, err := report.Record(ctx, s, noHash, "orchestrator"); err == nil {
			t.Error("a report with no content hash was recorded; a copy found later could not be checked")
		}

		noBody := issued
		noBody.JSON = nil
		if _, err := report.Record(ctx, s, noBody, "orchestrator"); err == nil {
			t.Error("a report with no body was recorded; the record would cite nothing")
		}
	})
}
