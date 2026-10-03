package store_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/store"
)

// Report supersession, held to one suite across both backends.
//
// The rules live in two places — Go in the memory store, SQL plus a unique
// partial index in Postgres — and nothing about either implementation reveals
// a disagreement, because each passes its own tests. The only way to find one
// is to ask both the same question.
//
// What makes this worth the duplication: the memory backend is what every
// other package's tests run against, so a rule the memory store does not
// enforce is a rule the whole suite believes is enforced.

func supersedeReport(id, supersedes, runID, kind, repo string, at time.Time) store.Report {
	query, _ := json.Marshal(map[string]string{"kind": kind, "supersedes": supersedes})
	return store.Report{
		ID: id, AnchorRunID: runID, Kind: kind, Repo: repo, Template: kind + ".v1",
		Query: query, ContentHash: "hash-" + id, Content: json.RawMessage(`{"id":"` + id + `"}`),
		IssuedAt: at, IssuedBy: "test", Supersedes: supersedes,
	}
}

// seedRunForReports creates the run every report must anchor to.
//
// Reports carry a foreign key to runs, so a report cannot exist without one —
// which is VM-ADR-15's point: a report generated from live state cannot be
// regenerated, and therefore cannot be cited.
func seedRunForReports(t *testing.T, s store.Store) string {
	t.Helper()
	run, err := s.CreateRun(context.Background(), store.KindSweep, "test",
		"vulnframework-scanner:v1", map[string]string{"govulncheck": "v1.8.0"})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	return run.ID
}

// TestSupersessionBehavesTheSameOnBothBackends is the conformance gate.
func TestSupersessionBehavesTheSameOnBothBackends(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

	for _, backend := range bothBackends(t) {
		t.Run(backend.name, func(t *testing.T) {
			s := backend.store
			runID := seedRunForReports(t, s)

			first := supersedeReport("R-sup-1", "", runID, "fleet", "", at)
			if err := s.SaveReport(ctx, first); err != nil {
				t.Fatalf("saving the first report: %v", err)
			}

			// Nothing supersedes it yet, and that must be a clean negative
			// rather than an error: "not superseded" is the ordinary case and
			// is what the interface renders for almost every report.
			if _, found, err := s.SupersededBy(ctx, first.ID); err != nil || found {
				t.Fatalf("a report nothing replaces reported found=%v, err=%v", found, err)
			}

			second := supersedeReport("R-sup-2", first.ID, runID, "fleet", "", at.Add(time.Hour))
			if err := s.SaveReport(ctx, second); err != nil {
				t.Fatalf("saving the replacement: %v", err)
			}

			got, found, err := s.SupersededBy(ctx, first.ID)
			if err != nil {
				t.Fatalf("SupersededBy: %v", err)
			}
			if !found || got.ID != second.ID {
				t.Fatalf("SupersededBy(%s) = %q (found=%v), want %s", first.ID, got.ID, found, second.ID)
			}

			// The superseded report is unchanged. VM-UI-F-1108 keeps both
			// visible, and a correction is only meaningful beside what it
			// corrected.
			original, err := s.GetReport(ctx, first.ID)
			if err != nil {
				t.Fatalf("the superseded report is no longer readable: %v", err)
			}
			if original.ContentHash != first.ContentHash || original.Supersedes != "" {
				t.Fatalf("the superseded report was modified: %+v", original)
			}

			t.Run("a lineage pointing at nothing is refused", func(t *testing.T) {
				orphan := supersedeReport("R-sup-orphan", "R-does-not-exist", runID, "fleet", "", at)
				err := s.SaveReport(ctx, orphan)
				if err == nil {
					t.Fatal("a report superseding one that does not exist was saved. The interface " +
						"would state a relationship that cannot be followed")
				}
				// Both backends must explain it the same way. Postgres has a
				// foreign key that would refuse this anyway, with a message
				// about a constraint rather than about a lineage — so without
				// this assertion the two backends refuse the same write for
				// reasons an operator would read quite differently, which is
				// exactly what a conformance suite exists to prevent.
				if !strings.Contains(err.Error(), "does not exist") {
					t.Errorf("the refusal does not explain the lineage: %v", err)
				}
			})

			t.Run("a forked lineage is refused", func(t *testing.T) {
				fork := supersedeReport("R-sup-fork", first.ID, runID, "fleet", "", at.Add(2*time.Hour))
				if err := s.SaveReport(ctx, fork); err == nil {
					t.Fatal("two reports were allowed to supersede the same original. There is no " +
						"defined winner, and VM-UI-F-1108 requires THE relationship to be stated")
				}
			})

			t.Run("a chain of corrections is allowed", func(t *testing.T) {
				third := supersedeReport("R-sup-3", second.ID, runID, "fleet", "", at.Add(3*time.Hour))
				if err := s.SaveReport(ctx, third); err != nil {
					t.Fatalf("a correction of a correction was refused, so the fork rule rejects "+
						"everything: %v", err)
				}
				got, found, err := s.SupersededBy(ctx, second.ID)
				if err != nil || !found || got.ID != third.ID {
					t.Fatalf("the second link of the chain is not readable: %q found=%v err=%v",
						got.ID, found, err)
				}
			})

			t.Run("re-saving a replacement is idempotent", func(t *testing.T) {
				// Idempotent, because a worker that retried after a timeout
				// must not trip the fork rule against its own earlier write.
				if err := s.SaveReport(ctx, second); err != nil {
					t.Fatalf("re-saving an identical replacement was refused as a fork: %v", err)
				}
			})

			t.Run("an empty id is a clean negative", func(t *testing.T) {
				if _, found, err := s.SupersededBy(ctx, ""); err != nil || found {
					t.Fatalf("SupersededBy(\"\") = found %v, err %v; a report with no supersedes "+
						"must not match every other report that also has none", found, err)
				}
			})
		})
	}
}
