package store_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/store/storetest"
)

// The conformance suite runs against every Store implementation.
//
// Both backends share their invariant decisions (PlanUpsert, PlanReconcile,
// Project), but sharing code is not the same as behaving identically once SQL,
// transactions and type conversions are involved. Running one suite against
// both is what makes the in-memory store usable as a fake in later phases: a
// fake that enforces different rules than production would make every test that
// uses it a statement about the fake.

type backend struct {
	name string
	open func(t *testing.T) store.Store
}

// backends returns the implementations available in this environment.
//
// Memory always runs, so the suite is fully exercisable offline as VM-AD §17
// requires of phases 0–2. Postgres runs when VULNFRAMEWORK_TEST_DSN is set.
func backends(t *testing.T) []backend {
	t.Helper()
	out := []backend{{
		name: "memory",
		open: func(t *testing.T) store.Store {
			s := store.NewMemory()
			s.SetClock(fixedClock())
			if err := s.Migrate(context.Background()); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			return s
		},
	}}

	if os.Getenv(storetest.EnvDSN) == "" {
		t.Logf("%s not set: skipping the Postgres backend", storetest.EnvDSN)
		return out
	}
	out = append(out, backend{
		name: "postgres",
		open: func(t *testing.T) store.Store {
			t.Helper()
			db := storetest.OpenDB(t, "store")
			ctx := context.Background()
			// Each test gets a clean schema: roll all the way down, then up.
			if err := store.NewPostgres(db).MigrateTo(ctx, 0); err != nil {
				t.Fatalf("reset schema: %v", err)
			}
			s := store.NewPostgres(db)
			s.SetClock(fixedClock())
			if err := s.Migrate(ctx); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			return s
		},
	})
	return out
}

// fixedClock advances a deterministic clock one second per call.
//
// It is mutex-guarded because the store calls its clock from concurrent
// dispatch goroutines; an unsynchronised counter here races under -race and the
// failure looks like a production bug rather than a test one.
func fixedClock() func() time.Time {
	base := time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	n := 0
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		n++
		return base.Add(time.Duration(n) * time.Second)
	}
}

// run executes fn against every available backend.
func run(t *testing.T, fn func(t *testing.T, s store.Store)) {
	t.Helper()
	for _, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			fn(t, b.open(t))
		})
	}
}

const testRepo = "org/wanaware-api"

func seedRepo(t *testing.T, s store.Store) {
	t.Helper()
	err := s.UpsertRepo(context.Background(), store.Repo{
		Name: testRepo, Tier: 1, Languages: []string{"go"}, HasTestSuite: true,
	})
	if err != nil {
		t.Fatalf("upsert repo: %v", err)
	}
}

func newRun(t *testing.T, s store.Store, kind store.RunKind) store.Run {
	t.Helper()
	r, err := s.CreateRun(context.Background(), kind, "test", "img@sha256:abc", map[string]string{"govulncheck": "v1.1.4"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	return r
}

func scanned(t *testing.T, s store.Store, runID string, outcome store.ScanOutcome, toolsOK, toolsFailed []string) {
	t.Helper()
	err := s.RecordScanResult(context.Background(), store.RepoScanResult{
		RunID: runID, Repo: testRepo, Outcome: outcome,
		ToolsOK: toolsOK, ToolsFailed: toolsFailed,
	})
	if err != nil {
		t.Fatalf("record scan result: %v", err)
	}
}

// cryptoFinding is the running example: golang.org/x/crypto GO-2025-3106.
func cryptoFinding(tool string) model.RawFinding {
	f := model.RawFinding{
		Repo:        testRepo,
		Category:    model.CategoryDependency,
		Module:      "golang.org/x/crypto",
		ModuleMajor: "v0",
		Tool:        tool,
		ToolVersion: "v1.1.4",
		Versions:    model.Versions{Current: "v0.35.0", Fixed: "v0.36.0"},
	}
	switch tool {
	case "govulncheck":
		f.PrimaryID = "GO-2025-3106"
		f.Aliases = []string{"CVE-2025-22869", "GHSA-hcg3-q754-cr77"}
		f.Classification = model.Classification{
			Severity: model.SeverityUnknown, Reachable: model.ReachableTrue,
			DepClass: model.DepProduction,
		}
	case "osv-scanner":
		f.PrimaryID = "GHSA-hcg3-q754-cr77"
		f.Aliases = []string{"CVE-2025-22869", "GO-2025-3106"}
		f.Classification = model.Classification{
			Severity: model.SeverityHigh, CVSS: 7.5, Reachable: model.ReachableUnknown,
			DepClass: model.DepProduction,
		}
	}
	return f
}

func cryptoFP() string { return fingerprint.Compute(cryptoFinding("govulncheck")) }

// --- Gate: upsert records an observation, never a duplicate ----------------

// TestUpsertCreatesObservationNotDuplicate is the second gate clause. A known
// fingerprint observed again is an observation against the existing finding
// (VM-F-104); findings reported by several tools merge into one record
// (VM-F-106).
func TestUpsertCreatesObservationNotDuplicate(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)

		r1 := newRun(t, s, store.KindSweep)
		stats, err := s.UpsertObservations(ctx, r1.ID, testRepo, []model.RawFinding{cryptoFinding("govulncheck")})
		if err != nil {
			t.Fatalf("first upsert: %v", err)
		}
		if stats.Created != 1 || stats.Observed != 0 {
			t.Fatalf("first upsert: created=%d observed=%d, want 1/0", stats.Created, stats.Observed)
		}

		// Same defect, second run, same tool.
		r2 := newRun(t, s, store.KindSweep)
		stats, err = s.UpsertObservations(ctx, r2.ID, testRepo, []model.RawFinding{cryptoFinding("govulncheck")})
		if err != nil {
			t.Fatalf("second upsert: %v", err)
		}
		if stats.Created != 0 || stats.Observed != 1 {
			t.Errorf("second upsert: created=%d observed=%d, want 0/1", stats.Created, stats.Observed)
		}

		all, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(all) != 1 {
			t.Fatalf("store holds %d findings, want 1: an existing fingerprint must not duplicate", len(all))
		}

		obs, err := s.Observations(ctx, cryptoFP())
		if err != nil {
			t.Fatalf("observations: %v", err)
		}
		if len(obs) != 2 {
			t.Errorf("got %d observations, want 2 (one per run, VM-F-104)", len(obs))
		}
	})
}

// TestTwoToolsOneFindingTwoObservations is the cross-tool case: one fingerprint,
// two observation rows, one merged record.
func TestTwoToolsOneFindingTwoObservations(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		r := newRun(t, s, store.KindSweep)

		stats, err := s.UpsertObservations(ctx, r.ID, testRepo, []model.RawFinding{
			cryptoFinding("govulncheck"),
			cryptoFinding("osv-scanner"),
		})
		if err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if stats.Created != 1 {
			t.Errorf("created=%d, want 1: two tools reporting one defect is one finding (VM-F-106)", stats.Created)
		}
		if stats.Observations != 2 {
			t.Errorf("observations=%d, want 2: every per-source value is retained (VM-AD §8.6)", stats.Observations)
		}

		all, _ := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
		if len(all) != 1 {
			t.Fatalf("store holds %d findings, want 1", len(all))
		}

		// The merged record carries both tools' complementary attributes.
		f := all[0]
		if f.Classification.Reachable != model.ReachableTrue {
			t.Errorf("reachable = %q, want true (from govulncheck)", f.Classification.Reachable)
		}
		if f.Classification.Severity != model.SeverityHigh {
			t.Errorf("severity = %q, want HIGH (from osv-scanner)", f.Classification.Severity)
		}
		if f.Classification.CVSS != 7.5 {
			t.Errorf("cvss = %v, want 7.5", f.Classification.CVSS)
		}
		if len(f.Provenance.Tools) != 2 {
			t.Errorf("tools = %v, want both", f.Provenance.Tools)
		}
		if f.Identity.PrimaryID != "GO-2025-3106" {
			t.Errorf("primary id = %q, want GO-2025-3106 (precedence over the alias union)", f.Identity.PrimaryID)
		}
	})
}

// --- Gate: VERIFIED -> observed -> REGRESSED (VM-F-105) --------------------

func TestVerifiedThenObservedYieldsRegressed(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		fp := cryptoFP()

		// Detect, then walk the finding to MERGED.
		r1 := newRun(t, s, store.KindSweep)
		mustUpsert(t, s, r1.ID, cryptoFinding("govulncheck"))
		scanned(t, s, r1.ID, model.ScanComplete, []string{"govulncheck"}, nil)
		walkToMerged(t, s, fp)

		// A successful scan that does not observe it verifies it.
		r2 := newRun(t, s, store.KindSweep)
		scanned(t, s, r2.ID, model.ScanComplete, []string{"govulncheck"}, nil)
		stats, err := s.Reconcile(ctx, r2.ID, testRepo)
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if stats.Verified != 1 {
			t.Fatalf("verified=%d, want 1", stats.Verified)
		}
		if got := stateOf(t, s, fp); got != model.Verified {
			t.Fatalf("state = %q, want VERIFIED", got)
		}

		// Observed again: REGRESSED, not a new finding (VM-F-105).
		r3 := newRun(t, s, store.KindSweep)
		upsertStats, err := s.UpsertObservations(ctx, r3.ID, testRepo, []model.RawFinding{cryptoFinding("govulncheck")})
		if err != nil {
			t.Fatalf("re-observe: %v", err)
		}
		if upsertStats.Regressed != 1 {
			t.Errorf("regressed=%d, want 1", upsertStats.Regressed)
		}
		if upsertStats.Created != 0 {
			t.Errorf("created=%d, want 0: a regression is not a new finding", upsertStats.Created)
		}
		if got := stateOf(t, s, fp); got != model.Regressed {
			t.Errorf("state = %q, want REGRESSED", got)
		}

		all, _ := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
		if len(all) != 1 {
			t.Errorf("store holds %d findings, want 1", len(all))
		}

		// The history is auditable end to end (VM-F-153).
		transitions, err := s.Transitions(ctx, fp)
		if err != nil {
			t.Fatalf("transitions: %v", err)
		}
		wantPath := []model.State{
			model.Detected, model.Triaged, model.AutoRemediating, model.PROpen,
			model.Merged, model.Verified, model.Regressed,
		}
		if len(transitions) != len(wantPath) {
			t.Fatalf("got %d transitions, want %d: %v", len(transitions), len(wantPath), statesOf(transitions))
		}
		for i, want := range wantPath {
			if transitions[i].To != want {
				t.Errorf("transition %d -> %q, want %q", i, transitions[i].To, want)
			}
		}
	})
}

// --- Gate: a failed scan does not verify (VM-ADR-12, VM-F-160) -------------

// TestFailedScanDoesNotVerify is the gate's central correctness clause. Without
// it, a repository that stops scanning marks its entire finding set as
// verified: the fleet numbers improve, the risk does not, and the failure is
// invisible precisely because it looks like success.
func TestFailedScanDoesNotVerify(t *testing.T) {
	for _, outcome := range []store.ScanOutcome{model.ScanFailed, model.ScanPartial} {
		t.Run(string(outcome), func(t *testing.T) {
			run(t, func(t *testing.T, s store.Store) {
				ctx := context.Background()
				seedRepo(t, s)
				fp := cryptoFP()

				r1 := newRun(t, s, store.KindSweep)
				mustUpsert(t, s, r1.ID, cryptoFinding("govulncheck"))
				scanned(t, s, r1.ID, model.ScanComplete, []string{"govulncheck"}, nil)
				walkToMerged(t, s, fp)

				// The next run does not observe it — because it did not finish.
				r2 := newRun(t, s, store.KindSweep)
				scanned(t, s, r2.ID, outcome, nil, []string{"govulncheck"})
				stats, err := s.Reconcile(ctx, r2.ID, testRepo)
				if err != nil {
					t.Fatalf("reconcile: %v", err)
				}

				if stats.Verified != 0 {
					t.Fatalf("a %s scan verified %d findings; absence is not resolution (VM-ADR-12)", outcome, stats.Verified)
				}
				if got := stateOf(t, s, fp); got != model.Merged {
					t.Errorf("state = %q, want MERGED retained", got)
				}
				if stats.NotReobserved != 1 {
					t.Errorf("not_reobserved=%d, want 1 (VM-F-161)", stats.NotReobserved)
				}
				// The count VM-F-216 requires alongside the gap.
				if stats.RetainedUnverified != 1 {
					t.Errorf("retained_unverified=%d, want 1 (VM-F-216)", stats.RetainedUnverified)
				}

				f, err := s.GetFinding(ctx, fp)
				if err != nil {
					t.Fatalf("get finding: %v", err)
				}
				if !f.Derived.NotReobserved {
					t.Error("finding is not flagged not_reobserved (VM-F-161)")
				}
				// Traceable to the gap that explains it (VM-F-162).
				if f.Derived.GapRepoScan == nil || *f.Derived.GapRepoScan != r2.ID {
					t.Errorf("gap link = %v, want %s (VM-F-162)", f.Derived.GapRepoScan, r2.ID)
				}

				// And it is still counted as open: not closed, not hidden.
				open, _ := s.ListFindings(ctx, store.Query{Scope: store.ScopeOpen})
				if len(open) != 1 {
					t.Errorf("open corpus holds %d findings, want 1 (VM-F-163)", len(open))
				}
			})
		})
	}
}

// TestFailedScanThenSuccessfulScanVerifies confirms the finding is retained
// rather than stuck: once a scan actually succeeds, verification proceeds.
func TestFailedScanThenSuccessfulScanVerifies(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		fp := cryptoFP()

		r1 := newRun(t, s, store.KindSweep)
		mustUpsert(t, s, r1.ID, cryptoFinding("govulncheck"))
		scanned(t, s, r1.ID, model.ScanComplete, []string{"govulncheck"}, nil)
		walkToMerged(t, s, fp)

		r2 := newRun(t, s, store.KindSweep)
		scanned(t, s, r2.ID, model.ScanFailed, nil, []string{"govulncheck"})
		if _, err := s.Reconcile(ctx, r2.ID, testRepo); err != nil {
			t.Fatalf("reconcile after failure: %v", err)
		}

		r3 := newRun(t, s, store.KindSweep)
		scanned(t, s, r3.ID, model.ScanComplete, []string{"govulncheck"}, nil)
		stats, err := s.Reconcile(ctx, r3.ID, testRepo)
		if err != nil {
			t.Fatalf("reconcile after success: %v", err)
		}
		if stats.Verified != 1 {
			t.Errorf("verified=%d, want 1 once a scan succeeded", stats.Verified)
		}
		if got := stateOf(t, s, fp); got != model.Verified {
			t.Errorf("state = %q, want VERIFIED", got)
		}
		f, _ := s.GetFinding(ctx, fp)
		if f.Derived.NotReobserved {
			t.Error("not_reobserved should be cleared once the finding resolves")
		}
	})
}

// TestReconcileRequiresAScanResult covers the precondition: reconciliation
// cannot judge absence without knowing whether the scan succeeded.
func TestReconcileRequiresAScanResult(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		r := newRun(t, s, store.KindSweep)
		if _, err := s.Reconcile(ctx, r.ID, testRepo); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("reconcile without a scan result returned %v, want ErrNotFound (VM-ADR-12)", err)
		}
	})
}

// --- Gate: the projection is deterministic under reordering and replay ------

// TestProjectionDeterministicUnderReorderAndReplay is the fifth gate clause.
//
// The stored finding must be a function of the observations, never of the order
// they arrived in. Last-upsert-wins would make the record depend on scan
// scheduling, so replaying a run — or the same two tools finishing in the other
// order — would silently change the finding.
func TestProjectionDeterministicUnderReorderAndReplay(t *testing.T) {
	sources := []model.RawFinding{
		cryptoFinding("govulncheck"),
		cryptoFinding("osv-scanner"),
	}

	var reference model.Finding
	for perm := 0; perm < 2; perm++ {
		ordered := []model.RawFinding{sources[perm], sources[1-perm]}

		run(t, func(t *testing.T, s store.Store) {
			ctx := context.Background()
			seedRepo(t, s)
			r := newRun(t, s, store.KindSweep)

			if _, err := s.UpsertObservations(ctx, r.ID, testRepo, ordered); err != nil {
				t.Fatalf("upsert: %v", err)
			}
			// Replay the same batch, twice, in the other order.
			if _, err := s.UpsertObservations(ctx, r.ID, testRepo, ordered); err != nil {
				t.Fatalf("replay: %v", err)
			}
			if _, err := s.UpsertObservations(ctx, r.ID, testRepo, []model.RawFinding{ordered[1], ordered[0]}); err != nil {
				t.Fatalf("reordered replay: %v", err)
			}

			f, err := s.GetFinding(ctx, cryptoFP())
			if err != nil {
				t.Fatalf("get finding: %v", err)
			}

			// Replay must not multiply observations: one row per source per run.
			obs, _ := s.Observations(ctx, cryptoFP())
			if len(obs) != 2 {
				t.Errorf("got %d observations after replay, want 2 (one per source per run)", len(obs))
			}

			if reference.Fingerprint == "" {
				reference = f
				return
			}
			assertSameProjection(t, reference, f)
		})
	}
}

// TestProjectionStableAcrossRunsAndSources drives a longer, shuffled sequence:
// several runs, several tools, replayed in random order. The merged view must
// be identical every time.
func TestProjectionStableAcrossRunsAndSources(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)

		batch := []model.RawFinding{cryptoFinding("govulncheck"), cryptoFinding("osv-scanner")}

		var reference model.Finding
		rng := rand.New(rand.NewSource(7))
		for i := 0; i < 6; i++ {
			r := newRun(t, s, store.KindSweep)
			shuffled := append([]model.RawFinding(nil), batch...)
			rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })

			if _, err := s.UpsertObservations(ctx, r.ID, testRepo, shuffled); err != nil {
				t.Fatalf("upsert %d: %v", i, err)
			}
			f, err := s.GetFinding(ctx, cryptoFP())
			if err != nil {
				t.Fatalf("get finding: %v", err)
			}
			if i == 0 {
				reference = f
				continue
			}
			assertSameProjection(t, reference, f)
		}
	})
}

// TestPriorSourceSurvivesAPartialScan is the VM-AD §8.6 consistency constraint
// with OQ-P1-01: the projection must not drop a source's contribution because a
// later partial scan did not re-observe it. Same invariant as verification —
// absence of evidence is not evidence of absence.
func TestPriorSourceSurvivesAPartialScan(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)

		// Run 1: both tools report.
		r1 := newRun(t, s, store.KindSweep)
		if _, err := s.UpsertObservations(ctx, r1.ID, testRepo, []model.RawFinding{
			cryptoFinding("govulncheck"), cryptoFinding("osv-scanner"),
		}); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		scanned(t, s, r1.ID, model.ScanComplete, []string{"govulncheck", "osv-scanner"}, nil)

		// Run 2: govulncheck failed, only osv-scanner reported.
		r2 := newRun(t, s, store.KindSweep)
		if _, err := s.UpsertObservations(ctx, r2.ID, testRepo, []model.RawFinding{
			cryptoFinding("osv-scanner"),
		}); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		scanned(t, s, r2.ID, model.ScanPartial, []string{"osv-scanner"}, []string{"govulncheck"})
		if _, err := s.Reconcile(ctx, r2.ID, testRepo); err != nil {
			t.Fatalf("reconcile: %v", err)
		}

		f, err := s.GetFinding(ctx, cryptoFP())
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		// govulncheck's reachability determination must survive: it was not
		// contradicted, merely not repeated.
		if f.Classification.Reachable != model.ReachableTrue {
			t.Errorf("reachable = %q, want true: a source's contribution is superseded only by a successful re-scan from that source (VM-AD §8.6)",
				f.Classification.Reachable)
		}
		if len(f.Provenance.Tools) != 2 {
			t.Errorf("tools = %v, want both retained", f.Provenance.Tools)
		}
	})
}

// --- Run identity (VM-ADR-11, VM-F-112, VM-F-115) --------------------------

func TestRunIdentityIsAPerKindSequence(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()

		s1 := newRun(t, s, store.KindSweep)
		s2 := newRun(t, s, store.KindSweep)
		a1 := newRun(t, s, store.KindAdvisory)

		if s1.ID != "S-000001" || s2.ID != "S-000002" {
			t.Errorf("sweep ids = %s, %s; want S-000001, S-000002", s1.ID, s2.ID)
		}
		// Sweep numbering is not consumed by other kinds (VM-F-115).
		if a1.ID != "A-000001" {
			t.Errorf("advisory id = %s, want A-000001: each kind draws from its own sequence", a1.ID)
		}

		got, err := s.GetRun(ctx, s2.ID)
		if err != nil {
			t.Fatalf("get run: %v", err)
		}
		if got.Kind != store.KindSweep || got.Seq != 2 {
			t.Errorf("run = %+v, want kind sweep seq 2", got)
		}
		if got.StartedAt.IsZero() {
			t.Error("run has no start timestamp; the identifier is not self-dating (VM-F-119)")
		}
	})
}

// TestRunsInTheSameSecondAreDistinct covers VM-F-112: the sequence is allocated
// by the datastore, not derived from a timestamp, so a timestamp collision
// cannot collide identifiers.
func TestRunsInTheSameSecondAreDistinct(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		frozen := time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)
		switch impl := s.(type) {
		case *store.Memory:
			impl.SetClock(func() time.Time { return frozen })
		case *store.Postgres:
			impl.SetClock(func() time.Time { return frozen })
		}

		seen := map[string]bool{}
		for i := 0; i < 5; i++ {
			r := newRun(t, s, store.KindSweep)
			if seen[r.ID] {
				t.Fatalf("duplicate run id %s from runs starting in the same second (VM-F-112)", r.ID)
			}
			seen[r.ID] = true
		}
	})
}

// --- Scope is never defaulted (VM-ADR-14) -----------------------------------

func TestQueryScopeIsRequired(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		if _, err := s.ListFindings(context.Background(), store.Query{}); !errors.Is(err, store.ErrScopeRequired) {
			t.Fatalf("a query with no scope returned %v, want ErrScopeRequired (VM-ADR-14)", err)
		}
	})
}

func TestScopesSelectDifferentCorpora(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		fp := cryptoFP()

		r1 := newRun(t, s, store.KindSweep)
		mustUpsert(t, s, r1.ID, cryptoFinding("govulncheck"))
		scanned(t, s, r1.ID, model.ScanComplete, []string{"govulncheck"}, nil)
		walkToMerged(t, s, fp)

		r2 := newRun(t, s, store.KindSweep)
		scanned(t, s, r2.ID, model.ScanComplete, []string{"govulncheck"}, nil)
		if _, err := s.Reconcile(ctx, r2.ID, testRepo); err != nil {
			t.Fatalf("reconcile: %v", err)
		}

		open, _ := s.ListFindings(ctx, store.Query{Scope: store.ScopeOpen})
		all, _ := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
		inRun1, _ := s.ListFindings(ctx, store.Query{Scope: store.ScopeRun, RunID: r1.ID})
		inRun2, _ := s.ListFindings(ctx, store.Query{Scope: store.ScopeRun, RunID: r2.ID})

		if len(open) != 0 {
			t.Errorf("open = %d, want 0 once verified", len(open))
		}
		if len(all) != 1 {
			t.Errorf("all = %d, want 1", len(all))
		}
		if len(inRun1) != 1 {
			t.Errorf("run 1 = %d, want 1", len(inRun1))
		}
		if len(inRun2) != 0 {
			t.Errorf("run 2 = %d, want 0", len(inRun2))
		}
	})
}

// --- Illegal transitions are rejected at the store boundary ----------------

func TestStoreRejectsIllegalTransitions(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		r := newRun(t, s, store.KindSweep)
		mustUpsert(t, s, r.ID, cryptoFinding("govulncheck"))
		fp := cryptoFP()

		// DETECTED -> MERGED is not in the table: no pull request was ever
		// opened, so there is nothing that could have merged.
		//
		// This used to be DETECTED -> VERIFIED, which became legal in
		// VM-AD §6.1.3: disappearance verifies from every active state, and a
		// finding can be fixed out of band before triage routes it.
		err := s.ApplyTransition(ctx, fp, model.Merged, model.TransitionContext{
			Actor: model.ActorOrchestrator, Cause: "should be rejected",
		})
		if err == nil {
			t.Fatal("store applied DETECTED -> MERGED")
		}
		var ite *model.IllegalTransitionError
		if !errors.As(err, &ite) {
			t.Errorf("got %T, want *IllegalTransitionError", err)
		}
		if got := stateOf(t, s, fp); got != model.Detected {
			t.Errorf("state = %q after a rejected transition, want DETECTED unchanged", got)
		}
	})
}

// TestStoreRejectsVerificationWithoutSuccessfulScan covers the guard at the
// store boundary, independently of reconciliation.
func TestStoreRejectsVerificationWithoutSuccessfulScan(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)
		r := newRun(t, s, store.KindSweep)
		mustUpsert(t, s, r.ID, cryptoFinding("govulncheck"))
		fp := cryptoFP()
		walkToMerged(t, s, fp)

		err := s.ApplyTransition(ctx, fp, model.Verified, model.TransitionContext{
			Actor: model.ActorScanWorker, ScanOutcome: model.ScanFailed,
		})
		if err == nil {
			t.Fatal("store verified a finding on a failed scan (VM-ADR-12)")
		}
		var uae *model.UnverifiedAbsenceError
		if !errors.As(err, &uae) {
			t.Errorf("got %T, want *UnverifiedAbsenceError", err)
		}
	})
}

// --- Scan results are retained per run (VM-F-213) ---------------------------

func TestScanResultsRetainedPerRun(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		seedRepo(t, s)

		for i, outcome := range []store.ScanOutcome{model.ScanComplete, model.ScanFailed, model.ScanFailed} {
			r := newRun(t, s, store.KindSweep)
			scanned(t, s, r.ID, outcome, nil, nil)
			_ = i
		}

		results, err := s.ScanResults(ctx, testRepo, 10)
		if err != nil {
			t.Fatalf("scan results: %v", err)
		}
		if len(results) != 3 {
			t.Fatalf("got %d results, want 3 (one per run, VM-F-213)", len(results))
		}
		// Newest first, so a consecutive-failure streak is computable.
		if results[0].Outcome != model.ScanFailed || results[1].Outcome != model.ScanFailed {
			t.Errorf("results are not newest-first: %v", []store.ScanOutcome{results[0].Outcome, results[1].Outcome})
		}
	})
}

// --- helpers ----------------------------------------------------------------

func mustUpsert(t *testing.T, s store.Store, runID string, raws ...model.RawFinding) {
	t.Helper()
	if _, err := s.UpsertObservations(context.Background(), runID, testRepo, raws); err != nil {
		t.Fatalf("upsert: %v", err)
	}
}

func stateOf(t *testing.T, s store.Store, fp string) model.State {
	t.Helper()
	f, err := s.GetFinding(context.Background(), fp)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	return f.State
}

// walkToMerged drives a finding along the legal path DETECTED -> MERGED.
func walkToMerged(t *testing.T, s store.Store, fp string) {
	t.Helper()
	ctx := context.Background()
	steps := []struct {
		to    model.State
		actor model.Actor
	}{
		{model.Triaged, model.ActorTriage},
		{model.AutoRemediating, model.ActorOrchestrator},
		{model.PROpen, model.ActorWorker},
		{model.Merged, model.ActorOrchestrator},
	}
	for _, step := range steps {
		// The lease-bound state is entered only with a lease (VM-AD §6.1.5).
		if store.LeaseBound(step.to) {
			if err := s.AcquireLease(ctx, fp, "test-worker", leaseFarFuture); err != nil {
				t.Fatalf("acquiring the lease before entering %s: %v", step.to, err)
			}
		}
		if err := s.ApplyTransition(ctx, fp, step.to, model.TransitionContext{
			Actor: step.actor, Cause: "test walk",
		}); err != nil {
			t.Fatalf("transition to %s: %v", step.to, err)
		}
	}
}

func statesOf(ts []model.StateTransition) []model.State {
	out := make([]model.State, len(ts))
	for i, t := range ts {
		out[i] = t.To
	}
	return out
}

// assertSameProjection compares the merged fields two runs produced.
func assertSameProjection(t *testing.T, want, got model.Finding) {
	t.Helper()
	checks := []struct {
		name      string
		want, got any
	}{
		{"reachable", want.Classification.Reachable, got.Classification.Reachable},
		{"severity", want.Classification.Severity, got.Classification.Severity},
		{"cvss", want.Classification.CVSS, got.Classification.CVSS},
		{"dep_class", want.Classification.DepClass, got.Classification.DepClass},
		{"primary_id", want.Identity.PrimaryID, got.Identity.PrimaryID},
		{"aliases", fmt.Sprint(want.Identity.Aliases), fmt.Sprint(got.Identity.Aliases)},
		{"tools", fmt.Sprint(want.Provenance.Tools), fmt.Sprint(got.Provenance.Tools)},
		{"fixed", want.Versions.Fixed, got.Versions.Fixed},
	}
	for _, c := range checks {
		if c.want != c.got {
			t.Errorf("projection is order-dependent: %s = %v, want %v (VM-AD §8.6)", c.name, c.got, c.want)
		}
	}
}
