package firstparty_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
	"github.com/wanaware/vulnframework/internal/store"
)

// THE PHASE 6 CONSTRAINT, NOW DUE.
//
// Recorded at Phase 6 and deferred until real data flowed this path:
//
//	"Phase 11 MUST include a full scan-to-decision test populating
//	 FirstPartyPath from real classification through to a defer_upstream
//	 outcome."
//
// This is the test that would have caught the Phase 6 projection bug. That bug
// was not that FirstPartyPath was computed wrongly — it was that the store's
// projection DROPPED the field, so upstream defer could never have fired in
// production, and every policy unit test passed because each one constructed
// the finding it tested directly.
//
// A passing policy unit test proves the rule, not that the rule runs. An
// invariant is only real if its input survives every projection between scan
// and decision. So ground truth here is the CLASSIFIER INPUT — the import path
// a scanner reported — and the assertion is at the far end, on the policy
// outcome, with the whole store in between.

var atTime = time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)

// TestFirstPartyPathSurvivesFromClassifierInputToPolicyOutcome is the gate.
func TestFirstPartyPathSurvivesFromClassifierInputToPolicyOutcome(t *testing.T) {
	ctx := context.Background()

	s := store.NewMemory()
	s.SetClock(func() time.Time { return atTime })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, repo := range []string{consumerRepo, ownerRepo} {
		if err := s.UpsertRepo(ctx, store.Repo{
			Name: repo, Tier: 1, Languages: []string{"go"}, HasTestSuite: true,
		}); err != nil {
			t.Fatalf("upsert repo: %v", err)
		}
	}

	// --- GROUND TRUTH: what the scanner reported ---------------------------
	//
	// A third-party vulnerability, reached through a first-party module. The
	// import path is the scanner's structural output, and it is the ONLY
	// place this fact exists: nothing else in the finding records the hop.
	raw := model.RawFinding{
		Repo: consumerRepo, Category: model.CategoryDependency,
		PrimaryID: "GO-2025-3106", Aliases: []string{"CVE-2025-22869"},
		Module: "golang.org/x/crypto", ModuleMajor: "v0",
		Tool: "govulncheck", ToolVersion: "v1.8.0",
		Versions: model.Versions{Current: "v0.35.0", Fixed: "v0.36.0"},
		Classification: model.Classification{
			Severity: model.SeverityHigh, Reachable: model.ReachableTrue,
			DepClass: model.DepProduction,
		},
		ImportPath: []string{consumerRepo, sharedModule, "golang.org/x/crypto"},
	}
	fp := fingerprint.Compute(raw)

	// --- 1. Classification, as normalisation performs it -------------------
	classified := registry(t).ClassifyAll([]model.RawFinding{raw})
	if classified[0].Classification.FirstPartyPath == nil {
		t.Fatal("classification did not populate first_party_path from the import path; " +
			"nothing downstream can defer upstream without it")
	}
	if got := *classified[0].Classification.FirstPartyPath; got != sharedModule {
		t.Fatalf("classifier produced %q, want %q", got, sharedModule)
	}

	// --- 2. Through the store ----------------------------------------------
	run, err := s.CreateRun(ctx, store.KindSweep, "cron", "img@sha256:abc",
		map[string]string{"govulncheck": "v1.8.0"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := s.RecordPlan(ctx, []store.PlanEntry{
		{RunID: run.ID, Repo: consumerRepo, State: store.DispatchPlanned},
	}); err != nil {
		t.Fatalf("record plan: %v", err)
	}
	if _, err := s.UpsertObservations(ctx, run.ID, consumerRepo, classified); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.RecordScanResult(ctx, store.RepoScanResult{
		RunID: run.ID, Repo: consumerRepo, Outcome: model.ScanComplete,
		ToolsOK: []string{"govulncheck"},
	}); err != nil {
		t.Fatalf("scan result: %v", err)
	}
	if _, err := s.Reconcile(ctx, run.ID, consumerRepo); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// --- 3. Read back: the field survived the projection -------------------
	//
	// This is the assertion the Phase 6 bug failed. It is read from the store,
	// not from the value passed in.
	stored, err := s.GetFinding(ctx, fp)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if stored.Classification.FirstPartyPath == nil {
		t.Fatal("the store's projection DROPPED first_party_path. Upstream defer could never fire in " +
			"production, and every policy unit test would still pass, because each constructs the " +
			"finding it tests directly. This is the Phase 6 bug, and this assertion is why it is here")
	}
	if got := *stored.Classification.FirstPartyPath; got != sharedModule {
		t.Fatalf("the store returned first_party_path %q, want %q", got, sharedModule)
	}

	// And it survives REPROJECTION, which is what the next scan triggers.
	run2, err := s.CreateRun(ctx, store.KindSweep, "cron", "img@sha256:abc",
		map[string]string{"govulncheck": "v1.8.0"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if _, err := s.UpsertObservations(ctx, run2.ID, consumerRepo, classified); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	reprojected, err := s.GetFinding(ctx, fp)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if reprojected.Classification.FirstPartyPath == nil {
		t.Fatal("reprojection dropped first_party_path; the defer would work on the first run and " +
			"silently stop on the second")
	}

	// --- 4. Triage, then the decision --------------------------------------
	if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{
		Actor: model.ActorTriage, Cause: "test", At: atTime,
	}); err != nil {
		t.Fatalf("triage: %v", err)
	}
	triaged, err := s.GetFinding(ctx, fp)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}

	pol, err := policy.LoadConfig("../../config/policy.yaml")
	if err != nil {
		t.Fatalf("policy config: %v", err)
	}
	decision, err := policy.New(pol).Evaluate(triaged, policy.Repo{
		Name: consumerRepo, Tier: 1, Language: policy.LangGo, HasTestSuite: true,
	}, upstreamView{owner: ownerRepo})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	// --- 5. THE DECISION ---------------------------------------------------
	if decision.Outcome != policy.DeferUpstream {
		t.Fatalf("outcome = %s, want defer_upstream (policy rule 5). The classifier set the field, "+
			"the store kept it, and the decision still did not use it — which means the chain is "+
			"broken somewhere between them, and only an end-to-end assertion can see where",
			decision.Outcome)
	}
	// Rule 6 in the corrected §10 numbering: the list omitted the
	// NEEDS_HUMAN / WONT_FIX rule added in Phase 4, so every index after it
	// was one low. The implementation was right and the specification was
	// stale; VM-F-405 records this index on the decision, so the two had to
	// be reconciled rather than left to disagree.
	if decision.Rule != 6 {
		t.Errorf("rule = %d, want 6 (first-party defer, VM-AD §10)", decision.Rule)
	}
}

// TestTheOwnerOfTheSharedModuleIsNotDeferred is the negative half of the same
// chain, and it is the one that would deadlock.
//
// The owning repository's own finding must NOT defer upstream: it would be
// waiting for a fix that only it can make. A classifier that set the field for
// everyone would produce a fleet in which nobody is responsible for anything,
// and every finding would carry a plausible reason for the delay.
func TestTheOwnerOfTheSharedModuleIsNotDeferred(t *testing.T) {
	ctx := context.Background()

	s := store.NewMemory()
	s.SetClock(func() time.Time { return atTime })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := s.UpsertRepo(ctx, store.Repo{
		Name: ownerRepo, Tier: 1, Languages: []string{"go"}, HasTestSuite: true,
	}); err != nil {
		t.Fatalf("upsert repo: %v", err)
	}

	// The same defect, reported in the OWNING repository.
	raw := model.RawFinding{
		Repo: ownerRepo, Category: model.CategoryDependency,
		PrimaryID: "GO-2025-3106", Module: "golang.org/x/crypto", ModuleMajor: "v0",
		Tool: "govulncheck", ToolVersion: "v1.8.0",
		Versions: model.Versions{Current: "v0.35.0", Fixed: "v0.36.0"},
		Classification: model.Classification{
			Severity: model.SeverityHigh, Reachable: model.ReachableTrue,
			DepClass: model.DepProduction,
		},
		ImportPath: []string{ownerRepo, sharedModule, "golang.org/x/crypto"},
	}
	fp := fingerprint.Compute(raw)
	classified := registry(t).ClassifyAll([]model.RawFinding{raw})

	run, err := s.CreateRun(ctx, store.KindSweep, "cron", "img", map[string]string{"govulncheck": "v1.8.0"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := s.RecordPlan(ctx, []store.PlanEntry{
		{RunID: run.ID, Repo: ownerRepo, State: store.DispatchPlanned},
	}); err != nil {
		t.Fatalf("record plan: %v", err)
	}
	if _, err := s.UpsertObservations(ctx, run.ID, ownerRepo, classified); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{
		Actor: model.ActorTriage, Cause: "test", At: atTime,
	}); err != nil {
		t.Fatalf("triage: %v", err)
	}

	stored, err := s.GetFinding(ctx, fp)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if stored.Classification.FirstPartyPath != nil {
		t.Fatalf("the owning repository's finding carries first_party_path %q; it would defer to "+
			"itself and nothing would ever unblock it", *stored.Classification.FirstPartyPath)
	}

	pol, err := policy.LoadConfig("../../config/policy.yaml")
	if err != nil {
		t.Fatalf("policy config: %v", err)
	}
	decision, err := policy.New(pol).Evaluate(stored, policy.Repo{
		Name: ownerRepo, Tier: 1, Language: policy.LangGo, HasTestSuite: true,
	}, upstreamView{owner: ownerRepo})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if decision.Outcome == policy.DeferUpstream {
		t.Error("the owning repository was told to defer upstream; it is upstream, and the finding " +
			"would wait for itself for ever")
	}
}

// upstreamView answers policy's question about first-party ownership.
type upstreamView struct{ owner string }

func (v upstreamView) HasOpenPullRequest(string) bool { return false }

// IsFirstPartyOwner reports whether this repository owns the module. Policy
// rule 5 defers only where the repository is NOT the owner.
func (v upstreamView) IsFirstPartyOwner(repo, _ string) bool { return repo == v.owner }

var _ = firstparty.Dependency{}

// TestARealAdapterPopulatesTheImportPathClassificationReads is the assertion
// that would catch this mechanism being inert.
//
// Everything else in this file constructs the RawFinding directly, which means
// every one of them would pass with NO adapter populating ImportPath at all —
// classification would read an empty field, find nothing first-party, and the
// whole two-wave design would quietly never fire. That is the Phase 6
// projection bug moved one layer further out, and it presents identically: a
// feature that is wired, tested, and dead.
//
// So ground truth here is the captured govulncheck output, parsed by the real
// adapter.
func TestARealAdapterPopulatesTheImportPathClassificationReads(t *testing.T) {
	out, err := os.ReadFile("../../testdata/fixtures/govulncheck/go-api.json")
	if err != nil {
		t.Fatalf("reading the govulncheck fixture: %v", err)
	}

	raws, err := adapters.NewGovulncheck(nil, "v1.8.0").Normalize(scan.RawOutput{
		Tool: "govulncheck", ToolVersion: "v1.8.0", Repo: consumerRepo, Stdout: out,
	})
	if err != nil {
		t.Fatalf("normalising: %v", err)
	}
	if len(raws) == 0 {
		t.Fatal("the fixture produced no findings")
	}

	var withPath int
	for _, r := range raws {
		if len(r.ImportPath) == 0 {
			continue
		}
		withPath++
		// The path runs from the consumer outwards: classification walks it
		// looking for the first internal hop, and a reversed path would find
		// the wrong module or none.
		if r.ImportPath[0] != consumerRepo {
			t.Errorf("import path starts at %q, want the consuming repository %q — classification "+
				"walks OUT from the consumer, and a reversed path finds the wrong hop",
				r.ImportPath[0], consumerRepo)
		}
		if last := r.ImportPath[len(r.ImportPath)-1]; r.Module != "" && last != r.Module {
			t.Errorf("import path ends at %q but the vulnerable module is %q", last, r.Module)
		}
	}
	if withPath == 0 {
		t.Fatal("the real adapter populated no import paths. First-party classification reads this " +
			"field and nothing else populates it: every finding would look third-party, and the " +
			"two-wave design would never fire in production while every unit test passed")
	}
}

// TestClassificationOfRealAdapterOutputIsInertWithoutARegistryEntry is the
// honest negative. The captured fixture's repository has no first-party
// intermediary, so nothing in it classifies — and that must be the case
// rather than an accident of the registry being empty.
func TestClassificationOfRealAdapterOutputIsInertWithoutARegistryEntry(t *testing.T) {
	out, err := os.ReadFile("../../testdata/fixtures/govulncheck/go-api.json")
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	raws, err := adapters.NewGovulncheck(nil, "v1.8.0").Normalize(scan.RawOutput{
		Tool: "govulncheck", ToolVersion: "v1.8.0", Repo: consumerRepo, Stdout: out,
	})
	if err != nil {
		t.Fatalf("normalising: %v", err)
	}

	for _, c := range registry(t).ClassifyAll(raws) {
		if c.Classification.FirstPartyPath != nil {
			t.Errorf("%s was classified first-party (%q) from a trace with no registered hop; the "+
				"registry is the only authority on ownership", c.PrimaryID, *c.Classification.FirstPartyPath)
		}
	}

	// And with a hop that IS registered, the same adapter output classifies.
	// Constructed rather than captured: this repository's fixtures contain no
	// first-party module, and pretending otherwise would be a fake fixture.
	withHop := raws[0]
	withHop.ImportPath = []string{consumerRepo, sharedModule, withHop.Module}
	classified := registry(t).Classify(withHop)
	if classified.Classification.FirstPartyPath == nil {
		t.Fatal("a registered hop in the adapter's own output did not classify")
	}
}
