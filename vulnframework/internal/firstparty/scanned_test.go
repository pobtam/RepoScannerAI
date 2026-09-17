package firstparty_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/store"
)

// OQ-P11-01 closed: the wave machinery, re-run over SCANNER-WRITTEN data.
//
// Everything else in this package builds its index by hand. That proves the
// algorithm is correct; it does not prove the algorithm runs. The distinction
// is not academic — it is the third instance in one phase of a consumer
// reading a field no producer wrote, and the two previous instances
// (FirstPartyPath, ImportPath) were each invisible to a full green suite.
//
// So these tests start at a go.mod on disk and end at a wave plan.

// writeRepo creates a checkout with a manifest, as a clone would be.
func writeRepo(t *testing.T, gomod string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	return dir
}

// scanInto reads a repository's manifest the way the worker does and records
// it, so the index below is built from producer output rather than fixtures.
func scanInto(t *testing.T, s store.Store, runID, repo, gomod string) {
	t.Helper()
	deps, err := scan.ReadGoManifest(writeRepo(t, gomod))
	if err != nil {
		t.Fatalf("ReadGoManifest: %v", err)
	}
	var recorded []store.ModuleDep
	for _, d := range deps {
		recorded = append(recorded, store.ModuleDep{
			Module: d.Module, Version: d.Version, Direct: d.Direct, Replaced: d.Replaced,
		})
	}
	if err := s.RecordDeps(context.Background(), runID, repo, recorded); err != nil {
		t.Fatalf("RecordDeps: %v", err)
	}
}

func scannedFleet(t *testing.T) (store.Store, *firstparty.Index) {
	t.Helper()
	ctx := context.Background()
	s := store.NewMemory()
	s.SetClock(func() time.Time { return atTime })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Four consumers, written as real manifests. One has a replace directive
	// and one is behind — both facts that ONLY exist in a go.mod.
	scanInto(t, s, "S-000001", "org/wanaware-api", `module github.com/wanaware/api
go 1.24
require (
	github.com/wanaware/common v1.4.0
	golang.org/x/crypto v0.35.0
)
`)
	scanInto(t, s, "S-000001", "org/wanaware-jobs", `module github.com/wanaware/jobs
go 1.24
require github.com/wanaware/common v1.4.0
`)
	scanInto(t, s, "S-000001", "org/wanaware-web", `module github.com/wanaware/web
go 1.24
require github.com/wanaware/common v1.4.0
replace github.com/wanaware/common => ../common
`)
	scanInto(t, s, "S-000001", "org/wanaware-batch", `module github.com/wanaware/batch
go 1.24
require github.com/wanaware/common v1.1.0
`)
	// The owner itself, which must not appear as its own consumer.
	scanInto(t, s, "S-000001", ownerRepo, `module github.com/wanaware/common
go 1.24
require golang.org/x/crypto v0.35.0
`)

	idx, err := firstparty.LoadIndex(ctx, s, registry(t))
	if err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}
	return s, idx
}

// TestTheIndexIsBuiltFromScannerWrittenManifests is the clause that closes
// OQ-P11-01.
func TestTheIndexIsBuiltFromScannerWrittenManifests(t *testing.T) {
	_, idx := scannedFleet(t)

	consumers := idx.Consumers(sharedModule)
	var names []string
	for _, c := range consumers {
		names = append(names, c.Repo)
	}
	sort.Strings(names)
	want := []string{"org/wanaware-api", "org/wanaware-batch", "org/wanaware-jobs", "org/wanaware-web"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("Consumers = %v, want %v. The index is built from what scans recorded; if this is "+
			"empty, nothing writes module_deps and every wave decision in this package is an "+
			"assertion about a fixture (OQ-P11-01)", names, want)
	}

	// The two facts that exist only in a manifest, carried through the
	// producer, the store, and the index.
	byRepo := map[string]firstparty.Consumer{}
	for _, c := range consumers {
		byRepo[c.Repo] = c
	}
	if !byRepo["org/wanaware-web"].Replaced {
		t.Error("the replace directive did not survive from go.mod to the index; VM-F-608's exclusion " +
			"would never fire, and a wave would bump a requirement that changes nothing built")
	}
	if byRepo["org/wanaware-batch"].Version != "v1.1.0" {
		t.Errorf("the laggard's version is %q, want v1.1.0 from its manifest",
			byRepo["org/wanaware-batch"].Version)
	}
	// And the owner is not its own consumer.
	if _, ok := byRepo[ownerRepo]; ok {
		t.Error("the owning repository appears as a consumer of its own module")
	}
}

// TestWavePlanningOverScannerWrittenData re-runs the Phase 11 decisions over
// real producer output: the replace exclusion and the spread split, both from
// facts that were in a go.mod ten minutes ago.
func TestWavePlanningOverScannerWrittenData(t *testing.T) {
	_, idx := scannedFleet(t)

	plan := firstparty.PlanWaveTwo(idx, firstparty.WaveRequest{
		Module: sharedModule, UpstreamFP: "upstream-fp-0001", TargetVersion: "v1.5.0",
	})

	var dispatched []string
	for _, c := range plan.Dispatch {
		dispatched = append(dispatched, c.Repo)
	}
	sort.Strings(dispatched)
	if strings.Join(dispatched, ",") != "org/wanaware-api,org/wanaware-jobs" {
		t.Errorf("dispatch = %v, want the two current, unreplaced consumers", dispatched)
	}

	if len(plan.Excluded) != 1 || plan.Excluded[0].Repo != "org/wanaware-web" {
		t.Errorf("excluded = %+v, want the replaced consumer (VM-F-608)", plan.Excluded)
	}
	if len(plan.Deferred) != 1 || plan.Deferred[0].Repo != "org/wanaware-batch" {
		t.Errorf("deferred = %+v, want the laggard (VM-F-613)", plan.Deferred)
	}
	if !plan.Split {
		t.Error("the diverged fleet was not split")
	}
	if !plan.Spread.Diverged() || plan.Spread.Newest != "v1.4.0" {
		t.Errorf("spread = %+v, want divergence with v1.4.0 newest", plan.Spread)
	}
}

// TestDeterminismHoldsOverScannerWrittenData re-runs the permutation property
// over producer output, in the order the store returns it.
//
// The Phase 11 version rotated a hand-built slice. This one varies the order
// repositories are SCANNED in, which is the order that actually varies in
// production: dispatch is concurrent and most-stale-first.
func TestDeterminismHoldsOverScannerWrittenData(t *testing.T) {
	manifests := []struct{ repo, gomod string }{
		{"org/a", "module a\nrequire github.com/wanaware/common v1.4.0\n"},
		{"org/b", "module b\nrequire github.com/wanaware/common v1.4.0\n"},
		{"org/c", "module c\nrequire github.com/wanaware/common v1.1.0\n"},
		{"org/d", "module d\nrequire github.com/wanaware/common v1.4.0\nreplace github.com/wanaware/common => ../common\n"},
	}

	render := func(p firstparty.WavePlan) string {
		var b strings.Builder
		for _, c := range p.Dispatch {
			b.WriteString("D:" + c.Repo + ";")
		}
		for _, c := range p.Excluded {
			b.WriteString("X:" + c.Repo + ";")
		}
		for _, c := range p.Deferred {
			b.WriteString("F:" + c.Repo + ";")
		}
		return b.String()
	}

	var first string
	for shift := 0; shift < len(manifests); shift++ {
		ctx := context.Background()
		s := store.NewMemory()
		s.SetClock(func() time.Time { return atTime })
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		for i := range manifests {
			m := manifests[(i+shift)%len(manifests)]
			scanInto(t, s, "S-000001", m.repo, m.gomod)
		}
		idx, err := firstparty.LoadIndex(ctx, s, registry(t))
		if err != nil {
			t.Fatalf("LoadIndex: %v", err)
		}
		got := render(firstparty.PlanWaveTwo(idx, firstparty.WaveRequest{
			Module: sharedModule, UpstreamFP: "up", TargetVersion: "v1.5.0",
		}))
		if shift == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("scanning in a different order produced a different wave:\n got %s\nwant %s", got, first)
		}
	}
}

// TestADroppedDependencyStopsBeingAConsumer is the negative half, and it is
// why RecordDeps replaces a repository's manifest wholesale rather than
// merging into it.
//
// A repository that removed the shared module must stop appearing as a
// consumer. Merging would leave it listed for ever, and the next wave would
// try to advance a module it no longer uses — a pull request its owners
// cannot explain.
func TestADroppedDependencyStopsBeingAConsumer(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemory()
	s.SetClock(func() time.Time { return atTime })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	scanInto(t, s, "S-000001", "org/leaver", "module l\nrequire github.com/wanaware/common v1.4.0\n")
	idx, err := firstparty.LoadIndex(ctx, s, registry(t))
	if err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}
	if len(idx.Consumers(sharedModule)) != 1 {
		t.Fatalf("fixture: expected one consumer")
	}

	// The next scan finds the dependency gone.
	scanInto(t, s, "S-000002", "org/leaver", "module l\nrequire golang.org/x/crypto v0.35.0\n")
	idx, err = firstparty.LoadIndex(ctx, s, registry(t))
	if err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}
	if n := len(idx.Consumers(sharedModule)); n != 0 {
		t.Errorf("%d consumers after the dependency was dropped, want 0; the next wave would open a "+
			"pull request against a module the repository no longer uses", n)
	}
}

// TestTheOrchestratorPersistsWhatTheWorkerRead is the last link, and the one
// most likely to be missing.
//
// The worker can read a manifest perfectly and the index still be empty if
// nothing carries it to the store. That is precisely the shape of all three
// defects this phase found: each link worked, and one of them was not
// connected to the next.
func TestTheOrchestratorPersistsWhatTheWorkerRead(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemory()
	s.SetClock(func() time.Time { return atTime })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := s.UpsertRepo(ctx, store.Repo{
		Name: consumerRepo, Tier: 1, Languages: []string{"go"}, HasTestSuite: true,
	}); err != nil {
		t.Fatalf("upsert repo: %v", err)
	}

	// What the WORKER produces, from a real manifest on disk.
	deps, err := scan.ReadGoManifest(writeRepo(t, `module github.com/wanaware/api
go 1.24
require github.com/wanaware/common v1.4.0
`))
	if err != nil {
		t.Fatalf("ReadGoManifest: %v", err)
	}
	if len(deps) == 0 {
		t.Fatal("the worker read no dependencies from a manifest that has one")
	}

	// The dispatcher hands that Result to the orchestrator, which must persist
	// it. Asserted through the store, not through the Result.
	d := orchestrator.NewFakeDispatcher()
	d.WithDeps(consumerRepo, deps)
	o := orchestrator.New(s, d, orchestrator.NewRateBudget(10), orchestrator.Config{CreditsPerScan: 1})
	o.Clock = func() time.Time { return atTime }

	repos := []store.Repo{{Name: consumerRepo, Tier: 1, Languages: []string{"go"}, HasTestSuite: true}}
	if _, err := o.Sweep(ctx, store.KindSweep, "cron", repos, nil); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	recorded, err := s.AllDeps(ctx)
	if err != nil {
		t.Fatalf("AllDeps: %v", err)
	}
	if len(recorded) == 0 {
		t.Fatal("a sweep recorded no dependencies. The worker read the manifest and nothing carried " +
			"it to the store: the index stays empty and every first-party wave is inert, while every " +
			"test in this package that builds its own index still passes")
	}
	idx, err := firstparty.LoadIndex(ctx, s, registry(t))
	if err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}
	if len(idx.Consumers(sharedModule)) != 1 {
		t.Errorf("the index built from a real sweep has %d consumers, want 1",
			len(idx.Consumers(sharedModule)))
	}
}
