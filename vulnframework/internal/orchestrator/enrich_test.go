package orchestrator_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/feed"
	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/triage"
)

// OQ-AUDIT-01(b) — the pass that gives KEV and EPSS a producer.
//
// The scorer declares five inputs. Two of them — is this being exploited right
// now, and how likely is it to be — were written by nothing, so every priority
// in the system was computed from three inputs while presenting as a priority.
// The tests here are about what the SCORE says afterwards, because the point of
// the pass is not that rows land in a table.

// aliasedDep is a Go advisory with a CVE alias, which is the ordinary shape:
// the feeds are CVE-keyed and the finding is GO- identified.
func aliasedDep(repo, goID, cve string) model.RawFinding {
	f := depFinding(repo, goID, "v0.16.0", "v0.16.1")
	f.Aliases = []string{cve, "GHSA-xxxx-yyyy-zzzz"}
	return f
}

func enrichFixture(t *testing.T, s store.Store) (store.Repo, string) {
	t.Helper()
	repos := fleet(t, s, "org/api")
	raw := aliasedDep("org/api", "GO-2023-2402", "CVE-2023-48795")
	seedDetected(t, s, repos, raw)
	return repos[0], fingerprint.Compute(raw)
}

// scoreOf runs the real triage-and-route pass and returns what the finding got.
func scoreOf(t *testing.T, o *orchestrator.Orchestrator, s store.Store, repo store.Repo, fp string) (model.Finding, score.Result) {
	t.Helper()
	ctx := context.Background()
	tr, sc, pol := pipeline(t)
	if _, err := o.TriageAndRoute(ctx, repo, tr, sc, pol, routeView{}); err != nil {
		t.Fatalf("TriageAndRoute: %v", err)
	}
	f, err := s.GetFinding(ctx, fp)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	// Re-score through the same scorer, to read the caveat the pass computed
	// from the same inputs.
	res := sc.Score(score.Input{
		Category: f.Category, Severity: f.Classification.Severity, CVSS: f.Classification.CVSS,
		EPSS: f.Classification.EPSS, KEV: f.Classification.KEV,
		EPSSAvailable: f.Classification.EPSSAvailable, KEVAvailable: f.Classification.KEVAvailable,
		EPSSAsOf: f.Classification.EPSSAsOf, KEVAsOf: f.Classification.KEVAsOf,
		Reachable: f.Classification.Reachable, DepClass: f.Classification.DepClass,
		Tier: repo.Tier, Now: at,
	})
	return f, res
}

func TestEnrichmentResolvesAliasesAndReachesTheScore(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repo, fp := enrichFixture(t, s)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50),
			orchestrator.Config{})
		o.Clock = func() time.Time { return at }

		// The catalogues know the CVE. They have never heard of GO-2023-2402,
		// which is the whole reason the pass offers every identifier.
		kev := feed.NewFakeKEV().WithKEV("CVE-2023-48795", at.Add(-24*time.Hour))
		epss := feed.NewFakeEPSS().WithEPSS("CVE-2023-48795", 0.61, at.Add(-12*time.Hour))

		stats, err := o.EnrichPass(ctx, feed.Multi{Sources: []feed.Source{kev, epss}}, repo.Name)
		if err != nil {
			t.Fatalf("EnrichPass: %v", err)
		}
		if stats.Answered != 1 {
			t.Fatalf("answered=%d of %d identifiers; the CVE alias was not offered to the feeds "+
				"(asked: %v)", stats.Answered, stats.Identifiers, kev.LastIDs())
		}
		if stats.Stored != 1 {
			t.Errorf("stored=%d, want 1", stats.Stored)
		}

		f, res := scoreOf(t, o, s, repo, fp)
		if !f.Classification.KEVAvailable || !f.Classification.KEV {
			t.Errorf("the finding does not carry the KEV answer: %+v", f.Classification)
		}
		if !f.Classification.EPSSAvailable || f.Classification.EPSS != 0.61 {
			t.Errorf("the finding does not carry the EPSS answer: %+v", f.Classification)
		}
		if f.Classification.KEVAsOf == nil || f.Classification.EPSSAsOf == nil {
			t.Error("the answers arrived with no snapshot dates; a score quoted without its date " +
				"cannot be judged")
		}
		if res.KEVBoost == 0 {
			t.Error("kev_boost did not apply to a known-exploited finding; the boost has been " +
				"configured at 3.0 since Phase 5 and could never fire")
		}
		if res.EPSSBoost == 0 {
			t.Error("the epss coefficient did not apply")
		}
		if res.Caveat != "" {
			t.Errorf("a fully-informed score still carries a caveat: %q", res.Caveat)
		}
		if len(res.UnavailableInputs) != 0 {
			t.Errorf("unavailable inputs remain after both feeds answered: %v", res.UnavailableInputs)
		}
	})
}

// TestAnIdentifierInNeitherCatalogueScoresWithACaveat is the tri-state clause:
// nothing answered, so the score says so rather than treating silence as zero.
func TestAnIdentifierInNeitherCatalogueScoresWithACaveat(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repo, fp := enrichFixture(t, s)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50),
			orchestrator.Config{})
		o.Clock = func() time.Time { return at }

		// Both feeds are up and neither lists this vulnerability.
		kev, epss := feed.NewFakeKEV(), feed.NewFakeEPSS()
		stats, err := o.EnrichPass(ctx, feed.Multi{Sources: []feed.Source{kev, epss}}, repo.Name)
		if err != nil {
			t.Fatalf("EnrichPass: %v", err)
		}
		if stats.Stored != 0 {
			t.Errorf("stored=%d rows for an identifier nothing answered about. A row with both "+
				"availability flags false is indistinguishable from one never fetched, and writing "+
				"it would turn 'we asked and learned nothing' into 'checked, negligible'", stats.Stored)
		}
		if stats.Degraded() {
			t.Errorf("both feeds answered; the pass must not report degradation: %v", stats.SourcesDown)
		}

		f, res := scoreOf(t, o, s, repo, fp)
		if f.Classification.KEVAvailable || f.Classification.EPSSAvailable {
			t.Errorf("availability was asserted for feeds that said nothing: %+v", f.Classification)
		}
		if len(res.UnavailableInputs) != 2 {
			t.Errorf("unavailable=%v, want both KEV and EPSS", res.UnavailableInputs)
		}
		if !strings.Contains(strings.ToLower(res.Caveat), "kev") {
			t.Errorf("the caveat does not name the missing input: %q", res.Caveat)
		}
		if res.KEVBoost != 0 || res.EPSSBoost != 0 {
			t.Error("a boost applied on the strength of an answer nobody gave")
		}
	})
}

// TestAFeedOutageIsRecordedLoudlyAndNeverScoresAsZero is the fail-closed half.
func TestAFeedOutageIsRecordedLoudlyAndNeverScoresAsZero(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repo, fp := enrichFixture(t, s)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50),
			orchestrator.Config{})
		o.Clock = func() time.Time { return at }

		// KEV lists it. EPSS is down. The score must carry the KEV boost and
		// name EPSS as missing — not score EPSS as zero, which is what a
		// single "found" flag would have produced.
		kev := feed.NewFakeKEV().WithKEV("CVE-2023-48795", at.Add(-24*time.Hour))
		epss := feed.NewFakeEPSS().Down("503 service unavailable")

		stats, err := o.EnrichPass(ctx, feed.Multi{Sources: []feed.Source{kev, epss}}, repo.Name)
		if err != nil {
			t.Fatalf("a feed outage must not fail the pass: %v", err)
		}
		if !stats.Degraded() || stats.SourcesDown[0] != "epss" {
			t.Errorf("the outage was absorbed silently: %+v", stats)
		}

		var recorded bool
		for _, e := range o.Recovery.Events() {
			if e.Kind == orchestrator.RecoveryFeedUnavailable {
				recorded = true
				if !strings.Contains(e.Reason, "epss") {
					t.Errorf("the event does not name the source that was down: %q", e.Reason)
				}
			}
		}
		if !recorded {
			t.Error("a fleet was scored without an exploitation feed and nothing recorded it; " +
				"every priority in that run is narrower than the ones beside it and the number " +
				"does not show it")
		}

		f, res := scoreOf(t, o, s, repo, fp)
		if !f.Classification.KEV || !f.Classification.KEVAvailable {
			t.Error("the source that was up lost its answer")
		}
		if f.Classification.EPSSAvailable {
			t.Error("a source that was down produced an availability claim")
		}
		if len(res.UnavailableInputs) != 1 || !strings.Contains(res.UnavailableInputs[0], "EPSS") {
			t.Errorf("unavailable=%v, want EPSS only", res.UnavailableInputs)
		}
		if res.KEVBoost == 0 {
			t.Error("the KEV boost did not apply during an EPSS outage")
		}
	})
}

// TestAStaleSnapshotIsUsedAndLabelled is the freshness clause. A stale answer
// beats silence — "known exploited as of nine days ago" outranks nothing — and
// the age travels with the number.
func TestAStaleSnapshotIsUsedAndLabelled(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repo, fp := enrichFixture(t, s)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50),
			orchestrator.Config{})
		o.Clock = func() time.Time { return at }

		stale := at.Add(-30 * 24 * time.Hour)
		kev := feed.NewFakeKEV().WithKEV("CVE-2023-48795", stale)
		epss := feed.NewFakeEPSS().WithEPSS("CVE-2023-48795", 0.44, stale)
		if _, err := o.EnrichPass(ctx, feed.Multi{Sources: []feed.Source{kev, epss}}, repo.Name); err != nil {
			t.Fatalf("EnrichPass: %v", err)
		}

		f, res := scoreOf(t, o, s, repo, fp)
		if !f.Classification.KEVAvailable || !f.Classification.EPSSAvailable {
			t.Fatal("a stale snapshot was discarded; 'known exploited last month' outranks silence")
		}
		if res.KEVBoost == 0 {
			t.Error("the boost was withheld because the snapshot was old, which discards the answer")
		}
		if len(res.StaleInputs) != 2 {
			t.Errorf("stale=%v, want both inputs labelled", res.StaleInputs)
		}
		if !strings.Contains(res.Caveat, "not been refreshed") &&
			!strings.Contains(res.Caveat, "not current") {
			t.Errorf("the caveat does not say the intelligence is old: %q", res.Caveat)
		}
		if !strings.Contains(res.Caveat, stale.Format("2006-01-02")) {
			t.Errorf("the caveat does not carry the snapshot date: %q", res.Caveat)
		}
	})
}

// TestEnrichmentAsksOncePerIdentifierNotOncePerFinding is the batching clause.
// A fleet sharing one advisory must produce one lookup, not one per repository.
func TestEnrichmentAsksOncePerIdentifierNotOncePerFinding(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")

		// Ten findings, all carrying the same CVE alias.
		var raws []model.RawFinding
		for i := 0; i < 10; i++ {
			raw := aliasedDep("org/api", "GO-2023-240"+string(rune('0'+i)), "CVE-2023-48795")
			raw.Module = "golang.org/x/mod" + string(rune('0'+i))
			raws = append(raws, raw)
		}
		seedDetected(t, s, repos, raws...)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50),
			orchestrator.Config{})
		o.Clock = func() time.Time { return at }

		kev := feed.NewFakeKEV().WithKEV("CVE-2023-48795", at.Add(-24*time.Hour))
		stats, err := o.EnrichPass(ctx, feed.Multi{Sources: []feed.Source{kev}}, repos[0].Name)
		if err != nil {
			t.Fatalf("EnrichPass: %v", err)
		}
		if stats.Findings != 10 {
			t.Fatalf("findings=%d, want 10", stats.Findings)
		}
		if kev.Lookups() != 1 {
			t.Errorf("the catalogue was queried %d times for ten findings; both real feeds are "+
				"whole-file publications and a request per finding is how a rate limit is "+
				"discovered in production", kev.Lookups())
		}
		// And one row serves all ten findings, because the intelligence is a
		// property of the vulnerability rather than of the occurrence.
		if stats.Stored != 1 {
			t.Errorf("stored=%d rows for one advisory shared by ten findings", stats.Stored)
		}
		all, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeOpen, Repo: "org/api"})
		if err != nil {
			t.Fatalf("ListFindings: %v", err)
		}
		for _, f := range all {
			if !f.Classification.KEV {
				t.Errorf("%s did not receive the shared answer", f.Fingerprint)
			}
		}
	})
}

// TestARefreshedFeedReachesFindingsWithoutARescan is why the join happens at
// read time. EPSS republishes daily; a value baked into the stored projection
// would only change when the next scan reprojected the finding, so an incident
// would reach the repositories that happened to be scanned that hour and no
// others.
func TestARefreshedFeedReachesFindingsWithoutARescan(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repo, fp := enrichFixture(t, s)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50),
			orchestrator.Config{})
		o.Clock = func() time.Time { return at }

		epss := feed.NewFakeEPSS().WithEPSS("CVE-2023-48795", 0.02, at.Add(-48*time.Hour))
		if _, err := o.EnrichPass(ctx, feed.Multi{Sources: []feed.Source{epss}}, repo.Name); err != nil {
			t.Fatalf("first EnrichPass: %v", err)
		}
		before, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("GetFinding: %v", err)
		}
		if before.Classification.EPSS != 0.02 {
			t.Fatalf("epss = %v, want 0.02", before.Classification.EPSS)
		}

		// The feed republishes: the vulnerability is now being exploited.
		epss.WithEPSS("CVE-2023-48795", 0.97, at.Add(-1*time.Hour))
		if _, err := o.EnrichPass(ctx, feed.Multi{Sources: []feed.Source{epss}}, repo.Name); err != nil {
			t.Fatalf("second EnrichPass: %v", err)
		}
		after, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("GetFinding: %v", err)
		}
		if after.Classification.EPSS != 0.97 {
			t.Errorf("epss = %v after a refresh, want 0.97 — no scan happened in between, and "+
				"waiting for one would mean an incident reached only the repositories being "+
				"scanned that hour", after.Classification.EPSS)
		}
	})
}

// TestNoFeedsConfiguredIsNotAnErrorAndNotSilent keeps the no-credentials path
// honest: the framework must run with no feeds at all, and say so in the score.
func TestNoFeedsConfiguredIsNotAnErrorAndNotSilent(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repo, fp := enrichFixture(t, s)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50),
			orchestrator.Config{})
		o.Clock = func() time.Time { return at }

		stats, err := o.EnrichPass(ctx, feed.Multi{}, repo.Name)
		if err != nil {
			t.Fatalf("a deployment with no feeds configured must still run: %v", err)
		}
		if stats.Stored != 0 || stats.Answered != 0 {
			t.Errorf("a pass with no sources claimed to have learned something: %+v", stats)
		}

		_, res := scoreOf(t, o, s, repo, fp)
		if len(res.UnavailableInputs) != 2 || res.Caveat == "" {
			t.Errorf("a score computed with no feeds configured does not say so: unavailable=%v "+
				"caveat=%q", res.UnavailableInputs, res.Caveat)
		}
	})
}

var _ = triage.Eligible
var _ = policy.AutoRemediate

// TestAnEmptyAnswerIsNotStoredAsAnAnswer is the negative that guards the
// pass's own filter. A row with both availability flags false is
// indistinguishable from one never fetched, so storing it converts "we asked
// and learned nothing" into "checked, negligible" — permanently, because the
// next pass sees a row and has no reason to doubt it.
func TestAnEmptyAnswerIsNotStoredAsAnAnswer(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repo, fp := enrichFixture(t, s)

		o := newOrchestrator(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(50),
			orchestrator.Config{})
		o.Clock = func() time.Time { return at }

		// The endpoint echoes the identifier back with no score attached.
		epss := feed.NewFakeEPSS().WithEmptyAnswer("CVE-2023-48795")
		stats, err := o.EnrichPass(ctx, feed.Multi{Sources: []feed.Source{epss}}, repo.Name)
		if err != nil {
			t.Fatalf("EnrichPass: %v", err)
		}
		if stats.Stored != 0 {
			t.Errorf("stored=%d rows from an answer that said nothing", stats.Stored)
		}

		intel, err := s.IntelFor(ctx, []string{"CVE-2023-48795"})
		if err != nil {
			t.Fatalf("IntelFor: %v", err)
		}
		if len(intel) != 0 {
			t.Errorf("an intelligence row exists for an identifier nothing assessed: %+v", intel)
		}

		_, res := scoreOf(t, o, s, repo, fp)
		if len(res.UnavailableInputs) != 2 {
			t.Errorf("unavailable=%v, want both: nothing was learned", res.UnavailableInputs)
		}
	})
}

// OQ-AUDIT-09 — a producer nothing invoked.
//
// firstparty.Registry.ClassifyAll existed, the adapters wrote the import path
// it reads, and policy rule 6 read its result — and no code path called it.
// Classification.FirstPartyPath was therefore never written by the running
// pipeline: the first-party defer could not fire, and the wave view had
// nothing to show. The same defect class as a field with no producer, in a
// shape the field census cannot see, because the field IS written whenever
// anything calls the function and every test that wanted it called it.
func TestThePipelineClassifiesFirstPartyFindingsAsItRecordsThem(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")

		registry, err := firstparty.ParseRegistry([]byte(
			"version: 1\nmodules:\n  github.com/wanaware/common: org/common\n"))
		if err != nil {
			t.Fatalf("ParseRegistry: %v", err)
		}

		// A finding in a registered first-party module, and one in a
		// third-party module, from the same scan.
		ours := depFinding("org/api", "GO-2026-0001", "v1.4.0", "v1.5.0")
		ours.Module, ours.ModuleMajor = "github.com/wanaware/common", "v1"
		ours.ImportPath = []string{"org/api", "github.com/wanaware/common/hash"}
		theirs := depFinding("org/api", "GO-2026-0002", "v0.1.0", "v0.2.0")
		theirs.Module, theirs.ModuleMajor = "golang.org/x/text", "v0"
		theirs.ImportPath = []string{"org/api", "golang.org/x/text/encoding"}

		d := orchestrator.NewFakeDispatcher()
		d.WithFindings("org/api", []string{"govulncheck"}, ours, theirs)

		o := newOrchestrator(s, d, orchestrator.NewRateBudget(50), orchestrator.Config{
			FirstParty: registry,
		})
		o.Clock = func() time.Time { return at }
		if _, err := o.Sweep(ctx, store.KindSweep, "cron", repos, nil); err != nil {
			t.Fatalf("Sweep: %v", err)
		}

		mine, err := s.GetFinding(ctx, fingerprint.Compute(ours))
		if err != nil {
			t.Fatalf("GetFinding: %v", err)
		}
		if mine.Classification.FirstPartyPath == nil {
			t.Fatal("a finding in a REGISTERED first-party module was recorded unclassified. " +
				"Nothing in the pipeline called the classifier, so policy rule 6 could never " +
				"defer to an upstream fix and the wave view had nothing to show (OQ-AUDIT-09)")
		}
		// The classifier records the first-party hop NEAREST THE CONSUMER,
		// which is the subpackage the vulnerable path traverses. That is the
		// hop the consumer can be advanced past; the registry resolves it back
		// to the module a wave is keyed by.
		if got := *mine.Classification.FirstPartyPath; got != "github.com/wanaware/common/hash" {
			t.Errorf("first_party_path = %q, want the nearest first-party hop", got)
		}
		if module, ok := registry.Module(*mine.Classification.FirstPartyPath); !ok ||
			module != "github.com/wanaware/common" {
			t.Errorf("the classified path does not resolve to the registered module: %q, %v",
				module, ok)
		}

		// The negative: a third-party module must NOT be claimed as ours.
		// Classifying everything would defer third-party findings to an
		// upstream fix nobody owns, and they would leave the queue and arrive
		// nowhere.
		other, err := s.GetFinding(ctx, fingerprint.Compute(theirs))
		if err != nil {
			t.Fatalf("GetFinding: %v", err)
		}
		if other.Classification.FirstPartyPath != nil {
			t.Errorf("a third-party module was classified as first-party: %q",
				*other.Classification.FirstPartyPath)
		}
	})
}

// TestWithNoRegistryNothingIsClassified is the other half: a deployment that
// has not declared its modules must not have findings silently claimed.
func TestWithNoRegistryNothingIsClassified(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		repos := fleet(t, s, "org/api")

		raw := depFinding("org/api", "GO-2026-0001", "v1.4.0", "v1.5.0")
		raw.Module = "github.com/wanaware/common"
		d := orchestrator.NewFakeDispatcher()
		d.WithFindings("org/api", []string{"govulncheck"}, raw)

		o := newOrchestrator(s, d, orchestrator.NewRateBudget(50), orchestrator.Config{})
		o.Clock = func() time.Time { return at }
		if _, err := o.Sweep(ctx, store.KindSweep, "cron", repos, nil); err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		f, err := s.GetFinding(ctx, fingerprint.Compute(raw))
		if err != nil {
			t.Fatalf("GetFinding: %v", err)
		}
		if f.Classification.FirstPartyPath != nil {
			t.Errorf("with no registry configured, %q was classified as first-party",
				*f.Classification.FirstPartyPath)
		}
	})
}
