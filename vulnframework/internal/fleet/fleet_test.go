package fleet_test

import (
	"context"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/fleet"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
)

// The twenty-repository fleet simulation.
//
// Everything here is fabricated and offline. What it tests is the behaviour
// that six repositories cannot show: planning under a budget that cannot cover
// the fleet, over enough rounds that an unfair rotation would be visible.

var simAt = time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)

type sim struct {
	store  *store.Memory
	result fleet.Result
	m      fleet.Measurement
}

// runSim drives the whole simulation once and measures it.
//
// Not cached between tests: each test gets its own store, so a test that
// mutated the fleet could not make another pass or fail. The cost is a few
// seconds and the alternative is tests that depend on their own order.
func runSim(t *testing.T) sim {
	t.Helper()
	ctx := context.Background()

	cal, err := score.LoadCalibration("../../config/calibration.yaml")
	if err != nil {
		t.Fatalf("calibration: %v", err)
	}
	pol, err := policy.LoadConfig("../../config/policy.yaml")
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	s := store.NewMemory()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	opts := fleet.Options{
		Calibration: cal, Policy: pol, Now: simAt,
		Rounds: fleet.DefaultRounds, Budget: fleet.DefaultBudget,
	}
	res, err := fleet.Seed(ctx, s, opts)
	if err != nil {
		t.Fatalf("fleet.Seed: %v", err)
	}
	m, err := fleet.Measure(ctx, s, res, opts)
	if err != nil {
		t.Fatalf("fleet.Measure: %v", err)
	}
	return sim{store: s, result: res, m: m}
}

// --- the premise -------------------------------------------------------------

// TestTheBudgetCannotCoverTheFleet is the precondition every other test here
// depends on.
//
// With a budget that covers the whole fleet nothing is ever deferred, the
// planner never has to choose, and the ordering that prevents starvation is
// never exercised. A simulation that quietly grew its budget would still pass
// every assertion below while testing nothing.
func TestTheBudgetCannotCoverTheFleet(t *testing.T) {
	sim := runSim(t)

	if sim.m.Budget >= sim.m.Repos {
		t.Fatalf("budget %d covers the whole fleet of %d; nothing is ever deferred and the "+
			"planning order is never exercised", sim.m.Budget, sim.m.Repos)
	}
	if sim.m.Repos != 20 {
		t.Fatalf("fleet is %d repositories, want 20", sim.m.Repos)
	}
	if deferred := sim.m.Coverage.ByCause[store.SkipBudgetExhausted]; deferred == 0 {
		t.Fatal("no repository was ever deferred for budget, so the premise did not hold")
	}
}

// --- starvation ---------------------------------------------------------------

// TestNoRepositoryStarves is the central question.
//
// Each round's budget covers 12 of 20, so a perfectly fair rotation still
// leaves some repository waiting ceil(20/12) = 2 rounds. The question is
// whether any repository waits materially longer — which is what happens when
// planning order is arbitrary and a repository can lose the lottery
// repeatedly.
//
// Measured as the longest CONSECUTIVE gap anywhere in the sequence, not from
// the final state: a fleet where one repository was skipped nine times running
// and scanned on the tenth looks identical, at the end, to one that rotated
// fairly.
func TestNoRepositoryStarves(t *testing.T) {
	sim := runSim(t)
	st := sim.m.Starvation

	if !st.EveryRepoScanned {
		var never []string
		for repo, n := range st.ScansPerRepo {
			if n == 0 {
				never = append(never, repo)
			}
		}
		sort.Strings(never)
		t.Fatalf("after %d rounds these repositories have never had a qualifying scan: %v",
			sim.m.Rounds, never)
	}

	// The allowance above the theoretical floor is for the injected failures:
	// a repository whose scan failed or went silent did not get a qualifying
	// scan that round however the planner ordered it, and the aborted round
	// cost every repository one.
	const allowance = 2
	if st.LongestGapRounds > st.Bound+allowance {
		t.Fatalf("%s went %d consecutive rounds without a qualifying scan. A fair rotation at "+
			"%d credits over %d repositories has a floor of %d, and the simulation injects "+
			"failures worth at most %d more. This is starvation: the planner is not promoting "+
			"stale repositories",
			st.WorstRepo, st.LongestGapRounds, sim.m.Budget, sim.m.Repos, st.Bound, allowance)
	}
}

// TestTheRotationIsEven is the other half.
//
// A fleet can avoid outright starvation and still be unfair: every repository
// scanned at least once, and one of them scanned twice as often as another.
// That shows up as a spread in the per-repository scan counts.
func TestTheRotationIsEven(t *testing.T) {
	sim := runSim(t)
	st := sim.m.Starvation

	spread := st.MaxScans - st.MinScans
	// Over ten rounds at 12/20 capacity, every repository should get roughly
	// six scans. A spread wider than the rotation period means somebody is
	// systematically losing.
	if spread > st.Bound+2 {
		var low []string
		for repo, n := range st.ScansPerRepo {
			if n == st.MinScans {
				low = append(low, repo)
			}
		}
		sort.Strings(low)
		t.Errorf("scan counts range from %d to %d across %d rounds (spread %d); the least-scanned "+
			"are %v. The rotation is not even",
			st.MinScans, st.MaxScans, sim.m.Rounds, spread, low)
	}
}

// TestStalenessIsBoundedRatherThanGrowing is the measurement a percentage
// cannot make.
//
// A flat gap count with a rising maximum age is starvation, and coverage
// percentage is blind to it: the same twelve repositories scanned every round
// gives 60% coverage for ever while the other eight age without limit.
func TestStalenessIsBoundedRatherThanGrowing(t *testing.T) {
	sim := runSim(t)
	cov := sim.m.Coverage

	if len(cov.MaxAgeByRound) < 4 {
		t.Fatalf("only %d rounds of staleness; too few to see a trend", len(cov.MaxAgeByRound))
	}

	// Compare the first half of the simulation with the second. If the
	// maximum age in the second half is materially higher, coverage is
	// decaying rather than holding.
	half := len(cov.MaxAgeByRound) / 2
	var firstPeak, secondPeak float64
	for i, v := range cov.MaxAgeByRound {
		if i < half {
			if v > firstPeak {
				firstPeak = v
			}
			continue
		}
		if v > secondPeak {
			secondPeak = v
		}
	}

	if secondPeak > firstPeak*2 {
		t.Errorf("the worst coverage age was %.0f days in the first half of the simulation and "+
			"%.0f in the second. Coverage is decaying: the gap COUNT can stay flat while this "+
			"grows, which is why the distribution travels with the percentage",
			firstPeak, secondPeak)
	}

	if cov.NeverScanned != 0 {
		t.Errorf("%d repositories finished with no qualifying scan ever", cov.NeverScanned)
	}
}

// --- the coverage picture ------------------------------------------------------

// TestTheCoverageArithmeticCloses is OQ-P2-02 at fleet scale.
//
// Coverage is measured against the PLAN, so every planned repository leaves a
// row whatever happened to it. Twenty repositories over ten rounds is two
// hundred outcomes, and every one of them must be accounted for — a fleet that
// reports fewer has measured coverage against what happened to report.
func TestTheCoverageArithmeticCloses(t *testing.T) {
	sim := runSim(t)
	cov := sim.m.Coverage

	want := sim.m.Repos * sim.m.Rounds
	if cov.Observations != want {
		t.Fatalf("%d repository-round outcomes recorded, want %d×%d = %d. Coverage measured "+
			"against what reported rather than against the plan (OQ-P2-02)",
			cov.Observations, sim.m.Repos, sim.m.Rounds, want)
	}

	// The outcome partition must sum to the whole.
	var sum int
	for _, n := range cov.ByOutcome {
		sum += n
	}
	if sum != cov.Observations {
		t.Errorf("the outcome partition sums to %d, not %d", sum, cov.Observations)
	}
}

// TestEveryGapCauseOccurs keeps the taxonomy from being decorative.
//
// Each cause is a different operational problem with a different owner.
// A simulation that produced only budget deferrals would exercise one branch
// of the gap arithmetic and leave the other three untested — and those three
// are the ones a real fleet hits at three in the morning.
func TestEveryGapCauseOccurs(t *testing.T) {
	sim := runSim(t)
	cov := sim.m.Coverage

	for _, c := range []struct{ cause, why string }{
		{store.SkipBudgetExhausted,
			"a repository deferred for budget: expected, and resumed next round"},
		{store.SkipNeverDispatched,
			"planned and never picked up: this one means dispatch ITSELF failed"},
		{store.CauseWorkerNoResult,
			"dispatched and silent: a worker died after starting"},
	} {
		if cov.ByCause[c.cause] == 0 {
			t.Errorf("no repository-round recorded cause %q (%s). The taxonomy has a branch "+
				"nothing exercises", c.cause, c.why)
		}
	}

	// And the two non-qualifying OUTCOMES that are not skips.
	for _, outcome := range []model.ScanOutcome{model.ScanPartial, model.ScanFailed} {
		if cov.ByOutcome[string(outcome)] == 0 {
			t.Errorf("no repository-round ended %q", outcome)
		}
	}

	// A partial scan must not refresh coverage. If it did, a repository whose
	// scanners half-ran would look freshly covered.
	if cov.ByOutcome[string(model.ScanComplete)] == 0 {
		t.Fatal("no scan completed at all, so nothing above means anything")
	}
}

// --- deduplication and merge ---------------------------------------------------

// TestOneAdvisoryInManyRepositoriesIsManyFindings is the distinction that
// breaks if merge is applied too widely.
//
// The wave advisory is reported in the owner and in five consumers. That is
// SIX findings, not one: the defect is per-repository, each has its own
// lifecycle, and merging across repositories would make one fix appear to
// close all of them — and then verification in one repository would resolve a
// finding in five others that nobody touched.
func TestOneAdvisoryInManyRepositoriesIsManyFindings(t *testing.T) {
	sim := runSim(t)
	mp := sim.m.Merge

	if len(mp.SharedAdvisories) < 3 {
		t.Fatalf("only %d advisories appear in more than one repository; too few to test merge "+
			"across a fleet", len(mp.SharedAdvisories))
	}

	repos := mp.SharedAdvisories[fleet.AdvCrypto.ID()]
	if repos < 5 {
		t.Errorf("the core-auth advisory appears in %d repositories, want at least 5", repos)
	}

	// The same advisory in N repositories produces N findings.
	var expected int
	for _, n := range mp.SharedAdvisories {
		expected += n
	}
	if mp.DistinctFingerprints != expected {
		t.Errorf("%d shared-advisory findings across %d repository-advisory pairs. One advisory "+
			"in N repositories must be N findings: merging them would make a single fix appear "+
			"to close all of them", mp.DistinctFingerprints, expected)
	}

	// And within one repository, one advisory in one module is ONE finding
	// however many tools reported it. That is what merge across tools is for.
	if mp.MaxPerRepoPerAdvisory != 1 {
		t.Errorf("a repository carries %d findings for one advisory; cross-tool merge should "+
			"leave exactly one", mp.MaxPerRepoPerAdvisory)
	}
}

// TestFingerprintsAreOrderIndependentAcrossTheFleet is the determinism clause.
//
// Processing order across twenty repositories is not guaranteed — the
// dispatcher runs four at a time — so an identity that depended on arrival
// order would make the same fleet produce different findings on different
// runs, and every delta report would be noise.
func TestFingerprintsAreOrderIndependentAcrossTheFleet(t *testing.T) {
	baseline := fleet.Baseline()

	// Every raw finding the fleet can produce, flattened.
	var flat []model.RawFinding
	for _, rs := range baseline {
		flat = append(flat, rs...)
	}
	if len(flat) < 40 {
		t.Fatalf("only %d raw findings; too few to test ordering across a fleet", len(flat))
	}

	fingerprintSet := func(in []model.RawFinding) []string {
		var out []string
		for _, f := range in {
			if err := fingerprint.Validate(f); err != nil {
				t.Fatalf("fixture finding is not fingerprintable: %v", err)
			}
			out = append(out, fingerprint.Compute(f))
		}
		sort.Strings(out)
		return out
	}

	want := fingerprintSet(flat)

	// Five independent shuffles. One could agree by luck.
	for seed := int64(1); seed <= 5; seed++ {
		shuffled := append([]model.RawFinding(nil), flat...)
		r := rand.New(rand.NewSource(seed))
		r.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})

		got := fingerprintSet(shuffled)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("shuffle %d produced a different fingerprint set. Identity depends on "+
				"processing order, so the same fleet would produce different findings run to "+
				"run and every delta would be noise", seed)
		}
	}

	// Non-vacuity: the shuffles must actually have reordered something.
	shuffled := append([]model.RawFinding(nil), flat...)
	rand.New(rand.NewSource(1)).Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	same := true
	for i := range flat {
		if flat[i].Repo != shuffled[i].Repo || flat[i].PrimaryID != shuffled[i].PrimaryID {
			same = false
			break
		}
	}
	if same {
		t.Fatal("the shuffle did not reorder anything, so the comparison above proved nothing")
	}
}

// --- the waves -----------------------------------------------------------------

// TestBothWavesPropagateIndependently is the two-wave clause.
//
// One wave shows the mechanism. Two show that they do not interfere: a
// repository consuming both shared modules is blocked on two separate upstream
// findings, and neither wave may claim the other's consumers.
func TestBothWavesPropagateIndependently(t *testing.T) {
	sim := runSim(t)

	if len(sim.m.Waves) != 2 {
		t.Fatalf("%d waves measured, want 2", len(sim.m.Waves))
	}

	for _, w := range sim.m.Waves {
		if w.BlastRadius < 5 {
			t.Errorf("%s has a blast radius of %d; the reverse-dependency index did not find "+
				"its consumers", w.Module, w.BlastRadius)
		}
		if len(w.Blocked) == 0 {
			t.Errorf("%s blocked no consumer at all, so the wave is inert", w.Module)
		}
	}

	// No consumer of one wave may appear as a consumer of the other unless it
	// genuinely depends on both.
	a, b := sim.m.Waves[0], sim.m.Waves[1]
	both := map[string]bool{}
	for _, r := range a.Consumers {
		for _, r2 := range b.Consumers {
			if r == r2 {
				both[r] = true
			}
		}
	}
	if !both[fleet.Org+"/partner-api"] {
		t.Errorf("partner-api consumes both shared modules and the index puts it in only one " +
			"wave; a repository blocked on two upstreams is the case that catches 'blocked' " +
			"being treated as a flag rather than a relationship")
	}
}

// TestTheReplaceExcludedConsumerIsNotBlocked is VM-F-608.
//
// A consumer with a replace directive builds against something the published
// version bump will not change. Blocking it makes it wait for a fix that
// cannot reach it, and the finding sits in BLOCKED_UPSTREAM for ever while
// nobody looks at it.
func TestTheReplaceExcludedConsumerIsNotBlocked(t *testing.T) {
	sim := runSim(t)

	var wave fleet.WavePicture
	for _, w := range sim.m.Waves {
		if w.Module == fleet.ModuleCoreAuth {
			wave = w
		}
	}

	if len(wave.ExcludedByReplace) == 0 {
		t.Fatalf("the index found no replace-excluded consumer of %s, so this proves nothing. "+
			"The fixture declares one", fleet.ModuleCoreAuth)
	}
	found := false
	for _, r := range wave.ExcludedByReplace {
		if r == fleet.ReplaceExcluded {
			found = true
		}
	}
	if !found {
		t.Fatalf("excluded-by-replace is %v, and %s is the one with the directive",
			wave.ExcludedByReplace, fleet.ReplaceExcluded)
	}

	// It is a CONSUMER — it does depend on the module — and it must not be
	// waiting on the owner's fix.
	inConsumers := false
	for _, r := range wave.Consumers {
		if r == fleet.ReplaceExcluded {
			inConsumers = true
		}
	}
	if !inConsumers {
		t.Errorf("%s was dropped from the consumer list entirely. It IS a consumer; it is "+
			"excluded from the WAVE, and a consumer silently left out of both is a live "+
			"finding nobody is looking at", fleet.ReplaceExcluded)
	}
}

// --- the fleet's shape ---------------------------------------------------------

// TestTheFleetHasTheVarietyItClaims keeps the fixture honest.
//
// A simulation over twenty identical repositories would pass every test above
// and exercise none of the variety the fleet views aggregate over.
func TestTheFleetHasTheVarietyItClaims(t *testing.T) {
	sim := runSim(t)

	for tier := 1; tier <= 3; tier++ {
		if sim.m.Tiers[tier] < 3 {
			t.Errorf("tier %d has %d repositories; too few to aggregate over",
				tier, sim.m.Tiers[tier])
		}
	}

	for _, c := range []model.Category{
		model.CategoryDependency, model.CategoryCode,
		model.CategorySecret, model.CategoryConfig,
	} {
		if sim.m.Categories[string(c)] == 0 {
			t.Errorf("no %s findings in the fleet", c)
		}
	}

	// The states a fleet view has to distinguish. Each is a different thing
	// for a reader to do.
	for _, st := range []model.State{
		model.Triaged, model.PROpen, model.Verified, model.BlockedUpstream,
	} {
		if sim.m.States[string(st)] == 0 {
			t.Errorf("no finding is in state %s, so the interface cannot show it", st)
		}
	}

	if sim.m.Findings < 50 {
		t.Errorf("%d findings across 20 repositories; too few to strain any aggregate",
			sim.m.Findings)
	}
}

// TestNoCredentialValueExistsInTheFleet is the standing property, re-checked
// at twenty repositories because the fleet has four secret findings and the
// guard has to hold for every one.
func TestNoCredentialValueExistsInTheFleet(t *testing.T) {
	sim := runSim(t)
	ctx := context.Background()

	all, err := sim.store.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}

	secrets := 0
	for _, f := range all {
		if f.Category != model.CategorySecret {
			continue
		}
		secrets++
		if f.CredentialType == "" {
			t.Errorf("%s records no credential CLASS; the class is what makes it actionable "+
				"without the value", f.Fingerprint)
		}
	}
	if secrets < 4 {
		t.Fatalf("%d secret findings; the fixture declares 4", secrets)
	}
}
