package firstparty_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/firstparty"
)

// Wave propagation (§12.3, VM-F-603 to VM-F-615).

func fleetIndex(t *testing.T) *firstparty.Index {
	t.Helper()
	idx := firstparty.NewIndex(registry(t))
	for _, d := range []firstparty.Dependency{
		{Repo: "org/wanaware-api", Module: sharedModule, Version: "v1.4.0"},
		{Repo: "org/wanaware-jobs", Module: sharedModule, Version: "v1.4.0"},
		{Repo: "org/wanaware-web", Module: sharedModule, Version: "v1.4.0", Replaced: true},
		{Repo: "org/wanaware-batch", Module: sharedModule, Version: "v1.4.0"},
	} {
		idx.Add(d)
	}
	return idx
}

// --- Wave 1: one pull request, consumers blocked ----------------------------

// TestWaveOneTargetsTheOwnerAndBlocksConsumers covers VM-F-603/604/605.
func TestWaveOneTargetsTheOwnerAndBlocksConsumers(t *testing.T) {
	plan := firstparty.PlanWaveOne(fleetIndex(t), firstparty.WaveRequest{
		Module:     sharedModule,
		UpstreamFP: "a3f9c21e8b7d4056",
	})

	if plan.Owner != ownerRepo {
		t.Errorf("owner = %q, want %q (VM-F-603)", plan.Owner, ownerRepo)
	}
	// Every consumer is blocked, including the one with a replace directive:
	// its finding is real, it is simply excluded from the automated wave later.
	var blocked []string
	for _, c := range plan.Blocked {
		blocked = append(blocked, c.Repo)
	}
	sort.Strings(blocked)
	want := []string{"org/wanaware-api", "org/wanaware-batch", "org/wanaware-jobs", "org/wanaware-web"}
	if strings.Join(blocked, ",") != strings.Join(want, ",") {
		t.Errorf("blocked = %v, want %v", blocked, want)
	}
	// One upstream ticket lists them all; no consumer tickets (VM-F-605).
	if plan.ConsumerTickets {
		t.Error("Wave 1 proposes consumer tickets; a single upstream ticket lists the affected " +
			"consumers (VM-F-605), and twelve tickets for one upstream fix is how a queue becomes noise")
	}
	if plan.ConsumerPullRequests {
		t.Error("Wave 1 proposes consumer pull requests; there is nothing for them to upgrade to yet (VM-F-604)")
	}
	// The upstream reference travels with each blocked consumer, or a consumer
	// has no way to discover what it is waiting for.
	for _, c := range plan.Blocked {
		if c.UpstreamFP != "a3f9c21e8b7d4056" {
			t.Errorf("consumer %s carries upstream reference %q, want the owner's fingerprint",
				c.Repo, c.UpstreamFP)
		}
	}
}

// TestWaveOneOnAModuleNobodyConsumesIsNotAWave is the degenerate case. A
// first-party module with no consumers is an ordinary finding in the owning
// repository, and treating it as a wave would open an upstream ticket about
// nobody.
func TestWaveOneOnAModuleNobodyConsumesIsNotAWave(t *testing.T) {
	idx := firstparty.NewIndex(registry(t))
	plan := firstparty.PlanWaveOne(idx, firstparty.WaveRequest{
		Module: sharedModule, UpstreamFP: "abc",
	})
	if len(plan.Blocked) != 0 {
		t.Errorf("a module with no consumers blocked %d repositories", len(plan.Blocked))
	}
	if plan.IsWave() {
		t.Error("a module with no consumers reads as a wave; the upstream ticket would list nobody")
	}
}

// --- Wave 2: the trigger, and the replace exclusion -------------------------

// TestWaveTwoExcludesReplaceDirectives covers VM-F-608. A consumer with a
// `replace` does not resolve the module from the registry at all, so bumping
// its requirement changes nothing — and the bump would build, pass, and close
// a finding that is still live.
func TestWaveTwoExcludesReplaceDirectives(t *testing.T) {
	plan := firstparty.PlanWaveTwo(fleetIndex(t), firstparty.WaveRequest{
		Module: sharedModule, UpstreamFP: "abc", TargetVersion: "v1.5.0",
	})

	var dispatched []string
	for _, c := range plan.Dispatch {
		dispatched = append(dispatched, c.Repo)
	}
	sort.Strings(dispatched)
	want := []string{"org/wanaware-api", "org/wanaware-batch", "org/wanaware-jobs"}
	if strings.Join(dispatched, ",") != strings.Join(want, ",") {
		t.Errorf("dispatch = %v, want %v (the replaced consumer excluded)", dispatched, want)
	}

	if len(plan.Excluded) != 1 || plan.Excluded[0].Repo != "org/wanaware-web" {
		t.Fatalf("excluded = %+v, want org/wanaware-web", plan.Excluded)
	}
	// Excluded is not dropped: it is reported for manual handling, with the
	// reason. A consumer silently left out of a wave is a live finding nobody
	// is looking at.
	if plan.Excluded[0].Reason == "" {
		t.Error("the exclusion carries no reason; the consumer would be invisible")
	}
	if !strings.Contains(strings.ToLower(plan.Excluded[0].Reason), "replace") {
		t.Errorf("the exclusion reason does not name the cause: %q", plan.Excluded[0].Reason)
	}
}

// TestWaveTwoRefusesWithoutATarget is the guard on the dangerous input. A wave
// dispatched with no target version would bump every consumer to whatever the
// proxy happens to serve, which is not a remediation, it is a fleet-wide
// unreviewed upgrade.
func TestWaveTwoRefusesWithoutATarget(t *testing.T) {
	plan := firstparty.PlanWaveTwo(fleetIndex(t), firstparty.WaveRequest{
		Module: sharedModule, UpstreamFP: "abc",
	})
	if len(plan.Dispatch) != 0 {
		t.Errorf("a wave with no target version dispatched %d consumers; they would be bumped to "+
			"whatever the proxy served, which is a fleet-wide unreviewed upgrade", len(plan.Dispatch))
	}
	if plan.Refusal == "" {
		t.Error("the refusal is silent")
	}
}

// TestWaveTwoSplitsADivergedFleet covers VM-F-613 at dispatch. Half a wave of
// failed builds is the failure the spread check exists to prevent.
func TestWaveTwoSplitsADivergedFleet(t *testing.T) {
	idx := firstparty.NewIndex(registry(t))
	idx.Add(firstparty.Dependency{Repo: "org/current-a", Module: sharedModule, Version: "v1.4.0"})
	idx.Add(firstparty.Dependency{Repo: "org/current-b", Module: sharedModule, Version: "v1.4.0"})
	idx.Add(firstparty.Dependency{Repo: "org/behind", Module: sharedModule, Version: "v0.9.0"})

	plan := firstparty.PlanWaveTwo(idx, firstparty.WaveRequest{
		Module: sharedModule, UpstreamFP: "abc", TargetVersion: "v1.5.0",
	})

	if !plan.Split {
		t.Fatal("a diverged fleet was dispatched as one wave; the laggard would fail to build and " +
			"nobody would know until half the wave was red (VM-F-613)")
	}
	// The consumers that can be advanced still are: a split defers the
	// laggards, it does not stop the wave.
	var dispatched []string
	for _, c := range plan.Dispatch {
		dispatched = append(dispatched, c.Repo)
	}
	sort.Strings(dispatched)
	if strings.Join(dispatched, ",") != "org/current-a,org/current-b" {
		t.Errorf("dispatch = %v, want the two current consumers", dispatched)
	}
	if len(plan.Deferred) != 1 || plan.Deferred[0].Repo != "org/behind" {
		t.Errorf("deferred = %+v, want org/behind", plan.Deferred)
	}
	if plan.Deferred[0].Reason == "" {
		t.Error("a deferred consumer carries no reason; it would look like an omission")
	}
}

// --- Determinism under permutation ------------------------------------------

// TestWavePlanningIsDeterministicUnderReorderedTraversal is the property this
// build has asserted at every fold: the cross-source merge, the fan-out
// traversal, the fix grouping. A plan that depended on the order dependencies
// happened to be indexed in would dispatch a different wave on every run, and
// the difference would look like fleet churn rather than a bug.
func TestWavePlanningIsDeterministicUnderReorderedTraversal(t *testing.T) {
	deps := []firstparty.Dependency{
		{Repo: "org/e", Module: sharedModule, Version: "v1.4.0"},
		{Repo: "org/a", Module: sharedModule, Version: "v1.4.0"},
		{Repo: "org/d", Module: sharedModule, Version: "v1.4.0", Replaced: true},
		{Repo: "org/c", Module: sharedModule, Version: "v1.1.0"},
		{Repo: "org/b", Module: sharedModule, Version: "v1.4.0"},
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
	// Every rotation of the input, which is enough to catch an
	// order-dependent fold without a permutation library.
	for shift := 0; shift < len(deps); shift++ {
		idx := firstparty.NewIndex(registry(t))
		for i := range deps {
			idx.Add(deps[(i+shift)%len(deps)])
		}
		got := render(firstparty.PlanWaveTwo(idx, firstparty.WaveRequest{
			Module: sharedModule, UpstreamFP: "abc", TargetVersion: "v1.5.0",
		}))
		if shift == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("rotation %d produced a different wave:\n got %s\nwant %s", shift, got, first)
		}
	}
}

// --- Cyclic first-party graphs ----------------------------------------------

// TestMutualConsumersTerminateAndDoNotDoubleCount is the termination clause.
//
// Two first-party modules that consume each other is not pathological: a
// `common` that imports `telemetry` for its own metrics while `telemetry`
// imports `common` for its config types is an ordinary, if regrettable, shape.
// A naive propagation walks it for ever, and one that visits a repository
// twice reports a blast radius larger than the fleet.
func TestMutualConsumersTerminateAndDoNotDoubleCount(t *testing.T) {
	idx := firstparty.NewIndex(registry(t))
	// common <-> telemetry, each a consumer of the other.
	idx.Add(firstparty.Dependency{Repo: "org/wanaware-common", Module: "github.com/wanaware/telemetry", Version: "v1.0.0"})
	idx.Add(firstparty.Dependency{Repo: "org/wanaware-telemetry", Module: sharedModule, Version: "v1.4.0"})
	// And an ordinary consumer of each.
	idx.Add(firstparty.Dependency{Repo: "org/app", Module: sharedModule, Version: "v1.4.0"})
	idx.Add(firstparty.Dependency{Repo: "org/app", Module: "github.com/wanaware/telemetry", Version: "v1.0.0"})

	done := make(chan firstparty.Propagation, 1)
	go func() {
		done <- idx.Propagate(sharedModule)
	}()

	var prop firstparty.Propagation
	select {
	case prop = <-done:
	case <-timeout():
		t.Fatal("propagation did not terminate on a cyclic first-party graph")
	}

	seen := map[string]int{}
	for _, r := range prop.Repos {
		seen[r]++
	}
	for repo, n := range seen {
		if n > 1 {
			t.Errorf("%s appears %d times in the propagation; a blast radius that counts a repository "+
				"twice can exceed the size of the fleet", repo, n)
		}
	}
	// The cycle is reported rather than silently absorbed: a mutual first-party
	// dependency is an architectural fact someone should know about, and a
	// propagation that quietly handled it would never surface it.
	if !prop.Cyclic {
		t.Error("the propagation did not report the cycle it walked through")
	}
	if len(prop.Cycles) == 0 {
		t.Error("the cycle is reported but not named; nobody can act on it")
	}
}

func timeout() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		// Deliberately short: a correct propagation over four dependencies is
		// instant, and anything slower is not slow, it is looping.
		defer close(ch)
		sleep()
	}()
	return ch
}

// --- Blast radius honesty (VM-F-610, VM-F-611) ------------------------------

// TestBlastRadiusReportsDependAndReachSeparately is the honesty clause, and
// the specification is unusually direct about why: reporting one number for
// both overstates the incident and burns credibility.
//
// A repository that imports a shared module but never calls the vulnerable
// path carries a real dependency and negligible risk. Counting it as exposed
// turns a two-repository incident into a twenty-repository one, and the next
// time a real twenty-repository incident arrives nobody believes the number.
func TestBlastRadiusReportsDependAndReachSeparately(t *testing.T) {
	idx := fleetIndex(t)

	radius := idx.BlastRadius(sharedModule, map[string]string{
		"org/wanaware-api":   "true",
		"org/wanaware-jobs":  "false",
		"org/wanaware-web":   "unknown",
		"org/wanaware-batch": "false",
	})

	if radius.Depend != 4 {
		t.Errorf("depend = %d, want 4", radius.Depend)
	}
	if radius.Reach != 1 {
		t.Errorf("reach = %d, want 1 — only the consumer that actually executes the vulnerable path "+
			"(VM-F-611)", radius.Reach)
	}
	// "unknown" is its own figure, never folded into either. Folding it into
	// reach overstates; folding it into not-reached understates and is the more
	// dangerous of the two (VM-F-243).
	if radius.Unknown != 1 {
		t.Errorf("unknown = %d, want 1", radius.Unknown)
	}
	if radius.Reach+radius.NotReached+radius.Unknown != radius.Depend {
		t.Errorf("the three reachability figures (%d + %d + %d) do not account for all %d dependents",
			radius.Reach, radius.NotReached, radius.Unknown, radius.Depend)
	}

	// The rendered summary must not present one number as the radius.
	summary := radius.Summary()
	for _, want := range []string{"4", "1", "depend", "reach"} {
		if !strings.Contains(strings.ToLower(summary), want) {
			t.Errorf("the summary omits %q: %s", want, summary)
		}
	}
	if !strings.Contains(strings.ToLower(summary), "unknown") {
		t.Errorf("the summary hides the unknown reachability: %s", summary)
	}
}

// TestReachabilityIsNeverInheritedFromUpstream covers VM-F-610 directly. The
// upstream finding's own reachability says whether the OWNER executes the
// vulnerable path. It says nothing about any consumer, and inheriting it is
// the specific mistake that produces the overstated number.
func TestReachabilityIsNeverInheritedFromUpstream(t *testing.T) {
	idx := fleetIndex(t)

	// The upstream finding is reachable in the owning repository. No consumer
	// reachability has been determined yet.
	radius := idx.BlastRadius(sharedModule, nil)

	if radius.Reach != 0 {
		t.Errorf("reach = %d with no per-consumer determination; the upstream verdict was inherited, "+
			"which is exactly what VM-F-610 forbids", radius.Reach)
	}
	if radius.Unknown != radius.Depend {
		t.Errorf("unknown = %d of %d dependents; an undetermined consumer is UNKNOWN, not reachable "+
			"and not unreachable", radius.Unknown, radius.Depend)
	}
	if strings.Contains(strings.ToLower(radius.Summary()), "0 reach") &&
		!strings.Contains(strings.ToLower(radius.Summary()), "unknown") {
		t.Error("the summary reads as though nothing is exposed when the truth is that nobody has looked")
	}
}

// TestPropagationIsCorrectOnADiamond covers the shape a real fleet has:
// internal modules that share consumers, so the same repository is reachable
// by several paths.
//
// It asserts CORRECTNESS on that shape — every repository once, whatever the
// path count — and deliberately does not claim to prove the memoisation that
// bounds the work. Correctness here comes from the repository deduplication
// and the back-edge detection, both of which have mutations that turn this
// file red. The memoisation prevents exponential re-walking, and at a layer
// count small enough to keep this test fast the difference is not measurable:
// see OQ-P11-02 rather than a threshold tuned until it happened to fail.
func TestPropagationIsCorrectOnADiamond(t *testing.T) {
	const layers = 22

	var modules []string
	var b strings.Builder
	b.WriteString("version: 1\nmodules:\n")
	for i := 0; i < layers; i++ {
		m := "github.com/wanaware/m" + itoa(i)
		modules = append(modules, m)
		b.WriteString("  " + m + ": org/r" + itoa(i) + "\n")
	}
	reg, err := firstparty.ParseRegistry([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseRegistry: %v", err)
	}

	idx := firstparty.NewIndex(reg)
	// Each layer's owner consumes the next two modules: a Fibonacci-shaped
	// DAG, which is the cheapest way to get exponential path count from a
	// linear number of edges.
	for i := 0; i < layers; i++ {
		for _, next := range []int{i + 1, i + 2} {
			if next < layers {
				idx.Add(firstparty.Dependency{
					Repo: "org/r" + itoa(i), Module: modules[next], Version: "v1.0.0",
				})
			}
		}
	}

	done := make(chan firstparty.Propagation, 1)
	go func() { done <- idx.Propagate(modules[layers-1]) }()

	select {
	case prop := <-done:
		// Every repository at most once, whatever the path count.
		seen := map[string]bool{}
		for _, r := range prop.Repos {
			if seen[r] {
				t.Errorf("%s appears more than once", r)
			}
			seen[r] = true
		}
	case <-timeout():
		t.Fatalf("propagation over %d layers did not finish", layers)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
