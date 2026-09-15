package score_test

import (
	"fmt"
	"math"
	"math/rand"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/score"
)

const calPath = "../../config/calibration.yaml"

func cal(t *testing.T) score.Calibration {
	t.Helper()
	c, err := score.LoadCalibration(calPath)
	if err != nil {
		t.Fatalf("loading calibration: %v", err)
	}
	return c
}

func scorer(t *testing.T) *score.Scorer { return score.New(cal(t)) }

func dep(sev model.Severity, reach model.Reachable) score.Input {
	return score.Input{
		Category: model.CategoryDependency, Severity: sev, Reachable: reach,
		DepClass: model.DepProduction, Tier: 2,
	}
}

// --- Gate: reachability is consumed as a tri-state (VM-F-243) --------------

// TestUnknownReachabilityIsItsOwnCase is the gate's central scoring clause.
// Unknown must be neither of the determinations: collapsing it to true lets
// transitive advisories dominate the P0 queue, and collapsing it to false hides
// real risk behind a tool's silence.
func TestUnknownReachabilityIsItsOwnCase(t *testing.T) {
	s := scorer(t)

	tr := s.Score(dep(model.SeverityHigh, model.ReachableTrue))
	un := s.Score(dep(model.SeverityHigh, model.ReachableUnknown))
	fa := s.Score(dep(model.SeverityHigh, model.ReachableFalse))

	if !(tr.Score > un.Score && un.Score > fa.Score) {
		t.Fatalf("unknown did not land strictly between the determinations: true=%.3f unknown=%.3f false=%.3f",
			tr.Score, un.Score, fa.Score)
	}
	if un.Score == tr.Score {
		t.Error("unknown scores identically to reachable=true; the tri-state has collapsed upward")
	}
	if un.Score == fa.Score {
		t.Error("unknown scores identically to reachable=false; the tri-state has collapsed downward")
	}

	// And the multiplier is a distinct, named value rather than an accident of
	// arithmetic.
	if un.ReachMultiplier == tr.ReachMultiplier || un.ReachMultiplier == fa.ReachMultiplier {
		t.Errorf("unknown shares a multiplier: true=%.2f unknown=%.2f false=%.2f",
			tr.ReachMultiplier, un.ReachMultiplier, fa.ReachMultiplier)
	}
}

// TestInvalidReachabilityIsTreatedAsUnknownNotAsADetermination covers the
// boundary: an absent or malformed value must not become a claim.
func TestInvalidReachabilityIsTreatedAsUnknownNotAsADetermination(t *testing.T) {
	s := scorer(t)
	un := s.Score(dep(model.SeverityHigh, model.ReachableUnknown))

	for _, bad := range []model.Reachable{"", "yes", "TRUE", "maybe"} {
		got := s.Score(dep(model.SeverityHigh, bad))
		if got.Score != un.Score {
			t.Errorf("reachable=%q scored %.3f, want the unknown score %.3f — an invalid value must not become a determination",
				bad, got.Score, un.Score)
		}
		// And the substitution must be visible, not silent.
		var explained bool
		for _, line := range got.Explain {
			if contains(line, "not a valid tri-state") {
				explained = true
			}
		}
		if !explained {
			t.Errorf("reachable=%q was substituted silently; the derivation must record it", bad)
		}
	}
}

// TestScoreIsMonotonicInReachability sweeps the whole input space rather than
// checking one example.
func TestScoreIsMonotonicInReachability(t *testing.T) {
	s := scorer(t)
	order := []model.Reachable{model.ReachableFalse, model.ReachableUnknown, model.ReachableTrue}

	for _, sev := range model.AllSeverities {
		for _, tier := range []int{1, 2, 3} {
			for _, dc := range []model.DepClass{model.DepProduction, model.DepDevelopment} {
				for _, kev := range []bool{false, true} {
					prev := -1.0
					for _, reach := range order {
						in := score.Input{
							Category: model.CategoryDependency, Severity: sev,
							Reachable: reach, DepClass: dc, Tier: tier, KEV: kev,
						}
						got := s.Score(in).Score
						if got < prev-1e-9 {
							t.Fatalf("score decreased as reachability strengthened: sev=%s tier=%d dep=%s kev=%v reach=%s gave %.4f after %.4f",
								sev, tier, dc, kev, reach, got, prev)
						}
						prev = got
					}
				}
			}
		}
	}
}

// TestScoreIsMonotonicInSeverity covers the other required monotonicity.
func TestScoreIsMonotonicInSeverity(t *testing.T) {
	s := scorer(t)
	// Ascending severity, excluding UNKNOWN which is an absence rather than a
	// point on the scale.
	ascending := []model.Severity{model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical}

	for _, reach := range model.AllReachable {
		for _, tier := range []int{1, 2, 3} {
			prev := -1.0
			for _, sev := range ascending {
				got := s.Score(score.Input{
					Category: model.CategoryDependency, Severity: sev,
					Reachable: reach, DepClass: model.DepProduction, Tier: tier,
				}).Score
				if got < prev-1e-9 {
					t.Fatalf("score decreased as severity rose: reach=%s tier=%d sev=%s gave %.4f after %.4f",
						reach, tier, sev, got, prev)
				}
				prev = got
			}
		}
	}
}

// TestUnknownSeverityIsNotTreatedAsHarmless covers the calibration choice: a
// finding whose severity nobody stated is not thereby safe.
func TestUnknownSeverityIsNotTreatedAsHarmless(t *testing.T) {
	s := scorer(t)
	unknown := s.Score(dep(model.SeverityUnknown, model.ReachableTrue))
	low := s.Score(dep(model.SeverityLow, model.ReachableTrue))

	if unknown.Score <= low.Score {
		t.Errorf("UNKNOWN severity scored %.3f, at or below LOW's %.3f; an unstated severity would rank below every scored finding and be hidden",
			unknown.Score, low.Score)
	}
	if unknown.Score == 0 {
		t.Error("UNKNOWN severity scored zero; a finding nobody scored is not harmless")
	}
}

// --- Determinism ------------------------------------------------------------

func TestScoringIsDeterministic(t *testing.T) {
	s := scorer(t)
	in := score.Input{
		Category: model.CategoryDependency, Severity: model.SeverityHigh,
		CVSS: 7.5, EPSS: 0.0421, KEV: true,
		Reachable: model.ReachableTrue, DepClass: model.DepProduction, Tier: 1,
	}
	want := s.Score(in)
	for i := 0; i < 500; i++ {
		got := s.Score(in)
		if got.Score != want.Score || got.Priority != want.Priority {
			t.Fatalf("scoring is not deterministic: %.6f/%s then %.6f/%s",
				want.Score, want.Priority, got.Score, got.Priority)
		}
	}
}

// --- Secret override (VM-F-407, VM-F-851) ----------------------------------

// TestSecretAlwaysScoresMaximumAndIsNotOverridable covers the one case no
// combination of multipliers may reduce.
func TestSecretAlwaysScoresMaximumAndIsNotOverridable(t *testing.T) {
	s := scorer(t)

	// Every combination that would otherwise push a finding to the bottom.
	for _, reach := range model.AllReachable {
		for _, tier := range []int{1, 2, 3, 0, 99} {
			for _, dc := range []model.DepClass{model.DepProduction, model.DepDevelopment, model.DepNotApplicable} {
				for _, sev := range model.AllSeverities {
					got := s.Score(score.Input{
						Category: model.CategorySecret, Severity: sev,
						Reachable: reach, DepClass: dc, Tier: tier,
					})
					if got.Priority != model.P0 {
						t.Fatalf("secret scored %s with sev=%s reach=%s tier=%d dep=%s; secrets are fixed at P0 and not overridable (VM-F-407)",
							got.Priority, sev, reach, tier, dc)
					}
					if got.Score != score.MaxScore {
						t.Fatalf("secret scored %.2f, want the fixed maximum %.2f", got.Score, score.MaxScore)
					}
					if !got.SecretOverride {
						t.Error("secret score did not record that it bypassed the formula")
					}
				}
			}
		}
	}
}

// TestSecretOverrideSurvivesACalibrationThatWouldSuppressIt proves the override
// is in code, not in configuration: a calibration crafted to zero out every
// multiplier still cannot demote a secret.
func TestSecretOverrideSurvivesACalibrationThatWouldSuppressIt(t *testing.T) {
	c := cal(t)
	// Deliberately hostile calibration.
	c.Scoring.SeverityBase = map[string]float64{
		"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0,
	}
	c.Scoring.Reachable = map[string]float64{"true": 0.03, "unknown": 0.02, "false": 0.01}
	c.Scoring.DepClass = map[string]float64{"production": 0, "development": 0, "n/a": 0}
	c.Scoring.Tier = map[int]float64{1: 0, 2: 0, 3: 0}

	s := score.New(c)
	got := s.Score(score.Input{Category: model.CategorySecret, Severity: model.SeverityLow, Tier: 3})
	if got.Priority != model.P0 || got.Score != score.MaxScore {
		t.Errorf("a hostile calibration demoted a secret to %s/%.2f; the override must be enforced in code (VM-F-407)",
			got.Priority, got.Score)
	}
}

// --- Priority bands are pinned ---------------------------------------------

// TestPriorityBandBoundaries pins each boundary exactly. A band that drifts
// silently re-prioritises the whole fleet, so each edge is asserted on both
// sides.
func TestPriorityBandBoundaries(t *testing.T) {
	c := cal(t)
	s := score.New(c)

	bands := []struct {
		name string
		at   float64
		want model.Priority
	}{
		{"P0", c.Scoring.PriorityBands["P0"], model.P0},
		{"P1", c.Scoring.PriorityBands["P1"], model.P1},
		{"P2", c.Scoring.PriorityBands["P2"], model.P2},
	}

	// Drive the score directly through a neutral input: base carries the value,
	// every multiplier is 1.
	scoreAt := func(v float64) model.Priority {
		return s.Score(score.Input{
			Category: model.CategoryDependency, CVSS: v,
			Reachable: model.ReachableTrue, DepClass: model.DepNotApplicable, Tier: 2,
		}).Priority
	}

	for _, b := range bands {
		if got := scoreAt(b.at); got != b.want {
			t.Errorf("score exactly at the %s boundary (%.2f) gave %s, want %s — bands are inclusive at the lower edge",
				b.name, b.at, got, b.want)
		}
		if got := scoreAt(b.at - 0.01); got == b.want {
			t.Errorf("score just below the %s boundary (%.2f) still gave %s; the band is not closed",
				b.name, b.at-0.01, got)
		}
	}

	// And below the lowest band.
	if got := scoreAt(c.Scoring.PriorityBands["P2"] - 0.01); got != model.P3 {
		t.Errorf("score below P2 gave %s, want P3", got)
	}
}

// --- Calibration is data, and validated ------------------------------------

func TestCalibrationRefusesToCollapseTheTriState(t *testing.T) {
	base := `version: 1
scoring:
  severity_base: {CRITICAL: 9.5, HIGH: 7.5, MEDIUM: 5.0, LOW: 2.5, UNKNOWN: 4.0}
  kev_boost: 3.0
  epss_coefficient: 2.0
  reachable: {"true": %s, "unknown": %s, "false": %s}
  dep_class: {production: 1.0, development: 0.4, "n/a": 1.0}
  tier: {1: 1.2, 2: 1.0, 3: 0.8}
  priority_bands: {P0: 9.0, P1: 7.0, P2: 4.0}
fanout: {enabled: false, per_tier1_reach_consumer: 0.0, per_reach_consumer: 0.0, max_multiplier: 1.5}
static_analysis:
  calibrated: false
  tiers:
    3: {gosec_severity: high, gosec_confidence: high, staticcheck_exclude: []}
routing: {escalate_at: P0, auto_remediate_at: P2, ticket_below: P2}
`
	tests := []struct {
		name        string
		t, u, f     string
		wantRefused bool
	}{
		{"strictly ordered", "1.0", "0.5", "0.25", false},
		{"unknown equals true", "1.0", "1.0", "0.25", true},
		{"unknown equals false", "1.0", "0.25", "0.25", true},
		{"all equal", "1.0", "1.0", "1.0", true},
		{"inverted", "0.25", "0.5", "1.0", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := score.ParseCalibration([]byte(fmt.Sprintf(base, tc.t, tc.u, tc.f)))
			if tc.wantRefused && err == nil {
				t.Error("a calibration that collapses the tri-state was accepted (VM-F-243)")
			}
			if !tc.wantRefused && err != nil {
				t.Errorf("a valid calibration was refused: %v", err)
			}
		})
	}
}

func TestCalibrationRejectsMissingValues(t *testing.T) {
	// A severity with no base silently scores zero, which makes a critical
	// finding P3 — so the file must refuse to load rather than default.
	bad := `version: 1
scoring:
  severity_base: {CRITICAL: 9.5, HIGH: 7.5}
  kev_boost: 3.0
  epss_coefficient: 2.0
  reachable: {"true": 1.0, "unknown": 0.5, "false": 0.25}
  dep_class: {production: 1.0, development: 0.4, "n/a": 1.0}
  tier: {1: 1.2, 2: 1.0, 3: 0.8}
  priority_bands: {P0: 9.0, P1: 7.0, P2: 4.0}
fanout: {enabled: false, per_tier1_reach_consumer: 0.0, per_reach_consumer: 0.0, max_multiplier: 1.5}
static_analysis: {calibrated: false, tiers: {3: {gosec_severity: high, gosec_confidence: high, staticcheck_exclude: []}}}
routing: {escalate_at: P0, auto_remediate_at: P2, ticket_below: P2}
`
	if _, err := score.ParseCalibration([]byte(bad)); err == nil {
		t.Error("a calibration missing severity bases was accepted; the missing ones would silently score zero")
	}
}

func TestCalibrationRejectsUnknownKeys(t *testing.T) {
	bad := `version: 1
typoed_section: {}
scoring:
  severity_base: {CRITICAL: 9.5, HIGH: 7.5, MEDIUM: 5.0, LOW: 2.5, UNKNOWN: 4.0}
  kev_boost: 3.0
  epss_coefficient: 2.0
  reachable: {"true": 1.0, "unknown": 0.5, "false": 0.25}
  dep_class: {production: 1.0, development: 0.4, "n/a": 1.0}
  tier: {1: 1.2, 2: 1.0, 3: 0.8}
  priority_bands: {P0: 9.0, P1: 7.0, P2: 4.0}
fanout: {enabled: false, per_tier1_reach_consumer: 0.0, per_reach_consumer: 0.0, max_multiplier: 1.5}
static_analysis: {calibrated: false, tiers: {3: {gosec_severity: high, gosec_confidence: high, staticcheck_exclude: []}}}
routing: {escalate_at: P0, auto_remediate_at: P2, ticket_below: P2}
`
	if _, err := score.ParseCalibration([]byte(bad)); err == nil {
		t.Error("an unknown key was accepted; a typo in a calibration file must not read as a silent default")
	}
}

// TestShippedCalibrationPinsItsValues is the "not magic numbers" clause: the
// shipped values are asserted here, so changing one without re-justifying it
// fails the build.
func TestShippedCalibrationPinsItsValues(t *testing.T) {
	c := cal(t)

	checks := []struct {
		name      string
		got, want float64
	}{
		{"kev_boost", c.Scoring.KEVBoost, 3.0},
		{"epss_coefficient", c.Scoring.EPSSCoefficient, 2.0},
		{"reach true", c.Scoring.Reachable["true"], 1.0},
		{"reach unknown", c.Scoring.Reachable["unknown"], 0.5},
		{"reach false", c.Scoring.Reachable["false"], 0.25},
		{"dep production", c.Scoring.DepClass["production"], 1.0},
		{"dep development", c.Scoring.DepClass["development"], 0.4},
		{"tier 1", c.Scoring.Tier[1], 1.2},
		{"tier 2", c.Scoring.Tier[2], 1.0},
		{"tier 3", c.Scoring.Tier[3], 0.8},
		{"band P0", c.Scoring.PriorityBands["P0"], 9.0},
		{"band P1", c.Scoring.PriorityBands["P1"], 7.0},
		{"band P2", c.Scoring.PriorityBands["P2"], 4.0},
	}
	for _, ch := range checks {
		if math.Abs(ch.got-ch.want) > 1e-9 {
			t.Errorf("%s = %v, want %v (VM-AD §9.4). If this change is intended, update the test and say why.",
				ch.name, ch.got, ch.want)
		}
	}

	// Fan-out ships disabled: the weighting is VM-OQ-12's to decide.
	if c.FanOut.Enabled {
		t.Error("fan-out scoring ships enabled; the weighting is still VM-OQ-12 and a guessed multiplier reorders the P0 queue on an unreviewed opinion")
	}
	// Static analysis thresholds ship uncalibrated, and say so.
	if c.StaticAnalysis.Calibrated {
		t.Error("static_analysis.calibrated is true but VM-OQ-06 has not been answered")
	}
}

// TestStaticAnalysisThresholdsPerTier covers VM-F-224 and the VM-OQ-06 surface.
func TestStaticAnalysisThresholdsPerTier(t *testing.T) {
	c := cal(t)

	sev1, conf1, _ := c.StaticAnalysisFor(1)
	sev3, conf3, excl3 := c.StaticAnalysisFor(3)

	if sev1 != "medium" || conf1 != "medium" {
		t.Errorf("tier 1 thresholds = %s/%s, want medium/medium (VM-AD §8.2 default)", sev1, conf1)
	}
	if sev3 != "high" || conf3 != "high" {
		t.Errorf("tier 3 thresholds = %s/%s, want high/high", sev3, conf3)
	}
	if len(excl3) == 0 {
		t.Error("tier 3 excludes no checks; the tier distinction is not expressed")
	}

	// An unclassified repository must not get the most permissive treatment by
	// accident while VM-OQ-01 is open.
	sevX, confX, _ := c.StaticAnalysisFor(0)
	if sevX != sev3 || confX != conf3 {
		t.Errorf("unknown tier got %s/%s, want the tier-3 bar %s/%s", sevX, confX, sev3, conf3)
	}
}

// --- Gate: fan-out is deterministic and terminates -------------------------

// graph builds a first-party consumer graph.
//
//	common  <- api (t1, reachable), web (t2, unknown), batch (t3, false)
//	shared  <- api (t1, reachable)
//	api owns nothing; web owns "widgets"; widgets <- reports (t1, reachable)
func graph() *score.Graph {
	g := score.NewGraph()
	g.Add("common", score.Consumer{Repo: "org/api", Tier: 1, Reachable: model.ReachableTrue})
	g.Add("common", score.Consumer{Repo: "org/web", Tier: 2, Reachable: model.ReachableUnknown, OwnsModules: []string{"widgets"}})
	g.Add("common", score.Consumer{Repo: "org/batch", Tier: 3, Reachable: model.ReachableFalse})
	g.Add("widgets", score.Consumer{Repo: "org/reports", Tier: 1, Reachable: model.ReachableTrue})
	return g
}

func TestBlastRadiusSeparatesDependFromReach(t *testing.T) {
	f := graph().BlastRadius("common")

	// Four repositories consume it transitively; two execute the vulnerable
	// path. Reporting the dependency count as the impact figure would inflate
	// the incident twofold (VM-ADR-13).
	if f.DependCount != 4 {
		t.Errorf("depend_count=%d, want 4", f.DependCount)
	}
	if f.ReachCount != 2 {
		t.Errorf("reach_count=%d, want 2", f.ReachCount)
	}
	if f.Tier1ReachCount != 2 {
		t.Errorf("tier1_reach_count=%d, want 2", f.Tier1ReachCount)
	}
	// The undetermined consumer is counted separately: the tri-state survives
	// aggregation rather than being folded into either answer.
	if f.UnknownReachCount != 1 {
		t.Errorf("unknown_reach_count=%d, want 1", f.UnknownReachCount)
	}
	if f.DependCount == f.ReachCount {
		t.Error("depend and reach counts are identical; they must be reported separately (VM-ADR-13)")
	}
}

// TestBlastRadiusIsDeterministicUnderTraversalPermutation is the gate clause.
// The answer must be a function of the graph, never of insertion or iteration
// order.
func TestBlastRadiusIsDeterministicUnderTraversalPermutation(t *testing.T) {
	consumers := []score.Consumer{
		{Repo: "org/api", Tier: 1, Reachable: model.ReachableTrue},
		{Repo: "org/web", Tier: 2, Reachable: model.ReachableUnknown, OwnsModules: []string{"widgets"}},
		{Repo: "org/batch", Tier: 3, Reachable: model.ReachableFalse},
		{Repo: "org/edge", Tier: 1, Reachable: model.ReachableTrue, OwnsModules: []string{"shared"}},
	}
	deeper := []score.Consumer{
		{Repo: "org/reports", Tier: 1, Reachable: model.ReachableTrue},
		{Repo: "org/jobs", Tier: 2, Reachable: model.ReachableTrue},
	}

	var want string
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 200; i++ {
		rng.Shuffle(len(consumers), func(a, b int) { consumers[a], consumers[b] = consumers[b], consumers[a] })
		rng.Shuffle(len(deeper), func(a, b int) { deeper[a], deeper[b] = deeper[b], deeper[a] })

		g := score.NewGraph()
		for _, c := range consumers {
			g.Add("common", c)
		}
		for _, c := range deeper {
			g.Add("widgets", c)
			g.Add("shared", c)
		}

		got := fmt.Sprint(g.BlastRadius("common"))
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("blast radius depends on traversal order:\n got  %s\n want %s", got, want)
		}
	}
}

// TestBlastRadiusTerminatesOnCycles is the other gate clause.
//
// Two shared modules whose owning repositories consume each other is a normal
// arrangement, not a pathology. A naive walk recurses for ever.
func TestBlastRadiusTerminatesOnCycles(t *testing.T) {
	t.Run("mutual consumers", func(t *testing.T) {
		g := score.NewGraph()
		// common <- repo-a, which owns shared; shared <- repo-b, which owns common.
		g.Add("common", score.Consumer{Repo: "org/a", Tier: 1, Reachable: model.ReachableTrue, OwnsModules: []string{"shared"}})
		g.Add("shared", score.Consumer{Repo: "org/b", Tier: 2, Reachable: model.ReachableTrue, OwnsModules: []string{"common"}})

		f := g.BlastRadius("common")
		if f.DependCount != 2 {
			t.Errorf("depend_count=%d, want 2 — each repository counted once", f.DependCount)
		}
		if f.Truncated {
			t.Error("a two-node cycle hit the depth ceiling; the visited set is not doing its job")
		}
	})

	t.Run("self-consuming module", func(t *testing.T) {
		g := score.NewGraph()
		g.Add("common", score.Consumer{Repo: "org/self", Tier: 1, Reachable: model.ReachableTrue, OwnsModules: []string{"common"}})
		f := g.BlastRadius("common")
		if f.DependCount != 1 {
			t.Errorf("depend_count=%d, want 1", f.DependCount)
		}
	})

	t.Run("long cycle", func(t *testing.T) {
		g := score.NewGraph()
		const n = 50
		for i := 0; i < n; i++ {
			m := fmt.Sprintf("mod-%02d", i)
			next := fmt.Sprintf("mod-%02d", (i+1)%n)
			g.Add(m, score.Consumer{
				Repo: fmt.Sprintf("org/repo-%02d", i), Tier: 2,
				Reachable: model.ReachableTrue, OwnsModules: []string{next},
			})
		}
		f := g.BlastRadius("mod-00")
		// Every repository exactly once, however tangled the ring.
		if f.DependCount != n {
			t.Errorf("depend_count=%d, want %d", f.DependCount, n)
		}
	})
}

// TestBlastRadiusDoesNotDoubleCount covers the diamond: a repository reachable
// by several paths is one repository.
func TestBlastRadiusDoesNotDoubleCount(t *testing.T) {
	g := score.NewGraph()
	// common is consumed by two repositories, each of which owns a module that
	// the same downstream repository consumes.
	g.Add("common", score.Consumer{Repo: "org/left", Tier: 2, Reachable: model.ReachableTrue, OwnsModules: []string{"left-mod"}})
	g.Add("common", score.Consumer{Repo: "org/right", Tier: 2, Reachable: model.ReachableTrue, OwnsModules: []string{"right-mod"}})
	g.Add("left-mod", score.Consumer{Repo: "org/downstream", Tier: 1, Reachable: model.ReachableTrue})
	g.Add("right-mod", score.Consumer{Repo: "org/downstream", Tier: 1, Reachable: model.ReachableTrue})

	f := g.BlastRadius("common")
	if f.DependCount != 3 {
		t.Errorf("depend_count=%d, want 3 — org/downstream is reachable by two paths but is one repository", f.DependCount)
	}
	if f.ReachCount != 3 {
		t.Errorf("reach_count=%d, want 3", f.ReachCount)
	}
	if f.Tier1ReachCount != 1 {
		t.Errorf("tier1_reach_count=%d, want 1", f.Tier1ReachCount)
	}
	seen := map[string]int{}
	for _, c := range f.Consumers {
		seen[c]++
	}
	for repo, n := range seen {
		if n > 1 {
			t.Errorf("%s appears %d times in the consumer list", repo, n)
		}
	}
}

// TestReplaceDirectiveConsumerIsExcludedFromBothCounts covers VM-F-608. A
// consumer with a replace directive does not resolve the module normally, so it
// is neither exposed nor a dependant — which is a different claim from being
// unreachable.
func TestReplaceDirectiveConsumerIsExcludedFromBothCounts(t *testing.T) {
	g := score.NewGraph()
	g.Add("common", score.Consumer{Repo: "org/normal", Tier: 1, Reachable: model.ReachableTrue})
	g.Add("common", score.Consumer{Repo: "org/replaced", Tier: 1, Reachable: model.ReachableTrue, Excluded: true})

	f := g.BlastRadius("common")
	if f.DependCount != 1 {
		t.Errorf("depend_count=%d, want 1 — a replace-directive consumer is excluded (VM-F-608)", f.DependCount)
	}
	if f.ReachCount != 1 {
		t.Errorf("reach_count=%d, want 1", f.ReachCount)
	}
	if f.UnknownReachCount != 0 {
		t.Error("an excluded consumer was counted as undetermined; exclusion and uncertainty are different claims")
	}
	for _, c := range f.Consumers {
		if c == "org/replaced" {
			t.Error("an excluded consumer appears in the exposed set")
		}
	}
}

// --- Fan-out weighting is not applied by default (VM-OQ-12) ----------------

func TestFanOutIsRecordedButNotAppliedByDefault(t *testing.T) {
	s := scorer(t)
	f := graph().BlastRadius("common")

	withFanOut := s.Score(score.Input{
		Category: model.CategoryDependency, Severity: model.SeverityMedium,
		Reachable: model.ReachableTrue, DepClass: model.DepProduction, Tier: 2, FanOut: f,
	})
	without := s.Score(score.Input{
		Category: model.CategoryDependency, Severity: model.SeverityMedium,
		Reachable: model.ReachableTrue, DepClass: model.DepProduction, Tier: 2,
	})

	if withFanOut.Score != without.Score {
		t.Errorf("fan-out changed the score (%.3f vs %.3f) while the weighting is still VM-OQ-12",
			withFanOut.Score, without.Score)
	}
	// But it must be recorded, so the data to answer VM-OQ-12 accumulates.
	if withFanOut.FanOut.ReachCount != f.ReachCount {
		t.Error("the blast radius was not recorded on the result; VM-OQ-12 cannot be answered from data that was never stored")
	}
	if withFanOut.FanOutMult != 1 {
		t.Errorf("fanout_multiplier=%.2f, want 1 while disabled", withFanOut.FanOutMult)
	}
}

func TestFanOutRaisesScoreWhenEnabled(t *testing.T) {
	c := cal(t)
	c.FanOut.Enabled = true
	c.FanOut.PerTier1ReachConsumer = 0.1
	c.FanOut.PerReachConsumer = 0.05
	s := score.New(c)

	f := graph().BlastRadius("common")
	with := s.Score(score.Input{
		Category: model.CategoryDependency, Severity: model.SeverityMedium,
		Reachable: model.ReachableTrue, DepClass: model.DepProduction, Tier: 2, FanOut: f,
	})
	without := s.Score(score.Input{
		Category: model.CategoryDependency, Severity: model.SeverityMedium,
		Reachable: model.ReachableTrue, DepClass: model.DepProduction, Tier: 2,
	})
	if with.Score <= without.Score {
		t.Errorf("with fan-out enabled, a module reaching two tier-1 consumers scored %.3f, not above the isolated %.3f",
			with.Score, without.Score)
	}
	if with.FanOutMult > c.FanOut.MaxMultiplier {
		t.Errorf("fanout multiplier %.2f exceeded the ceiling %.2f", with.FanOutMult, c.FanOut.MaxMultiplier)
	}
}

func TestFanOutMultiplierIsCapped(t *testing.T) {
	c := cal(t)
	c.FanOut.Enabled = true
	c.FanOut.PerTier1ReachConsumer = 1.0
	c.FanOut.MaxMultiplier = 1.5
	s := score.New(c)

	got := s.Score(score.Input{
		Category: model.CategoryDependency, Severity: model.SeverityCritical,
		Reachable: model.ReachableTrue, DepClass: model.DepProduction, Tier: 1,
		FanOut: score.FanOut{ReachCount: 40, Tier1ReachCount: 40, DependCount: 40},
	})
	if got.FanOutMult != 1.5 {
		t.Errorf("fanout multiplier = %.2f, want the 1.5 ceiling — one widely used module must not swamp the queue", got.FanOutMult)
	}
}

// --- Derivation is auditable ------------------------------------------------

func TestScoreExplainsItself(t *testing.T) {
	s := scorer(t)
	got := s.Score(score.Input{
		Category: model.CategoryDependency, Severity: model.SeverityHigh, CVSS: 7.5,
		EPSS: 0.04, KEV: true, Reachable: model.ReachableUnknown,
		DepClass: model.DepProduction, Tier: 1,
	})
	if len(got.Explain) < 5 {
		t.Fatalf("derivation has %d steps: %v", len(got.Explain), got.Explain)
	}
	for _, want := range []string{"base=", "kev_boost=", "epss_boost=", "reach=", "tier=", "score="} {
		var found bool
		for _, line := range got.Explain {
			if contains(line, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("derivation does not account for %q: %v", want, got.Explain)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 ||
		indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
