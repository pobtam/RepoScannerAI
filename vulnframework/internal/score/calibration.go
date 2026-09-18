// Package score computes priority deterministically (VM-AD §9.4, VM-F-305).
//
// Nothing here is delegated to inference. Triage supplies narrative; priority is
// arithmetic, so that two runs over an unchanged repository produce the same
// queue and a change in ordering is always explicable.
package score

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/wanaware/vulnframework/internal/model"
)

// Calibration is every tunable number, loaded from config/calibration.yaml.
//
// They live in one file rather than as constants because they need reviewing by
// people who will not read Go, and because the Phase 5 shadow run exists to
// change them (VM-OQ-06, VM-OQ-12).
type Calibration struct {
	Version int `yaml:"version"`

	Scoring struct {
		SeverityBase    map[string]float64 `yaml:"severity_base"`
		KEVBoost        float64            `yaml:"kev_boost"`
		EPSSCoefficient float64            `yaml:"epss_coefficient"`
		Reachable       map[string]float64 `yaml:"reachable"`
		DepClass        map[string]float64 `yaml:"dep_class"`
		Tier            map[int]float64    `yaml:"tier"`
		PriorityBands   map[string]float64 `yaml:"priority_bands"`
		// FeedFreshnessDays is how old an exploitation-intelligence snapshot
		// may be before a score qualifies itself. Not a cutoff: a stale
		// answer is used and labelled, never dropped.
		FeedFreshnessDays int `yaml:"feed_freshness_days"`
	} `yaml:"scoring"`

	FanOut struct {
		Enabled               bool    `yaml:"enabled"`
		PerTier1ReachConsumer float64 `yaml:"per_tier1_reach_consumer"`
		PerReachConsumer      float64 `yaml:"per_reach_consumer"`
		MaxMultiplier         float64 `yaml:"max_multiplier"`
	} `yaml:"fanout"`

	StaticAnalysis struct {
		Calibrated bool `yaml:"calibrated"`
		Tiers      map[int]struct {
			GosecSeverity      string   `yaml:"gosec_severity"`
			GosecConfidence    string   `yaml:"gosec_confidence"`
			StaticcheckExclude []string `yaml:"staticcheck_exclude"`
		} `yaml:"tiers"`
	} `yaml:"static_analysis"`

	// SLA holds the remediation windows and whether anyone has reviewed them.
	//
	// The windows are configuration rather than constants for the same reason
	// the thresholds are: a `calibrated` flag next to a table nobody can edit
	// would attest to numbers that live in Go source (OQ-P7b-03).
	SLA struct {
		// Calibrated is false while VM-OQ-02 is unanswered. While it is false
		// every rendered breach count carries a provisional qualifier.
		Calibrated bool `yaml:"calibrated"`
		// Windows are duration strings per tier per priority.
		Windows map[int]map[string]string `yaml:"windows"`
	} `yaml:"sla"`

	Routing struct {
		EscalateAt      model.Priority `yaml:"escalate_at"`
		AutoRemediateAt model.Priority `yaml:"auto_remediate_at"`
		TicketBelow     model.Priority `yaml:"ticket_below"`
	} `yaml:"routing"`
}

// LoadCalibration reads and validates a calibration file.
func LoadCalibration(path string) (Calibration, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Calibration{}, fmt.Errorf("calibration: %w", err)
	}
	return ParseCalibration(b)
}

// ParseCalibration decodes and validates calibration data.
//
// Validation is strict because a missing multiplier does not fail loudly at
// runtime — it silently reads as zero, and a zero multiplier makes every
// affected finding P3. A calibration file that is wrong must refuse to load.
func ParseCalibration(b []byte) (Calibration, error) {
	var c Calibration
	dec := yaml.NewDecoder(bytesReader(b))
	dec.KnownFields(true) // an unknown key is a typo, and a typo is a silent default
	if err := dec.Decode(&c); err != nil {
		return Calibration{}, fmt.Errorf("calibration: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Calibration{}, err
	}
	return c, nil
}

// Validate checks that every value the scorer will look up is present.
func (c Calibration) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("calibration: unsupported version %d", c.Version)
	}

	// Every severity band must have a base, or a finding carrying that band
	// scores zero and silently becomes P3.
	for _, s := range model.AllSeverities {
		if _, ok := c.Scoring.SeverityBase[string(s)]; !ok {
			return fmt.Errorf("calibration: no severity_base for %s", s)
		}
	}
	// All three reachability values, and they must be strictly ordered so the
	// tri-state cannot collapse (VM-F-243).
	for _, r := range model.AllReachable {
		if _, ok := c.Scoring.Reachable[string(r)]; !ok {
			return fmt.Errorf("calibration: no reachable multiplier for %q", r)
		}
	}
	t := c.Scoring.Reachable[string(model.ReachableTrue)]
	u := c.Scoring.Reachable[string(model.ReachableUnknown)]
	f := c.Scoring.Reachable[string(model.ReachableFalse)]
	if !(t > u && u > f) {
		return fmt.Errorf(
			"calibration: reachability multipliers must be strictly ordered true > unknown > false, got %v > %v > %v; "+
				"equal values collapse the tri-state that VM-F-243 exists to preserve", t, u, f)
	}

	for _, d := range []model.DepClass{model.DepProduction, model.DepDevelopment, model.DepNotApplicable} {
		if _, ok := c.Scoring.DepClass[string(d)]; !ok {
			return fmt.Errorf("calibration: no dep_class multiplier for %q", d)
		}
	}
	for tier := 1; tier <= 3; tier++ {
		if _, ok := c.Scoring.Tier[tier]; !ok {
			return fmt.Errorf("calibration: no tier multiplier for tier %d", tier)
		}
	}

	// Priority bands must descend, or two bands overlap and the band a finding
	// lands in depends on evaluation order.
	p0, ok0 := c.Scoring.PriorityBands["P0"]
	p1, ok1 := c.Scoring.PriorityBands["P1"]
	p2, ok2 := c.Scoring.PriorityBands["P2"]
	if !ok0 || !ok1 || !ok2 {
		return fmt.Errorf("calibration: priority_bands must define P0, P1 and P2")
	}
	if !(p0 > p1 && p1 > p2) {
		return fmt.Errorf("calibration: priority bands must descend, got P0=%v P1=%v P2=%v", p0, p1, p2)
	}

	// The freshness window must be positive where it is set at all. Zero
	// falls back to the working default rather than meaning "never stale":
	// a window of zero would mark every answer stale, and a window of
	// infinity would mark none — and the second failure is silent.
	if c.Scoring.FeedFreshnessDays < 0 {
		return fmt.Errorf("calibration: scoring.feed_freshness_days must be positive, got %d",
			c.Scoring.FeedFreshnessDays)
	}

	if _, err := c.SLAWindows(); err != nil {
		return err
	}

	if c.FanOut.Enabled && c.FanOut.MaxMultiplier < 1 {
		return fmt.Errorf("calibration: fanout.max_multiplier must be at least 1, got %v", c.FanOut.MaxMultiplier)
	}
	for _, p := range []model.Priority{c.Routing.EscalateAt, c.Routing.AutoRemediateAt, c.Routing.TicketBelow} {
		if !p.Valid() {
			return fmt.Errorf("calibration: invalid routing priority %q", p)
		}
	}
	return nil
}

// StaticAnalysisFor returns the tier's static analysis thresholds, falling back
// to tier 3 for an unknown tier — the strictest configured bar, since an
// unclassified repository should not get the most permissive treatment by
// accident (VM-OQ-01 is still open on tier assignment).
func (c Calibration) StaticAnalysisFor(tier int) (severity, confidence string, exclude []string) {
	t, ok := c.StaticAnalysis.Tiers[tier]
	if !ok {
		t = c.StaticAnalysis.Tiers[3]
	}
	return t.GosecSeverity, t.GosecConfidence, t.StaticcheckExclude
}
