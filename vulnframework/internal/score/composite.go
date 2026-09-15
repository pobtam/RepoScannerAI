package score

import (
	"bytes"
	"fmt"
	"io"
	"math"

	"github.com/wanaware/vulnframework/internal/model"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// Input is everything the composite score consumes (VM-AD §9.4).
type Input struct {
	Category  model.Category
	Severity  model.Severity
	CVSS      float64
	EPSS      float64
	KEV       bool
	Reachable model.Reachable
	DepClass  model.DepClass
	Tier      int

	// FanOut is the blast radius of a first-party module finding. It is always
	// computed and recorded; whether it influences the score is calibration
	// (VM-OQ-12).
	FanOut FanOut
}

// Result is a scored finding, with the arithmetic retained.
type Result struct {
	Score    float64        `json:"score"`
	Priority model.Priority `json:"priority"`

	Base            float64 `json:"base"`
	KEVBoost        float64 `json:"kev_boost"`
	EPSSBoost       float64 `json:"epss_boost"`
	ReachMultiplier float64 `json:"reach_multiplier"`
	DepMultiplier   float64 `json:"dep_multiplier"`
	TierMultiplier  float64 `json:"tier_multiplier"`
	FanOutMult      float64 `json:"fanout_multiplier"`

	// FanOut is recorded whether or not it influenced the score, so the data
	// VM-OQ-12 needs accumulates from the first sweep rather than from whenever
	// someone decides to switch it on.
	FanOut FanOut `json:"fanout"`

	// SecretOverride marks a score that bypassed the formula entirely.
	SecretOverride bool `json:"secret_override,omitempty"`

	// Explain is the step-by-step derivation, so a priority can always be
	// accounted for rather than merely asserted (VM-F-405 in spirit).
	Explain []string `json:"explain,omitempty"`
}

// MaxScore is the ceiling a secret finding takes.
const MaxScore = 10.0

// Scorer computes priorities from a calibration.
type Scorer struct {
	Cal Calibration
}

// New builds a scorer.
func New(c Calibration) *Scorer { return &Scorer{Cal: c} }

// Score computes a finding's composite score and priority (VM-AD §9.4).
//
//	score = (base + kev_boost + epss_boost) × reach × depclass × tier [× fanout]
//
// The function is total: every enumeration value has a defined multiplier, and
// the calibration refuses to load without them. There is no implicit default,
// because an implicit default here is a silent zero and a silent zero makes a
// critical finding P3.
func (s *Scorer) Score(in Input) Result {
	// Secrets take a fixed maximum and bypass the formula entirely
	// (VM-AD §9.4). This is the first branch for the same reason the policy
	// engine short-circuits on secrets: no combination of multipliers may
	// reduce a leaked credential below the top of the queue.
	if in.Category == model.CategorySecret {
		return Result{
			Score: MaxScore, Priority: model.P0, Base: MaxScore,
			SecretOverride:  true,
			ReachMultiplier: 1, DepMultiplier: 1, TierMultiplier: 1, FanOutMult: 1,
			FanOut: in.FanOut,
			Explain: []string{
				"category=secret: fixed maximum, bypasses the composite formula (VM-AD §9.4)",
				fmt.Sprintf("score=%.2f priority=P0", MaxScore),
			},
		}
	}

	r := Result{FanOut: in.FanOut}

	// Base: the advisory's own CVSS where it has one, otherwise the severity
	// band. A tool that reports a band but no score still has to land on the
	// same 0..10 scale as one that reports both.
	if in.CVSS > 0 {
		r.Base = clamp(in.CVSS, 0, 10)
		r.Explain = append(r.Explain, fmt.Sprintf("base=%.2f from CVSS", r.Base))
	} else {
		r.Base = s.Cal.Scoring.SeverityBase[string(in.Severity)]
		r.Explain = append(r.Explain, fmt.Sprintf("base=%.2f from severity %s (no CVSS)", r.Base, in.Severity))
	}

	if in.KEV {
		r.KEVBoost = s.Cal.Scoring.KEVBoost
		r.Explain = append(r.Explain, fmt.Sprintf("kev_boost=+%.2f (in CISA KEV)", r.KEVBoost))
	}
	if in.EPSS > 0 {
		r.EPSSBoost = s.Cal.Scoring.EPSSCoefficient * clamp(in.EPSS, 0, 1)
		r.Explain = append(r.Explain, fmt.Sprintf("epss_boost=+%.3f (epss=%.4f)", r.EPSSBoost, in.EPSS))
	}

	// Reachability is consumed as a tri-state. Unknown has its own multiplier,
	// strictly between the two determinations — it is never read as false and
	// never read as true (VM-F-243). The calibration loader enforces the strict
	// ordering, so this lookup cannot silently collapse.
	reach := in.Reachable
	if !reach.Valid() {
		// An absent or invalid value is treated as unknown rather than
		// defaulted to a determination: asserting either would be inventing
		// evidence. The explanation records that it happened.
		reach = model.ReachableUnknown
		r.Explain = append(r.Explain,
			fmt.Sprintf("reachable=%q is not a valid tri-state value; treated as unknown", in.Reachable))
	}
	r.ReachMultiplier = s.Cal.Scoring.Reachable[string(reach)]
	r.Explain = append(r.Explain, fmt.Sprintf("reach=×%.2f (%s)", r.ReachMultiplier, reach))

	depClass := in.DepClass
	if depClass == "" {
		depClass = model.DepNotApplicable
	}
	r.DepMultiplier = s.Cal.Scoring.DepClass[string(depClass)]
	r.Explain = append(r.Explain, fmt.Sprintf("dep_class=×%.2f (%s)", r.DepMultiplier, depClass))

	r.TierMultiplier = s.tierMultiplier(in.Tier)
	r.Explain = append(r.Explain, fmt.Sprintf("tier=×%.2f (tier %d)", r.TierMultiplier, in.Tier))

	r.FanOutMult = s.fanOutMultiplier(in.FanOut)
	if r.FanOutMult != 1 {
		r.Explain = append(r.Explain, fmt.Sprintf("fanout=×%.2f (%d reachable consumers, %d tier-1)",
			r.FanOutMult, in.FanOut.ReachCount, in.FanOut.Tier1ReachCount))
	} else if in.FanOut.DependCount > 0 {
		// Recorded but not applied: this is the VM-OQ-12 data trail.
		r.Explain = append(r.Explain, fmt.Sprintf(
			"fanout recorded but not applied (depend=%d reach=%d); weighting is VM-OQ-12",
			in.FanOut.DependCount, in.FanOut.ReachCount))
	}

	r.Score = (r.Base + r.KEVBoost + r.EPSSBoost) *
		r.ReachMultiplier * r.DepMultiplier * r.TierMultiplier * r.FanOutMult
	r.Priority = s.priorityOf(r.Score)
	r.Explain = append(r.Explain, fmt.Sprintf("score=%.4f priority=%s", r.Score, r.Priority))
	return r
}

func (s *Scorer) tierMultiplier(tier int) float64 {
	if m, ok := s.Cal.Scoring.Tier[tier]; ok {
		return m
	}
	// An unclassified repository takes the tier-3 multiplier rather than a
	// neutral 1.0: VM-OQ-01 (tier assignment) is still open, and quietly
	// promoting unclassified repositories to tier-2 weighting would inflate the
	// queue with findings nobody has triaged the importance of.
	return s.Cal.Scoring.Tier[3]
}

// priorityOf maps a score to its band (VM-AD §9.4).
func (s *Scorer) priorityOf(score float64) model.Priority {
	b := s.Cal.Scoring.PriorityBands
	switch {
	case score >= b["P0"]:
		return model.P0
	case score >= b["P1"]:
		return model.P1
	case score >= b["P2"]:
		return model.P2
	default:
		return model.P3
	}
}

// fanOutMultiplier turns a blast radius into a multiplier.
//
// Disabled by default: VM-AD §9.4 calls the weighting "a judgement about breadth
// versus depth" and deferred it to VM-OQ-12 rather than guessing, and shipping a
// guessed multiplier would silently reorder the P0 queue on an unreviewed
// opinion. The mechanism is built and tested so enabling it is a configuration
// change, and the blast radius is recorded regardless so the data to answer
// VM-OQ-12 accumulates.
func (s *Scorer) fanOutMultiplier(f FanOut) float64 {
	if !s.Cal.FanOut.Enabled {
		return 1
	}
	m := 1.0
	m += float64(f.Tier1ReachCount) * s.Cal.FanOut.PerTier1ReachConsumer
	// Tier-1 consumers are counted once, under the tier-1 weight only.
	others := f.ReachCount - f.Tier1ReachCount
	if others < 0 {
		others = 0
	}
	m += float64(others) * s.Cal.FanOut.PerReachConsumer
	return clamp(m, 1, s.Cal.FanOut.MaxMultiplier)
}

func clamp(v, lo, hi float64) float64 {
	return math.Max(lo, math.Min(hi, v))
}
