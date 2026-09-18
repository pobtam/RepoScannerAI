package score

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

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

	// EPSSAvailable and KEVAvailable say whether the enrichment feed ANSWERED,
	// as distinct from answering zero.
	//
	// The distinction is the same one reachability's tri-state exists for. An
	// EPSS of zero means "measured, and nothing exploits this"; an absent EPSS
	// means "nobody looked". Collapsing them lets a missing lookup read as
	// good news, and it is how a P0 becomes a P2 on the strength of a feed
	// that was down.
	//
	// Both are false throughout the build so far, because nothing writes
	// either input — which is what the Producer-Coverage Audit found, and why
	// a score has to say so (OQ-AUDIT-01).
	EPSSAvailable bool
	KEVAvailable  bool

	// EPSSAsOf and KEVAsOf are the snapshot dates behind those two inputs, and
	// Now is the clock the age is measured against.
	//
	// An age is part of the answer. "EPSS 0.94" and "EPSS 0.94 as of eleven
	// days ago" support different decisions, and the second one has to say so
	// where the number is read rather than in a footnote about feeds.
	EPSSAsOf *time.Time
	KEVAsOf  *time.Time
	Now      time.Time
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

	// UnavailableInputs names the declared scoring inputs that did not answer.
	//
	// A score computed from three of five inputs is not a worse score, it is a
	// narrower one, and the difference is invisible in the number. Naming them
	// is what lets a reader judge how much of the judgement is actually there.
	UnavailableInputs []string `json:"unavailable_inputs,omitempty"`

	// StaleInputs names the inputs whose snapshot is older than the
	// calibrated freshness window. They ARE used — a stale answer beats
	// silence — and they are labelled, because a reader deciding on the
	// strength of "known exploited" is entitled to know it was true last week
	// and has not been rechecked.
	StaleInputs []string `json:"stale_inputs,omitempty"`

	// Caveat travels WITH the score, not in a document-level block a reader
	// may never reach. A priority is quoted onward — into a ticket, a slide, a
	// status mail — and the qualification has to survive the quoting
	// (OQ-P5-02's lesson, applied to the score itself).
	Caveat string `json:"caveat,omitempty"`

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

	// The two enrichment inputs, and whether they answered at all.
	//
	// "Did not answer" and "answered zero" are different facts and are kept
	// apart here for the same reason reachability is a tri-state: a missing
	// lookup must not read as good news. Nothing in this system writes either
	// input today, which the Producer-Coverage Audit found and which is why
	// every score currently carries a caveat (OQ-AUDIT-01).
	if in.KEVAvailable {
		if in.KEV {
			r.KEVBoost = s.Cal.Scoring.KEVBoost
			r.Explain = append(r.Explain, fmt.Sprintf("kev_boost=+%.2f (in CISA KEV)", r.KEVBoost))
		} else {
			r.Explain = append(r.Explain, "kev=false (checked against CISA KEV)")
		}
		if age, stale := s.staleness(in.KEVAsOf, in.Now); stale {
			r.StaleInputs = append(r.StaleInputs, fmt.Sprintf("KEV as of %s (%d days old)",
				in.KEVAsOf.Format("2006-01-02"), age))
			r.Explain = append(r.Explain, fmt.Sprintf("kev snapshot is %d days old", age))
		}
	} else {
		r.UnavailableInputs = append(r.UnavailableInputs, "KEV (CISA known-exploited)")
		r.Explain = append(r.Explain, fmt.Sprintf(
			"kev UNAVAILABLE: nothing answered for this finding's identifiers, so kev_boost=+%.2f "+
				"can never apply. This is not kev=false — nobody looked (OQ-AUDIT-01)",
			s.Cal.Scoring.KEVBoost))
	}

	if in.EPSSAvailable {
		if in.EPSS > 0 {
			r.EPSSBoost = s.Cal.Scoring.EPSSCoefficient * clamp(in.EPSS, 0, 1)
			r.Explain = append(r.Explain, fmt.Sprintf("epss_boost=+%.3f (epss=%.4f)", r.EPSSBoost, in.EPSS))
		} else {
			r.Explain = append(r.Explain, "epss=0 (measured)")
		}
		if age, stale := s.staleness(in.EPSSAsOf, in.Now); stale {
			r.StaleInputs = append(r.StaleInputs, fmt.Sprintf("EPSS as of %s (%d days old)",
				in.EPSSAsOf.Format("2006-01-02"), age))
			r.Explain = append(r.Explain, fmt.Sprintf("epss snapshot is %d days old", age))
		}
	} else {
		r.UnavailableInputs = append(r.UnavailableInputs, "EPSS (exploit prediction)")
		r.Explain = append(r.Explain, fmt.Sprintf(
			"epss UNAVAILABLE: nothing answered for this finding's identifiers, so the epss "+
				"coefficient of %.2f can never apply. This is not epss=0 — nobody looked "+
				"(OQ-AUDIT-01, VM-OQ-07)", s.Cal.Scoring.EPSSCoefficient))
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
	r.Caveat = caveatFor(r.UnavailableInputs, r.StaleInputs)
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

// declaredInputs is how many inputs the composite formula declares: base
// severity or CVSS, KEV, EPSS, reachability, dependency class and tier
// multipliers. Counted as five decision-changing inputs plus the tier
// weighting, which is repository policy rather than a property of the defect.
const declaredInputs = 5

// caveatFor renders the qualification that travels WITH a score.
//
// With the score, not in a document-level block. A priority is the most-quoted
// number this system produces — it reaches a ticket title, a slide, a status
// mail — and a caveat that stays behind in the report is a caveat nobody
// quoting the priority ever saw. That is the lesson of OQ-P5-02 and
// OQ-P7b-03, applied one level in.
//
// The two missing inputs are not arbitrary ones. KEV answers "is this being
// exploited right now" and EPSS answers "how likely is it to be", which are
// the two questions that most often change what a human does about a finding.
// A score computed without them is not slightly less informed; it is missing
// the part that would have argued loudest.
func caveatFor(unavailable, stale []string) string {
	if len(unavailable) == 0 {
		if len(stale) == 0 {
			return ""
		}
		// Every input answered; some answered about last week. The number is
		// usable and the age travels with it.
		return fmt.Sprintf(
			"This priority uses exploitation intelligence that has not been refreshed: %s. A stale "+
				"answer beats silence, and it is still an answer about the past — recheck before "+
				"acting on it during an active incident.",
			strings.Join(stale, "; "))
	}
	available := declaredInputs - len(unavailable)
	out := fmt.Sprintf(
		"This priority rests on %d of %d declared inputs: %s %s unavailable because no feed is "+
			"wired (OQ-AUDIT-01). Those two answer whether the vulnerability is being exploited now "+
			"and how likely it is to be — the questions that most often change what a human does — "+
			"so this score is not merely less precise, it is missing the input that would have "+
			"argued loudest. Treat it as a floor, not an assessment.",
		available, declaredInputs, strings.Join(unavailable, " and "),
		plural(len(unavailable), "is", "are"))
	if len(stale) > 0 {
		out += fmt.Sprintf(" What did answer is not current: %s.", strings.Join(stale, "; "))
	}
	return out
}

// staleness reports the age in days of a snapshot and whether it exceeds the
// calibrated freshness window.
//
// A missing date is not stale — it is unavailable, handled by the caller — and
// a zero window means the question was never calibrated, in which case the
// default applies rather than "everything is fresh".
func (s *Scorer) staleness(asOf *time.Time, now time.Time) (int, bool) {
	if asOf == nil || asOf.IsZero() || now.IsZero() {
		return 0, false
	}
	days := int(now.UTC().Sub(asOf.UTC()).Hours() / 24)
	if days < 0 {
		days = 0
	}
	return days, days > s.feedFreshnessDays()
}

// feedFreshnessDays is the calibrated window, or the working default.
func (s *Scorer) feedFreshnessDays() int {
	if s.Cal.Scoring.FeedFreshnessDays > 0 {
		return s.Cal.Scoring.FeedFreshnessDays
	}
	return 7
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// DeclaredInputs is how many inputs the composite formula declares.
func DeclaredInputs() int { return declaredInputs }

// UnavailableInputs names the declared inputs nothing writes today.
//
// A deployment-level fact rather than a per-finding one: until a feed is
// wired, the answer is the same for every finding in every report. It exists
// so a report can carry the qualification without having to score something
// first (OQ-AUDIT-01).
func UnavailableInputs() []string {
	return []string{"KEV (CISA known-exploited)", "EPSS (exploit prediction)"}
}
