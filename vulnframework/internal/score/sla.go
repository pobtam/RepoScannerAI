package score

import (
	"fmt"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
)

// SLAWindows maps tier and priority to a remediation window (VM-NF-301).
//
// VM-OQ-02 (the real windows, per severity per tier) is still open; these are
// working defaults, and like the calibration thresholds they are provisional
// until someone reviews them.
type SLAWindows map[int]map[model.Priority]time.Duration

// SLAWindows parses the configured remediation windows.
//
// It validates rather than falling back, because every plausible fallback is
// wrong in a way nothing downstream can see: a missing window reads as zero and
// breaches the finding on detection, an inverted table gives P0 the most time,
// and in both cases the breach count still looks like a measurement.
func (c Calibration) SLAWindows() (SLAWindows, error) {
	out := SLAWindows{}
	order := []model.Priority{model.P0, model.P1, model.P2, model.P3}

	for tier := 1; tier <= 3; tier++ {
		raw, ok := c.SLA.Windows[tier]
		if !ok {
			return nil, fmt.Errorf("calibration: sla.windows has no entry for tier %d", tier)
		}
		byPriority := map[model.Priority]time.Duration{}
		for _, p := range order {
			s, ok := raw[string(p)]
			if !ok {
				return nil, fmt.Errorf("calibration: sla.windows tier %d has no window for %s", tier, p)
			}
			d, err := time.ParseDuration(s)
			if err != nil {
				return nil, fmt.Errorf("calibration: sla.windows tier %d %s: %q is not a duration", tier, p, s)
			}
			if d <= 0 {
				return nil, fmt.Errorf("calibration: sla.windows tier %d %s must be positive, got %v; "+
					"a zero window breaches every finding at detection", tier, p, d)
			}
			byPriority[p] = d
		}
		// Windows must ascend with decreasing urgency. Equal values collapse two
		// priority bands into one, which makes the band assignment upstream
		// pointless without changing any visible number.
		for i := 1; i < len(order); i++ {
			prev, cur := order[i-1], order[i]
			if byPriority[cur] <= byPriority[prev] {
				return nil, fmt.Errorf(
					"calibration: sla.windows tier %d must ascend P0 < P1 < P2 < P3, but %s (%v) is not longer than %s (%v); "+
						"an inverted table gives the most urgent findings the most time while every breach count still looks plausible",
					tier, cur, byPriority[cur], prev, byPriority[prev])
			}
		}
		out[tier] = byPriority
	}
	return out, nil
}

// DefaultSLAWindows are the working defaults, used when no calibration file has
// been loaded. They are pinned equal to the shipped configuration by test, so
// the caveat a report renders describes the table actually in force.
func DefaultSLAWindows() SLAWindows {
	day := 24 * time.Hour
	return SLAWindows{
		1: {model.P0: 1 * day, model.P1: 7 * day, model.P2: 30 * day, model.P3: 90 * day},
		2: {model.P0: 2 * day, model.P1: 14 * day, model.P2: 60 * day, model.P3: 180 * day},
		3: {model.P0: 3 * day, model.P1: 30 * day, model.P2: 90 * day, model.P3: 365 * day},
	}
}

// Window returns the remediation window for a tier and priority, falling back to
// tier 3 for an unclassified repository (VM-OQ-01).
func (w SLAWindows) Window(tier int, p model.Priority) time.Duration {
	byPriority, ok := w[tier]
	if !ok {
		byPriority = w[3]
	}
	if d, ok := byPriority[p]; ok {
		return d
	}
	return byPriority[model.P3]
}

// SLAInput is what the SLA computation consumes.
type SLAInput struct {
	State       model.State
	Priority    model.Priority
	Tier        int
	ReasonCode  *model.ReasonCode
	FirstSeenAt time.Time
	ResolvedAt  *time.Time
}

// SLAResult is the computed SLA position (VM-AD §9.5).
type SLAResult struct {
	Status     model.SLAStatus `json:"status"`
	Age        time.Duration   `json:"age"`
	Window     time.Duration   `json:"window"`
	BreachedBy time.Duration   `json:"breached_by,omitempty"`
	Explain    string          `json:"explain,omitempty"`
}

// SLA computes a finding's SLA position (VM-AD §9.5, VM-F-908).
//
// It is computed once, here, and exposed on the finding rather than derived by
// each consumer, so reports, tickets and the interface cannot disagree about
// whether something is late.
//
// The clock starts at detection, not at triage or assignment (VM-NF-302), and
// stops at VERIFIED, not at merge (VM-NF-303) — a merged fix that no scan has
// confirmed is not yet a fix.
func SLA(in SLAInput, windows SLAWindows, now time.Time) SLAResult {
	window := windows.Window(in.Tier, in.Priority)
	res := SLAResult{Window: window}

	// Stopped: the clock ends at resolution, not at merge.
	if model.PartitionOf(in.State) == model.PartitionResolved {
		end := now
		if in.ResolvedAt != nil {
			end = *in.ResolvedAt
		}
		res.Age = end.Sub(in.FirstSeenAt)
		res.Status = model.SLAStopped
		res.Explain = "resolved: the clock stopped at resolution (VM-NF-303)"
		return res
	}

	res.Age = now.Sub(in.FirstSeenAt)

	// Paused: a finding with no upstream fix available cannot be remediated, so
	// it can never register as breached (VM-NF-304, VM-F-909).
	//
	// Breaching a window you have no means to meet produces a permanently red
	// row, and permanently red rows get ignored — including when they later
	// become actionable. The pause is checked before the breach comparison for
	// exactly that reason.
	if in.ReasonCode != nil && in.ReasonCode.PausesSLA() {
		res.Status = model.SLAPaused
		res.Explain = "reason_code=NO_UPSTREAM_FIX: clock paused; a paused finding can never breach (VM-NF-304, VM-F-909)"
		return res
	}

	switch {
	case res.Age > window:
		res.Status = model.SLABreached
		res.BreachedBy = res.Age - window
		res.Explain = "age exceeds the window"
	case float64(res.Age) > 0.75*float64(window):
		res.Status = model.SLAApproaching
		res.Explain = "age is within the final quarter of the window"
	default:
		res.Status = model.SLAWithin
		res.Explain = "within the window"
	}
	return res
}
