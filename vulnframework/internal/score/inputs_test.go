package score_test

import (
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/score"
)

// OQ-AUDIT-01(a): a priority resting on three of five declared inputs must not
// look complete.
//
// The Producer-Coverage Audit found that nothing writes EPSS or KEV. Both are
// read here: kev_boost is 3.0 in calibration.yaml and epss_coefficient is 2.0.
// Neither has ever applied to any priority this system computed, and the
// scoring tests pass because each one constructs the input it needs.
//
// The standard set by OQ-P5-02 and OQ-P7b-03 applies: a provisional input must
// surface in OUTPUT, and it must travel WITH the number rather than sitting in
// a caveat block a reader may not reach. A score is quoted onward — into a
// ticket, a slide, a status mail — and the qualification has to survive the
// quoting.

// TestScoreDeclaresWhichInputsAreUnavailable is the gate.
func TestScoreDeclaresWhichInputsAreUnavailable(t *testing.T) {
	c := cal(t)
	sc := score.New(c)

	res := sc.Score(score.Input{
		Category: model.CategoryDependency, Severity: model.SeverityHigh,
		CVSS: 7.5, Reachable: model.ReachableTrue, DepClass: model.DepProduction, Tier: 1,
		// EPSS and KEV deliberately absent: this is production's state, not a
		// degenerate case.
	})

	if len(res.UnavailableInputs) == 0 {
		t.Fatal("the score reports no unavailable inputs while nothing in the system writes EPSS or " +
			"KEV. Two of five declared inputs have never contributed to any priority, and a score " +
			"that does not say so presents three inputs' worth of judgement as five")
	}
	joined := strings.ToLower(strings.Join(res.UnavailableInputs, " "))
	for _, want := range []string{"kev", "epss"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the unavailable-input list does not name %q: %v", want, res.UnavailableInputs)
		}
	}

	// The qualification travels with the number. A caveat elsewhere in a
	// document is not attached to the figure that gets quoted.
	if !strings.Contains(strings.ToLower(res.Caveat), "kev") {
		t.Errorf("the score's own caveat does not name the missing inputs: %q", res.Caveat)
	}
	for _, want := range []string{"3 of 5", "exploit"} {
		if !strings.Contains(strings.ToLower(res.Caveat), strings.ToLower(want)) {
			t.Errorf("the caveat does not say %q, so a reader cannot tell how much of the judgement "+
				"is missing: %q", want, res.Caveat)
		}
	}

	// And the explain trail, which is what an engineer reads when they
	// disagree with a priority.
	if !strings.Contains(strings.ToLower(strings.Join(res.Explain, "\n")), "kev") {
		t.Errorf("the explain trail does not mention the unavailable inputs: %v", res.Explain)
	}
}

// TestAScoreWithEveryInputCarriesNoCaveat is the other half. A caveat that
// never clears is decoration: once the feeds are wired the qualification must
// disappear, or nobody will believe the next one.
func TestAScoreWithEveryInputCarriesNoCaveat(t *testing.T) {
	sc := score.New(cal(t))

	res := sc.Score(score.Input{
		Category: model.CategoryDependency, Severity: model.SeverityHigh,
		CVSS: 7.5, Reachable: model.ReachableTrue, DepClass: model.DepProduction, Tier: 1,
		EPSS: 0.42, KEV: true,
		// Both feeds present and answering.
		EPSSAvailable: true, KEVAvailable: true,
	})
	if len(res.UnavailableInputs) != 0 {
		t.Errorf("a fully-informed score still reports unavailable inputs: %v", res.UnavailableInputs)
	}
	if res.Caveat != "" {
		t.Errorf("a fully-informed score carries a caveat: %q", res.Caveat)
	}
}

// TestAbsentIsNotZeroForAnEnrichmentFeed is the invariant that matters most
// when the feeds ARE wired, and it is the same one as reachability's
// tri-state.
//
// A finding with no EPSS score is not a finding with an EPSS of zero. Zero
// means "measured, and nothing exploits this"; absent means "nobody looked".
// Treating them alike is how a P0 becomes a P2 on the strength of a missing
// lookup — and it is the failure the feed's own staleness handling must avoid
// (OQ-AUDIT-01(b)).
func TestAbsentIsNotZeroForAnEnrichmentFeed(t *testing.T) {
	sc := score.New(cal(t))
	base := score.Input{
		Category: model.CategoryDependency, Severity: model.SeverityHigh,
		CVSS: 7.5, Reachable: model.ReachableTrue, DepClass: model.DepProduction, Tier: 1,
	}

	absent := sc.Score(base)

	measuredZero := base
	measuredZero.EPSSAvailable, measuredZero.KEVAvailable = true, true
	measuredZero.EPSS, measuredZero.KEV = 0, false
	measured := sc.Score(measuredZero)

	// The scores may coincide — zero contribution either way — but the two
	// must be DISTINGUISHABLE, or a reader cannot tell an unmeasured finding
	// from a measured-benign one.
	if len(absent.UnavailableInputs) == len(measured.UnavailableInputs) {
		t.Error("an unmeasured EPSS is indistinguishable from a measured zero. Zero means nothing " +
			"exploits this; absent means nobody looked, and collapsing them lets a missing lookup " +
			"read as good news")
	}
	if measured.Caveat != "" {
		t.Errorf("a measured-benign score carries an unavailability caveat: %q", measured.Caveat)
	}
}
