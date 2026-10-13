package store

import (
	"sort"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
)

// CoverageState is how well covered one repository currently is.
//
// It exists because a gap *count* hides per-repository starvation: forty
// repositories each deferred once looks identical to one repository deferred
// forty times, and only the second is a real hole in the fleet's coverage.
type CoverageState struct {
	Repo string `json:"repo"`

	// LastQualifyingRun and LastQualifyingAt describe the most recent scan that
	// completed successfully. "Qualifying" is the VM-ADR-12 predicate,
	// unchanged: a partial or failed scan does not refresh coverage any more
	// than it verifies a finding.
	LastQualifyingRun string     `json:"last_qualifying_run,omitempty"`
	LastQualifyingAt  *time.Time `json:"last_qualifying_at,omitempty"`

	// SweepsSinceQualifying counts consecutive runs, most recent first, in
	// which the repository was in scope but no qualifying scan happened —
	// whatever the cause. This is the VM-F-215 streak.
	SweepsSinceQualifying int `json:"sweeps_since_qualifying"`

	// ConsecutiveDeferrals counts how many of those consecutive runs were
	// deliberate deferrals rather than failures. It breaks planning ties so a
	// repository that keeps losing the budget lottery climbs the order.
	ConsecutiveDeferrals int `json:"consecutive_deferrals"`

	// QualifyingHistory is the start time of every qualifying scan, newest
	// first; its head is LastQualifyingAt. Planning reads it to break ties
	// between repositories whose last qualifying scan was the same run —
	// which, because a run's scans share its start time, is every repository
	// that run covered.
	QualifyingHistory []time.Time `json:"-"`

	// LastCause is why the most recent run did not produce a qualifying scan.
	// The cause is an attribute of the streak, never a separate streak: a
	// repository alternating between a build failure and a budget deferral is
	// just as uncovered as one failing the same way twice (VM-F-215).
	LastCause string `json:"last_cause,omitempty"`
}

// NeverScanned reports whether the repository has no qualifying scan at all.
func (c CoverageState) NeverScanned() bool { return c.LastQualifyingAt == nil }

// Age returns how long it has been since the last qualifying scan. A repository
// that has never been scanned has no finite age; the caller decides how to
// order it, and every caller here sorts it first.
func (c CoverageState) Age(now time.Time) (time.Duration, bool) {
	if c.LastQualifyingAt == nil {
		return 0, false
	}
	return now.Sub(*c.LastQualifyingAt), true
}

// ByCoverageStaleness orders repositories most-stale first, for planning.
//
// Reading of the decision (2026-09-15): "plan by ascending last-qualifying-scan
// age (never-scanned sort first)" is implemented as **most stale first** —
// ascending by last-qualifying *timestamp*, so the longest-uncovered repository
// is planned first and a never-scanned one precedes everything. Taken literally,
// ascending *age* would put the freshest first, which contradicts both
// "never-scanned sort first" and the stated purpose of bounding worst-case
// coverage age. Recorded as assumption A19.
//
// Tie-break is (timestamp asc, consecutive deferrals desc, qualifying history
// least-recently-served first, repo asc), which makes the order a total
// function of stored state — no wall clock, no map iteration, no input order.
//
// The history step is the fairness guard. Every repository a run scans shares
// that run's start time, so ties on the last qualifying scan are the normal
// case whenever the budget is short. Breaking them by name alone let the same
// alphabetically-early repositories take the spare slots every round, so a
// fleet that never starved anyone still scanned some repositories twice as
// often as others. Comparing the scans before the last one, newest to oldest,
// prefers whichever repository was served less recently — a repository whose
// history runs out first has had fewer qualifying scans and goes first.
func ByCoverageStaleness(states []CoverageState) []CoverageState {
	out := make([]CoverageState, len(states))
	copy(out, states)

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]

		// Never scanned is maximally stale.
		switch {
		case a.NeverScanned() && !b.NeverScanned():
			return true
		case !a.NeverScanned() && b.NeverScanned():
			return false
		case !a.NeverScanned() && !b.NeverScanned():
			if !a.LastQualifyingAt.Equal(*b.LastQualifyingAt) {
				return a.LastQualifyingAt.Before(*b.LastQualifyingAt)
			}
		}

		// A repository that keeps being deferred climbs above one that does not.
		if a.ConsecutiveDeferrals != b.ConsecutiveDeferrals {
			return a.ConsecutiveDeferrals > b.ConsecutiveDeferrals
		}
		if less, decided := lessRecentlyServed(a.QualifyingHistory, b.QualifyingHistory); decided {
			return less
		}
		return a.Repo < b.Repo
	})
	return out
}

// lessRecentlyServed compares two newest-first qualifying histories past their
// shared head. A history that ends first — fewer qualifying scans — or reaches
// an older scan first has been served less recently. decided is false when the
// histories are identical.
func lessRecentlyServed(a, b []time.Time) (less, decided bool) {
	for k := 1; ; k++ {
		switch {
		case k >= len(a) && k >= len(b):
			return false, false
		case k >= len(a):
			return true, true
		case k >= len(b):
			return false, true
		case !a[k].Equal(b[k]):
			return a[k].Before(b[k]), true
		}
	}
}

// StalenessReport is the coverage-age distribution across a scope.
//
// Reported alongside the gap count, never instead of it: a flat gap count with a
// growing maximum age is exactly the starvation this exists to surface
// (OQ-P4-01).
type StalenessReport struct {
	InScope      int `json:"in_scope"`
	NeverScanned int `json:"never_scanned"`

	MaxAge    time.Duration `json:"max_age"`
	P95Age    time.Duration `json:"p95_age"`
	MedianAge time.Duration `json:"median_age"`

	// StalestRepo names the repository at MaxAge, so the number is actionable
	// rather than merely alarming. Empty when every repository is unscanned.
	StalestRepo string `json:"stalest_repo,omitempty"`
}

// Staleness computes the coverage-age distribution as of now.
//
// Never-scanned repositories are counted separately rather than folded in with
// an invented age: they have no age, and substituting one (zero, or the epoch)
// would either hide them or swamp every percentile.
func Staleness(states []CoverageState, now time.Time) StalenessReport {
	rep := StalenessReport{InScope: len(states)}

	var ages []agedRepo
	for _, s := range states {
		age, ok := s.Age(now)
		if !ok {
			rep.NeverScanned++
			continue
		}
		ages = append(ages, agedRepo{s.Repo, age})
	}
	if len(ages) == 0 {
		return rep
	}

	sort.Slice(ages, func(i, j int) bool {
		if ages[i].age != ages[j].age {
			return ages[i].age < ages[j].age
		}
		return ages[i].repo < ages[j].repo
	})

	rep.MaxAge = ages[len(ages)-1].age
	rep.StalestRepo = ages[len(ages)-1].repo
	rep.MedianAge = percentile(ages, 50)
	rep.P95Age = percentile(ages, 95)
	return rep
}

type agedRepo struct {
	repo string
	age  time.Duration
}

// percentile returns the nearest-rank percentile of a sorted age slice.
func percentile(sorted []agedRepo, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	// Nearest-rank: the smallest value at or above the p-th percentile. For
	// small fleets this is the honest reading — interpolating between two
	// repositories' ages would report an age no repository actually has.
	idx := (p*len(sorted) + 99) / 100
	if idx < 1 {
		idx = 1
	}
	if idx > len(sorted) {
		idx = len(sorted)
	}
	return sorted[idx-1].age
}

// Escalation is a repository whose coverage streak has crossed the threshold
// (VM-F-215).
type Escalation struct {
	Repo                  string `json:"repo"`
	SweepsSinceQualifying int    `json:"sweeps_since_qualifying"`
	// Cause is carried as an attribute, not as a filter. A repository deferred
	// for budget three times running is as uncovered as one whose build failed
	// three times, and only the remedy differs (OQ-P4-01).
	Cause             string     `json:"cause,omitempty"`
	LastQualifyingRun string     `json:"last_qualifying_run,omitempty"`
	LastQualifyingAt  *time.Time `json:"last_qualifying_at,omitempty"`
}

// Escalations returns the repositories whose consecutive-run streak without a
// qualifying scan has reached threshold.
//
// The streak is cause-agnostic by design. Counting only failures would let a
// repository that is never dispatched escape escalation entirely, which is the
// hole OQ-P4-01 closes — and a coverage gap that is only visible to someone who
// opens a dashboard is not surfaced (VM-F-215).
func Escalations(states []CoverageState, threshold int) []Escalation {
	if threshold <= 0 {
		threshold = 2 // VM-OQ-10's working default.
	}
	var out []Escalation
	for _, s := range states {
		if s.SweepsSinceQualifying < threshold {
			continue
		}
		out = append(out, Escalation{
			Repo:                  s.Repo,
			SweepsSinceQualifying: s.SweepsSinceQualifying,
			Cause:                 s.LastCause,
			LastQualifyingRun:     s.LastQualifyingRun,
			LastQualifyingAt:      s.LastQualifyingAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SweepsSinceQualifying != out[j].SweepsSinceQualifying {
			return out[i].SweepsSinceQualifying > out[j].SweepsSinceQualifying
		}
		return out[i].Repo < out[j].Repo
	})
	return out
}

// coverageFromHistory derives a repository's coverage state from its scan
// results, newest first, across the runs it was planned into.
//
// Shared by both backends so the streak cannot be counted one way in Postgres
// and another in memory.
//
// startedAt resolves a run to its start time, which is what LastQualifyingAt
// and QualifyingHistory record.
func coverageFromHistory(repo string, newestFirst []RepoScanResult, startedAt func(runID string) (time.Time, bool)) CoverageState {
	c := CoverageState{Repo: repo}

	for _, r := range newestFirst {
		if r.Outcome.Succeeded() {
			if at, ok := startedAt(r.RunID); ok {
				c.QualifyingHistory = append(c.QualifyingHistory, at)
			}
		}
	}
	if len(c.QualifyingHistory) > 0 {
		at := c.QualifyingHistory[0]
		c.LastQualifyingAt = &at
	}

	for _, r := range newestFirst {
		if r.Outcome.Succeeded() {
			c.LastQualifyingRun = r.RunID
			break
		}
		c.SweepsSinceQualifying++
		if c.LastCause == "" {
			c.LastCause = causeOf(r)
		}
		if r.Outcome == model.ScanNotDispatched {
			// Only counts while the deferral streak is unbroken from the most
			// recent run: an old deferral behind a recent failure says nothing
			// about losing the budget lottery now.
			if c.ConsecutiveDeferrals == c.SweepsSinceQualifying-1 {
				c.ConsecutiveDeferrals++
			}
		}
	}
	return c
}

// causeOf names why a run did not produce a qualifying scan.
func causeOf(r RepoScanResult) string {
	if r.FailureCause != "" {
		return r.FailureCause
	}
	return string(r.Outcome)
}
