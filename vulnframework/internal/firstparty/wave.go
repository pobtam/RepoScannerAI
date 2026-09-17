package firstparty

import (
	"fmt"

	"github.com/wanaware/vulnframework/internal/store"
)

// WaveRequest is what a wave is planned from.
type WaveRequest struct {
	Module     string
	UpstreamFP string
	// TargetVersion is the version of the first-party module consumers are
	// advanced to. Required for Wave 2: without it a wave would bump every
	// consumer to whatever the proxy happens to serve, which is not a
	// remediation but a fleet-wide unreviewed upgrade.
	TargetVersion string
}

// WavePlan is a planned wave. It is a plan and not an action: nothing here
// touches a repository, so a plan can be inspected, logged and asserted before
// anything is dispatched.
type WavePlan struct {
	Module string `json:"module"`
	Owner  string `json:"owner"`
	Wave   int    `json:"wave"`

	// Blocked is Wave 1's consumer set: findings move to BLOCKED_UPSTREAM with
	// a reference to the owner's finding (VM-F-604).
	Blocked []Consumer `json:"blocked,omitempty"`
	// ConsumerTickets and ConsumerPullRequests are always false in Wave 1 and
	// are stated rather than implied, because both are the specific things
	// VM-F-604 and VM-F-605 forbid: twelve tickets for one upstream fix is how
	// a queue becomes noise, and a consumer pull request has nothing to
	// upgrade to yet.
	ConsumerTickets      bool `json:"consumer_tickets"`
	ConsumerPullRequests bool `json:"consumer_pull_requests"`

	// Dispatch is Wave 2's consumer set.
	Dispatch []Consumer `json:"dispatch,omitempty"`
	// Excluded are consumers a wave cannot advance at all — a replace
	// directive (VM-F-608). Reported for manual handling, never dropped.
	Excluded []Consumer `json:"excluded,omitempty"`
	// Deferred are consumers this wave will not advance yet, because the
	// fleet's version spread means they would fail to build (VM-F-613).
	Deferred []Consumer `json:"deferred,omitempty"`
	// Split records that the spread forced the wave apart.
	Split bool `json:"split"`

	// Spread is the distribution the plan was computed from, retained so the
	// decision is inspectable rather than merely asserted.
	Spread Spread `json:"spread"`

	// Refusal is set when the wave cannot be planned at all.
	Refusal string `json:"refusal,omitempty"`
}

// IsWave reports whether there is anything to sequence.
//
// A first-party module with no consumers is an ordinary finding in the owning
// repository. Treating it as a wave would open an upstream ticket listing
// nobody, which reads as a coordination problem where there is none.
func (p WavePlan) IsWave() bool { return len(p.Blocked) > 0 || len(p.Dispatch) > 0 }

// PlanWaveOne plans the upstream fix and the consumer block (VM-AD §12.3).
//
// One pull request, in the owning repository (VM-F-603). Every consumer is
// blocked — including one with a replace directive, whose finding is real and
// is simply excluded from the automated wave later. Blocking is not the same
// as being remediable, and conflating them would hide a live finding.
func PlanWaveOne(idx *Index, req WaveRequest) WavePlan {
	plan := WavePlan{Module: req.Module, Wave: 1, Spread: idx.VersionSpread(req.Module)}

	owner, ok := idx.Owner(req.Module)
	if !ok {
		plan.Refusal = fmt.Sprintf(
			"%q is not a registered first-party module, so there is no owning repository to fix it. "+
				"Routing a wave at an unowned module sends the finding nowhere (VM-F-601)", req.Module)
		return plan
	}
	plan.Owner = owner

	for _, c := range idx.Consumers(req.Module) {
		c.UpstreamFP = req.UpstreamFP
		plan.Blocked = append(plan.Blocked, c)
	}
	return plan
}

// PlanWaveTwo plans the consumer advance once the fix is published.
//
// Deterministic, and no inference (VM-F-607). Every decision here is a
// comparison against the index and the target version; the consumer bumps
// themselves are deterministic bump workers.
func PlanWaveTwo(idx *Index, req WaveRequest) WavePlan {
	plan := WavePlan{Module: req.Module, Wave: 2, Spread: idx.VersionSpread(req.Module)}

	owner, ok := idx.Owner(req.Module)
	if !ok {
		plan.Refusal = fmt.Sprintf("%q is not a registered first-party module", req.Module)
		return plan
	}
	plan.Owner = owner

	if req.TargetVersion == "" {
		plan.Refusal = "refusing to plan Wave 2 with no target version: consumers would be bumped to " +
			"whatever the module proxy happened to serve, which is a fleet-wide unreviewed upgrade " +
			"rather than a remediation"
		return plan
	}

	// The spread is consulted BEFORE dispatch. Discovering divergence as half
	// a wave of failed builds is the failure this exists to prevent, and by
	// then the pull requests exist and someone has to close them (VM-F-613).
	newest := plan.Spread.Newest

	for _, c := range idx.Consumers(req.Module) {
		switch {
		case c.Replaced:
			// A replace directive means this consumer does not resolve the
			// module from the registry at all. Bumping its requirement changes
			// nothing, and the bump would build, pass, and close a finding
			// that is still live (VM-F-608).
			c.Reason = fmt.Sprintf(
				"a replace directive affects %s, so bumping the requirement would change nothing "+
					"that is actually built — the bump would pass and close a live finding (VM-F-608). "+
					"Needs manual handling", req.Module)
			plan.Excluded = append(plan.Excluded, c)

		case plan.Spread.Diverged() && c.Version != "" && newest != "" &&
			store.CompareVersions(c.Version, newest) < 0:
			// Behind the fleet. Advancing it to the target in one step is the
			// case that fails to build.
			c.Reason = fmt.Sprintf(
				"on %s while the fleet's newest is %s: advancing to %s in one step may not build, so "+
					"this consumer is deferred to its own wave rather than discovered as a failed "+
					"build (VM-F-613)", c.Version, newest, req.TargetVersion)
			plan.Deferred = append(plan.Deferred, c)
			plan.Split = true

		default:
			plan.Dispatch = append(plan.Dispatch, c)
		}
	}
	return plan
}
