package firstparty

import (
	"context"
	"fmt"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// Driver applies a wave plan to the findings store.
//
// Split from planning deliberately: a plan is inspectable, loggable and
// assertable before anything changes, and the split is what lets the wave
// tests assert a dispatch decision without a store at all.
type Driver struct {
	Store store.Store
	Index *Index
	Clock func() time.Time
}

// NewDriver builds a driver.
func NewDriver(s store.Store, idx *Index) *Driver {
	return &Driver{Store: s, Index: idx, Clock: func() time.Time { return time.Now().UTC() }}
}

func (d *Driver) now() time.Time {
	if d.Clock != nil {
		return d.Clock().UTC()
	}
	return time.Now().UTC()
}

// WaveStats is what a wave did, and what it did not.
type WaveStats struct {
	Plan     WavePlan `json:"plan"`
	Blocked  int      `json:"blocked"`
	Advanced int      `json:"advanced"`
	Excluded int      `json:"excluded"`
	Deferred int      `json:"deferred"`
	// Notes records everything the wave declined to do, with the reason.
	//
	// Recovery must be loud, and so must partial action. A wave that advanced
	// nine of twelve consumers and said nothing about the other three has
	// reported success for something it only partly did.
	Notes []string `json:"notes,omitempty"`
}

// ApplyWaveOne blocks the consumers on the owner's fix (VM-F-604, VM-F-609).
//
// Consumer findings are identified by the caller rather than rediscovered
// here: the orchestrator already knows which findings this module produced,
// and a driver that re-derived the set from the module name could sweep in
// findings a human had settled.
func (d *Driver) ApplyWaveOne(ctx context.Context, req WaveRequest, consumerFPs []string) (WaveStats, error) {
	stats := WaveStats{Plan: PlanWaveOne(d.Index, req)}
	if stats.Plan.Refusal != "" {
		stats.Notes = append(stats.Notes, stats.Plan.Refusal)
		return stats, nil
	}
	now := d.now()
	reason := model.ReasonBlockedUpstreamFirstParty

	for _, fp := range consumerFPs {
		f, err := d.Store.GetFinding(ctx, fp)
		if err != nil {
			return stats, err
		}
		if f.Repo == stats.Plan.Owner {
			// The owner remediates normally. Blocking it would leave it
			// waiting for itself.
			continue
		}
		if !model.CanTransition(f.State, model.BlockedUpstream) {
			stats.Notes = append(stats.Notes, fmt.Sprintf(
				"%s (%s) is in state %s and cannot be blocked upstream; left as it is",
				f.Repo, fp, f.State))
			continue
		}
		// The reason before the transition, so a blocked finding is never
		// without one, and the upstream reference so the consumer can discover
		// what it is waiting for.
		if err := d.Store.SetPriority(ctx, fp, f.Priority, &reason); err != nil {
			return stats, err
		}
		if err := d.Store.SetUpstreamFinding(ctx, fp, req.UpstreamFP); err != nil {
			return stats, err
		}
		if err := d.Store.ApplyTransition(ctx, fp, model.BlockedUpstream, model.TransitionContext{
			Actor: model.ActorOrchestrator,
			Cause: fmt.Sprintf("blocked on the first-party fix to %s in %s (upstream finding %s)",
				req.Module, stats.Plan.Owner, req.UpstreamFP),
			At: now,
		}); err != nil {
			return stats, err
		}
		stats.Blocked++
	}
	return stats, nil
}

// ApplyWaveTwo advances the blocked consumers once the fix is published
// (VM-F-606).
//
// The findings it moves are those actually in BLOCKED_UPSTREAM for this
// module. Advancing everything that matches the module name would reopen work
// a human had declined or suppressed, on the strength of a string.
func (d *Driver) ApplyWaveTwo(ctx context.Context, req WaveRequest) (WaveStats, error) {
	stats := WaveStats{Plan: PlanWaveTwo(d.Index, req)}
	if stats.Plan.Refusal != "" {
		stats.Notes = append(stats.Notes, stats.Plan.Refusal)
		return stats, nil
	}
	now := d.now()

	advance := map[string]bool{}
	for _, c := range stats.Plan.Dispatch {
		advance[c.Repo] = true
	}
	stall := map[string]Consumer{}
	for _, c := range stats.Plan.Excluded {
		stall[c.Repo] = c
	}
	for _, c := range stats.Plan.Deferred {
		stall[c.Repo] = c
	}

	blocked, err := d.Store.ListFindings(ctx, store.Query{
		Scope: store.ScopeOpen, States: []model.State{model.BlockedUpstream},
	})
	if err != nil {
		return stats, err
	}

	for _, f := range blocked {
		if f.Classification.FirstPartyPath == nil || *f.Classification.FirstPartyPath != req.Module {
			continue
		}

		if advance[f.Repo] {
			if err := d.Store.ApplyTransition(ctx, f.Fingerprint, model.AutoRemediating, model.TransitionContext{
				Actor: model.ActorOrchestrator,
				Cause: fmt.Sprintf("upstream fix to %s published as %s; advancing the consumer",
					req.Module, req.TargetVersion),
				At: now,
			}); err != nil {
				return stats, err
			}
			stats.Advanced++
			continue
		}

		c, stalled := stall[f.Repo]
		if !stalled {
			continue
		}

		// THE LIVENESS INVARIANT (Phase 9, reached by a different route).
		//
		// This consumer cannot be advanced automatically. Left in
		// BLOCKED_UPSTREAM it waits for an upstream fix that has ALREADY
		// shipped: nothing further will arrive, nothing escalates it, and it
		// reads as correctly-pending indefinitely. A wave that produces a
		// finding nothing can move has strand ed it, however good its reason.
		reason := model.ReasonBlockedUpstreamFirstParty
		if err := d.Store.SetPriority(ctx, f.Fingerprint, f.Priority, &reason); err != nil {
			return stats, err
		}
		if err := d.Store.ApplyTransition(ctx, f.Fingerprint, model.NeedsHuman, model.TransitionContext{
			Actor: model.ActorOrchestrator,
			Cause: fmt.Sprintf("the upstream fix to %s shipped, but this consumer cannot be advanced "+
				"automatically: %s", req.Module, c.Reason),
			At: now,
		}); err != nil {
			return stats, err
		}
		stats.Notes = append(stats.Notes, fmt.Sprintf(
			"%s was NOT advanced and needs a person: %s", f.Repo, c.Reason))
		if c.Replaced {
			stats.Excluded++
		} else {
			stats.Deferred++
		}
	}
	return stats, nil
}
