package orchestrator

import (
	"context"
	"fmt"
	"sort"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/triage"
)

// TriageStats summarises a triage-and-route pass.
type TriageStats struct {
	Eligible    int
	Triaged     int
	Scored      int
	SLAComputed int
	Routed      map[policy.Outcome]int
	Unmatched   []string
	Triage      triage.Stats
}

// TriageAndRoute enriches, scores and routes a repository's new findings.
//
// This is the pipeline step that turns a detected finding into a decided one:
//
//	triage narrative  -> persisted, and DETECTED -> TRIAGED driven
//	composite score   -> priority persisted
//	policy            -> outcome, with the deciding rule recorded
//
// The order matters. The narrative is persisted and the state advanced *before*
// policy runs, because policy evaluates findings in TRIAGED — and the narrative
// is persisted rather than merely computed so that a ticket or report can quote
// it later without re-running inference.
//
// Policy does not read the narrative. It is recorded alongside the finding for
// humans; the routing decision is made from deterministic attributes only.
func (o *Orchestrator) TriageAndRoute(
	ctx context.Context,
	repo store.Repo,
	tr *triage.Triager,
	sc *score.Scorer,
	pol *policy.Engine,
	view policy.StoreView,
) (TriageStats, error) {
	stats := TriageStats{Routed: map[policy.Outcome]int{}}

	open, err := o.Store.ListFindings(ctx, store.Query{Scope: store.ScopeOpen, Repo: repo.Name})
	if err != nil {
		return stats, err
	}

	// Triage runs on DETECTED and REGRESSED only (VM-AD §9.1).
	var eligible []model.Finding
	for _, f := range open {
		if triage.Eligible(f.State) {
			eligible = append(eligible, f)
		}
	}
	sort.Slice(eligible, func(i, j int) bool { return eligible[i].Fingerprint < eligible[j].Fingerprint })
	stats.Eligible = len(eligible)

	if len(eligible) > 0 && tr != nil {
		items := make([]triage.Item, 0, len(eligible))
		for _, f := range eligible {
			items = append(items, triage.ItemFrom(f))
		}

		profile := triage.RepoProfile{
			Repo: repo.Name, Languages: repo.Languages, Tier: repo.Tier,
			HasTestSuite: repo.HasTestSuite, ModuleTopology: repo.ModuleTopology,
		}
		verdicts, tstats, err := tr.Run(ctx, profile, items)
		if err != nil {
			return stats, fmt.Errorf("triage %s: %w", repo.Name, err)
		}
		stats.Triage = tstats

		for _, f := range eligible {
			// Persist the narrative where one survived validation. A finding
			// with no verdict still advances: the run is never blocked on
			// triage (VM-AD §9.3), and a finding without a narrative is still
			// detected, scored and routable.
			if v, ok := verdicts[f.Fingerprint]; ok {
				if err := o.Store.SetTriage(ctx, f.Fingerprint, v); err != nil {
					return stats, err
				}
			}
			if f.State == model.Detected {
				if err := o.Store.ApplyTransition(ctx, f.Fingerprint, model.Triaged, model.TransitionContext{
					Actor: model.ActorTriage, Cause: "triage complete", At: o.clock(),
				}); err != nil {
					return stats, fmt.Errorf("advancing %s to TRIAGED: %w", f.Fingerprint, err)
				}
				stats.Triaged++
			}
		}
	}

	// Re-read: the states and narratives have changed underneath.
	open, err = o.Store.ListFindings(ctx, store.Query{Scope: store.ScopeOpen, Repo: repo.Name})
	if err != nil {
		return stats, err
	}
	sort.Slice(open, func(i, j int) bool { return open[i].Fingerprint < open[j].Fingerprint })

	pr := policy.Repo{
		Name: repo.Name, Tier: repo.Tier,
		Language:     policy.Language(primaryLanguage(repo)),
		HasTestSuite: repo.HasTestSuite,
	}

	for _, f := range open {
		if f.State == model.Detected {
			// Not triaged — either triage was not supplied or it failed. Policy
			// runs after triage, so it is not evaluated here.
			continue
		}

		if sc != nil {
			res := sc.Score(score.Input{
				Category: f.Category, Severity: f.Classification.Severity,
				CVSS: f.Classification.CVSS, EPSS: f.Classification.EPSS,
				KEV: f.Classification.KEV, Reachable: f.Classification.Reachable,
				DepClass: f.Classification.DepClass, Tier: repo.Tier,
			})
			if err := o.Store.SetPriority(ctx, f.Fingerprint, res.Priority, nil); err != nil {
				return stats, err
			}
			f.Priority = res.Priority
			stats.Scored++

			// SLA is computed in the same pass, from the priority just
			// assigned. Computing the priority and leaving the SLA uncomputed
			// is worse than omitting SLA entirely: the report then reads
			// "0 breached" because nobody looked, which a reader cannot tell
			// from "nothing is late" (OQ-P7-03).
			sla := score.SLA(score.SLAInput{
				State: f.State, Priority: res.Priority, Tier: repo.Tier,
				ReasonCode: f.ReasonCode, FirstSeenAt: f.FirstSeenAt, ResolvedAt: f.ResolvedAt,
			}, o.SLAWindows(), o.clock())

			derived := f.Derived
			derived.SLAStatus = sla.Status
			derived.SLAWindowDays = int(sla.Window.Hours() / 24)
			derived.SLABreachDays = int(sla.BreachedBy.Hours() / 24)
			derived.AgeDays = int(sla.Age.Hours() / 24)
			if err := o.Store.SetSLA(ctx, f.Fingerprint, derived); err != nil {
				return stats, err
			}
			stats.SLAComputed++
		}

		if pol == nil {
			continue
		}
		decision, err := pol.Evaluate(f, pr, view)
		if err != nil {
			// A hole in the decision table is loud. The finding is recorded as
			// unmatched and the run continues, so one gap does not stop the
			// fleet — but it is never silently routed.
			stats.Unmatched = append(stats.Unmatched, f.Fingerprint)
			continue
		}
		stats.Routed[decision.Outcome]++

		if err := o.applyDecision(ctx, f, decision); err != nil {
			return stats, err
		}
	}

	sort.Strings(stats.Unmatched)
	return stats, nil
}

// applyDecision drives the state change a decision implies.
//
// Only the transitions VM-AD §6.1 admits from TRIAGED are driven here; the skip
// outcomes deliberately change nothing, which is what "skip" means.
func (o *Orchestrator) applyDecision(ctx context.Context, f model.Finding, d policy.Decision) error {
	var to model.State
	switch d.Outcome {
	case policy.AutoRemediate:
		// No state change (VM-AD §6.1.5, OQ-AUDIT-05).
		//
		// The decision marks the finding claimable and is recorded; a DISPATCH
		// enters AUTO_REMEDIATING, together with the lease, because that state
		// is lease-bound. Routing into it here left a finding holding a lease
		// nobody owned: policy rule 2 then skipped it as in progress, the
		// lease sweeper had no lease to expire, and the stranding sweep
		// recovered it every pass — loudly, against work that was never wrong.
		// It also meant the remediation worker, which claims findings from
		// TRIAGED, never saw the work routed to it at all.
		return o.recordReason(ctx, f, d)
	case policy.OpenTicket, policy.EscalateP0:
		to = model.NeedsHuman
	case policy.DeferUpstream:
		to = model.BlockedUpstream
	default:
		// skip_in_progress, skip_declined, skip_suppressed: no state change.
		return nil
	}

	if !model.CanTransition(f.State, to) {
		// Not an error: a finding already in NEEDS_HUMAN that routes to
		// open_ticket again is stable, not illegal. Recording the reason still
		// matters, so that falls through to the reason write below.
		return o.recordReason(ctx, f, d)
	}
	if err := o.Store.ApplyTransition(ctx, f.Fingerprint, to, model.TransitionContext{
		Actor: model.ActorOrchestrator,
		Cause: fmt.Sprintf("policy rule %d (%s): %s", d.Rule, d.RuleName, d.Outcome),
		At:    o.clock(),
	}); err != nil {
		return err
	}
	return o.recordReason(ctx, f, d)
}

func (o *Orchestrator) recordReason(ctx context.Context, f model.Finding, d policy.Decision) error {
	if d.Reason == "" {
		return nil
	}
	reason := d.Reason
	return o.Store.SetPriority(ctx, f.Fingerprint, f.Priority, &reason)
}

// SLAWindows returns the configured remediation windows (VM-NF-301).
func (o *Orchestrator) SLAWindows() score.SLAWindows {
	if o.Config.SLAWindows != nil {
		return o.Config.SLAWindows
	}
	return score.DefaultSLAWindows()
}

func primaryLanguage(r store.Repo) string {
	if len(r.Languages) == 0 {
		return string(policy.LangGo)
	}
	return r.Languages[0]
}
