package orchestrator

import (
	"context"
	"fmt"
	"sort"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/remediate"
	"github.com/wanaware/vulnframework/internal/store"
)

// RemediationRequest parameterises one remediation dispatch pass.
type RemediationRequest struct {
	Repo  store.Repo
	RunID string

	// Worker performs the attempt. The deterministic bumper and the agentic
	// harness are the same Worker with a different Fixer, so this pass does
	// not know or care which one it is dispatching.
	Worker *remediate.Worker
	Policy *policy.Engine
	View   policy.StoreView
	Groups remediate.GroupConfig

	// MaxGroups bounds one pass. Zero means every group the repository has.
	MaxGroups int
}

// RemediationStats is what one dispatch pass did.
type RemediationStats struct {
	// Claimable is how many findings policy would auto-remediate right now.
	Claimable int
	Groups    int
	Attempted int
	PROpened  int
	Outcomes  map[remediate.Outcome]int
	// Unmatched names findings policy could not decide about. A hole in the
	// table is loud and does not stop the pass (VM-F-405).
	Unmatched []string
	// Deferred counts groups left for the next pass because the bound was
	// reached, so a repository with more work than one pass allows says so
	// rather than looking finished.
	Deferred int
}

// RemediationPass dispatches remediation for a repository's claimable work.
//
// This is the step between a decision and an attempt, and its absence was a
// hole the producer-coverage audit walked into (OQ-AUDIT-05): policy routed
// findings to auto_remediate, the remediation worker claimed findings from
// TRIAGED, and NOTHING connected the two. No pull request record, no repository
// lock and no remediation branch had a producer in a full pipeline run — the
// types existed, consumers read them, and only hand-built fixtures ever wrote
// them.
//
// The pass re-evaluates policy rather than trusting the routing decision
// recorded earlier. A decision from the previous run may have been overtaken:
// the pull request may now exist, the finding may have been declined, the
// version may have moved. Re-deciding is cheap and deterministic; acting on a
// stale decision is how a declined finding gets re-remediated (VM-F-154).
func (o *Orchestrator) RemediationPass(ctx context.Context, req RemediationRequest) (RemediationStats, error) {
	stats := RemediationStats{Outcomes: map[remediate.Outcome]int{}}
	if req.Worker == nil || req.Policy == nil {
		return stats, fmt.Errorf("orchestrator: remediation pass needs a worker and a policy engine")
	}

	queued, err := o.Store.ListFindings(ctx, store.Query{
		Scope: store.ScopeOpen, Repo: req.Repo.Name,
		States: []model.State{model.Triaged},
	})
	if err != nil {
		return stats, err
	}
	sort.Slice(queued, func(i, j int) bool { return queued[i].Fingerprint < queued[j].Fingerprint })

	pr := policy.Repo{
		Name: req.Repo.Name, Tier: req.Repo.Tier,
		Language:     policy.Language(primaryLanguage(req.Repo)),
		HasTestSuite: req.Repo.HasTestSuite,
	}

	byClass := map[policy.Class][]model.Finding{}
	for _, f := range queued {
		decision, err := req.Policy.Evaluate(f, pr, req.View)
		if err != nil {
			stats.Unmatched = append(stats.Unmatched, f.Fingerprint)
			continue
		}
		if decision.Outcome != policy.AutoRemediate {
			continue
		}
		stats.Claimable++
		class := policy.ClassOf(f)
		byClass[class] = append(byClass[class], f)
	}

	classes := make([]policy.Class, 0, len(byClass))
	for c := range byClass {
		classes = append(classes, c)
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })

	for _, class := range classes {
		groups := remediate.Group(req.Repo.Name, byClass[class], class, req.Groups)
		for _, g := range groups {
			stats.Groups++
			if req.MaxGroups > 0 && stats.Attempted >= req.MaxGroups {
				stats.Deferred++
				continue
			}
			stats.Attempted++
			res, err := req.Worker.Remediate(ctx, g)
			if err != nil {
				return stats, fmt.Errorf("remediating %s group %s: %w", req.Repo.Name, g.ID, err)
			}
			stats.Outcomes[res.Outcome]++
			if res.Outcome == remediate.OutcomePROpen {
				stats.PROpened++
			}
		}
	}

	sort.Strings(stats.Unmatched)
	return stats, nil
}
