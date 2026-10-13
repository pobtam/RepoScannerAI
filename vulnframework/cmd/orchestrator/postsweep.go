package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/wanaware/vulnframework/internal/feed"
	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/triage"
)

// postSweep is what turns a sweep's detected findings into decided ones:
// exploitation intelligence, a triage narrative where one can be had, a
// priority, an SLA position and a policy outcome — the same steps
// internal/demo runs after each of its sweeps.
//
// Before this pass existed nothing outside the demo and the fleet test called
// EnrichPass or TriageAndRoute, so every finding a real sweep found stayed
// DETECTED forever: unscored, unrouted, and absent from every SLA count.
//
// It deliberately stops at the decision. The demo goes on to TicketPass and
// RemediationPass; this pass does NOT, and must not be extended to. A ticket
// is written to an external tracker and a remediation opens a pull request;
// this deployment is read-only against everything but its own store. A
// finding routed to open_ticket lands in NEEDS_HUMAN with the deciding rule
// recorded, and one routed to auto_remediate stays TRIAGED with its reason —
// both visible in the interface, neither acted on.
type postSweep struct {
	Orch    *orchestrator.Orchestrator
	Feeds   feed.Multi
	Triager *triage.Triager
	Scorer  *score.Scorer
	Policy  *policy.Engine
	View    policy.StoreView
	Log     *slog.Logger
}

// RepoPass is one repository's post-sweep outcome.
type RepoPass struct {
	Repo   string                   `json:"repo"`
	Enrich orchestrator.EnrichStats `json:"enrich"`
	Triage orchestrator.TriageStats `json:"triage"`
	// NarrativeUnavailable says why this repository's findings carry no
	// triage narrative, when they do not.
	NarrativeUnavailable string `json:"narrative_unavailable,omitempty"`
}

// PostSweepStats is the whole pass.
type PostSweepStats struct {
	RunID string     `json:"run_id"`
	Repos []RepoPass `json:"repos"`
	// NotScanned are planned repositories for which no scanner completed in
	// this run — failed, deferred, or a worker that never reported. They are
	// left alone: nothing new was observed in them, and the sweep's own
	// coverage accounting already names them.
	NotScanned []string `json:"not_scanned,omitempty"`
	// OverdueProposals counts, per repository, suppression proposals nobody
	// reviewed inside the secret SLA window, escalated again this pass.
	OverdueProposals map[string]int `json:"overdue_proposals,omitempty"`
}

// Run applies the pass to every repository the run scanned.
func (p *postSweep) Run(ctx context.Context, runID string, repos []store.Repo) (PostSweepStats, error) {
	out := PostSweepStats{RunID: runID}
	for _, repo := range repos {
		// Overdue review is a matter of time, not of this run's scan: a
		// proposal ages whether or not its repository was reached.
		n, err := p.Orch.EscalateOverdueProposals(ctx, repo)
		if err != nil {
			return out, fmt.Errorf("escalating overdue proposals in %s: %w", repo.Name, err)
		}
		if n > 0 {
			if out.OverdueProposals == nil {
				out.OverdueProposals = map[string]int{}
			}
			out.OverdueProposals[repo.Name] = n
			p.Log.Warn("suppression proposals unreviewed past the secret SLA window were escalated",
				"repo", repo.Name, "count", n)
		}

		scanned, err := scannedIn(ctx, p.Orch.Store, repo.Name, runID)
		if err != nil {
			return out, err
		}
		if !scanned {
			out.NotScanned = append(out.NotScanned, repo.Name)
			continue
		}

		pass := RepoPass{Repo: repo.Name}
		if pass.Enrich, err = p.Orch.EnrichPass(ctx, p.Feeds, repo.Name); err != nil {
			return out, fmt.Errorf("enriching %s: %w", repo.Name, err)
		}

		pass.Triage, err = p.Orch.TriageAndRoute(ctx, repo, p.Triager, p.Scorer, p.Policy, p.View)
		if err != nil && p.Triager.Unavailable == "" {
			// Inference failed — an outage, a rejected key, a rate limit. The
			// run is never blocked on triage (VM-AD §9.3): score and route
			// without the narrative, and say why. TriageAndRoute fails before
			// it writes anything when inference fails, so the retry starts
			// from the same state.
			reason := fmt.Sprintf("AI triage failed for this repository: %v", err)
			p.Log.Warn("triage unavailable; scoring and routing without a narrative",
				"repo", repo.Name, "error", err)
			fallback := &triage.Triager{Cache: p.Triager.Cache, Unavailable: reason}
			pass.Triage, err = p.Orch.TriageAndRoute(ctx, repo, fallback, p.Scorer, p.Policy, p.View)
		}
		if err != nil {
			return out, fmt.Errorf("triage and route %s: %w", repo.Name, err)
		}
		pass.NarrativeUnavailable = pass.Triage.Triage.Unavailable
		out.Repos = append(out.Repos, pass)
	}
	return out, nil
}

// scannedIn reports whether at least one scanner completed for the repository
// in the run. Every planned repository gets a result row, including one whose
// worker never reported, so the row alone is not evidence of a scan.
func scannedIn(ctx context.Context, st store.Store, repo, runID string) (bool, error) {
	results, err := st.ScanResults(ctx, repo, 1)
	if err != nil {
		return false, fmt.Errorf("reading scan results for %s: %w", repo, err)
	}
	if len(results) == 0 || results[0].RunID != runID {
		return false, nil
	}
	switch results[0].Outcome {
	case model.ScanComplete, model.ScanPartial:
		return true, nil
	}
	return false, nil
}

// storeView answers the policy engine's two questions from the store and the
// first-party registry.
type storeView struct {
	ctx      context.Context
	st       store.Store
	registry *firstparty.Registry
	log      *slog.Logger
}

// HasOpenPullRequest asks the store. Nothing in this deployment opens pull
// requests, so the answer is no unless the store was shared with one that
// did — in which case the honest answer is that store's.
func (v storeView) HasOpenPullRequest(fingerprint string) bool {
	_, open, err := v.st.RemediationPRForFinding(v.ctx, fingerprint)
	if err != nil {
		// Unknown is treated as in progress: policy then skips the finding,
		// which changes nothing and is retried next run, rather than routing
		// it on a guess.
		v.log.Error("reading remediation pull requests", "fingerprint", fingerprint, "error", err)
		return true
	}
	return open
}

// IsFirstPartyOwner asks the registry. Policy asks it only of findings with a
// first-party path, which the sweep sets only when a registry is configured
// (-firstparty); with none, nothing is first-party and the answer is moot.
func (v storeView) IsFirstPartyOwner(repo, modulePath string) bool {
	if v.registry == nil {
		return false
	}
	module, ok := v.registry.Module(modulePath)
	if !ok {
		return false
	}
	owner, ok := v.registry.Owner(module)
	return ok && owner == repo
}
