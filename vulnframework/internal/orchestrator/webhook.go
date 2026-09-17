package orchestrator

import (
	"context"
	"fmt"

	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// ApplyWebhook drives the transition a verified webhook implies (VM-AD §7.4).
//
// The webhook makes a transition PROMPT. Reconciliation (Phase 9b) still makes
// it eventual, and both remain: a delivery can be lost, an endpoint can be
// down, a secret can be rotated without the App being told. The webhook is an
// accelerator, never the only path — a design that removed the fallback would
// be correct exactly as often as the network is.
//
// Both paths route through applyPRClosure, which is what keeps them from
// diverging. Two code paths that can each move a finding will drift unless
// something holds them together, and the drift would be invisible until an
// outage switched the system from one to the other.
func (o *Orchestrator) ApplyWebhook(ctx context.Context, ev gh.Event) (SyncStats, error) {
	var stats SyncStats

	switch ev.Kind {
	case gh.EventPullRequestClosed:
		rec, ok, err := o.Store.GetRemediationPR(ctx, ev.Branch)
		if err != nil {
			return stats, err
		}
		if !ok || !rec.Open() {
			// Not ours, or already settled. Not an error: this App receives
			// events for every pull request in every installed repository,
			// and most of them are nothing to do with remediation.
			return stats, nil
		}
		if rec.Number != ev.Number || rec.Repo != ev.Repo {
			// The branch is ours and the identifiers do not match. Refusing
			// rather than trusting the event: a delivery that disagrees with
			// the record is either a misconfiguration or forged.
			return stats, fmt.Errorf(
				"gh: webhook for %s#%d does not match the recorded pull request %s#%d on branch %s",
				ev.Repo, ev.Number, rec.Repo, rec.Number, ev.Branch)
		}

		moved, err := o.applyPRClosure(ctx, rec, ev.Merged)
		if err != nil {
			return stats, err
		}
		stats.Examined = 1
		if ev.Merged {
			stats.Merged = moved
		} else {
			stats.Declined = moved
		}
		o.Recovery.Record(RecoveryEvent{
			Kind: RecoveryPRStateSync, Repo: rec.Repo,
			Reason: fmt.Sprintf("webhook: pull request %s was %s; %d findings moved promptly rather "+
				"than at the next sweep", rec.URL, closedHow(gh.PullRequest{Merged: ev.Merged}), moved),
			At: o.clock(),
		})
		return stats, nil

	default:
		return stats, nil
	}
}

// applyPRClosure is the single implementation both the webhook and
// reconciliation use.
//
// MERGED, never VERIFIED. A merge is a claim about intent; only a scan of the
// merged default branch that no longer observes the finding is evidence
// (VM-F-533, VM-ADR-12). The webhook makes the framework learn sooner; it does
// not make it learn more.
func (o *Orchestrator) applyPRClosure(ctx context.Context, rec store.RemediationPR, merged bool) (int, error) {
	now := o.clock()

	to, reason := model.Declined, model.ReasonDeclined
	if merged {
		to, reason = model.Merged, model.ReasonCode("")
	}

	moved := 0
	for _, fp := range rec.Findings {
		f, err := o.Store.GetFinding(ctx, fp)
		if err != nil {
			return moved, err
		}
		if f.State != model.PROpen {
			// The transition table is the last defence when the webhook
			// secret leaks: a finding that was never in PR_OPEN has no
			// pull request to close, whatever an event claims.
			continue
		}
		if reason != "" {
			if err := o.Store.SetPriority(ctx, fp, f.Priority, &reason); err != nil {
				return moved, err
			}
		}
		if err := o.Store.ApplyTransition(ctx, fp, to, model.TransitionContext{
			Actor: model.ActorOrchestrator,
			Cause: fmt.Sprintf("pull request %s was %s", rec.URL,
				closedHow(gh.PullRequest{Merged: merged})),
			At: now,
		}); err != nil {
			return moved, err
		}
		moved++
	}

	if err := o.Store.CloseRemediationPR(ctx, rec.Branch, now, merged); err != nil {
		return moved, err
	}
	return moved, nil
}
