package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// SyncStats is what a pull request state-sync did.
type SyncStats struct {
	Examined int
	Merged   int
	Declined int
}

// SyncPullRequests reconciles open remediation pull requests against the remote
// (VM-F-545, OQ-P9a-02).
//
// The framework ASKS rather than waiting to be told. There is no webhook yet,
// and without this a human closing a remediation pull request leaves its
// findings in PR_OPEN indefinitely: policy rule 2 skips them as in progress,
// nothing escalates them, and nothing reports that anything is wrong. That is
// the same silent-strand shape as a lease nobody releases, one layer out.
//
// A webhook (VM-AD §7.4) later only makes this prompt instead of eventual —
// the same reconciliation-driven, webhook-accelerated pattern as the
// disappearance trigger in §6.1.1.
func (o *Orchestrator) SyncPullRequests(ctx context.Context, prOps gh.PROps, repo string) (SyncStats, error) {
	var stats SyncStats

	open, err := o.Store.OpenRemediationPRs(ctx, repo)
	if err != nil {
		return stats, err
	}
	now := o.clock()

	for _, rec := range open {
		stats.Examined++

		remote, found, err := prOps.GetPR(ctx, rec.Repo, rec.Number)
		if err != nil {
			// A remote that cannot be reached is not evidence about the pull
			// request. Skipping preserves the current state; guessing would
			// decline findings because of an outage.
			continue
		}
		if !found || remote.State == "open" {
			continue
		}

		to, reason := model.Declined, model.ReasonDeclined
		if remote.Merged {
			// MERGED, never VERIFIED. A merge is a claim about intent; only a
			// scan of the merged default branch that no longer observes the
			// finding is evidence (VM-F-533, VM-ADR-12).
			to, reason = model.Merged, model.ReasonCode("")
		}

		moved := 0
		for _, fp := range rec.Findings {
			f, err := o.Store.GetFinding(ctx, fp)
			if err != nil {
				return stats, err
			}
			if f.State != model.PROpen {
				continue
			}
			if reason != "" {
				// Recorded before the transition, so a DECLINED finding is
				// never left without an explanation of who declined it.
				if err := o.Store.SetPriority(ctx, fp, f.Priority, &reason); err != nil {
					return stats, err
				}
			}
			if err := o.Store.ApplyTransition(ctx, fp, to, model.TransitionContext{
				Actor: model.ActorOrchestrator,
				Cause: fmt.Sprintf("pull request %s was %s on the remote", rec.URL, closedHow(remote)),
				At:    now,
			}); err != nil {
				return stats, err
			}
			moved++
		}

		if err := o.Store.CloseRemediationPR(ctx, rec.Branch, now, remote.Merged); err != nil {
			return stats, err
		}
		if remote.Merged {
			stats.Merged += moved
		} else {
			stats.Declined += moved
		}
		o.Recovery.Record(RecoveryEvent{
			Kind: RecoveryPRStateSync, Repo: rec.Repo,
			Reason: fmt.Sprintf("pull request %s was %s on the remote and no webhook reported it; "+
				"%d findings moved", rec.URL, closedHow(remote), moved),
			At: now,
		})
	}
	return stats, nil
}

func closedHow(pr gh.PullRequest) string {
	if pr.Merged {
		return "merged"
	}
	return "closed without merging"
}

// StrandSweep configures the stranding recovery sweep.
type StrandSweep struct {
	Repo string
	// PR is consulted before declaring a PR_OPEN finding stranded: a finding
	// whose pull request is genuinely open is not stranded, it is waiting.
	PR gh.PROps
}

// StrandStats is what a stranding sweep recovered.
type StrandStats struct {
	Examined  int
	Recovered int
	// Reasons names why each finding was stranded, so the sweep is diagnostic
	// rather than merely corrective: a sweep that quietly fixes the same
	// strand every hour is hiding a bug upstream of it.
	Reasons map[string]string
}

// SweepStranded recovers findings in an active-looking state that nothing can
// move.
//
// This is the general form of the defect Phase 9a found in one place. The
// question it answers for every finding is: if nothing else happens, WHAT moves
// this? A finding in AUTO_REMEDIATING or PR_OPEN is presented as being worked
// on — nothing escalates it, no human is asked about it, and policy rule 2
// skips it — so when the mechanism behind that appearance is gone, the finding
// drops out of the system in the least visible way possible. It looks exactly
// like a repository with nothing to do.
//
// The sweep is deliberately conservative: a finding is recovered only when
// NOTHING could move it. An in-flight worker holds a live lease; a real pull
// request is open on the remote. Both are left alone.
func (o *Orchestrator) SweepStranded(ctx context.Context, cfg StrandSweep) (StrandStats, error) {
	stats := StrandStats{Reasons: map[string]string{}}
	now := o.clock()

	findings, err := o.Store.ListFindings(ctx, store.Query{
		Scope: store.ScopeOpen, Repo: cfg.Repo,
		States: []model.State{model.AutoRemediating, model.PROpen},
	})
	if err != nil {
		return stats, err
	}

	for _, f := range findings {
		stats.Examined++

		stranded, why, err := o.isStranded(ctx, f, cfg, now)
		if err != nil {
			return stats, err
		}
		if !stranded {
			continue
		}

		// Back to TRIAGED: the work returns to the queue, where policy can act
		// on it again. Anything else — NEEDS_HUMAN, say — would move the state
		// without making the finding actionable, which is the same strand with
		// a different label.
		if err := o.Store.ApplyTransition(ctx, f.Fingerprint, model.Triaged, model.TransitionContext{
			Actor: model.ActorOrchestrator,
			Cause: "recovered from a stranded state: " + why,
			At:    now,
		}); err != nil {
			return stats, err
		}
		if err := o.Store.ReleaseLease(ctx, f.Fingerprint); err != nil {
			return stats, err
		}
		stats.Recovered++
		stats.Reasons[f.Fingerprint] = why
		// Recovery must be loud: recorded with enough context that the same
		// repository recovering every sweep is a visible recurring event
		// rather than an absorbed one.
		o.Recovery.Record(RecoveryEvent{
			Kind: RecoveryStranded, Repo: f.Repo, Fingerprint: f.Fingerprint,
			Reason: why, At: now,
		})
	}
	return stats, nil
}

// isStranded reports whether anything at all could still move this finding.
//
// Conservative by design: it answers "no" whenever a live mechanism exists,
// because recovering a finding a worker is actively fixing would cause the
// duplicate work the lock exists to prevent.
func (o *Orchestrator) isStranded(ctx context.Context, f model.Finding, cfg StrandSweep, now time.Time) (bool, string, error) {
	lease, err := o.Store.GetLease(ctx, f.Fingerprint)
	if err != nil {
		return false, "", err
	}

	switch f.State {
	case model.AutoRemediating:
		if lease.Held() && !lease.Expired(now) {
			// A worker is on it. Its own failure path or the lease sweeper
			// will deal with it.
			return false, "", nil
		}
		if lease.Held() {
			return true, "the lease held by " + lease.Owner + " expired and was never reclaimed", nil
		}
		return true, "no lease is held, so the lease sweeper has nothing to find and policy skips it as in progress", nil

	case model.PROpen:
		rec, ok, err := o.Store.RemediationPRForFinding(ctx, f.Fingerprint)
		if err != nil {
			return false, "", err
		}
		if !ok {
			return true, "no pull request record exists, so no state-sync can ever discover what became of it", nil
		}
		if cfg.PR == nil {
			// Cannot check the remote: assume the pull request is real rather
			// than discarding work on no evidence.
			return false, "", nil
		}
		_, found, err := cfg.PR.GetPR(ctx, rec.Repo, rec.Number)
		if err != nil {
			// An unreachable remote is not evidence.
			return false, "", nil
		}
		if !found {
			return true, "the recorded pull request does not exist on the remote", nil
		}
		// A genuinely open pull request is not a strand: it is waiting for a
		// human, which is a mechanism. A closed one is SyncPullRequests' job,
		// not this sweep's — handling it here would race with that and could
		// return a merged finding to the queue.
		return false, "", nil

	default:
		return false, "", nil
	}
}
