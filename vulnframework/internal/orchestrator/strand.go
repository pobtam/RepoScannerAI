package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// SyncStats is what a pull request reconciliation pass did.
type SyncStats struct {
	// Examined counts pull requests the pass ASKED the remote about. With the
	// webhook delivering, this is near zero on a healthy sweep — which is the
	// point of OQ-P12-01, and the reason it is reported rather than inferred.
	Examined int
	Merged   int
	Declined int
	// Confirmed counts pull requests found still open, and therefore vouched
	// for until the next horizon.
	Confirmed int
	// Deferred counts unconfirmed pull requests this pass did not reach,
	// because the batch bound or the rate budget stopped it. A pass that
	// silently reached fewer than it meant to would look like a quiet fleet.
	Deferred int
	// WebhookLive reports whether a verified delivery arrived inside the
	// silence window. False means this pass fell back to asking about
	// everything, which is recorded loudly rather than left to be noticed.
	WebhookLive bool
	// Lost counts closures the remote knew about and no webhook reported. Each
	// one is a delivery that did not arrive, and a fleet with a steady stream
	// of them has a delivery problem, not a reconciliation success.
	Lost int
}

// ReconcileConfig parameterises the fallback reconciliation (OQ-P12-01).
type ReconcileConfig struct {
	PR   gh.PROps
	Repo string

	// Horizon is how long a pull request's state may go unconfirmed while the
	// webhook path is live. Zero means the default.
	//
	// It is a fallback interval, not a polling interval: with deliveries
	// arriving, every open pull request is confirmed by its own events and
	// nothing is asked about at all.
	Horizon time.Duration

	// Silence is how long without ANY verified delivery before the webhook
	// path is treated as not delivering. Zero means the default.
	Silence time.Duration

	// MaxChecks bounds one pass. Zero means the default. The bound is what
	// turns an unbounded fan-out over every open pull request into a fixed
	// cost per sweep; Deferred says what it did not reach.
	MaxChecks int
}

// Reconcile defaults, chosen so a live webhook costs nothing and a dead one is
// noticed within one sweep.
const (
	DefaultReconcileHorizon = 6 * time.Hour
	DefaultWebhookSilence   = 30 * time.Minute
	DefaultReconcileChecks  = 25
)

func (c ReconcileConfig) horizon() time.Duration {
	if c.Horizon > 0 {
		return c.Horizon
	}
	return DefaultReconcileHorizon
}

func (c ReconcileConfig) silence() time.Duration {
	if c.Silence > 0 {
		return c.Silence
	}
	return DefaultWebhookSilence
}

func (c ReconcileConfig) maxChecks() int {
	if c.MaxChecks > 0 {
		return c.MaxChecks
	}
	return DefaultReconcileChecks
}

// ReconcilePullRequests is the FALLBACK path for pull request state
// (OQ-P12-01, VM-F-545).
//
// The webhook is primary: a verified delivery confirms the pull request it
// names, and ApplyWebhook drives the transition promptly. This pass exists for
// what the webhook cannot cover — a lost delivery, an endpoint that was down, a
// secret rotated without the App being told, an event for a repository
// installed after the fact.
//
// What changed when the webhook arrived is the SHAPE of the fallback. It used
// to ask the remote about every open pull request on every sweep: one API call
// per pull request per sweep, forever, to re-learn what the webhook had already
// said. Now it asks only about pull requests nothing has vouched for since the
// horizon, oldest first, in a bounded batch, and each call draws on the rate
// budget like any other remote call — so the cost of the fallback is fixed
// rather than proportional to the fleet.
//
// It fails CLOSED. If no verified delivery has arrived inside the silence
// window, the webhook path is not delivering, the horizon collapses to zero,
// and the pass reverts to asking about everything — loudly, because a silent
// fallback to full polling is a broken delivery path that nobody finds out
// about until the bill or the audit.
func (o *Orchestrator) ReconcilePullRequests(ctx context.Context, cfg ReconcileConfig) (SyncStats, error) {
	var stats SyncStats
	if cfg.PR == nil {
		return stats, nil
	}
	now := o.clock()

	health, err := o.Store.WebhookHealth(ctx)
	if err != nil {
		return stats, err
	}
	stats.WebhookLive = health.Live(now, cfg.silence())

	// A live webhook vouches for everything it has spoken about recently; a
	// silent one vouches for nothing.
	since := now.Add(-cfg.horizon())
	if !stats.WebhookLive {
		since = now
		o.Recovery.Record(RecoveryEvent{
			Kind: RecoveryWebhookSilent, Repo: cfg.Repo,
			Reason: fmt.Sprintf("no verified webhook delivery in the last %s (last: %s); "+
				"reconciliation is asking the remote about every open pull request, which is the "+
				"fallback working and the delivery path not",
				cfg.silence(), lastDelivery(health)),
			At: now,
		})
	}

	due, err := o.Store.UnconfirmedRemediationPRs(ctx, cfg.Repo, since, cfg.maxChecks())
	if err != nil {
		return stats, err
	}

	for _, rec := range due {
		// The fallback pays for itself out of the same budget as everything
		// else. An unbudgeted reconciliation is how a rate limit arrives
		// during a sweep instead of before one.
		if err := o.Budget.Acquire(o.Config.CreditsPerScan); err != nil {
			var exhausted *ErrBudgetExhausted
			if errors.As(err, &exhausted) {
				stats.Deferred += len(due) - stats.Examined
				o.Recovery.Record(RecoveryEvent{
					Kind: RecoveryWebhookSilent, Repo: cfg.Repo,
					Reason: fmt.Sprintf("the rate budget stopped reconciliation after %d of %d "+
						"unconfirmed pull requests; the rest are deferred to the next sweep",
						stats.Examined, len(due)),
					At: now,
				})
				break
			}
			return stats, err
		}
		stats.Examined++

		remote, found, err := cfg.PR.GetPR(ctx, rec.Repo, rec.Number)
		o.Budget.Consume(o.Config.CreditsPerScan)
		if err != nil {
			// A remote that cannot be reached is not evidence about the pull
			// request. Skipping preserves the current state and leaves it
			// unconfirmed, so the next pass tries again; guessing would
			// decline findings because of an outage.
			continue
		}
		if !found {
			// The record points at a pull request the remote does not have.
			// That is the stranding sweep's case, not this one's: it has the
			// PR_OPEN findings in hand and the reason vocabulary for it.
			continue
		}
		if remote.State == "open" {
			if err := o.Store.ConfirmRemediationPR(ctx, rec.Branch, now); err != nil {
				return stats, err
			}
			stats.Confirmed++
			continue
		}

		// The same implementation the webhook uses. Two paths that can each
		// move a finding drift unless something holds them together, and the
		// drift is invisible until an outage switches the system from one to
		// the other.
		moved, err := o.applyPRClosure(ctx, rec, remote.Merged)
		if err != nil {
			return stats, err
		}
		if remote.Merged {
			stats.Merged += moved
		} else {
			stats.Declined += moved
		}
		stats.Lost++
		o.Recovery.Record(RecoveryEvent{
			Kind: RecoveryPRStateSync, Repo: rec.Repo,
			Reason: fmt.Sprintf("pull request %s was %s on the remote and no webhook reported it; "+
				"%d findings moved by reconciliation. A closure the webhook missed is a LOST "+
				"DELIVERY, not a success: the fallback caught it, and the delivery path did not",
				rec.URL, closedHow(remote), moved),
			At: now,
		})
	}
	return stats, nil
}

func lastDelivery(h store.WebhookHealth) string {
	if h.LastDeliveryAt.IsZero() {
		return "never"
	}
	return h.LastDeliveryAt.UTC().Format(time.RFC3339)
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
