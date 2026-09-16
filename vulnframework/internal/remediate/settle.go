package remediate

import (
	"context"
	"fmt"
	"time"

	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// SettleStats is what a settle pass did.
type SettleStats struct {
	Examined       int
	PRsClosed      int
	LeasesReleased int
}

// Settle carries out the side effects a state change cannot (OQ-P2-01).
//
// A finding verifies inside the store: a successful scan stopped seeing it, and
// `Reconcile` moved it to VERIFIED with an honest reason. But a finding can be
// fixed by hand while the framework holds a lease on it and has a pull request
// open, and two things then live OUTSIDE the findings store and have to be
// cleaned up:
//
//	The pull request is now moot. Leaving it open asks a reviewer to review a
//	fix for something already fixed, and they will reasonably conclude the
//	tooling is noise.
//
//	The lease is stuck. Nothing will release it, because the worker that took
//	it is gone or is about to find its work irrelevant, and a held lease keeps
//	the finding out of every later sweep.
//
// The attribution is the part worth stating plainly: the framework's pull
// request was never merged, so the reason is `external` and the closing comment
// claims no credit.
func Settle(ctx context.Context, s store.Store, prOps gh.PROps, repo string, now time.Time) (SettleStats, error) {
	var stats SettleStats

	resolved, err := s.ListFindings(ctx, store.Query{
		Scope: store.ScopeAll, Repo: repo,
		States: model.StatesInPartition(model.PartitionResolved),
	})
	if err != nil {
		return stats, err
	}

	for _, f := range resolved {
		stats.Examined++

		// The lease first: it is the thing that blocks future work, so it is
		// released even if closing the pull request fails.
		if lease, err := s.GetLease(ctx, f.Fingerprint); err != nil {
			return stats, err
		} else if lease.Held() {
			if err := s.ReleaseLease(ctx, f.Fingerprint); err != nil {
				return stats, err
			}
			stats.LeasesReleased++
		}

		pr, ok, err := s.RemediationPRForFinding(ctx, f.Fingerprint)
		if err != nil {
			return stats, err
		}
		if !ok || !pr.Open() {
			continue
		}
		// A pull request covers a fix group, so it is closed only when every
		// finding it addresses is resolved. Closing it while one member is
		// still open would discard a fix for that member.
		stillOpen, err := anyUnresolved(ctx, s, pr.Findings)
		if err != nil {
			return stats, err
		}
		if stillOpen {
			continue
		}

		if err := prOps.ClosePR(ctx, pr.Repo, pr.Number, closureComment(f)); err != nil {
			return stats, fmt.Errorf("remediate: closing pull request %s#%d: %w", pr.Repo, pr.Number, err)
		}
		if err := s.CloseRemediationPR(ctx, pr.Branch, now); err != nil {
			return stats, err
		}
		stats.PRsClosed++
	}
	return stats, nil
}

func anyUnresolved(ctx context.Context, s store.Store, fingerprints []string) (bool, error) {
	for _, fp := range fingerprints {
		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			return false, err
		}
		if model.PartitionOf(f.State) != model.PartitionResolved {
			return true, nil
		}
	}
	return false, nil
}

// closureComment says why the pull request is being closed, and by whom the
// finding was actually fixed.
func closureComment(f model.Finding) string {
	reason := model.VerifiedExternal
	if f.VerifiedReason != nil {
		reason = *f.VerifiedReason
	}

	switch reason {
	case model.VerifiedByFrameworkMerge:
		return "Closing: the findings this addressed are verified fixed, by this framework's own merge. " +
			"`verified_reason=framework_merge`"
	case model.VerifiedByUpstream:
		return "Closing: the findings this addressed are verified fixed by an upstream first-party change, " +
			"so this pull request is no longer needed. `verified_reason=upstream`"
	default:
		return "Closing: a successful scan no longer reports the findings this addressed — they were fixed " +
			"outside this framework, or the code carrying them was removed. This pull request was never " +
			"merged and this framework claims no credit for the fix. `verified_reason=external`\n\n" +
			"_Closure required a successful scan. A finding that merely stopped being reported, because a " +
			"scan failed or did not run, is retained rather than resolved (VM-ADR-12)._"
	}
}
