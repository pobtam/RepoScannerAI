package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// FleetDriftReport is the difference between GitHub and the registry.
type FleetDriftReport struct {
	// Unsynced are repositories that exist on GitHub and are absent from the
	// registry. They are the dangerous half: absent from the registry means
	// absent from planned scope, which means absent from the coverage
	// DENOMINATOR — the fleet reports full coverage while never having looked
	// at them (A18, OQ-P2-02).
	Unsynced []string `json:"unsynced,omitempty"`
	// Vanished are registry entries GitHub no longer lists.
	Vanished []string `json:"vanished,omitempty"`
}

// Clean reports whether the registry matches GitHub.
func (r FleetDriftReport) Clean() bool { return len(r.Unsynced) == 0 && len(r.Vanished) == 0 }

// Summary names what drifted, because a count tells nobody what to do.
func (r FleetDriftReport) Summary() string {
	if r.Clean() {
		return "fleet registry matches GitHub"
	}
	var b strings.Builder
	b.WriteString("fleet registry has drifted from GitHub: ")
	if len(r.Unsynced) > 0 {
		fmt.Fprintf(&b, "%d repositories exist and are NOT in the registry (%s) — they are outside "+
			"the coverage denominator entirely, so the fleet reports full coverage while never having "+
			"scanned them; ", len(r.Unsynced), strings.Join(r.Unsynced, ", "))
	}
	if len(r.Vanished) > 0 {
		fmt.Fprintf(&b, "%d registry entries GitHub no longer lists (%s); ",
			len(r.Vanished), strings.Join(r.Vanished, ", "))
	}
	return strings.TrimSuffix(b.String(), "; ")
}

// FleetDrift compares GitHub against the registry WITHOUT changing anything.
//
// Read-only on purpose. The drift has to be observable before it is corrected,
// because a sync that silently fixed it would leave nobody any way to notice
// that a repository had been invisible for a week.
func (o *Orchestrator) FleetDrift(ctx context.Context, app gh.App) (FleetDriftReport, error) {
	var report FleetDriftReport

	remote, err := app.Repositories(ctx)
	if err != nil {
		return report, fmt.Errorf("orchestrator: listing repositories: %w", err)
	}
	known, err := o.Store.RepoNames(ctx)
	if err != nil {
		return report, err
	}

	inRegistry := make(map[string]bool, len(known))
	for _, n := range known {
		inRegistry[n] = true
	}
	onGitHub := make(map[string]bool, len(remote))
	for _, r := range remote {
		onGitHub[r.FullName] = true
		if !inRegistry[r.FullName] {
			report.Unsynced = append(report.Unsynced, r.FullName)
		}
	}
	for _, n := range known {
		if !onGitHub[n] {
			report.Vanished = append(report.Vanished, n)
		}
	}
	sort.Strings(report.Unsynced)
	sort.Strings(report.Vanished)
	return report, nil
}

// FleetSyncStats is what a sync changed.
type FleetSyncStats struct {
	Seen     int `json:"seen"`
	Added    int `json:"added"`
	Updated  int `json:"updated"`
	Archived int `json:"archived"`
}

// SyncFleet brings the registry into line with GitHub (A18, VM-OQ-10).
//
// Two refusals, both about the same failure: an empty or error result is not
// evidence of an empty fleet.
//
// A repository GitHub no longer lists is ARCHIVED rather than deleted.
// Deleting it would make historical coverage unreadable — every run that
// scanned it would reference a repository nobody can look up — while archiving
// takes it out of the denominator and keeps the record.
func (o *Orchestrator) SyncFleet(ctx context.Context, app gh.App) (FleetSyncStats, error) {
	var stats FleetSyncStats

	remote, err := app.Repositories(ctx)
	if err != nil {
		return stats, fmt.Errorf("orchestrator: listing repositories: %w", err)
	}
	known, err := o.Store.RepoNames(ctx)
	if err != nil {
		return stats, err
	}

	if len(remote) == 0 && len(known) > 0 {
		// The most destructive thing this function could do, and the input
		// that would cause it is indistinguishable from an ordinary outage.
		return stats, &gh.ErrEmptyFleet{Known: len(known)}
	}
	stats.Seen = len(remote)

	inRegistry := make(map[string]bool, len(known))
	for _, n := range known {
		inRegistry[n] = true
	}
	onGitHub := make(map[string]bool, len(remote))

	for _, r := range remote {
		onGitHub[r.FullName] = true
		existing, err := o.Store.GetRepo(ctx, r.FullName)
		isNew := err != nil

		repo := store.Repo{
			Name:         r.FullName,
			Languages:    normaliseLanguages(r.Languages),
			Archived:     r.Archived,
			Codeowners:   r.Codeowners,
			HasTestSuite: existing.HasTestSuite,
			HasLockfile:  existing.HasLockfile,
			Tier:         existing.Tier,
		}
		if repo.Tier == 0 {
			// Unclassified repositories get the strictest tier, not the most
			// permissive: VM-OQ-01 is open, and defaulting to lenient would
			// let an unclassified production service be treated as a
			// scratch repository.
			repo.Tier = 3
		}
		if err := o.Store.UpsertRepo(ctx, repo); err != nil {
			return stats, err
		}
		if isNew {
			stats.Added++
			o.Recovery.Record(RecoveryEvent{
				Kind: RecoveryFleetSync, Repo: r.FullName,
				Reason: "repository exists on GitHub and was absent from the registry: it was outside " +
					"the coverage denominator until this sync",
				At: o.clock(),
			})
		} else {
			stats.Updated++
		}
	}

	for _, n := range known {
		if onGitHub[n] {
			continue
		}
		existing, err := o.Store.GetRepo(ctx, n)
		if err != nil || existing.Archived {
			continue
		}
		existing.Archived = true
		if err := o.Store.UpsertRepo(ctx, existing); err != nil {
			return stats, err
		}
		stats.Archived++
		o.Recovery.Record(RecoveryEvent{
			Kind: RecoveryFleetSync, Repo: n,
			Reason: "GitHub no longer lists this repository; archived rather than deleted so its " +
				"historical scan results remain readable",
			At: o.clock(),
		})
	}
	return stats, nil
}

// normaliseLanguages lowercases GitHub's language names to the framework's.
func normaliseLanguages(in []string) []string {
	out := make([]string, 0, len(in))
	for _, l := range in {
		out = append(out, strings.ToLower(l))
	}
	sort.Strings(out)
	return out
}

// --- VM-F-614: merged without publish ---------------------------------------

// PublishWatch is one upstream fix being watched for publication.
type PublishWatch struct {
	Owner  string
	Branch string
	Module string
	// Grace is how long after the merge to wait before escalating. A release
	// job that runs minutes after a merge must not page anyone.
	Grace time.Duration
}

// PublishEscalation is a Wave 1 fix that merged and never shipped.
type PublishEscalation struct {
	Owner            string        `json:"owner"`
	Module           string        `json:"module"`
	Branch           string        `json:"branch"`
	MergedAgo        time.Duration `json:"merged_ago"`
	BlockedConsumers int           `json:"blocked_consumers"`
	Reason           string        `json:"reason"`
}

// DetectMergedWithoutPublish covers VM-F-614.
//
// The specification calls this "the most common silent failure of the two-wave
// design", and the reason it is silent is that every individual signal is
// correct. The pull request merged — true. The upstream finding is handled —
// true. The consumers are blocked on an upstream fix — true. Nothing is
// inconsistent; the combination is simply a fleet that has stopped moving, and
// no single check would notice.
func (o *Orchestrator) DetectMergedWithoutPublish(ctx context.Context, app gh.App, watch PublishWatch) ([]PublishEscalation, error) {
	rec, ok, err := o.Store.GetRemediationPR(ctx, watch.Branch)
	if err != nil {
		return nil, err
	}
	if !ok || !rec.Merged || rec.ClosedAt == nil {
		return nil, nil
	}

	now := o.clock()
	mergedAgo := now.Sub(*rec.ClosedAt)
	if mergedAgo < watch.Grace {
		return nil, nil
	}

	tags, err := app.Tags(ctx, watch.Owner)
	if err != nil {
		// An unreachable App is not evidence that no tag was published.
		return nil, nil
	}
	for _, t := range tags {
		if t.At.After(*rec.ClosedAt) {
			return nil, nil
		}
	}

	blocked, err := o.Store.ListFindings(ctx, store.Query{
		Scope: store.ScopeOpen, States: []model.State{model.BlockedUpstream},
	})
	if err != nil {
		return nil, err
	}

	e := PublishEscalation{
		Owner: watch.Owner, Module: watch.Module, Branch: watch.Branch,
		MergedAgo: mergedAgo, BlockedConsumers: len(blocked),
		Reason: fmt.Sprintf(
			"the Wave 1 fix to %s merged %s ago and no tag has been published since. Where the "+
				"wave 2 trigger is a tag, merging releases nothing: %d consumers remain blocked on a "+
				"fix that exists and has not shipped. Every signal here is individually correct, which "+
				"is why nothing else notices (VM-F-614)",
			watch.Module, mergedAgo.Round(time.Hour), len(blocked)),
	}

	o.Recovery.Record(RecoveryEvent{
		Kind: RecoveryMergedWithoutPublish, Repo: watch.Owner,
		Reason: e.Reason, At: now,
	})
	return []PublishEscalation{e}, nil
}
