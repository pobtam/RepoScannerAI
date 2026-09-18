package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/wanaware/vulnframework/internal/feed"
	"github.com/wanaware/vulnframework/internal/store"
)

// EnrichStats is what one exploitation-intelligence pass learned.
type EnrichStats struct {
	// Findings is how many findings were in scope.
	Findings int
	// Identifiers is how many distinct identifiers were asked about, which is
	// smaller than Findings whenever a fleet shares an advisory — and that
	// ratio is the reason the lookup is keyed by identifier.
	Identifiers int
	// Answered and Unknown partition the identifiers. Unknown is not a
	// failure: most identifiers are in neither catalogue.
	Answered int
	Unknown  int
	// SourcesDown names feeds that could not answer at all. A pass where every
	// source is down learned NOTHING, and must never be recorded as a pass
	// where nothing was found (OQ-AUDIT-01).
	SourcesDown []string
	// Malformed counts published rows that could not be believed and were
	// dropped rather than repaired.
	Malformed int
	// Stored is how many intelligence rows were written.
	Stored int
}

// Degraded reports whether this pass ran without some of its sources.
func (s EnrichStats) Degraded() bool { return len(s.SourcesDown) > 0 }

// EnrichPass refreshes exploitation intelligence for a repository's open
// findings (OQ-AUDIT-01(b), VM-AD §9.4).
//
// It runs BEFORE scoring, and scoring reads what it wrote. That ordering is the
// whole point: the scorer declares KEV and EPSS among its five inputs, and
// until this pass existed neither had a producer, so every score in the system
// was computed from three inputs while presenting as a score.
//
// Keyed by IDENTIFIER, not by finding, and asked in ONE batch per source. Both
// feeds are published as whole files; a request per finding would be a request
// per finding per run against a third-party endpoint, which is how a rate limit
// is discovered in production rather than in a test.
//
// Every identifier of every finding is offered, aliases included. The feeds are
// CVE-keyed while this framework's findings are keyed by GO- and GHSA-
// identifiers as often as not, so asking only about primary identifiers would
// report "no exploitation data" for most Go advisories — which is
// indistinguishable, in the score, from "checked, not exploited".
func (o *Orchestrator) EnrichPass(ctx context.Context, sources feed.Multi, repo string) (EnrichStats, error) {
	var stats EnrichStats
	if len(sources.Sources) == 0 {
		// No feeds configured. Deliberately not an error, and deliberately not
		// silent either: the caller learns that nothing was enriched, and
		// every score computed afterwards names EPSS and KEV as unavailable
		// rather than scoring them as zero.
		return stats, nil
	}
	now := o.clock()
	if sources.Clock == nil {
		sources.Clock = o.clock
	}

	findings, err := o.Store.ListFindings(ctx, store.Query{Scope: store.ScopeOpen, Repo: repo})
	if err != nil {
		return stats, err
	}
	stats.Findings = len(findings)

	seen := map[string]bool{}
	var ids []string
	for _, f := range findings {
		for _, id := range store.IntelIDs(f) {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	stats.Identifiers = len(ids)
	if len(ids) == 0 {
		return stats, nil
	}

	answers, look, err := sources.Lookup(ctx, ids)
	if err != nil {
		return stats, fmt.Errorf("enriching %s: %w", repo, err)
	}
	stats.Answered, stats.Unknown = look.Answered, look.Unknown
	stats.SourcesDown, stats.Malformed = look.SourcesDown, look.Malformed

	if len(look.SourcesDown) > 0 {
		// Recovery must be loud, and so must degradation. A pass that scored a
		// fleet without the exploitation feeds and said nothing would leave
		// every priority in that run quietly narrower than the ones around it.
		o.Recovery.Record(RecoveryEvent{
			Kind: RecoveryFeedUnavailable, Repo: repo,
			Reason: fmt.Sprintf("exploitation intelligence source(s) %v could not answer; "+
				"%d identifiers were asked about and every score computed from this pass names "+
				"the missing input rather than treating it as zero",
				look.SourcesDown, len(ids)),
			At: now,
		})
	}

	rows := make([]store.Intel, 0, len(answers))
	for id, a := range answers {
		if !a.Known() {
			continue
		}
		row := store.Intel{
			ID: id, EPSS: a.EPSS, EPSSAvailable: a.EPSSAvailable,
			KEV: a.KEV, KEVAvailable: a.KEVAvailable,
			FetchedAt: now, Sources: sourceNames(sources),
		}
		if a.EPSSAvailable {
			at := a.EPSSAsOf
			row.EPSSAsOf = &at
		}
		if a.KEVAvailable {
			at := a.KEVAsOf
			row.KEVAsOf = &at
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })

	// An identifier nothing answered about is NOT written as a row.
	//
	// Writing "we asked and learned nothing" would be a lie of a subtle kind:
	// absent from the catalogue and absent from the answer are different
	// facts, and a row with both flags false is indistinguishable from a row
	// that was never fetched. The absence of a row is the honest record, and
	// the score says "unavailable" on the strength of it.
	if len(rows) > 0 {
		if err := o.Store.SaveIntel(ctx, rows); err != nil {
			return stats, err
		}
		stats.Stored = len(rows)
	}
	return stats, nil
}

func sourceNames(m feed.Multi) []string {
	out := make([]string, 0, len(m.Sources))
	for _, s := range m.Sources {
		out = append(out, s.Name())
	}
	sort.Strings(out)
	return out
}

// RunEnrichment refreshes intelligence on an interval until the context is
// cancelled.
//
// On its own schedule, because EPSS republishes daily and KEV several times a
// week: tying the refresh to scans would mean a repository scanned weekly
// scored against week-old exploitation data, and an incident reaching only the
// repositories that happened to be scanned that hour.
func (o *Orchestrator) RunEnrichment(ctx context.Context, sources feed.Multi, repos func() []string, every time.Duration, onErr func(error)) {
	if every <= 0 {
		every = 6 * time.Hour
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, repo := range repos() {
				if _, err := o.EnrichPass(ctx, sources, repo); err != nil && onErr != nil {
					onErr(err)
				}
			}
		}
	}
}
