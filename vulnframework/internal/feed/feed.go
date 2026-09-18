// Package feed is the exploitation-intelligence boundary: KEV and EPSS
// (OQ-AUDIT-01(b), VM-AD §9.4).
//
// The scorer declares five inputs and two of them — is this being exploited
// right now, and how likely is it to be — had no producer at all. A scorer that
// structurally cannot see active-exploitation status has a feed-shaped hole
// where its most decision-changing input belongs, and the Producer-Coverage
// Audit found it by asking who writes the field rather than who reads it.
//
// Everything here is behind an interface with a hostile fake. Enabling the live
// feeds is a HUMAN step: it needs network access and, for EPSS, a published
// daily snapshot that is a third-party dependency with its own outages. The
// framework must score, report and ticket correctly while both are absent, and
// must say which inputs were absent rather than scoring as though absence were
// a zero.
package feed

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Assessment is what the feeds say about ONE vulnerability identifier.
//
// Per-field availability, not a single "found" flag: KEV and EPSS are separate
// publications with separate outages, and one answering is not the other
// answering. A finding can be known-exploited with no EPSS score at all, which
// is the most urgent combination there is.
type Assessment struct {
	ID string `json:"id"`

	// EPSS is the exploit-prediction score, 0..1, valid only when
	// EPSSAvailable. Zero with EPSSAvailable means MEASURED AND NEGLIGIBLE,
	// which is a different fact from nobody having looked.
	EPSS          float64   `json:"epss"`
	EPSSAvailable bool      `json:"epss_available"`
	EPSSAsOf      time.Time `json:"epss_as_of,omitempty"`

	// KEV reports presence in the Known Exploited Vulnerabilities catalogue,
	// valid only when KEVAvailable. False with KEVAvailable means CHECKED AND
	// NOT LISTED.
	KEV          bool      `json:"kev"`
	KEVAvailable bool      `json:"kev_available"`
	KEVAsOf      time.Time `json:"kev_as_of,omitempty"`
}

// Known reports whether anything at all was learned.
func (a Assessment) Known() bool { return a.EPSSAvailable || a.KEVAvailable }

// Merge combines two assessments of the same identifier.
//
// Per field, and never downgrades an answer to silence: two sources, one of
// which does not publish EPSS, must not erase the other's score. Where both
// answer, the FRESHER snapshot wins — not the higher score, because the point
// is what is true now, and picking the scarier of two answers is how a feed's
// stale row outlives its correction.
func (a Assessment) Merge(b Assessment) Assessment {
	out := a
	if out.ID == "" {
		out.ID = b.ID
	}
	if b.EPSSAvailable && (!out.EPSSAvailable || b.EPSSAsOf.After(out.EPSSAsOf)) {
		out.EPSS, out.EPSSAvailable, out.EPSSAsOf = b.EPSS, true, b.EPSSAsOf
	}
	if b.KEVAvailable && (!out.KEVAvailable || b.KEVAsOf.After(out.KEVAsOf)) {
		out.KEV, out.KEVAvailable, out.KEVAsOf = b.KEV, true, b.KEVAsOf
	}
	return out
}

// Source is one exploitation-intelligence publication.
//
// Lookup answers for the identifiers it recognises and OMITS the rest. An
// identifier absent from the result means "this source does not know", which a
// zero-valued entry would silently convert into "measured as harmless" — the
// exact collapse the availability flags exist to prevent. Implementations must
// never zero-fill.
type Source interface {
	Name() string
	// Lookup is batched because both real feeds are: EPSS publishes a daily
	// CSV and KEV a single JSON catalogue, and one HTTP request per finding
	// against a fleet-sized run is how a rate limit is discovered.
	Lookup(ctx context.Context, ids []string) (map[string]Assessment, error)
}

// ErrUnavailable marks a source that could not answer at all.
//
// Distinct from an empty result, which means the source answered and knew none
// of the identifiers. A caller that treated the two alike would record "checked,
// nothing found" for a feed that was down.
type ErrUnavailable struct {
	Source string
	Cause  string
}

func (e *ErrUnavailable) Error() string {
	return fmt.Sprintf("feed: %s could not answer: %s", e.Source, e.Cause)
}

// LookupStats is what one enrichment pass learned and lost.
type LookupStats struct {
	Requested int
	// Answered counts identifiers at least one source knew something about.
	Answered int
	// Unknown counts identifiers every source omitted. Not an error: most
	// identifiers are in neither catalogue, and "not listed" is an answer only
	// when the source that omitted it is known to cover it.
	Unknown int
	// SourcesDown names sources that could not answer. A pass where every
	// source is down answered nothing, and must not be recorded as a pass
	// where nothing was found.
	SourcesDown []string
	// Malformed counts rows a source published that could not be believed —
	// an EPSS outside 0..1, an empty identifier, a date in the future. They
	// are DROPPED, never clamped into range: a clamped 1.7 becomes a
	// maximum-urgency score off the back of a corrupt row.
	Malformed int
}

// Multi queries several sources and merges what they say.
type Multi struct {
	Sources []Source
	// Clock supplies now, for freshness decisions.
	Clock func() time.Time
}

// Lookup queries every source. A source that cannot answer is recorded and the
// pass continues: the framework's own availability must not depend on a
// third-party publication being up.
func (m Multi) Lookup(ctx context.Context, ids []string) (map[string]Assessment, LookupStats, error) {
	stats := LookupStats{Requested: len(ids)}
	out := map[string]Assessment{}
	if len(ids) == 0 {
		return out, stats, nil
	}

	for _, src := range m.Sources {
		got, err := src.Lookup(ctx, ids)
		if err != nil {
			stats.SourcesDown = append(stats.SourcesDown, src.Name())
			continue
		}
		for id, a := range got {
			if problem := validate(id, a, m.now()); problem != "" {
				stats.Malformed++
				continue
			}
			a.ID = id
			out[id] = out[id].Merge(a)
		}
	}
	sort.Strings(stats.SourcesDown)

	for _, id := range ids {
		if a, ok := out[id]; ok && a.Known() {
			stats.Answered++
		} else {
			stats.Unknown++
		}
	}
	return out, stats, nil
}

func (m Multi) now() time.Time {
	if m.Clock != nil {
		return m.Clock().UTC()
	}
	return time.Now().UTC()
}

// validate says why a published row cannot be believed, or "" if it can.
//
// Dropping rather than repairing. A score outside 0..1 is not a score that
// needs clamping, it is evidence that the row was not produced by the process
// this system thinks it was — and clamping 1.7 to 1.0 turns a corrupt row into
// the most urgent finding in the fleet.
func validate(id string, a Assessment, now time.Time) string {
	if strings.TrimSpace(id) == "" {
		return "empty identifier"
	}
	if a.EPSSAvailable {
		if a.EPSS < 0 || a.EPSS > 1 {
			return fmt.Sprintf("epss %.4f is outside 0..1", a.EPSS)
		}
		if a.EPSSAsOf.IsZero() {
			return "epss with no snapshot date: a score whose age is unknown cannot be qualified"
		}
		if a.EPSSAsOf.After(now.Add(24 * time.Hour)) {
			return "epss snapshot dated in the future"
		}
	}
	if a.KEVAvailable {
		if a.KEVAsOf.IsZero() {
			return "kev with no catalogue date"
		}
		if a.KEVAsOf.After(now.Add(24 * time.Hour)) {
			return "kev catalogue dated in the future"
		}
	}
	return ""
}
