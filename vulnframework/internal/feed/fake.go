package feed

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Fake is an offline feed that models the WEAKEST behaviour the real ones
// permit (the Phase 8 standing sentinel).
//
// What the real feeds actually do, each of which the framework has to survive:
//
//	EPSS publishes a DAILY snapshot. It is routinely a day or more behind, and
//	during an incident the score that matters is the one nobody has published
//	yet. So the fake serves stale snapshots and says how stale.
//
//	KEV is a single catalogue file. An identifier absent from it is not
//	"score zero", it is "not in this catalogue" — and the catalogue itself can
//	fail to load, which is a different fact again.
//
//	Both are third-party HTTP endpoints. They rate-limit, time out, serve
//	truncated JSON, and occasionally publish rows that cannot be true (an EPSS
//	greater than one, a date in the future, an empty identifier).
//
//	Identifier namespaces DISAGREE. EPSS and KEV are keyed by CVE; this
//	framework's findings are keyed by GO- and GHSA- identifiers as often as by
//	CVE. A fake that answered to whatever key it was given would hide the
//	alias resolution the caller has to do.
type Fake struct {
	mu sync.Mutex

	name string
	// rows are the identifiers this source knows, keyed EXACTLY as the real
	// feed keys them.
	rows map[string]Assessment
	// cveOnly makes the source refuse to recognise anything but a CVE
	// identifier, as both real feeds do.
	cveOnly bool

	down          string
	failAfter     int
	truncateAfter int
	malformed     map[string]Assessment
	lookups       int
	lastIDs       []string
	maxBatch      int
}

// NewFake builds an empty source under a name.
func NewFake(name string) *Fake {
	return &Fake{name: name, rows: map[string]Assessment{}, malformed: map[string]Assessment{}}
}

// NewFakeKEV builds a KEV-shaped source: CVE-keyed, catalogue membership only.
func NewFakeKEV() *Fake {
	f := NewFake("kev")
	f.cveOnly = true
	return f
}

// NewFakeEPSS builds an EPSS-shaped source: CVE-keyed, daily snapshot.
func NewFakeEPSS() *Fake {
	f := NewFake("epss")
	f.cveOnly = true
	return f
}

func (f *Fake) Name() string { return f.name }

// WithKEV lists an identifier in the catalogue as of a date.
func (f *Fake) WithKEV(id string, asOf time.Time) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.rows[id]
	a.KEV, a.KEVAvailable, a.KEVAsOf = true, true, asOf.UTC()
	f.rows[id] = a
	return f
}

// WithNotKEV records that the catalogue was checked and does not list it.
//
// Separate from omitting the identifier: "checked, not listed" is an answer
// and "this source does not cover it" is not, and a consumer that cannot tell
// them apart will report the second as the first.
func (f *Fake) WithNotKEV(id string, asOf time.Time) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.rows[id]
	a.KEV, a.KEVAvailable, a.KEVAsOf = false, true, asOf.UTC()
	f.rows[id] = a
	return f
}

// WithEPSS publishes a score as of a snapshot date.
func (f *Fake) WithEPSS(id string, score float64, asOf time.Time) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.rows[id]
	a.EPSS, a.EPSSAvailable, a.EPSSAsOf = score, true, asOf.UTC()
	f.rows[id] = a
	return f
}

// WithEmptyAnswer makes the source return a row that answers NOTHING: both
// availability flags false.
//
// A real endpoint does this — a JSON object with the identifier and no score,
// a CSV line with an empty column — and a consumer that counted the row as an
// answer would record "checked, negligible" for a vulnerability nobody
// assessed.
func (f *Fake) WithEmptyAnswer(id string) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[id] = Assessment{ID: id}
	return f
}

// WithMalformedRow publishes a row that cannot be believed.
func (f *Fake) WithMalformedRow(id string, a Assessment) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.malformed[id] = a
	return f
}

// Down makes the source unable to answer at all.
func (f *Fake) Down(cause string) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = cause
	return f
}

// Up restores it, for testing recovery.
func (f *Fake) Up() *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = ""
	return f
}

// FailAfter makes the source fail once this many lookups have been made.
func (f *Fake) FailAfter(n int) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failAfter = n
	return f
}

// TruncateAfter makes the source answer for only the first n identifiers of
// each batch, as a paginated endpoint silently does.
func (f *Fake) TruncateAfter(n int) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.truncateAfter = n
	return f
}

// MaxBatch makes the source REFUSE a batch larger than n, as a real endpoint
// does with a 414 or a 400.
func (f *Fake) MaxBatch(n int) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.maxBatch = n
	return f
}

// Lookups reports how many times the source was queried, so a caller can show
// it batches rather than asking per finding.
func (f *Fake) Lookups() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lookups
}

// LastIDs reports the identifiers of the most recent lookup.
func (f *Fake) LastIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.lastIDs...)
}

func (f *Fake) Lookup(ctx context.Context, ids []string) (map[string]Assessment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	f.lastIDs = append([]string(nil), ids...)

	if err := ctx.Err(); err != nil {
		return nil, &ErrUnavailable{Source: f.name, Cause: err.Error()}
	}
	if f.down != "" {
		return nil, &ErrUnavailable{Source: f.name, Cause: f.down}
	}
	if f.failAfter > 0 && f.lookups > f.failAfter {
		return nil, &ErrUnavailable{Source: f.name,
			Cause: fmt.Sprintf("429 too many requests after %d lookups", f.failAfter)}
	}
	if f.maxBatch > 0 && len(ids) > f.maxBatch {
		return nil, &ErrUnavailable{Source: f.name,
			Cause: fmt.Sprintf("400 request too large: %d identifiers, limit %d", len(ids), f.maxBatch)}
	}

	out := map[string]Assessment{}
	for i, id := range ids {
		if f.truncateAfter > 0 && i >= f.truncateAfter {
			// Silently short. The caller is not told the page ended, which is
			// why a caller must never read a missing identifier as an answer.
			break
		}
		if f.cveOnly && !strings.HasPrefix(id, "CVE-") {
			// The real feeds are CVE-keyed. A GO- or GHSA- identifier is not
			// unknown to the catalogue, it is unaskable — and the caller has
			// to resolve aliases before asking.
			continue
		}
		if bad, ok := f.malformed[id]; ok {
			out[id] = bad
			continue
		}
		if a, ok := f.rows[id]; ok {
			out[id] = a
		}
		// Omitted otherwise. Never zero-filled.
	}
	return out, nil
}
