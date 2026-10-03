package feed

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The live clients for the two exploitation-intelligence publications.
//
// Both are full-catalogue publications rather than per-identifier lookups:
// KEV is one JSON document and EPSS is one gzipped CSV of every scored CVE.
// A client that issued one request per finding would discover a rate limit on
// its first fleet-sized run, which is why Source.Lookup is batched.
//
// **Nothing here is wired up.** Choosing where the snapshots come from, where
// they are cached and for how long, what "stale" means and what to do when a
// feed is down for a day are four policy decisions, and they are D3's. These
// clients are stateless on purpose: each Lookup fetches a snapshot, and
// anything cleverer would be this code making D3's decision quietly.
//
// What these clients must get right, and what their tests are about, is the
// handful of places a feed client can lie:
//
//   - A feed that is DOWN must be distinguishable from a feed that answered
//     and knew none of the identifiers. The first is *ErrUnavailable; the
//     second is an empty map and a nil error. A caller that treated them
//     alike would record "checked, not listed" for a catalogue it never
//     reached — and "not listed in KEV" is a statement that lowers a
//     priority.
//
//   - A TRUNCATED catalogue must not parse as a short one. A KEV document cut
//     in half is still valid JSON prefix-wise, and half the catalogue missing
//     reads as half the fleet's vulnerabilities no longer being exploited.
//
//   - An identifier the catalogue does not list is OMITTED, never zero-filled.
//     EPSS 0.0 with EPSSAvailable is "measured, negligible"; the absence of an
//     entry is "nobody looked". Collapsing them is the exact failure the
//     availability flags exist to prevent.

// maxCatalogueBytes bounds a response body.
//
// Hitting the bound is an ERROR rather than a truncation, for the reason
// above: a catalogue silently cut short reports that vulnerabilities are no
// longer exploited. The figure is generous — KEV is a few megabytes and EPSS
// compressed is a few more — because the bound is there to stop a runaway
// response, not to express an expectation about size.
const maxCatalogueBytes = 128 << 20

// userAgent identifies the framework to the publishers, so an operator on
// their side can tell who is fetching.
const userAgent = "wanaware-vulnframework/1.0 (+exploitation-intelligence)"

// KEVSource is the CISA Known Exploited Vulnerabilities catalogue.
type KEVSource struct {
	// URL is the catalogue endpoint. Required: there is deliberately no
	// default, so a deployment cannot acquire a third-party dependency by
	// omission.
	URL string
	// HTTP is the client. Nil uses a client with a bounded timeout rather
	// than http.DefaultClient, which has none — a feed that accepts the
	// connection and never answers would otherwise hang a scan run.
	HTTP *http.Client

	mu        sync.Mutex
	malformed int
}

// Name identifies the source in LookupStats.SourcesDown.
func (s *KEVSource) Name() string { return "kev" }

// Malformed reports rows this source could not parse at all and therefore
// dropped.
//
// Distinct from Multi's Malformed count, which is rows that parsed and could
// not be BELIEVED — an EPSS outside 0..1, a date in the future. A row that is
// syntactic garbage cannot be passed upwards to be judged, so it is counted
// here instead of being invented into something judgeable.
func (s *KEVSource) Malformed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.malformed
}

// kevDocument is the catalogue as published.
type kevDocument struct {
	CatalogVersion string `json:"catalogVersion"`
	DateReleased   string `json:"dateReleased"`
	// Count is what makes truncation detectable. It is the publisher's own
	// statement of how many records the document contains, and comparing it
	// against what arrived is the difference between a short catalogue and a
	// catalogue that was cut off in transit.
	Count           int `json:"count"`
	Vulnerabilities []struct {
		CVEID     string `json:"cveID"`
		DateAdded string `json:"dateAdded"`
	} `json:"vulnerabilities"`
}

// Lookup fetches the catalogue and answers for the identifiers in it.
func (s *KEVSource) Lookup(ctx context.Context, ids []string) (map[string]Assessment, error) {
	if s.URL == "" {
		return nil, &ErrUnavailable{Source: s.Name(), Cause: "no catalogue URL is configured"}
	}

	body, err := fetch(ctx, s.HTTP, s.URL, s.Name())
	if err != nil {
		return nil, err
	}

	var doc kevDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, &ErrUnavailable{Source: s.Name(),
			Cause: fmt.Sprintf("the catalogue did not parse as JSON: %v", err)}
	}

	// Truncation. A document that arrived short is not a catalogue in which
	// fewer things are exploited.
	if doc.Count != 0 && doc.Count != len(doc.Vulnerabilities) {
		return nil, &ErrUnavailable{Source: s.Name(), Cause: fmt.Sprintf(
			"the catalogue declares %d entries and carries %d. A short catalogue reads as "+
				"vulnerabilities no longer being exploited, so it is refused rather than used",
			doc.Count, len(doc.Vulnerabilities))}
	}

	asOf, err := parseKEVReleased(doc.DateReleased)
	if err != nil {
		// A catalogue whose age is unknown cannot be qualified, and an
		// unqualified exploitation claim is one that outlives its correction.
		return nil, &ErrUnavailable{Source: s.Name(), Cause: err.Error()}
	}

	listed := make(map[string]bool, len(doc.Vulnerabilities))
	malformed := 0
	for _, v := range doc.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if id == "" {
			malformed++
			continue
		}
		listed[id] = true
	}

	s.mu.Lock()
	s.malformed = malformed
	s.mu.Unlock()

	// Every requested identifier gets an answer, because for KEV the catalogue
	// is exhaustive: it is the complete list of what CISA considers
	// known-exploited, so absence from it is a MEASUREMENT — "checked and not
	// listed" — rather than silence. That is the one place in this package
	// where a negative is a real answer, and it is only true because the
	// publication is a complete enumeration.
	out := make(map[string]Assessment, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		out[id] = Assessment{
			ID:           id,
			KEV:          listed[strings.ToUpper(id)],
			KEVAvailable: true,
			KEVAsOf:      asOf,
		}
	}
	return out, nil
}

// parseKEVReleased reads the catalogue's release timestamp.
//
// CISA publishes a fractional-second form that is not RFC 3339, so both are
// tried. A date that cannot be read is an error rather than "now": dating a
// stale catalogue to the present is how a correction gets outlived.
func parseKEVReleased(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("the catalogue carries no release date, so its age is unknown " +
			"and nothing read from it can be qualified")
	}
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05.0000Z07:00",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("the catalogue's release date %q is in no recognised format", s)
}

// EPSSSource is the FIRST Exploit Prediction Scoring System daily snapshot.
type EPSSSource struct {
	// URL is the snapshot endpoint, a gzipped CSV.
	URL string
	// HTTP is the client. Nil uses a bounded-timeout client.
	HTTP *http.Client

	mu        sync.Mutex
	malformed int
}

// Name identifies the source.
func (s *EPSSSource) Name() string { return "epss" }

// Malformed reports rows that could not be parsed and were dropped.
func (s *EPSSSource) Malformed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.malformed
}

// Lookup fetches the daily snapshot and answers for the identifiers it scores.
func (s *EPSSSource) Lookup(ctx context.Context, ids []string) (map[string]Assessment, error) {
	if s.URL == "" {
		return nil, &ErrUnavailable{Source: s.Name(), Cause: "no snapshot URL is configured"}
	}

	body, err := fetch(ctx, s.HTTP, s.URL, s.Name())
	if err != nil {
		return nil, err
	}

	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, &ErrUnavailable{Source: s.Name(),
			Cause: fmt.Sprintf("the snapshot is not gzip: %v", err)}
	}
	defer gz.Close()

	plain, err := io.ReadAll(gz)
	if err != nil {
		// An unexpected EOF here is a truncated transfer. Parsing what
		// arrived would silently drop every score after the cut, and an
		// absent score is read as "nobody looked".
		return nil, &ErrUnavailable{Source: s.Name(), Cause: fmt.Sprintf(
			"the snapshot ended early (%v). The scores after the cut would be indistinguishable "+
				"from identifiers nobody scored, so the snapshot is refused rather than used", err)}
	}

	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[strings.ToUpper(strings.TrimSpace(id))] = true
	}

	out := map[string]Assessment{}
	malformed := 0
	var asOf time.Time
	var sawHeader bool

	reader := csv.NewReader(bytes.NewReader(plain))
	// The publication carries a comment line and a header; the record width is
	// not uniform across them.
	reader.FieldsPerRecord = -1

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, &ErrUnavailable{Source: s.Name(),
				Cause: fmt.Sprintf("the snapshot is not readable as CSV: %v", err)}
		}
		if len(record) == 0 {
			continue
		}

		first := strings.TrimSpace(record[0])
		if strings.HasPrefix(first, "#") {
			if t, ok := parseScoreDate(strings.Join(record, ",")); ok {
				asOf = t
			}
			continue
		}
		if strings.EqualFold(first, "cve") {
			sawHeader = true
			continue
		}
		if len(record) < 2 {
			malformed++
			continue
		}

		id := strings.ToUpper(first)
		if !wanted[id] {
			// Not asked for. Omitted rather than returned, so the caller's
			// batch size bounds the result rather than the catalogue's.
			continue
		}
		score, err := strconv.ParseFloat(strings.TrimSpace(record[1]), 64)
		if err != nil {
			// A row that is not a number cannot be passed up to be judged,
			// and inventing a judgeable value from it would be worse than
			// dropping it.
			malformed++
			continue
		}
		out[first] = Assessment{
			ID: first, EPSS: score, EPSSAvailable: true, EPSSAsOf: asOf,
		}
	}

	s.mu.Lock()
	s.malformed = malformed
	s.mu.Unlock()

	if !sawHeader {
		return nil, &ErrUnavailable{Source: s.Name(), Cause: "the snapshot has no cve,epss header row. " +
			"Without it the format is not the one this parser was written against, and reading it " +
			"anyway would produce confident scores from columns that mean something else"}
	}
	if asOf.IsZero() {
		return nil, &ErrUnavailable{Source: s.Name(), Cause: "the snapshot carries no score_date. " +
			"A score whose age is unknown cannot be qualified, and freshness is the whole of what " +
			"makes yesterday's prediction usable"}
	}
	return out, nil
}

// parseScoreDate reads the score_date from EPSS's comment line.
func parseScoreDate(line string) (time.Time, bool) {
	const key = "score_date:"
	i := strings.Index(line, key)
	if i < 0 {
		return time.Time{}, false
	}
	value := strings.TrimSpace(line[i+len(key):])
	if j := strings.IndexAny(value, ", \t"); j >= 0 {
		value = value[:j]
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05-0700",
		time.RFC3339,
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// --- the shared transport ----------------------------------------------------

// fetch performs one GET and returns the body, mapping every failure to
// *ErrUnavailable.
//
// Every failure, deliberately. A transport error, a 500, a 404 and a rate
// limit are different operational problems and the same fact for the caller:
// this source did not answer. What must never happen is any of them becoming
// an empty result, which means the source DID answer and knew nothing.
func fetch(ctx context.Context, client *http.Client, url, source string) ([]byte, error) {
	if client == nil {
		client = defaultClient()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, &ErrUnavailable{Source: source, Cause: fmt.Sprintf("the request could not be built: %v", err)}
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, &ErrUnavailable{Source: source, Cause: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		cause := fmt.Sprintf("HTTP %d", resp.StatusCode)
		if retry := resp.Header.Get("Retry-After"); retry != "" {
			cause += ", Retry-After: " + retry
		}
		return nil, &ErrUnavailable{Source: source, Cause: cause}
	}

	// One byte over the bound, so hitting it is detectable rather than
	// arriving as a body that happens to be exactly the limit.
	limited := io.LimitReader(resp.Body, maxCatalogueBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, &ErrUnavailable{Source: source,
			Cause: fmt.Sprintf("the response ended early: %v", err)}
	}
	if len(body) > maxCatalogueBytes {
		return nil, &ErrUnavailable{Source: source, Cause: fmt.Sprintf(
			"the response exceeded %d bytes and was not read to the end. A partial catalogue is "+
				"refused rather than parsed: the entries after the cut are indistinguishable from "+
				"entries that are no longer listed", maxCatalogueBytes)}
	}
	return body, nil
}

// defaultClient has a timeout, which http.DefaultClient does not.
//
// A publisher that accepts the connection and never answers would otherwise
// hold a scan run open indefinitely — and the framework's own availability
// must not depend on a third party's.
func defaultClient() *http.Client {
	return &http.Client{Timeout: 60 * time.Second}
}
