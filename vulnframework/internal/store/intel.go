package store

import "time"

// Intel is what the exploitation-intelligence feeds say about one vulnerability
// identifier (OQ-AUDIT-01(b), VM-AD §9.4).
//
// Keyed by IDENTIFIER, not by finding. EPSS and KEV are properties of a
// vulnerability, not of an occurrence of it: one row serves every finding in
// the fleet that carries the identifier, and a per-finding copy would let two
// findings of the same CVE disagree about whether it is being exploited.
//
// Stored outside the finding document for the same reason the ticket and pull
// request references are: the document is rebuilt from observations on every
// scan, so anything kept inside it is erased by the next run. The projection
// joins these rows in.
type Intel struct {
	ID string `json:"id"`

	EPSS          float64    `json:"epss"`
	EPSSAvailable bool       `json:"epss_available"`
	EPSSAsOf      *time.Time `json:"epss_as_of,omitempty"`

	KEV          bool       `json:"kev"`
	KEVAvailable bool       `json:"kev_available"`
	KEVAsOf      *time.Time `json:"kev_as_of,omitempty"`

	// FetchedAt is when this framework asked, as distinct from when the feed
	// published. Both matter: a fresh fetch of a stale snapshot is still a
	// stale snapshot, and telling them apart is how an operator knows whether
	// to chase the feed or the fetcher.
	FetchedAt time.Time `json:"fetched_at"`
	// Sources names the feeds that contributed, so a value can be traced to a
	// publication rather than to "the system".
	Sources []string `json:"sources,omitempty"`
}

// Known reports whether anything at all is known about the identifier.
func (i Intel) Known() bool { return i.EPSSAvailable || i.KEVAvailable }

// IntelFreshness is when each exploitation feed last answered, across the
// whole store. A zero time means that feed has never answered here.
type IntelFreshness struct {
	KEV  time.Time `json:"kev"`
	EPSS time.Time `json:"epss"`
}
