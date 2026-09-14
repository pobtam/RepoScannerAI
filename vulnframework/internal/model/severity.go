package model

import "fmt"

// Severity is the tool-reported severity band of a finding.
//
// The specification does not enumerate this set (see BUILD-LOG, Phase 0
// assumption A3). These are the four bands used throughout the report-browser
// reference, plus SeverityUnknown for tools that report none — an absent
// severity must be representable rather than silently collapsing to LOW.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityUnknown  Severity = "UNKNOWN"
)

// AllSeverities is the closed enumeration, ordered most to least severe.
var AllSeverities = []Severity{
	SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityUnknown,
}

var severityRank = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityUnknown:  4,
}

// Valid reports whether s is a member of the closed enumeration.
func (s Severity) Valid() bool { _, ok := severityRank[s]; return ok }

// Rank orders severities most severe (0) to least. Unknown sorts last: it is
// not a severity floor, it is an absence, and sorting it among the known bands
// would assert a confidence the tool never expressed.
func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return len(severityRank)
}

func (s Severity) String() string { return string(s) }

// Priority is the computed composite priority band (VM-AD §9.4).
//
// Priority is never produced by inference; internal/score computes it
// deterministically in Phase 5 (VM-F-305). This type only defines the band.
type Priority string

const (
	P0 Priority = "P0"
	P1 Priority = "P1"
	P2 Priority = "P2"
	P3 Priority = "P3"
)

// AllPriorities is the closed enumeration, ordered most to least urgent.
var AllPriorities = []Priority{P0, P1, P2, P3}

var priorityRank = map[Priority]int{P0: 0, P1: 1, P2: 2, P3: 3}

// Valid reports whether p is a member of the closed enumeration.
func (p Priority) Valid() bool { _, ok := priorityRank[p]; return ok }

// Rank orders priorities most urgent (0) to least.
func (p Priority) Rank() int {
	if r, ok := priorityRank[p]; ok {
		return r
	}
	return len(priorityRank)
}

func (p Priority) String() string { return string(p) }

// ValidatePriority returns an error unless p is a member of the enumeration.
func ValidatePriority(p Priority) error {
	if !p.Valid() {
		return fmt.Errorf("invalid priority %q", p)
	}
	return nil
}
