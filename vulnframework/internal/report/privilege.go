package report

import (
	"fmt"
	"sort"
)

// Level is a recipient's access level.
//
// Redaction is meaningless without a model of who may see what, so the levels
// come first and the redaction rules are expressed in terms of them.
type Level int

const (
	// LevelUnknown is the zero value and is never a permission. Delivery fails
	// closed on it rather than choosing a level (see Deliver).
	LevelUnknown Level = iota
	// LevelPublic is the least-privileged audience: counts and coverage, no
	// finding detail. This is the rendering that travels furthest.
	LevelPublic
	// LevelEngineer sees non-secret finding detail for the repositories they
	// work on.
	LevelEngineer
	// LevelSecurityOwner sees everything the system holds.
	LevelSecurityOwner
)

// AllLevels is the closed enumeration, least privileged first.
var AllLevels = []Level{LevelPublic, LevelEngineer, LevelSecurityOwner}

// LeastPrivileged is the lowest real level. The secret scan is run against its
// rendering because that is the artifact distributed most widely: a leak there
// is a leak to everyone.
const LeastPrivileged = LevelPublic

func (l Level) String() string {
	switch l {
	case LevelPublic:
		return "public"
	case LevelEngineer:
		return "engineer"
	case LevelSecurityOwner:
		return "security_owner"
	default:
		return "unknown"
	}
}

// Valid reports whether l is a real permission level.
func (l Level) Valid() bool { return l >= LevelPublic && l <= LevelSecurityOwner }

// ParseLevel reads a level name.
func ParseLevel(s string) (Level, bool) {
	for _, l := range AllLevels {
		if l.String() == s {
			return l, true
		}
	}
	return LevelUnknown, false
}

// Recipient is who a report is being delivered to.
//
// Determined is explicit rather than inferred from Level, so "we could not find
// out" is representable and cannot be confused with "public". Without it, an
// identity lookup failure would silently produce the zero value and the caller
// would have to remember to check — which is exactly the check that gets
// forgotten.
type Recipient struct {
	ID         string
	Level      Level
	Determined bool
}

// SecurityOwner returns a fully privileged recipient.
func SecurityOwner(id string) Recipient {
	return Recipient{ID: id, Level: LevelSecurityOwner, Determined: true}
}

// Undetermined returns a recipient whose privilege could not be established.
func Undetermined(id string) Recipient { return Recipient{ID: id} }

// ErrPrivilegeUndetermined is returned when a recipient's level is unknown.
//
// Delivery fails closed. Falling back to a fuller rendering would mean an
// identity lookup failure quietly upgrades someone's access, and the failure
// mode of a permissions system must never be "grant more".
type ErrPrivilegeUndetermined struct{ Recipient string }

func (e *ErrPrivilegeUndetermined) Error() string {
	return fmt.Sprintf(
		"report: refusing to deliver to %q: the recipient's privilege level could not be determined. "+
			"Delivery fails closed — it never falls back to a fuller rendering, because an identity lookup "+
			"failure must not quietly grant access", e.Recipient)
}

// ErrOverLimit is returned for a request larger than the generator will serve.
type ErrOverLimit struct {
	Requested int
	Limit     int
}

func (e *ErrOverLimit) Error() string {
	return fmt.Sprintf(
		"report: refusing a request for %d findings: the limit is %d. "+
			"Narrow the query — by repository, state or priority — or request an audit pack, which is generated asynchronously",
		e.Requested, e.Limit)
}

// MaxFindingsPerReport bounds a single report.
//
// The limit is stated in the error rather than silently truncating: a report
// quietly cut to its first N rows is a report that under-states the fleet while
// looking complete.
const MaxFindingsPerReport = 5000

// Redact produces the rendering a level may see.
//
// The rules, and what each protects:
//
//	Below security owner, a secret finding's DETAIL is withheld — its location,
//	its credential type, its identifier — while the finding is still COUNTED.
//	The count is what tells an engineer that secrets exist in their repository;
//	the detail is what would tell them where to look for the credential
//	(VM-UI-F-803, U8).
//
//	Below engineer, all finding detail is withheld and only the aggregate
//	figures remain. Counts and coverage are not sensitive; the list of exactly
//	which vulnerabilities are open and unfixed is.
//
// Counts are never redacted. A redacted report that also under-counts would
// misrepresent the fleet rather than merely withhold from the reader, and the
// notice would be false as well as incomplete.
func Redact(rep Report, level Level) (Report, error) {
	if !level.Valid() {
		return Report{}, &ErrPrivilegeUndetermined{Recipient: "<unspecified>"}
	}
	if level == LevelSecurityOwner {
		return rep, nil
	}

	out := rep
	out.Findings = nil
	withheld := 0

	for _, row := range rep.Findings {
		switch {
		case level < LevelEngineer:
			// Aggregates only.
			withheld++
			continue
		case row.Category == "secret":
			// Counted, never detailed.
			withheld++
			continue
		default:
			out.Findings = append(out.Findings, row)
		}
	}
	sort.Slice(out.Findings, func(i, j int) bool { return out.Findings[i].Fingerprint < out.Findings[j].Fingerprint })

	if withheld > 0 {
		out.Redacted = true
		out.WithheldCount = withheld
	}
	// The identifier changes with the rendering: two artifacts with different
	// content must not share an identity, or a citation is ambiguous about
	// which one it refers to (VM-ADR-15).
	out.Query.Template = rep.Query.Template + "@" + level.String()
	out.ID = reportID(out)
	return out, nil
}
