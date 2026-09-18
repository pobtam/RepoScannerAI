package store

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
)

// Filtering, sorting and cursor pagination (VM-UI-F-402, VM-UI-F-403,
// UI-ADR-06).
//
// Server-side, because the finding set grows without bound across history and
// client-side filtering fails exactly when the fleet is largest. Cursor-based,
// because offset pagination silently duplicates and skips rows while findings
// change state underneath a paging session — and this set changes state
// constantly, which is the whole point of it.
//
// The matching and ordering rules live HERE, in one place, and both backends
// are held to them. The memory backend calls these functions directly; the
// Postgres backend renders them into SQL from the same source values (see
// severityCaseSQL). A rule expressed twice in two languages is a rule that
// will disagree, and the disagreement would be invisible: each backend would
// look right in its own tests.

// Filter is every dimension a finding query can narrow on (VM-UI-F-406).
//
// Every slice is OR within the dimension and AND across dimensions
// (VM-UI-F-407). A nil pointer means the dimension is not filtered, which is a
// different thing from filtering on false — hence pointers rather than bools.
type Filter struct {
	Repos      []string
	Tiers      []int
	Languages  []string
	Categories []model.Category
	States     []model.State
	Reasons    []model.ReasonCode
	Priorities []model.Priority
	Severities []model.Severity
	Reachable  []model.Reachable
	DepClasses []model.DepClass

	Transitive *bool
	// FirstParty selects findings in a module this organisation owns.
	FirstParty *bool
	// Blocked selects findings waiting on an upstream first-party fix.
	Blocked   *bool
	HasPR     *bool
	HasTicket *bool
	// NotReobserved selects findings the most recent applicable run did not
	// see while they remain unresolved (VM-UI-F-422). A filter dimension of
	// its own because it is a question people ask directly: what might we have
	// stopped looking at?
	NotReobserved *bool
	// SLABreached selects findings past their remediation window.
	SLABreached *bool

	FirstSeenFrom *time.Time
	FirstSeenTo   *time.Time
	LastSeenFrom  *time.Time
	LastSeenTo    *time.Time

	// Text matches identifier and ALIASES, module, package, file and
	// repository (VM-UI-F-404, VM-UI-F-405). Case-insensitive substring: an
	// incident responder pastes half a CVE.
	Text string
}

// Empty reports whether the filter narrows nothing.
func (f Filter) Empty() bool {
	return len(f.Repos) == 0 && len(f.Tiers) == 0 && len(f.Languages) == 0 &&
		len(f.Categories) == 0 && len(f.States) == 0 && len(f.Reasons) == 0 &&
		len(f.Priorities) == 0 && len(f.Severities) == 0 && len(f.Reachable) == 0 &&
		len(f.DepClasses) == 0 && f.Transitive == nil && f.FirstParty == nil &&
		f.Blocked == nil && f.HasPR == nil && f.HasTicket == nil &&
		f.NotReobserved == nil && f.SLABreached == nil &&
		f.FirstSeenFrom == nil && f.FirstSeenTo == nil &&
		f.LastSeenFrom == nil && f.LastSeenTo == nil && f.Text == ""
}

// RepoFacts are the repository properties a finding filter can reach.
//
// Tier and language belong to the repository, not to the finding, and a query
// that filters on them has to join. Passed in rather than looked up here so
// this stays a pure function.
type RepoFacts struct {
	Tier      int
	Languages []string
}

// Match reports whether a finding satisfies the filter.
//
// The single source of truth for "does this row match", used directly by the
// memory backend and mirrored in SQL by the Postgres one. The dual-backend
// conformance suite runs the same corpus through both and compares the pages,
// which is what keeps the mirror honest.
func (f Filter) Match(fd model.Finding, repo RepoFacts) bool {
	if len(f.Repos) > 0 && !containsString(f.Repos, fd.Repo) {
		return false
	}
	if len(f.Tiers) > 0 && !containsInt(f.Tiers, repo.Tier) {
		return false
	}
	if len(f.Languages) > 0 && !anyString(repo.Languages, f.Languages) {
		return false
	}
	if len(f.Categories) > 0 && !containsCategory(f.Categories, fd.Category) {
		return false
	}
	if len(f.States) > 0 && !containsState(f.States, fd.State) {
		return false
	}
	if len(f.Reasons) > 0 {
		if fd.ReasonCode == nil || !containsReason(f.Reasons, *fd.ReasonCode) {
			return false
		}
	}
	if len(f.Priorities) > 0 && !containsPriority(f.Priorities, fd.Priority) {
		return false
	}
	if len(f.Severities) > 0 && !containsSeverity(f.Severities, fd.Classification.Severity) {
		return false
	}
	if len(f.Reachable) > 0 && !containsReachable(f.Reachable, reachableOf(fd)) {
		return false
	}
	if len(f.DepClasses) > 0 && !containsDepClass(f.DepClasses, fd.Classification.DepClass) {
		return false
	}
	if f.Transitive != nil && fd.Classification.Transitive != *f.Transitive {
		return false
	}
	if f.FirstParty != nil && (fd.Classification.FirstPartyPath != nil) != *f.FirstParty {
		return false
	}
	if f.Blocked != nil && (fd.State == model.BlockedUpstream) != *f.Blocked {
		return false
	}
	if f.HasPR != nil && (fd.Refs.PullRequest != nil) != *f.HasPR {
		return false
	}
	if f.HasTicket != nil && (fd.Refs.Ticket != nil) != *f.HasTicket {
		return false
	}
	if f.NotReobserved != nil && fd.Derived.NotReobserved != *f.NotReobserved {
		return false
	}
	if f.SLABreached != nil && (fd.Derived.SLAStatus == model.SLABreached) != *f.SLABreached {
		return false
	}
	if f.FirstSeenFrom != nil && fd.FirstSeenAt.Before(*f.FirstSeenFrom) {
		return false
	}
	if f.FirstSeenTo != nil && fd.FirstSeenAt.After(*f.FirstSeenTo) {
		return false
	}
	if f.LastSeenFrom != nil && fd.LastSeenAt.Before(*f.LastSeenFrom) {
		return false
	}
	if f.LastSeenTo != nil && fd.LastSeenAt.After(*f.LastSeenTo) {
		return false
	}
	if f.Text != "" && !matchesText(fd, f.Text) {
		return false
	}
	return true
}

// reachableOf reads reachability as the tri-state it is. An absent value is
// UNKNOWN, never false (VM-F-243).
func reachableOf(f model.Finding) model.Reachable {
	if f.Classification.Reachable.Valid() {
		return f.Classification.Reachable
	}
	return model.ReachableUnknown
}

// SearchText returns every string a free-text query may match against
// (VM-UI-F-404, VM-UI-F-405).
//
// Aliases are included because searching by any alias must return the finding
// whichever identifier is primary: two tools name one vulnerability
// differently, and the responder has whichever name the advisory they are
// reading used.
func SearchText(f model.Finding) []string {
	out := []string{f.Identity.PrimaryID, f.Repo, f.Location.Module, f.Fingerprint}
	out = append(out, f.Identity.Aliases...)
	for _, p := range []*string{f.Location.Package, f.Location.File, f.Identity.RuleID} {
		if p != nil {
			out = append(out, *p)
		}
	}
	return out
}

func matchesText(f model.Finding, q string) bool {
	needle := strings.ToLower(q)
	for _, hay := range SearchText(f) {
		if hay != "" && strings.Contains(strings.ToLower(hay), needle) {
			return true
		}
	}
	return false
}

// SortField is the closed set of orderings the interface offers
// (VM-UI-F-412).
type SortField string

const (
	SortPriority  SortField = "priority"
	SortSeverity  SortField = "severity"
	SortFirstSeen SortField = "first_seen"
	SortLastSeen  SortField = "last_seen"
	SortRepo      SortField = "repo"
)

// AllSortFields is the closed enumeration.
var AllSortFields = []SortField{SortPriority, SortSeverity, SortFirstSeen, SortLastSeen, SortRepo}

// Valid reports membership of the closed set. An unrecognised sort is refused
// rather than defaulted: silently substituting one ordering for another makes
// a shared URL show a different list to two people (VM-UI-F-401).
func (s SortField) Valid() bool {
	for _, f := range AllSortFields {
		if f == s {
			return true
		}
	}
	return false
}

// SortDir is the direction.
type SortDir string

const (
	// SortDesc means MOST FIRST: most urgent, most severe, most recent, and
	// for a repository name, last alphabetically.
	SortDesc SortDir = "desc"
	SortAsc  SortDir = "asc"
)

// Valid reports membership.
func (d SortDir) Valid() bool { return d == SortAsc || d == SortDesc }

// Sort is one ordering. The fingerprint is always the tiebreaker, which is
// what makes the ordering TOTAL — and a total ordering is what makes a cursor
// able to resume exactly once (no duplicates, no skips).
type Sort struct {
	Field SortField
	Dir   SortDir
}

// DefaultSort is priority, most urgent first (VM-UI-F-613's first key).
func DefaultSort() Sort { return Sort{Field: SortPriority, Dir: SortDesc} }

// Normalise fills defaults and rejects nothing: validation is the caller's.
func (s Sort) Normalise() Sort {
	if !s.Field.Valid() {
		s.Field = SortPriority
	}
	if !s.Dir.Valid() {
		s.Dir = SortDesc
	}
	return s
}

// SortKey renders the value a finding is ordered by, as a string that compares
// lexicographically in the SAME order as the underlying value.
//
// One rendering for both backends and for the cursor, so "where did the last
// page end" is expressed once. Times are RFC3339 in UTC (lexicographic equals
// chronological); ranks are single digits (so 0 < 1 < … as strings); an absent
// priority renders as "P9" so it sorts after every real band rather than
// before them, because an unscored finding is not the most urgent thing in the
// fleet.
func SortKey(f model.Finding, field SortField) string {
	switch field {
	case SortSeverity:
		return fmt.Sprintf("%d", f.Classification.Severity.Rank())
	case SortFirstSeen:
		return f.FirstSeenAt.UTC().Format(sortTimeLayout)
	case SortLastSeen:
		return f.LastSeenAt.UTC().Format(sortTimeLayout)
	case SortRepo:
		return f.Repo
	default:
		if f.Priority == "" {
			return "P9"
		}
		return string(f.Priority)
	}
}

// sortTimeLayout is a FIXED-WIDTH timestamp rendering.
//
// Fixed width, because the key is compared as a string and RFC3339Nano trims
// trailing zeros: "…:05Z" and "…:05.120000Z" then sort against each other by
// the wrong characters. Six fractional digits, because that is what a
// timestamptz column stores — rendering nanoseconds in Go would produce a key
// the database cannot reproduce, and a cursor issued by one backend would
// resume in the wrong place on the other.
const sortTimeLayout = "2006-01-02T15:04:05.000000Z"

// ascendingKey reports whether a LOWER key means "first" under this ordering.
//
// Priority and severity are ranks: rank 0 is the most urgent and the most
// severe, so "most first" (desc) walks the keys ASCENDING. Times and names are
// values: "most first" walks them descending. Getting this backwards puts the
// P3s at the top of a queue sorted by urgency, and the ordering still looks
// deliberate.
func ascendingKey(s Sort) bool {
	rankField := s.Field == SortPriority || s.Field == SortSeverity
	if rankField {
		return s.Dir == SortDesc
	}
	return s.Dir == SortAsc
}

// Less is the total ordering: sort key, then fingerprint.
func Less(a, b model.Finding, s Sort) bool {
	s = s.Normalise()
	ka, kb := SortKey(a, s.Field), SortKey(b, s.Field)
	if ka != kb {
		if ascendingKey(s) {
			return ka < kb
		}
		return ka > kb
	}
	// The tiebreaker runs in the same direction, so a page boundary in the
	// middle of a tie resumes correctly.
	if ascendingKey(s) {
		return a.Fingerprint < b.Fingerprint
	}
	return a.Fingerprint > b.Fingerprint
}

// SortFindings orders a page in place.
func SortFindings(fs []model.Finding, s Sort) {
	sort.SliceStable(fs, func(i, j int) bool { return Less(fs[i], fs[j], s) })
}

// Cursor is an opaque position in a sorted result set.
//
// It carries the sort it was issued for. A cursor replayed against a different
// ordering is refused rather than reinterpreted: the same string would then
// mean a different position, and a paging session that changed sort mid-way
// would silently skip rows.
type Cursor struct {
	Field SortField `json:"f"`
	Dir   SortDir   `json:"d"`
	Key   string    `json:"k"`
	FP    string    `json:"p"`
}

// Encode renders a cursor as an opaque token.
//
// Opaque on purpose: a client that parsed it would couple itself to the
// ordering implementation, and a client that constructed one could ask for a
// position that does not exist.
func (c Cursor) Encode() string {
	raw, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// DecodeCursor parses a token, refusing one issued for a different ordering.
func DecodeCursor(token string, s Sort) (Cursor, error) {
	if token == "" {
		return Cursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return Cursor{}, fmt.Errorf("store: malformed cursor")
	}
	var c Cursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return Cursor{}, fmt.Errorf("store: malformed cursor")
	}
	s = s.Normalise()
	if c.Field != s.Field || c.Dir != s.Dir {
		return Cursor{}, fmt.Errorf(
			"store: this cursor was issued for %s %s and the query asks for %s %s; "+
				"resuming would skip or repeat rows, so it is refused rather than reinterpreted",
			c.Field, c.Dir, s.Field, s.Dir)
	}
	return c, nil
}

// After reports whether a finding falls strictly after the cursor position
// under this ordering. Strictly, so the row the cursor names is not served
// twice.
func (c Cursor) After(f model.Finding, s Sort) bool {
	if c.Key == "" && c.FP == "" {
		return true
	}
	s = s.Normalise()
	key := SortKey(f, s.Field)
	if key != c.Key {
		if ascendingKey(s) {
			return key > c.Key
		}
		return key < c.Key
	}
	if ascendingKey(s) {
		return f.Fingerprint > c.FP
	}
	return f.Fingerprint < c.FP
}

// CursorFor issues the cursor that resumes after this finding.
func CursorFor(f model.Finding, s Sort) Cursor {
	s = s.Normalise()
	return Cursor{Field: s.Field, Dir: s.Dir, Key: SortKey(f, s.Field), FP: f.Fingerprint}
}

// Page is one page of findings plus what the client needs to ask for the next.
type Page struct {
	Findings []model.Finding
	// Next is empty when this is the last page. Empty means END, not
	// "unknown": a client that had to guess would either stop early or loop.
	Next string
	// Matched is how many findings match the filter within the corpus, and
	// InCorpus how many the corpus holds at all. Both, because a count is
	// meaningless without saying what it counts (VM-UI-F-419).
	Matched  int
	InCorpus int
}

// FacetCounts is the per-option result count for every filter dimension
// (VM-UI-F-408).
//
// Counted under the OTHER active filters, so the numbers say what would happen
// if the option were added — which is the question the reader is actually
// asking. Options with zero are present with zero rather than absent: a hidden
// option looks like a dimension that does not exist, and the reader concludes
// the wrong thing about the fleet.
type FacetCounts struct {
	Repos      map[string]int `json:"repos"`
	Tiers      map[int]int    `json:"tiers"`
	Languages  map[string]int `json:"languages"`
	Categories map[string]int `json:"categories"`
	States     map[string]int `json:"states"`
	Reasons    map[string]int `json:"reasons"`
	Priorities map[string]int `json:"priorities"`
	Severities map[string]int `json:"severities"`
	Reachable  map[string]int `json:"reachable"`
	DepClasses map[string]int `json:"dep_classes"`
}

func newFacetCounts() FacetCounts {
	return FacetCounts{
		Repos: map[string]int{}, Tiers: map[int]int{}, Languages: map[string]int{},
		Categories: map[string]int{}, States: map[string]int{}, Reasons: map[string]int{},
		Priorities: map[string]int{}, Severities: map[string]int{}, Reachable: map[string]int{},
		DepClasses: map[string]int{},
	}
}

// --- small set helpers ------------------------------------------------------

func containsString(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func anyString(have, want []string) bool {
	for _, h := range have {
		if containsString(want, h) {
			return true
		}
	}
	return false
}

func containsInt(set []int, v int) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func containsReason(set []model.ReasonCode, v model.ReasonCode) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func containsPriority(set []model.Priority, v model.Priority) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func containsSeverity(set []model.Severity, v model.Severity) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func containsReachable(set []model.Reachable, v model.Reachable) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func containsDepClass(set []model.DepClass, v model.DepClass) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// SearchQuery is one interface query: a corpus, a filter, an ordering and a
// position.
//
// Scope is never defaulted (VM-ADR-14): a count is meaningless without stating
// which findings it counts, and a reader who did not choose the corpus is
// reading someone else's question.
type SearchQuery struct {
	Scope Scope
	// RunID is required for ScopeRun.
	RunID  string
	Filter Filter
	Sort   Sort
	// Cursor is an opaque token from a previous page's Next.
	Cursor string
	// Limit is the page size. Zero means DefaultPageSize; anything above
	// MaxPageSize is refused rather than clamped, because a client that asked
	// for ten thousand rows and silently got five hundred would paginate
	// wrongly and never know.
	Limit int
}

// Page size bounds.
const (
	DefaultPageSize = 50
	MaxPageSize     = 500
)

// Validate checks a query before either backend touches it.
//
// One function, so both backends refuse the same things. A query one backend
// accepts and the other rejects is a deployment-dependent API.
func (q SearchQuery) Validate() error {
	if !q.Scope.Valid() {
		return ErrScopeRequired
	}
	if q.Scope == ScopeRun && q.RunID == "" {
		return fmt.Errorf("store: scope %q requires a run identifier", ScopeRun)
	}
	if q.Sort.Field != "" && !q.Sort.Field.Valid() {
		return fmt.Errorf("store: unknown sort field %q; the offered set is %v", q.Sort.Field, AllSortFields)
	}
	if q.Sort.Dir != "" && !q.Sort.Dir.Valid() {
		return fmt.Errorf("store: unknown sort direction %q", q.Sort.Dir)
	}
	if q.Limit < 0 {
		return fmt.Errorf("store: negative page size %d", q.Limit)
	}
	if q.Limit > MaxPageSize {
		return fmt.Errorf("store: page size %d exceeds the maximum of %d; ask for pages rather "+
			"than being silently given one", q.Limit, MaxPageSize)
	}
	for _, s := range q.Filter.Severities {
		if !s.Valid() {
			return fmt.Errorf("store: unknown severity %q in filter", s)
		}
	}
	for _, p := range q.Filter.Priorities {
		if !p.Valid() {
			return fmt.Errorf("store: unknown priority %q in filter", p)
		}
	}
	for _, r := range q.Filter.Reachable {
		if !r.Valid() {
			return fmt.Errorf("store: unknown reachability %q in filter; the tri-state is "+
				"true, false or unknown (VM-F-243)", r)
		}
	}
	for _, st := range q.Filter.States {
		if !st.Valid() {
			return fmt.Errorf("store: unknown state %q in filter", st)
		}
	}
	return nil
}

// pageSize resolves the effective page size.
func (q SearchQuery) pageSize() int {
	if q.Limit > 0 {
		return q.Limit
	}
	return DefaultPageSize
}

// RunQuery lists runs for the history views.
type RunQuery struct {
	// Kind narrows to one run kind. Empty means every kind — and a caller that
	// mixes kinds in a TREND is making the mistake VM-UI-F-310 warns about, so
	// the trend endpoints always set it.
	Kind RunKind
	// BeforeSeq pages backwards through history: runs with a LOWER sequence
	// than this. Sequence, not offset, and not a timestamp: run identity is a
	// per-kind monotonic sequence (VM-ADR-11), so this is stable while runs
	// are being created underneath the paging session.
	BeforeSeq int64
	Limit     int
}

// pageSize resolves the effective run page size.
func (q RunQuery) pageSize() int {
	if q.Limit > 0 {
		return q.Limit
	}
	return 25
}
