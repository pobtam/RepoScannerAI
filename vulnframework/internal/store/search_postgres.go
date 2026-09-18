package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/wanaware/vulnframework/internal/model"
)

// The Postgres rendering of internal/store/query.go.
//
// Every predicate here mirrors one clause of Filter.Match, and the ordering
// mirrors Less. The mirror is checked, not trusted: the conformance suite runs
// the same corpus through both backends and compares the pages row for row, so
// a clause that drifts fails the build rather than producing a
// deployment-dependent answer.
//
// Where a value comes from the finding DOCUMENT rather than a column, the
// expression reads the document — severity, reachability, dependency class,
// module, aliases. Where it is a column, the column is used. And where the
// value is a JOIN — a repository's tier, an open pull request, a ticket — the
// predicate is an EXISTS, never a value copied onto the finding row, because a
// copy is a second source of truth that will go stale.

// severityCaseSQL renders the severity ordering from the SAME ranks the Go
// comparator uses.
//
// Generated rather than written out, so a new severity band cannot be ranked
// in Go and left unranked in SQL — which would sort it first in one backend
// and last in the other.
func severityCaseSQL(expr string) string {
	var b strings.Builder
	b.WriteString("CASE " + expr)
	for _, s := range model.AllSeverities {
		fmt.Fprintf(&b, " WHEN '%s' THEN '%d'", s, s.Rank())
	}
	// Anything not in the enumeration ranks after everything known, exactly as
	// Severity.Rank does for an unrecognised value.
	fmt.Fprintf(&b, " ELSE '%d' END", len(model.AllSeverities))
	return b.String()
}

const (
	sqlSeverity  = `f.data->'classification'->>'severity'`
	sqlReachable = `COALESCE(NULLIF(f.data->'classification'->>'reachable', ''), 'unknown')`
	sqlDepClass  = `COALESCE(f.data->'classification'->>'dep_class', '')`
	sqlModule    = `COALESCE(f.data->'location'->>'module', '')`
	sqlPackage   = `COALESCE(f.data->'location'->>'package', '')`
	sqlFile      = `COALESCE(f.data->'location'->>'file', '')`
	sqlPrimaryID = `COALESCE(f.data->'identity'->>'primary_id', '')`
	sqlRuleID    = `COALESCE(f.data->'identity'->>'rule_id', '')`
	sqlSLAStatus = `COALESCE(f.data->'derived'->>'sla_status', '')`
)

// sortExprSQL is the ordering key expression, rendered as TEXT so it compares
// in the same order as SortKey's string.
func sortExprSQL(field SortField) string {
	switch field {
	case SortSeverity:
		return severityCaseSQL(sqlSeverity)
	case SortFirstSeen:
		return `to_char(f.first_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`
	case SortLastSeen:
		return `to_char(f.last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`
	case SortRepo:
		return `f.repo`
	default:
		return `COALESCE(NULLIF(f.priority, ''), 'P9')`
	}
}

// builder accumulates a parameterised WHERE clause.
type builder struct {
	where []string
	args  []any
}

func (b *builder) add(clause string, args ...any) {
	// $n placeholders are numbered as they are added, so a clause is written
	// with %d markers and filled here. Hand-numbering is how a filter ends up
	// reading another filter's value.
	markers := make([]any, len(args))
	for i := range args {
		b.args = append(b.args, args[i])
		markers[i] = len(b.args)
	}
	b.where = append(b.where, fmt.Sprintf(clause, markers...))
}

func (b *builder) clause() string {
	if len(b.where) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(b.where, " AND ")
}

// scopeSQL narrows to the corpus (VM-ADR-14).
func (b *builder) scopeSQL(q SearchQuery) {
	switch q.Scope {
	case ScopeOpen:
		b.add("f.state <> ALL($%d)", pgTextArray(statesToStrings(model.StatesInPartition(model.PartitionResolved))))
	case ScopeRun:
		b.add("EXISTS (SELECT 1 FROM finding_observations o WHERE o.fingerprint = f.fingerprint AND o.run_id = $%d)", q.RunID)
	}
}

// filterSQL renders Filter.Match.
func (b *builder) filterSQL(f Filter) {
	if len(f.Repos) > 0 {
		b.add("f.repo = ANY($%d)", pgTextArray(f.Repos))
	}
	if len(f.Tiers) > 0 {
		b.add("EXISTS (SELECT 1 FROM repos r WHERE r.name = f.repo AND r.tier = ANY($%d))", pgIntArray(f.Tiers))
	}
	if len(f.Languages) > 0 {
		b.add("EXISTS (SELECT 1 FROM repos r WHERE r.name = f.repo AND r.languages && $%d)", pgTextArray(f.Languages))
	}
	if len(f.Categories) > 0 {
		b.add("f.category = ANY($%d)", pgTextArray(categoriesToStrings(f.Categories)))
	}
	if len(f.States) > 0 {
		b.add("f.state = ANY($%d)", pgTextArray(statesToStrings(f.States)))
	}
	if len(f.Reasons) > 0 {
		b.add("f.reason_code = ANY($%d)", pgTextArray(reasonsToStrings(f.Reasons)))
	}
	if len(f.Priorities) > 0 {
		b.add("f.priority = ANY($%d)", pgTextArray(prioritiesToStrings(f.Priorities)))
	}
	if len(f.Severities) > 0 {
		b.add(sqlSeverity+" = ANY($%d)", pgTextArray(severitiesToStrings(f.Severities)))
	}
	if len(f.Reachable) > 0 {
		b.add(sqlReachable+" = ANY($%d)", pgTextArray(reachableToStrings(f.Reachable)))
	}
	if len(f.DepClasses) > 0 {
		b.add(sqlDepClass+" = ANY($%d)", pgTextArray(depClassesToStrings(f.DepClasses)))
	}
	if f.Transitive != nil {
		b.add("COALESCE((f.data->'classification'->>'transitive')::boolean, false) = $%d", *f.Transitive)
	}
	if f.FirstParty != nil {
		b.add("(f.data->'classification'->>'first_party_path' IS NOT NULL) = $%d", *f.FirstParty)
	}
	if f.Blocked != nil {
		b.add("(f.state = $%d) = $%d", string(model.BlockedUpstream), *f.Blocked)
	}
	if f.HasPR != nil {
		b.add(`EXISTS (
			SELECT 1 FROM remediation_pr_findings pf
			JOIN remediation_prs p ON p.branch = pf.branch
			WHERE pf.fingerprint = f.fingerprint AND p.state = 'open' AND COALESCE(p.url, '') <> ''
		) = $%d`, *f.HasPR)
	}
	if f.HasTicket != nil {
		b.add(`EXISTS (
			SELECT 1 FROM tickets t WHERE t.fingerprint = f.fingerprint AND COALESCE(t.url, '') <> ''
		) = $%d`, *f.HasTicket)
	}
	if f.NotReobserved != nil {
		b.add("f.not_reobserved = $%d", *f.NotReobserved)
	}
	if f.SLABreached != nil {
		b.add("("+sqlSLAStatus+" = $%d) = $%d", string(model.SLABreached), *f.SLABreached)
	}
	if f.FirstSeenFrom != nil {
		b.add("f.first_seen_at >= $%d", f.FirstSeenFrom.UTC())
	}
	if f.FirstSeenTo != nil {
		b.add("f.first_seen_at <= $%d", f.FirstSeenTo.UTC())
	}
	if f.LastSeenFrom != nil {
		b.add("f.last_seen_at >= $%d", f.LastSeenFrom.UTC())
	}
	if f.LastSeenTo != nil {
		b.add("f.last_seen_at <= $%d", f.LastSeenTo.UTC())
	}
	if f.Text != "" {
		// The same fields SearchText lists, and no others. Searching the whole
		// document with `data::text ILIKE` would also match triage prose and
		// annotations, so the two backends would return different rows for the
		// same query — and the wider one would look like better search until
		// someone searched for "test".
		needle := "%" + escapeLike(f.Text) + "%"
		b.add(`(
			f.repo ILIKE $%d OR f.fingerprint ILIKE $%d
			OR `+sqlPrimaryID+` ILIKE $%d OR `+sqlRuleID+` ILIKE $%d
			OR `+sqlModule+` ILIKE $%d OR `+sqlPackage+` ILIKE $%d OR `+sqlFile+` ILIKE $%d
			OR EXISTS (
				SELECT 1 FROM jsonb_array_elements_text(
					COALESCE(f.data->'identity'->'aliases', '[]'::jsonb)) a
				WHERE a ILIKE $%d)
		)`, needle, needle, needle, needle, needle, needle, needle, needle)
	}
}

// escapeLike neutralises the wildcards a user may type, so searching for "50%"
// is a search for the characters rather than for everything.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	return strings.ReplaceAll(s, "_", `\_`)
}

// Search returns one filtered, sorted, cursor-paginated page.
func (p *Postgres) Search(ctx context.Context, q SearchQuery) (Page, error) {
	if err := q.Validate(); err != nil {
		return Page{}, err
	}
	sortBy := q.Sort.Normalise()
	cursor, err := DecodeCursor(q.Cursor, sortBy)
	if err != nil {
		return Page{}, err
	}

	// The corpus and the matched count, separately, because a count is
	// meaningless without saying what it counts (VM-UI-F-419).
	var corpusB builder
	corpusB.scopeSQL(q)
	inCorpus, err := p.countFindings(ctx, corpusB)
	if err != nil {
		return Page{}, err
	}

	var matchB builder
	matchB.scopeSQL(q)
	matchB.filterSQL(q.Filter)
	matched, err := p.countFindings(ctx, matchB)
	if err != nil {
		return Page{}, err
	}

	// The page: the same predicates, plus the keyset position.
	var pageB builder
	pageB.scopeSQL(q)
	pageB.filterSQL(q.Filter)

	expr := sortExprSQL(sortBy.Field)
	asc := ascendingKey(sortBy)
	if cursor.Key != "" || cursor.FP != "" {
		cmp := "<"
		if asc {
			cmp = ">"
		}
		// A row-value comparison, so the tie case resumes correctly: the
		// fingerprint breaks the tie in the same direction as the key.
		pageB.add("("+expr+", f.fingerprint) "+cmp+" ($%d, $%d)", cursor.Key, cursor.FP)
	}

	dir := "DESC"
	if asc {
		dir = "ASC"
	}
	query := qListFindingsBase + pageB.clause() +
		fmt.Sprintf(" ORDER BY %s %s, f.fingerprint %s LIMIT %d", expr, dir, dir, q.pageSize()+1)

	findings, err := p.queryFindings(ctx, query, pageB.args...)
	if err != nil {
		return Page{}, err
	}

	out := Page{Matched: matched, InCorpus: inCorpus}
	if len(findings) > q.pageSize() {
		findings = findings[:q.pageSize()]
		out.Next = CursorFor(findings[len(findings)-1], sortBy).Encode()
	}
	out.Findings = findings
	return out, nil
}

func (p *Postgres) countFindings(ctx context.Context, b builder) (int, error) {
	var n int
	if err := p.db.QueryRowContext(ctx,
		"SELECT count(*) FROM findings f"+b.clause(), b.args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: counting findings: %w", err)
	}
	return n, nil
}

// Facets counts each filter option under the other active filters.
//
// One aggregate query per dimension, with that dimension's own filter cleared.
// Not a count of the returned page: the page is fifty rows and the question is
// about the whole matching set.
func (p *Postgres) Facets(ctx context.Context, q SearchQuery) (FacetCounts, error) {
	if err := q.Validate(); err != nil {
		return FacetCounts{}, err
	}
	out := newFacetCounts()

	// Every option present, including at zero (VM-UI-F-408). The registry
	// supplies repositories, tiers and languages; the model supplies the
	// closed enumerations.
	repos, err := p.repoFacts(ctx)
	if err != nil {
		return FacetCounts{}, err
	}
	for name, facts := range repos {
		out.Repos[name] = 0
		out.Tiers[facts.Tier] = 0
		for _, l := range facts.Languages {
			out.Languages[l] = 0
		}
	}
	for _, c := range model.AllCategories {
		out.Categories[string(c)] = 0
	}
	for _, st := range model.AllStates {
		out.States[string(st)] = 0
	}
	for _, rc := range model.AllReasonCodes {
		out.Reasons[string(rc)] = 0
	}
	for _, pr := range model.AllPriorities {
		out.Priorities[string(pr)] = 0
	}
	for _, sv := range model.AllSeverities {
		out.Severities[string(sv)] = 0
	}
	for _, r := range model.AllReachable {
		out.Reachable[string(r)] = 0
	}
	for _, d := range []model.DepClass{model.DepProduction, model.DepDevelopment, model.DepNotApplicable} {
		out.DepClasses[string(d)] = 0
	}

	type dimension struct {
		expr  string
		clear func(*Filter)
		into  func(key string, n int)
	}
	dims := []dimension{
		{"f.repo", func(f *Filter) { f.Repos = nil }, func(k string, n int) { out.Repos[k] = n }},
		{"f.category", func(f *Filter) { f.Categories = nil }, func(k string, n int) { out.Categories[k] = n }},
		{"f.state", func(f *Filter) { f.States = nil }, func(k string, n int) { out.States[k] = n }},
		{"COALESCE(f.reason_code, '')", func(f *Filter) { f.Reasons = nil }, func(k string, n int) {
			if k != "" {
				out.Reasons[k] = n
			}
		}},
		{"COALESCE(f.priority, '')", func(f *Filter) { f.Priorities = nil }, func(k string, n int) {
			if k != "" {
				out.Priorities[k] = n
			}
		}},
		{sqlSeverity, func(f *Filter) { f.Severities = nil }, func(k string, n int) { out.Severities[k] = n }},
		{sqlReachable, func(f *Filter) { f.Reachable = nil }, func(k string, n int) { out.Reachable[k] = n }},
		{sqlDepClass, func(f *Filter) { f.DepClasses = nil }, func(k string, n int) {
			if k != "" {
				out.DepClasses[k] = n
			}
		}},
	}

	for _, d := range dims {
		narrowed := q
		f := q.Filter
		d.clear(&f)
		narrowed.Filter = f

		var b builder
		b.scopeSQL(narrowed)
		b.filterSQL(narrowed.Filter)
		rows, err := p.db.QueryContext(ctx,
			"SELECT "+d.expr+" AS k, count(*) FROM findings f"+b.clause()+" GROUP BY k", b.args...)
		if err != nil {
			return FacetCounts{}, fmt.Errorf("store: facet %s: %w", d.expr, err)
		}
		for rows.Next() {
			var key *string
			var n int
			if err := rows.Scan(&key, &n); err != nil {
				rows.Close()
				return FacetCounts{}, err
			}
			k := ""
			if key != nil {
				k = *key
			}
			d.into(k, n)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return FacetCounts{}, err
		}
		rows.Close()
	}

	// Tier and language are repository properties, so they are counted by
	// joining rather than grouping on the finding row.
	for _, dim := range []struct {
		clear func(*Filter)
		apply func(RepoFacts, int)
	}{
		{func(f *Filter) { f.Tiers = nil }, func(r RepoFacts, n int) { out.Tiers[r.Tier] += n }},
		{func(f *Filter) { f.Languages = nil }, func(r RepoFacts, n int) {
			for _, l := range r.Languages {
				out.Languages[l] += n
			}
		}},
	} {
		narrowed := q
		f := q.Filter
		dim.clear(&f)
		narrowed.Filter = f

		var b builder
		b.scopeSQL(narrowed)
		b.filterSQL(narrowed.Filter)
		rows, err := p.db.QueryContext(ctx,
			"SELECT f.repo, count(*) FROM findings f"+b.clause()+" GROUP BY f.repo", b.args...)
		if err != nil {
			return FacetCounts{}, fmt.Errorf("store: facet by repository: %w", err)
		}
		perRepo := map[string]int{}
		for rows.Next() {
			var repo string
			var n int
			if err := rows.Scan(&repo, &n); err != nil {
				rows.Close()
				return FacetCounts{}, err
			}
			perRepo[repo] = n
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return FacetCounts{}, err
		}
		rows.Close()
		for repo, n := range perRepo {
			dim.apply(repos[repo], n)
		}
	}

	return out, nil
}

// repoFacts loads the registry properties a facet count needs.
func (p *Postgres) repoFacts(ctx context.Context) (map[string]RepoFacts, error) {
	names, err := p.RepoNames(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]RepoFacts, len(names))
	for _, n := range names {
		r, err := p.GetRepo(ctx, n)
		if err != nil {
			return nil, err
		}
		out[n] = RepoFacts{Tier: r.Tier, Languages: r.Languages}
	}
	return out, nil
}

// --- enumeration renderings -------------------------------------------------

func reasonsToStrings(rs []model.ReasonCode) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}

func prioritiesToStrings(ps []model.Priority) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	return out
}

func severitiesToStrings(ss []model.Severity) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = string(s)
	}
	return out
}

func reachableToStrings(rs []model.Reachable) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}

func depClassesToStrings(ds []model.DepClass) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = string(d)
	}
	return out
}

// pgIntArray renders a Go int slice as a Postgres integer array literal.
func pgIntArray(vs []int) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return "{" + strings.Join(parts, ",") + "}"
}
