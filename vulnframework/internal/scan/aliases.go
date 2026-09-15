package scan

import (
	"sort"
	"strings"

	"github.com/wanaware/vulnframework/internal/model"
)

// AliasTable groups advisory identifiers that name the same defect (VM-AD §5).
//
// Alias resolution must happen before fingerprinting. Tools report one defect
// under different namespaces — govulncheck reports GO-2025-3487, trivy reports
// CVE-2025-22869 — and without resolution these produce two fingerprints, two
// findings and two tickets, and the deduplication requirement (VM-F-106) fails.
//
// Crucially, the tool reporting the CVE need not know the GO identifier: trivy
// emits no alias set at all. The table is populated from the tools that do
// publish OSV alias data, and every finding in the scan is enriched from it, so
// one tool's knowledge repairs another's blind spot.
type AliasTable struct {
	parent map[string]string
}

// NewAliasTable builds an empty table.
func NewAliasTable() *AliasTable { return &AliasTable{parent: map[string]string{}} }

// Add records that every identifier given names the same defect.
func (t *AliasTable) Add(ids ...string) {
	var prev string
	for _, raw := range ids {
		id := normaliseID(raw)
		if id == "" {
			continue
		}
		t.add(id)
		if prev != "" {
			t.union(prev, id)
		}
		prev = id
	}
}

// AddFindings populates the table from a set of findings' identity fields.
func (t *AliasTable) AddFindings(findings []model.RawFinding) {
	for _, f := range findings {
		if f.Category != model.CategoryDependency {
			continue
		}
		t.Add(append([]string{f.PrimaryID}, f.Aliases...)...)
	}
}

// Group returns every identifier known to name the same defect as id, sorted.
// An unknown identifier returns just itself.
func (t *AliasTable) Group(id string) []string {
	id = normaliseID(id)
	if id == "" {
		return nil
	}
	root, known := t.find(id)
	if !known {
		return []string{id}
	}
	var out []string
	for member := range t.parent {
		if r, _ := t.find(member); r == root {
			out = append(out, member)
		}
	}
	sort.Strings(out)
	return out
}

// Enrich widens every dependency finding's alias set with the identifiers the
// table knows for it, so that fingerprinting resolves to the same canonical
// identifier whichever tool reported the defect.
//
// It never changes PrimaryID: what the tool said it found is preserved as
// provenance, and the canonical choice is made by the precedence rule at
// fingerprint time.
func (t *AliasTable) Enrich(findings []model.RawFinding) []model.RawFinding {
	out := make([]model.RawFinding, len(findings))
	copy(out, findings)

	for i := range out {
		if out[i].Category != model.CategoryDependency {
			continue
		}
		group := t.Group(out[i].PrimaryID)
		if len(group) <= 1 {
			continue
		}
		seen := map[string]bool{normaliseID(out[i].PrimaryID): true}
		aliases := make([]string, 0, len(group))
		for _, a := range out[i].Aliases {
			if n := normaliseID(a); n != "" && !seen[n] {
				seen[n] = true
				aliases = append(aliases, n)
			}
		}
		for _, id := range group {
			if !seen[id] {
				seen[id] = true
				aliases = append(aliases, id)
			}
		}
		sort.Strings(aliases)
		out[i].Aliases = aliases
	}
	return out
}

// Size reports how many identifiers the table knows.
func (t *AliasTable) Size() int { return len(t.parent) }

func (t *AliasTable) add(id string) {
	if _, ok := t.parent[id]; !ok {
		t.parent[id] = id
	}
}

func (t *AliasTable) find(id string) (string, bool) {
	root, ok := t.parent[id]
	if !ok {
		return id, false
	}
	for root != t.parent[root] {
		t.parent[root] = t.parent[t.parent[root]] // path halving
		root = t.parent[root]
	}
	t.parent[id] = root
	return root, true
}

func (t *AliasTable) union(a, b string) {
	ra, _ := t.find(a)
	rb, _ := t.find(b)
	if ra == rb {
		return
	}
	// Deterministic merge: the lexicographically smaller root wins, so the
	// table's shape does not depend on the order findings arrived in.
	if ra < rb {
		t.parent[rb] = ra
	} else {
		t.parent[ra] = rb
	}
}

func normaliseID(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }
