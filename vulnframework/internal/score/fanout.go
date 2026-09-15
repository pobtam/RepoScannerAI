package score

import (
	"sort"

	"github.com/wanaware/vulnframework/internal/model"
)

// FanOut is the blast radius of a first-party module finding (VM-ADR-13).
//
// Depend-count and reach-count are kept separate and reported separately.
// Consumers of a vulnerable shared module are not uniformly exposed: a
// repository that imports the module but never calls the vulnerable path carries
// a real dependency and negligible risk. Reporting the dependency count as the
// impact figure inflates every first-party incident, and an escalation process
// that cries wolf stops being used.
type FanOut struct {
	// DependCount is how many repositories consume the module, directly or
	// transitively. It answers "who depends".
	DependCount int `json:"depend_count"`
	// ReachCount is how many of those execute the vulnerable path. It answers
	// "who is exposed".
	ReachCount int `json:"reach_count"`
	// Tier1ReachCount is the exposed subset that is tier 1.
	Tier1ReachCount int `json:"tier1_reach_count"`
	// UnknownReachCount is the subset whose reachability is undetermined. It is
	// reported rather than folded into either count: the tri-state survives
	// aggregation (VM-F-243).
	UnknownReachCount int `json:"unknown_reach_count"`

	// Consumers is the exposed set, sorted, so the counts can be checked
	// against names rather than trusted.
	Consumers []string `json:"consumers,omitempty"`

	// Truncated marks a traversal stopped by the depth ceiling. It is recorded
	// rather than silently accepted: an under-reported blast radius that looks
	// exact is worse than one that says it is incomplete.
	Truncated bool `json:"truncated,omitempty"`
}

// Consumer is one repository's consumption of a first-party module.
type Consumer struct {
	Repo      string
	Tier      int
	Reachable model.Reachable
	// OwnsModules are the first-party modules this repository publishes, which
	// is what makes the graph transitive — and cyclic.
	OwnsModules []string
	// Excluded marks a consumer the wave planner will skip, typically because a
	// replace directive means it does not resolve the module normally
	// (VM-F-608). Excluded consumers count for neither depend nor reach.
	Excluded bool
}

// Graph is the reverse-dependency index: which repositories consume a module
// (VM-AD §12.1).
//
// It is built from module_deps, which the scan populates at zero marginal cost.
type Graph struct {
	consumers map[string][]Consumer
}

// NewGraph builds an empty graph.
func NewGraph() *Graph { return &Graph{consumers: map[string][]Consumer{}} }

// Add records that a repository consumes a module.
func (g *Graph) Add(module string, c Consumer) {
	if g.consumers == nil {
		g.consumers = map[string][]Consumer{}
	}
	g.consumers[module] = append(g.consumers[module], c)
}

// Consumers returns the direct consumers of a module, sorted by repository so
// traversal order never depends on insertion order (VM-AD §12.1).
func (g *Graph) Consumers(module string) []Consumer {
	in := g.consumers[module]
	out := make([]Consumer, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Repo < out[j].Repo })
	return out
}

// depthLimit bounds traversal as a backstop.
//
// Termination is already guaranteed by the visited sets: each module is expanded
// at most once and each repository counted at most once, so the walk cannot
// revisit anything however cyclic the graph. This limit exists only to stop a
// future bug in that logic from looping for ever.
//
// It is therefore derived from the graph rather than fixed. A chain of N modules
// is a legitimate N-deep traversal, and a fixed ceiling silently truncated it —
// under-reporting a blast radius while looking exact, which is worse than either
// failing or taking longer. A traversal deeper than the number of modules that
// exist has revisited something, which is a defect, and Truncated says so.
func (g *Graph) depthLimit() int {
	n := len(g.consumers) + 1
	if n < 8 {
		n = 8
	}
	return n
}

// BlastRadius computes a module's fan-out across the transitive consumer graph.
//
// Two properties this must hold, both of which the tests assert directly:
//
// It TERMINATES on cyclic graphs. First-party modules genuinely do form cycles —
// two shared modules whose owning repositories consume each other is a normal
// arrangement, not a pathology — and a naive walk would recurse for ever.
//
// It does not DOUBLE-COUNT. A repository reachable by several paths through the
// graph is one repository, and counting it once per path would inflate the blast
// radius exactly where the graph is most tangled, which is where an accurate
// figure matters most.
//
// Both follow from the same mechanism: a repository is admitted to the frontier
// at most once, keyed on its name.
func (g *Graph) BlastRadius(module string) FanOut {
	var out FanOut

	// Modules already expanded, and repositories already counted. The repo set
	// is what gives both termination and exactly-once counting.
	seenModule := map[string]bool{module: true}
	seenRepo := map[string]bool{}

	limit := g.depthLimit()
	frontier := []string{module}
	for depth := 0; len(frontier) > 0; depth++ {
		if depth >= limit {
			// Unreachable unless the visited sets are broken: record it rather
			// than returning a quietly short answer.
			out.Truncated = true
			break
		}

		// Sorted so the walk is a deterministic function of the graph, never of
		// map iteration order.
		sort.Strings(frontier)
		var next []string

		for _, m := range frontier {
			for _, c := range g.Consumers(m) {
				// A replace-directive consumer does not resolve the module
				// normally, so it is neither exposed nor a dependant
				// (VM-F-608). It is excluded from both counts, not counted as
				// unreachable — those are different claims.
				if c.Excluded {
					continue
				}
				if seenRepo[c.Repo] {
					continue
				}
				seenRepo[c.Repo] = true

				out.DependCount++
				switch c.Reachable {
				case model.ReachableTrue:
					out.ReachCount++
					out.Consumers = append(out.Consumers, c.Repo)
					if c.Tier == 1 {
						out.Tier1ReachCount++
					}
				case model.ReachableUnknown:
					out.UnknownReachCount++
				}

				// Follow the modules this consumer itself publishes. This is
				// what makes the graph transitive, and what makes it cyclic.
				for _, owned := range c.OwnsModules {
					if !seenModule[owned] {
						seenModule[owned] = true
						next = append(next, owned)
					}
				}
			}
		}
		frontier = next
	}

	sort.Strings(out.Consumers)
	return out
}
