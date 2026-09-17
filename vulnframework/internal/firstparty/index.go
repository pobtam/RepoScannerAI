package firstparty

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/wanaware/vulnframework/internal/store"
)

// Dependency is one repository's use of one module, from the manifests already
// read during scanning (VM-F-602: at zero marginal cost).
type Dependency struct {
	Repo    string
	Module  string
	Version string
	Direct  bool
	// Replaced marks a `replace` directive affecting this module. Such a
	// consumer does not resolve the module from the registry at all, so
	// bumping its requirement changes nothing — and the bump would build,
	// pass, and close a finding that is still live (VM-F-608).
	Replaced bool
}

// Consumer is a repository that depends on a first-party module.
type Consumer struct {
	Repo     string `json:"repo"`
	Version  string `json:"version"`
	Replaced bool   `json:"replaced,omitempty"`
	// UpstreamFP is the owner's finding this consumer is waiting on, so a
	// consumer can discover what it is blocked by (VM-F-604).
	UpstreamFP string `json:"upstream_finding,omitempty"`
	// Reason explains an exclusion or a deferral. Never empty when one
	// applies: a consumer silently left out of a wave is a live finding nobody
	// is looking at.
	Reason string `json:"reason,omitempty"`
}

// Index is the reverse-dependency index (VM-AD §12.1).
//
// It is a standing artifact, queryable with no active finding, so exposure can
// be assessed before an advisory arrives (VM-F-612) rather than assembled in
// the hour someone needs it.
type Index struct {
	registry *Registry
	byModule map[string]map[string]Dependency // module -> repo -> dependency
}

// NewIndex builds an empty index.
func NewIndex(r *Registry) *Index {
	return &Index{registry: r, byModule: map[string]map[string]Dependency{}}
}

// Add records a dependency. Adding the same pair twice is an update, so a
// re-scan does not double-count a repository.
func (i *Index) Add(d Dependency) {
	if d.Repo == "" || d.Module == "" {
		return
	}
	if i.byModule[d.Module] == nil {
		i.byModule[d.Module] = map[string]Dependency{}
	}
	i.byModule[d.Module][d.Repo] = d
}

// Registry returns the ownership registry.
func (i *Index) Registry() *Registry { return i.registry }

// Owner returns a module's owning repository.
func (i *Index) Owner(module string) (string, bool) { return i.registry.Owner(module) }

// IsFirstParty reports registry membership.
func (i *Index) IsFirstParty(module string) bool { return i.registry.IsFirstParty(module) }

// Consumers returns the repositories depending on a module, sorted, excluding
// the owner itself.
//
// Sorted because every plan derived from it must be identical run to run: a
// wave that dispatched in map-iteration order would differ every time, and the
// difference would read as fleet churn rather than as a bug.
func (i *Index) Consumers(module string) []Consumer {
	owner, _ := i.Owner(module)

	var out []Consumer
	for repo, d := range i.byModule[module] {
		if repo == owner {
			// The owner is not its own consumer. Including it would put the
			// owning repository in its own wave, waiting for itself.
			continue
		}
		out = append(out, Consumer{Repo: repo, Version: d.Version, Replaced: d.Replaced})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Repo < out[b].Repo })
	return out
}

// Spread is the version distribution across a module's consumers (VM-F-613).
type Spread struct {
	Module   string     `json:"module"`
	Versions []string   `json:"versions"`
	Newest   string     `json:"newest"`
	Laggards []Consumer `json:"laggards,omitempty"`
}

// Diverged reports whether consumers sit on more than one version.
func (s Spread) Diverged() bool { return len(s.Versions) > 1 }

// VersionSpread computes the distribution before dispatch.
//
// Before, deliberately. Discovering divergence as half a wave of failed builds
// is the failure mode the specification calls out, and by then the pull
// requests exist and someone has to close them.
func (i *Index) VersionSpread(module string) Spread {
	consumers := i.Consumers(module)
	seen := map[string]bool{}
	s := Spread{Module: module}
	for _, c := range consumers {
		if c.Version != "" && !seen[c.Version] {
			seen[c.Version] = true
			s.Versions = append(s.Versions, c.Version)
		}
	}
	sort.Slice(s.Versions, func(a, b int) bool {
		return store.CompareVersions(s.Versions[a], s.Versions[b]) > 0
	})
	if len(s.Versions) > 0 {
		s.Newest = s.Versions[0]
	}
	for _, c := range consumers {
		if c.Version != "" && c.Version != s.Newest {
			c.Reason = fmt.Sprintf("on %s while the fleet's newest is %s", c.Version, s.Newest)
			s.Laggards = append(s.Laggards, c)
		}
	}
	return s
}

// Radius is blast radius, reported as the distinct figures it actually is
// (VM-F-611).
type Radius struct {
	Module string `json:"module"`
	// Depend is who has the dependency.
	Depend int `json:"depend"`
	// Reach is who executes the vulnerable path. This is the exposure figure.
	Reach int `json:"reach"`
	// NotReached is who demonstrably does not.
	NotReached int `json:"not_reached"`
	// Unknown is who has not been determined. Its own figure, never folded
	// into either side: folding it into reach overstates, and folding it into
	// not-reached understates, which is the more dangerous of the two.
	Unknown int `json:"unknown"`
}

// Summary renders the radius as the several numbers it is.
//
// The specification is unusually direct about why: reporting one number for
// both depend and reach overstates the incident and burns credibility. A
// two-repository incident presented as twenty is believed once; the next time
// a real twenty-repository incident arrives, nobody believes the number.
func (r Radius) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d repositories depend on %s; %d reach the vulnerable code",
		r.Depend, r.Module, r.Reach)
	if r.Unknown > 0 {
		fmt.Fprintf(&b, "; %d have not been determined and are UNKNOWN — not reachable and not "+
			"unreachable", r.Unknown)
	}
	b.WriteString(". Dependency count alone overstates exposure (VM-F-611).")
	return b.String()
}

// BlastRadius computes the radius from per-consumer reachability.
//
// reachable maps a consumer repository to "true", "false" or "unknown". A
// consumer absent from the map is UNKNOWN, and that is the whole point of
// VM-F-610: the upstream finding's reachability describes the OWNER. A
// consumer that has not been examined has not been examined, and inheriting
// the owner's verdict is the specific mistake that produces the overstated
// figure.
func (i *Index) BlastRadius(module string, reachable map[string]string) Radius {
	r := Radius{Module: module}
	for _, c := range i.Consumers(module) {
		r.Depend++
		switch reachable[c.Repo] {
		case "true":
			r.Reach++
		case "false":
			r.NotReached++
		default:
			r.Unknown++
		}
	}
	return r
}

// Propagation is the transitive consumer set of a first-party module.
type Propagation struct {
	Module string   `json:"module"`
	Repos  []string `json:"repos"`
	// Cyclic reports that the walk crossed a mutual first-party dependency.
	//
	// Reported rather than absorbed: two internal modules consuming each other
	// is an architectural fact someone should know, and a propagation that
	// quietly handled it would never surface it.
	Cyclic bool     `json:"cyclic"`
	Cycles []string `json:"cycles,omitempty"`
}

// Propagate walks the transitive consumers of a first-party module.
//
// Terminating and non-double-counting, for the same reasons the fan-out
// traversal had to be: a mutual dependency between two internal modules is an
// ordinary shape, a naive walk of it never returns, and one that revisits a
// repository reports a blast radius larger than the fleet.
func (i *Index) Propagate(module string) Propagation {
	p := Propagation{Module: module}

	seenRepo := map[string]bool{}
	expanded := map[string]bool{}
	// onStack is the current walk, so a back-edge is distinguishable from a
	// diamond. Two paths arriving at the same module is ordinary; a module
	// reachable from itself is the cycle worth naming.
	onStack := map[string]bool{}

	var walk func(current string)
	walk = func(current string) {
		if onStack[current] {
			p.Cyclic = true
			p.Cycles = append(p.Cycles, current)
			return
		}
		if expanded[current] {
			// Memoisation, not correctness: the repository set is already
			// deduplicated by seenRepo and termination is already guaranteed
			// by onStack. What this prevents is exponential WORK — a fleet
			// where modules share consumers forms a diamond, and re-walking
			// every path through it doubles with each layer.
			return
		}
		onStack[current] = true
		defer func() { onStack[current] = false }()
		expanded[current] = true

		for _, c := range i.Consumers(current) {
			if !seenRepo[c.Repo] {
				seenRepo[c.Repo] = true
				p.Repos = append(p.Repos, c.Repo)
			}
			// A consumer that owns a first-party module of its own extends
			// the walk: whoever depends on that module is also downstream of
			// this one.
			for _, owned := range i.modulesOwnedBy(c.Repo) {
				walk(owned)
			}
		}
	}
	walk(module)

	sort.Strings(p.Repos)
	sort.Strings(p.Cycles)
	p.Cycles = dedupe(p.Cycles)
	return p
}

// modulesOwnedBy returns the first-party modules a repository owns, sorted so
// the walk order does not depend on map iteration.
func (i *Index) modulesOwnedBy(repo string) []string {
	var out []string
	for module, owner := range i.registry.Modules {
		if owner == repo {
			out = append(out, module)
		}
	}
	sort.Strings(out)
	return out
}

func dedupe(in []string) []string {
	var out []string
	var last string
	for i, s := range in {
		if i == 0 || s != last {
			out = append(out, s)
		}
		last = s
	}
	return out
}

// LoadIndex builds the standing index from what scans recorded.
//
// This is the function whose absence made all of Phase 11 an assertion about
// hand-built data (OQ-P11-01). The index is only as good as the manifests
// recorded into it, and nothing here invents an entry: a repository that has
// never been scanned contributes nothing, and appears as a gap rather than as
// a repository with no dependencies.
func LoadIndex(ctx context.Context, s DepSource, r *Registry) (*Index, error) {
	deps, err := s.AllDeps(ctx)
	if err != nil {
		return nil, err
	}
	idx := NewIndex(r)
	for _, d := range deps {
		idx.Add(Dependency{
			Repo: d.Repo, Module: d.Module, Version: d.Version,
			Direct: d.Direct, Replaced: d.Replaced,
		})
	}
	return idx, nil
}

// DepSource is the store surface the index is built from.
type DepSource interface {
	AllDeps(ctx context.Context) ([]store.ModuleDep, error)
}
