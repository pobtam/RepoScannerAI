// Package scan defines the scanner adapter contract (VM-AD §8.4) and the
// registry through which adapters are discovered.
//
// Adding a scanner means implementing Adapter and registering it. Nothing
// downstream changes (VM-NF-502).
package scan

import (
	"context"
	"fmt"
	"sort"

	"github.com/wanaware/vulnframework/internal/model"
)

// Language identifies a repository language for adapter selection.
type Language string

const (
	LangGo         Language = "go"
	LangJavaScript Language = "javascript"
)

// ModuleTopology records how a repository's modules are arranged (VM-F-208).
// A workspace must not be scanned as a single module (VM-F-225).
type ModuleTopology string

const (
	TopologySingle    ModuleTopology = "single"
	TopologyMulti     ModuleTopology = "multi"
	TopologyWorkspace ModuleTopology = "workspace"
)

// RepoProfile is what an adapter consults to decide whether it applies
// (VM-F-208). It carries no credentials: scan workers hold no credential that
// grants write access to any repository (VM-F-206).
type RepoProfile struct {
	Repo           string
	Languages      []Language
	Tier           int
	HasTestSuite   bool
	ModuleTopology ModuleTopology

	// HasLockfile reports a committed dependency lockfile. A JavaScript
	// repository without one is a coverage gap, not a clean result (VM-F-241).
	HasLockfile bool
}

// HasLanguage reports whether the repository uses l.
func (r RepoProfile) HasLanguage(l Language) bool {
	for _, got := range r.Languages {
		if got == l {
			return true
		}
	}
	return false
}

// Mode selects repository-wide or diff-scoped scanning (VM-F-207, VM-AD §8.5).
type Mode string

const (
	ModeFull Mode = "full"
	ModeDiff Mode = "diff"
)

// RunOpts parameterises one adapter invocation.
type RunOpts struct {
	Mode    Mode
	BaseSHA string
	HeadSHA string

	// ChangedFiles is the diff-scoped file set, repository-relative. It is
	// consulted only for code, secret and config findings: a pull request that
	// touches one handler can still be running a vulnerable dependency, so
	// dependency findings remain repository-wide (VM-AD §8.5).
	ChangedFiles []string

	// APICredits is the rate budget granted for this invocation (VM-AD §7.2).
	APICredits int

	// RunID, Repo and CommitSHA name exactly what is being scanned: the run,
	// the repository as owner/name, and the commit its tree on disk was taken
	// at. An adapter that scans remotely (NuGuard) uses them to scan the same
	// commit the local tools see. None is a credential, and no credential is
	// ever added to RunOpts (VM-F-206): a credential an adapter needs reaches
	// it through a function, as gh.TokenClient.Token does.
	//
	// The worker fills RunID and Repo from its own arguments. CommitSHA is
	// set by the dispatcher, and empty where nothing recorded the commit (a
	// checkout with no .git, a download that resolved none).
	RunID     string
	Repo      string
	CommitSHA string
}

// RawOutput is a tool's verbatim output plus the context needed to normalise
// it. Repo and Dir are required: fingerprints incorporate repository identity
// (VM-F-103) and paths must have the clone directory stripped before hashing.
type RawOutput struct {
	Tool        string
	ToolVersion string
	Repo        string
	Dir         string
	ExitCode    int
	Stdout      []byte
	Stderr      []byte

	// Aux carries repository files an adapter needs in order to normalise, keyed
	// by repository-relative path. It exists because some tools do not encode
	// everything the finding schema requires: npm audit's report says nothing
	// about whether a vulnerable package is a development-only dependency, and
	// VM-F-242 requires that classification as an input to prioritisation.
	//
	// Keeping those files here rather than reading them inside Normalize is what
	// keeps normalisation a pure function of bytes, which is what makes the
	// fixture tests meaningful.
	Aux map[string][]byte

	// Versions records what the tool reported about itself beyond its pinned
	// version, keyed as Result.ToolVersions is: "nuguard" (the version the
	// service reported), "nuguard/rulepack", "nuguard/image". The worker
	// merges it into the result's ToolVersions (VM-F-202). Nil for a tool
	// with nothing further to report.
	Versions map[string]string
}

// Adapter is the scanner contract (VM-AD §8.4).
//
// Run and Normalize are deliberately separate. Normalize is a pure function of
// bytes, which is what makes the fixture tests possible: real captured tool
// output in testdata/fixtures/<tool>/ normalises to an asserted result, and a
// tool changing its output format on upgrade fails the build instead of
// silently producing zero findings.
type Adapter interface {
	Name() string
	Version() string
	Supports(r RepoProfile) bool
	Run(ctx context.Context, dir string, opts RunOpts) (RawOutput, error)
	Normalize(out RawOutput) ([]model.RawFinding, error)
}

// Registry holds the adapters available to a scan worker.
type Registry struct {
	byName map[string]Adapter
}

// NewRegistry builds a registry from a set of adapters.
func NewRegistry(adapters ...Adapter) (*Registry, error) {
	r := &Registry{byName: make(map[string]Adapter, len(adapters))}
	for _, a := range adapters {
		if err := r.Register(a); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Register adds an adapter. Duplicate names are an error: two adapters
// answering to one name would make provenance ambiguous, and provenance is what
// tool-level verification depends on.
func (r *Registry) Register(a Adapter) error {
	if r.byName == nil {
		r.byName = map[string]Adapter{}
	}
	name := a.Name()
	if name == "" {
		return fmt.Errorf("scan: adapter with empty name")
	}
	if _, dup := r.byName[name]; dup {
		return fmt.Errorf("scan: adapter %q registered twice", name)
	}
	r.byName[name] = a
	return nil
}

// Get returns the adapter registered under name.
func (r *Registry) Get(name string) (Adapter, bool) {
	a, ok := r.byName[name]
	return a, ok
}

// Names returns every registered adapter name, sorted.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.byName))
	for n := range r.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// For returns the adapters applicable to a repository profile, sorted by name
// so that a scan's tool set is deterministic.
func (r *Registry) For(p RepoProfile) []Adapter {
	var out []Adapter
	for _, n := range r.Names() {
		if a := r.byName[n]; a.Supports(p) {
			out = append(out, a)
		}
	}
	return out
}
