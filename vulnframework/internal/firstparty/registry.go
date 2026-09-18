// Package firstparty classifies findings that reach a repository through a
// shared internal module, and sequences the two-wave remediation that follows
// (VM-AD §12, VM-ADR-07).
//
// The shape of the problem: a vulnerability in `golang.org/x/crypto` that
// twenty repositories pull in through `github.com/wanaware/common` is ONE
// defect with one fix, in the module. Opening twenty pull requests that each
// bump the shared module's requirement fixes nothing until the module itself
// is fixed, and produces nineteen pull requests whose reviewers cannot act.
//
// So: Wave 1 fixes the owner and blocks the consumers; Wave 2 advances the
// consumers once the fix is published.
//
// Two properties are carried from earlier phases because they are the same
// properties. Propagation is a fold over a graph, so it is deterministic
// under permutation and terminating on cycles — as the cross-source merge and
// the fan-out scoring had to be. And blast radius is two numbers, not one,
// for the same reason reachability is a tri-state: collapsing a distinction
// that exists produces a confident figure that is wrong.
package firstparty

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/wanaware/vulnframework/internal/model"
)

// Trigger is what releases Wave 2 (VM-AD §12.3).
type Trigger string

const (
	// TriggerMerge releases consumers when the owner's pull request merges.
	TriggerMerge Trigger = "merge"
	// TriggerTag releases consumers when the owner publishes a tag. This puts
	// the owning repository's release process on the remediation SLA critical
	// path (VM-OQ-03), and introduces the merged-without-publish failure
	// (VM-F-614).
	TriggerTag Trigger = "tag"
)

// Registry maps first-party module paths to their owning repository
// (VM-F-601).
type Registry struct {
	Version int               `yaml:"version"`
	Wave2   Trigger           `yaml:"wave2_trigger"`
	Modules map[string]string `yaml:"modules"`

	// sorted holds module paths longest-first, so the most specific
	// registered prefix wins: a registry containing both
	// `wanaware/common` and `wanaware/common/hash` must resolve the
	// subpackage to its own owner.
	sorted []string
}

// ParseRegistry reads and validates the registry.
//
// Validation refuses anything it could not act on. A module with no owner
// would route its consumers' findings to nobody: they would leave the
// consumer's queue and arrive nowhere, which is worse than never having been
// classified.
func ParseRegistry(b []byte) (*Registry, error) {
	var r Registry
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("firstparty: %w", err)
	}
	if r.Version != 1 {
		return nil, fmt.Errorf("firstparty: unsupported registry version %d", r.Version)
	}
	if r.Wave2 == "" {
		r.Wave2 = TriggerMerge
	}
	if r.Wave2 != TriggerMerge && r.Wave2 != TriggerTag {
		return nil, fmt.Errorf("firstparty: wave2_trigger %q is neither %q nor %q", r.Wave2, TriggerMerge, TriggerTag)
	}

	for module, owner := range r.Modules {
		if strings.TrimSpace(module) == "" {
			return nil, fmt.Errorf("firstparty: a registry entry has no module path")
		}
		if strings.TrimSpace(owner) == "" {
			return nil, fmt.Errorf(
				"firstparty: module %q has no owning repository. A first-party module with no owner "+
					"routes its consumers' findings to nobody: they leave the consumer's queue and arrive "+
					"nowhere, which is worse than leaving them unclassified (VM-F-601)", module)
		}
		r.sorted = append(r.sorted, module)
	}
	// Longest first: the most specific registered path wins.
	sort.Slice(r.sorted, func(i, j int) bool { return len(r.sorted[i]) > len(r.sorted[j]) })
	return &r, nil
}

// Owner returns the repository that owns a module, resolving subpackages to
// their module's owner.
func (r *Registry) Owner(module string) (string, bool) {
	if r == nil {
		return "", false
	}
	if owner, ok := r.Modules[module]; ok {
		return owner, true
	}
	for _, registered := range r.sorted {
		// A boundary-aware prefix match. `wanaware/commonwealth` must not
		// match `wanaware/common`: the owning repository would be asked to fix
		// a module it has never heard of.
		if strings.HasPrefix(module, registered+"/") {
			return r.Modules[registered], true
		}
	}
	return "", false
}

// Module returns the REGISTERED module path an import path belongs to.
//
// Distinct from Owner, which answers "who fixes this", and from ClassifyPath,
// which answers "which first-party hop is nearest the consumer". This answers
// "which module is that hop part of", and it exists because a classified path
// is often a SUBPACKAGE: `github.com/wanaware/common/hash` is first-party and
// is not a module anyone depends on by that name.
//
// A wave keyed by the subpackage finds no consumers at all — every manifest
// row names the module — so it would render as a wave with nothing in it,
// which reads as "nobody is affected" rather than "we looked up the wrong
// key".
func (r *Registry) Module(path string) (string, bool) {
	if r == nil || path == "" {
		return "", false
	}
	if _, ok := r.Modules[path]; ok {
		return path, true
	}
	for _, registered := range r.sorted {
		if strings.HasPrefix(path, registered+"/") {
			return registered, true
		}
	}
	return "", false
}

// IsFirstParty reports whether a module is in the registry.
//
// The registry is the only authority. Nothing here infers membership from an
// organisation name or a path prefix: a plausible guess routes a finding to a
// repository that does not own the code, and its owner has no idea why.
func (r *Registry) IsFirstParty(module string) bool {
	_, ok := r.Owner(module)
	return ok
}

// ClassifyPath walks a vulnerable dependency's import path and returns the
// first-party module it traverses, nearest the consumer (VM-AD §12.2).
//
// Nearest the consumer, because that is the module the consumer can actually
// be advanced past. A deeper first-party hop is the NEXT wave's problem, and
// targeting it first would block the consumer on a fix two releases away.
func (r *Registry) ClassifyPath(path []string) string {
	if r == nil || len(path) < 2 {
		return ""
	}
	// path[0] is the consuming repository, not a module.
	for _, hop := range path[1:] {
		if r.IsFirstParty(hop) {
			return hop
		}
	}
	return ""
}

// Classify sets first_party_path on a raw finding (VM-AD §12.2).
//
// The owner is never classified as blocked on itself. That would tell the
// owning repository to wait for an upstream fix only it can make, and nothing
// would ever unblock it — a deadlock that presents as a permanently blocked
// finding with a plausible reason attached.
func (r *Registry) Classify(raw model.RawFinding) model.RawFinding {
	module := r.ClassifyPath(raw.ImportPath)
	if module == "" {
		return raw
	}
	owner, ok := r.Owner(module)
	if !ok || owner == raw.Repo {
		return raw
	}
	path := module
	raw.Classification.FirstPartyPath = &path
	return raw
}

// ClassifyAll classifies a batch, for use during normalisation.
func (r *Registry) ClassifyAll(raws []model.RawFinding) []model.RawFinding {
	if r == nil {
		return raws
	}
	out := make([]model.RawFinding, len(raws))
	for i, raw := range raws {
		out[i] = r.Classify(raw)
	}
	return out
}
