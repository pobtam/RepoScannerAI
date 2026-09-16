// Package guard enforces what a remediation is not allowed to change
// (VM-AD §11.2 steps 5–6, VM-F-508/509/510).
//
// This is the most security-critical code in the remediation path, and the
// reason is narrow: a worker that can edit `.github/workflows/**` can weaken
// the CI that gates its own pull requests. That is a privilege-escalation loop
// which closes silently — the workflow change looks like part of the fix, the
// checks go green, and every later pull request inherits the weakened gate.
// Nothing downstream detects it, because the thing that would have detected it
// is what was edited.
//
// Three properties follow, and each is a test:
//
// It is a POST-CHANGE DIFF INSPECTION, never a prompt instruction and never a
// worker's self-report (VM-F-510, principle P4). The guard reads the tree.
//
// A violation REJECTS the whole change. It does not drop the offending file and
// push the remainder: a trimmed change is a partial fix (VM-F-506), and the
// violation would go unreported.
//
// It FAILS LOUD. An empty deny-list will not construct, because a guard that
// permits everything is indistinguishable from a guard nothing has tripped.
package guard

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/wanaware/vulnframework/internal/model"
)

// Config is the guard's configuration, sourced from policy.defaults.deny_paths.
type Config struct {
	DenyPaths []string
}

// Guard inspects a change set.
type Guard struct {
	patterns []pattern
}

// pattern keeps both spellings: the normalised form is what matching uses, and
// the configured form is what an error reports, so an operator reading an alert
// sees the line they wrote in policy.yaml.
type pattern struct {
	configured string
	normalised string
}

// Violation is one denied path and the pattern that denied it.
type Violation struct {
	Path    string `json:"path"`
	Pattern string `json:"pattern"`
}

// ErrDeniedPath reports a change to a protected path.
//
// It is a distinct type because the response is distinct: discard the branch,
// hard-fail the job, and alert. A caller that treated it like a build failure
// would retry, and retrying a privilege-escalation attempt is not a recovery
// strategy.
type ErrDeniedPath struct {
	Path       string
	Pattern    string
	Violations []Violation
}

func (e *ErrDeniedPath) Error() string {
	var also string
	if len(e.Violations) > 1 {
		also = fmt.Sprintf(" (%d protected paths were modified in total)", len(e.Violations))
	}
	return fmt.Sprintf(
		"guard: refusing the change: %q is a protected path, matching deny-list pattern %q%s. "+
			"The branch is discarded in full — the offending file is NOT dropped and the rest pushed, "+
			"because a partial fix must never be pushed (VM-F-506) and a trimmed violation goes unreported. "+
			"A worker able to edit the CI that gates its own pull requests could weaken that gate silently "+
			"(VM-F-508)",
		e.Path, e.Pattern, also)
}

// ErrSuppression reports an applied suppression directive (VM-F-507).
type ErrSuppression struct {
	Line    string
	Pattern string
}

func (e *ErrSuppression) Error() string {
	return fmt.Sprintf(
		"guard: refusing the change: it adds a suppression directive matching %q. "+
			"A suppression asserts a finding does not matter, which is a human judgement no worker may make. "+
			"Where suppression is correct it is PROPOSED in the pull request body and the finding marked "+
			"SUPPRESSION_PROPOSED (VM-F-507)",
		e.Pattern)
}

// ErrCredentialInDiff reports credential material added by a change.
//
// The message deliberately does not quote what it found: a guard that reports a
// leak by repeating it has moved the leak into the log (VM-F-263).
type ErrCredentialInDiff struct {
	Pattern string
}

func (e *ErrCredentialInDiff) Error() string {
	return fmt.Sprintf(
		"guard: refusing the change: an added line contains something matching %s, which is shaped like a "+
			"live credential. The value is not reproduced here. The branch is discarded; find how credential "+
			"material entered the working tree (VM-F-263)",
		e.Pattern)
}

// requiredKinds is the minimum deny-list VM-F-509 mandates. Each entry is a
// substring that must appear somewhere in the configured patterns.
//
// Checked at construction rather than trusted, because the failure mode of a
// short deny-list is silence: the guard is installed, it never fires, and
// nobody can tell whether that is because nothing tried or because nothing is
// covered.
var requiredKinds = []struct {
	name  string
	hints []string
}{
	{"CI workflow definitions", []string{".github/workflows", ".gitlab-ci", "azure-pipelines", "Jenkinsfile", ".circleci"}},
	{"code ownership", []string{"CODEOWNERS", "OWNERS"}},
	{"infrastructure-as-code", []string{".tf", ".tfvars", "helm", "k8s", "kustomization", "Dockerfile", "terraform"}},
}

// New builds a guard, refusing a configuration that would not protect anything.
func New(cfg Config) (*Guard, error) {
	if len(cfg.DenyPaths) == 0 {
		return nil, fmt.Errorf("guard: the deny-list is empty. " +
			"A guard with no patterns permits every path while appearing installed, and the symptom is " +
			"indistinguishable from a guard nothing has tripped (VM-F-508/509)")
	}

	joined := strings.ToLower(strings.Join(cfg.DenyPaths, "\n"))
	for _, kind := range requiredKinds {
		var found bool
		for _, hint := range kind.hints {
			if strings.Contains(joined, strings.ToLower(hint)) {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("guard: the deny-list covers no %s, which VM-F-509 requires at a minimum. "+
				"Configured patterns: %v", kind.name, cfg.DenyPaths)
		}
	}

	patterns := make([]pattern, len(cfg.DenyPaths))
	for i, p := range cfg.DenyPaths {
		patterns[i] = pattern{configured: p, normalised: normalise(p)}
	}
	return &Guard{patterns: patterns}, nil
}

// CheckPaths rejects a change set touching any protected path.
//
// It takes the paths the TREE reports — `git diff --name-only` — never a
// worker's account of what it changed.
func (g *Guard) CheckPaths(changed []string) error {
	violations := g.Violations(changed)
	if len(violations) == 0 {
		return nil
	}
	return &ErrDeniedPath{
		Path: violations[0].Path, Pattern: violations[0].Pattern, Violations: violations,
	}
}

// Violations returns every denied path, sorted, so an alert can say whether one
// file or forty were touched.
func (g *Guard) Violations(changed []string) []Violation {
	var out []Violation
	for _, raw := range changed {
		clean := normalise(raw)
		if clean == "" {
			continue
		}
		for _, p := range g.patterns {
			if matches(p.normalised, clean) {
				out = append(out, Violation{Path: raw, Pattern: p.configured})
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// suppressionPatterns match a directive that silences a tool.
//
// Kept here as well as in triage validation because the two guard different
// things: triage must not PROPOSE one in narrative, and remediation must not
// APPLY one to the tree. The second is the one that changes what the scanners
// will report next run.
var suppressionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)//\s*nolint`),
	regexp.MustCompile(`(?i)#\s*nolint`),
	regexp.MustCompile(`(?i)//\s*lint:ignore`),
	regexp.MustCompile(`(?i)#\s*nosemgrep`),
	regexp.MustCompile(`(?i)//\s*nosemgrep`),
	regexp.MustCompile(`(?i)gitleaks:\s*allow`),
	regexp.MustCompile(`(?i)golang:ignore`),
	regexp.MustCompile(`(?i)//\s*eslint-disable`),
	regexp.MustCompile(`(?i)/\*\s*eslint-disable`),
	regexp.MustCompile(`(?i)#\s*noqa`),
	regexp.MustCompile(`(?i)//\s*@ts-ignore`),
	regexp.MustCompile(`(?i)"?audit"?\s*:\s*\{[^}]*exception`),
	regexp.MustCompile(`(?i)\bnpm\s+audit\s+--?\w*\s*exception`),
}

// CheckDiff inspects the content a change adds (VM-AD §11.2 step 6).
//
// Only ADDED lines are examined. A diff that removes a suppression is a fix
// improving the codebase, and blocking it would turn the guard into an obstacle
// to the thing it protects.
func (g *Guard) CheckDiff(diff []byte) error {
	for _, line := range strings.Split(string(diff), "\n") {
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		added := strings.TrimPrefix(line, "+")

		for _, re := range suppressionPatterns {
			if re.MatchString(added) {
				return &ErrSuppression{Line: added, Pattern: re.String()}
			}
		}
		// The shared definition, so the tree, the ticket and the report cannot
		// disagree about what a credential looks like.
		var ce *model.ErrCredential
		if err := model.AssertNoCredential("diff", []byte(added)); err != nil {
			if asCredential(err, &ce) {
				return &ErrCredentialInDiff{Pattern: ce.Pattern}
			}
			return err
		}
	}
	return nil
}

// Check runs both inspections. Callers in the harness use this: the two guards
// are one step conceptually, and separating them at the call site invites one
// of them to be forgotten.
func (g *Guard) Check(changed []string, diff []byte) error {
	if err := g.CheckPaths(changed); err != nil {
		return err
	}
	return g.CheckDiff(diff)
}

func asCredential(err error, target **model.ErrCredential) bool {
	ce, ok := err.(*model.ErrCredential)
	if ok {
		*target = ce
	}
	return ok
}

// normalise reduces a path to one canonical spelling before matching.
//
// Every transformation here corresponds to a way the guard could otherwise be
// walked around: a leading `./`, a `..` segment that climbs back into a
// protected directory, doubled separators, a Windows separator, or a different
// case on a case-insensitive filesystem. `git diff --name-only` produces none
// of these, but it is not the only thing that ever feeds this function, and a
// guard should not depend on its caller being well behaved.
func normalise(p string) string {
	s := strings.ReplaceAll(p, `\`, "/")
	s = path.Clean(s)
	s = strings.TrimPrefix(s, "/")
	s = strings.TrimPrefix(s, "./")
	return strings.ToLower(s)
}

// matches implements the glob dialect the policy file uses: `*` within a path
// segment, `**` across segments.
//
// Written rather than taken from path.Match, which has no `**` and would
// therefore silently fail to match `.github/workflows/nested/deploy.yml` —
// a nested workflow being exactly the file most worth protecting.
func matches(pattern, name string) bool {
	return globMatch(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func globMatch(pattern, name []string) bool {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			// `**` matches zero or more segments: try every split.
			rest := pattern[1:]
			if len(rest) == 0 {
				return true
			}
			for i := 0; i <= len(name); i++ {
				if globMatch(rest, name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		if !segmentMatch(pattern[0], name[0]) {
			return false
		}
		pattern, name = pattern[1:], name[1:]
	}
	return len(name) == 0
}

// segmentMatch matches one path segment, honouring `*` but not `/`.
func segmentMatch(pattern, name string) bool {
	ok, err := path.Match(pattern, name)
	if err != nil {
		// A malformed pattern must not silently match nothing: treat it as a
		// literal, which is the conservative reading.
		return pattern == name
	}
	return ok
}
