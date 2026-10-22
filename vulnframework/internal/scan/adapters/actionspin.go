package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

// ActionsPin reports third-party GitHub Actions referenced by mutable tag
// rather than commit SHA (VM-F-266, VM-AD §8.2 "(internal)").
//
// This is the one adapter with no external binary: it parses
// .github/workflows/* directly. It still implements scan.Adapter so the scan
// worker treats it identically — a failure here is a coverage gap like any
// other, and its output is fixture-tested like any other.
//
// The defect it reports is real: a mutable tag can be repointed by whoever
// controls the action's repository, which makes every workflow referencing it a
// standing supply-chain exposure.
type ActionsPin struct {
	Pinned string
}

// NewActionsPin builds the adapter.
func NewActionsPin(_ runner.CommandRunner, version string) *ActionsPin {
	return &ActionsPin{Pinned: version}
}

func (a *ActionsPin) Name() string    { return "actions-pin" }
func (a *ActionsPin) Version() string { return a.Pinned }

// Supports reports every repository: any repository may define workflows.
func (a *ActionsPin) Supports(scan.RepoProfile) bool { return true }

// usesLine matches a `uses:` step reference in a workflow file.
var usesLine = regexp.MustCompile(`^\s*(?:-\s*)?uses:\s*['"]?([^'"\s#]+)['"]?`)

// fullSHA matches a 40-character hexadecimal git object name.
var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// actionsPinOutput is this adapter's own tool output. Producing an intermediate
// document rather than findings directly keeps Run/Normalize split the same way
// as every other adapter, so the same fixture discipline applies.
type actionsPinOutput struct {
	Tool    string         `json:"tool"`
	Version string         `json:"version"`
	Uses    []actionsUsage `json:"uses"`
}

type actionsUsage struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Job    string `json:"job"`
	Step   string `json:"step"`
	Uses   string `json:"uses"`
	Ref    string `json:"ref"`
	Pinned bool   `json:"pinned"`
}

// Run walks .github/workflows and records every action reference.
func (a *ActionsPin) Run(ctx context.Context, dir string, opts scan.RunOpts) (scan.RawOutput, error) {
	out := actionsPinOutput{Tool: a.Name(), Version: a.Version()}

	workflows := filepath.Join(dir, ".github", "workflows")
	entries, err := os.ReadDir(workflows)
	if err != nil {
		if os.IsNotExist(err) {
			// No workflows is a clean result, not a gap.
			stdout, _ := json.Marshal(out)
			return scan.RawOutput{
				Tool: a.Name(), ToolVersion: a.Version(), Dir: dir, Stdout: stdout,
			}, nil
		}
		return scan.RawOutput{}, fmt.Errorf("actions-pin: reading workflows: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ext := strings.ToLower(filepath.Ext(e.Name())); ext != ".yml" && ext != ".yaml" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		rel := path.Join(".github", "workflows", name)
		content, err := os.ReadFile(filepath.Join(workflows, name))
		if err != nil {
			if err, ok := err.(*fs.PathError); ok {
				return scan.RawOutput{}, fmt.Errorf("actions-pin: %w", err)
			}
			return scan.RawOutput{}, fmt.Errorf("actions-pin: reading %s: %w", rel, err)
		}
		out.Uses = append(out.Uses, parseUses(rel, string(content))...)
	}

	stdout, err := json.Marshal(out)
	if err != nil {
		return scan.RawOutput{}, fmt.Errorf("actions-pin: encoding output: %w", err)
	}
	return scan.RawOutput{
		Tool: a.Name(), ToolVersion: a.Version(), Dir: dir, Stdout: stdout,
	}, nil
}

// parseUses extracts action references from a workflow document.
func parseUses(file, content string) []actionsUsage {
	var out []actionsUsage
	for i, line := range strings.Split(content, "\n") {
		m := usesLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ref := m[1]
		// A local or container action is not a third-party tag reference.
		if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
			continue
		}
		at := strings.LastIndex(ref, "@")
		if at < 0 {
			continue
		}
		version := ref[at+1:]
		out = append(out, actionsUsage{
			File:   file,
			Line:   i + 1,
			Uses:   ref,
			Ref:    version,
			Pinned: fullSHA.MatchString(version),
		})
	}
	return out
}

// Normalize converts the usage inventory into findings for unpinned actions.
func (a *ActionsPin) Normalize(out scan.RawOutput) ([]model.RawFinding, error) {
	var parsed actionsPinOutput
	if err := json.Unmarshal(out.Stdout, &parsed); err != nil {
		return nil, fmt.Errorf("actions-pin: parsing output: %w", err)
	}

	var raw []model.RawFinding
	for _, u := range parsed.Uses {
		if u.Pinned {
			continue
		}
		action := u.Uses
		if at := strings.LastIndex(action, "@"); at >= 0 {
			action = action[:at]
		}

		raw = append(raw, model.RawFinding{
			Repo:     out.Repo,
			Category: model.CategoryConfig,
			CheckID:  "ACTIONS-UNPINNED",
			Tool:     a.Name(),
			File:     relPath(u.File, out.Dir),
			// The resource key is the action being referenced, so two unpinned
			// actions in one workflow are two findings rather than one.
			ResourceKey: action,
			Line:        u.Line,
			Classification: model.Classification{
				Severity:  model.SeverityMedium,
				Reachable: model.ReachableUnknown,
				DepClass:  model.DepNotApplicable,
			},
			ToolVersion: a.Version(),
			AdvisoryURL: "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
			Description: fmt.Sprintf("The workflow uses %s by a tag or branch rather than a full commit SHA. "+
				"Whoever controls that tag can change the code this repository's workflow runs; pin it to a commit SHA.", u.Uses),
			Raw: mustRaw(u),
		})
	}

	raw = dedupe(raw)
	sortFindings(raw)
	return raw, nil
}
