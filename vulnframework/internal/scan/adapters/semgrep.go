package adapters

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

// Semgrep is the JavaScript/TypeScript static analysis adapter (VM-AD §8.2).
type Semgrep struct {
	Runner runner.CommandRunner
	Pinned string

	// Config selects the rulesets. The security rulesets are the default;
	// semgrep also ships correctness and best-practice rules that would swamp
	// the finding store, so results are additionally filtered on the rule's own
	// security category.
	Config string
}

// NewSemgrep builds the adapter pointed at semgrep's security rulesets.
func NewSemgrep(r runner.CommandRunner, version string) *Semgrep {
	return &Semgrep{Runner: r, Pinned: version, Config: "p/javascript"}
}

func (a *Semgrep) Name() string    { return "semgrep" }
func (a *Semgrep) Version() string { return a.Pinned }

func (a *Semgrep) Supports(r scan.RepoProfile) bool { return r.HasLanguage(scan.LangJavaScript) }

// Run executes semgrep in JSON mode.
func (a *Semgrep) Run(ctx context.Context, dir string, opts scan.RunOpts) (scan.RawOutput, error) {
	args := []string{"--json", "--quiet", "--config", a.Config}
	// Code findings are diff-scoped where a base is supplied; dependency
	// findings never are (VM-AD §8.5).
	if opts.Mode == scan.ModeDiff && opts.BaseSHA != "" {
		args = append(args, "--baseline-commit", opts.BaseSHA)
	}
	args = append(args, ".")

	res, err := a.Runner.Run(ctx, dir, "semgrep", args...)
	if err != nil {
		return scan.RawOutput{}, fmt.Errorf("semgrep: %w", err)
	}
	return scan.RawOutput{
		Tool: a.Name(), ToolVersion: a.Version(), Dir: dir,
		ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr,
	}, nil
}

type semgrepReport struct {
	Version string          `json:"version"`
	Results []semgrepResult `json:"results"`
	Errors  []struct {
		Message string `json:"message"`
		Level   string `json:"level"`
	} `json:"errors"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"start"`
	End struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"end"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Metadata struct {
			CWE        []string `json:"cwe"`
			OWASP      []string `json:"owasp"`
			Category   string   `json:"category"`
			Confidence string   `json:"confidence"`
			References []string `json:"references"`
		} `json:"metadata"`
		IsIgnored bool `json:"is_ignored"`
	} `json:"extra"`
}

// Normalize converts a semgrep report into raw findings, keeping only rules
// semgrep itself categorises as security.
func (a *Semgrep) Normalize(out scan.RawOutput) ([]model.RawFinding, error) {
	var report semgrepReport
	if err := json.Unmarshal(out.Stdout, &report); err != nil {
		return nil, fmt.Errorf("semgrep: parsing report: %w", err)
	}

	var raw []model.RawFinding
	for _, r := range report.Results {
		if r.Extra.IsIgnored {
			continue
		}
		// semgrep tags every rule with a category. Anything but security is a
		// code-quality observation this framework does not exist to report.
		if r.Extra.Metadata.Category != "security" {
			continue
		}

		advisory := ""
		if len(r.Extra.Metadata.References) > 0 {
			advisory = r.Extra.Metadata.References[0]
		}

		raw = append(raw, model.RawFinding{
			Repo:     out.Repo,
			Category: model.CategoryCode,
			Tool:     a.Name(),
			RuleID:   r.CheckID,
			File:     relPath(r.Path, out.Dir),
			Line:     r.Start.Line,
			Classification: model.Classification{
				Severity:  semgrepSeverity(r.Extra.Severity),
				Reachable: model.ReachableTrue,
				DepClass:  model.DepNotApplicable,
			},
			ToolVersion: a.Version(),
			AdvisoryURL: advisory,
			Raw:         mustRaw(r),
		})
	}

	raw = dedupe(raw)
	sortFindings(raw)
	return raw, nil
}

// semgrepSeverity maps semgrep's ERROR/WARNING/INFO to the model bands.
func semgrepSeverity(s string) model.Severity {
	switch s {
	case "ERROR":
		return model.SeverityHigh
	case "WARNING":
		return model.SeverityMedium
	case "INFO":
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}
