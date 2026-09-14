package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

// Gosec is the Go static analysis adapter (VM-AD §8.2).
//
// Thresholds are configurable per tier (VM-F-224); the defaults here are the
// specification's `-severity=medium -confidence=medium`. Calibration of those
// thresholds is VM-OQ-06, deferred to Phase 5 shadow running.
type Gosec struct {
	Runner runner.CommandRunner
	Pinned string

	// MinSeverity and MinConfidence are the per-tier thresholds (VM-F-224).
	MinSeverity   string
	MinConfidence string
}

// NewGosec builds the adapter with the specification's default thresholds.
func NewGosec(r runner.CommandRunner, version string) *Gosec {
	return &Gosec{Runner: r, Pinned: version, MinSeverity: "medium", MinConfidence: "medium"}
}

func (a *Gosec) Name() string    { return "gosec" }
func (a *Gosec) Version() string { return a.Pinned }

func (a *Gosec) Supports(r scan.RepoProfile) bool { return r.HasLanguage(scan.LangGo) }

// Run executes gosec in JSON mode at the configured thresholds.
func (a *Gosec) Run(ctx context.Context, dir string, opts scan.RunOpts) (scan.RawOutput, error) {
	res, err := a.Runner.Run(ctx, dir, "gosec",
		"-fmt=json", "-severity="+a.MinSeverity, "-confidence="+a.MinConfidence, "./...")
	if err != nil {
		return scan.RawOutput{}, fmt.Errorf("gosec: %w", err)
	}
	return scan.RawOutput{
		Tool: a.Name(), ToolVersion: a.Version(), Dir: dir,
		ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr,
	}, nil
}

type gosecReport struct {
	Issues []struct {
		Severity   string `json:"severity"`
		Confidence string `json:"confidence"`
		CWE        struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		} `json:"cwe"`
		RuleID  string `json:"rule_id"`
		Details string `json:"details"`
		File    string `json:"file"`
		Line    string `json:"line"`
		Column  string `json:"column"`
		Nosec   bool   `json:"nosec"`
	} `json:"Issues"`
	GosecVersion string `json:"GosecVersion"`
}

// Normalize converts a gosec report into raw findings.
//
// gosec reports a file and line but no enclosing function, so these findings
// take the file-path fallback for their fingerprint location (VM-AD §5). Two
// instances of one rule in a file therefore collapse to a single finding, which
// VM-ADR-04 accepts: the remediation is the same edit.
func (a *Gosec) Normalize(out scan.RawOutput) ([]model.RawFinding, error) {
	var report gosecReport
	if err := json.Unmarshal(out.Stdout, &report); err != nil {
		return nil, fmt.Errorf("gosec: parsing report: %w", err)
	}

	var raw []model.RawFinding
	for _, issue := range report.Issues {
		// A suppressed issue is not a finding. Recording it as one would put
		// the framework in the business of second-guessing an explicit,
		// reviewed in-repository decision.
		if issue.Nosec {
			continue
		}
		line, _ := strconv.Atoi(issue.Line)

		raw = append(raw, model.RawFinding{
			Repo:     out.Repo,
			Category: model.CategoryCode,
			Tool:     a.Name(),
			RuleID:   issue.RuleID,
			File:     relPath(issue.File, out.Dir),
			Line:     line,
			Classification: model.Classification{
				Severity: severityFromBand(issue.Severity),
				// Static analysis findings are in first-party code, which is by
				// definition executed; the tri-state applies to dependency
				// reachability, not to code the repository itself contains.
				Reachable: model.ReachableTrue,
				DepClass:  model.DepNotApplicable,
			},
			ToolVersion: a.Version(),
			AdvisoryURL: issue.CWE.URL,
			Raw:         mustRaw(issue),
		})
	}

	raw = dedupe(raw)
	sortFindings(raw)
	return raw, nil
}
