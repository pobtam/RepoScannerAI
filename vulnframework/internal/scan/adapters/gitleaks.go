package adapters

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

// Gitleaks is the secret detection adapter (VM-AD §8.2).
//
// This adapter is the enforcement point for VM-F-264: redaction happens in the
// normalisation layer, before the value reaches any store or downstream
// consumer. gitleaks reports the matched credential verbatim in its Secret and
// Match fields; neither is ever copied into a finding, and the retained raw
// output is a reconstruction that structurally cannot contain them.
//
// Prompt-level instruction is explicitly not the control here (VM-F-264), and
// neither is a redaction pass further downstream: by the time output reaches a
// store, a log or a report, it is already too late.
type Gitleaks struct {
	Runner runner.CommandRunner
	Pinned string
}

// NewGitleaks builds the adapter with a pinned version from tools.lock.
func NewGitleaks(r runner.CommandRunner, version string) *Gitleaks {
	return &Gitleaks{Runner: r, Pinned: version}
}

func (a *Gitleaks) Name() string    { return "gitleaks" }
func (a *Gitleaks) Version() string { return a.Pinned }

// Supports reports every repository: secrets are language independent.
func (a *Gitleaks) Supports(scan.RepoProfile) bool { return true }

// Run executes gitleaks against the working tree (VM-F-261).
//
// History scanning runs on a separate, less frequent schedule (VM-F-262) and is
// not this invocation.
//
// Gitleaks honours the repository's own allowlists — .gitleaks.toml,
// .gitleaksignore and inline gitleaks:allow comments — and an allowlisted
// secret simply stops being reported, exactly as a deleted one does. The two
// must not be confused: one is still in the files, the other is gone, and
// neither has been rotated. So after the ordinary run, Run looks past the
// allowlists (see collectAllowlistEvidence) and hands what it finds to
// Normalize through Aux. If that second look fails, the whole run fails: a
// secret that read as "removed" when it was only allowlisted would be wrong
// in the direction that hides it.
func (a *Gitleaks) Run(ctx context.Context, dir string, opts scan.RunOpts) (scan.RawOutput, error) {
	res, err := a.Runner.Run(ctx, dir, "gitleaks", gitleaksArgs()...)
	if err != nil {
		return scan.RawOutput{}, fmt.Errorf("gitleaks: %w", err)
	}
	aux, err := a.collectAllowlistEvidence(ctx, dir)
	if err != nil {
		return scan.RawOutput{}, fmt.Errorf("gitleaks: looking past the repository's allowlists: %w", err)
	}
	return scan.RawOutput{
		Tool: a.Name(), ToolVersion: a.Version(), Dir: dir,
		ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr,
		Aux: aux,
	}, nil
}

// gitleaksArgs is the ordinary invocation plus any extra flags.
func gitleaksArgs(extra ...string) []string {
	return append([]string{"detect",
		"--no-git", "--report-format", "json", "--report-path", "/dev/stdout", "--redact"}, extra...)
}

// gitleaksHit mirrors gitleaks' report entry.
//
// Match and Secret are declared so the decoder consumes them and they are
// accounted for, never because they are used. Nothing in this file may copy
// either into a finding.
type gitleaksHit struct {
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Match       string   `json:"Match"`  // credential material — never propagated
	Secret      string   `json:"Secret"` // credential material — never propagated
	File        string   `json:"File"`
	SymlinkFile string   `json:"SymlinkFile"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Tags        []string `json:"Tags"`
	RuleID      string   `json:"RuleID"`
	Fingerprint string   `json:"Fingerprint"`
}

// redactedHit is the only shape of a secret finding that is ever retained. It
// records where the credential is and what kind it is, and has no field capable
// of holding the credential itself (VM-F-263).
type redactedHit struct {
	Description string  `json:"description"`
	RuleID      string  `json:"rule_id"`
	File        string  `json:"file"`
	StartLine   int     `json:"start_line"`
	EndLine     int     `json:"end_line"`
	Entropy     float64 `json:"entropy"`
	Redacted    bool    `json:"redacted"`
}

// Normalize converts a gitleaks report into redacted secret findings, plus a
// finding marked Allowlisted for each secret only the look past the
// repository's allowlists found.
func (a *Gitleaks) Normalize(out scan.RawOutput) ([]model.RawFinding, error) {
	var hits []gitleaksHit
	if err := json.Unmarshal(out.Stdout, &hits); err != nil {
		return nil, fmt.Errorf("gitleaks: parsing report: %w", err)
	}

	raw := a.secretFindings(out, hits, nil)
	allowlisted, err := a.allowlistedFindings(out, hits)
	if err != nil {
		return nil, err
	}
	raw = append(raw, allowlisted...)

	raw = dedupe(raw)
	sortFindings(raw)
	return raw, nil
}

// secretFindings builds redacted findings from gitleaks hits, each carrying
// evidence when evidence is non-nil.
func (a *Gitleaks) secretFindings(out scan.RawOutput, hits []gitleaksHit, evidence func(gitleaksHit, string) *model.Allowlist) []model.RawFinding {
	var raw []model.RawFinding
	for _, hit := range hits {
		file := relPath(hit.File, out.Dir)

		// The retained raw output is rebuilt from the safe fields only. It is
		// never the tool's original object, so there is no path by which Match
		// or Secret can survive into the store (VM-F-109 is satisfied without
		// violating VM-F-263).
		safe := redactedHit{
			Description: hit.Description,
			RuleID:      hit.RuleID,
			File:        file,
			StartLine:   hit.StartLine,
			EndLine:     hit.EndLine,
			Entropy:     hit.Entropy,
			Redacted:    true,
		}

		raw = append(raw, model.RawFinding{
			Repo:     out.Repo,
			Category: model.CategorySecret,
			// Identity is the detector rule; location is the file path alone,
			// so the finding survives the credential moving down the file
			// (VM-AD §5).
			DetectorRuleID: hit.RuleID,
			Tool:           a.Name(),
			File:           file,
			Line:           hit.StartLine,
			CredentialType: hit.RuleID,
			Classification: model.Classification{
				// Secrets take a fixed maximum severity and bypass the scoring
				// formula entirely (VM-AD §9.4).
				Severity:  model.SeverityCritical,
				Reachable: model.ReachableUnknown,
				DepClass:  model.DepNotApplicable,
			},
			ToolVersion: a.Version(),
			Raw:         mustRaw(safe),
		})
		if evidence != nil {
			raw[len(raw)-1].Allowlisted = evidence(hit, file)
		}
	}
	return raw
}
