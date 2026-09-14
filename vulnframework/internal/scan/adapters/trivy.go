package adapters

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

// Trivy reports container and infrastructure misconfiguration (VM-AD §8.2,
// VM-F-265).
type Trivy struct {
	Runner runner.CommandRunner
	Pinned string
}

// NewTrivy builds the adapter with a pinned version from tools.lock.
func NewTrivy(r runner.CommandRunner, version string) *Trivy {
	return &Trivy{Runner: r, Pinned: version}
}

func (a *Trivy) Name() string    { return "trivy" }
func (a *Trivy) Version() string { return a.Pinned }

// Supports reports every repository: any repository may carry a Dockerfile or
// an infrastructure manifest.
func (a *Trivy) Supports(scan.RepoProfile) bool { return true }

// Run executes trivy's configuration scanner.
func (a *Trivy) Run(ctx context.Context, dir string, opts scan.RunOpts) (scan.RawOutput, error) {
	res, err := a.Runner.Run(ctx, dir, "trivy", "config", "--format", "json", "--quiet", ".")
	if err != nil {
		return scan.RawOutput{}, fmt.Errorf("trivy: %w", err)
	}
	return scan.RawOutput{
		Tool: a.Name(), ToolVersion: a.Version(), Dir: dir,
		ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr,
	}, nil
}

type trivyReport struct {
	SchemaVersion int    `json:"SchemaVersion"`
	ArtifactName  string `json:"ArtifactName"`
	Results       []struct {
		Target            string           `json:"Target"`
		Class             string           `json:"Class"`
		Type              string           `json:"Type"`
		Misconfigurations []trivyMisconfig `json:"Misconfigurations"`
	} `json:"Results"`
}

type trivyMisconfig struct {
	Type          string `json:"Type"`
	ID            string `json:"ID"`
	AVDID         string `json:"AVDID"`
	Title         string `json:"Title"`
	Description   string `json:"Description"`
	Message       string `json:"Message"`
	Severity      string `json:"Severity"`
	PrimaryURL    string `json:"PrimaryURL"`
	Status        string `json:"Status"`
	CauseMetadata struct {
		Provider  string `json:"Provider"`
		Service   string `json:"Service"`
		StartLine int    `json:"StartLine"`
		EndLine   int    `json:"EndLine"`
		Resource  string `json:"Resource"`
	} `json:"CauseMetadata"`
}

// Normalize converts a trivy config report into raw findings.
func (a *Trivy) Normalize(out scan.RawOutput) ([]model.RawFinding, error) {
	var report trivyReport
	if err := json.Unmarshal(out.Stdout, &report); err != nil {
		return nil, fmt.Errorf("trivy: parsing report: %w", err)
	}

	var raw []model.RawFinding
	for _, result := range report.Results {
		for _, m := range result.Misconfigurations {
			// Trivy reports passing checks alongside failures. Only failures
			// are findings.
			if m.Status != "FAIL" {
				continue
			}
			raw = append(raw, model.RawFinding{
				Repo:     out.Repo,
				Category: model.CategoryConfig,
				CheckID:  m.ID,
				Tool:     a.Name(),
				File:     relPath(result.Target, out.Dir),
				// The resource key distinguishes two failures of one check
				// against different resources in the same manifest. Dockerfile
				// checks carry no resource, in which case the check id alone
				// separates them (VM-AD §5).
				ResourceKey: m.CauseMetadata.Resource,
				Line:        m.CauseMetadata.StartLine,
				Classification: model.Classification{
					Severity:  severityFromBand(m.Severity),
					Reachable: model.ReachableUnknown,
					DepClass:  model.DepNotApplicable,
				},
				ToolVersion: a.Version(),
				AdvisoryURL: m.PrimaryURL,
				Raw:         mustRaw(m),
			})
		}
	}

	raw = dedupe(raw)
	sortFindings(raw)
	return raw, nil
}
