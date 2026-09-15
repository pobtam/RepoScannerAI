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

// Run executes trivy over both misconfiguration and dependency scanners
// (VM-AD §8.2: "trivy config / trivy fs").
//
// The vulnerability scanner matters beyond cross-checking: trivy reports Go
// advisories under CVE identifiers where govulncheck reports GO ones, which is
// the cross-namespace case alias resolution exists for (VM-AD §5).
func (a *Trivy) Run(ctx context.Context, dir string, opts scan.RunOpts) (scan.RawOutput, error) {
	res, err := a.Runner.Run(ctx, dir, "trivy", "fs", "--scanners", "vuln,misconfig", "--format", "json", "--quiet", ".")
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
		Target            string               `json:"Target"`
		Class             string               `json:"Class"`
		Type              string               `json:"Type"`
		Misconfigurations []trivyMisconfig     `json:"Misconfigurations"`
		Vulnerabilities   []trivyVulnerability `json:"Vulnerabilities"`
	} `json:"Results"`
}

// trivyVulnerability is one dependency advisory.
//
// Trivy publishes no alias set of its own, so a CVE it reports can only be
// matched to another tool's GO or GHSA identifier through the scan's alias
// table (VM-AD §5).
type trivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	PrimaryURL       string `json:"PrimaryURL"`
	Status           string `json:"Status"`
	CVSS             map[string]struct {
		V3Score float64 `json:"V3Score"`
	} `json:"CVSS"`
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

// bestCVSS takes the highest v3 base score trivy reports across its sources.
func bestCVSS(v trivyVulnerability) float64 {
	var best float64
	for _, c := range v.CVSS {
		if c.V3Score > best {
			best = c.V3Score
		}
	}
	return best
}

// Normalize converts a trivy report into raw findings, covering both the
// dependency and misconfiguration scanners.
func (a *Trivy) Normalize(out scan.RawOutput) ([]model.RawFinding, error) {
	var report trivyReport
	if err := json.Unmarshal(out.Stdout, &report); err != nil {
		return nil, fmt.Errorf("trivy: parsing report: %w", err)
	}

	var raw []model.RawFinding
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			raw = append(raw, model.RawFinding{
				Repo:        out.Repo,
				Category:    model.CategoryDependency,
				PrimaryID:   v.VulnerabilityID,
				Tool:        a.Name(),
				Module:      v.PkgName,
				ModuleMajor: moduleMajor(v.PkgName, v.InstalledVersion),
				Versions: model.Versions{
					Current: v.InstalledVersion,
					Fixed:   v.FixedVersion,
				},
				Classification: model.Classification{
					Severity: severityFromBand(v.Severity),
					CVSS:     bestCVSS(v),
					// Trivy performs no reachability analysis.
					Reachable: model.ReachableUnknown,
					DepClass:  model.DepProduction,
				},
				ToolVersion: a.Version(),
				AdvisoryURL: v.PrimaryURL,
				Raw:         mustRaw(v),
			})
		}

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
