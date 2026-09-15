package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

// OSVScanner cross-checks dependencies against the OSV database (VM-AD §8.2).
//
// For Go it catches what reachability analysis skips; for JavaScript it is the
// primary lockfile scanner. It cannot determine reachability for either, so it
// reports reachable=unknown and never asserts otherwise — for Go findings
// govulncheck supplies the verdict for the same fingerprint, and the store
// merges them.
type OSVScanner struct {
	Runner runner.CommandRunner
	Pinned string
}

// NewOSVScanner builds the adapter with a pinned version from tools.lock.
func NewOSVScanner(r runner.CommandRunner, version string) *OSVScanner {
	return &OSVScanner{Runner: r, Pinned: version}
}

func (a *OSVScanner) Name() string    { return "osv-scanner" }
func (a *OSVScanner) Version() string { return a.Pinned }

// Supports reports Go and JavaScript repositories.
func (a *OSVScanner) Supports(r scan.RepoProfile) bool {
	return r.HasLanguage(scan.LangGo) || r.HasLanguage(scan.LangJavaScript)
}

// Run executes osv-scanner over the repository.
func (a *OSVScanner) Run(ctx context.Context, dir string, opts scan.RunOpts) (scan.RawOutput, error) {
	res, err := a.Runner.Run(ctx, dir, "osv-scanner", "--format", "json", "--recursive", ".")
	if err != nil {
		return scan.RawOutput{}, fmt.Errorf("osv-scanner: %w", err)
	}
	return scan.RawOutput{
		Tool: a.Name(), ToolVersion: a.Version(), Dir: dir,
		ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr,
	}, nil
}

type osvReport struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
			Groups          []struct {
				IDs         []string `json:"ids"`
				Aliases     []string `json:"aliases"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

type osvVulnerability struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Affected []struct {
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// Normalize converts an osv-scanner JSON report into raw findings.
func (a *OSVScanner) Normalize(out scan.RawOutput) ([]model.RawFinding, error) {
	var report osvReport
	if err := json.Unmarshal(out.Stdout, &report); err != nil {
		return nil, fmt.Errorf("osv-scanner: parsing report: %w", err)
	}

	var raw []model.RawFinding
	for _, result := range report.Results {
		lockfile := relPath(result.Source.Path, out.Dir)
		for _, pkg := range result.Packages {
			// The group carries the numeric severity and the union of aliases
			// across the vulnerabilities it covers.
			cvssByID := map[string]float64{}
			aliasByID := map[string][]string{}
			for _, g := range pkg.Groups {
				score, _ := strconv.ParseFloat(g.MaxSeverity, 64)
				for _, id := range g.IDs {
					cvssByID[id] = score
					aliasByID[id] = g.Aliases
				}
			}

			for _, v := range pkg.Vulnerabilities {
				// Prefer the group's alias union: it is the widest set the tool
				// knows, and alias resolution before fingerprinting is what
				// collapses this report onto govulncheck's (VM-F-106).
				aliases := v.Aliases
				if wider, ok := aliasByID[v.ID]; ok && len(wider) > len(aliases) {
					aliases = wider
				}

				rf := model.RawFinding{
					Repo:        out.Repo,
					Category:    model.CategoryDependency,
					PrimaryID:   v.ID,
					Aliases:     aliases,
					Tool:        a.Name(),
					Module:      pkg.Package.Name,
					ModuleMajor: moduleMajor(pkg.Package.Name, pkg.Package.Version),
					File:        lockfile,
					Versions: model.Versions{
						Current: pkg.Package.Version,
						Fixed:   firstFixed(v),
					},
					Classification: model.Classification{
						// Go advisories carry no severity band in
						// database_specific — only the group's numeric score.
						// Without the fallback every Go dependency finding
						// normalises to UNKNOWN severity, and osv-scanner's
						// whole contribution to the cross-source merge (VM-AD
						// §8.6) is the severity govulncheck cannot supply.
						Severity: severityFromOSVOrScore(v.DatabaseSpecific.Severity, cvssByID[v.ID]),
						CVSS:     cvssByID[v.ID],
						// osv-scanner performs no reachability analysis. Saying
						// "unknown" rather than assuming is the whole point of
						// the tri-state (VM-F-243).
						Reachable:  model.ReachableUnknown,
						DepClass:   model.DepProduction,
						Transitive: false,
					},
					ToolVersion: a.Version(),
					AdvisoryURL: advisoryURL(v),
					Raw:         mustRaw(v),
				}
				raw = append(raw, rf)
			}
		}
	}

	raw = dedupe(raw)
	sortFindings(raw)
	return raw, nil
}

// firstFixed returns the first fixed version across the advisory's ranges,
// normalised to the Go "v" prefix convention where the ecosystem uses it.
func firstFixed(v osvVulnerability) string {
	for _, aff := range v.Affected {
		for _, r := range aff.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func advisoryURL(v osvVulnerability) string {
	for _, ref := range v.References {
		if strings.EqualFold(ref.Type, "ADVISORY") {
			return ref.URL
		}
	}
	if len(v.References) > 0 {
		return v.References[0].URL
	}
	return ""
}
