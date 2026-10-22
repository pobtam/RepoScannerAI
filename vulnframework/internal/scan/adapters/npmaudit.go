package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

// PackageJSONPath is the auxiliary file the npm-audit adapter needs in order to
// classify a finding as production or development-only.
const PackageJSONPath = "package.json"

// NPMAudit cross-checks JavaScript dependencies (VM-AD §8.2).
//
// It is the secondary JavaScript scanner — osv-scanner is primary and npm audit
// is noisier — but it carries the CVSS score and the fix availability that osv
// does not always supply.
type NPMAudit struct {
	Runner runner.CommandRunner
	Pinned string
}

// NewNPMAudit builds the adapter with a pinned version from tools.lock.
func NewNPMAudit(r runner.CommandRunner, version string) *NPMAudit {
	return &NPMAudit{Runner: r, Pinned: version}
}

func (a *NPMAudit) Name() string    { return "npm-audit" }
func (a *NPMAudit) Version() string { return a.Pinned }

// Supports reports JavaScript repositories that have a committed lockfile.
//
// A repository with no lockfile is a coverage gap, not a clean result
// (VM-F-241); reporting "no vulnerabilities" for an unresolvable dependency
// tree would be the most misleading output this adapter could produce.
func (a *NPMAudit) Supports(r scan.RepoProfile) bool {
	return r.HasLanguage(scan.LangJavaScript) && r.HasLockfile
}

// Run executes npm audit against the committed lockfile.
func (a *NPMAudit) Run(ctx context.Context, dir string, opts scan.RunOpts) (scan.RawOutput, error) {
	res, err := a.Runner.Run(ctx, dir, "npm", "audit", "--json")
	if err != nil {
		return scan.RawOutput{}, fmt.Errorf("npm-audit: %w", err)
	}
	return scan.RawOutput{
		Tool: a.Name(), ToolVersion: a.Version(), Dir: dir,
		ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr,
	}, nil
}

type npmAuditReport struct {
	AuditReportVersion int                         `json:"auditReportVersion"`
	Vulnerabilities    map[string]npmVulnerability `json:"vulnerabilities"`
}

type npmVulnerability struct {
	Name         string          `json:"name"`
	Severity     string          `json:"severity"`
	IsDirect     bool            `json:"isDirect"`
	Via          json.RawMessage `json:"via"`
	Range        string          `json:"range"`
	Nodes        []string        `json:"nodes"`
	FixAvailable json.RawMessage `json:"fixAvailable"`
}

type npmVia struct {
	Source     int      `json:"source"`
	Name       string   `json:"name"`
	Dependency string   `json:"dependency"`
	Title      string   `json:"title"`
	URL        string   `json:"url"`
	Severity   string   `json:"severity"`
	CWE        []string `json:"cwe"`
	CVSS       struct {
		Score        float64 `json:"score"`
		VectorString string  `json:"vectorString"`
	} `json:"cvss"`
	Range string `json:"range"`
}

type npmFix struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	IsSemVerMajor bool   `json:"isSemVerMajor"`
}

type packageManifest struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// ghsaFromAdvisoryURL extracts the GHSA identifier from a GitHub advisory URL.
// npm audit reports no identifier field of its own, so the URL is the only
// carrier — and without the identifier this adapter's findings could not
// deduplicate against osv-scanner's (VM-F-106).
var ghsaFromAdvisoryURL = regexp.MustCompile(`(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})`)

// Normalize converts an npm audit report into raw findings.
//
// Development-only classification (VM-F-242) is resolved from package.json,
// supplied in RawOutput.Aux: the audit report itself does not record it, and
// treating a development-only advisory as production inflates the priority
// queue with findings that never reach a production runtime.
func (a *NPMAudit) Normalize(out scan.RawOutput) ([]model.RawFinding, error) {
	var report npmAuditReport
	if err := json.Unmarshal(out.Stdout, &report); err != nil {
		return nil, fmt.Errorf("npm-audit: parsing report: %w", err)
	}

	devOnly := map[string]bool{}
	if manifest, ok := out.Aux[PackageJSONPath]; ok {
		var pm packageManifest
		if err := json.Unmarshal(manifest, &pm); err != nil {
			return nil, fmt.Errorf("npm-audit: parsing %s: %w", PackageJSONPath, err)
		}
		for name := range pm.DevDependencies {
			if _, alsoProd := pm.Dependencies[name]; !alsoProd {
				devOnly[name] = true
			}
		}
	}

	// Map iteration is unordered; collect names and sort so the output is
	// deterministic before the findings are sorted properly.
	names := make([]string, 0, len(report.Vulnerabilities))
	for name := range report.Vulnerabilities {
		names = append(names, name)
	}
	sort.Strings(names)

	var raw []model.RawFinding
	for _, name := range names {
		v := report.Vulnerabilities[name]

		// via is a heterogeneous array: advisory objects, or bare strings
		// naming another package through which this one is vulnerable. Only
		// the objects carry an advisory.
		var vias []npmVia
		var viaRaw []json.RawMessage
		if err := json.Unmarshal(v.Via, &viaRaw); err != nil {
			return nil, fmt.Errorf("npm-audit: parsing via for %s: %w", name, err)
		}
		for _, entry := range viaRaw {
			var via npmVia
			if err := json.Unmarshal(entry, &via); err != nil {
				// A string entry: an indirect path, not an advisory.
				continue
			}
			if via.URL != "" {
				vias = append(vias, via)
			}
		}

		depClass := model.DepProduction
		if devOnly[v.Name] {
			depClass = model.DepDevelopment
		}

		var fix npmFix
		_ = json.Unmarshal(v.FixAvailable, &fix)

		for _, via := range vias {
			id := via.URL
			if m := ghsaFromAdvisoryURL.FindString(via.URL); m != "" {
				id = m
			}

			raw = append(raw, model.RawFinding{
				Repo:      out.Repo,
				Category:  model.CategoryDependency,
				PrimaryID: id,
				Tool:      a.Name(),
				Module:    v.Name,
				// npm packages carry no major-version path suffix; the range
				// is the vulnerable span and the installed version is not in
				// the audit report, so the major component is left empty and
				// the package name alone locates the finding.
				ModuleMajor: "",
				Versions: model.Versions{
					Fixed: fix.Version,
				},
				Classification: model.Classification{
					Severity: severityFromBand(via.Severity),
					CVSS:     via.CVSS.Score,
					// npm audit performs no reachability analysis.
					Reachable:  model.ReachableUnknown,
					DepClass:   depClass,
					Transitive: !v.IsDirect,
				},
				ToolVersion: a.Version(),
				AdvisoryURL: via.URL,
				Description: via.Title,
				Raw:         mustRaw(via),
			})
		}
	}

	raw = dedupe(raw)
	sortFindings(raw)
	return raw, nil
}
