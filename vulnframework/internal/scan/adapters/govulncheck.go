package adapters

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

// Govulncheck is the authoritative Go dependency scanner (VM-AD §8.2).
//
// It is the only tool in the matrix that performs reachability analysis, so it
// is the source of truth for classification.reachable on Go findings
// (VM-F-221). Where it reports a vulnerability at module level only, the
// vulnerable symbol is genuinely not called and the finding is reachable=false
// — not unknown. That distinction is load-bearing for prioritisation.
type Govulncheck struct {
	Runner   runner.CommandRunner
	Pinned   string
	GoVulnDB string
}

// NewGovulncheck builds the adapter with a pinned version from tools.lock.
func NewGovulncheck(r runner.CommandRunner, version string) *Govulncheck {
	return &Govulncheck{Runner: r, Pinned: version}
}

func (a *Govulncheck) Name() string    { return "govulncheck" }
func (a *Govulncheck) Version() string { return a.Pinned }

// Supports reports Go repositories only.
func (a *Govulncheck) Supports(r scan.RepoProfile) bool { return r.HasLanguage(scan.LangGo) }

// Run executes govulncheck in JSON mode.
//
// Dependency findings are always repository-wide, even in diff-scoped mode: a
// pull request that touches one handler can still be running a vulnerable
// dependency (VM-AD §8.5).
func (a *Govulncheck) Run(ctx context.Context, dir string, opts scan.RunOpts) (scan.RawOutput, error) {
	res, err := a.Runner.Run(ctx, dir, "govulncheck", "-json", "./...")
	if err != nil {
		return scan.RawOutput{}, fmt.Errorf("govulncheck: %w", err)
	}
	return scan.RawOutput{
		Tool: a.Name(), ToolVersion: a.Version(), Dir: dir,
		ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr,
	}, nil
}

// govulncheck -json emits a stream of single-key JSON objects.
type gvcMessage struct {
	Config  *gvcConfig  `json:"config,omitempty"`
	OSV     *gvcOSV     `json:"osv,omitempty"`
	Finding *gvcFinding `json:"finding,omitempty"`
}

type gvcConfig struct {
	ScannerName    string `json:"scanner_name"`
	ScannerVersion string `json:"scanner_version"`
	GoVersion      string `json:"go_version"`
	ScanLevel      string `json:"scan_level"`
}

type gvcOSV struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases"`
	Summary          string   `json:"summary"`
	DatabaseSpecific struct {
		URL string `json:"url"`
	} `json:"database_specific"`
}

type gvcFinding struct {
	OSV          string     `json:"osv"`
	FixedVersion string     `json:"fixed_version"`
	Trace        []gvcFrame `json:"trace"`
}

type gvcFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

// Normalize converts a govulncheck JSON stream into raw findings.
func (a *Govulncheck) Normalize(out scan.RawOutput) ([]model.RawFinding, error) {
	advisories := map[string]gvcOSV{}
	var findings []gvcFinding

	sc := bufio.NewScanner(bytes.NewReader(out.Stdout))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var msg gvcMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			return nil, fmt.Errorf("govulncheck: parsing message: %w", err)
		}
		switch {
		case msg.OSV != nil:
			advisories[msg.OSV.ID] = *msg.OSV
		case msg.Finding != nil:
			findings = append(findings, *msg.Finding)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("govulncheck: reading output: %w", err)
	}

	var raw []model.RawFinding
	for _, f := range findings {
		if len(f.Trace) == 0 {
			continue
		}
		// trace[0] is the vulnerable frame; later frames are the call path back
		// into repository code.
		vuln := f.Trace[0]
		adv := advisories[f.OSV]

		// Reachability: govulncheck reports the same advisory at module,
		// package and symbol level. A frame naming a function is positive proof
		// the vulnerable symbol is called.
		reach := model.ReachableFalse
		if vuln.Function != "" {
			reach = model.ReachableTrue
		}

		rf := model.RawFinding{
			Repo:        out.Repo,
			Category:    model.CategoryDependency,
			PrimaryID:   f.OSV,
			Aliases:     adv.Aliases,
			Tool:        a.Name(),
			Module:      vuln.Module,
			ModuleMajor: moduleMajor(vuln.Module, vuln.Version),
			Versions: model.Versions{
				Current: vuln.Version,
				Fixed:   f.FixedVersion,
			},
			Classification: model.Classification{
				// govulncheck carries no severity or CVSS: the Go vulnerability
				// database does not score advisories. This is precisely why the
				// severity enumeration needs an explicit UNKNOWN rather than a
				// silent floor — osv-scanner supplies the score for the same
				// fingerprint on the cross-check pass.
				Severity:   model.SeverityUnknown,
				Reachable:  reach,
				DepClass:   model.DepProduction,
				Transitive: len(f.Trace) > 2,
			},
			ToolVersion: a.Version(),
			AdvisoryURL: adv.DatabaseSpecific.URL,
			Raw:         mustRaw(f),
		}
		raw = append(raw, rf)
	}

	raw = dedupe(raw)
	sortFindings(raw)
	return raw, nil
}
