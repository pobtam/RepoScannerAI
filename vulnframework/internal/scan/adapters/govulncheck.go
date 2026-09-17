package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

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

// gvcMessage is one message in govulncheck's JSON stream.
//
// The stream is a *concatenation of JSON objects*, not newline-delimited JSON:
// govulncheck pretty-prints each message across many lines. Parsing it a line
// at a time yields zero findings, which is indistinguishable from a clean
// repository — the exact failure mode fixture tests exist to prevent. See
// TestGovulncheckParsesPrettyPrintedStream.
//
// SBOM is accepted and ignored. It appeared in the v1.8.0 output and an
// unknown top-level key must not be an error, or every tool upgrade breaks the
// adapter; it must also not be silently treated as a finding.
type gvcMessage struct {
	Config  *gvcConfig       `json:"config,omitempty"`
	OSV     *gvcOSV          `json:"osv,omitempty"`
	Finding *gvcFinding      `json:"finding,omitempty"`
	SBOM    *json.RawMessage `json:"SBOM,omitempty"`
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

	// A streaming decoder consumes the concatenated-object form govulncheck
	// actually emits, and handles newline-delimited output identically.
	dec := json.NewDecoder(bytes.NewReader(out.Stdout))
	for {
		var msg gvcMessage
		err := dec.Decode(&msg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("govulncheck: parsing message stream: %w", err)
		}
		switch {
		case msg.OSV != nil:
			advisories[msg.OSV.ID] = *msg.OSV
		case msg.Finding != nil:
			findings = append(findings, *msg.Finding)
		}
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
			ImportPath:  importPath(out.Repo, f.Trace),
			Raw:         mustRaw(f),
		}
		raw = append(raw, rf)
	}

	raw = dedupe(raw)
	sortFindings(raw)
	return raw, nil
}

// importPath renders govulncheck's trace as a path from the consuming
// repository outwards (VM-AD §12.2).
//
// govulncheck orders its trace innermost first: trace[0] is the vulnerable
// frame and later frames walk back toward repository code. First-party
// classification needs the opposite order — it walks OUT from the consumer
// looking for the first internal hop — so the trace is reversed and the
// repository prefixed.
//
// Without this the whole first-party mechanism is inert: classification reads
// this field, nothing else populates it, and every finding would look
// third-party. That is the Phase 6 projection bug one layer further out, and
// it would present identically — a feature that is wired, tested, and never
// fires.
func importPath(repo string, trace []gvcFrame) []string {
	if len(trace) == 0 {
		return nil
	}
	out := make([]string, 0, len(trace)+1)
	out = append(out, repo)

	var last string
	for i := len(trace) - 1; i >= 0; i-- {
		module := trace[i].Module
		// Consecutive frames in one module collapse: the path is a chain of
		// modules, not of call frames, and a module repeated adjacently would
		// make an ordinary call stack look like a dependency chain.
		if module == "" || module == last {
			continue
		}
		out = append(out, module)
		last = module
	}
	if len(out) < 2 {
		return nil
	}
	return out
}
