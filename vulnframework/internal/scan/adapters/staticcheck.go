package adapters

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

// securityRelevantChecks is the staticcheck subset this framework reports.
//
// VM-AD §8.2 requires filtering "to the security rule subset only" but does not
// enumerate it, and staticcheck publishes no security categorisation of its own
// (see BUILD-LOG assumption A7). Without a filter, staticcheck's correctness and
// style checks would dominate the finding store with defects that are real but
// not security defects, and the signal this framework exists to surface would be
// buried — the same failure mode VM-ADR-05 describes for ticket volume.
//
// Each entry below is included for a stated security consequence.
var securityRelevantChecks = map[string]string{
	"SA1000": "invalid regular expression — a malformed pattern can fail open in a validation path",
	"SA1012": "nil context — defeats cancellation and timeout, an availability concern",
	"SA1019": "deprecated identifier — the deprecated form is frequently the insecure one",
	"SA1027": "misaligned atomic access — undefined behaviour under concurrency",
	"SA2000": "WaitGroup.Add called in the wrong place — races on shared state",
	"SA2001": "empty critical section — the lock protects nothing",
	"SA2002": "testing.T used from a non-test goroutine",
	"SA2003": "deferred Lock right after locking",
	"SA4016": "certainly useless bit operation — frequently a masking or permissions bug",
	"SA5011": "possible nil pointer dereference — a reachable crash is an availability defect",
	"SA9001": "defer in a range loop over a channel",
	"SA9003": "empty branch — a swallowed error or an unenforced security check",
	"SA9005": "struct with no serialisable fields — silently writes nothing",
}

// Staticcheck reports the security-relevant subset of staticcheck's checks
// (VM-AD §8.2).
type Staticcheck struct {
	Runner runner.CommandRunner
	Pinned string

	// Checks overrides the default security subset. Nil uses
	// securityRelevantChecks.
	Checks map[string]string
}

// NewStaticcheck builds the adapter with the default security subset.
func NewStaticcheck(r runner.CommandRunner, version string) *Staticcheck {
	return &Staticcheck{Runner: r, Pinned: version}
}

func (a *Staticcheck) Name() string    { return "staticcheck" }
func (a *Staticcheck) Version() string { return a.Pinned }

func (a *Staticcheck) Supports(r scan.RepoProfile) bool { return r.HasLanguage(scan.LangGo) }

func (a *Staticcheck) checks() map[string]string {
	if a.Checks != nil {
		return a.Checks
	}
	return securityRelevantChecks
}

// SecuritySubset returns the check codes this adapter reports, sorted.
func (a *Staticcheck) SecuritySubset() []string {
	out := make([]string, 0, len(a.checks()))
	for code := range a.checks() {
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}

// Run executes staticcheck in JSON mode.
func (a *Staticcheck) Run(ctx context.Context, dir string, opts scan.RunOpts) (scan.RawOutput, error) {
	res, err := a.Runner.Run(ctx, dir, "staticcheck", "-f", "json", "./...")
	if err != nil {
		return scan.RawOutput{}, fmt.Errorf("staticcheck: %w", err)
	}
	return scan.RawOutput{
		Tool: a.Name(), ToolVersion: a.Version(), Dir: dir,
		ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr,
	}, nil
}

type staticcheckDiagnostic struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Location struct {
		File string `json:"file"`
		Line int    `json:"line"`
		Col  int    `json:"col"`
	} `json:"location"`
	Message string `json:"message"`
}

// Normalize converts staticcheck's newline-delimited JSON into raw findings,
// discarding checks outside the security subset.
func (a *Staticcheck) Normalize(out scan.RawOutput) ([]model.RawFinding, error) {
	subset := a.checks()

	var raw []model.RawFinding
	sc := bufio.NewScanner(bytes.NewReader(out.Stdout))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var d staticcheckDiagnostic
		if err := json.Unmarshal(line, &d); err != nil {
			return nil, fmt.Errorf("staticcheck: parsing diagnostic: %w", err)
		}
		if _, wanted := subset[d.Code]; !wanted {
			continue
		}

		severity := model.SeverityLow
		if d.Severity == "error" {
			severity = model.SeverityMedium
		}

		raw = append(raw, model.RawFinding{
			Repo:     out.Repo,
			Category: model.CategoryCode,
			Tool:     a.Name(),
			RuleID:   d.Code,
			File:     relPath(d.Location.File, out.Dir),
			Line:     d.Location.Line,
			Classification: model.Classification{
				Severity:  severity,
				Reachable: model.ReachableTrue,
				DepClass:  model.DepNotApplicable,
			},
			ToolVersion: a.Version(),
			Description: d.Message,
			Raw:         mustRaw(d),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("staticcheck: reading output: %w", err)
	}

	raw = dedupe(raw)
	sortFindings(raw)
	return raw, nil
}
