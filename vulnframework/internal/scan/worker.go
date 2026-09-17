package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
)

// Worker runs a repository's applicable scanners and assembles the result
// (VM-AD §8.1).
//
// Its contract is the one property that makes fleet scanning survivable: a
// scanner that fails produces a coverage gap, not a job failure (VM-F-204).
// Partial results are valid results.
type Worker struct {
	Registry *Registry
	Clock    func() time.Time
}

// NewWorker builds a worker over an adapter registry.
func NewWorker(reg *Registry) *Worker {
	return &Worker{Registry: reg, Clock: func() time.Time { return time.Now().UTC() }}
}

// Result is one repository's scan outcome.
type Result struct {
	RunID    string
	Repo     string
	Dir      string
	Outcome  model.ScanOutcome
	Findings []model.RawFinding

	// ToolsOK and ToolsFailed record which signals survived and which were lost,
	// so a partial gap still says what remains current (VM-F-212).
	ToolsOK     []string
	ToolsFailed []string

	// Gaps describes each failure, attributed to an owner (VM-F-214).
	Gaps []CoverageGap

	ToolVersions map[string]string
	DurationSec  int

	// Aliases is the identifier grouping built during this scan, retained so a
	// caller can audit why two tools' findings collapsed (VM-AD §5).
	Aliases *AliasTable `json:"-"`

	// Deps is the repository's dependency manifest (VM-F-602, VM-AD §8.1).
	//
	// Read here because the clone is already on disk, and recorded because the
	// reverse-dependency index that first-party waves rest on has no other
	// source. Phase 11 built classification, waves and blast radius over an
	// index nothing populated — the field existed, a consumer read it, and no
	// producer wrote it (OQ-P11-01).
	Deps []ModuleDep `json:"deps"`
}

// CoverageGap records a scanner that did not produce results (VM-F-205).
type CoverageGap struct {
	Tool string `json:"tool"`
	// Classification is total where no scanner produced results for the
	// repository, partial where some completed (VM-F-211).
	Classification GapClass `json:"classification"`
	Cause          string   `json:"cause"`
	Detail         string   `json:"detail,omitempty"`
	// Owner is platform for infrastructure causes and repo for repository
	// causes (VM-F-214). The distinction decides who is asked to fix it, so
	// getting it wrong routes the work to someone who cannot act.
	Owner GapOwner `json:"owner"`
}

// GapClass classifies a coverage gap (VM-F-211).
type GapClass string

const (
	GapTotal   GapClass = "total"
	GapPartial GapClass = "partial"
)

// GapOwner attributes a coverage gap (VM-F-214).
type GapOwner string

const (
	OwnerPlatform GapOwner = "platform"
	OwnerRepo     GapOwner = "repo"
)

// Scan runs every applicable adapter against a checkout.
//
// It returns an error only for a failure of the worker itself. A tool that
// cannot run, crashes, or emits output the adapter cannot parse becomes a
// coverage gap on the result — never a job failure, and never silence.
func (w *Worker) Scan(ctx context.Context, runID, repo, dir string, profile RepoProfile, opts RunOpts) (Result, error) {
	started := w.clock()

	res := Result{
		RunID: runID, Repo: repo, Dir: dir,
		ToolVersions: map[string]string{},
	}

	adapters := w.Registry.For(profile)
	if len(adapters) == 0 {
		return res, fmt.Errorf("scan: no adapter applies to %s", repo)
	}

	aux, err := loadAux(dir)
	if err != nil {
		return res, err
	}

	for _, a := range adapters {
		res.ToolVersions[a.Name()] = a.Version()

		raw, err := a.Run(ctx, dir, opts)
		if err != nil {
			res.ToolsFailed = append(res.ToolsFailed, a.Name())
			res.Gaps = append(res.Gaps, CoverageGap{
				Tool:  a.Name(),
				Cause: "execution_failed",
				// The adapter could not be executed at all: missing binary,
				// timeout, cancelled context. That is the platform's to fix.
				Owner:  OwnerPlatform,
				Detail: err.Error(),
			})
			continue
		}

		raw.Repo = repo
		raw.Dir = dir
		if raw.Aux == nil {
			raw.Aux = aux
		}

		findings, err := a.Normalize(raw)
		if err != nil {
			res.ToolsFailed = append(res.ToolsFailed, a.Name())
			res.Gaps = append(res.Gaps, CoverageGap{
				Tool:  a.Name(),
				Cause: "normalise_failed",
				// The tool ran but its output could not be understood. That is
				// an adapter defect, which is the platform's.
				Owner:  OwnerPlatform,
				Detail: err.Error(),
			})
			continue
		}

		// Code, secret and config findings are diff-scoped where a diff is
		// supplied; dependency findings stay repository-wide, because a pull
		// request touching one handler can still be running a vulnerable
		// dependency (VM-AD §8.5).
		findings = applyDiffScope(findings, opts)

		res.ToolsOK = append(res.ToolsOK, a.Name())
		res.Findings = append(res.Findings, findings...)
	}

	// Alias resolution, before anything is fingerprinted (VM-AD §5).
	//
	// The table is built from every tool that publishes OSV alias data and then
	// applied to every finding, including those from tools that publish none.
	// That is what lets trivy's CVE-2025-22869 and govulncheck's GO-2025-3487
	// collapse to one fingerprint: trivy does not know the GO identifier, and
	// does not need to.
	aliases := NewAliasTable()
	aliases.AddFindings(res.Findings)
	res.Findings = aliases.Enrich(res.Findings)
	res.Aliases = aliases

	// The manifest, from the clone already on disk. A failure to read it is a
	// coverage gap in the dependency index, not a failed scan: the findings
	// are valid regardless, and treating a missing manifest as a scan failure
	// would turn every JavaScript repository into a gap.
	deps, err := ReadGoManifest(dir)
	if err != nil {
		res.Gaps = append(res.Gaps, CoverageGap{
			Tool: "manifest", Classification: GapPartial, Cause: "manifest_unreadable",
			Detail: err.Error(), Owner: OwnerRepo,
		})
	}
	res.Deps = deps

	sort.Strings(res.ToolsOK)
	sort.Strings(res.ToolsFailed)
	res.Outcome = classify(len(res.ToolsOK), len(res.ToolsFailed))
	for i := range res.Gaps {
		res.Gaps[i].Classification = gapClass(res.Outcome)
	}
	res.DurationSec = int(w.clock().Sub(started).Seconds())

	return res, nil
}

// classify derives the repository outcome from which tools survived
// (VM-F-211). A run where every tool failed is not a clean scan: it is total
// loss of coverage, and must never be presented as an absence of findings.
func classify(ok, failed int) model.ScanOutcome {
	switch {
	case failed == 0:
		return model.ScanComplete
	case ok == 0:
		return model.ScanFailed
	default:
		return model.ScanPartial
	}
}

func gapClass(outcome model.ScanOutcome) GapClass {
	if outcome == model.ScanFailed {
		return GapTotal
	}
	return GapPartial
}

// applyDiffScope restricts non-dependency findings to the changed file set
// (VM-AD §8.5, VM-F-207).
func applyDiffScope(in []model.RawFinding, opts RunOpts) []model.RawFinding {
	if opts.Mode != ModeDiff || len(opts.ChangedFiles) == 0 {
		return in
	}
	changed := make(map[string]bool, len(opts.ChangedFiles))
	for _, f := range opts.ChangedFiles {
		changed[strings.TrimPrefix(filepath.ToSlash(f), "./")] = true
	}

	out := in[:0:0]
	for _, f := range in {
		if f.Category == model.CategoryDependency {
			out = append(out, f)
			continue
		}
		if changed[f.File] {
			out = append(out, f)
		}
	}
	return out
}

// loadAux reads the repository files adapters need in order to normalise
// (see RawOutput.Aux). A missing file is not an error: the adapter decides
// whether it can proceed without it.
func loadAux(dir string) (map[string][]byte, error) {
	aux := map[string][]byte{}
	for _, name := range []string{"package.json"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("scan: reading %s: %w", name, err)
		}
		aux[name] = b
	}
	return aux, nil
}

func (w *Worker) clock() time.Time {
	if w.Clock != nil {
		return w.Clock()
	}
	return time.Now().UTC()
}
