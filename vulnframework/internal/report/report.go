// Package report renders fleet and per-repository reports (VM-AD §14).
//
// JSON is authoritative and Markdown is rendered from it (principle P5). The two
// are never generated independently, because two independent renderings of the
// same data drift, and the one people read is the one that drifts.
//
// The generator reads ground truth through the Store interface — the same
// queries production uses — rather than through a reporting-specific view. That
// is deliberate, and it is the lesson of the Phase 6 projection bug: a passing
// test proves the rule, not that the rule runs, and an invariant is only real if
// its input survives every projection between scan and decision. A report is
// another projection. One that reads from a convenience view will under-report
// exactly the fields that view forgot, and every test written against that view
// will pass.
package report

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
)

// Kind is the sort of report.
type Kind string

const (
	KindFleet Kind = "fleet"
	KindRepo  Kind = "repo"
)

// Query is what produced a report, stored verbatim so it can be regenerated
// byte-identically rather than approximately (VM-ADR-15).
type Query struct {
	Kind Kind `json:"kind"`
	// AnchorRun is the run the report describes. A report cannot be generated
	// for "right now": the most recent anchor is the latest completed run, and
	// the interface must say so rather than silently anchoring.
	AnchorRun string      `json:"anchor_run"`
	Repo      string      `json:"repo,omitempty"`
	Scope     store.Scope `json:"scope"`
	Template  string      `json:"template"`
}

// Counts are the headline figures (VM-AD §14.2).
//
// The three partitions are reported separately and never summed into a single
// "closed" figure: MERGED is neither resolved nor unresolved, and folding it
// either way misstates the total (VM-F-159, VM-OQ-09).
type Counts struct {
	Total               int `json:"total"`
	Unresolved          int `json:"unresolved"`
	PendingVerification int `json:"pending_verification"`
	Resolved            int `json:"resolved"`

	ByPriority map[string]int `json:"by_priority"`
	ByState    map[string]int `json:"by_state"`
	ByCategory map[string]int `json:"by_category"`

	// NotReobserved is findings the run did not observe while they remain
	// unresolved (VM-F-161). Reported alongside the totals, never folded into
	// resolved: absence is not resolution.
	NotReobserved int `json:"not_reobserved"`
	// SLABreached and SLAPaused are reported separately. A paused finding is not
	// a compliant one; it is one the SLA cannot speak to (VM-NF-304).
	SLABreached int `json:"sla_breached"`
	SLAPaused   int `json:"sla_paused"`
	// SLANotComputed counts findings whose SLA was never computed.
	//
	// It exists so a report can never present "0 breached" as assurance when
	// the truth is that nobody looked. Those are different claims, and a reader
	// has no way to tell them apart from a zero (OQ-P7-03).
	SLANotComputed int `json:"sla_not_computed"`
}

// Delta compares two runs of the same kind (VM-F-14 acceptance criterion).
//
// Same-kind is the whole point: comparing a sweep against an advisory rescan
// that touched six repositories produces a delta that looks like a catastrophe
// or a miracle, and is neither.
type Delta struct {
	PreviousRun string `json:"previous_run,omitempty"`
	// Comparable is false when there is no previous run of this kind. The
	// report says so rather than rendering a delta against zero, which would
	// present the first run as though everything had just appeared.
	Comparable bool `json:"comparable"`

	TotalChange      int `json:"total_change"`
	UnresolvedChange int `json:"unresolved_change"`
	New              int `json:"new"`
	// NoLongerObserved is deliberately not called "fixed". A finding observed
	// last run and not this one may have been fixed, or may simply not have
	// been looked for — absence is not resolution (VM-ADR-12), and a delta that
	// labelled it "fixed" would launder a coverage gap into good news.
	NoLongerObserved int `json:"no_longer_observed"`
	// Verified counts findings that actually reached VERIFIED, which is the
	// figure that means what "fixed" sounds like.
	Verified  int `json:"verified"`
	Regressed int `json:"regressed"`
}

// Coverage is the fleet's scan coverage for the anchoring run (VM-F-213).
//
// Every gap cause is carried separately. A repository deferred for budget, one
// whose build failed, one never dispatched and one whose worker died are four
// different operational problems with four different remedies, and a single
// "gaps: 4" tells nobody what to do.
type Coverage struct {
	InScope  int `json:"in_scope"`
	Complete int `json:"complete"`
	Partial  int `json:"partial"`
	Failed   int `json:"failed"`
	// NotDispatched and NoResult are the OQ-P2-02 distinctions: the scan never
	// started, versus it started and the result was lost.
	NotDispatched int `json:"not_dispatched"`
	NoResult      int `json:"no_result"`

	// ByCause counts every non-qualifying outcome by its recorded cause, so a
	// gap is actionable rather than merely counted.
	ByCause map[string]int `json:"by_cause,omitempty"`

	// Percent is complete scans over in-scope repositories. It is the figure
	// most likely to be quoted out of context, which is why Staleness travels
	// with it.
	Percent float64 `json:"percent"`

	// Staleness is the coverage-age distribution (OQ-P4-01). A flat gap count
	// with a growing maximum age is starvation that a percentage cannot show.
	Staleness store.StalenessReport `json:"staleness"`

	// Escalations are repositories past the consecutive-failure threshold,
	// whatever the cause (VM-F-215).
	Escalations []store.Escalation `json:"escalations,omitempty"`

	// UnscannedRepos names the repositories with no qualifying scan in this
	// run. Named, not counted: an audit attestation needs the names
	// (v1.0 acceptance criterion 15).
	UnscannedRepos []string `json:"unscanned_repos,omitempty"`
}

// FindingRow is one finding as it appears in a report.
//
// It carries the fields a reader needs to act, and deliberately carries no
// field capable of holding credential material — the same structural guarantee
// as the finding record itself (VM-F-263), re-stated at the output boundary
// because this is the artifact that leaves the system.
type FindingRow struct {
	Fingerprint    string   `json:"fingerprint"`
	Repo           string   `json:"repo"`
	Category       string   `json:"category"`
	PrimaryID      string   `json:"primary_id,omitempty"`
	Module         string   `json:"module,omitempty"`
	File           string   `json:"file,omitempty"`
	State          string   `json:"state"`
	Priority       string   `json:"priority,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	Reachable      string   `json:"reachable,omitempty"`
	DepClass       string   `json:"dep_class,omitempty"`
	FirstPartyPath string   `json:"first_party_path,omitempty"`
	ReasonCode     string   `json:"reason_code,omitempty"`
	VerifiedReason string   `json:"verified_reason,omitempty"`
	Tools          []string `json:"tools,omitempty"`
	FixedVersion   string   `json:"fixed_version,omitempty"`
	CredentialType string   `json:"credential_type,omitempty"`
	NotReobserved  bool     `json:"not_reobserved,omitempty"`
	GapRun         string   `json:"gap_run,omitempty"`
	SLAStatus      string   `json:"sla_status,omitempty"`
}

// Provenance records how the numbers in a report were produced.
//
// It exists so a report cannot present a confident-looking priority while
// hiding that the thresholds behind it are uncalibrated (OQ-P5-02).
type Provenance struct {
	ScannerImage string            `json:"scanner_image,omitempty"`
	ToolVersions map[string]string `json:"tool_versions,omitempty"`

	// ThresholdsCalibrated is false while VM-OQ-06 is unanswered. When false
	// the rendered report carries a visible caveat wherever a priority appears.
	ThresholdsCalibrated bool `json:"thresholds_calibrated"`
	// SLAWindowsCalibrated is false while VM-OQ-02 is unanswered. A breach
	// count is a measurement against a table; if nobody has reviewed the table,
	// the count carries a qualifier wherever it is rendered (OQ-P7b-03).
	SLAWindowsCalibrated bool `json:"sla_windows_calibrated"`
	// Caveats are rendered prominently. A reader must not have to open a config
	// file to learn that a number is provisional.
	Caveats []string `json:"caveats,omitempty"`
}

// Report is the authoritative document (VM-AD §14.1: fleet.json).
type Report struct {
	ID    string `json:"id"`
	Kind  Kind   `json:"kind"`
	Query Query  `json:"query"`

	AnchorRun       string    `json:"anchor_run"`
	AnchorStartedAt time.Time `json:"anchor_started_at"`
	IssuedAt        time.Time `json:"issued_at"`

	Repo string `json:"repo,omitempty"`

	Counts   Counts       `json:"counts"`
	Delta    Delta        `json:"delta"`
	Coverage Coverage     `json:"coverage"`
	Findings []FindingRow `json:"findings"`

	Provenance Provenance `json:"provenance"`

	// Redacted and WithheldCount record delivery below the generator's
	// privilege level: a redacted report says that redaction occurred rather
	// than silently omitting rows (VM-F-75x).
	Redacted      bool `json:"redacted,omitempty"`
	WithheldCount int  `json:"withheld_count,omitempty"`

	// ContentHash is set when the report is issued (VM-ADR-15).
	ContentHash string `json:"content_hash,omitempty"`
}

// Generator builds reports from the store.
type Generator struct {
	Store store.Store
	// Calibration is consulted only for its provenance flags: the report states
	// whether the thresholds behind a priority have been calibrated.
	Calibration score.Calibration
	Clock       func() time.Time
}

// NewGenerator builds a generator.
func NewGenerator(s store.Store, cal score.Calibration) *Generator {
	return &Generator{Store: s, Calibration: cal, Clock: func() time.Time { return time.Now().UTC() }}
}

func (g *Generator) now() time.Time {
	if g.Clock != nil {
		return g.Clock().UTC()
	}
	return time.Now().UTC()
}

// ErrLiveAnchor is returned for a request to report on current state.
//
// Reports cannot be generated for "right now": the most recent anchor is the
// latest completed run, and the interface must state that limitation rather
// than silently anchoring to something else (VM-ADR-15).
var ErrLiveAnchor = fmt.Errorf("report: reports anchor to a completed run; the most recent anchor is the latest finished run, and live state cannot be reported (VM-ADR-15)")

// Generate builds a report for a query.
//
// Every figure is read through the Store interface, so a field the store's
// projection drops is a field the report is missing — which is what the ground
// truth test asserts, and what makes a dropped field a failing report rather
// than a quiet under-count.
func (g *Generator) Generate(ctx context.Context, q Query) (Report, error) {
	if q.AnchorRun == "" {
		return Report{}, ErrLiveAnchor
	}
	if !q.Scope.Valid() {
		return Report{}, store.ErrScopeRequired
	}

	run, err := g.Store.GetRun(ctx, q.AnchorRun)
	if err != nil {
		return Report{}, err
	}
	if run.FinishedAt == nil {
		return Report{}, ErrLiveAnchor
	}

	rep := Report{
		Kind: q.Kind, Query: q, Repo: q.Repo,
		AnchorRun: run.ID, AnchorStartedAt: run.StartedAt,
		IssuedAt: g.now(),
		Provenance: Provenance{
			ScannerImage: run.ScannerImage,
			ToolVersions: run.ToolVersions,
			// VM-OQ-06 is unanswered until someone reviews shadow-run data, and
			// the flag in the calibration file is the single source of that
			// fact (OQ-P5-02).
			ThresholdsCalibrated: g.Calibration.StaticAnalysis.Calibrated,
			SLAWindowsCalibrated: g.Calibration.SLA.Calibrated,
		},
	}
	rep.Provenance.Caveats = caveatsFor(g.Calibration)

	findings, err := g.Store.ListFindings(ctx, store.Query{
		Scope: q.Scope, Repo: q.Repo, RunID: q.AnchorRun,
	})
	if err != nil {
		return Report{}, err
	}
	rep.Counts = countOf(findings)
	rep.Findings = rowsOf(findings)

	rep.Coverage, err = g.coverage(ctx, run, q.Repo)
	if err != nil {
		return Report{}, err
	}
	rep.Delta, err = g.delta(ctx, run, q)
	if err != nil {
		return Report{}, err
	}

	rep.ID = reportID(rep)
	return rep, nil
}

// caveatsFor renders the provenance caveats a reader must see.
//
// Every caveat here is in OUTPUT, not only in the config file. A P0 that looks
// confident while resting on uncalibrated thresholds hides its own provenance
// (OQ-P5-02), and so does a breach count measured against windows nobody has
// reviewed (OQ-P7b-03). Marking one and not the other is worse than marking
// neither: it teaches the reader that an absent caveat means calibrated.
func caveatsFor(cal score.Calibration) []string {
	var out []string
	if !cal.StaticAnalysis.Calibrated {
		out = append(out, "Priorities in this report derive from static analysis thresholds that have NOT been calibrated (VM-OQ-06). "+
			"Treat P0/P1 routing as provisional: the thresholds are the specification's defaults and are expected to be noisy until shadow-run data has been reviewed.")
	}
	if !cal.SLA.Calibrated {
		out = append(out, "SLA figures in this report are measured against PROVISIONAL remediation windows (VM-OQ-02 is unanswered): "+
			"the windows are the specification's working defaults and have not been agreed with the teams they bind. "+
			"A breach here means \"older than an unreviewed window\", not \"late against a commitment\".")
	}
	if !cal.FanOut.Enabled {
		out = append(out, "Blast radius is recorded but does not influence priority (VM-OQ-12 is unanswered), "+
			"so a vulnerability in a widely consumed shared module may rank below one confined to a single repository.")
	}
	return out
}

func countOf(findings []model.Finding) Counts {
	c := Counts{
		ByPriority: map[string]int{},
		ByState:    map[string]int{},
		ByCategory: map[string]int{},
	}
	for _, f := range findings {
		c.Total++
		switch model.PartitionOf(f.State) {
		case model.PartitionResolved:
			c.Resolved++
		case model.PartitionPendingVerification:
			c.PendingVerification++
		default:
			c.Unresolved++
		}
		if f.Priority != "" {
			c.ByPriority[string(f.Priority)]++
		}
		c.ByState[string(f.State)]++
		c.ByCategory[string(f.Category)]++
		if f.Derived.NotReobserved {
			c.NotReobserved++
		}
		switch f.Derived.SLAStatus {
		case model.SLABreached:
			c.SLABreached++
		case model.SLAPaused:
			c.SLAPaused++
		case "":
			c.SLANotComputed++
		}
	}
	return c
}

// rowsOf projects findings into report rows.
//
// Every field that survives the store's own projection is carried here. A field
// the store drops is a field this cannot invent, which is precisely the
// property the ground-truth test relies on.
func rowsOf(findings []model.Finding) []FindingRow {
	out := make([]FindingRow, 0, len(findings))
	for _, f := range findings {
		row := FindingRow{
			Fingerprint:    f.Fingerprint,
			Repo:           f.Repo,
			Category:       string(f.Category),
			PrimaryID:      f.Identity.PrimaryID,
			Module:         f.Location.Module,
			State:          string(f.State),
			Priority:       string(f.Priority),
			Severity:       string(f.Classification.Severity),
			Reachable:      string(f.Classification.Reachable),
			DepClass:       string(f.Classification.DepClass),
			Tools:          f.Provenance.Tools,
			FixedVersion:   f.Versions.Fixed,
			CredentialType: f.CredentialType,
			NotReobserved:  f.Derived.NotReobserved,
			SLAStatus:      string(f.Derived.SLAStatus),
		}
		if f.Location.File != nil {
			row.File = *f.Location.File
		}
		if f.Classification.FirstPartyPath != nil {
			row.FirstPartyPath = *f.Classification.FirstPartyPath
		}
		if f.ReasonCode != nil {
			row.ReasonCode = string(*f.ReasonCode)
		}
		if f.VerifiedReason != nil {
			row.VerifiedReason = string(*f.VerifiedReason)
		}
		if f.Derived.GapRepoScan != nil {
			row.GapRun = *f.Derived.GapRepoScan
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}

// coverage assembles the run's coverage picture from the plan and the scan
// results — never from the findings, which cannot show a repository that
// produced none.
func (g *Generator) coverage(ctx context.Context, run store.Run, repo string) (Coverage, error) {
	cov := Coverage{ByCause: map[string]int{}}

	plan, err := g.Store.PlanEntries(ctx, run.ID)
	if err != nil {
		return cov, err
	}

	var inScope []string
	for _, e := range plan {
		// Repositories excluded from scope entirely are not coverage: counting
		// an archived repository as a gap would inflate the denominator with
		// work nobody intends to do.
		if e.State == store.DispatchSkipped && e.SkipReason == store.SkipArchived {
			continue
		}
		if repo != "" && e.Repo != repo {
			continue
		}
		inScope = append(inScope, e.Repo)
	}
	sort.Strings(inScope)
	cov.InScope = len(inScope)

	for _, name := range inScope {
		results, err := g.Store.ScanResults(ctx, name, 200)
		if err != nil {
			return cov, err
		}
		var found bool
		for _, r := range results {
			if r.RunID != run.ID {
				continue
			}
			found = true
			switch r.Outcome {
			case model.ScanComplete:
				cov.Complete++
			case model.ScanPartial:
				cov.Partial++
			case model.ScanFailed:
				cov.Failed++
			case model.ScanNotDispatched:
				cov.NotDispatched++
			case model.ScanNoResult:
				cov.NoResult++
			}
			if !r.Outcome.Succeeded() {
				cause := r.FailureCause
				if cause == "" {
					cause = string(r.Outcome)
				}
				cov.ByCause[cause]++
				cov.UnscannedRepos = append(cov.UnscannedRepos, name)
			}
			break
		}
		if !found {
			// A planned repository with no scan result at all. This should not
			// happen once run close has written the delta, and it is counted as
			// a gap rather than ignored: silence is the one thing coverage
			// reporting must never render as clean.
			cov.NotDispatched++
			cov.ByCause["missing_scan_result"]++
			cov.UnscannedRepos = append(cov.UnscannedRepos, name)
		}
	}

	if cov.InScope > 0 {
		cov.Percent = float64(cov.Complete) / float64(cov.InScope) * 100
	}

	states, err := g.Store.FleetCoverage(ctx, run.Kind, inScope)
	if err != nil {
		return cov, err
	}
	cov.Staleness = store.Staleness(states, run.StartedAt)
	cov.Escalations = store.Escalations(states, 2)

	sort.Strings(cov.UnscannedRepos)
	return cov, nil
}

// delta compares against the previous run of the same kind (VM-F-14).
func (g *Generator) delta(ctx context.Context, run store.Run, q Query) (Delta, error) {
	var d Delta

	prev, err := g.Store.PreviousRun(ctx, run.Kind, run.Seq)
	if err != nil {
		return d, err
	}
	if prev.ID == "" {
		// No previous run of this kind. The report says so rather than
		// rendering a delta against zero, which would present the first run as
		// though the whole backlog had just appeared.
		return d, nil
	}
	d.PreviousRun = prev.ID
	d.Comparable = true

	// A delta is about run membership, so both sides are scoped to their run
	// regardless of the report's own scope. Using the report's scope would
	// compare two identical corpora — ScopeAll ignores the run filter entirely —
	// and every delta would be zero.
	current, err := g.Store.ListFindings(ctx, store.Query{Scope: store.ScopeRun, Repo: q.Repo, RunID: run.ID})
	if err != nil {
		return d, err
	}
	previous, err := g.Store.ListFindings(ctx, store.Query{Scope: store.ScopeRun, Repo: q.Repo, RunID: prev.ID})
	if err != nil {
		return d, err
	}

	prevSet := map[string]model.Finding{}
	for _, f := range previous {
		prevSet[f.Fingerprint] = f
	}
	curSet := map[string]model.Finding{}
	for _, f := range current {
		curSet[f.Fingerprint] = f
	}

	for fp, f := range curSet {
		if _, seen := prevSet[fp]; !seen {
			d.New++
		}
		if f.State == model.Regressed {
			d.Regressed++
		}
	}
	for fp := range prevSet {
		if _, still := curSet[fp]; !still {
			d.NoLongerObserved++
			// Only a finding that actually reached VERIFIED counts as fixed.
			if f, err := g.Store.GetFinding(ctx, fp); err == nil && f.State == model.Verified {
				d.Verified++
			}
		}
	}

	d.TotalChange = len(current) - len(previous)
	d.UnresolvedChange = countOf(current).Unresolved - countOf(previous).Unresolved
	return d, nil
}
