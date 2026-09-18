package store

import (
	"sort"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
)

// SourceObservation is what one tool asserted about one finding in one run.
//
// Observations are retained per source so the merged finding can always be
// recomputed from them and audited against them (VM-AD §8.6): it must remain
// possible to ask which tool asserted what.
type SourceObservation struct {
	Fingerprint string    `json:"fingerprint"`
	RunID       string    `json:"run_id"`
	Tool        string    `json:"tool"`
	ToolVersion string    `json:"tool_version"`
	ObservedAt  time.Time `json:"observed_at"`

	// Asserted values. A source that does not determine a value leaves it at
	// its zero: SeverityUnknown, ReachableUnknown, zero CVSS/EPSS.
	PrimaryID string          `json:"primary_id,omitempty"`
	Aliases   []string        `json:"aliases,omitempty"`
	Severity  model.Severity  `json:"severity,omitempty"`
	Reachable model.Reachable `json:"reachable,omitempty"`
	CVSS      float64         `json:"cvss,omitempty"`
	EPSS      float64         `json:"epss,omitempty"`
	KEV       bool            `json:"kev,omitempty"`
	DepClass  model.DepClass  `json:"dep_class,omitempty"`
	// FirstPartyPath is the shared module a vulnerable dependency is pulled in
	// through (VM-AD §12.2). It must survive the merge: it is the sole input to
	// the policy engine's upstream-defer rule, and a projection that drops it
	// silently turns every first-party finding into a per-consumer fix — the
	// exact divergence two-wave remediation exists to prevent (VM-ADR-07).
	FirstPartyPath string `json:"first_party_path,omitempty"`
	Transitive     bool   `json:"transitive,omitempty"`
	// Location fields. They come from the scanner rather than from the merge,
	// but they must travel with the observation: the Postgres store rebuilds the
	// whole finding document from the projection, so anything not carried here
	// is simply lost — which is how module, file and line went missing.
	Module      string `json:"module,omitempty"`
	ModuleMajor string `json:"module_major,omitempty"`
	Package     string `json:"package,omitempty"`
	Function    string `json:"function,omitempty"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`

	CurrentVer   string `json:"current_version,omitempty"`
	FixedVer     string `json:"fixed_version,omitempty"`
	IntroducedIn string `json:"introduced_version,omitempty"`
	AdvisoryURL  string `json:"advisory_url,omitempty"`
	CredentialTy string `json:"credential_type,omitempty"`

	// RuleID is the tool's own rule identifier — G404, SA1019, a semgrep
	// check id. Carried because it is the only human-readable name a code
	// finding has: without it a ticket title reads "unspecified" and a
	// reviewer cannot tell one static-analysis finding from another.
	RuleID string `json:"rule_id,omitempty"`

	// Annotations are the non-determining, version-tagged observations
	// OQ-P3-01 decided to RETAIN — osv-scanner's experimental reachability
	// among them. Dropping them here discarded the whole point of that
	// decision: the provenance was recorded on the raw finding and then lost
	// on the way into the store.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// SourceOf builds a SourceObservation from an adapter's raw finding.
func SourceOf(fp, runID string, observedAt time.Time, raw model.RawFinding) SourceObservation {
	return SourceObservation{
		Fingerprint:    fp,
		RunID:          runID,
		Tool:           raw.Tool,
		ToolVersion:    raw.ToolVersion,
		ObservedAt:     observedAt.UTC(),
		PrimaryID:      raw.PrimaryID,
		Aliases:        raw.Aliases,
		Severity:       raw.Classification.Severity,
		Reachable:      raw.Classification.Reachable,
		CVSS:           raw.Classification.CVSS,
		EPSS:           raw.Classification.EPSS,
		KEV:            raw.Classification.KEV,
		DepClass:       raw.Classification.DepClass,
		FirstPartyPath: derefString(raw.Classification.FirstPartyPath),
		Transitive:     raw.Classification.Transitive,
		Module:         raw.Module,
		ModuleMajor:    raw.ModuleMajor,
		Package:        raw.Package,
		Function:       raw.Function,
		File:           raw.File,
		Line:           raw.Line,
		CurrentVer:     raw.Versions.Current,
		FixedVer:       raw.Versions.Fixed,
		IntroducedIn:   raw.Versions.Introduced,
		AdvisoryURL:    raw.AdvisoryURL,
		CredentialTy:   raw.CredentialType,
		RuleID:         firstNonEmpty(raw.RuleID, raw.DetectorRuleID, raw.CheckID),
		Annotations:    raw.Annotations,
	}
}

// Projection is the merged view of a finding across its sources (VM-AD §8.6).
type Projection struct {
	PrimaryID      string
	Aliases        []string
	Tools          []string
	Classification model.Classification
	FixedVersion   string
	CurrentVersion string
	AdvisoryURL    string
	IntroducedIn   string
	RuleID         string
	Annotations    map[string]string
	CredentialType string
	FirstPartyPath string

	// Location, taken from the first source that reports it. Sources are folded
	// in a deterministic order, so this does not depend on which tool happened
	// to run first.
	Module      string
	ModuleMajor string
	Package     string
	Function    string
	File        string
	Line        int

	// FixedCandidates retains every fixed version any source proposed, so the
	// choice of FixedVersion is auditable rather than merely asserted.
	FixedCandidates []string

	// ReachabilityConflict records two sources determining reachability
	// differently. The projection resolves conservatively to "true"; the
	// conflict is recorded rather than discarded because a disagreement between
	// two reachability-capable tools is itself a finding about the tools.
	ReachabilityConflict bool
	ConflictDetail       string
}

// Project folds per-source observations into the merged finding view.
//
// It is a pure, order-independent function, recomputed on every change rather
// than applied incrementally (VM-AD §8.6). Last-upsert-wins is non-compliant:
// it would make the stored record a function of scan scheduling, so replaying a
// run — or the same two tools finishing in the other order — would silently
// change the finding.
//
// Callers pass the latest observation per source. A source's contribution is
// superseded only by a successful re-scan from that same source; it is never
// dropped because some later partial or failed scan did not re-observe it
// (VM-ADR-12 consistency constraint, VM-AD §8.6).
func Project(obs []SourceObservation) Projection {
	var p Projection
	if len(obs) == 0 {
		p.Classification.Severity = model.SeverityUnknown
		p.Classification.Reachable = model.ReachableUnknown
		return p
	}

	// Folded in a deterministic order so "first source that reports it" is a
	// property of the observation set, not of arrival order.
	obs = append([]SourceObservation(nil), obs...)
	sort.SliceStable(obs, func(i, j int) bool { return obs[i].Tool < obs[j].Tool })

	var (
		tools                 = map[string]bool{}
		aliases               = map[string]bool{}
		fixes                 = map[string]bool{}
		sevSet                bool
		reachTrue, reachFalse []string
		bestSeverity          model.Severity = model.SeverityUnknown
	)

	for _, o := range obs {
		if o.Tool != "" {
			tools[o.Tool] = true
		}

		// Identity: the alias union across every source. The canonical
		// identifier is then the §4.1 precedence winner over that union, which
		// is what lets two tools naming one defect differently agree.
		if o.PrimaryID != "" {
			aliases[o.PrimaryID] = true
		}
		for _, a := range o.Aliases {
			if a != "" {
				aliases[a] = true
			}
		}

		// Severity: maximum over the sources that supply one. A source
		// supplying none contributes nothing — it must not pull the result
		// down to UNKNOWN, which is what would happen under a naive fold.
		if o.Severity != "" && o.Severity != model.SeverityUnknown {
			if !sevSet || o.Severity.Rank() < bestSeverity.Rank() {
				bestSeverity = o.Severity
				sevSet = true
			}
		}

		// Reachability: record which sources determined what, so a genuine
		// conflict is distinguishable from silence.
		switch o.Reachable {
		case model.ReachableTrue:
			reachTrue = append(reachTrue, o.Tool)
		case model.ReachableFalse:
			reachFalse = append(reachFalse, o.Tool)
		}

		// Numeric risk inputs: maximum over the sources that supply them.
		if o.CVSS > p.Classification.CVSS {
			p.Classification.CVSS = o.CVSS
		}
		if o.EPSS > p.Classification.EPSS {
			p.Classification.EPSS = o.EPSS
		}
		if o.KEV {
			p.Classification.KEV = true
		}
		if o.Transitive {
			p.Classification.Transitive = true
		}

		// Dependency class: a source asserting production outranks one
		// asserting development-only. Over-stating exposure is safer than
		// under-stating it.
		if o.DepClass == model.DepProduction {
			p.Classification.DepClass = model.DepProduction
		} else if o.DepClass != "" && p.Classification.DepClass == "" {
			p.Classification.DepClass = o.DepClass
		}

		if o.FixedVer != "" {
			fixes[o.FixedVer] = true
		}
		if p.CurrentVersion == "" && o.CurrentVer != "" {
			p.CurrentVersion = o.CurrentVer
		}
		if p.AdvisoryURL == "" && o.AdvisoryURL != "" {
			p.AdvisoryURL = o.AdvisoryURL
		}
		if p.IntroducedIn == "" && o.IntroducedIn != "" {
			p.IntroducedIn = o.IntroducedIn
		}
		if p.RuleID == "" && o.RuleID != "" {
			p.RuleID = o.RuleID
		}
		// Merged across sources rather than taken from one: two tools may each
		// annotate the same finding, and keeping only the first would discard
		// the other's provenance (OQ-P3-01). The tool name prefixes each key,
		// so there is nothing to collide.
		for k, v := range o.Annotations {
			if p.Annotations == nil {
				p.Annotations = map[string]string{}
			}
			if _, exists := p.Annotations[k]; !exists {
				p.Annotations[k] = v
			}
		}
		if p.CredentialType == "" && o.CredentialTy != "" {
			p.CredentialType = o.CredentialTy
		}
		// Any source naming a first-party path settles it: one tool knowing the
		// dependency comes in through a shared module is enough, and losing that
		// because another tool did not report it would route the finding as a
		// direct dependency.
		if p.FirstPartyPath == "" && o.FirstPartyPath != "" {
			p.FirstPartyPath = o.FirstPartyPath
		}
		if p.Module == "" && o.Module != "" {
			p.Module, p.ModuleMajor = o.Module, o.ModuleMajor
		}
		if p.Package == "" && o.Package != "" {
			p.Package = o.Package
		}
		if p.Function == "" && o.Function != "" {
			p.Function = o.Function
		}
		if p.File == "" && o.File != "" {
			p.File, p.Line = o.File, o.Line
		}
	}

	p.Tools = sortedKeys(tools)
	p.Aliases = sortedKeys(aliases)
	p.FixedCandidates = sortedKeys(fixes)

	// Canonical identifier over the alias union, by the §4.1 precedence.
	if len(p.Aliases) > 0 {
		p.PrimaryID = fingerprint.ResolveAlias(p.Aliases[0], p.Aliases[1:])
	}

	p.Classification.Severity = bestSeverity
	p.Classification.Reachable = resolveReachability(reachTrue, reachFalse, &p)

	// The fix that fully closes the defect is the highest proposed.
	p.FixedVersion = highestVersion(p.FixedCandidates)

	return p
}

// resolveReachability applies the VM-AD §8.6 reachability rule.
//
// A determination overrides unknown; unknown never overrides a determination.
// Two sources determining differently resolve to "true" — the conservative
// answer — and the conflict is recorded.
//
// The conflict branch is not reachable with today's tool matrix, since
// govulncheck is the only source that determines reachability. It is
// implemented so that adding a second reachability-capable source is a
// configuration change rather than a correctness question.
func resolveReachability(determinedTrue, determinedFalse []string, p *Projection) model.Reachable {
	switch {
	case len(determinedTrue) > 0 && len(determinedFalse) > 0:
		p.ReachabilityConflict = true
		sort.Strings(determinedTrue)
		sort.Strings(determinedFalse)
		p.ConflictDetail = "reachable=true from [" + strings.Join(determinedTrue, " ") +
			"], reachable=false from [" + strings.Join(determinedFalse, " ") +
			"]; resolved to true (VM-AD §8.6)"
		return model.ReachableTrue
	case len(determinedTrue) > 0:
		return model.ReachableTrue
	case len(determinedFalse) > 0:
		return model.ReachableFalse
	default:
		return model.ReachableUnknown
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// LatestPerSource reduces a set of observations to the most recent one from
// each tool.
//
// This is the VM-ADR-12 consistency constraint in code: a source's contribution
// survives until that same source observes again in a later run. A partial or
// failed scan that did not re-observe the finding contributes no observation at
// all, so it cannot silently drop another tool's prior assertion.
func LatestPerSource(obs []SourceObservation) []SourceObservation {
	latest := map[string]SourceObservation{}
	for _, o := range obs {
		prev, seen := latest[o.Tool]
		if !seen || supersedes(o, prev) {
			latest[o.Tool] = o
		}
	}
	out := make([]SourceObservation, 0, len(latest))
	for _, o := range latest {
		out = append(out, o)
	}
	// Sorted so that callers holding the slice see a deterministic order; the
	// projection itself does not depend on it.
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}

// supersedes reports whether a is a later observation than b from the same
// source. Ties on timestamp fall back to run identifier so that replaying a run
// is idempotent rather than order-sensitive.
func supersedes(a, b SourceObservation) bool {
	if a.ObservedAt.After(b.ObservedAt) {
		return true
	}
	if a.ObservedAt.Equal(b.ObservedAt) {
		return a.RunID > b.RunID
	}
	return false
}

// withFirstParty puts the projected first-party path back on a classification.
func withFirstParty(c model.Classification, path string) model.Classification {
	if path != "" {
		p := path
		c.FirstPartyPath = &p
	}
	return c
}

// LocationOf builds the finding location from a projection.
func (p Projection) LocationOf() model.Location {
	loc := model.Location{Module: p.Module, ModuleMajor: p.ModuleMajor}
	if p.Package != "" {
		v := p.Package
		loc.Package = &v
	}
	if p.Function != "" {
		v := p.Function
		loc.Function = &v
	}
	if p.File != "" {
		v := p.File
		loc.File = &v
	}
	if p.Line != 0 {
		v := p.Line
		loc.Line = &v
	}
	return loc
}

// firstNonEmpty returns the first non-empty string.
//
// The three rule-identifier fields are populated by different tool families —
// RuleID by gosec, DetectorRuleID by gitleaks, CheckID by semgrep and
// staticcheck — and exactly one is set per finding.
func firstNonEmpty(in ...string) string {
	for _, s := range in {
		if s != "" {
			return s
		}
	}
	return ""
}

// ApplyIntel fills a projection's exploitation-intelligence fields from the
// intel rows, matching on ANY of the finding's identifiers.
//
// One shared function, called by both backends, because a join written twice
// is a join that will disagree twice — and this one decides whether a finding
// reads as known-exploited.
//
// Matching on aliases is not an optimisation. The feeds are CVE-keyed and this
// framework's findings are keyed by GO- and GHSA- identifiers as often as not,
// so a lookup that only consulted the primary identifier would report "no KEV
// data" for the majority of Go advisories — which is indistinguishable, in the
// score, from "checked and not exploited".
//
// Where two identifiers of one finding both have rows, the FRESHER snapshot
// wins per field: the question is what is true now, and preferring the scarier
// of two answers is how a stale row outlives its correction.
func ApplyIntel(p *Projection, intel map[string]Intel) {
	ApplyIntelTo(&p.Classification, append([]string{p.PrimaryID}, p.Aliases...), intel)
}

// ApplyIntelToFinding is the same join against a materialised finding, which
// is where both backends apply it: joined at READ time, so a feed refresh is
// visible without waiting for the next scan to reproject.
func ApplyIntelToFinding(f *model.Finding, intel map[string]Intel) {
	ApplyIntelTo(&f.Classification, IntelIDs(*f), intel)
}

// ApplyIntelTo fills a classification from the intel rows matching any of ids.
func ApplyIntelTo(c *model.Classification, ids []string, intel map[string]Intel) {
	if len(intel) == 0 {
		return
	}
	var epss *Intel
	var kev *Intel
	for _, id := range ids {
		row, ok := intel[id]
		if !ok {
			continue
		}
		if row.EPSSAvailable && (epss == nil || fresher(row.EPSSAsOf, epss.EPSSAsOf)) {
			r := row
			epss = &r
		}
		if row.KEVAvailable && (kev == nil || fresher(row.KEVAsOf, kev.KEVAsOf)) {
			r := row
			kev = &r
		}
	}

	if epss != nil {
		c.EPSS = epss.EPSS
		c.EPSSAvailable = true
		c.EPSSAsOf = epss.EPSSAsOf
	}
	if kev != nil {
		c.KEV = kev.KEV
		c.KEVAvailable = true
		c.KEVAsOf = kev.KEVAsOf
	}
}

// fresher reports whether a is a later snapshot than b. A nil date is not
// fresher than anything: an answer whose age is unknown cannot be preferred
// over one whose age is known.
func fresher(a, b *time.Time) bool {
	if a == nil {
		return false
	}
	if b == nil {
		return true
	}
	return a.After(*b)
}

// IntelIDs returns the identifiers worth asking the feeds about for a finding.
//
// Every identifier, primary and alias, because the feeds are CVE-keyed and the
// caller cannot know which of a finding's names the catalogue uses.
func IntelIDs(f model.Finding) []string {
	out := make([]string, 0, 1+len(f.Identity.Aliases))
	seen := map[string]bool{}
	for _, id := range append([]string{f.Identity.PrimaryID}, f.Identity.Aliases...) {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
