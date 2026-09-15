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
	CurrentVer     string `json:"current_version,omitempty"`
	FixedVer       string `json:"fixed_version,omitempty"`
	AdvisoryURL    string `json:"advisory_url,omitempty"`
	CredentialTy   string `json:"credential_type,omitempty"`
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
		CurrentVer:     raw.Versions.Current,
		FixedVer:       raw.Versions.Fixed,
		AdvisoryURL:    raw.AdvisoryURL,
		CredentialTy:   raw.CredentialType,
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
	CredentialType string
	FirstPartyPath string

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
