package model

import (
	"encoding/json"
	"fmt"
	"time"
)

// Category is the kind of defect a finding describes. The categories are
// exactly these four (VM-F-108).
type Category string

const (
	CategoryDependency Category = "dependency"
	CategoryCode       Category = "code"
	CategorySecret     Category = "secret"
	CategoryConfig     Category = "config"
)

// AllCategories is the closed enumeration (VM-F-108).
var AllCategories = []Category{
	CategoryDependency, CategoryCode, CategorySecret, CategoryConfig,
}

var categorySet = func() map[Category]bool {
	m := make(map[Category]bool, len(AllCategories))
	for _, c := range AllCategories {
		m[c] = true
	}
	return m
}()

// Valid reports whether c is a member of the closed enumeration.
func (c Category) Valid() bool { return categorySet[c] }

func (c Category) String() string { return string(c) }

// Reachable is a tri-state: "true" | "false" | "unknown".
//
// It is deliberately NOT a bool (VM-F-243, VM-AD §4.1). The third value is
// load-bearing: treating unknown as reachable lets transitive advisories
// dominate the P0 queue, and treating it as unreachable hides real risk. The
// scoring multiplier sits between the two known values for exactly this reason
// (VM-AD §9.6).
//
// UnmarshalJSON rejects JSON booleans outright so that a producer which
// regresses to `"reachable": true` fails loudly at the boundary rather than
// silently degrading the tri-state to two values.
type Reachable string

const (
	ReachableTrue    Reachable = "true"
	ReachableFalse   Reachable = "false"
	ReachableUnknown Reachable = "unknown"
)

// AllReachable is the closed enumeration.
var AllReachable = []Reachable{ReachableTrue, ReachableFalse, ReachableUnknown}

// Valid reports whether r is one of the three permitted values.
func (r Reachable) Valid() bool {
	return r == ReachableTrue || r == ReachableFalse || r == ReachableUnknown
}

func (r Reachable) String() string { return string(r) }

// ErrReachableBoolean is returned when reachability arrives as a JSON boolean.
type ErrReachableBoolean struct{ Literal string }

func (e *ErrReachableBoolean) Error() string {
	return fmt.Sprintf(
		"reachable must be the string %q, %q or %q, got JSON boolean %s: the tri-state is load-bearing and must not collapse to two values (VM-F-243)",
		ReachableTrue, ReachableFalse, ReachableUnknown, e.Literal)
}

// UnmarshalJSON decodes a tri-state reachability value, rejecting booleans.
func (r *Reachable) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "true" || s == "false" {
		return &ErrReachableBoolean{Literal: s}
	}
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("reachable: expected one of %q, %q, %q: %w",
			ReachableTrue, ReachableFalse, ReachableUnknown, err)
	}
	got := Reachable(v)
	if !got.Valid() {
		return fmt.Errorf("invalid reachable value %q: must be %q, %q or %q",
			v, ReachableTrue, ReachableFalse, ReachableUnknown)
	}
	*r = got
	return nil
}

// DepClass distinguishes a production dependency from a development-only one.
// It is an input to prioritisation (VM-F-242).
type DepClass string

const (
	DepProduction  DepClass = "production"
	DepDevelopment DepClass = "development"
	// DepNotApplicable is used for non-dependency categories.
	DepNotApplicable DepClass = "n/a"
)

// Identity names the defect. primary_id is chosen by a fixed precedence:
// GO-ID > GHSA > CVE > OSV > tool rule ID (VM-AD §4.1).
type Identity struct {
	PrimaryID string   `json:"primary_id"`
	Aliases   []string `json:"aliases"`
	RuleID    *string  `json:"rule_id"`
}

// Location places the defect. line is populated for human display only and is
// never an input to the fingerprint (VM-F-102, VM-ADR-04).
type Location struct {
	Module      string  `json:"module,omitempty"`
	ModuleMajor string  `json:"module_major,omitempty"`
	Package     *string `json:"package"`
	Function    *string `json:"function"`
	File        *string `json:"file"`
	Line        *int    `json:"line"`
}

// Versions records the affected and fixed versions of a dependency.
type Versions struct {
	Current    string `json:"current,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	Introduced string `json:"introduced,omitempty"`
}

// Classification carries the risk attributes that feed scoring (VM-AD §9.4).
type Classification struct {
	Severity       Severity  `json:"severity"`
	CVSS           float64   `json:"cvss,omitempty"`
	EPSS           float64   `json:"epss,omitempty"`
	KEV            bool      `json:"kev"`
	Reachable      Reachable `json:"reachable"`
	DepClass       DepClass  `json:"dep_class,omitempty"`
	Transitive     bool      `json:"transitive"`
	FirstPartyPath *string   `json:"first_party_path"`
}

// Provenance records which tools reported the finding and when it was seen.
// Run identifiers are per-kind sequences, never timestamps (VM-ADR-11).
type Provenance struct {
	Tools        []string          `json:"tools"`
	ToolVersions map[string]string `json:"tool_versions"`
	FirstSeenRun string            `json:"first_seen_run"`
	LastSeenRun  string            `json:"last_seen_run"`
}

// Triage is the model-produced enrichment (VM-AD §9.2).
//
// Priority is absent by design: it is computed deterministically by
// internal/score, never produced by inference (VM-F-305, VM-AD §9.2).
type Triage struct {
	Description            string     `json:"description"`
	Impact                 string     `json:"impact"`
	Remediation            string     `json:"remediation"`
	FalsePositiveCandidate bool       `json:"false_positive_candidate"`
	FPReasoning            *string    `json:"fp_reasoning"`
	TriagedAt              *time.Time `json:"triaged_at"`
	Model                  string     `json:"model,omitempty"`
}

// SLAStatus is the computed SLA position of a finding (VM-AD §9.5).
type SLAStatus string

const (
	SLAWithin      SLAStatus = "within"
	SLAApproaching SLAStatus = "approaching"
	SLABreached    SLAStatus = "breached"
	SLAPaused      SLAStatus = "paused"
	SLAStopped     SLAStatus = "stopped"
)

// Derived holds values computed by the framework rather than reported by a
// tool. They are exposed on the finding rather than recomputed by each consumer
// (VM-F-908), so that reports, tickets and the interface cannot disagree.
type Derived struct {
	// NotReobserved marks a finding that the most recent applicable run did not
	// observe while it remains unresolved (VM-F-161). It is not a resolution:
	// see GapRepoScan for the coverage gap that explains it (VM-F-162).
	NotReobserved bool      `json:"not_reobserved"`
	GapRepoScan   *string   `json:"gap_repo_scan"`
	AgeDays       int       `json:"age_days"`
	SLAWindowDays int       `json:"sla_window_days"`
	SLAStatus     SLAStatus `json:"sla_status,omitempty"`
	SLABreachDays int       `json:"sla_breach_days"`
}

// Refs links the finding to artifacts outside the findings store.
type Refs struct {
	Ticket          *string `json:"ticket"`
	PullRequest     *string `json:"pull_request"`
	UpstreamFinding *string `json:"upstream_finding"`
	AdvisoryURL     *string `json:"advisory_url"`
}

// Finding is the canonical finding record, schema findings.v1 (VM-AD §4.1).
//
// There is deliberately no field anywhere in this struct — nor in any struct it
// contains — capable of carrying a secret value. A secret finding records only
// its file path, line number and credential type (VM-F-263). The matched value,
// any substring of it, and any hash or derivative of it are not representable,
// which is a stronger guarantee than a redaction step that can be forgotten.
type Finding struct {
	SchemaVersion  string         `json:"schema_version"`
	Fingerprint    string         `json:"fingerprint"`
	Repo           string         `json:"repo"`
	Category       Category       `json:"category"`
	Identity       Identity       `json:"identity"`
	Location       Location       `json:"location"`
	Versions       Versions       `json:"versions"`
	Classification Classification `json:"classification"`
	Provenance     Provenance     `json:"provenance"`
	Triage         *Triage        `json:"triage"`
	State          State          `json:"state"`
	ReasonCode     *ReasonCode    `json:"reason_code"`
	Priority       Priority       `json:"priority,omitempty"`
	Derived        Derived        `json:"derived"`
	Refs           Refs           `json:"refs"`

	// VerifiedReason records how a VERIFIED finding came to be verified
	// (VM-AD §6.1.1). Nil unless the finding is verified.
	//
	// Disappearance on a qualifying scan is the universal verification trigger,
	// so VERIFIED no longer implies this framework fixed anything. Reporting
	// must be able to tell "we fixed it" from "it went away", or it claims
	// credit it has not earned.
	VerifiedReason *VerificationReason `json:"verified_reason,omitempty"`

	// CredentialType names the kind of credential for secret findings
	// (VM-F-263). It describes the class, never the value.
	CredentialType string `json:"credential_type,omitempty"`

	// Annotations carry observations a tool made that are recorded but do NOT
	// determine any classified value.
	//
	// The motivating case is osv-scanner v2's experimental Go reachability
	// analysis: it is retained, version-tagged, and auditable, so agreement with
	// the authority can be measured over time — but govulncheck remains the sole
	// reachability authority (VM-AD §8.2), and nothing here may reach
	// Classification. Promoting an annotation to a determiner must be an
	// explicit, tested widening, never a quiet one.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Validate checks the finding against the closed enumerations and the schema
// version. It does not check the fingerprint: computing one requires
// internal/fingerprint, and model depends on nothing (VM-AD §3).
func (f *Finding) Validate() error {
	if err := ValidateSchemaVersion(f.SchemaVersion); err != nil {
		return err
	}
	if f.Fingerprint == "" {
		return fmt.Errorf("finding: empty fingerprint")
	}
	if f.Repo == "" {
		return fmt.Errorf("finding %s: empty repo", f.Fingerprint)
	}
	if !f.Category.Valid() {
		return fmt.Errorf("finding %s: invalid category %q (must be one of dependency, code, secret, config)", f.Fingerprint, f.Category)
	}
	if !f.State.Valid() {
		return fmt.Errorf("finding %s: invalid state %q", f.Fingerprint, f.State)
	}
	if !f.Classification.Reachable.Valid() {
		return fmt.Errorf("finding %s: invalid reachable %q (must be %q, %q or %q)",
			f.Fingerprint, f.Classification.Reachable, ReachableTrue, ReachableFalse, ReachableUnknown)
	}
	if !f.Classification.Severity.Valid() {
		return fmt.Errorf("finding %s: invalid severity %q", f.Fingerprint, f.Classification.Severity)
	}
	if f.Priority != "" && !f.Priority.Valid() {
		return fmt.Errorf("finding %s: invalid priority %q", f.Fingerprint, f.Priority)
	}
	if f.ReasonCode != nil && !f.ReasonCode.Valid() {
		return fmt.Errorf("finding %s: invalid reason code %q", f.Fingerprint, *f.ReasonCode)
	}
	return nil
}

// RawFinding is what a scanner adapter produces after normalisation and before
// fingerprinting (VM-AD §8.4). It carries the identity and location inputs the
// fingerprint is computed from, in category-specific fields.
//
// Like Finding, it has no field capable of carrying a secret value. Redaction
// is enforced in the normalisation layer, before the value reaches any store or
// downstream consumer (VM-F-264) — the type makes that enforceable by leaving
// nowhere for a value to go.
type RawFinding struct {
	Repo     string
	Category Category

	// Identity inputs. Which are populated depends on Category (VM-AD §5).
	PrimaryID      string   // dependency: advisory id, before alias resolution
	Aliases        []string // dependency: alias set, e.g. from the OSV aliases field
	Tool           string   // code: reporting tool name
	RuleID         string   // code: tool rule id
	DetectorRuleID string   // secret: detector rule id
	CheckID        string   // config: check id

	// Location inputs.
	Module      string // dependency: module path
	ModuleMajor string // dependency: major version, e.g. "v0"
	Package     string // code: package import path
	Function    string // code: enclosing function name
	File        string // code fallback, secret, config: file path
	ResourceKey string // config: resource key

	// Line is retained for human display only. It is never an input to the
	// fingerprint (VM-F-102, VM-ADR-04): line-anchored identity resurrects every
	// finding on any reformat, destroying delta reporting and MTTR.
	Line int

	// CredentialType names the class of credential for secret findings.
	CredentialType string

	Versions       Versions
	Classification Classification
	ToolVersion    string
	AdvisoryURL    string

	// Annotations carry non-determining, version-tagged observations. See
	// Finding.Annotations: nothing here may reach Classification.
	Annotations map[string]string

	// Raw is the originating tool output, retained for audit and re-triage
	// (VM-F-109). For secret findings the adapter must redact before populating
	// this field.
	Raw json.RawMessage
}
