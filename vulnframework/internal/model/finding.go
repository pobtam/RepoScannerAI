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
	Severity Severity `json:"severity"`
	CVSS     float64  `json:"cvss,omitempty"`
	EPSS     float64  `json:"epss,omitempty"`
	KEV      bool     `json:"kev"`

	// EPSSAvailable and KEVAvailable say whether the enrichment feed ANSWERED,
	// as distinct from answering zero or false (OQ-AUDIT-01).
	//
	// An EPSS of 0 with EPSSAvailable means measured and negligible. An EPSS
	// of 0 without it means nobody looked, and the two must never render as
	// the same thing: collapsing them lets a feed outage read as good news.
	// This is reachability's tri-state discipline applied to the two inputs
	// that most often change what a human does.
	EPSSAvailable bool `json:"epss_available"`
	KEVAvailable  bool `json:"kev_available"`
	// EPSSAsOf and KEVAsOf are the snapshot dates. EPSS publishes daily and is
	// routinely behind; a score quoted without its date cannot be judged, and
	// during an incident the number that matters is the one not yet published.
	EPSSAsOf *time.Time `json:"epss_as_of,omitempty"`
	KEVAsOf  *time.Time `json:"kev_as_of,omitempty"`

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

	// ResidualPossible marks a VERIFIED finding whose fingerprint granularity
	// could have covered more than one occurrence (OQ-AUDIT-02).
	//
	// Code and secret findings are located to a FILE, because no pinned tool
	// reports the enclosing symbol. Two occurrences of one rule — or two
	// credentials — in one file are therefore ONE finding, and a verification
	// can mean the reported occurrence was fixed while another in the same
	// file was not flagged, or was flagged as the same finding.
	//
	// This is absence-is-not-resolution one level down. VM-ADR-12 asks whether
	// the scan looked; this asks whether what it looked AT was one thing. A
	// VERIFIED that can hide a live twin must not pass silently.
	ResidualPossible bool `json:"residual_possible,omitempty"`
	// ResidualDetail explains it. A boolean nobody can act on is not a
	// warning, it is a decoration.
	ResidualDetail string `json:"residual_detail,omitempty"`
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

	// FirstSeenAt and LastSeenAt are the detection and last-observation
	// timestamps. The SLA clock starts at detection, not at triage or
	// assignment (VM-NF-302), so the age cannot be computed without them —
	// they were held in the store and never surfaced, which is why nothing
	// downstream could compute an SLA at all.
	FirstSeenAt time.Time  `json:"first_seen_at,omitempty"`
	LastSeenAt  time.Time  `json:"last_seen_at,omitempty"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`

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

	// SuppressionProposal is the record of the repository's own scanner
	// configuration proposing to suppress this secret: which mechanism, which
	// file, when, and what a human decided. Kept after a decision, so the
	// audit trail outlives the proposal.
	SuppressionProposal *SuppressionProposal `json:"suppression_proposal,omitempty"`

	// RemovedUnrotated is set while a secret has left the scanned files and no
	// human has confirmed the credential was rotated. The finding stays open:
	// the secret is still in the repository's history and, until rotated,
	// still valid (VM-F-856). It records when, never what.
	RemovedUnrotated *SecretRemoval `json:"removed_unrotated,omitempty"`
}

// AllowlistMechanism names how a repository told its secret scanner to ignore
// something.
type AllowlistMechanism string

const (
	// AllowlistConfig — an allowlist in the repository's .gitleaks.toml.
	AllowlistConfig AllowlistMechanism = "gitleaks_toml"
	// AllowlistIgnoreFile — an entry in the repository's .gitleaksignore.
	AllowlistIgnoreFile AllowlistMechanism = "gitleaksignore"
	// AllowlistInline — a gitleaks:allow comment on the line itself.
	AllowlistInline AllowlistMechanism = "inline_allow"
)

// Allowlist is the evidence that a repository's scanner configuration, not a
// fix, is why a secret went unreported. It records where the decision lives,
// never anything about the credential.
type Allowlist struct {
	Mechanism AllowlistMechanism `json:"mechanism"`
	// Path is the file holding the decision, repository-relative: the config
	// file, or for an inline comment the file the secret is in.
	Path string `json:"path"`
	// ConfigSHA256 identifies the version of the config file that made the
	// decision. A hash of the configuration — never of a secret (VM-F-263).
	ConfigSHA256 string `json:"config_sha256,omitempty"`
	// Description is what the allowlist says about itself, where it says
	// anything: the allowlist's description, or the ignore-file entry.
	Description string `json:"description,omitempty"`
}

// ProposalStatus is where a suppression proposal stands.
type ProposalStatus string

const (
	// ProposalPending — awaiting a human.
	ProposalPending ProposalStatus = "pending"
	// ProposalOverdue — unreviewed past the secret SLA window, and escalated.
	// Still decidable.
	ProposalOverdue ProposalStatus = "overdue"
	// ProposalConfirmed — a human agreed; the finding is SUPPRESSED.
	ProposalConfirmed ProposalStatus = "confirmed"
	// ProposalRejected — a human disagreed. Not proposed again while the
	// allowlist configuration is unchanged.
	ProposalRejected ProposalStatus = "rejected"
	// ProposalWithdrawn — the allowlist stopped hiding the secret.
	ProposalWithdrawn ProposalStatus = "withdrawn"
)

// Open reports whether the proposal still awaits a decision.
func (s ProposalStatus) Open() bool { return s == ProposalPending || s == ProposalOverdue }

// SuppressionProposal is the audit record of one allowlist proposal.
type SuppressionProposal struct {
	Allowlist
	Status      ProposalStatus `json:"status"`
	ProposedRun string         `json:"proposed_run"`
	ProposedAt  time.Time      `json:"proposed_at"`
	EscalatedAt *time.Time     `json:"escalated_at,omitempty"`
	DecidedBy   string         `json:"decided_by,omitempty"`
	DecidedAt   *time.Time     `json:"decided_at,omitempty"`
	// WithdrawnRun is the run that saw the secret again without the allowlist
	// hiding it.
	WithdrawnRun string     `json:"withdrawn_run,omitempty"`
	WithdrawnAt  *time.Time `json:"withdrawn_at,omitempty"`
}

// SecretRemoval records the complete scan that first no longer saw a secret.
type SecretRemoval struct {
	Run string    `json:"run"`
	At  time.Time `json:"at"`
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

	// ImportPath is how the vulnerable module is reached, from the consuming
	// repository outwards: [repo, intermediate module, ..., vulnerable module].
	//
	// Structural output from the scanner's own module graph — govulncheck's
	// trace, a lockfile's dependency tree — and not inference. It is the input
	// first-party classification reads (VM-AD §12.2): what makes a
	// third-party vulnerability a first-party problem is the hop in between,
	// and nothing else in the finding records that hop.
	//
	// It is deliberately NOT part of the fingerprint. The path through which a
	// module is reached changes when an unrelated dependency is added, and a
	// fingerprint that moved on that would report the same defect as new
	// (VM-ADR-04's reasoning, applied one level out).
	ImportPath  []string
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

	// Allowlisted is set on a secret the scanner found only by looking past
	// the repository's own allowlist: present in the files, hidden by
	// configuration. Its presence is an observation; the allowlist is a
	// suppression proposal for a human (see Finding.SuppressionProposal).
	Allowlisted *Allowlist `json:",omitempty"`
}

// ResidualWarning describes the imprecision a verification at this category's
// fingerprint granularity carries (OQ-AUDIT-02).
//
// Returns the empty string where the granularity hides nothing. Living in the
// model rather than in the store means both backends produce the same wording
// from the same rule — a warning phrased differently by each would read as two
// different problems.
func ResidualWarning(c Category) string {
	switch c {
	case CategoryCode:
		return "This finding is located to a FILE, not to a function: no scanner in the pinned tool " +
			"set reports the enclosing symbol. Two occurrences of the same rule in the same file are " +
			"therefore one finding, so this verification may have confirmed the reported occurrence " +
			"while another in the same file remains. Check the file, not just the fix (OQ-AUDIT-02)."
	case CategorySecret:
		return "This finding is located to a FILE. Two credentials in the same file are one finding, " +
			"so this verification may have confirmed one rotation while another credential in the " +
			"same file remains live. Check the file, not just the fix (OQ-AUDIT-02)."
	case CategoryConfig:
		return "This finding is located to a file and a resource key. A second misconfiguration " +
			"under the same key may not have been reported separately (OQ-AUDIT-02)."
	default:
		// Dependency findings are located to a module and major version. The
		// module either resolves to the fixed version or it does not, so there
		// is no second occurrence to hide — and a warning on every
		// verification would be filtered out within a week, taking the real
		// ones with it.
		return ""
	}
}
