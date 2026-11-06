// Package nuguard is a client for the NuGuard Remote Scan API: submit a scan
// of one repository at one commit, wait for it, and fetch its result.
//
// The contract is NuGuard's own published OpenAPI document
// (nuguard/service/openapi.json in the NuGuard repository). Where its prose
// specification and that document disagree, the document wins. The types here
// mirror only the schemas this project reads.
//
// Decoding is strict about enum VALUES and tolerant of new FIELDS. A status,
// kind or severity this code has never seen is an error, because a value
// mapped to a default would turn, say, an unknown failure state into an
// unrecognised success. A new field is ignored here and caught instead by the
// fixture shape test (internal/scan/adapters), which is where a newly-seen
// field becomes a decision rather than a silent drop.
package nuguard

import (
	"encoding/json"
	"fmt"
)

// ScanStatus is a job's lifecycle state.
type ScanStatus string

const (
	StatusQueued    ScanStatus = "queued"
	StatusRunning   ScanStatus = "running"
	StatusSucceeded ScanStatus = "succeeded"
	// StatusPartial finished, but at least one requested tool did not reach
	// ok or not_applicable.
	StatusPartial   ScanStatus = "partial"
	StatusFailed    ScanStatus = "failed"
	StatusCancelled ScanStatus = "cancelled"
	StatusExpired   ScanStatus = "expired"
)

// ScanStatuses is every status this client understands.
var ScanStatuses = []ScanStatus{StatusQueued, StatusRunning, StatusSucceeded,
	StatusPartial, StatusFailed, StatusCancelled, StatusExpired}

// Terminal reports whether a job in this state will not change again.
func (s ScanStatus) Terminal() bool {
	switch s {
	case StatusQueued, StatusRunning:
		return false
	default:
		return true
	}
}

func (s *ScanStatus) UnmarshalJSON(b []byte) error {
	return decodeEnum(b, s, "scan status", ScanStatuses)
}

// ScanPhase is where a running job is.
type ScanPhase string

const (
	PhaseQueued     ScanPhase = "queued"
	PhaseCloning    ScanPhase = "cloning"
	PhaseSBOM       ScanPhase = "sbom"
	PhaseAnalyzing  ScanPhase = "analyzing"
	PhaseFinalizing ScanPhase = "finalizing"
)

// ScanPhases is every phase this client understands.
var ScanPhases = []ScanPhase{PhaseQueued, PhaseCloning, PhaseSBOM, PhaseAnalyzing, PhaseFinalizing}

func (p *ScanPhase) UnmarshalJSON(b []byte) error { return decodeEnum(b, p, "scan phase", ScanPhases) }

// Kind is what a finding is about.
type Kind string

const (
	KindCode        Kind = "code"
	KindPosture     Kind = "posture"
	KindDependency  Kind = "dependency"
	KindIaC         Kind = "iac"
	KindContainer   Kind = "container"
	KindSupplyChain Kind = "supply_chain"
)

// Kinds is every finding kind this client understands.
var Kinds = []Kind{KindCode, KindPosture, KindDependency, KindIaC, KindContainer, KindSupplyChain}

func (k *Kind) UnmarshalJSON(b []byte) error { return decodeEnum(b, k, "finding kind", Kinds) }

// Severity is a finding's band.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Severities is every severity this client understands.
var Severities = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

func (s *Severity) UnmarshalJSON(b []byte) error { return decodeEnum(b, s, "severity", Severities) }

// ToolRunStatus is how one of NuGuard's tools ended.
type ToolRunStatus string

const (
	ToolOK            ToolRunStatus = "ok"
	ToolFailed        ToolRunStatus = "failed"
	ToolSkipped       ToolRunStatus = "skipped"
	ToolDisabled      ToolRunStatus = "disabled"
	ToolNotApplicable ToolRunStatus = "not_applicable"
	ToolTimeout       ToolRunStatus = "timeout"
)

// ToolRunStatuses is every tool status this client understands.
var ToolRunStatuses = []ToolRunStatus{ToolOK, ToolFailed, ToolSkipped, ToolDisabled, ToolNotApplicable, ToolTimeout}

func (s *ToolRunStatus) UnmarshalJSON(b []byte) error {
	return decodeEnum(b, s, "tool run status", ToolRunStatuses)
}

// ToolName is one of the analysis tools a scan can be asked to run.
type ToolName string

const (
	ToolNGARules    ToolName = "nga-rules"
	ToolAtlas       ToolName = "atlas"
	ToolSemgrep     ToolName = "semgrep"
	ToolOSV         ToolName = "osv"
	ToolGrype       ToolName = "grype"
	ToolCheckov     ToolName = "checkov"
	ToolTrivy       ToolName = "trivy"
	ToolSupplyChain ToolName = "supply-chain"
)

// ToolNames is every tool name this client understands.
var ToolNames = []ToolName{ToolNGARules, ToolAtlas, ToolSemgrep, ToolOSV, ToolGrype,
	ToolCheckov, ToolTrivy, ToolSupplyChain}

func (n *ToolName) UnmarshalJSON(b []byte) error { return decodeEnum(b, n, "tool name", ToolNames) }

// KindsOf names the finding kinds a tool can produce, so a result can be
// checked against what was asked for. nga-rules, atlas and semgrep produce
// code findings, and posture findings when posture is requested; the others
// produce only what their names say.
func KindsOf(tool string) []Kind {
	switch ToolName(tool) {
	case ToolOSV, ToolGrype:
		return []Kind{KindDependency}
	case ToolTrivy:
		return []Kind{KindDependency, KindContainer, KindIaC}
	case ToolCheckov:
		return []Kind{KindIaC}
	case ToolSupplyChain:
		return []Kind{KindSupplyChain}
	default:
		return []Kind{KindCode}
	}
}

// ScanOptions narrows what a scan does. A nil Tools asks for every tool the
// server allows; the server may narrow further and never widens.
type ScanOptions struct {
	Tools          []ToolName `json:"tools"`
	MinSeverity    Severity   `json:"min_severity,omitempty"`
	IncludeSBOM    bool       `json:"include_sbom"`
	IncludePosture bool       `json:"include_posture"`
	Network        bool       `json:"network"`
	UseLLM         bool       `json:"use_llm"`
	Subpath        *string    `json:"subpath,omitempty"`
}

// ScanCreateRequest is a scan submission without its credential. The GitHub
// token is never a field of any type here: it is read from a function at the
// moment the request body is written, and exists only in that body
// (VM-F-206).
type ScanCreateRequest struct {
	RepoURL         string      `json:"repo_url"`
	Ref             string      `json:"ref,omitempty"`
	Options         ScanOptions `json:"options"`
	ClientReference string      `json:"client_reference,omitempty"`
}

// ProblemDetail is an RFC 9457 error. Code is the stable machine code; the
// set is open, so it is a string and an unknown one is a plain failure.
type ProblemDetail struct {
	Type   string  `json:"type"`
	Title  string  `json:"title"`
	Status int     `json:"status"`
	Code   string  `json:"code"`
	Detail *string `json:"detail"`
}

// ScanJob is a job's status.
type ScanJob struct {
	ID              string            `json:"id"`
	Status          ScanStatus        `json:"status"`
	Phase           *ScanPhase        `json:"phase"`
	RepoURL         string            `json:"repo_url"`
	RefRequested    *string           `json:"ref_requested"`
	CommitSHA       *string           `json:"commit_sha"`
	ClientReference *string           `json:"client_reference"`
	CreatedAt       string            `json:"created_at"`
	StartedAt       *string           `json:"started_at"`
	FinishedAt      *string           `json:"finished_at"`
	Error           *ProblemDetail    `json:"error"`
	Links           map[string]string `json:"links"`
}

// ToolVersion is one tool's exact version, as the service reports it.
type ToolVersion struct {
	Name    string  `json:"name"`
	Version *string `json:"version"`
}

// Provenance pins what produced a result.
type Provenance struct {
	NuGuardVersion string        `json:"nuguard_version"`
	ServiceVersion string        `json:"service_version"`
	ImageDigest    *string       `json:"image_digest"`
	RulepackSHA256 string        `json:"rulepack_sha256"`
	Tools          []ToolVersion `json:"tools"`
	// OptionsEffective is the options after the server's clamping. Its Tools
	// has been observed null even when the server narrowed the set, so it is
	// not the authority for what ran: Coverage.ToolRuns is.
	OptionsEffective ScanOptions `json:"options_effective"`
	LLMUsed          bool        `json:"llm_used"`
}

// ToolRun is how one requested tool ended.
type ToolRun struct {
	Tool       string        `json:"tool"`
	Version    *string       `json:"version"`
	Status     ToolRunStatus `json:"status"`
	Findings   int           `json:"findings"`
	DurationMS *int          `json:"duration_ms"`
	Reason     *string       `json:"reason"`
}

// Coverage says what a scan covered and what it did not.
type Coverage struct {
	ToolRuns          []ToolRun `json:"tool_runs"`
	LanguagesDetected []string  `json:"languages_detected"`
	FilesScanned      int       `json:"files_scanned"`
	FilesSkipped      int       `json:"files_skipped"`
	Gaps              []string  `json:"gaps"`
}

// FindingLocation is where a finding is. Paths are repository-relative.
type FindingLocation struct {
	Path      string  `json:"path"`
	StartLine *int    `json:"start_line"`
	EndLine   *int    `json:"end_line"`
	Symbol    *string `json:"symbol"`
}

// ScanFinding is one finding as the service projects it. Raw is NuGuard's
// full finding, kept as bytes: this project reads none of it.
type ScanFinding struct {
	Fingerprint         string            `json:"fingerprint"`
	RuleID              string            `json:"rule_id"`
	SourceTool          string            `json:"source_tool"`
	Kind                Kind              `json:"kind"`
	Severity            Severity          `json:"severity"`
	Title               string            `json:"title"`
	Description         string            `json:"description"`
	Locations           []FindingLocation `json:"locations"`
	AffectedComponent   *string           `json:"affected_component"`
	References          []string          `json:"references"`
	OWASPLLMRef         *string           `json:"owasp_llm_ref"`
	OWASPASIRef         *string           `json:"owasp_asi_ref"`
	MITREAtlasTechnique *string           `json:"mitre_atlas_technique"`
	Remediation         *string           `json:"remediation"`
	Raw                 json.RawMessage   `json:"raw"`
}

// InventorySummary is the AI component inventory.
type InventorySummary struct {
	NodeCounts     map[string]int `json:"node_counts"`
	EdgeCount      int            `json:"edge_count"`
	Frameworks     []string       `json:"frameworks"`
	ModelProviders []string       `json:"model_providers"`
}

// ScanResult is a finished scan.
type ScanResult struct {
	SchemaVersion string           `json:"schema_version"`
	Job           ScanJob          `json:"job"`
	Provenance    Provenance       `json:"provenance"`
	Coverage      Coverage         `json:"coverage"`
	Summary       map[string]int   `json:"summary"`
	Findings      []ScanFinding    `json:"findings"`
	Inventory     InventorySummary `json:"inventory"`
	ResultSHA256  string           `json:"result_sha256"`
}

// Capabilities is what the service can do.
type Capabilities struct {
	NuGuardVersion  string         `json:"nuguard_version"`
	ServiceVersion  string         `json:"service_version"`
	Tools           []ToolVersion  `json:"tools"`
	ToolsAllowed    []string       `json:"tools_allowed"`
	NetworkDefault  bool           `json:"network_default"`
	LLMAvailable    bool           `json:"llm_available"`
	AllowedGitHosts []string       `json:"allowed_git_hosts"`
	Limits          map[string]any `json:"limits"`
}

// HealthStatus is the readiness answer: ok, or not_ready with the failing
// checks named.
type HealthStatus struct {
	Status  string   `json:"status"`
	Failing []string `json:"failing"`
}

// ParseResult decodes a stored result strictly enough to trust it: the
// schema version must be one this client reads, and every enum value must be
// known.
func ParseResult(b []byte) (ScanResult, error) {
	var r ScanResult
	if err := json.Unmarshal(b, &r); err != nil {
		return ScanResult{}, fmt.Errorf("nuguard: the scan result does not parse: %w", err)
	}
	if r.SchemaVersion != "" && r.SchemaVersion != "1.0" {
		return ScanResult{}, fmt.Errorf("nuguard: result schema_version %q is not 1.0", r.SchemaVersion)
	}
	return r, nil
}

func decodeEnum[T ~string](b []byte, dst *T, what string, known []T) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("nuguard: %s is not a string: %w", what, err)
	}
	for _, k := range known {
		if string(k) == s {
			*dst = k
			return nil
		}
	}
	return fmt.Errorf("nuguard: unknown %s %q", what, s)
}
