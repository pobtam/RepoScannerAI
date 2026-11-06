// Package api is the HTTP surface the interface reads (VM-AD §7.4, VM-UI §6.2).
//
// Three properties govern every type in this file.
//
// NO SECRET VALUE CROSSES THIS BOUNDARY (VM-UI-F-105). The finding record has
// no field capable of holding credential material and neither do these types:
// a secret finding carries its detector, its file and its credential CLASS,
// and never the credential. The structure is the guarantee; the response guard
// in api.go is the second line, and the test that walks every endpoint looking
// for a seeded credential is the third.
//
// EVERY HONESTY DISTINCTION SURVIVES. Absence is not zero: an EPSS nobody
// looked up is ABSENT from the response, not 0.0. Absence is not resolution: a
// finding the last run did not observe says so, with the reason it might be
// ambiguous. A number computed from part of its inputs carries its caveat
// inline, next to the number, because a caveat in a header does not survive
// being quoted into a ticket.
//
// NOTHING IS COMPUTED HERE THAT THE PIPELINE ALREADY COMPUTES. The interface
// must not be able to disagree with a report about the same run (VM-F-908), so
// the overview is a report, the counts are the report's counts, and the score
// decomposition is the scorer's.
package api

import (
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/store"
)

// Identity is the finding's names.
type Identity struct {
	PrimaryID string   `json:"primary_id,omitempty"`
	Aliases   []string `json:"aliases,omitempty"`
	RuleID    string   `json:"rule_id,omitempty"`
}

// Location is where the finding is, at the granularity the tools support.
type Location struct {
	Module      string `json:"module,omitempty"`
	ModuleMajor string `json:"module_major,omitempty"`
	Package     string `json:"package,omitempty"`
	Function    string `json:"function,omitempty"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
}

// Versions is the dependency version triple.
type Versions struct {
	Current    string `json:"current,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	Introduced string `json:"introduced,omitempty"`
}

// Classification is the risk assessment, with the tri-states intact.
//
// EPSS and KEV are POINTERS. A feed that did not answer leaves the field
// absent from the JSON, so a client cannot read "nobody looked" as "measured
// at zero" — which is the collapse that let a feed outage present as good news
// (OQ-AUDIT-01). Any client that renders a missing value as 0 is making that
// mistake visibly rather than silently.
type Classification struct {
	Severity string  `json:"severity"`
	CVSS     float64 `json:"cvss,omitempty"`

	EPSS     *float64   `json:"epss,omitempty"`
	EPSSAsOf *time.Time `json:"epss_as_of,omitempty"`
	KEV      *bool      `json:"kev,omitempty"`
	KEVAsOf  *time.Time `json:"kev_as_of,omitempty"`
	// ExploitIntelUnavailable names the exploitation inputs nothing answered
	// for this finding, in words, so a reader does not have to notice an
	// absent key.
	ExploitIntelUnavailable []string `json:"exploit_intel_unavailable,omitempty"`

	// Reachable is the tri-state as a STRING: "true", "false" or "unknown",
	// never a boolean (VM-F-243). A boolean cannot express the third state,
	// and the third state is the common one.
	Reachable      string `json:"reachable"`
	DepClass       string `json:"dep_class,omitempty"`
	Transitive     bool   `json:"transitive"`
	FirstPartyPath string `json:"first_party_path,omitempty"`
}

// ScoreInputs says how much of the scoring formula actually answered.
//
// A fraction, not a boolean: "complete" and "missing the two that matter most"
// are different claims (OQ-AUDIT-01).
type ScoreInputs struct {
	Available   int      `json:"available"`
	Declared    int      `json:"declared"`
	Unavailable []string `json:"unavailable,omitempty"`
	// Stale names inputs whose snapshot is older than the calibrated freshness
	// window. They were used — a stale answer beats silence — and the date
	// travels with them.
	Stale []string `json:"stale,omitempty"`
}

// ScoreBreakdown is the priority as an argument rather than an assertion
// (VM-UI-F-510).
type ScoreBreakdown struct {
	Score           float64     `json:"score"`
	Priority        string      `json:"priority"`
	Base            float64     `json:"base"`
	KEVBoost        float64     `json:"kev_boost"`
	EPSSBoost       float64     `json:"epss_boost"`
	ReachMultiplier float64     `json:"reach_multiplier"`
	DepMultiplier   float64     `json:"dep_multiplier"`
	TierMultiplier  float64     `json:"tier_multiplier"`
	FanOutMult      float64     `json:"fanout_multiplier"`
	Explain         []string    `json:"explain,omitempty"`
	Inputs          ScoreInputs `json:"inputs"`
	// Caveat travels with the number (OQ-AUDIT-01, OQ-P5-02).
	Caveat string `json:"caveat,omitempty"`
	// ThresholdsCalibrated is false while VM-OQ-06 is open. A priority band is
	// a measurement against a table nobody has reviewed, and the number must
	// say so wherever it is rendered.
	ThresholdsCalibrated bool `json:"thresholds_calibrated"`
	// Recomputed reports that this decomposition was computed now, from the
	// finding's current inputs, rather than read from the scoring pass.
	Recomputed bool `json:"recomputed"`
	// DisagreesWithStored is true when recomputing gives a different band from
	// the one stored on the finding — which means the calibration changed
	// since it was scored. Surfaced rather than hidden: quietly showing the
	// recomputed band would present a number as current that no pass produced,
	// and quietly showing the stored one would hide that the table moved.
	DisagreesWithStored bool   `json:"disagrees_with_stored,omitempty"`
	StoredPriority      string `json:"stored_priority,omitempty"`
}

// SLA is the finding's position against its remediation window.
type SLA struct {
	// Computed is explicit. A zero breach count with Computed false means
	// nobody looked, and a reader cannot tell that from "nothing is late"
	// (OQ-P7-03).
	Computed   bool   `json:"computed"`
	Status     string `json:"status,omitempty"`
	WindowDays int    `json:"window_days,omitempty"`
	BreachDays int    `json:"breach_days,omitempty"`
	AgeDays    int    `json:"age_days"`
	// WindowsProvisional is true while VM-OQ-02 is unanswered: the windows
	// have not been reviewed by anyone.
	WindowsProvisional bool   `json:"windows_provisional"`
	Caveat             string `json:"caveat,omitempty"`
}

// Observation is the honesty block: what this finding's presence does and does
// not tell you.
type Observation struct {
	FirstSeenRun string     `json:"first_seen_run,omitempty"`
	LastSeenRun  string     `json:"last_seen_run,omitempty"`
	FirstSeenAt  time.Time  `json:"first_seen_at"`
	LastSeenAt   time.Time  `json:"last_seen_at"`
	ResolvedAt   *time.Time `json:"resolved_at,omitempty"`

	// NotReobserved marks a finding the most recent applicable run did not see
	// while it remains unresolved (VM-F-161, VM-UI-F-422).
	NotReobserved bool `json:"not_reobserved"`
	// NotReobservedNote is the explanation the interface must show next to the
	// marker (VM-UI-F-423). Carried in the response rather than written into
	// the client, so the words cannot drift from the framework's own.
	NotReobservedNote string `json:"not_reobserved_note,omitempty"`
	// GapRepoScan names the run whose coverage gap explains the absence, where
	// there is one.
	GapRepoScan string `json:"gap_repo_scan,omitempty"`

	// ResidualPossible marks a VERIFIED finding whose granularity could have
	// covered more than one occurrence (OQ-AUDIT-02).
	ResidualPossible bool   `json:"residual_possible,omitempty"`
	ResidualDetail   string `json:"residual_detail,omitempty"`
}

// Refs are the links out.
type Refs struct {
	Ticket          string `json:"ticket,omitempty"`
	PullRequest     string `json:"pull_request,omitempty"`
	AdvisoryURL     string `json:"advisory_url,omitempty"`
	UpstreamFinding string `json:"upstream_finding,omitempty"`
}

// Provenance is which tools said so, and when.
type Provenance struct {
	Tools        []string          `json:"tools,omitempty"`
	ToolVersions map[string]string `json:"tool_versions,omitempty"`
}

// Triage is the model-produced narrative. Priority is absent by design: it is
// computed deterministically and never inferred (VM-F-305).
type Triage struct {
	Description            string     `json:"description,omitempty"`
	Impact                 string     `json:"impact,omitempty"`
	Remediation            string     `json:"remediation,omitempty"`
	FalsePositiveCandidate bool       `json:"false_positive_candidate"`
	FPReasoning            string     `json:"fp_reasoning,omitempty"`
	TriagedAt              *time.Time `json:"triaged_at,omitempty"`
	Model                  string     `json:"model,omitempty"`
}

// Finding is the record as the interface reads it.
type Finding struct {
	Fingerprint    string         `json:"fingerprint"`
	Repo           string         `json:"repo"`
	Category       string         `json:"category"`
	Identity       Identity       `json:"identity"`
	Location       Location       `json:"location"`
	Versions       Versions       `json:"versions,omitempty"`
	Classification Classification `json:"classification"`

	State      string `json:"state"`
	Partition  string `json:"partition"`
	Priority   string `json:"priority,omitempty"`
	ReasonCode string `json:"reason_code,omitempty"`
	// VerifiedReason attributes a verification: this framework's merge, an
	// upstream fix, or something outside it. A report that claimed credit for
	// a fix it did not make would be a false record (VM-AD §6.1.1).
	VerifiedReason string `json:"verified_reason,omitempty"`

	// CredentialType is the CLASS of credential for a secret finding. There is
	// no field for the credential itself, here or anywhere (VM-F-263,
	// VM-UI-F-105).
	CredentialType string `json:"credential_type,omitempty"`

	// Description says what the problem is, on every finding. It is the
	// reporting scanner's own text where one was recorded, and otherwise an
	// account built from the record's fields; DescriptionSource says which
	// (the tool names, or "derived"), so a reader never mistakes our wording
	// for the tool's. The AI triage narrative, when there is one, is separate.
	Description       string `json:"description,omitempty"`
	DescriptionSource string `json:"description_source,omitempty"`

	SLA         SLA               `json:"sla"`
	Observation Observation       `json:"observation"`
	Refs        Refs              `json:"refs"`
	Provenance  Provenance        `json:"provenance"`
	Triage      *Triage           `json:"triage,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`

	// Score is the decomposition, present on the detail view and on list rows
	// (the caveat has to travel with the priority wherever the priority goes).
	Score *ScoreBreakdown `json:"score,omitempty"`

	// Restricted marks a finding the caller may count but not open
	// (VM-UI-F-803/804). The record is present with its detail withheld rather
	// than absent, so an aggregate never silently excludes what the reader
	// cannot see.
	Restricted bool `json:"restricted,omitempty"`
}

// Corpus states which findings a count counts (VM-UI-F-417/418/419).
//
// In words, in the response. A count without its corpus is not a smaller
// truth, it is a different one, and the interface must not be able to imply a
// default.
type Corpus struct {
	Scope string `json:"scope"`
	// Description is the corpus in words: "unresolved findings across all
	// runs", not "open".
	Description string `json:"description"`
	// Excludes says what this corpus leaves out, and how many records that is.
	Excludes      string `json:"excludes,omitempty"`
	ExcludedCount int    `json:"excluded_count"`
	RunID         string `json:"run_id,omitempty"`
}

// FindingPage is one page of a filtered query.
type FindingPage struct {
	Findings []Finding `json:"findings"`
	// Matched, InCorpus and Total are separate figures, so filter and scope
	// are separately legible (VM-UI-F-419).
	Matched  int    `json:"matched"`
	InCorpus int    `json:"in_corpus"`
	Total    int    `json:"total"`
	Corpus   Corpus `json:"corpus"`
	// NextCursor is empty on the last page. Empty means END, not unknown.
	NextCursor string `json:"next_cursor,omitempty"`
	Sort       string `json:"sort"`
	Dir        string `json:"dir"`
	// RestrictedCount is how many of the matched findings the caller may count
	// but not open (VM-UI-F-804).
	RestrictedCount int `json:"restricted_count"`
}

// FacetOption is one filter option and what selecting it would return.
type FacetOption struct {
	Value string `json:"value"`
	Count int    `json:"count"`
	// Disabled is true for an option that would return nothing. Present and
	// disabled rather than hidden: an option that disappears looks like a
	// dimension that does not exist (VM-UI-F-408).
	Disabled bool `json:"disabled"`
}

// Facets is the per-dimension option counts under the current filter.
type Facets struct {
	Repos      []FacetOption `json:"repos"`
	Tiers      []FacetOption `json:"tiers"`
	Languages  []FacetOption `json:"languages"`
	Categories []FacetOption `json:"categories"`
	States     []FacetOption `json:"states"`
	Reasons    []FacetOption `json:"reasons"`
	Priorities []FacetOption `json:"priorities"`
	Severities []FacetOption `json:"severities"`
	Reachable  []FacetOption `json:"reachable"`
	DepClasses []FacetOption `json:"dep_classes"`
}

// Transition is one state change, with who made it and why.
type Transition struct {
	From        string    `json:"from,omitempty"`
	To          string    `json:"to"`
	Actor       string    `json:"actor"`
	Cause       string    `json:"cause,omitempty"`
	At          time.Time `json:"at"`
	ScanOutcome string    `json:"scan_outcome,omitempty"`
}

// RunObservation is one run's view of a finding, including the runs that did
// not see it (VM-UI-F-503).
type RunObservation struct {
	RunID    string    `json:"run_id"`
	Kind     string    `json:"kind"`
	At       time.Time `json:"at"`
	Observed bool      `json:"observed"`
	// Outcome is the repository's scan outcome in that run, so "not observed"
	// can be read against whether the scan even completed.
	Outcome string   `json:"outcome,omitempty"`
	Tools   []string `json:"tools,omitempty"`
	// Note explains an ambiguous absence in words.
	Note string `json:"note,omitempty"`
}

// Timeline is the finding's history.
type Timeline struct {
	Fingerprint  string           `json:"fingerprint"`
	Transitions  []Transition     `json:"transitions"`
	Observations []RunObservation `json:"observations"`
}

// Attempt is one remediation attempt (VM-UI-F-508).
type Attempt struct {
	Branch     string     `json:"branch"`
	FixGroupID string     `json:"fix_group_id,omitempty"`
	Repo       string     `json:"repo"`
	Number     int        `json:"number,omitempty"`
	URL        string     `json:"url,omitempty"`
	State      string     `json:"state"`
	Merged     bool       `json:"merged"`
	OpenedAt   time.Time  `json:"opened_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	Findings   []string   `json:"findings,omitempty"`
	TicketURL  string     `json:"ticket_url,omitempty"`
	// ConfirmedAt is when this pull request's state was last established by
	// authoritative word — a webhook delivery or a query (OQ-P12-01).
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
}

// RunSummary is a run as it appears in a list (VM-UI-F-301, VM-UI-F-311).
type RunSummary struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// StartedAt always travels with the identifier: the identifier is not
	// self-dating and the timestamp is not unique (VM-UI-F-207a).
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	Trigger      string     `json:"trigger,omitempty"`
	ScannerImage string     `json:"scanner_image,omitempty"`
	ReposPlanned int        `json:"repos_planned"`
	ReposScanned int        `json:"repos_scanned"`
	ReposFailed  int        `json:"repos_failed"`
	// Partial marks a run that did not cover its fleet. Every history and
	// trend view must mark it rather than showing an artificially low count
	// (VM-UI-F-307).
	Partial bool `json:"partial"`
	// PartialNote says so in words.
	PartialNote string `json:"partial_note,omitempty"`
}

// RunPage is a page of runs.
type RunPage struct {
	Runs       []RunSummary `json:"runs"`
	NextCursor string       `json:"next_cursor,omitempty"`
	Total      int          `json:"total"`
}

// Overview is a run's headline view (VM-UI-F-2xx).
//
// It carries a generated report rather than recomputing anything, so the
// interface and the report cannot disagree about the same run (VM-F-908).
type Overview struct {
	Run RunSummary `json:"run"`
	// Live says whether these figures are the state AS OF the run or the state
	// NOW (VM-UI-F-424). A run-scoped view showing live state has to say so.
	Live bool `json:"live"`
	// LiveNote explains it in words.
	LiveNote string `json:"live_note,omitempty"`
	// SnapshotID and ContentHash are present when the figures come from a
	// persisted, immutable report record (VM-ADR-15). Their absence is why
	// Live is true.
	SnapshotID  string `json:"snapshot_id,omitempty"`
	ContentHash string `json:"content_hash,omitempty"`

	Counts     reportCounts     `json:"counts"`
	Delta      reportDelta      `json:"delta"`
	Coverage   reportCoverage   `json:"coverage"`
	Provenance reportProvenance `json:"provenance"`
	// Caveats are the document-level qualifications. They are ALSO carried
	// inline wherever the figure they qualify appears; this copy is for a
	// reader who starts at the top.
	Caveats []string `json:"caveats,omitempty"`
}

// CoverageGap is one repository's missing or partial coverage (VM-UI-F-75x).
type CoverageGap struct {
	Repo    string    `json:"repo"`
	RunID   string    `json:"run_id"`
	RunAt   time.Time `json:"run_at"`
	Outcome string    `json:"outcome"`
	// Classification is total where no scanner produced results, partial where
	// some did (VM-F-211).
	Classification string `json:"classification"`
	Cause          string `json:"cause,omitempty"`
	Detail         string `json:"detail,omitempty"`
	// Owner routes the work: platform causes and repository causes go to
	// different people (VM-F-214).
	Owner string `json:"owner,omitempty"`
	// ToolsOK and ToolsFailed say which signals remain current and which were
	// lost, which is what makes a partial gap actionable (VM-F-212).
	ToolsOK     []string `json:"tools_ok,omitempty"`
	ToolsFailed []string `json:"tools_failed,omitempty"`

	// ConsecutiveRuns is how many runs in a row have produced no qualifying
	// scan, and LastQualifyingRun the last one that did. A single-run view
	// cannot distinguish a transient failure from a standing blind spot
	// (VM-UI-F-752).
	ConsecutiveRuns      int        `json:"consecutive_runs"`
	ConsecutiveDeferrals int        `json:"consecutive_deferrals"`
	LastQualifyingRun    string     `json:"last_qualifying_run,omitempty"`
	LastQualifyingAt     *time.Time `json:"last_qualifying_at,omitempty"`
	HoursWithoutData     float64    `json:"hours_without_data,omitempty"`
	// NeverScanned is the honest answer where there is no last qualifying run:
	// an age cannot be computed, and substituting zero would read as fresh.
	NeverScanned bool `json:"never_scanned"`

	// NotReobserved is how many findings this gap leaves unaccounted for, with
	// the query that lists them.
	NotReobserved int    `json:"not_reobserved"`
	FindingsQuery string `json:"findings_query,omitempty"`
}

// CoverageView is the gaps page (VM-UI-F-75x).
type CoverageView struct {
	RunID       string                `json:"run_id,omitempty"`
	Gaps        []CoverageGap         `json:"gaps"`
	InScope     int                   `json:"in_scope"`
	Complete    int                   `json:"complete"`
	Percent     float64               `json:"percent"`
	Staleness   store.StalenessReport `json:"staleness"`
	Escalations []store.Escalation    `json:"escalations,omitempty"`
	// Warning is the sentence this view exists to say: a failed scan and a
	// clean scan are indistinguishable in every aggregate (VM-UI-F-757).
	Warning string `json:"warning"`
	// History is the per-repository outcome across recent runs, so coverage
	// decay is visible without reading individual gaps (VM-UI-F-756).
	History []RepoCoverageHistory `json:"history,omitempty"`
}

// RepoCoverageHistory is one repository's recent scan outcomes, newest first.
type RepoCoverageHistory struct {
	Repo     string   `json:"repo"`
	Outcomes []string `json:"outcomes"`
	Runs     []string `json:"runs"`
}

// RepoSummary is a repository in the index.
type RepoSummary struct {
	Name           string   `json:"name"`
	Tier           int      `json:"tier"`
	Languages      []string `json:"languages"`
	HasTestSuite   bool     `json:"has_test_suite"`
	ModuleTopology string   `json:"module_topology,omitempty"`
	Codeowners     []string `json:"codeowners,omitempty"`
	Archived       bool     `json:"archived,omitempty"`

	OpenFindings   int            `json:"open_findings"`
	BySeverity     map[string]int `json:"by_severity,omitempty"`
	ByCategory     map[string]int `json:"by_category,omitempty"`
	SLABreached    int            `json:"sla_breached"`
	NotReobserved  int            `json:"not_reobserved"`
	LastScannedRun string         `json:"last_scanned_run,omitempty"`
	LastScannedAt  *time.Time     `json:"last_scanned_at,omitempty"`
	LastOutcome    string         `json:"last_outcome,omitempty"`
	// LastCommitSHA is the commit the latest scan read, where it was
	// recorded.
	LastCommitSHA string `json:"last_commit_sha,omitempty"`
	// NoTestSuiteNote states what the absence constrains, because it decides
	// what the framework may do there (VM-UI-F-607).
	NoTestSuiteNote string `json:"no_test_suite_note,omitempty"`
}

// RepoDetail is the repository view (VM-UI-F-6xx).
type RepoDetail struct {
	Repo RepoSummary `json:"repo"`
	// SLAWindows are the windows in force, stated rather than left implicit
	// (VM-UI-F-612).
	SLAWindows map[int]map[string]string `json:"sla_windows"`
	// SLAWindowsProvisional is true while nobody has reviewed them.
	SLAWindowsProvisional bool `json:"sla_windows_provisional"`

	Dependencies []Dependency `json:"dependencies,omitempty"`
	OpenPRs      []Attempt    `json:"open_prs,omitempty"`
	// Consumers lists the repositories depending on a first-party module this
	// repository owns (VM-UI-F-606).
	Consumers []Consumer            `json:"consumers,omitempty"`
	Coverage  []RepoCoverageHistory `json:"coverage,omitempty"`

	// AIComponents is what the latest scan found of the repository's AI
	// use. Always present, because "not measured" must be said, not implied
	// by absence or rendered as zero (OQ-AUDIT-01's discipline).
	AIComponents AIComponents `json:"ai_components"`
}

// AIComponents is an AI component inventory: an inventory signal, never
// findings. Nothing here is a defect, and nothing here is scored or routed.
type AIComponents struct {
	// Measured is false where the latest scan reported no inventory: the
	// adapter that produces one (NuGuard) is not configured, or did not run.
	Measured bool   `json:"measured"`
	Note     string `json:"note"`
	RunID    string `json:"run_id,omitempty"`

	// Source names the producing tool and version; RulepackSHA256 and
	// ImageDigest pin it further.
	Source         string         `json:"source,omitempty"`
	RulepackSHA256 string         `json:"rulepack_sha256,omitempty"`
	ImageDigest    string         `json:"image_digest,omitempty"`
	NodeCounts     map[string]int `json:"node_counts,omitempty"`
	EdgeCount      *int           `json:"edge_count,omitempty"`
	Frameworks     []string       `json:"frameworks,omitempty"`
	ModelProviders []string       `json:"model_providers,omitempty"`
	// PostureObservations counts posture observations by rule, where they
	// were requested. Not findings: they describe the components' shape and
	// do not tell safe code from vulnerable code.
	PostureObservations map[string]int `json:"posture_observations,omitempty"`
}

// Dependency is one module in a repository's manifest.
type Dependency struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Direct   bool   `json:"direct"`
	Replaced bool   `json:"replaced"`
}

// Consumer is a repository depending on a first-party module.
type Consumer struct {
	Repo    string `json:"repo"`
	Version string `json:"version"`
	Tier    int    `json:"tier"`
	// Reachable is the tri-state: a consumer that reaches the vulnerable code
	// is a different thing from one that merely depends on the module, and
	// from one nobody has determined (VM-UI-F-707).
	Reachable string `json:"reachable"`
	Replaced  bool   `json:"replaced,omitempty"`
	Excluded  bool   `json:"excluded,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// Wave is a first-party propagation in flight (VM-UI-F-7xx).
type Wave struct {
	Module        string `json:"module"`
	OwnerRepo     string `json:"owner_repo"`
	UpstreamFP    string `json:"upstream_finding,omitempty"`
	UpstreamState string `json:"upstream_state,omitempty"`
	// Wave1PR and its age: a stalled upstream fix blocking twelve consumers is
	// a distinct escalation from twelve independent findings (VM-UI-F-703).
	Wave1PR       string     `json:"wave1_pr,omitempty"`
	Wave1PRAt     *time.Time `json:"wave1_pr_at,omitempty"`
	Wave1AgeHours float64    `json:"wave1_age_hours,omitempty"`
	// Trigger is what clears wave two — a merge or a tag — because it decides
	// whether merging is sufficient (VM-UI-F-705).
	Trigger string `json:"trigger"`
	// DependCount and ReachCount are separate figures, adjacent, so neither
	// can be quoted alone (VM-UI-F-708).
	DependCount  int        `json:"depend_count"`
	ReachCount   int        `json:"reach_count"`
	UnknownCount int        `json:"unknown_count"`
	Consumers    []Consumer `json:"consumers"`
	// VersionSpread is the versions consumers are on, since divergence may
	// prevent a single-target wave (VM-UI-F-712).
	VersionSpread map[string]int `json:"version_spread,omitempty"`
	// Steps enumerates what clears the wave, in order (VM-UI-F-709).
	Steps []string `json:"steps"`
}

// ReportSummary is an issued report (VM-UI-F-1106).
type ReportSummary struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Repo        string    `json:"repo,omitempty"`
	Template    string    `json:"template"`
	AnchorRunID string    `json:"anchor_run_id"`
	IssuedAt    time.Time `json:"issued_at"`
	IssuedBy    string    `json:"issued_by,omitempty"`
	ContentHash string    `json:"content_hash"`
	// Supersedes names the report this one replaces, and SupersededBy the one
	// that replaced this.
	//
	// Both directions, because VM-UI-F-1108 requires BOTH reports to remain
	// visible with the relationship stated — and a reader arriving at the
	// older one is the reader who most needs to be told. Someone quoting a
	// figure from a report that has since been corrected will have the
	// superseded identifier in their hand, not the replacement's.
	//
	// SupersededBy is derived from the lineage rather than stored, so it
	// cannot disagree with Supersedes.
	Supersedes   string `json:"supersedes,omitempty"`
	SupersededBy string `json:"superseded_by,omitempty"`
	Redacted     bool   `json:"redacted,omitempty"`
	// WithheldCount is shown wherever a redacted report is (VM-UI-F-1109).
	WithheldCount int `json:"withheld_count"`
}

// TrendPoint is one run's value in a trend series.
type TrendPoint struct {
	RunID string    `json:"run_id"`
	At    time.Time `json:"at"`
	Value float64   `json:"value"`
	// Partial marks a run that did not cover the fleet, so a dip caused by
	// half the fleet failing to scan is not read as remediation working
	// (VM-UI-F-307).
	Partial bool `json:"partial"`
	// ScannerChanged marks a run whose scanner image differs from the previous
	// one, so a step change is attributable (VM-UI-F-306).
	ScannerChanged bool `json:"scanner_changed"`
	// Live marks a point computed from the store NOW rather than read from the
	// run's immutable snapshot.
	//
	// The distinction is the whole of VM-UI-F-102 in one boolean. A series
	// regenerated from today's state shows every past run as it looks now, so
	// a finding detected in June and fixed in August is absent from June's
	// point — and the line slopes downwards whatever actually happened.
	Live         bool   `json:"live"`
	ScannerImage string `json:"scanner_image,omitempty"`
}

// TrendSeries is one metric over runs of ONE kind (VM-UI-F-310).
type TrendSeries struct {
	Metric string       `json:"metric"`
	Kind   string       `json:"kind"`
	Points []TrendPoint `json:"points"`
	// Note states the limitation a chart invites the reader to forget.
	Note string `json:"note,omitempty"`
}

// Comparison is two runs compared (VM-UI-F-305).
type Comparison struct {
	A RunSummary `json:"a"`
	B RunSummary `json:"b"`
	// Comparable is false where the runs are of different kinds: a sweep
	// against a single-repository rescan produces a figure that looks like a
	// collapse (VM-UI-F-309).
	Comparable bool   `json:"comparable"`
	Note       string `json:"note,omitempty"`

	Appearing    []Finding     `json:"appearing"`
	Disappearing []Finding     `json:"disappearing"`
	Changed      []StateChange `json:"changed"`
}

// StateChange is one finding's state difference between two runs.
type StateChange struct {
	Finding Finding `json:"finding"`
	From    string  `json:"from"`
	To      string  `json:"to"`
}

// Error is the API's error shape. Always both: what failed and what the caller
// can do about it (VM-UI-F-903).
type Error struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
	// Remedy is what to do. An error message without one makes the reader
	// guess, and they will guess that the system is broken.
	Remedy string `json:"remedy,omitempty"`
}

// Health is the liveness surface, including what is degraded.
type Health struct {
	OK      bool   `json:"ok"`
	Backend string `json:"backend"`
	// Degraded names capabilities that are absent in this deployment, so the
	// interface can say so rather than rendering their absence as zero.
	Degraded []string `json:"degraded,omitempty"`
	Demo     bool     `json:"demo"`
	// ScanRequests says whether scans can be requested from the interface:
	// whether a scan worker drains the queue in this deployment.
	ScanRequests bool `json:"scan_requests"`
}

// The overview carries the report package's own structures rather than
// restating them. Restating would create a second definition of "the counts",
// and the interface could then disagree with the report about the same run
// (VM-F-908).
type (
	reportCounts     = report.Counts
	reportDelta      = report.Delta
	reportCoverage   = report.Coverage
	reportProvenance = report.Provenance
)

// stateOf renders a finding's resolution partition in words.
func partitionOf(s model.State) string { return string(model.PartitionOf(s)) }

// --- no nulls where the interface iterates ----------------------------------
//
// A nil Go slice marshals to JSON `null`, and a client that iterates it
// crashes. The generated TypeScript for a required array field says
// `string[]`, not `string[] | null`, so a null would type-check on the client
// and fail at runtime — in the one place the generated types were supposed to
// make safe.
//
// The rule at this boundary: a field the interface ITERATES is always an array
// or an object, even when empty. A field that may be genuinely absent is
// `omitempty` and is then an ABSENT KEY, never a null. Absence is a missing
// key; emptiness is an empty collection; and neither is a zero.

func emptyIfNil[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}

func emptyMapIfNil[K comparable, V any](in map[K]V) map[K]V {
	if in == nil {
		return map[K]V{}
	}
	return in
}
