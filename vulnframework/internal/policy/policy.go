// Package policy is the deterministic decision engine (VM-AD §10, VM-F-401).
//
// Every decision to remediate, to open a ticket, or to take no action is made
// here, in code, from a version-controlled table — never by inference. The
// engine is a pure function with no I/O, which is what makes the whole decision
// space testable rather than merely sampled.
//
// Two properties are structural rather than conventional:
//
// TOTALITY. Every input in the declared domain maps to exactly one outcome. An
// input the table does not cover is a loud error naming what was unmatched, not
// a fall-through to open_ticket. A decision table with a hole that quietly files
// tickets looks like it is working, and the gap is discovered only when someone
// asks why a class of findings was never remediated.
//
// UNTRUSTED TRIAGE. The triage narrative is model output, and model output is
// data. The engine never reads it. Routing is determined by category, state,
// class, and the table — all of which are established by deterministic code
// before triage runs — so a narrative that argues for a different outcome, or
// that carries an injected instruction, cannot change one.
package policy

import (
	"fmt"
	"sort"

	"github.com/wanaware/vulnframework/internal/model"
)

// Outcome is the closed enumeration of policy decisions (VM-F-404).
type Outcome string

const (
	AutoRemediate  Outcome = "auto_remediate"
	OpenTicket     Outcome = "open_ticket"
	EscalateP0     Outcome = "escalate_p0"
	SkipInProgress Outcome = "skip_in_progress"
	SkipDeclined   Outcome = "skip_declined"
	SkipSuppressed Outcome = "skip_suppressed"
	DeferUpstream  Outcome = "defer_upstream"
)

// AllOutcomes is the closed enumeration (VM-F-404).
var AllOutcomes = []Outcome{
	AutoRemediate, OpenTicket, EscalateP0,
	SkipInProgress, SkipDeclined, SkipSuppressed, DeferUpstream,
}

// Valid reports whether o is a member of the closed enumeration.
func (o Outcome) Valid() bool {
	for _, v := range AllOutcomes {
		if v == o {
			return true
		}
	}
	return false
}

// Class is the remediation class of a finding — what kind of change fixing it
// would be. It is derived deterministically from the finding, never from triage.
type Class string

const (
	ClassDependencyPatch Class = "dependency_patch"
	ClassDependencyMinor Class = "dependency_minor"
	ClassDependencyMajor Class = "dependency_major"
	ClassCodeFix         Class = "code_fix"
	ClassConfigFix       Class = "config_fix"
	// ClassSecret never reaches the table: secrets short-circuit first.
	ClassSecret Class = "secret"
)

// Classes are the classes the table must cover, for every tier and language.
// ClassSecret is excluded: it is decided before the table is consulted.
var Classes = []Class{
	ClassDependencyPatch, ClassDependencyMinor, ClassDependencyMajor,
	ClassCodeFix, ClassConfigFix,
}

// Language is the repository language the table is keyed on.
type Language string

const (
	LangGo         Language = "go"
	LangJavaScript Language = "javascript"
)

// Languages are the languages the table must cover.
var Languages = []Language{LangGo, LangJavaScript}

// Tiers are the tiers the table must cover.
var Tiers = []int{1, 2, 3}

// Repo is the repository context a decision needs.
type Repo struct {
	Name         string
	Tier         int
	Language     Language
	HasTestSuite bool
}

// StoreView supplies existing state the engine must respect (VM-AD §10).
//
// It is an interface so the engine stays a pure function of its inputs: nothing
// here reaches a database, and every test states the world explicitly rather
// than arranging one.
type StoreView interface {
	// HasOpenPullRequest reports an in-flight remediation for this finding.
	HasOpenPullRequest(fingerprint string) bool
	// IsFirstPartyOwner reports whether this repository owns the first-party
	// module the finding is in.
	IsFirstPartyOwner(repo, modulePath string) bool
}

// Decision is a routed finding, with the rule that produced it (VM-F-405).
type Decision struct {
	Outcome Outcome `json:"outcome"`
	// Rule is the index of the rule that decided, in VM-AD §10's evaluation
	// order. Recorded so every decision is auditable against the table rather
	// than merely asserted (VM-F-405).
	Rule     int              `json:"rule"`
	RuleName string           `json:"rule_name"`
	Reason   model.ReasonCode `json:"reason_code,omitempty"`
	Explain  string           `json:"explain"`
}

// ErrUnmatched is returned when an input falls outside the declared domain.
//
// It exists so a hole in the table fails loudly. Returning open_ticket instead
// would be the worst available behaviour: the run appears to work, tickets
// appear, and nobody discovers that a whole class of findings was never
// considered for remediation.
type ErrUnmatched struct {
	Tier     int
	Language Language
	Class    Class
	State    model.State
	Detail   string
}

func (e *ErrUnmatched) Error() string {
	return fmt.Sprintf(
		"policy: no rule matched (tier=%d language=%q class=%q state=%q): %s; "+
			"the decision table must be total over its declared domain — a missing entry is never an implicit open_ticket",
		e.Tier, e.Language, e.Class, e.State, e.Detail)
}

// Engine evaluates findings against a policy table.
type Engine struct {
	Config Config
}

// New builds an engine.
func New(c Config) *Engine { return &Engine{Config: c} }

// Evaluate routes one finding (VM-AD §10).
//
// Evaluation order is fixed and short-circuits. The order is the specification's
// and the reasons are load-bearing:
//
//  1. secret            — before anything else, and not overridable
//  2. in progress       — do not open a second pull request (VM-F-155)
//  3. declined          — never re-remediate without a human (VM-F-154)
//  4. suppressed        — a human decided this is not real
//  5. awaiting a human  — a nomination is already queued for decision
//  6. upstream          — fix shared modules once, upstream (VM-ADR-07)
//  7. the table         — tier × language × class
//  8. test-suite gate   — no agentic code fix without a way to verify it
//
// The triage narrative is not consulted at any step.
func (e *Engine) Evaluate(f model.Finding, r Repo, view StoreView) (Decision, error) {
	if view == nil {
		view = emptyView{}
	}
	class := ClassOf(f)

	// Rule 1 — secrets escalate, always, and no configuration can change it
	// (VM-F-407, VM-F-851). This is first so that no later rule, no table entry
	// and no triage narrative can reach a leaked credential. A secret in a
	// tier-3 repository with a reachability of false and a triage verdict
	// arguing it is a test fixture still escalates.
	if f.Category == model.CategorySecret {
		return Decision{
			Outcome: EscalateP0, Rule: 1, RuleName: "secret",
			Explain: "category=secret: escalates to P0; not overridable by configuration (VM-F-407, VM-F-851)",
		}, nil
	}

	// Rule 2 — work already in flight. A second attempt produces a conflicting
	// branch and a duplicate pull request (VM-F-155).
	switch f.State {
	case model.PROpen, model.AutoRemediating:
		return Decision{
			Outcome: SkipInProgress, Rule: 2, RuleName: "in_progress",
			Explain: fmt.Sprintf("state=%s: remediation already in flight (VM-F-155)", f.State),
		}, nil
	}
	if view.HasOpenPullRequest(f.Fingerprint) {
		return Decision{
			Outcome: SkipInProgress, Rule: 2, RuleName: "in_progress",
			Explain: "an open pull request already addresses this finding (VM-F-155)",
		}, nil
	}

	// Rule 3 — a reviewer rejected an automated fix. It is never re-remediated
	// automatically, in any subsequent run, absent an explicit human reset
	// (VM-F-154). The vulnerability is still real, which is why DECLINED stays
	// in the unresolved partition; what the decline removes is the framework's
	// licence to try again.
	if f.State == model.Declined {
		return Decision{
			Outcome: SkipDeclined, Rule: 3, RuleName: "declined",
			Reason:  model.ReasonDeclined,
			Explain: "state=DECLINED: never automatically re-remediated; requires an explicit human reset (VM-F-154)",
		}, nil
	}

	// Rule 4 — a human judged this not real.
	if f.State == model.Suppressed {
		return Decision{
			Outcome: SkipSuppressed, Rule: 4, RuleName: "suppressed",
			Explain: "state=SUPPRESSED: a human decided this finding is not real",
		}, nil
	}

	// Rule 5 — a false-positive nomination is awaiting a human decision.
	//
	// VM-AD §10 does not list this case; see BUILD-LOG assumption A22. It is
	// treated as in-progress rather than ticketed, because a ticket for a
	// finding already queued for a decision is duplicate work aimed at the same
	// person.
	if f.State == model.FPCandidate {
		return Decision{
			Outcome: SkipInProgress, Rule: 5, RuleName: "awaiting_human",
			Reason:  model.ReasonSuppressionProposed,
			Explain: "state=FALSE_POSITIVE_CANDIDATE: a suppression nomination is awaiting human decision (VM-F-307)",
		}, nil
	}
	if f.State == model.WontFix {
		return Decision{
			Outcome: SkipSuppressed, Rule: 5, RuleName: "accepted_risk",
			Explain: "state=WONT_FIX: risk consciously accepted; not re-remediated without a human",
		}, nil
	}

	// Rule 6 — first-party modules are fixed once, upstream (VM-ADR-07). A
	// consumer defers; the owner remediates normally. Fixing a shared module's
	// vulnerability independently in each consumer produces divergent manifests
	// that are reverted on the next tidy.
	if fp := f.Classification.FirstPartyPath; fp != nil && *fp != "" {
		if !view.IsFirstPartyOwner(r.Name, *fp) {
			return Decision{
				Outcome: DeferUpstream, Rule: 6, RuleName: "upstream",
				Reason: model.ReasonBlockedUpstreamFirstParty,
				Explain: fmt.Sprintf(
					"first_party_path=%s and %s is not its owner: defer to the upstream fix (VM-ADR-07, VM-F-605)", *fp, r.Name),
			}, nil
		}
	}

	// Rules 7 and 8 consult the table. Everything before this point is
	// unconditional; everything after is configuration.
	if !e.Config.KnownState(f.State) {
		return Decision{}, &ErrUnmatched{
			Tier: r.Tier, Language: r.Language, Class: class, State: f.State,
			Detail: "state is outside the domain the table covers; policy runs after triage, so a finding in this state has reached it out of sequence",
		}
	}

	action, err := e.Config.Action(r.Tier, r.Language, class)
	if err != nil {
		return Decision{}, err
	}

	switch action {
	case ActionTicket:
		reason := model.ReasonPolicyIssueOnly
		if class == ClassDependencyMajor {
			// Major bumps are never auto-remediated by default (VM-F-406).
			reason = model.ReasonMajorBumpPolicy
		}
		return Decision{
			Outcome: OpenTicket, Rule: 7, RuleName: "table",
			Reason:  reason,
			Explain: fmt.Sprintf("tier %d / %s / %s: policy says ticket", r.Tier, r.Language, class),
		}, nil

	case ActionRequireTestSuite:
		// Rule 8 — an agentic code fix without a test suite cannot be verified,
		// and an unverifiable change to first-party code is not one to make
		// automatically (VM-F-524).
		if !r.HasTestSuite {
			return Decision{
				Outcome: OpenTicket, Rule: 8, RuleName: "no_test_coverage",
				Reason: model.ReasonNoTestCoverage,
				Explain: fmt.Sprintf("tier %d / %s / %s: auto-remediation requires a test suite, and %s has none (VM-F-524)",
					r.Tier, r.Language, class, r.Name),
			}, nil
		}
		return Decision{
			Outcome: AutoRemediate, Rule: 8, RuleName: "table_with_test_suite",
			Explain: fmt.Sprintf("tier %d / %s / %s: auto-remediate, test suite present", r.Tier, r.Language, class),
		}, nil

	case ActionAuto:
		return Decision{
			Outcome: AutoRemediate, Rule: 7, RuleName: "table",
			Explain: fmt.Sprintf("tier %d / %s / %s: policy says auto", r.Tier, r.Language, class),
		}, nil
	}

	// Unreachable while Config.Action validates its return, and deliberately an
	// error rather than a default.
	return Decision{}, &ErrUnmatched{
		Tier: r.Tier, Language: r.Language, Class: class, State: f.State,
		Detail: fmt.Sprintf("table action %q is not a known action", action),
	}
}

// ClassOf derives a finding's remediation class deterministically.
//
// It reads the finding's category and version delta — both established by
// scanning and normalisation — and never the triage narrative.
func ClassOf(f model.Finding) Class {
	switch f.Category {
	case model.CategorySecret:
		return ClassSecret
	case model.CategoryCode:
		return ClassCodeFix
	case model.CategoryConfig:
		return ClassConfigFix
	case model.CategoryDependency:
		return dependencyClass(f.Versions.Current, f.Versions.Fixed)
	default:
		return ClassCodeFix
	}
}

// dependencyClass compares current and fixed versions.
//
// An unparseable or absent pair is treated as a major bump — the most
// conservative class, which routes to a ticket rather than to an automatic
// change. Guessing "patch" because the versions could not be read would
// auto-merge an upgrade nobody has characterised.
func dependencyClass(current, fixed string) Class {
	cur, okCur := parseVersion(current)
	fix, okFix := parseVersion(fixed)
	if !okCur || !okFix {
		return ClassDependencyMajor
	}
	switch {
	case fix.major != cur.major:
		return ClassDependencyMajor
	case fix.minor != cur.minor:
		return ClassDependencyMinor
	default:
		return ClassDependencyPatch
	}
}

// emptyView is the default StoreView: it knows nothing, which is the safe
// default for both of its questions.
type emptyView struct{}

func (emptyView) HasOpenPullRequest(string) bool        { return false }
func (emptyView) IsFirstPartyOwner(string, string) bool { return false }

// Domain is the declared input domain the table must be total over.
//
// It is exported so the totality test enumerates exactly what the engine claims
// to cover, rather than a list maintained separately that could drift from it.
type Domain struct {
	Tiers      []int
	Languages  []Language
	Classes    []Class
	States     []model.State
	Reachable  []model.Reachable
	Severities []model.Severity
	Categories []model.Category
	FirstParty []bool
	TestSuite  []bool
}

// DeclaredDomain returns the input domain the engine is total over.
func DeclaredDomain() Domain {
	states := make([]model.State, 0, len(model.AllStates))
	for _, s := range model.AllStates {
		// DETECTED is excluded: policy runs after triage, so a finding in
		// DETECTED has reached the engine out of sequence. That is a
		// sequencing bug and the engine reports it rather than routing it.
		if s == model.Detected {
			continue
		}
		states = append(states, s)
	}
	sort.Slice(states, func(i, j int) bool { return states[i] < states[j] })

	return Domain{
		Tiers:      Tiers,
		Languages:  Languages,
		Classes:    append([]Class{ClassSecret}, Classes...),
		States:     states,
		Reachable:  model.AllReachable,
		Severities: model.AllSeverities,
		Categories: model.AllCategories,
		FirstParty: []bool{false, true},
		TestSuite:  []bool{false, true},
	}
}
