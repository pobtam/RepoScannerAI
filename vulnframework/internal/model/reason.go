package model

import "fmt"

// ReasonCode explains why a finding is not fixed. Closed enumeration
// (VM-F-157, VM-FR §5.3 normative list).
type ReasonCode string

const (
	ReasonNoUpstreamFix             ReasonCode = "NO_UPSTREAM_FIX"
	ReasonBlockedUpstreamFirstParty ReasonCode = "BLOCKED_UPSTREAM_FIRST_PARTY"
	ReasonMajorBumpPolicy           ReasonCode = "MAJOR_BUMP_POLICY"
	ReasonBuildFailed               ReasonCode = "BUILD_FAILED"
	ReasonTestsFailed               ReasonCode = "TESTS_FAILED"
	ReasonNoTestCoverage            ReasonCode = "NO_TEST_COVERAGE"
	ReasonNeedsHumanSecret          ReasonCode = "NEEDS_HUMAN_SECRET"
	ReasonSuppressionProposed       ReasonCode = "SUPPRESSION_PROPOSED"
	ReasonDeclined                  ReasonCode = "DECLINED"
	ReasonAgentGaveUp               ReasonCode = "AGENT_GAVE_UP"
	ReasonBudgetExhausted           ReasonCode = "BUDGET_EXHAUSTED"
	ReasonPolicyIssueOnly           ReasonCode = "POLICY_ISSUE_ONLY"
)

// AllReasonCodes is the closed enumeration, in the order given by VM-FR §5.3.
var AllReasonCodes = []ReasonCode{
	ReasonNoUpstreamFix,
	ReasonBlockedUpstreamFirstParty,
	ReasonMajorBumpPolicy,
	ReasonBuildFailed,
	ReasonTestsFailed,
	ReasonNoTestCoverage,
	ReasonNeedsHumanSecret,
	ReasonSuppressionProposed,
	ReasonDeclined,
	ReasonAgentGaveUp,
	ReasonBudgetExhausted,
	ReasonPolicyIssueOnly,
}

var reasonCodeSet = func() map[ReasonCode]bool {
	m := make(map[ReasonCode]bool, len(AllReasonCodes))
	for _, r := range AllReasonCodes {
		m[r] = true
	}
	return m
}()

// Valid reports whether r is a member of the closed enumeration.
func (r ReasonCode) Valid() bool { return reasonCodeSet[r] }

func (r ReasonCode) String() string { return string(r) }

// PausesSLA reports whether this reason code stops the SLA clock (VM-NF-304).
//
// Only NO_UPSTREAM_FIX pauses. A paused finding can never register as breached
// (VM-F-909): breaching a window you have no means to meet produces a
// permanently red row, and permanently red rows get ignored — including when
// they later become actionable.
func (r ReasonCode) PausesSLA() bool { return r == ReasonNoUpstreamFix }

// ValidateReasonCode returns an error unless r is a member of the enumeration.
// The empty reason code is invalid; callers holding "no reason" should use a
// nil *ReasonCode rather than the empty string.
func ValidateReasonCode(r ReasonCode) error {
	if !r.Valid() {
		return fmt.Errorf("invalid reason code %q", r)
	}
	return nil
}
