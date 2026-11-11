package scan

import "github.com/wanaware/vulnframework/internal/nuguardopt"

// Optional adapter capabilities. Each is an interface an adapter may also
// implement; an adapter that implements none behaves exactly as before
// (VM-NF-502). They exist for adapters that wrap several tools, such as a
// remote scanning service, and can lose some of them while still producing
// valid output (VM-F-211).

// GapError is an adapter error that knows its cause and whose problem it is
// (VM-F-214). Without one, the worker records any Run failure as
// execution_failed and any Normalize failure as normalise_failed, both owned
// by the platform; a remote tool's failure can be the repository's (too
// large) or a credential's, and routing it to the wrong owner sends the work
// to someone who cannot act.
//
// Detail is the error's text and becomes the gap's detail. It must never
// carry a credential or a URL with userinfo.
type GapError struct {
	Cause  string
	Owner  GapOwner
	Detail string
}

func (e *GapError) Error() string { return e.Detail }

// GapReporter is implemented by adapters that wrap several tools and can
// lose some of them while still producing valid output (VM-F-211).
//
// SubTools is pure, like Normalize: it reads the stored output and nothing
// else. It names each sub-tool that ran as "<adapter>/<tool>" and returns a
// gap, with the same naming, for each that did not. The worker records the
// names in ToolsOK and ToolsFailed, so a report says which of the adapter's
// tools was lost; any gap makes the scan partial.
type GapReporter interface {
	SubTools(out RawOutput) (ok []string, gaps []CoverageGap, err error)
}

// NotRequested is a tool a scan did not ask for, and why: neither ok nor
// failed. Its earlier findings keep their state and are flagged not
// re-observed (VM-F-160/161).
type NotRequested = nuguardopt.NotRequested

// NotRequestedReporter is implemented by an adapter a scan may switch off,
// or whose tools a scan may choose from (NuGuard). The worker asks it before
// running it and records what it names in ToolsNotRequested; an entry naming
// the adapter itself means the adapter is not run at all.
type NotRequestedReporter interface {
	NotRequested(opts RunOpts) []NotRequested
}

// InventoryReporter is implemented by adapters that describe what a
// repository contains as well as what is wrong with it: an AI component
// inventory is a signal, never a finding. Pure, like Normalize. Nil means the
// adapter's output carried no inventory, which a report shows as not
// measured, never as zero.
type InventoryReporter interface {
	Inventory(out RawOutput) *AIInventory
}

// AIInventory is what a scan found of a repository's AI use: agents, models,
// tools, prompts and the frameworks and providers they use. An inventory
// signal, not a finding: nothing here is a defect, and no count here is
// scored or routed.
type AIInventory struct {
	// Source names the producing tool and version, for example
	// "nuguard 0.9.15"; RulepackSHA256 and ImageDigest pin it further
	// (VM-F-202).
	Source         string `json:"source"`
	RulepackSHA256 string `json:"rulepack_sha256,omitempty"`
	ImageDigest    string `json:"image_digest,omitempty"`

	// NodeCounts counts components by type (AGENT, MODEL, TOOL, PROMPT,
	// MCP_SERVER, ...); EdgeCount counts the connections between them.
	NodeCounts     map[string]int `json:"node_counts"`
	EdgeCount      int            `json:"edge_count"`
	Frameworks     []string       `json:"frameworks"`
	ModelProviders []string       `json:"model_providers"`

	// PostureObservations counts posture observations by rule, when posture
	// was requested; nil when it was not, which is "not measured". Posture
	// observations describe the shape of the AI components (an agent with a
	// tool and no guardrail node, say) and do not tell safe code from
	// vulnerable code, so they are counted here and never become findings.
	PostureObservations map[string]int `json:"posture_observations,omitempty"`

	// NotFindings counts findings of kinds this framework takes from its own
	// tools instead (dependency, IaC, container), which were requested and
	// deliberately not turned into findings.
	NotFindings map[string]int `json:"not_findings,omitempty"`
}
