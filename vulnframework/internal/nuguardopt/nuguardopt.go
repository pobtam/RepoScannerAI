// Package nuguardopt resolves which NuGuard options a repository's scan uses.
//
// Security owners choose NuGuard's settings at three levels (fleet,
// repository, scan request) and the operator sets a ceiling on the scan
// worker's command line. ResolveNuGuardOptions is the one function that
// turns those into the options a scan actually runs with. The scan worker
// calls it for every repository it scans, and the API's preview calls it to
// say what a scan would use, so the two cannot disagree (VM-UI-F-1204).
//
// Pure: no I/O, no clock, no credentials. Nothing here is secret.
package nuguardopt

import (
	"fmt"
	"sort"
	"strings"
)

// Selectable are the NuGuard tools a user may choose: NuGuard's AI code
// rules. Dependency, IaC, container and supply-chain scanning stay with this
// project's own adapters, and the adapter maps only code findings; offering
// osv, grype, trivy, checkov or supply-chain is a separate decision
// (NOW-VS-LATER.md).
var Selectable = []string{"nga-rules", "atlas", "semgrep"}

// IsSelectable reports whether a user may choose tool.
func IsSelectable(tool string) bool {
	for _, t := range Selectable {
		if t == tool {
			return true
		}
	}
	return false
}

// Fleet is the fleet-wide setting (nuguard_settings).
type Fleet struct {
	Enabled        bool     `json:"enabled"`
	Tools          []string `json:"tools"`
	IncludePosture bool     `json:"include_posture"`
	TimeoutS       int      `json:"timeout_s"`
}

// RepoMode is a repository override's mode.
type RepoMode string

const (
	RepoInherit RepoMode = "inherit"
	RepoOn      RepoMode = "on"
	RepoOff     RepoMode = "off"
)

// RepoOverride is one repository's override (nuguard_repo_overrides). Tools
// nil and IncludePosture nil inherit.
type RepoOverride struct {
	Mode           RepoMode `json:"mode"`
	Tools          []string `json:"tools,omitempty"`
	IncludePosture *bool    `json:"include_posture,omitempty"`
}

// RequestMode is a scan request's NuGuard choice.
type RequestMode string

const (
	RequestDefault RequestMode = "default"
	RequestOn      RequestMode = "on"
	RequestOff     RequestMode = "off"
)

// Request is what a scan request asked for (scan_requests.nuguard). A nil
// *Request is "nothing asked", exactly today's behaviour.
type Request struct {
	Mode           RequestMode `json:"mode"`
	Tools          []string    `json:"tools,omitempty"`
	IncludePosture *bool       `json:"include_posture,omitempty"`
	// KeepSBOM asks for NuGuard's AI-SBOM to be stored with the scan.
	KeepSBOM bool `json:"keep_sbom,omitempty"`
}

// Ceiling is what the operator allows, from the scan worker's flags, and
// the defaults for a fleet never configured in the interface.
type Ceiling struct {
	// Configured is false when the worker has no -nuguard-url: NuGuard is
	// unavailable everywhere.
	Configured   bool     `json:"configured"`
	AllowTools   []string `json:"allow_tools"`
	AllowPosture bool     `json:"allow_posture"`
	MaxTimeoutS  int      `json:"max_timeout_s"`
	// ServiceTools are the tools the service itself allows (capabilities);
	// nil when the worker could not ask.
	ServiceTools []string `json:"service_tools,omitempty"`
	// Defaults are -nuguard-tools, -nuguard-include-posture and
	// -nuguard-timeout: what a fleet never configured in the interface uses.
	Defaults Fleet `json:"defaults"`
}

// ClipNote records a value the ceiling did not allow, and what was used.
type ClipNote struct {
	Field string `json:"field"`
	Asked string `json:"asked"`
	Used  string `json:"used"`
	Why   string `json:"why"`
}

// NotRequested is a tool the scan did not ask for, and why. Neither ok nor
// failed: its findings keep their state and are flagged not re-observed.
type NotRequested struct {
	Tool   string `json:"tool"`
	Reason string `json:"reason"`
}

// Effective is what a scan of one repository uses, after inheritance and
// clipping: recorded on the repository's scan result as provenance
// (VM-F-202). A NuGuard finding or inventory is uninterpretable without it.
type Effective struct {
	Enabled        bool     `json:"enabled"`
	Tools          []string `json:"tools"`
	IncludePosture bool     `json:"include_posture"`
	TimeoutS       int      `json:"timeout_s"`
	KeepSBOM       bool     `json:"keep_sbom"`
	// From says where the on/off decision came from: "scan", "repository",
	// "fleet", "worker default" or "deployment" (not configured).
	From string `json:"from"`
	// Reason says why NuGuard is off; empty when on.
	Reason string     `json:"reason,omitempty"`
	Clips  []ClipNote `json:"clips,omitempty"`
	// NotRequested lists nuguard (when off) or each selectable sub-tool not
	// asked for (when on), with the reason.
	NotRequested []NotRequested `json:"not_requested,omitempty"`
}

// NotConfigured is the line the interface shows when the worker has no URL.
const NotConfigured = "NuGuard is not configured on this deployment"

// ResolveNuGuardOptions resolves the options one repository's scan uses.
//
// Order: scan request, then repository, then fleet, then the worker's flag
// defaults. Then every value is clipped to the ceiling, and each clip is
// noted: a stored value above the ceiling is never silently honoured.
// fleet nil is a fleet never configured; repo nil is no override; req nil is
// a scan that asked for nothing.
func ResolveNuGuardOptions(c Ceiling, fleet *Fleet, repo *RepoOverride, req *Request) (Effective, []ClipNote) {
	if !c.Configured {
		e := Effective{From: "deployment", Reason: NotConfigured, Tools: []string{}}
		e.NotRequested = []NotRequested{{Tool: "nuguard", Reason: NotConfigured}}
		return e, nil
	}

	base, baseFrom := c.Defaults, "worker default"
	if fleet != nil {
		base, baseFrom = *fleet, "fleet"
	}

	e := Effective{Enabled: base.Enabled, From: baseFrom, TimeoutS: base.TimeoutS}
	tools, toolsFrom := base.Tools, baseFrom
	posture := base.IncludePosture
	if !base.Enabled {
		e.Reason = "off for the fleet"
		if fleet == nil {
			e.Reason = "off by the worker's default"
		}
	}

	if repo != nil {
		switch repo.Mode {
		case RepoOn:
			e.Enabled, e.From, e.Reason = true, "repository", ""
		case RepoOff:
			e.Enabled, e.From, e.Reason = false, "repository", "off for this repository"
		}
		if repo.Tools != nil {
			tools, toolsFrom = repo.Tools, "repository"
		}
		if repo.IncludePosture != nil {
			posture = *repo.IncludePosture
		}
	}
	if req != nil {
		switch req.Mode {
		case RequestOn:
			e.Enabled, e.From, e.Reason = true, "scan", ""
		case RequestOff:
			e.Enabled, e.From, e.Reason = false, "scan", "off for this scan"
		}
		if req.Tools != nil {
			tools, toolsFrom = req.Tools, "scan"
		}
		if req.IncludePosture != nil {
			posture = *req.IncludePosture
		}
		e.KeepSBOM = req.KeepSBOM
	}

	var clips []ClipNote
	notChosen := map[string]string{}

	// Tools: selectable, allowed by the operator, offered by the service.
	allowed := set(c.AllowTools)
	var service map[string]bool
	if c.ServiceTools != nil {
		service = set(c.ServiceTools)
	}
	var kept []string
	for _, t := range dedupe(tools) {
		why := ""
		switch {
		case !IsSelectable(t):
			why = "not a tool users may choose"
		case !allowed[t]:
			why = "not allowed by the operator"
		case service != nil && !service[t]:
			why = "not offered by the service"
		}
		if why != "" {
			clips = append(clips, ClipNote{Field: "tools", Asked: t, Used: "left out", Why: why})
			notChosen[t] = why
			continue
		}
		kept = append(kept, t)
	}
	if kept == nil {
		kept = []string{}
	}
	e.Tools = kept

	if posture && !c.AllowPosture {
		clips = append(clips, ClipNote{Field: "include_posture", Asked: "true", Used: "false",
			Why: "not allowed by the operator"})
		posture = false
	}
	e.IncludePosture = posture

	if e.TimeoutS <= 0 {
		e.TimeoutS = c.Defaults.TimeoutS
	}
	if c.MaxTimeoutS > 0 && e.TimeoutS > c.MaxTimeoutS {
		clips = append(clips, ClipNote{Field: "timeout_s", Asked: fmt.Sprint(e.TimeoutS), Used: fmt.Sprint(c.MaxTimeoutS),
			Why: "above the operator's maximum"})
		e.TimeoutS = c.MaxTimeoutS
	}

	if e.Enabled && len(e.Tools) == 0 {
		e.Enabled = false
		e.Reason = "no tool it may run remains after the operator's limits"
		if len(tools) == 0 {
			e.Reason = "no tool chosen"
		}
	}
	if !e.Enabled {
		e.KeepSBOM = false
		e.NotRequested = []NotRequested{{Tool: "nuguard", Reason: e.Reason}}
	} else {
		for _, t := range Selectable {
			if contains(e.Tools, t) {
				continue
			}
			why := notChosen[t]
			if why == "" {
				why = "not chosen (tools from the " + toolsFrom + " setting)"
			}
			e.NotRequested = append(e.NotRequested, NotRequested{Tool: "nuguard/" + t, Reason: why})
		}
	}
	e.Clips = clips
	return e, clips
}

// FieldError names an input field a value is refused for, and why.
type FieldError struct {
	Field string `json:"field"`
	Why   string `json:"why"`
}

func (e FieldError) Error() string { return e.Field + ": " + e.Why }

// ValidateFleet checks a fleet setting against the ceiling. Values above the
// ceiling are refused, never clipped, when a person sets them: clipping is
// only for stored values the operator has since lowered the ceiling under.
func ValidateFleet(c Ceiling, f Fleet) []FieldError {
	var errs []FieldError
	if !c.Configured && f.Enabled {
		errs = append(errs, FieldError{"enabled", NotConfigured})
	}
	errs = append(errs, validateTools(c, f.Tools, "tools")...)
	if f.Enabled && len(f.Tools) == 0 {
		errs = append(errs, FieldError{"tools", "choose at least one tool, or turn NuGuard off"})
	}
	if f.IncludePosture && !c.AllowPosture {
		errs = append(errs, FieldError{"include_posture", "the operator does not allow posture (ceiling: off)"})
	}
	switch {
	case f.TimeoutS < 30:
		errs = append(errs, FieldError{"timeout_s", "at least 30 seconds"})
	case c.MaxTimeoutS > 0 && f.TimeoutS > c.MaxTimeoutS:
		errs = append(errs, FieldError{"timeout_s", fmt.Sprintf("above the ceiling of %d seconds", c.MaxTimeoutS)})
	}
	return errs
}

// ValidateRepo checks a repository override.
func ValidateRepo(c Ceiling, o RepoOverride) []FieldError {
	var errs []FieldError
	switch o.Mode {
	case RepoInherit, RepoOff:
	case RepoOn:
		if !c.Configured {
			errs = append(errs, FieldError{"mode", NotConfigured})
		}
	default:
		errs = append(errs, FieldError{"mode", "must be inherit, on or off"})
	}
	if o.Tools != nil {
		errs = append(errs, validateTools(c, o.Tools, "tools")...)
		if len(o.Tools) == 0 {
			errs = append(errs, FieldError{"tools", "leave tools out to inherit them, or choose at least one"})
		}
	}
	if o.IncludePosture != nil && *o.IncludePosture && !c.AllowPosture {
		errs = append(errs, FieldError{"include_posture", "the operator does not allow posture (ceiling: off)"})
	}
	return errs
}

// ValidateRequest checks a scan request's NuGuard options.
func ValidateRequest(c Ceiling, r Request) []FieldError {
	var errs []FieldError
	switch r.Mode {
	case RequestDefault, RequestOff:
	case RequestOn:
		if !c.Configured {
			errs = append(errs, FieldError{"nuguard.mode", NotConfigured})
		}
	default:
		errs = append(errs, FieldError{"nuguard.mode", "must be default, on or off"})
	}
	if r.Mode == RequestOff && (r.Tools != nil || r.IncludePosture != nil || r.KeepSBOM) {
		errs = append(errs, FieldError{"nuguard", "tools, posture and keep_sbom apply only when NuGuard runs"})
	}
	if r.Tools != nil {
		errs = append(errs, validateTools(c, r.Tools, "nuguard.tools")...)
		if len(r.Tools) == 0 {
			errs = append(errs, FieldError{"nuguard.tools", "leave tools out to use the setting's, or choose at least one"})
		}
	}
	if r.IncludePosture != nil && *r.IncludePosture && !c.AllowPosture {
		errs = append(errs, FieldError{"nuguard.include_posture", "the operator does not allow posture (ceiling: off)"})
	}
	return errs
}

func validateTools(c Ceiling, tools []string, field string) []FieldError {
	var errs []FieldError
	allowed := set(c.AllowTools)
	seen := map[string]bool{}
	for _, t := range tools {
		switch {
		case seen[t]:
			errs = append(errs, FieldError{field, fmt.Sprintf("%q is listed twice", t)})
		case !IsSelectable(t):
			errs = append(errs, FieldError{field, fmt.Sprintf("%q is not a tool users may choose (%s)", t, strings.Join(Selectable, ", "))})
		case !allowed[t]:
			errs = append(errs, FieldError{field, fmt.Sprintf("%q is above the ceiling: the operator allows %s", t, listOrNone(c.AllowTools))})
		}
		seen[t] = true
	}
	return errs
}

func listOrNone(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return strings.Join(l, ", ")
}

func set(l []string) map[string]bool {
	m := make(map[string]bool, len(l))
	for _, x := range l {
		m[x] = true
	}
	return m
}

func contains(l []string, x string) bool {
	for _, y := range l {
		if y == x {
			return true
		}
	}
	return false
}

// dedupe keeps the first of each tool, in Selectable's order where it can.
func dedupe(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range l {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	order := map[string]int{}
	for i, t := range Selectable {
		order[t] = i + 1
	}
	rank := func(t string) int {
		if r, ok := order[t]; ok {
			return r
		}
		return len(Selectable) + 1
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	return out
}
