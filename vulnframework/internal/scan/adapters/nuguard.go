package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/nuguard"
	"github.com/wanaware/vulnframework/internal/nuguardopt"
	"github.com/wanaware/vulnframework/internal/scan"
)

// NuGuard is the remote AI code-rule and inventory adapter (VM-AD §8.2,
// opt-in; DECISIONS-NEEDED D13 amendment of 2026-11-03).
//
// Unlike every other adapter it runs no binary: Run submits the repository,
// at the commit the local tools scanned, to a NuGuard Remote Scan service and
// waits for the result. Normalize, SubTools and Inventory are pure functions
// of that stored result (VM-AD §8.4).
//
// It is registered only when a service URL is configured. Off by default.
//
// What it contributes, deliberately narrow:
//   - code findings from NuGuard's AI rules (nga-rules, atlas, semgrep with
//     NuGuard's AI rule pack), as CategoryCode;
//   - an AI component inventory, as a signal and never as findings.
//
// Posture observations, when requested, are counted into the inventory and
// are not findings: in this project's evaluation they did not tell safe code
// from vulnerable code (PROGRESS.md, "Phase 3 evaluation"). Dependency, IaC
// and container findings are left to this project's own adapters, which
// already cover them; asking NuGuard too would duplicate findings under other
// identifiers and need network access.
type NuGuard struct {
	Client *nuguard.Client
	Pinned string
	// GitHubToken is the same read-only token the worker already holds
	// (VM-F-206), passed to NuGuard in the request body only. Nil scans
	// public repositories without one.
	GitHubToken func() (string, error)
	// GitHubHost is the host repository URLs are built on; empty means
	// github.com.
	GitHubHost string

	// Tools are the NuGuard tools asked for; IncludePosture asks for posture
	// observations, for the inventory.
	Tools          []nuguard.ToolName
	IncludePosture bool
	// Timeout bounds one repository's NuGuard scan, so a slow job cannot use
	// up the scan's whole time limit and cost the local tools' results.
	Timeout time.Duration
}

// DefaultNuGuardTools are the tools asked for unless configured otherwise:
// the AI code rules, and nothing this project's own adapters already do.
var DefaultNuGuardTools = []nuguard.ToolName{nuguard.ToolNGARules, nuguard.ToolAtlas, nuguard.ToolSemgrep}

// NewNuGuard builds the adapter with the defaults.
func NewNuGuard(c *nuguard.Client, version string, githubToken func() (string, error)) *NuGuard {
	return &NuGuard{
		Client: c, Pinned: version, GitHubToken: githubToken,
		Tools: DefaultNuGuardTools, Timeout: 10 * time.Minute,
	}
}

func (a *NuGuard) Name() string    { return "nuguard" }
func (a *NuGuard) Version() string { return a.Pinned }

// Supports applies the adapter wherever this project scans today: Go and
// JavaScript.
func (a *NuGuard) Supports(r scan.RepoProfile) bool {
	return r.HasLanguage(scan.LangGo) || r.HasLanguage(scan.LangJavaScript)
}

// runOptions are the options one run uses: the scan's resolved options
// (RunOpts.NuGuard) where the scan worker resolved them, else this adapter's
// own configuration from its flags.
func (a *NuGuard) runOptions(opts scan.RunOpts) (tools []nuguard.ToolName, posture bool, timeout time.Duration, keepSBOM bool) {
	e := opts.NuGuard
	if e == nil {
		return a.Tools, a.IncludePosture, a.Timeout, false
	}
	for _, t := range e.Tools {
		tools = append(tools, nuguard.ToolName(t))
	}
	return tools, e.IncludePosture, time.Duration(e.TimeoutS) * time.Second, e.KeepSBOM
}

// NotRequested names what this scan does not ask NuGuard for (VM-F-160):
// NuGuard itself when it is off for the repository or the scan, so the
// worker does not run it, and each user-selectable tool not chosen. Their
// earlier findings are then neither verified nor counted against a gap.
//
// A local clone with no github.com origin is not scanned at all: NuGuard
// clones from GitHub, and there is nothing there for it to read.
func (a *NuGuard) NotRequested(opts scan.RunOpts) []scan.NotRequested {
	if lc := opts.LocalClone; lc != nil && lc.GitHubRepo == "" && !offFor(opts.NuGuard) {
		return []scan.NotRequested{{Tool: a.Name(), Reason: NoGitHubOrigin}}
	}
	if opts.NuGuard != nil {
		return append([]scan.NotRequested(nil), opts.NuGuard.NotRequested...)
	}
	var out []scan.NotRequested
	for _, t := range nuguardopt.Selectable {
		if !a.asks(nuguard.ToolName(t)) {
			out = append(out, scan.NotRequested{Tool: a.Name() + "/" + t, Reason: "not in -nuguard-tools"})
		}
	}
	return out
}

// NoGitHubOrigin is why a local clone with no github.com origin is not
// scanned by NuGuard.
const NoGitHubOrigin = "no GitHub origin; NuGuard needs the repository on GitHub"

// offFor reports whether the scan's options already switched NuGuard off,
// whose own reason then stands.
func offFor(e *nuguardopt.Effective) bool {
	if e == nil {
		return false
	}
	for _, nr := range e.NotRequested {
		if nr.Tool == "nuguard" {
			return true
		}
	}
	return false
}

func (a *NuGuard) asks(t nuguard.ToolName) bool {
	for _, x := range a.Tools {
		if x == t {
			return true
		}
	}
	return false
}

var nuguardRepoName = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// Run asks the service to scan the repository at exactly the commit the
// other adapters scanned, and returns the result as received.
//
// For a local clone (real mode) the repository is the clone's GitHub origin,
// not the registered name, which need not be the GitHub owner/name.
func (a *NuGuard) Run(ctx context.Context, _ string, opts scan.RunOpts) (scan.RawOutput, error) {
	if opts.CommitSHA == "" {
		return scan.RawOutput{}, &scan.GapError{Cause: "execution_failed", Owner: scan.OwnerPlatform,
			Detail: "nuguard: no commit was recorded for this checkout, so NuGuard cannot be asked to scan the same one"}
	}
	repo := opts.Repo
	if opts.LocalClone != nil {
		repo = opts.LocalClone.GitHubRepo
		if repo == "" {
			return scan.RawOutput{}, &scan.GapError{Cause: "execution_failed", Owner: scan.OwnerRepo,
				Detail: "nuguard: " + NoGitHubOrigin}
		}
	}
	if !nuguardRepoName.MatchString(repo) || strings.Contains(repo, "..") {
		return scan.RawOutput{}, &scan.GapError{Cause: "execution_failed", Owner: scan.OwnerPlatform,
			Detail: fmt.Sprintf("nuguard: %q is not an owner/name repository", repo)}
	}
	tools, posture, timeout, keepSBOM := a.runOptions(opts)
	if len(tools) == 0 {
		return scan.RawOutput{}, &scan.GapError{Cause: "execution_failed", Owner: scan.OwnerPlatform,
			Detail: "nuguard: the scan resolved to no tool, so NuGuard was not asked"}
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	host := a.GitHubHost
	if host == "" {
		host = "github.com"
	}
	req := nuguard.ScanCreateRequest{
		RepoURL: "https://" + host + "/" + repo, Ref: opts.CommitSHA, ClientReference: opts.RunID,
		Options: nuguard.ScanOptions{
			Tools: tools, MinSeverity: nuguard.SeverityLow, IncludePosture: posture,
			IncludeSBOM: keepSBOM, Network: false, UseLLM: false,
		},
	}
	key := nuguard.IdempotencyKey(opts.RunID, opts.Repo, opts.CommitSHA)
	job, raw, err := a.Client.Scan(ctx, req, key, a.GitHubToken)
	secrets := a.secrets()
	if err != nil {
		if opts.LocalClone != nil && jobCode(err) == "ref_not_found" {
			// From a local clone, a commit GitHub does not have is the
			// repository's: pushed, it is scanned. Not a download fault.
			return scan.RawOutput{}, &scan.GapError{Cause: "commit_not_on_github", Owner: scan.OwnerRepo,
				Detail: fmt.Sprintf("nuguard: commit %s is not on GitHub in %s (not pushed yet, or the clone's history is local only); "+
					"NuGuard scans only what GitHub has", opts.CommitSHA, repo)}
		}
		return scan.RawOutput{}, scrubGap(nuguardGap(err), secrets)
	}
	// A service that echoed a credential into its result must not have it
	// stored: the result is kept verbatim, so it is refused whole.
	for _, s := range secrets {
		if bytes.Contains(raw, []byte(s)) {
			return scan.RawOutput{}, &scan.GapError{Cause: "execution_failed", Owner: scan.OwnerPlatform,
				Detail: "nuguard: the result contained a credential this project sent; it was discarded unread"}
		}
	}
	if job.CommitSHA == nil || !strings.EqualFold(*job.CommitSHA, opts.CommitSHA) {
		got := "none"
		if job.CommitSHA != nil {
			got = *job.CommitSHA
		}
		return scan.RawOutput{}, &scan.GapError{Cause: "commit_mismatch", Owner: scan.OwnerPlatform,
			Detail: fmt.Sprintf("nuguard: scanned commit %s, not %s, which the other tools scanned; its findings are dropped", got, opts.CommitSHA)}
	}

	res, err := nuguard.ParseResult(raw)
	if err != nil {
		return scan.RawOutput{}, err
	}
	exit := 0
	if res.Job.Status == nuguard.StatusPartial {
		exit = 1
	}
	versions := map[string]string{"nuguard": res.Provenance.NuGuardVersion}
	if res.Provenance.RulepackSHA256 != "" {
		versions["nuguard/rulepack"] = res.Provenance.RulepackSHA256
	}
	if res.Provenance.ImageDigest != nil && *res.Provenance.ImageDigest != "" {
		versions["nuguard/image"] = *res.Provenance.ImageDigest
	}
	requested := make([]string, len(tools))
	for i, t := range tools {
		requested[i] = string(t)
	}
	out := scan.RawOutput{
		Tool: a.Name(), ToolVersion: a.Version(), ExitCode: exit, Stdout: raw, Versions: versions,
		Requested: requested,
	}
	if keepSBOM && len(res.SBOM) > 0 && string(res.SBOM) != "null" {
		out.SBOM = res.SBOM
	}
	if lc := opts.LocalClone; lc != nil && lc.WorkTree != scan.WorkTreeClean {
		// The local tools scanned the tree on disk; NuGuard scanned GitHub's
		// copy of the commit. Every NuGuard finding says so.
		note := "NuGuard scanned the committed state, not the working tree"
		if lc.WorkTree != scan.WorkTreeDirty {
			note = "NuGuard scanned the committed state; working-tree state unknown"
		}
		out.Annotations = map[string]string{a.Name() + "/" + a.Version() + "/scanned": note}
	}
	return out, nil
}

// jobCode is the service's code for a scan that ended without a result, or "".
func jobCode(err error) string {
	var je *nuguard.JobError
	if errors.As(err, &je) {
		return je.Code
	}
	return ""
}

// secrets are the credentials this adapter sends, read only to keep them out
// of what it returns.
func (a *NuGuard) secrets() []string {
	var out []string
	for _, f := range []func() (string, error){a.GitHubToken, a.apiKey()} {
		if f == nil {
			continue
		}
		if s, err := f(); err == nil && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func (a *NuGuard) apiKey() func() (string, error) {
	if a.Client == nil {
		return nil
	}
	return a.Client.APIKey
}

// scrubGap removes the credentials from a gap's detail. The client already
// scrubs what it builds; this also covers what the service itself wrote,
// such as a job error's detail.
func scrubGap(err error, secrets []string) error {
	var g *scan.GapError
	if !errors.As(err, &g) {
		return err
	}
	for _, s := range secrets {
		g.Detail = strings.ReplaceAll(g.Detail, s, "[redacted]")
	}
	return g
}

// nuguardGap attributes a failed NuGuard scan (VM-F-214).
func nuguardGap(err error) error {
	g := &scan.GapError{Cause: "execution_failed", Owner: scan.OwnerPlatform, Detail: err.Error()}
	var je *nuguard.JobError
	var ae *nuguard.APIError
	switch {
	case errors.As(err, &je):
		switch je.Code {
		case "auth_failed", "repo_not_found_or_no_access", "credential_unavailable":
			g.Cause = "credential_failed"
		case "ref_not_found", "clone_failed", "clone_timeout":
			// A clone that failed is a download that failed.
			g.Cause = "download_failed"
		case "repo_too_large":
			// The repository's to fix (or to exclude), not the platform's.
			g.Cause, g.Owner = "repo_too_large", scan.OwnerRepo
		}
	case errors.As(err, &ae):
		if ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden {
			// NuGuard refused this project's API key.
			g.Cause = "credential_failed"
		}
	}
	if !strings.HasPrefix(g.Detail, "nuguard") {
		g.Detail = "nuguard: " + g.Detail
	}
	return g
}

// Normalize turns NuGuard's code findings into raw findings. Everything else
// in the result is either the inventory (posture) or deliberately left to
// this project's own adapters (dependency, IaC, container, supply chain).
func (a *NuGuard) Normalize(out scan.RawOutput) ([]model.RawFinding, error) {
	res, err := a.parse(out)
	if err != nil {
		return nil, err
	}
	var items struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(out.Stdout, &items); err != nil || len(items.Findings) != len(res.Findings) {
		return nil, fmt.Errorf("nuguard: reading the findings: %v", err)
	}

	allowed := requestedKinds(res)
	var raw []model.RawFinding
	for i, f := range res.Findings {
		if !allowed[f.Kind] {
			// The request and the response disagree: the contract is broken,
			// and nothing in this result can be trusted to be what was asked.
			return nil, fmt.Errorf("nuguard: the result has a %s finding (%s), which was not requested", f.Kind, f.RuleID)
		}
		if f.Kind != nuguard.KindCode {
			continue // the inventory counts it
		}
		if len(f.Locations) == 0 {
			return nil, fmt.Errorf("nuguard: code finding %s has no location", f.RuleID)
		}
		loc := f.Locations[0]
		if !relativePath(loc.Path) {
			return nil, fmt.Errorf("nuguard: code finding %s has a path that is not repository-relative", f.RuleID)
		}
		rf := model.RawFinding{
			Repo:     out.Repo,
			Category: model.CategoryCode,
			Tool:     a.Name(),
			// The tool name is part of a code finding's identity, so a rule
			// id NuGuard shares with the local semgrep adapter cannot collide
			// with it: no prefix is needed.
			RuleID: f.RuleID,
			// Which of NuGuard's tools saw it: reconciliation verifies the
			// finding only in a scan where that tool ran (VM-F-160).
			SubTool: f.SourceTool,
			File:    relPath(loc.Path, out.Dir),
			Classification: model.Classification{
				Severity: severityFromBand(string(f.Severity)),
				// Same convention as the semgrep adapter: a rule matched in
				// the code, so the code is there.
				Reachable: model.ReachableTrue,
				DepClass:  model.DepNotApplicable,
			},
			ToolVersion: a.Version(),
			Description: model.SafeDescription(firstNonEmptyText(f.Description, f.Title)),
			Annotations: a.annotate(f, out.Annotations),
			Raw:         withoutRaw(items.Findings[i]),
		}
		if loc.Symbol != nil {
			// Recorded for display; never part of identity (OQ-AUDIT-02).
			rf.Function = *loc.Symbol
		}
		if loc.StartLine != nil {
			rf.Line = *loc.StartLine // display only (VM-F-102)
		}
		if len(f.References) > 0 {
			rf.AdvisoryURL = f.References[0]
		}
		raw = append(raw, rf)
	}
	raw = dedupe(raw)
	sortFindings(raw)
	return raw, nil
}

// parse reads the stored result and refuses one this adapter was not asked
// for: another NuGuard version (VM-F-202), or a job that did not finish.
func (a *NuGuard) parse(out scan.RawOutput) (nuguard.ScanResult, error) {
	res, err := nuguard.ParseResult(out.Stdout)
	if err != nil {
		return res, err
	}
	if got := res.Provenance.NuGuardVersion; strings.TrimPrefix(got, "v") != strings.TrimPrefix(a.Pinned, "v") {
		return res, &scan.GapError{Cause: "version_mismatch", Owner: scan.OwnerPlatform,
			Detail: fmt.Sprintf("nuguard: the service runs %s but config/tools.lock pins %s; its output is not accepted", got, a.Pinned)}
	}
	if s := res.Job.Status; s != nuguard.StatusSucceeded && s != nuguard.StatusPartial {
		return res, fmt.Errorf("nuguard: the result is for a job that ended %s", s)
	}
	return res, nil
}

// requestedKinds is what a result may contain: code findings always, posture
// when posture was requested, and what each tool that ran produces. The tools
// that ran are read from coverage.tool_runs, not options_effective.tools,
// which the service has been seen to report as null while narrowing it.
func requestedKinds(res nuguard.ScanResult) map[nuguard.Kind]bool {
	kinds := map[nuguard.Kind]bool{nuguard.KindCode: true}
	if res.Provenance.OptionsEffective.IncludePosture {
		kinds[nuguard.KindPosture] = true
	}
	for _, tr := range res.Coverage.ToolRuns {
		for _, k := range nuguard.KindsOf(tr.Tool) {
			kinds[k] = true
		}
	}
	return kinds
}

// SubTools reports which of NuGuard's tools ran and a gap for each that did
// not (VM-F-211): any tool not ok, not_applicable or disabled; a tool that
// was asked for and is missing from the result; and a job the service called
// partial without naming the tool.
func (a *NuGuard) SubTools(out scan.RawOutput) ([]string, []scan.CoverageGap, error) {
	res, err := a.parse(out)
	if err != nil {
		return nil, nil, err
	}
	var ok []string
	var gaps []scan.CoverageGap
	seen := map[string]bool{}
	asked := map[string]bool{}
	for _, t := range out.Requested {
		asked[t] = true
	}
	for _, tr := range res.Coverage.ToolRuns {
		seen[tr.Tool] = true
		name := a.Name() + "/" + tr.Tool
		cause := ""
		switch tr.Status {
		case nuguard.ToolOK, nuguard.ToolNotApplicable:
			// A tool this scan did not ask for is never an ok source, even
			// if the service ran it: the scan records it as not requested,
			// and reconciliation must not take its silence as evidence.
			if out.Requested == nil || asked[tr.Tool] {
				ok = append(ok, name)
			}
			continue
		case nuguard.ToolDisabled:
			continue
		case nuguard.ToolFailed:
			cause = "tool_failed"
		case nuguard.ToolTimeout:
			cause = "tool_timeout"
		case nuguard.ToolSkipped:
			cause = "tool_skipped"
		}
		detail := name + " " + string(tr.Status)
		if tr.Reason != nil && *tr.Reason != "" {
			detail += ": " + *tr.Reason
		}
		gaps = append(gaps, scan.CoverageGap{Tool: name, Cause: cause, Owner: scan.OwnerPlatform, Detail: detail})
	}
	want := out.Requested
	if want == nil {
		for _, t := range a.Tools {
			want = append(want, string(t))
		}
	}
	for _, t := range want {
		if !seen[t] {
			gaps = append(gaps, scan.CoverageGap{Tool: a.Name() + "/" + t, Cause: "tool_skipped",
				Owner: scan.OwnerPlatform, Detail: "nuguard/" + t + " was asked for and the result does not mention it"})
		}
	}
	if res.Job.Status == nuguard.StatusPartial && len(gaps) == 0 {
		gaps = append(gaps, scan.CoverageGap{Tool: a.Name(), Cause: "tool_failed", Owner: scan.OwnerPlatform,
			Detail: "nuguard reported the scan partial without naming the tool: " + strings.Join(res.Coverage.Gaps, "; ")})
	}
	sort.Strings(ok)
	return ok, gaps, nil
}

// Inventory is the AI component inventory, labelled with what produced it.
// Posture observations are counted by rule when posture was requested; nil
// otherwise, so "not requested" never reads as "none".
func (a *NuGuard) Inventory(out scan.RawOutput) *scan.AIInventory {
	res, err := a.parse(out)
	if err != nil {
		return nil
	}
	inv := &scan.AIInventory{
		Source:         "nuguard " + res.Provenance.NuGuardVersion,
		RulepackSHA256: res.Provenance.RulepackSHA256,
		NodeCounts:     res.Inventory.NodeCounts,
		EdgeCount:      res.Inventory.EdgeCount,
		Frameworks:     res.Inventory.Frameworks,
		ModelProviders: res.Inventory.ModelProviders,
	}
	if res.Provenance.ImageDigest != nil {
		inv.ImageDigest = *res.Provenance.ImageDigest
	}
	if inv.NodeCounts == nil {
		inv.NodeCounts = map[string]int{}
	}
	if inv.Frameworks == nil {
		inv.Frameworks = []string{}
	}
	if inv.ModelProviders == nil {
		inv.ModelProviders = []string{}
	}
	if res.Provenance.OptionsEffective.IncludePosture {
		inv.PostureObservations = map[string]int{}
	}
	for _, f := range res.Findings {
		switch f.Kind {
		case nuguard.KindCode:
		case nuguard.KindPosture:
			if inv.PostureObservations != nil {
				inv.PostureObservations[f.RuleID]++
			}
		default:
			if inv.NotFindings == nil {
				inv.NotFindings = map[string]int{}
			}
			inv.NotFindings[string(f.Kind)]++
		}
	}
	return inv
}

// annotate keeps what NuGuard says about a finding that this project does
// not use to decide anything: its own fingerprint (never the identity:
// fingerprints are computed here, VM-AD §5), the tool inside NuGuard that
// matched, and the taxonomy references. Version-tagged, as annotations are.
func (a *NuGuard) annotate(f nuguard.ScanFinding, run map[string]string) map[string]string {
	prefix := a.Name() + "/" + a.Version() + "/"
	out := map[string]string{}
	for k, v := range run {
		out[k] = v
	}
	out[prefix+"fingerprint"] = f.Fingerprint
	out[prefix+"source_tool"] = f.SourceTool
	for k, v := range map[string]*string{
		"owasp_llm_ref": f.OWASPLLMRef, "owasp_asi_ref": f.OWASPASIRef, "mitre_atlas_technique": f.MITREAtlasTechnique,
	} {
		if v != nil && *v != "" {
			out[prefix+k] = *v
		}
	}
	return out
}

// relativePath accepts only a repository-relative path: not absolute, no
// drive letter, no step outside the tree.
func relativePath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) ||
		(len(p) > 1 && p[1] == ':') {
		return false
	}
	for _, seg := range strings.Split(strings.ReplaceAll(p, `\`, "/"), "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// withoutRaw drops NuGuard's full finding (its raw field) from the retained
// copy: the store keeps the projection, and the full result stays in the
// scan's raw output.
func withoutRaw(b json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return compact(b)
	}
	delete(m, "raw")
	return mustRaw(m)
}

// NuGuardConfig is the deployment's NuGuard settings, from the command line
// (-nuguard-url, -nuguard-tools, -nuguard-include-posture, -nuguard-timeout)
// and the environment (the API key).
type NuGuardConfig struct {
	URL            string
	Tools          string // comma-separated; empty means DefaultNuGuardTools
	IncludePosture bool
	Timeout        time.Duration
	APIKey         func() (string, error)
	GitHubToken    func() (string, error)
	GitHubHost     string
}

// NewNuGuardFromConfig builds the adapter, or nil when no URL is configured:
// NuGuard is off unless asked for.
func NewNuGuardFromConfig(cfg NuGuardConfig, version string) (*NuGuard, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, nil
	}
	if version == "" {
		return nil, errors.New("nuguard: config/tools.lock pins no nuguard version")
	}
	tools, err := ParseNuGuardTools(cfg.Tools)
	if err != nil {
		return nil, err
	}
	a := NewNuGuard(&nuguard.Client{BaseURL: cfg.URL, APIKey: cfg.APIKey}, version, cfg.GitHubToken)
	a.Tools, a.IncludePosture, a.GitHubHost = tools, cfg.IncludePosture, cfg.GitHubHost
	if cfg.Timeout > 0 {
		a.Timeout = cfg.Timeout
	}
	// Refused here rather than on the first scan: the URL rule (https, or
	// http only to loopback) is a configuration error, not a scan failure.
	if err := a.Client.CheckURL(); err != nil {
		return nil, err
	}
	return a, nil
}

// ParseNuGuardTools reads a comma-separated tool list, refusing a name the
// service does not define.
func ParseNuGuardTools(s string) ([]nuguard.ToolName, error) {
	if strings.TrimSpace(s) == "" {
		return append([]nuguard.ToolName(nil), DefaultNuGuardTools...), nil
	}
	var out []nuguard.ToolName
	for _, part := range strings.Split(s, ",") {
		name := nuguard.ToolName(strings.TrimSpace(part))
		if name == "" {
			continue
		}
		known := false
		for _, k := range nuguard.ToolNames {
			known = known || k == name
		}
		if !known {
			return nil, fmt.Errorf("nuguard: %q is not a NuGuard tool", name)
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil, errors.New("nuguard: -nuguard-tools names no tool")
	}
	return out, nil
}

// NuGuardProbe is what one status check found (VM-UI-F-1201): published by
// the scan worker, the only process that talks to NuGuard, so the API can
// show it without holding a key.
type NuGuardProbe struct {
	Reachable      bool
	ServiceVersion string
	// ToolsAllowed is the service's own list; nil when it could not be asked.
	ToolsAllowed []string
	// Err is the failure, with every credential this adapter sends removed,
	// as from a gap's detail; empty when the check passed.
	Err string
}

// Probe asks the service whether it is ready and what it runs. It never
// fails: what went wrong is in the result, sanitized.
func (a *NuGuard) Probe(ctx context.Context) NuGuardProbe {
	var p NuGuardProbe
	scrub := func(err error) string {
		s := err.Error()
		for _, sec := range a.secrets() {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
		if !strings.HasPrefix(s, "nuguard") {
			s = "nuguard: " + s
		}
		return s
	}
	h, err := a.Client.Ready(ctx)
	if err != nil {
		p.Err = scrub(err)
		return p
	}
	if h.Status != "ok" {
		p.Err = "nuguard: the service is not ready (" + strings.Join(h.Failing, ", ") + ")"
		return p
	}
	p.Reachable = true
	caps, err := a.Client.Capabilities(ctx)
	if err != nil {
		p.Err = scrub(err)
		return p
	}
	p.ServiceVersion = caps.NuGuardVersion
	p.ToolsAllowed = append([]string{}, caps.ToolsAllowed...)
	if strings.TrimPrefix(caps.NuGuardVersion, "v") != strings.TrimPrefix(a.Pinned, "v") {
		p.Err = fmt.Sprintf("nuguard: the service runs %s but config/tools.lock pins %s; its results are refused",
			caps.NuGuardVersion, a.Pinned)
	}
	return p
}

// ErrNuGuardRefused is a start-up check that must stop the program: the
// service runs another version than the one pinned, or does not allow a tool
// this deployment asks for. Every scan would otherwise end in the same gap.
type ErrNuGuardRefused struct{ Reason string }

func (e *ErrNuGuardRefused) Error() string { return "nuguard: " + e.Reason }

// CheckService asks the service whether it is ready and what it runs.
//
// It returns *ErrNuGuardRefused when the version or the tools disagree with
// this deployment, which should stop the program; any other error means the
// service could not be asked (unreachable, not ready), which should be logged
// and tolerated, because each scan then records its own coverage gap, as any
// other tool failure does.
func (a *NuGuard) CheckService(ctx context.Context) error {
	h, err := a.Client.Ready(ctx)
	if err != nil {
		return err
	}
	if h.Status != "ok" {
		return fmt.Errorf("nuguard: the service is not ready (%s)", strings.Join(h.Failing, ", "))
	}
	caps, err := a.Client.Capabilities(ctx)
	if err != nil {
		var ae *nuguard.APIError
		if errors.As(err, &ae) && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden) {
			return &ErrNuGuardRefused{Reason: "the service refused the API key in VULNFRAMEWORK_NUGUARD_API_KEY"}
		}
		return err
	}
	if strings.TrimPrefix(caps.NuGuardVersion, "v") != strings.TrimPrefix(a.Pinned, "v") {
		return &ErrNuGuardRefused{Reason: fmt.Sprintf("the service runs NuGuard %s but config/tools.lock pins %s",
			caps.NuGuardVersion, a.Pinned)}
	}
	allowed := map[string]bool{}
	for _, t := range caps.ToolsAllowed {
		allowed[t] = true
	}
	for _, t := range a.Tools {
		if !allowed[string(t)] {
			return &ErrNuGuardRefused{Reason: fmt.Sprintf("the service does not allow the tool %q (it allows %s)",
				t, strings.Join(caps.ToolsAllowed, ", "))}
		}
	}
	return nil
}
