package remediate

import (
	"fmt"
	"strings"
)

// Body renders the pull request description (VM-F-543).
//
// The requirement enumerates what it must state: findings addressed, changes
// made, residual risk, anything deferred and why, any breaking change, and the
// manual steps required of the reviewer. The last two matter most — a reviewer
// who has to infer that a change is breaking, or that something is still
// outstanding, will infer wrongly under time pressure.
//
// Verification output is included verbatim. Summarising away a failure is a
// defect (VM-F-532), and the same applies to a success: a reviewer should be
// able to see what was actually run, not a claim that it passed.
func Body(group FixGroup, targets []Target, v Verification) string {
	var b strings.Builder

	b.WriteString("## What this changes\n\n")
	if len(targets) == 0 {
		b.WriteString("_No dependency changes._\n\n")
	} else {
		b.WriteString("| Module | From | To | Closes |\n|---|---|---|---|\n")
		for _, t := range targets {
			fmt.Fprintf(&b, "| `%s` | %s | **%s** | %s |\n", t.Module, dash(t.From), t.To, strings.Join(t.Closes, ", "))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Findings addressed\n\n")
	for _, f := range group.Findings {
		id := f.Identity.PrimaryID
		if id == "" {
			id = string(f.Category)
		}
		fmt.Fprintf(&b, "- **%s** — %s", id, dash(string(f.Priority)))
		if f.Classification.Reachable != "" {
			// The tri-state, verbatim. "unknown" is not "no": telling a
			// reviewer the code is unreachable when nobody knows invites them
			// to deprioritise it (VM-F-243).
			fmt.Fprintf(&b, ", reachable: %s", f.Classification.Reachable)
		}
		fmt.Fprintf(&b, " — `%s`\n", f.Fingerprint)
	}
	b.WriteString("\n")

	b.WriteString("## Verification\n\n")
	fmt.Fprintf(&b, "- Build: %s\n", tick(v.BuildOK))
	fmt.Fprintf(&b, "- Tests: %s\n", tick(v.TestsOK))
	fmt.Fprintf(&b, "- Dependency manifest tidy: %s\n", tick(v.TidyOK))
	fmt.Fprintf(&b, "- Re-scan with the tools that produced these findings: %s\n", tick(v.RescanClean))
	if !v.RescanClean && len(v.Remaining) > 0 {
		fmt.Fprintf(&b, "  - **still reported:** %s\n", strings.Join(v.Remaining, ", "))
	}
	if strings.TrimSpace(v.Output) != "" {
		b.WriteString("\n<details><summary>Verification output, verbatim</summary>\n\n```\n")
		b.WriteString(strings.TrimRight(v.Output, "\n"))
		b.WriteString("\n```\n\n</details>\n")
	}
	b.WriteString("\n")

	b.WriteString("## Residual risk and manual steps\n\n")
	// The honest statement of what this pull request does NOT establish. A
	// merged pull request is not a fix: only a scan of the merged default
	// branch that no longer reports the finding is (VM-F-533, VM-ADR-12).
	b.WriteString("- Merging this does not close the findings. They move to `MERGED`, and reach `VERIFIED` only " +
		"when a later scan of the default branch no longer observes them (VM-F-533, VM-ADR-12).\n")
	b.WriteString("- This change was produced deterministically: the modules were upgraded to the version " +
		"that closes every reporting source's advisory, with no inference involved (VM-ADR-09).\n")
	if breaking := breakingTargets(targets); len(breaking) > 0 {
		fmt.Fprintf(&b, "- **Breaking change:** %s crosses a major version. Call sites may need adaptation "+
			"that this deterministic change does not make.\n", strings.Join(breaking, ", "))
	}
	b.WriteString("- No suppression directive was added, and none may be: if suppression is the right answer " +
		"here, say so in review and the finding is marked `SUPPRESSION_PROPOSED` (VM-F-507).\n")
	b.WriteString("- This pull request is not merged automatically (VM-F-541). It needs a human decision.\n")

	b.WriteString("\n---\n\n")
	fmt.Fprintf(&b, "_Fix group `%s`, branch `%s`. Machine-generated. Re-running remediation for this group "+
		"finds this pull request rather than opening another (VM-F-502)._\n", group.ID, group.Branch)
	return b.String()
}

// breakingTargets names bumps that cross a major version.
func breakingTargets(targets []Target) []string {
	var out []string
	for _, t := range targets {
		if majorOf(t.From) != "" && majorOf(t.To) != "" && majorOf(t.From) != majorOf(t.To) {
			out = append(out, t.Module)
		}
	}
	return out
}

func majorOf(v string) string {
	s := strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.Index(s, "."); i > 0 {
		return s[:i]
	}
	return ""
}

func tick(ok bool) string {
	if ok {
		return "passed"
	}
	return "**FAILED**"
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
