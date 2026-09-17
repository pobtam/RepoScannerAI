package tracker

import (
	"fmt"
	"sort"
	"strings"

	"github.com/wanaware/vulnframework/internal/model"
)

// SpecOptions are the things a finding does not know about itself.
type SpecOptions struct {
	ReportURL string
	Assignee  string
	Parent    *Ref
	Labels    []string

	// UnavailableScoringInputs and DeclaredScoringInputs carry the scoring
	// provenance into the ticket (OQ-AUDIT-01).
	//
	// A ticket is read detached from any report, and the priority in its body
	// is the figure quoted in a planning meeting. A caveat that stayed in the
	// report would never reach that conversation.
	UnavailableScoringInputs []string
	DeclaredScoringInputs    int
}

// SpecFor renders the ticket for a finding.
//
// The body is composed from the finding record alone. Nothing is copied from
// raw tool output, which is the only place a credential value ever existed:
// composing from the record means a secret cannot be reintroduced by accident,
// because the record has nowhere to hold one (VM-F-263).
func SpecFor(f model.Finding, opts SpecOptions) (Spec, error) {
	if f.Fingerprint == "" {
		return Spec{}, ErrNoFingerprint
	}

	spec := Spec{
		Fingerprint: f.Fingerprint,
		Title:       titleFor(f),
		Severity:    f.Priority,
		Repo:        f.Repo,
		Assignee:    opts.Assignee,
		Parent:      opts.Parent,
		ReportURL:   opts.ReportURL,
		Labels:      labelsFor(f, opts.Labels),
	}
	spec.Body = bodyFor(f, opts)

	if err := spec.Validate(); err != nil {
		return Spec{}, err
	}
	return spec, nil
}

func titleFor(f model.Finding) string {
	switch f.Category {
	case model.CategorySecret:
		where := deref(f.Location.File)
		if where == "" {
			where = f.Repo
		}
		// The credential TYPE and its LOCATION, never the value. Both are
		// needed to act; neither is the secret.
		return fmt.Sprintf("Exposed credential (%s) in %s", dashIfEmpty(f.CredentialType), where)
	case model.CategoryDependency:
		id := f.Identity.PrimaryID
		if id == "" {
			id = "Vulnerable dependency"
		}
		if f.Location.Module != "" {
			return fmt.Sprintf("%s in %s", id, f.Location.Module)
		}
		return id
	default:
		id := f.Identity.PrimaryID
		if id == "" {
			id = deref(f.Identity.RuleID)
		}
		where := deref(f.Location.File)
		if where != "" {
			return fmt.Sprintf("%s: %s in %s", strings.ToUpper(string(f.Category)), dashIfEmpty(id), where)
		}
		return fmt.Sprintf("%s: %s", strings.ToUpper(string(f.Category)), dashIfEmpty(id))
	}
}

func labelsFor(f model.Finding, extra []string) []string {
	set := map[string]bool{"vf": true, "vf-" + string(f.Category): true}
	if f.Priority != "" {
		set["vf-"+strings.ToLower(string(f.Priority))] = true
	}
	for _, l := range extra {
		set[l] = true
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

func bodyFor(f model.Finding, opts SpecOptions) string {
	var b strings.Builder

	fmt.Fprintf(&b, "**Repository:** `%s`\n", f.Repo)
	fmt.Fprintf(&b, "**Category:** %s\n", f.Category)
	if f.Priority != "" {
		fmt.Fprintf(&b, "**Priority:** %s\n", f.Priority)
		// The qualification goes where the priority goes. A ticket is read
		// detached from any report, and the priority in its body is the figure
		// someone will quote in a planning meeting (OQ-AUDIT-01).
		if len(opts.UnavailableScoringInputs) > 0 {
			fmt.Fprintf(&b, "\n> This priority rests on %d of %d declared scoring inputs: %s "+
				"unavailable because no enrichment feed is wired. Those answer whether the "+
				"vulnerability is being exploited now and how likely it is to be, so treat the "+
				"priority as a **floor** rather than an assessment (OQ-AUDIT-01).\n\n",
				opts.DeclaredScoringInputs-len(opts.UnavailableScoringInputs),
				opts.DeclaredScoringInputs, strings.Join(opts.UnavailableScoringInputs, " and "))
		}
	}
	fmt.Fprintf(&b, "**State:** %s\n", f.State)

	if f.Identity.PrimaryID != "" {
		fmt.Fprintf(&b, "**Advisory:** %s", f.Identity.PrimaryID)
		if len(f.Identity.Aliases) > 0 {
			fmt.Fprintf(&b, " (also %s)", strings.Join(f.Identity.Aliases, ", "))
		}
		b.WriteString("\n")
	}
	if f.Location.Module != "" {
		fmt.Fprintf(&b, "**Module:** `%s`", f.Location.Module)
		if f.Versions.Current != "" {
			fmt.Fprintf(&b, " %s", f.Versions.Current)
		}
		if f.Versions.Fixed != "" {
			fmt.Fprintf(&b, " → fixed in %s", f.Versions.Fixed)
		}
		b.WriteString("\n")
	}
	if file := deref(f.Location.File); file != "" {
		fmt.Fprintf(&b, "**Location:** `%s`", file)
		if line := derefInt(f.Location.Line); line > 0 {
			fmt.Fprintf(&b, ":%d", line)
		}
		b.WriteString("\n")
	}
	// Reachability is rendered as the tri-state it is. Collapsing "unknown" to
	// "no" here would tell a reader the code is not exposed when nobody knows
	// (VM-F-243).
	if f.Classification.Reachable != "" {
		fmt.Fprintf(&b, "**Reachable:** %s\n", f.Classification.Reachable)
	}
	if f.Derived.SLAStatus != "" {
		fmt.Fprintf(&b, "**SLA:** %s\n", f.Derived.SLAStatus)
	}

	if f.Triage != nil && f.Triage.Description != "" {
		b.WriteString("\n### Assessment\n\n")
		b.WriteString(f.Triage.Description + "\n")
		if f.Triage.Impact != "" {
			b.WriteString("\n**Impact:** " + f.Triage.Impact + "\n")
		}
		if f.Triage.Remediation != "" {
			b.WriteString("\n**Suggested remediation:** " + f.Triage.Remediation + "\n")
		}
		b.WriteString("\n_This assessment is advisory. It did not decide the priority, the routing, or " +
			"whether this finding is real (VM-F-306)._\n")
	}

	if f.Category == model.CategorySecret {
		// VM-F-855 and VM-F-856. The most common wrong response to a leaked
		// credential is to delete the line and consider it handled, which
		// leaves a live credential in every clone, cache and backup.
		b.WriteString("\n### This requires credential rotation\n\n")
		b.WriteString("**Removing the secret from source does not constitute remediation.** " +
			"The credential must be rotated at the issuing system. Until it is rotated it remains valid " +
			"in every clone, fork, cache and backup of this repository, and in its history.\n\n")
		b.WriteString("This system will never rewrite history and never removes a secret from a working " +
			"tree as a remediation (VM-F-855). The value itself is not recorded anywhere in this system, " +
			"including in this ticket (VM-F-263).\n")
	}

	fmt.Fprintf(&b, "\n---\n\n[Full report](%s)\n", opts.ReportURL)
	fmt.Fprintf(&b, "\n_Fingerprint `%s`. This ticket is maintained automatically; a second ticket for the "+
		"same fingerprint is a defect, not a duplicate report._\n", f.Fingerprint)

	return b.String()
}

// RunSummary is the run parent ticket's content (VM-AD §13.3).
type RunSummary struct {
	RunID      string
	ReportURL  string
	Counts     map[string]int
	Aggregated []AggregateRow
}

// AggregateRow is one line of the aggregated table that stands in for the
// individual tickets P2 and P3 findings do not get (VM-F-808).
type AggregateRow struct {
	Repo     string
	Priority model.Priority
	Count    int
}

// RunParentBody renders the run parent ticket.
//
// The aggregated table is the reason this ticket exists. Findings that do not
// warrant their own ticket must still be visible somewhere, or "aggregated"
// means "dropped".
func RunParentBody(s RunSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Security run `%s`\n\n", s.RunID)
	fmt.Fprintf(&b, "[Full report](%s)\n\n", s.ReportURL)

	if len(s.Counts) > 0 {
		keys := make([]string, 0, len(s.Counts))
		for k := range s.Counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("| Measure | Count |\n|---|---:|\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "| %s | %d |\n", k, s.Counts[k])
		}
		b.WriteString("\n")
	}

	b.WriteString("## Not individually ticketed\n\n")
	if len(s.Aggregated) == 0 {
		b.WriteString("_None._\n")
		return b.String()
	}
	b.WriteString("P2 and P3 findings that were not remediated are listed here rather than as " +
		"individual tickets (VM-F-808). They are open, not dismissed.\n\n")
	b.WriteString("| Repository | Priority | Findings |\n|---|---|---:|\n")
	rows := append([]AggregateRow(nil), s.Aggregated...)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Repo != rows[j].Repo {
			return rows[i].Repo < rows[j].Repo
		}
		return rows[i].Priority < rows[j].Priority
	})
	for _, r := range rows {
		fmt.Fprintf(&b, "| `%s` | %s | %d |\n", r.Repo, r.Priority, r.Count)
	}
	return b.String()
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "unspecified"
	}
	return s
}
