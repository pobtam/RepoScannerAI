package report

import (
	"fmt"
	"sort"
	"strings"
)

// Render produces the Markdown view of a report.
//
// JSON is authoritative; this reads that document and nothing else (principle
// P5). Never generate two representations independently — they drift, and the
// one people read is the one that drifts.
func Render(rep Report) []byte {
	var b strings.Builder

	title := "Fleet security report"
	if rep.Kind == KindRepo {
		title = "Security report — " + rep.Repo
	}
	fmt.Fprintf(&b, "# %s\n\n", title)

	// The run identifier and its start time are always rendered together: the
	// identifier is not self-dating and the timestamp is not unique, so neither
	// alone identifies the run (VM-F-119).
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Run | `%s` (started %s) |\n", rep.AnchorRun, rep.AnchorStartedAt.Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(&b, "| Issued | %s |\n", rep.IssuedAt.Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(&b, "| Report | `%s` |\n", rep.ID)
	if rep.ContentHash != "" {
		fmt.Fprintf(&b, "| Content hash | `%s` |\n", rep.ContentHash)
	}
	if rep.Provenance.ScannerImage != "" {
		fmt.Fprintf(&b, "| Scanner image | `%s` |\n", rep.Provenance.ScannerImage)
	}
	b.WriteString("\n")

	// Caveats come before the numbers, not after them. A reader who stops at
	// the headline must still have seen that the thresholds are provisional
	// (OQ-P5-02).
	if len(rep.Provenance.Caveats) > 0 {
		b.WriteString("> **Read these numbers with the following caveats.**\n>\n")
		for _, c := range rep.Provenance.Caveats {
			fmt.Fprintf(&b, "> - %s\n", c)
		}
		b.WriteString("\n")
	}
	if rep.Redacted {
		fmt.Fprintf(&b, "> **This report is redacted.** %d findings were withheld because the recipient's "+
			"access level is below the generator's. The counts above include them; the detail does not.\n\n",
			rep.WithheldCount)
	}

	// --- Headline ---
	b.WriteString("## Headline\n\n")
	fmt.Fprintf(&b, "| Measure | Count | Change vs previous %s |\n|---|---:|---:|\n", "run of the same kind")
	fmt.Fprintf(&b, "| Total findings | %d | %s |\n", rep.Counts.Total, signed(rep.Delta.TotalChange, rep.Delta.Comparable))
	fmt.Fprintf(&b, "| Unresolved | %d | %s |\n", rep.Counts.Unresolved, signed(rep.Delta.UnresolvedChange, rep.Delta.Comparable))
	// MERGED is reported as its own line, never folded into resolved or
	// unresolved: counting it either way misstates the total (VM-F-159).
	fmt.Fprintf(&b, "| Merged, pending verification | %d | |\n", rep.Counts.PendingVerification)
	fmt.Fprintf(&b, "| Resolved | %d | |\n", rep.Counts.Resolved)
	b.WriteString("\n")

	if rep.Delta.Comparable {
		fmt.Fprintf(&b, "Compared against `%s`, the previous run of the same kind: **%d new**, **%d no longer observed** (of which %d verified), **%d regressed**.\n\n",
			rep.Delta.PreviousRun, rep.Delta.New, rep.Delta.NoLongerObserved, rep.Delta.Verified, rep.Delta.Regressed)
		b.WriteString("_\"No longer observed\" is not \"fixed\": a finding the run did not look for is also not observed. " +
			"Only the verified count means the defect is gone (VM-ADR-12)._\n\n")
	} else {
		b.WriteString("_No previous run of this kind: there is nothing to compare against, and the counts above are not a delta._\n\n")
	}

	// --- Priority ---
	if len(rep.Counts.ByPriority) > 0 {
		b.WriteString("## By priority\n\n")
		if !rep.Provenance.ThresholdsCalibrated {
			b.WriteString("_Priorities below rest on uncalibrated thresholds (VM-OQ-06) and are provisional._\n\n")
		}
		b.WriteString("| Priority | Count |\n|---|---:|\n")
		for _, p := range []string{"P0", "P1", "P2", "P3"} {
			if n, ok := rep.Counts.ByPriority[p]; ok {
				fmt.Fprintf(&b, "| %s | %d |\n", p, n)
			}
		}
		b.WriteString("\n")
	}

	// --- Not re-observed and SLA ---
	b.WriteString("## Outstanding risk\n\n")
	fmt.Fprintf(&b, "- **Not re-observed:** %d unresolved findings this run did not see. "+
		"They are retained, not resolved — absence is not resolution (VM-ADR-12).\n", rep.Counts.NotReobserved)
	// "0 breached" and "nobody computed it" are different claims, and a reader
	// cannot tell them apart from a zero. Where any SLA is uncomputed the
	// report says so instead of offering a reassuring number (OQ-P7-03).
	switch {
	case rep.Counts.SLANotComputed == rep.Counts.Total && rep.Counts.Total > 0:
		b.WriteString("- **SLA: not computed.** No finding in this report has an SLA position. " +
			"This is not a statement that nothing is late — it is the absence of one.\n\n")
	case rep.Counts.SLANotComputed > 0:
		fmt.Fprintf(&b, "- **SLA breached:** %d%s _(of %d findings with a computed SLA; %d were not computed and are excluded from this figure)_\n",
			rep.Counts.SLABreached, windowNote(rep), rep.Counts.Total-rep.Counts.SLANotComputed, rep.Counts.SLANotComputed)
		fmt.Fprintf(&b, "- **SLA paused:** %d (no upstream fix available; these cannot breach, and are not compliant either)\n\n",
			rep.Counts.SLAPaused)
	default:
		fmt.Fprintf(&b, "- **SLA breached:** %d%s\n", rep.Counts.SLABreached, windowNote(rep))
		fmt.Fprintf(&b, "- **SLA paused:** %d (no upstream fix available; these cannot breach, and are not compliant either)\n\n",
			rep.Counts.SLAPaused)
	}

	// --- Coverage ---
	b.WriteString("## Coverage\n\n")
	c := rep.Coverage
	fmt.Fprintf(&b, "**%.1f%%** of %d in-scope repositories completed a qualifying scan.\n\n", c.Percent, c.InScope)
	b.WriteString("| Outcome | Repositories |\n|---|---:|\n")
	fmt.Fprintf(&b, "| Complete | %d |\n", c.Complete)
	fmt.Fprintf(&b, "| Partial | %d |\n", c.Partial)
	fmt.Fprintf(&b, "| Failed | %d |\n", c.Failed)
	fmt.Fprintf(&b, "| Not dispatched | %d |\n", c.NotDispatched)
	fmt.Fprintf(&b, "| Dispatched, no result | %d |\n", c.NoResult)
	b.WriteString("\n")

	if len(c.ByCause) > 0 {
		b.WriteString("Gaps by cause — the remedy differs by cause, so they are not summed:\n\n")
		causes := make([]string, 0, len(c.ByCause))
		for k := range c.ByCause {
			causes = append(causes, k)
		}
		sort.Strings(causes)
		for _, k := range causes {
			fmt.Fprintf(&b, "- `%s`: %d\n", k, c.ByCause[k])
		}
		b.WriteString("\n")
	}

	// Staleness travels with the percentage, because a flat gap count with a
	// growing maximum age is starvation a percentage cannot show (OQ-P4-01).
	fmt.Fprintf(&b, "**Coverage age** — median %s, p95 %s, worst %s",
		dur(c.Staleness.MedianAge), dur(c.Staleness.P95Age), dur(c.Staleness.MaxAge))
	if c.Staleness.StalestRepo != "" {
		fmt.Fprintf(&b, " (`%s`)", c.Staleness.StalestRepo)
	}
	fmt.Fprintf(&b, ". %d repositories have never had a qualifying scan.\n\n", c.Staleness.NeverScanned)

	if len(c.UnscannedRepos) > 0 {
		b.WriteString("Repositories without a qualifying scan in this run:\n\n")
		for _, r := range c.UnscannedRepos {
			fmt.Fprintf(&b, "- `%s`\n", r)
		}
		b.WriteString("\n")
	}
	if len(c.Escalations) > 0 {
		b.WriteString("**Escalations** — consecutive runs without a qualifying scan, whatever the cause:\n\n")
		for _, e := range c.Escalations {
			fmt.Fprintf(&b, "- `%s`: %d runs (last cause: `%s`)\n", e.Repo, e.SweepsSinceQualifying, e.Cause)
		}
		b.WriteString("\n")
	}

	// --- Findings ---
	if len(rep.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		b.WriteString("| Fingerprint | Repo | Category | Identifier | Priority | State | Reachable | Reason |\n")
		b.WriteString("|---|---|---|---|---|---|---|---|\n")
		for _, f := range rep.Findings {
			id := f.PrimaryID
			if id == "" {
				id = f.CredentialType
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s | %s | %s |\n",
				f.Fingerprint, f.Repo, f.Category, id, dash(f.Priority), f.State, dash(f.Reachable), dash(f.ReasonCode))
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n")
	fmt.Fprintf(&b, "_Report `%s`, anchored to run `%s`. Immutable once issued; regenerate from the stored query rather than editing._\n",
		rep.ID, rep.AnchorRun)

	return []byte(b.String())
}

// windowNote qualifies a breach count with the provenance of the window it was
// measured against (OQ-P7b-03).
//
// It travels with the NUMBER rather than sitting only in the caveat block at
// the top, because a figure is quoted onward — into a slide, a ticket, a status
// mail — and the qualifier has to survive the quoting. A reader must not be able
// to obtain a confident-looking breach count with no provenance attached.
func windowNote(rep Report) string {
	if rep.Provenance.SLAWindowsCalibrated {
		return ""
	}
	return " _(measured against PROVISIONAL windows — VM-OQ-02 unanswered; not a commitment)_"
}

func signed(n int, comparable bool) string {
	if !comparable {
		return "—"
	}
	if n > 0 {
		return fmt.Sprintf("+%d", n)
	}
	return fmt.Sprintf("%d", n)
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func dur(d interface{ String() string }) string {
	if d == nil {
		return "—"
	}
	s := d.String()
	if s == "0s" {
		return "—"
	}
	return s
}
