package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Delivery is a report rendered for one recipient.
type Delivery struct {
	Recipient Recipient
	Issued    Issued
	Redacted  bool
	Withheld  int
}

// Deliver renders, guards and hands over a report at the recipient's level.
//
// Two things happen here that do not happen in Issue, and both are the point of
// the phase:
//
// It FAILS CLOSED on an undetermined privilege level. There is no fallback to a
// fuller rendering, because the failure mode of a permissions system must never
// be "grant more" — an identity lookup that times out would otherwise quietly
// upgrade the recipient.
//
// It re-runs the credential scan against the ARTIFACT THE RECIPIENT ACTUALLY
// GETS. Scanning only the unredacted document would miss anything redaction
// itself introduces, and the redacted rendering is the one that travels
// furthest.
func Deliver(ctx context.Context, p Publisher, path string, rep Report, to Recipient) (Delivery, error) {
	if !to.Determined || !to.Level.Valid() {
		return Delivery{}, &ErrPrivilegeUndetermined{Recipient: to.ID}
	}
	if len(rep.Findings) > MaxFindingsPerReport {
		return Delivery{}, &ErrOverLimit{Requested: len(rep.Findings), Limit: MaxFindingsPerReport}
	}

	redacted, err := Redact(rep, to.Level)
	if err != nil {
		return Delivery{}, err
	}

	// Issue guards and hashes this exact rendering.
	issued, err := Issue(redacted)
	if err != nil {
		return Delivery{}, err
	}

	if p != nil {
		if err := p.Publish(ctx, path+"/report.json", issued.JSON); err != nil {
			return Delivery{}, err
		}
		if err := p.Publish(ctx, path+"/report.md", issued.Markdown); err != nil {
			return Delivery{}, err
		}
	}

	return Delivery{
		Recipient: to, Issued: issued,
		Redacted: issued.Report.Redacted, Withheld: issued.Report.WithheldCount,
	}, nil
}

// AssertLeastPrivilegedRenderingIsClean renders a report at the least-privileged
// level and scans that artifact for credential material.
//
// It exists as a separate, callable check because the least-privileged rendering
// is the one distributed most widely — a leak there reaches the largest
// audience — and because redaction is itself code that can introduce text. The
// generator runs it before any delivery, so the widest-travelling artifact is
// always the one that has been checked.
func AssertLeastPrivilegedRenderingIsClean(rep Report) error {
	least, err := Redact(rep, LeastPrivileged)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(least, "", "  ")
	if err != nil {
		return fmt.Errorf("report: encoding least-privileged rendering: %w", err)
	}
	if err := AssertNoCredentials("least-privileged report.json", body); err != nil {
		return err
	}
	return AssertNoCredentials("least-privileged report.md", Render(least))
}

// AuditPack is a sealed evidence bundle for one run (v1.0 acceptance 15).
type AuditPack struct {
	ID        string `json:"id"`
	AnchorRun string `json:"anchor_run"`
	Query     Query  `json:"query"`
	Level     string `json:"level"`

	Report Report `json:"report"`

	// Attestation is the coverage statement, including the repositories that
	// were NOT scanned. An evidence pack that lists only what was covered
	// invites the reader to assume the rest was clean, which is the assumption
	// the whole coverage model exists to prevent.
	Attestation Attestation `json:"attestation"`

	// Artifacts maps each file in the pack to its sha256, so any single file
	// can be checked in isolation years later.
	Artifacts map[string]string `json:"artifacts"`
	// ContentHash covers the whole pack.
	ContentHash string `json:"content_hash,omitempty"`
}

// Attestation is the coverage statement inside an audit pack.
type Attestation struct {
	InScope           int      `json:"in_scope"`
	QualifyingScans   int      `json:"qualifying_scans"`
	CoveragePercent   float64  `json:"coverage_percent"`
	UnscannedRepos    []string `json:"unscanned_repos"`
	NeverScannedRepos int      `json:"never_scanned_repos"`
	// Statement is the plain-language claim this pack makes, and the limits of
	// it. An audit reader should not have to infer the scope of an assurance
	// from a table.
	Statement string `json:"statement"`
	// Caveats repeats the report's provenance caveats, because a pack is often
	// read detached from the report it was built from.
	Caveats []string `json:"caveats,omitempty"`
}

// BuildAuditPack seals a report into an evidence bundle.
//
// The pack is built from an already-issued report so that the report's own hash
// is preserved inside it: the pack attests to a specific document, not to a
// re-derivation that might differ.
func BuildAuditPack(rep Report, level Level) (AuditPack, error) {
	if !level.Valid() {
		return AuditPack{}, &ErrPrivilegeUndetermined{Recipient: "<audit pack>"}
	}

	redacted, err := Redact(rep, level)
	if err != nil {
		return AuditPack{}, err
	}
	issued, err := Issue(redacted)
	if err != nil {
		return AuditPack{}, err
	}

	pack := AuditPack{
		ID:        "AP-" + rep.AnchorRun + "-" + level.String(),
		AnchorRun: rep.AnchorRun,
		Query:     rep.Query,
		Level:     level.String(),
		Report:    issued.Report,
		Attestation: Attestation{
			InScope:           rep.Coverage.InScope,
			QualifyingScans:   rep.Coverage.Complete,
			CoveragePercent:   rep.Coverage.Percent,
			UnscannedRepos:    rep.Coverage.UnscannedRepos,
			NeverScannedRepos: rep.Coverage.Staleness.NeverScanned,
			Caveats:           rep.Provenance.Caveats,
		},
		Artifacts: map[string]string{
			"report.json": sha256Of(issued.JSON),
			"report.md":   sha256Of(issued.Markdown),
		},
	}
	pack.Attestation.Statement = attestationStatement(rep, issued.Report)

	body, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return AuditPack{}, fmt.Errorf("report: encoding audit pack: %w", err)
	}
	if err := AssertNoCredentials("audit-pack.json", body); err != nil {
		return AuditPack{}, err
	}
	pack.ContentHash = sha256Of(body)
	return pack, nil
}

// attestationStatement writes the claim the pack makes, and its limits.
func attestationStatement(rep Report, delivered Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "This pack attests to run %s, started %s. ",
		rep.AnchorRun, rep.AnchorStartedAt.Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(&b, "%d of %d in-scope repositories completed a qualifying scan (%.1f%%). ",
		rep.Coverage.Complete, rep.Coverage.InScope, rep.Coverage.Percent)

	if n := len(rep.Coverage.UnscannedRepos); n > 0 {
		fmt.Fprintf(&b, "%d repositories did NOT complete a qualifying scan and are named in this pack; "+
			"no claim is made about their contents. ", n)
	} else {
		b.WriteString("Every in-scope repository completed a qualifying scan. ")
	}

	if rep.Counts.SLANotComputed == rep.Counts.Total && rep.Counts.Total > 0 {
		b.WriteString("SLA position was not computed for any finding, so this pack makes no SLA compliance claim. ")
	} else if rep.Counts.SLANotComputed > 0 {
		fmt.Fprintf(&b, "SLA position was not computed for %d of %d findings, which are excluded from the breach figure. ",
			rep.Counts.SLANotComputed, rep.Counts.Total)
	}

	if delivered.Redacted {
		fmt.Fprintf(&b, "This rendering is redacted: %d findings are counted but not detailed. ", delivered.WithheldCount)
	}
	b.WriteString("Coverage is measured against planned scope, so a repository that was never dispatched appears as a gap rather than as clean.")
	return b.String()
}

// PublishAuditPack writes a pack and its artifacts.
func PublishAuditPack(ctx context.Context, p Publisher, pack AuditPack, issued Issued) error {
	base := "audit/" + pack.ID
	body, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return err
	}
	if err := p.Publish(ctx, base+"/pack.json", body); err != nil {
		return err
	}
	if err := p.Publish(ctx, base+"/report.json", issued.JSON); err != nil {
		return err
	}
	return p.Publish(ctx, base+"/report.md", issued.Markdown)
}

func sha256Of(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// LevelsBelow returns every level strictly below l, least privileged first.
func LevelsBelow(l Level) []Level {
	var out []Level
	for _, candidate := range AllLevels {
		if candidate < l {
			out = append(out, candidate)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
