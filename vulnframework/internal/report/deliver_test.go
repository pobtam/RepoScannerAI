package report_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/triage"
)

// Phase 7b gate:
//
//	a genuinely breached SLA produces a NON-ZERO breach count in the report;
//	NO_UPSTREAM_FIX pauses the clock;
//	an uncomputed SLA renders as "not computed", never "0 breaches";
//	the secret scan runs against the LEAST-privileged rendering;
//	delivery FAILS CLOSED on undetermined privilege;
//	byte-identical regeneration stays green;
//	an audit pack carries the coverage attestation including unscanned
//	  repositories, and regenerates byte-identically;
//	an over-limit request is rejected with the limit stated.

// --- SLA is computed into the store (OQ-P7-03) -----------------------------

// slaFixture seeds a finding detected long ago and runs the pipeline pass that
// scores and computes SLA.
//
// Ground truth is the scanner input: the raw finding written in, and the
// detection time the store recorded from it. Nothing here reads a figure the
// report produced and compares it to itself.
func slaFixture(t *testing.T, s store.Store, detectedAt time.Time, reason *model.ReasonCode) (string, string) {
	t.Helper()
	ctx := context.Background()

	raw := dep("org/a", "GO-2025-0001")
	fp := fingerprint.Compute(raw)

	// Detection happened long ago: the SLA clock starts at detection
	// (VM-NF-302), so the store's clock is wound back for the write.
	switch impl := s.(type) {
	case *store.Memory:
		impl.SetClock(func() time.Time { return detectedAt })
	case *store.Postgres:
		impl.SetClock(func() time.Time { return detectedAt })
	}

	f := seed(t, s, store.KindSweep, []model.RawFinding{raw},
		map[string]model.ScanOutcome{"org/a": model.ScanComplete})

	// Restore a present-day clock for everything after detection.
	now := detectedAt.Add(400 * 24 * time.Hour)
	switch impl := s.(type) {
	case *store.Memory:
		impl.SetClock(func() time.Time { return now })
	case *store.Postgres:
		impl.SetClock(func() time.Time { return now })
	}

	if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{
		Actor: model.ActorTriage, Cause: "test", At: now,
	}); err != nil {
		t.Fatalf("triage: %v", err)
	}
	if reason != nil {
		if err := s.SetPriority(ctx, fp, model.P1, reason); err != nil {
			t.Fatalf("set reason: %v", err)
		}
	}

	// The pipeline pass that persists priority now also persists SLA.
	cal := calibration(t)
	pol, err := policy.LoadConfig("../../config/policy.yaml")
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	o := orchestrator.New(s, orchestrator.NewFakeDispatcher(), orchestrator.NewRateBudget(10), orchestrator.Config{})
	o.Clock = func() time.Time { return now }

	repo, err := s.GetRepo(ctx, "org/a")
	if err != nil {
		t.Fatalf("get repo: %v", err)
	}
	tr := &triage.Triager{Client: triage.NewFakeClient(), Cache: triage.NewMemoryCache(), Model: "m",
		Clock: func() time.Time { return now }}

	stats, err := o.TriageAndRoute(ctx, repo, tr, score.New(cal), policy.New(pol), routeView{})
	if err != nil {
		t.Fatalf("TriageAndRoute: %v", err)
	}
	if stats.SLAComputed == 0 {
		t.Fatal("the pipeline pass computed no SLA at all")
	}
	return f.runID, fp
}

type routeView struct{}

func (routeView) HasOpenPullRequest(string) bool        { return false }
func (routeView) IsFirstPartyOwner(string, string) bool { return false }

// TestBreachedSLAProducesANonZeroBreachCount is the gate clause. Not "the field
// is populated" — an actual breach, actually counted.
func TestBreachedSLAProducesANonZeroBreachCount(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		detected := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		runID, fp := slaFixture(t, s, detected, nil)

		// Ground truth: the store's own detection timestamp, and the window the
		// windows table gives for this finding's tier and priority.
		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		if f.FirstSeenAt.IsZero() {
			t.Fatal("the store holds no detection timestamp; the SLA clock has nothing to start from (VM-NF-302)")
		}
		if f.Derived.SLAStatus == "" {
			t.Fatal("SLA was not persisted; the report would read '0 breached' because nobody looked (OQ-P7-03)")
		}
		if f.Derived.SLAStatus != model.SLABreached {
			t.Fatalf("SLA status = %q, want breached for a finding detected %v ago",
				f.Derived.SLAStatus, 400*24*time.Hour)
		}

		rep := generate(t, s, runID)
		if rep.Counts.SLABreached == 0 {
			t.Fatal("the report shows 0 breached for a genuinely breached finding")
		}
		if rep.Counts.SLANotComputed != 0 {
			t.Errorf("sla_not_computed = %d, want 0 once the pipeline has run", rep.Counts.SLANotComputed)
		}

		issued, err := report.Issue(rep)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		md := string(issued.Markdown)
		if !strings.Contains(md, "**SLA breached:** 1") {
			t.Errorf("the rendered report does not show the breach:\n%s", sectionOf(md, "Outstanding risk"))
		}
	})
}

// TestNoUpstreamFixPausesTheClockEndToEnd covers VM-NF-304 through the pipeline
// rather than against the function.
func TestNoUpstreamFixPausesTheClockEndToEnd(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		detected := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		reason := model.ReasonNoUpstreamFix
		runID, fp := slaFixture(t, s, detected, &reason)

		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		if f.Derived.SLAStatus != model.SLAPaused {
			t.Fatalf("SLA status = %q, want paused — a finding with no upstream fix can never breach (VM-NF-304, VM-F-909)",
				f.Derived.SLAStatus)
		}
		if f.Derived.SLABreachDays != 0 {
			t.Errorf("breach days = %d on a paused finding", f.Derived.SLABreachDays)
		}

		rep := generate(t, s, runID)
		if rep.Counts.SLABreached != 0 {
			t.Errorf("a paused finding was counted as breached")
		}
		if rep.Counts.SLAPaused != 1 {
			t.Errorf("sla_paused = %d, want 1", rep.Counts.SLAPaused)
		}
	})
}

// TestUncomputedSLARendersAsNotComputedNeverAsZeroBreaches is the clause that
// makes the difference between an absent measurement and a clean bill of health
// legible.
func TestUncomputedSLARendersAsNotComputedNeverAsZeroBreaches(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		// A run with findings that the pipeline pass has NOT scored.
		f := seed(t, s, store.KindSweep, []model.RawFinding{dep("org/a", "GO-2025-0001")},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})

		rep := generate(t, s, f.runID)
		if rep.Counts.SLANotComputed != rep.Counts.Total {
			t.Fatalf("sla_not_computed = %d of %d; the fixture should have no computed SLA",
				rep.Counts.SLANotComputed, rep.Counts.Total)
		}

		issued, err := report.Issue(rep)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		md := string(issued.Markdown)

		if !strings.Contains(md, "SLA: not computed") {
			t.Errorf("the report does not say the SLA was not computed:\n%s", sectionOf(md, "Outstanding risk"))
		}
		// The reassuring zero must not appear: it is an assurance claim nobody
		// is entitled to make.
		if strings.Contains(md, "**SLA breached:** 0") {
			t.Error("the report presents '0 breached' while no SLA was computed; " +
				"a reader cannot tell that from 'nothing is late' (OQ-P7-03)")
		}
		if !strings.Contains(md, "absence of one") {
			t.Error("the report does not explain that this is the absence of a statement, not a statement")
		}
	})
}

// TestPartiallyComputedSLAIsQualified covers the middle case: some computed,
// some not. The breach figure must say what it is a figure over.
func TestPartiallyComputedSLAIsQualified(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		a := dep("org/a", "GO-2025-0001")
		b := dep("org/a", "GO-2025-0002")
		b.Module = "golang.org/x/net"

		f := seed(t, s, store.KindSweep, []model.RawFinding{a, b},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})

		// Compute SLA for one of the two only.
		if err := s.SetSLA(ctx, fingerprint.Compute(a), model.Derived{SLAStatus: model.SLAWithin}); err != nil {
			t.Fatalf("set sla: %v", err)
		}

		rep := generate(t, s, f.runID)
		if rep.Counts.SLANotComputed != 1 {
			t.Fatalf("sla_not_computed = %d, want 1", rep.Counts.SLANotComputed)
		}

		issued, _ := report.Issue(rep)
		md := string(issued.Markdown)
		if !strings.Contains(md, "were not computed and are excluded") {
			t.Errorf("a partially computed SLA is presented without qualification:\n%s", sectionOf(md, "Outstanding risk"))
		}
	})
}

// --- Privilege and redaction ------------------------------------------------

// TestDeliveryFailsClosedOnUndeterminedPrivilege is the load-bearing clause.
// The failure mode of a permissions system must never be "grant more".
func TestDeliveryFailsClosedOnUndeterminedPrivilege(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		f := seed(t, s, store.KindSweep, []model.RawFinding{dep("org/a", "GO-2025-0001")},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})
		rep := generate(t, s, f.runID)

		pub := report.NewFakePublisher()
		_, err := report.Deliver(ctx, pub, "deliveries/unknown", rep, report.Undetermined("someone@example.com"))
		if err == nil {
			t.Fatal("a report was delivered to a recipient whose privilege could not be determined")
		}
		var undetermined *report.ErrPrivilegeUndetermined
		if !asErr(err, &undetermined) {
			t.Errorf("got %T, want *ErrPrivilegeUndetermined", err)
		}
		// Nothing was written: failing closed means nothing leaves, not that a
		// smaller thing leaves.
		if len(pub.Paths()) != 0 {
			t.Errorf("artifacts were published despite the failure: %v", pub.Paths())
		}

		// A recipient with a level but no determination is equally refused: the
		// two fields exist so "we could not find out" is representable.
		_, err = report.Deliver(ctx, pub, "deliveries/x", rep,
			report.Recipient{ID: "x", Level: report.LevelSecurityOwner})
		if err == nil {
			t.Error("a recipient with Determined=false was delivered to on the strength of its Level field")
		}
	})
}

// TestSecretDetailIsWithheldBelowSecurityOwner covers the U8 rule: the count is
// visible, the detail is not.
func TestSecretDetailIsWithheldBelowSecurityOwner(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()

		secret := model.RawFinding{
			Repo: "org/a", Category: model.CategorySecret, Tool: "gitleaks", ToolVersion: "v8.30.1",
			DetectorRuleID: "aws-access-token", File: "config/settings.yaml", Line: 17,
			CredentialType: "aws-access-token",
			Classification: model.Classification{
				Severity: model.SeverityCritical, Reachable: model.ReachableUnknown,
				DepClass: model.DepNotApplicable,
			},
		}
		f := seed(t, s, store.KindSweep, []model.RawFinding{secret, dep("org/a", "GO-2025-0001")},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})
		rep := generate(t, s, f.runID)

		// Ground truth from the scanner input: the file the secret was found in.
		const secretPath = "config/settings.yaml"

		owner, err := report.Deliver(ctx, nil, "", rep, report.SecurityOwner("sec@example.com"))
		if err != nil {
			t.Fatalf("deliver to owner: %v", err)
		}
		if !strings.Contains(string(owner.Issued.JSON), secretPath) {
			t.Error("a security owner's rendering withholds the secret's location")
		}
		if owner.Redacted {
			t.Error("a security owner's rendering is redacted")
		}

		engineer, err := report.Deliver(ctx, nil, "", rep,
			report.Recipient{ID: "eng@example.com", Level: report.LevelEngineer, Determined: true})
		if err != nil {
			t.Fatalf("deliver to engineer: %v", err)
		}
		if strings.Contains(string(engineer.Issued.JSON), secretPath) {
			t.Error("an engineer's rendering leaks the secret's location (U8)")
		}
		if !engineer.Redacted || engineer.Withheld != 1 {
			t.Errorf("the engineer's rendering is not marked redacted: redacted=%v withheld=%d",
				engineer.Redacted, engineer.Withheld)
		}
		// The count is still visible: that is what tells an engineer secrets
		// exist in their repository at all.
		if engineer.Issued.Report.Counts.ByCategory["secret"] != 1 {
			t.Error("the secret count was redacted away; the count is what tells an engineer secrets exist")
		}
		// And the report says redaction occurred rather than silently omitting.
		if !strings.Contains(string(engineer.Issued.Markdown), "redacted") {
			t.Error("the redacted rendering does not say that it is redacted (VM-F-75x)")
		}

		// Public: aggregates only.
		public, err := report.Deliver(ctx, nil, "", rep,
			report.Recipient{ID: "all@example.com", Level: report.LevelPublic, Determined: true})
		if err != nil {
			t.Fatalf("deliver public: %v", err)
		}
		if len(public.Issued.Report.Findings) != 0 {
			t.Error("the public rendering carries finding detail")
		}
		if public.Issued.Report.Counts.Total != rep.Counts.Total {
			t.Error("the public rendering under-counts; redaction withholds detail, it does not change the figures")
		}
	})
}

// TestSecretScanRunsAgainstTheLeastPrivilegedRendering covers the constraint
// directly: the artifact that travels furthest is the one that is checked.
func TestSecretScanRunsAgainstTheLeastPrivilegedRendering(t *testing.T) {
	const planted = "REDACTED-FAKE-AWS-KEY-ID"

	// A credential that exists ONLY in the least-privileged rendering: it rides
	// in on a coverage field, which redaction keeps while dropping the findings
	// that a fuller rendering would have shown.
	rep := report.Report{
		Kind: report.KindFleet, AnchorRun: "S-000001",
		Findings: []report.FindingRow{
			{Fingerprint: "fp1", Repo: "org/a", Category: "dependency", State: "TRIAGED"},
		},
		Coverage: report.Coverage{
			InScope: 1, Complete: 0,
			UnscannedRepos: []string{"org/" + planted},
		},
	}

	if err := report.AssertLeastPrivilegedRenderingIsClean(rep); err == nil {
		t.Fatal("the least-privileged rendering was not scanned; it is the artifact that travels furthest")
	}

	// And delivery at that level refuses too.
	_, err := report.Deliver(context.Background(), nil, "", rep,
		report.Recipient{ID: "all", Level: report.LevelPublic, Determined: true})
	if err == nil {
		t.Fatal("a least-privileged rendering carrying a credential was delivered")
	}
	var credErr *report.ErrCredentialInReport
	if !asCredErr(err, &credErr) {
		t.Errorf("got %T, want *ErrCredentialInReport", err)
	}
}

func TestEveryRenderingLevelIsScanned(t *testing.T) {
	const planted = "REDACTED-FAKE-GITHUB-TOKEN"

	for _, level := range report.AllLevels {
		t.Run(level.String(), func(t *testing.T) {
			rep := report.Report{
				Kind: report.KindFleet, AnchorRun: "S-000001",
				// In a field every level keeps.
				Coverage: report.Coverage{InScope: 1, UnscannedRepos: []string{"org/" + planted}},
				Findings: []report.FindingRow{{Fingerprint: "fp1", Repo: "org/a", Category: "dependency", State: "TRIAGED"}},
			}
			_, err := report.Deliver(context.Background(), nil, "", rep,
				report.Recipient{ID: "x", Level: level, Determined: true})
			if err == nil {
				t.Errorf("a %s rendering carrying a credential was delivered", level)
			}
		})
	}
}

// --- Over-limit -------------------------------------------------------------

func TestOverLimitRequestIsRejectedWithTheLimitStated(t *testing.T) {
	rep := report.Report{Kind: report.KindFleet, AnchorRun: "S-000001"}
	for i := 0; i <= report.MaxFindingsPerReport; i++ {
		rep.Findings = append(rep.Findings, report.FindingRow{
			Fingerprint: fmtInt(i), Repo: "org/a", Category: "dependency", State: "TRIAGED",
		})
	}

	_, err := report.Deliver(context.Background(), nil, "", rep, report.SecurityOwner("sec"))
	if err == nil {
		t.Fatal("an over-limit request was served")
	}
	var over *report.ErrOverLimit
	if !asOverLimit(err, &over) {
		t.Fatalf("got %T, want *ErrOverLimit", err)
	}
	// The limit must be stated, not merely exceeded — a rejection that does not
	// say the limit leaves the caller guessing.
	if !strings.Contains(err.Error(), fmtInt(report.MaxFindingsPerReport)) {
		t.Errorf("the rejection does not state the limit: %v", err)
	}
	if over.Limit != report.MaxFindingsPerReport {
		t.Errorf("limit = %d, want %d", over.Limit, report.MaxFindingsPerReport)
	}
}

// --- Audit packs ------------------------------------------------------------

// TestAuditPackCarriesTheCoverageAttestationIncludingUnscannedRepos is v1.0
// acceptance criterion 15. An evidence pack that lists only what was covered
// invites the reader to assume the rest was clean.
func TestAuditPackCarriesTheCoverageAttestationIncludingUnscannedRepos(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		f := seed(t, s, store.KindSweep,
			[]model.RawFinding{dep("org/ok", "GO-2025-0001")},
			map[string]model.ScanOutcome{
				"org/ok":     model.ScanComplete,
				"org/failed": model.ScanFailed,
			})
		rep := generate(t, s, f.runID)

		pack, err := report.BuildAuditPack(rep, report.LevelSecurityOwner)
		if err != nil {
			t.Fatalf("BuildAuditPack: %v", err)
		}

		if pack.AnchorRun != f.runID {
			t.Errorf("anchor = %q, want %q", pack.AnchorRun, f.runID)
		}
		// The unscanned repository is NAMED, not merely counted.
		var found bool
		for _, r := range pack.Attestation.UnscannedRepos {
			if r == "org/failed" {
				found = true
			}
		}
		if !found {
			t.Errorf("the attestation does not name the unscanned repository: %v", pack.Attestation.UnscannedRepos)
		}
		// And the statement says what is NOT claimed.
		if !strings.Contains(pack.Attestation.Statement, "no claim is made about their contents") {
			t.Errorf("the attestation does not state the limits of its claim: %q", pack.Attestation.Statement)
		}
		if !strings.Contains(pack.Attestation.Statement, "planned scope") {
			t.Error("the attestation does not say coverage is measured against planned scope")
		}
		if pack.ContentHash == "" {
			t.Error("the pack has no content hash")
		}
		if len(pack.Artifacts) == 0 {
			t.Error("the pack lists no per-artifact hashes")
		}
	})
}

// TestAuditPackRegeneratesByteIdentically is the §17 Phase 7b clause and the
// VM-ADR-15 property: a pack that cannot be regenerated cannot be cited.
func TestAuditPackRegeneratesByteIdentically(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		f := seed(t, s, store.KindSweep,
			[]model.RawFinding{dep("org/ok", "GO-2025-0001")},
			map[string]model.ScanOutcome{"org/ok": model.ScanComplete, "org/failed": model.ScanFailed})

		rep := generate(t, s, f.runID)
		first, err := report.BuildAuditPack(rep, report.LevelSecurityOwner)
		if err != nil {
			t.Fatalf("BuildAuditPack: %v", err)
		}

		// Regenerate from the stored query alone, through a fresh generator.
		g := report.NewGenerator(s, calibration(t))
		g.Clock = func() time.Time { return base }
		again, err := g.Generate(ctx, first.Query)
		if err != nil {
			t.Fatalf("regenerate: %v", err)
		}
		second, err := report.BuildAuditPack(again, report.LevelSecurityOwner)
		if err != nil {
			t.Fatalf("rebuild: %v", err)
		}

		if second.ContentHash != first.ContentHash {
			t.Errorf("audit pack does not regenerate byte-identically:\n first  %s\n second %s",
				first.ContentHash, second.ContentHash)
		}
		for name, hash := range first.Artifacts {
			if second.Artifacts[name] != hash {
				t.Errorf("artifact %s differs: %s vs %s", name, hash, second.Artifacts[name])
			}
		}
	})
}

// TestAuditPackAtEachLevelIsInternallyConsistent checks the redacted packs
// declare their own redaction rather than presenting as complete.
func TestAuditPackAtEachLevelIsInternallyConsistent(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		secret := model.RawFinding{
			Repo: "org/a", Category: model.CategorySecret, Tool: "gitleaks", ToolVersion: "v8.30.1",
			DetectorRuleID: "aws-access-token", File: "config/settings.yaml", Line: 17,
			CredentialType: "aws-access-token",
			Classification: model.Classification{
				Severity: model.SeverityCritical, Reachable: model.ReachableUnknown,
				DepClass: model.DepNotApplicable,
			},
		}
		f := seed(t, s, store.KindSweep, []model.RawFinding{secret},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})
		rep := generate(t, s, f.runID)

		for _, level := range report.AllLevels {
			pack, err := report.BuildAuditPack(rep, level)
			if err != nil {
				t.Fatalf("%s: %v", level, err)
			}
			redacted := level < report.LevelSecurityOwner
			if pack.Report.Redacted != redacted {
				t.Errorf("%s: redacted = %v, want %v", level, pack.Report.Redacted, redacted)
			}
			if redacted && !strings.Contains(pack.Attestation.Statement, "redacted") {
				t.Errorf("%s: the attestation does not disclose that the rendering is redacted", level)
			}
			// Coverage figures are identical at every level: redaction withholds
			// detail, it does not change the fleet.
			if pack.Attestation.InScope != rep.Coverage.InScope {
				t.Errorf("%s: in_scope = %d, want %d — redaction must not alter coverage",
					level, pack.Attestation.InScope, rep.Coverage.InScope)
			}
		}
	})
}

func TestAuditPackIsPublishedWithItsArtifacts(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		f := seed(t, s, store.KindSweep, []model.RawFinding{dep("org/a", "GO-2025-0001")},
			map[string]model.ScanOutcome{"org/a": model.ScanComplete})
		rep := generate(t, s, f.runID)

		pack, err := report.BuildAuditPack(rep, report.LevelSecurityOwner)
		if err != nil {
			t.Fatalf("BuildAuditPack: %v", err)
		}
		issued, err := report.Issue(rep)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}

		pub := report.NewFakePublisher()
		if err := report.PublishAuditPack(ctx, pub, pack, issued); err != nil {
			t.Fatalf("PublishAuditPack: %v", err)
		}
		want := []string{
			"audit/" + pack.ID + "/pack.json",
			"audit/" + pack.ID + "/report.json",
			"audit/" + pack.ID + "/report.md",
		}
		got := pub.Paths()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("published %v, want %v", got, want)
		}
		for path, body := range pub.All() {
			if err := report.AssertNoCredentials(path, body); err != nil {
				t.Errorf("%s: %v", path, err)
			}
		}
	})
}

// --- helpers ----------------------------------------------------------------

func sectionOf(md, heading string) string {
	i := strings.Index(md, "## "+heading)
	if i < 0 {
		return md
	}
	rest := md[i:]
	if j := strings.Index(rest[3:], "\n## "); j > 0 {
		return rest[:j]
	}
	return rest
}

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func asErr(err error, target **report.ErrPrivilegeUndetermined) bool {
	for err != nil {
		if e, ok := err.(*report.ErrPrivilegeUndetermined); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func asOverLimit(err error, target **report.ErrOverLimit) bool {
	for err != nil {
		if e, ok := err.(*report.ErrOverLimit); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func asCredErr(err error, target **report.ErrCredentialInReport) bool {
	for err != nil {
		if e, ok := err.(*report.ErrCredentialInReport); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
