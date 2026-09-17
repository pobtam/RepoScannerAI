package tracker_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/tracker"
)

// Phase 8 gate:
//
//	three consecutive runs produce exactly one ticket per finding;
//	Find locates an existing ticket after the local record is deleted;
//	a finding reaching VERIFIED closes its ticket, carrying verified_reason;
//	a secret finding's ticket never carries the secret value;
//	every real backend sits behind the interface with a fake, and the local
//	  record survives reprojection.

const repo = "org/wanaware-api"

func newStore(t *testing.T) store.Store {
	t.Helper()
	s := store.NewMemory()
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := s.UpsertRepo(context.Background(), store.Repo{
		Name: repo, Tier: 1, Languages: []string{"go"}, HasTestSuite: true,
	}); err != nil {
		t.Fatalf("upsert repo: %v", err)
	}
	return s
}

func depFinding() model.RawFinding {
	return model.RawFinding{
		Repo: repo, Category: model.CategoryDependency,
		PrimaryID: "GO-2025-3106", Aliases: []string{"CVE-2025-22869"},
		Module: "golang.org/x/crypto", ModuleMajor: "v0",
		Tool: "govulncheck", ToolVersion: "v1.8.0",
		Versions:       model.Versions{Current: "v0.35.0", Fixed: "v0.36.0"},
		Classification: model.Classification{Severity: model.SeverityHigh, Reachable: model.ReachableTrue, DepClass: model.DepProduction},
	}
}

// observeIn runs one scan of the repository, as a sweep would.
func observeIn(t *testing.T, s store.Store, raws []model.RawFinding) string {
	t.Helper()
	ctx := context.Background()
	r, err := s.CreateRun(ctx, store.KindSweep, "cron", "img@sha256:abc", map[string]string{"govulncheck": "v1.8.0"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := s.RecordPlan(ctx, []store.PlanEntry{{RunID: r.ID, Repo: repo, State: store.DispatchPlanned}}); err != nil {
		t.Fatalf("record plan: %v", err)
	}
	if _, err := s.UpsertObservations(ctx, r.ID, repo, raws); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.RecordScanResult(ctx, store.RepoScanResult{
		RunID: r.ID, Repo: repo, Outcome: model.ScanComplete,
		ToolsOK: []string{"govulncheck", "gitleaks"},
	}); err != nil {
		t.Fatalf("record scan result: %v", err)
	}
	if _, err := s.Reconcile(ctx, r.ID, repo); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return r.ID
}

func service(s store.Store, tr tracker.Tracker) *tracker.Service {
	return &tracker.Service{
		Tracker: tr, Store: s,
		Clock: func() time.Time { return time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC) },
	}
}

func specFor(t *testing.T, s store.Store, fp string) tracker.Spec {
	t.Helper()
	f, err := s.GetFinding(context.Background(), fp)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	spec, err := tracker.SpecFor(f, tracker.SpecOptions{
		ReportURL: "https://reports.example/runs/S-000001/fleet.md",
		Assignee:  "team-api",
	})
	if err != nil {
		t.Fatalf("SpecFor: %v", err)
	}
	return spec
}

// --- Clause 1: exactly one ticket per finding ------------------------------

// TestThreeConsecutiveRunsProduceExactlyOneTicket is the ticketing analogue of
// upsert-not-duplicate. The finding is observed by three separate runs and the
// ticket pass runs after each; a second issue for the same fingerprint is the
// failure every on-call engineer recognises as "the scanner is spamming us",
// and it is what VM-F-804 exists to prevent.
func TestThreeConsecutiveRunsProduceExactlyOneTicket(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	fake := tracker.NewFake("github")
	svc := service(s, fake)

	fp := fingerprint.Compute(depFinding())
	var refs []tracker.Ref
	for i := 0; i < 3; i++ {
		observeIn(t, s, []model.RawFinding{depFinding()})
		ref, created, err := svc.Ensure(ctx, specFor(t, s, fp))
		if err != nil {
			t.Fatalf("run %d: Ensure: %v", i+1, err)
		}
		if i == 0 && !created {
			t.Error("the first run did not create a ticket")
		}
		if i > 0 && created {
			t.Errorf("run %d created a second ticket for the same fingerprint (VM-F-804)", i+1)
		}
		refs = append(refs, ref)
	}

	if n := fake.CreateCount(); n != 1 {
		t.Errorf("the backend received %d create calls across three runs, want 1", n)
	}
	// The LOCAL RECORD must be the mechanism, not the backend query. Both
	// prevent a duplicate, so a count of tickets alone cannot tell them apart:
	// with the record bypassed this test would still see one ticket, while
	// production quietly issued a search API call per finding per run and the
	// primary mechanism went unexercised. Exactly one lookup — the one before
	// the ticket existed — is the assertion that separates them.
	if n := fake.FindCount(); n != 1 {
		t.Errorf("the backend was queried %d times across three runs, want 1. "+
			"The local record is the primary idempotency mechanism (VM-F-804); the backend query is the "+
			"reconciliation fallback, and a run that re-queries it every time is not using the record at all", n)
	}
	for i, ref := range refs[1:] {
		if ref != refs[0] {
			t.Errorf("run %d returned ref %+v, want the original %+v", i+2, ref, refs[0])
		}
	}
	if n := len(fake.Tickets()); n != 1 {
		t.Errorf("the backend holds %d tickets, want 1", n)
	}
	// The backend does not deduplicate — real ones do not either — so this is
	// the assertion that would actually catch a second Create.
	if opened := fake.TicketsFor(fp); len(opened) != 1 {
		t.Errorf("%d tickets were opened for one fingerprint: %v (VM-F-804)", len(opened), opened)
	}
}

// --- Clause 2: reconciliation from the backend of record -------------------

// TestFindReconcilesAfterTheLocalRecordIsLost is the data-loss clause. The
// local record is the fast path, not the truth: if a restore, a migration or a
// bug loses it, the system must ask the backend rather than assume absence
// means "no ticket". Assuming absence here has exactly the shape of assuming
// absence in a scan — it manufactures a duplicate instead of a false
// resolution, but the reasoning error is the same one (VM-ADR-12).
func TestFindReconcilesAfterTheLocalRecordIsLost(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	fake := tracker.NewFake("github")
	svc := service(s, fake)

	fp := fingerprint.Compute(depFinding())
	observeIn(t, s, []model.RawFinding{depFinding()})
	original, _, err := svc.Ensure(ctx, specFor(t, s, fp))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	// Lose the local mirror entirely.
	if err := s.DeleteTicket(ctx, fp); err != nil {
		t.Fatalf("DeleteTicket: %v", err)
	}
	if _, ok, _ := s.GetTicket(ctx, fp); ok {
		t.Fatal("the local record was not actually deleted; the test proves nothing")
	}

	observeIn(t, s, []model.RawFinding{depFinding()})
	recovered, created, err := svc.Ensure(ctx, specFor(t, s, fp))
	if err != nil {
		t.Fatalf("Ensure after data loss: %v", err)
	}
	if created {
		t.Error("a lost local record produced a duplicate ticket; Find is the reconciliation path (VM-F-805)")
	}
	if recovered != original {
		t.Errorf("recovered ref %+v, want %+v", recovered, original)
	}
	if n := fake.CreateCount(); n != 1 {
		t.Errorf("the backend received %d create calls, want 1", n)
	}
	// And the local record is rebuilt, so the next run takes the fast path.
	if _, ok, err := s.GetTicket(ctx, fp); err != nil || !ok {
		t.Error("reconciliation did not restore the local record; every subsequent run would re-query the backend")
	}

	// Reconciliation must not depend on title or body text (VM-F-805): the
	// fingerprint carrier is the only thing it may match on.
	if fake.LastFindQuery() != fp {
		t.Errorf("Find was queried with %q, want the fingerprint %q", fake.LastFindQuery(), fp)
	}
}

// --- Clause 3: VERIFIED closes the ticket, honestly -------------------------

// TestVerifiedFindingClosesItsTicketWithHonestAttribution covers VM-F-811 and
// carries VM-ADR-12 to the tracker boundary: the ticket closes because a
// successful scan stopped seeing the finding, and the closing comment says WHO
// fixed it. A ticket closed with "fixed by automation" when an engineer fixed
// it upstream is a false record in the system of record people actually read.
func TestVerifiedFindingClosesItsTicketWithHonestAttribution(t *testing.T) {
	// Each case names the attribution it must carry AND the attributions it must
	// not. A positive substring check alone is not enough here: the comment also
	// prints `verified_reason=upstream`, so looking for "upstream" would match
	// the machine field while the prose claimed the framework fixed it — which
	// is precisely the false record this clause exists to prevent.
	reasons := []struct {
		name    string
		walk    []model.State
		reason  model.VerificationReason
		want    string
		mustNot []string
	}{
		{"framework merge", []model.State{model.Triaged, model.AutoRemediating, model.PROpen, model.Merged},
			model.VerifiedByFrameworkMerge, "merged by this framework",
			[]string{"fixed upstream", "outside this framework"}},
		{"upstream first-party fix", []model.State{model.Triaged, model.BlockedUpstream},
			model.VerifiedByUpstream, "fixed upstream",
			[]string{"merged by this framework", "outside this framework"}},
		{"fixed by someone else", []model.State{model.Triaged},
			model.VerifiedExternal, "outside this framework",
			[]string{"merged by this framework", "fixed upstream"}},
	}
	for _, tc := range reasons {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := newStore(t)
			fake := tracker.NewFake("github")
			svc := service(s, fake)

			fp := fingerprint.Compute(depFinding())
			observeIn(t, s, []model.RawFinding{depFinding()})
			ref, _, err := svc.Ensure(ctx, specFor(t, s, fp))
			if err != nil {
				t.Fatalf("Ensure: %v", err)
			}
			walk(t, s, fp, tc.walk)

			// Ground truth is the scan: a later run completes successfully and
			// does not observe the finding, which is the only thing that may
			// verify it (VM-ADR-12). Nothing here sets the state by hand.
			observeIn(t, s, nil)

			f, err := s.GetFinding(ctx, fp)
			if err != nil {
				t.Fatalf("get finding: %v", err)
			}
			if f.State != model.Verified {
				t.Fatalf("state = %q, want VERIFIED after a successful scan stopped seeing it", f.State)
			}
			if f.VerifiedReason == nil || *f.VerifiedReason != tc.reason {
				t.Fatalf("verified_reason = %v, want %q", f.VerifiedReason, tc.reason)
			}

			if err := svc.CloseVerified(ctx, f); err != nil {
				t.Fatalf("CloseVerified: %v", err)
			}

			if got := fake.State(ref); got != tracker.StateClosed {
				t.Errorf("ticket state = %q, want closed (VM-F-811)", got)
			}
			body := strings.Join(fake.Comments(ref), "\n")
			if !strings.Contains(strings.ToLower(body), tc.want) {
				t.Errorf("the closing comment does not attribute the fix honestly.\nwant mention of %q, got:\n%s", tc.want, body)
			}
			for _, forbidden := range tc.mustNot {
				if strings.Contains(strings.ToLower(body), forbidden) {
					t.Errorf("the closing comment claims %q for a finding verified as %s; "+
						"a ticket closed with the wrong attribution is a false record in the system people read:\n%s",
						forbidden, tc.reason, body)
				}
			}
			if !strings.Contains(body, string(tc.reason)) {
				t.Errorf("the closing comment does not carry verified_reason=%s:\n%s", tc.reason, body)
			}
			if !strings.Contains(strings.ToLower(body), "scan") {
				t.Errorf("the closing comment does not say a scan confirmed it; absence is not resolution (VM-ADR-12):\n%s", body)
			}

			// And the local record records the closure.
			rec, ok, err := s.GetTicket(ctx, fp)
			if err != nil || !ok {
				t.Fatalf("GetTicket = (%v, %v)", ok, err)
			}
			if rec.ClosedAt == nil {
				t.Error("the local record does not show the ticket closed")
			}
		})
	}
}

// TestUnverifiedFindingCannotCloseItsTicket is the other half. Closing on
// anything short of VERIFIED would let a merged-but-unconfirmed fix close the
// ticket, which is the failure VM-NF-303 and VM-ADR-12 both name.
func TestUnverifiedFindingCannotCloseItsTicket(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	fake := tracker.NewFake("github")
	svc := service(s, fake)

	fp := fingerprint.Compute(depFinding())
	observeIn(t, s, []model.RawFinding{depFinding()})
	ref, _, err := svc.Ensure(ctx, specFor(t, s, fp))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	for _, st := range []model.State{model.Detected, model.Triaged, model.Merged, model.NeedsHuman} {
		f, err := s.GetFinding(ctx, fp)
		if err != nil {
			t.Fatalf("get finding: %v", err)
		}
		f.State = st
		err = svc.CloseVerified(ctx, f)
		if !errors.Is(err, tracker.ErrNotVerified) {
			t.Errorf("CloseVerified in state %s returned %v, want ErrNotVerified", st, err)
		}
	}
	if got := fake.State(ref); got != tracker.StateOpen {
		t.Errorf("the ticket closed without verification: state = %q", got)
	}
}

// --- Clause 4: a secret's ticket never carries the value --------------------

// TestSecretTicketNeverCarriesTheValue anchors at SCANNER INPUT.
//
// Ground truth is the gitleaks fixture, which contains real credential strings
// in its Secret and Match fields. The value is followed from the raw tool
// output, through the adapter, the store and the spec builder, to the bytes the
// backend receives. Asserting against the model's fields would only prove the
// model agrees with itself; the tool output is the last place the value
// genuinely exists.
func TestSecretTicketNeverCarriesTheValue(t *testing.T) {
	ctx := context.Background()

	rawOutput, err := os.ReadFile("../../testdata/fixtures/gitleaks/go-api.json")
	if err != nil {
		t.Fatalf("reading the gitleaks fixture: %v", err)
	}
	// The literal secrets the scanner reported. If the fixture ever stops
	// containing a real-looking credential, this test is vacuous, so it checks.
	secrets := []string{"REDACTED-FAKE-AWS-SECRET", "REDACTED-FAKE-AWS-KEY-ID"}
	for _, secret := range secrets {
		if !strings.Contains(string(rawOutput), secret) {
			t.Fatalf("the fixture no longer contains %q; this test would pass vacuously", secret)
		}
	}

	a := adapters.NewGitleaks(nil, "v8.30.1")
	raws, err := a.Normalize(scan.RawOutput{
		Tool: "gitleaks", ToolVersion: "v8.30.1", Repo: repo, Stdout: rawOutput,
	})
	if err != nil {
		t.Fatalf("normalising gitleaks output: %v", err)
	}
	if len(raws) == 0 {
		t.Fatal("the adapter produced no findings from a fixture containing secrets")
	}

	s := newStore(t)
	observeIn(t, s, raws)

	fake := tracker.NewFake("github")
	svc := service(s, fake)

	for _, raw := range raws {
		fp := fingerprint.Compute(raw)
		spec := specFor(t, s, fp)
		if _, _, err := svc.Ensure(ctx, spec); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
	}

	// Everything the backend was handed, plus everything the store kept.
	haystack := fake.Everything()
	findings, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	for _, f := range findings {
		haystack += " " + f.Repo + " " + f.CredentialType + " " + derefString(f.Location.File)
	}

	for _, secret := range secrets {
		if strings.Contains(haystack, secret) {
			t.Errorf("the secret value %q reached the tracker or the store (VM-F-263, VM-F-703)", secret)
		}
		// A prefix long enough to be useful is also a leak.
		if len(secret) >= 12 && strings.Contains(haystack, secret[:12]) {
			t.Errorf("a 12-character prefix of %q reached the tracker; a partial credential is still a credential", secret)
		}
	}

	// The ticket must still be useful: location, type, and the rotation notice
	// (VM-F-856). Withholding the value is not withholding the finding.
	all := fake.Everything()
	for _, want := range []string{"config/settings.yaml", "aws-access-token", "rotat"} {
		if !strings.Contains(strings.ToLower(all), strings.ToLower(want)) {
			t.Errorf("the secret ticket does not mention %q; it names no actionable detail", want)
		}
	}
	if !strings.Contains(strings.ToLower(all), "does not constitute remediation") {
		t.Error("the ticket does not say that removing the secret from source is not remediation (VM-F-856)")
	}
}

// TestSpecBuilderRefusesCredentialMaterial is the belt to that braces. The
// model cannot represent a secret value, but a caller can still write one into
// a title or body by hand — from a commit message, a log line, a triage
// narrative. The spec builder refuses rather than trusting the caller.
func TestSpecBuilderRefusesCredentialMaterial(t *testing.T) {
	spec := tracker.Spec{
		Fingerprint: "abc123", Title: "Leaked key",
		Body:      "Found REDACTED-AWS-EXAMPLE-KEY-ID in config",
		Repo:      repo,
		ReportURL: "https://reports.example/x",
	}
	if err := spec.Validate(); err == nil {
		t.Error("a spec carrying credential material validated")
	}
}

// TestEveryTicketLinksItsReport covers VM-F-809. A ticket without the report
// link sends the reader back to a dashboard to find out what it is about, and
// the link is the only thing tying the ticket to the immutable evidence.
func TestEveryTicketLinksItsReport(t *testing.T) {
	spec := tracker.Spec{Fingerprint: "abc123", Title: "t", Body: "b", Repo: repo}
	if err := spec.Validate(); err == nil {
		t.Error("a spec with no report URL validated (VM-F-809)")
	}
}

// walk drives a finding through a sequence of states, as the orchestrator would.
func walk(t *testing.T, s store.Store, fp string, states []model.State) {
	t.Helper()
	ctx := context.Background()
	for _, to := range states {
		actor := model.ActorOrchestrator
		switch to {
		case model.Triaged:
			actor = model.ActorTriage
		case model.PROpen:
			actor = model.ActorWorker
		}
		if err := s.ApplyTransition(ctx, fp, to, model.TransitionContext{
			Actor: actor, Cause: "test walk",
		}); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// TestATicketsPriorityCarriesItsScoringProvenance covers OQ-AUDIT-01(a) at the
// boundary where a priority most often gets quoted.
//
// A ticket is read detached from any report. The priority in its body is the
// figure someone repeats in a planning meeting, and a caveat that stayed
// behind in the report never reaches that conversation.
func TestATicketsPriorityCarriesItsScoringProvenance(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	fp := fingerprint.Compute(depFinding())
	observeIn(t, s, []model.RawFinding{depFinding()})
	if err := s.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{
		Actor: model.ActorTriage, Cause: "test", At: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("triage: %v", err)
	}
	if err := s.SetPriority(ctx, fp, model.P1, nil); err != nil {
		t.Fatalf("priority: %v", err)
	}

	f, err := s.GetFinding(ctx, fp)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	spec, err := tracker.SpecFor(f, tracker.SpecOptions{
		ReportURL:                "https://reports.example/x",
		UnavailableScoringInputs: []string{"KEV (CISA known-exploited)", "EPSS (exploit prediction)"},
		DeclaredScoringInputs:    5,
	})
	if err != nil {
		t.Fatalf("SpecFor: %v", err)
	}

	low := strings.ToLower(spec.Body)
	for _, want := range []string{"3 of 5", "kev", "epss", "floor"} {
		if !strings.Contains(low, want) {
			t.Errorf("the ticket body does not carry %q alongside the priority:\n%s", want, spec.Body)
		}
	}

	// And it clears: a caveat that never clears is decoration.
	plain, err := tracker.SpecFor(f, tracker.SpecOptions{ReportURL: "https://reports.example/x"})
	if err != nil {
		t.Fatalf("SpecFor: %v", err)
	}
	if strings.Contains(strings.ToLower(plain.Body), "floor") {
		t.Error("the caveat appears with no unavailable inputs declared")
	}
}
