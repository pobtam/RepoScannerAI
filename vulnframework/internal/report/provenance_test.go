package report_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/store"
)

// OQ-P7b-03 gate.
//
// A breach count computed from provisional windows must surface its caveat in
// report OUTPUT, not only in config. The failure this prevents is not a wrong
// number — it is a right-looking number with no provenance: leaving SLA
// unmarked while the scoring thresholds are marked teaches the reader that an
// absent caveat means calibrated.
//
// The clause is "wherever an SLA breach count appears", so the test does not
// look for the caveat somewhere in the document. It finds every rendering of a
// breach figure and requires the qualifier to travel with it.

// slaBreachLines returns every rendered line that states a breach count.
func slaBreachLines(md string) []string {
	var out []string
	for _, line := range strings.Split(md, "\n") {
		if strings.Contains(strings.ToLower(line), "sla breached") {
			out = append(out, line)
		}
	}
	return out
}

func TestProvisionalSLAWindowsCaveatAccompaniesEveryBreachCount(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		if calibration(t).SLA.Calibrated {
			t.Skip("SLA windows are calibrated; the caveat is no longer expected")
		}

		detected := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		runID, _ := slaFixture(t, s, detected, nil)

		rep := generate(t, s, runID)
		if rep.Counts.SLABreached == 0 {
			t.Fatal("fixture produced no breach; there is no breach count to qualify")
		}
		issued, err := report.Issue(rep)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		md := string(issued.Markdown)

		// 1. The structured document says the windows are not calibrated.
		if rep.Provenance.SLAWindowsCalibrated {
			t.Error("provenance claims calibrated SLA windows while the calibration says otherwise")
		}

		// 2. The document-level caveat names the open question, so a reader can
		//    find out what would have to happen for the number to be trustworthy.
		var slaCaveat string
		for _, c := range rep.Provenance.Caveats {
			if strings.Contains(c, "VM-OQ-02") {
				slaCaveat = c
			}
		}
		if slaCaveat == "" {
			t.Fatalf("no caveat names VM-OQ-02; the breach count's provenance is unrecorded. caveats=%v", rep.Provenance.Caveats)
		}
		if !strings.Contains(strings.ToLower(md), strings.ToLower(slaCaveat[:40])) {
			t.Error("the SLA caveat is in the JSON but not in the rendered output; OQ-P7b-03 is about OUTPUT")
		}

		// 3. Every line that states a breach count carries the qualifier. A
		//    caveat forty lines above the number is not attached to the number.
		lines := slaBreachLines(md)
		if len(lines) == 0 {
			t.Fatalf("no rendered line states a breach count:\n%s", sectionOf(md, "Outstanding risk"))
		}
		for _, line := range lines {
			low := strings.ToLower(line)
			if !strings.Contains(low, "provisional") {
				t.Errorf("a breach count renders with no provenance:\n  %s\nA reader cannot tell this figure rests on unreviewed windows (OQ-P7b-03)", line)
			}
			if !strings.Contains(low, "vm-oq-02") {
				t.Errorf("the breach line does not name the open question behind it:\n  %s", line)
			}
		}

		// 4. Machine consumers get the same signal.
		var decoded map[string]any
		if err := json.Unmarshal(issued.JSON, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		prov, _ := decoded["provenance"].(map[string]any)
		if prov == nil || prov["sla_windows_calibrated"] != false {
			t.Errorf("provenance.sla_windows_calibrated is not false in the JSON: %v", prov)
		}
	})
}

// TestPartiallyComputedBreachCountAlsoCarriesTheCaveat covers the second
// rendering branch. The partial branch already qualifies the DENOMINATOR; it
// must also qualify the WINDOW, because "3 of 10 findings with a computed SLA"
// still presents 3 as a measured fact.
func TestPartiallyComputedBreachCountAlsoCarriesTheCaveat(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		if calibration(t).SLA.Calibrated {
			t.Skip("SLA windows are calibrated")
		}
		ctx := context.Background()

		detected := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		runID, _ := slaFixture(t, s, detected, nil)

		// A second finding in the same run with no SLA computed at all.
		raw := dep("org/a", "GO-2025-0002")
		if _, err := s.UpsertObservations(ctx, runID, "org/a", []model.RawFinding{raw}); err != nil {
			t.Fatalf("upsert: %v", err)
		}

		rep := generate(t, s, runID)
		if rep.Counts.SLANotComputed == 0 || rep.Counts.SLANotComputed == rep.Counts.Total {
			t.Skipf("fixture is not partially computed: %d of %d", rep.Counts.SLANotComputed, rep.Counts.Total)
		}
		issued, err := report.Issue(rep)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		lines := slaBreachLines(string(issued.Markdown))
		if len(lines) == 0 {
			t.Fatal("the partial branch renders no breach count")
		}
		for _, line := range lines {
			if !strings.Contains(strings.ToLower(line), "provisional") {
				t.Errorf("the partially-computed breach count renders with no window provenance:\n  %s", line)
			}
		}
	})
}

// TestCalibratedSLAWindowsDropTheCaveat is the other half. A caveat that never
// clears is decoration: once VM-OQ-02 is answered and the flag flipped, the
// qualifier must disappear from both the document and the breach line.
func TestCalibratedSLAWindowsDropTheCaveat(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		detected := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		runID, _ := slaFixture(t, s, detected, nil)

		cal := calibration(t)
		cal.SLA.Calibrated = true
		cal.StaticAnalysis.Calibrated = true
		cal.FanOut.Enabled = true

		g := report.NewGenerator(s, cal)
		g.Clock = func() time.Time { return base }
		rep, err := g.Generate(context.Background(), report.Query{
			Kind: report.KindFleet, AnchorRun: runID, Scope: store.ScopeAll, Template: "fleet.v1",
		})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if !rep.Provenance.SLAWindowsCalibrated {
			t.Error("sla_windows_calibrated is false with calibrated windows")
		}
		if len(rep.Provenance.Caveats) != 0 {
			t.Errorf("caveats remain once everything is calibrated: %v", rep.Provenance.Caveats)
		}
		for _, line := range slaBreachLines(string(report.Render(rep))) {
			if strings.Contains(strings.ToLower(line), "provisional") {
				t.Errorf("the provisional qualifier survives calibration:\n  %s", line)
			}
		}
	})
}

// TestAuditPackStatesTheProvenanceOfItsBreachFigure carries the clause into the
// evidence bundle. A pack is read detached from the report, often years later
// and by someone looking for an assurance claim; an unqualified breach figure
// there is the same defect with a longer half-life.
func TestAuditPackStatesTheProvenanceOfItsBreachFigure(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		if calibration(t).SLA.Calibrated {
			t.Skip("SLA windows are calibrated")
		}
		detected := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		runID, _ := slaFixture(t, s, detected, nil)

		rep := generate(t, s, runID)
		pack, err := report.BuildAuditPack(rep, report.LevelSecurityOwner)
		if err != nil {
			t.Fatalf("BuildAuditPack: %v", err)
		}

		var found bool
		for _, c := range pack.Attestation.Caveats {
			if strings.Contains(c, "VM-OQ-02") {
				found = true
			}
		}
		if !found {
			t.Errorf("the pack's attestation does not carry the SLA window caveat: %v", pack.Attestation.Caveats)
		}
		if !strings.Contains(strings.ToLower(pack.Attestation.Statement), "provisional") {
			t.Errorf("the attestation states an SLA position with no provenance:\n%s", pack.Attestation.Statement)
		}
	})
}
