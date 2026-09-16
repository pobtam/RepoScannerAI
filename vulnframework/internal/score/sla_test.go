package score_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/score"
)

// OQ-P7b-03: the windows behind a breach count are configuration, and the
// configuration says whether anyone has reviewed them.
//
// A `calibrated` flag next to a table nobody can edit would be a claim about
// numbers that live in Go source, so the windows move into the same file as the
// flag. Otherwise flipping the flag to true would attest to a table the
// reviewer never saw.

func TestSLAWindowsAreConfiguration(t *testing.T) {
	c := cal(t)

	windows, err := c.SLAWindows()
	if err != nil {
		t.Fatalf("SLAWindows: %v", err)
	}
	for tier := 1; tier <= 3; tier++ {
		for _, p := range []model.Priority{model.P0, model.P1, model.P2, model.P3} {
			if windows.Window(tier, p) <= 0 {
				t.Errorf("tier %d %s has no window; a zero window breaches everything on detection", tier, p)
			}
		}
	}
	if c.SLA.Calibrated {
		t.Error("sla.calibrated is true but VM-OQ-02 has not been answered")
	}
}

// TestShippedWindowsMatchTheCodeFallback keeps the file and the fallback from
// drifting. The report's caveat describes the table in force; if the shipped
// configuration and the no-config default disagreed, the caveat would describe
// one table while the orchestrator applied another.
func TestShippedWindowsMatchTheCodeFallback(t *testing.T) {
	c := cal(t)
	windows, err := c.SLAWindows()
	if err != nil {
		t.Fatalf("SLAWindows: %v", err)
	}
	fallback := score.DefaultSLAWindows()

	for tier := 1; tier <= 3; tier++ {
		for _, p := range []model.Priority{model.P0, model.P1, model.P2, model.P3} {
			if got, want := windows.Window(tier, p), fallback.Window(tier, p); got != want {
				t.Errorf("tier %d %s: config says %v, the code fallback says %v; the caveat would describe the wrong table",
					tier, p, got, want)
			}
		}
	}
}

// TestCalibrationRefusesWindowsThatInvertUrgency is the load-bearing validation.
// A P0 window longer than a P1 window silently gives the most urgent findings
// the most time, and nothing downstream would notice: every breach count would
// still look plausible.
func TestCalibrationRefusesWindowsThatInvertUrgency(t *testing.T) {
	base := calibrationYAML(t)

	cases := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"P0 slower than P1", "P0: 24h", "P0: 240h", "ascend"},
		{"equal windows collapse the band", "P1: 168h", "P1: 24h", "ascend"},
		{"a missing priority", "      P3: 2160h\n", "", "P3"},
		{"a zero window", "P0: 24h", "P0: 0s", "positive"},
		{"an unparseable duration", "P0: 24h", "P0: soon", "sla"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.Replace(base, tc.old, tc.new, 1)
			if mutated == base {
				t.Fatalf("mutation %q did not change the file", tc.old)
			}
			_, err := score.ParseCalibration([]byte(mutated))
			if err == nil {
				t.Fatalf("calibration loaded with %s", tc.name)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Errorf("error does not explain the problem: %v", err)
			}
		})
	}
}

// TestSLAStillComputesFromConfiguredWindows checks the table is actually the one
// applied, not merely parsed.
func TestSLAStillComputesFromConfiguredWindows(t *testing.T) {
	c := cal(t)
	windows, err := c.SLAWindows()
	if err != nil {
		t.Fatalf("SLAWindows: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	window := windows.Window(1, model.P0)

	in := score.SLAInput{
		State: model.Triaged, Priority: model.P0, Tier: 1,
		FirstSeenAt: now.Add(-window - time.Hour),
	}
	if got := score.SLA(in, windows, now); got.Status != model.SLABreached {
		t.Errorf("a finding older than its configured window is %q, want breached", got.Status)
	}
	within := score.SLAInput{
		State: model.Triaged, Priority: model.P0, Tier: 1,
		FirstSeenAt: now.Add(-window / 4),
	}
	if got := score.SLA(within, windows, now); got.Status != model.SLAWithin {
		t.Errorf("a fresh finding is %q, want within", got.Status)
	}
}

func calibrationYAML(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(calPath)
	if err != nil {
		t.Fatalf("reading calibration: %v", err)
	}
	return string(b)
}
