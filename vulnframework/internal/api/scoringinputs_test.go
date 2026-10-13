package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/api"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
)

// The defect: in -dsn mode /v1/health named KEV and EPSS unavailable because
// the server was TOLD so at startup, while the store held answers from both.
// Derived from the store, the statement follows what the feeds actually did.
func TestHealthDerivesFeedAvailabilityFromTheStore(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemory()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	cal, err := score.LoadCalibration("../../config/calibration.yaml")
	if err != nil {
		t.Fatal(err)
	}
	now := apiNow
	srv, err := api.New(api.Config{
		Store: s, Calibration: cal,
		Auth:                   api.DemoAuth{Level: report.LevelSecurityOwner},
		ScoringInputsFromStore: true,
		Logger:                 slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:                  func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	degraded := func() string {
		t.Helper()
		res, err := ts.Client().Get(ts.URL + "/v1/health")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var h api.Health
		if err := json.NewDecoder(res.Body).Decode(&h); err != nil {
			t.Fatal(err)
		}
		return strings.Join(h.Degraded, " | ")
	}

	if d := degraded(); !strings.Contains(d, "KEV (CISA known-exploited)") || !strings.Contains(d, "EPSS (exploit prediction)") {
		t.Errorf("no feed has answered, yet health says: %s", d)
	}

	asOf := now.Add(-48 * time.Hour)
	if err := s.SaveIntel(ctx, []store.Intel{{
		ID: "CVE-2025-22869", KEVAvailable: true, KEVAsOf: &asOf,
		EPSSAvailable: true, EPSS: 0.1, EPSSAsOf: &asOf,
		FetchedAt: now.Add(-time.Hour), Sources: []string{"kev", "epss"},
	}}); err != nil {
		t.Fatal(err)
	}
	if d := degraded(); strings.Contains(d, "KEV") || strings.Contains(d, "EPSS") {
		t.Errorf("both feeds answered an hour ago, yet health says: %s", d)
	}

	now = now.Add(10 * 24 * time.Hour)
	if d := degraded(); !strings.Contains(d, "KEV (CISA known-exploited) last answered 10 days ago") {
		t.Errorf("feeds silent for 10 days, yet health says: %s", d)
	}
}
