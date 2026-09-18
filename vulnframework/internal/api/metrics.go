package api

import (
	"context"
	"net/http"

	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/store"
)

// Fleet trends (VM-UI-F-303, VM-UI-F-306, VM-UI-F-307, VM-UI-F-310).
//
// One run kind per series, always, and the kind is labelled. A series drawn
// across kinds shows a sweep next to a six-repository advisory rescan, and the
// chart makes it look like the fleet halved.

// trendMetrics is the closed set of series the interface offers.
var trendMetrics = map[string]string{
	"open":         "unresolved findings at the end of each run",
	"new":          "findings first observed in each run",
	"verified":     "findings that reached VERIFIED in each run",
	"regressed":    "findings that returned after being verified",
	"not_observed": "findings not re-observed — AMBIGUOUS between a fix and a coverage gap",
	"coverage":     "percentage of in-scope repositories with a qualifying scan",
	"sla_breached": "findings past their remediation window",
}

func (s *Server) handleTrends(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	metric := orDefault(r.URL.Query().Get("metric"), "open")
	note, ok := trendMetrics[metric]
	if !ok {
		s.fail(w, r, http.StatusBadRequest, "unknown metric",
			"metric must be one of the offered series", "choose one of: open, new, verified, "+
				"regressed, not_observed, coverage, sla_breached")
		return
	}
	window, err := intParam(r, "window", 20, 200)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "bad query", err.Error(), "correct the parameter")
		return
	}
	kind := store.RunKind(orDefault(r.URL.Query().Get("kind"), string(store.KindSweep)))

	runs, err := s.cfg.Store.Runs(ctx, store.RunQuery{Kind: kind, Limit: window})
	if err != nil {
		s.failStore(w, r, err)
		return
	}

	series := TrendSeries{Metric: metric, Kind: string(kind), Points: []TrendPoint{},
		Note: note + ". Drawn from runs of kind " + string(kind) + " only (VM-UI-F-310); runs " +
			"that did not cover the fleet are marked partial, and a scanner-image change is " +
			"marked, because a step change is otherwise attributed to the wrong cause. Points " +
			"marked live were computed from the store NOW rather than read from the run's " +
			"immutable snapshot, and show those findings' CURRENT state (VM-UI-F-102)"}

	// Oldest first for a chart.
	var lastImage string
	for i := len(runs) - 1; i >= 0; i-- {
		run := runs[i]
		value, live, err := s.metricFor(ctx, metric, run)
		if err != nil {
			s.failStore(w, r, err)
			return
		}
		pt := TrendPoint{RunID: run.ID, At: run.StartedAt, Value: value,
			Live: live, ScannerImage: run.ScannerImage}
		if run.ReposFailed > 0 || (run.ReposPlanned > 0 && run.ReposScanned < run.ReposPlanned) {
			pt.Partial = true
		}
		if lastImage != "" && run.ScannerImage != lastImage {
			pt.ScannerChanged = true
		}
		lastImage = run.ScannerImage
		series.Points = append(series.Points, pt)
	}
	s.write(w, r, http.StatusOK, series)
}

// metricFor reads one run's value for a series.
//
// From the run's IMMUTABLE SNAPSHOT where one was issued, and only otherwise
// from a live generation — which is then marked as live on the point.
//
// This is VM-UI-F-102 arriving in the trend. Regenerating every point from
// today's store would draw a series in which every past run reflects the
// CURRENT state of its findings: a finding detected in June and fixed in
// August would be absent from June's point, so the line would slope downwards
// no matter what happened, and the chart would attribute today's position to
// every week in the past.
//
// Every figure still comes from the report generator or the store, never from
// a second calculation here: a trend that disagreed with the run overview
// about the same run would be worse than no trend (VM-F-908).
func (s *Server) metricFor(ctx context.Context, metric string, run store.Run) (float64, bool, error) {
	live := true
	var rep report.Report
	if rec, ok, err := s.snapshotFor(ctx, run.ID); err != nil {
		return 0, false, err
	} else if ok {
		if err := decodeReport(rec.Content, &rep); err == nil {
			live = false
		}
	}
	if live {
		var err error
		rep, err = s.gen.Generate(ctx, report.Query{
			Kind: report.KindFleet, AnchorRun: run.ID, Scope: store.ScopeAll, Template: "fleet.v1",
		})
		if err != nil {
			return 0, false, err
		}
	}
	switch metric {
	case "new":
		return float64(rep.Delta.New), live, nil
	case "verified":
		return float64(rep.Delta.Verified), live, nil
	case "regressed":
		return float64(rep.Delta.Regressed), live, nil
	case "not_observed":
		return float64(rep.Counts.NotReobserved), live, nil
	case "coverage":
		return rep.Coverage.Percent, live, nil
	case "sla_breached":
		return float64(rep.Counts.SLABreached), live, nil
	default:
		return float64(rep.Counts.Unresolved), live, nil
	}
}
