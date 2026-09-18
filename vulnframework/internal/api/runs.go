package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/store"
)

// The run views (VM-UI-F-1xx, VM-UI-F-2xx, VM-UI-F-3xx).
//
// The most important property here is VM-UI-F-102: a run's overview is the
// state AS OF that run, never recomputed from live findings. A finding detected
// on 12 August and fixed on 20 August must appear open when viewing the 12
// August run; rendering it from today's table would silently rewrite history
// and make every trend chart wrong.
//
// The framework already has the mechanism for that: an issued report is
// anchored to a run, immutable and content-hashed (VM-ADR-15). The snapshot
// endpoint serves that record. Where no report was issued for a run, the
// overview is generated LIVE and says so — because the alternative is to
// present live figures as historical ones, which is the defect itself.

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	limit, err := intParam(r, "limit", 25, 200)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "bad query", err.Error(), "correct the parameter")
		return
	}
	var before int64
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		before, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			s.fail(w, r, http.StatusBadRequest, "bad cursor", "the run cursor is a sequence number",
				"use the next_cursor from the previous page")
			return
		}
	}
	kind := store.RunKind(r.URL.Query().Get("kind"))

	runs, err := s.cfg.Store.Runs(r.Context(), store.RunQuery{
		Kind: kind, BeforeSeq: before, Limit: limit + 1,
	})
	if err != nil {
		s.failStore(w, r, err)
		return
	}

	out := RunPage{Runs: []RunSummary{}}
	for i, run := range runs {
		if i == limit {
			out.NextCursor = strconv.FormatInt(runs[i-1].Seq, 10)
			break
		}
		out.Runs = append(out.Runs, runSummary(run))
	}
	out.Total = len(out.Runs)
	s.write(w, r, http.StatusOK, out)
}

// runSummary renders a run, marking one that did not cover its fleet.
func runSummary(run store.Run) RunSummary {
	out := RunSummary{
		ID: run.ID, Kind: string(run.Kind), StartedAt: run.StartedAt, FinishedAt: run.FinishedAt,
		Trigger: run.TriggerDetail, ScannerImage: run.ScannerImage,
		ReposPlanned: run.ReposPlanned, ReposScanned: run.ReposScanned,
		ReposFailed: run.ReposFailed,
	}
	if run.ReposFailed > 0 || (run.ReposPlanned > 0 && run.ReposScanned < run.ReposPlanned) {
		// Marked everywhere it appears (VM-UI-F-307). A dip caused by half the
		// fleet failing to scan looks exactly like a dip caused by
		// remediation working, and someone will present the wrong one.
		out.Partial = true
		out.PartialNote = fmt.Sprintf(
			"%d of %d repositories produced no qualifying scan in this run, so its counts are "+
				"lower than the fleet's actual position rather than better",
			run.ReposPlanned-run.ReposScanned, run.ReposPlanned)
	}
	return out
}

func (s *Server) handleLatestRun(w http.ResponseWriter, r *http.Request) {
	runs, err := s.cfg.Store.Runs(r.Context(), store.RunQuery{
		Kind: store.RunKind(r.URL.Query().Get("kind")), Limit: 1,
	})
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	if len(runs) == 0 {
		s.fail(w, r, http.StatusNotFound, "no runs",
			"nothing has been scanned yet, which is different from a fleet with no findings",
			"trigger a run, or seed the demonstration data")
		return
	}
	s.overview(w, r, runs[0], false)
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.cfg.Store.GetRun(r.Context(), r.PathValue("id"))
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	s.overview(w, r, run, true)
}

// overview builds a run's headline view, preferring the persisted snapshot.
//
// historical says whether the caller asked for a named past run, which changes
// what has to be SAID about live figures rather than what is computed.
func (s *Server) overview(w http.ResponseWriter, r *http.Request, run store.Run, historical bool) {
	ctx := r.Context()

	// The persisted, immutable record first (VM-UI-F-102, VM-ADR-15).
	if rec, ok, err := s.snapshotFor(ctx, run.ID); err != nil {
		s.failStore(w, r, err)
		return
	} else if ok {
		var rep report.Report
		if err := decodeReport(rec.Content, &rep); err != nil {
			s.fail(w, r, http.StatusInternalServerError, "unreadable snapshot",
				fmt.Sprintf("the stored report for run %s could not be decoded: %v", run.ID, err),
				"the record is immutable; this is a schema-compatibility defect and the report "+
					"must be regenerated under a new identifier rather than edited")
			return
		}
		s.write(w, r, http.StatusOK, normaliseOverview(Overview{
			Run: runSummary(run), Live: false,
			SnapshotID: rec.ID, ContentHash: rec.ContentHash,
			Counts: rep.Counts, Delta: rep.Delta, Coverage: rep.Coverage,
			Provenance: rep.Provenance, Caveats: rep.Provenance.Caveats,
		}))
		return
	}

	// No snapshot: generate against this anchor and SAY that the figures are
	// live (VM-UI-F-424).
	rep, err := s.gen.Generate(ctx, report.Query{
		Kind: report.KindFleet, AnchorRun: run.ID, Scope: store.ScopeAll, Template: "fleet.v1",
	})
	if err != nil {
		if errors.Is(err, report.ErrLiveAnchor) {
			s.fail(w, r, http.StatusBadRequest, "no anchor", err.Error(),
				"choose a completed run; reports and overviews cannot be anchored to live state")
			return
		}
		s.failStore(w, r, err)
		return
	}
	note := "no report was issued for this run, so these figures are computed from the store NOW " +
		"rather than read from a snapshot taken at the time. Findings that have changed state " +
		"since the run are shown in their CURRENT state (VM-UI-F-424)"
	if !historical {
		note = "these figures are current: the run is the most recent one and no immutable " +
			"snapshot has been issued for it yet"
	}
	s.write(w, r, http.StatusOK, normaliseOverview(Overview{
		Run: runSummary(run), Live: true, LiveNote: note,
		Counts: rep.Counts, Delta: rep.Delta, Coverage: rep.Coverage,
		Provenance: rep.Provenance, Caveats: rep.Provenance.Caveats,
	}))
}

// normaliseOverview fills the collections the interface iterates.
//
// The report's own structures are carried through rather than restated, and a
// report whose map is nil marshals a JSON null into a field the generated
// TypeScript says is an object. Normalising here keeps the passthrough and
// keeps the contract.
func normaliseOverview(o Overview) Overview {
	o.Counts.ByPriority = emptyMapIfNil(o.Counts.ByPriority)
	o.Counts.ByState = emptyMapIfNil(o.Counts.ByState)
	o.Counts.ByCategory = emptyMapIfNil(o.Counts.ByCategory)
	o.Counts.NotFixedByReason = emptyMapIfNil(o.Counts.NotFixedByReason)
	o.Coverage.ByCause = emptyMapIfNil(o.Coverage.ByCause)
	o.Coverage.Escalations = emptyIfNil(o.Coverage.Escalations)
	o.Coverage.UnscannedRepos = emptyIfNil(o.Coverage.UnscannedRepos)
	o.Provenance.ToolVersions = emptyMapIfNil(o.Provenance.ToolVersions)
	o.Provenance.Caveats = emptyIfNil(o.Provenance.Caveats)
	o.Caveats = emptyIfNil(o.Caveats)
	return o
}

// snapshotFor returns the fleet report issued for a run, if one was.
func (s *Server) snapshotFor(ctx context.Context, runID string) (store.Report, bool, error) {
	reports, err := s.cfg.Store.ReportsForRun(ctx, runID)
	if err != nil {
		return store.Report{}, false, err
	}
	for _, rec := range reports {
		if rec.Kind == string(report.KindFleet) {
			return rec, true, nil
		}
	}
	return store.Report{}, false, nil
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	rec, ok, err := s.snapshotFor(r.Context(), r.PathValue("id"))
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	if !ok {
		// Not an empty snapshot — no snapshot. The distinction matters: an
		// empty document would read as a run that found nothing.
		s.fail(w, r, http.StatusNotFound, "no snapshot",
			fmt.Sprintf("no report was issued for run %s, so there is no immutable record of its "+
				"state", r.PathValue("id")),
			"use /v1/runs/{id} for figures generated now — they are the CURRENT state of those "+
				"findings, not the state as of that run")
		return
	}
	s.write(w, r, http.StatusOK, map[string]any{
		"id":           rec.ID,
		"run_id":       rec.AnchorRunID,
		"kind":         rec.Kind,
		"template":     rec.Template,
		"content_hash": rec.ContentHash,
		"issued_at":    rec.IssuedAt,
		"issued_by":    rec.IssuedBy,
		"query":        rec.Query,
		"report":       rec.Content,
	})
}

func (s *Server) handleCompare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	aID, bID := r.URL.Query().Get("a"), r.URL.Query().Get("b")
	if aID == "" || bID == "" {
		s.fail(w, r, http.StatusBadRequest, "two runs required",
			"pass a= and b= as run identifiers", "pick two runs from /v1/runs")
		return
	}
	a, err := s.cfg.Store.GetRun(ctx, aID)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	b, err := s.cfg.Store.GetRun(ctx, bID)
	if err != nil {
		s.failStore(w, r, err)
		return
	}

	out := Comparison{A: runSummary(a), B: runSummary(b), Comparable: a.Kind == b.Kind}
	if !out.Comparable {
		// Computed anyway, and labelled. Refusing would hide the data; not
		// labelling would invite the comparison VM-UI-F-309 warns about.
		out.Note = fmt.Sprintf(
			"these runs are of different kinds (%s and %s). A sweep compared against a "+
				"single-repository rescan produces a figure that looks like a collapse or a "+
				"miracle and is neither (VM-UI-F-309)", a.Kind, b.Kind)
	}

	inA, err := s.observedIn(ctx, aID)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	inB, err := s.observedIn(ctx, bID)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	p := principalFrom(ctx)
	for fp, f := range inB {
		if _, ok := inA[fp]; !ok {
			out.Appearing = append(out.Appearing, s.visible(ctx, p, f))
		}
	}
	for fp, f := range inA {
		if _, ok := inB[fp]; !ok {
			out.Disappearing = append(out.Disappearing, s.visible(ctx, p, f))
		}
	}
	if out.Appearing == nil {
		out.Appearing = []Finding{}
	}
	if out.Disappearing == nil {
		out.Disappearing = []Finding{}
	}
	out.Changed = []StateChange{}
	s.write(w, r, http.StatusOK, out)
}

// observedIn returns the findings a run observed, keyed by fingerprint.
func (s *Server) observedIn(ctx context.Context, runID string) (map[string]model.Finding, error) {
	out := map[string]model.Finding{}
	q := store.SearchQuery{Scope: store.ScopeRun, RunID: runID, Limit: store.MaxPageSize}
	for {
		page, err := s.cfg.Store.Search(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, f := range page.Findings {
			out[f.Fingerprint] = f
		}
		if page.Next == "" {
			return out, nil
		}
		q.Cursor = page.Next
	}
}

// visible renders a finding, restricting it where the caller may not open it.
func (s *Server) visible(ctx context.Context, p Principal, f model.Finding) Finding {
	dto := s.findingDTO(ctx, f, false)
	if !p.MaySeeFindingDetail(f) {
		return restrict(dto)
	}
	return dto
}

var _ = time.Time{}
