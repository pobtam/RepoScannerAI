package api

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/store"
)

// Issued reports (VM-UI-F-11xx).
//
// The interface lists what has been ISSUED. It offers no "current" or "live"
// report, because no such report is reproducible: a report anchors to a
// completed run, is immutable, and is identified by the hash of its content
// (VM-ADR-15, VM-UI-F-1111).

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Reports are held per run, so the listing walks recent runs. A dedicated
	// index would be faster and is worth having when the archive is large;
	// this is honest about what it does rather than pretending to page.
	runs, err := s.cfg.Store.Runs(ctx, store.RunQuery{Limit: 100})
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	out := []ReportSummary{}
	for _, run := range runs {
		recs, err := s.cfg.Store.ReportsForRun(ctx, run.ID)
		if err != nil {
			s.failStore(w, r, err)
			return
		}
		for _, rec := range recs {
			out = append(out, reportSummary(rec))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.After(out[j].IssuedAt) })
	s.write(w, r, http.StatusOK, out)
}

func reportSummary(rec store.Report) ReportSummary {
	return ReportSummary{
		ID: rec.ID, Kind: rec.Kind, Repo: rec.Repo, Template: rec.Template,
		AnchorRunID: rec.AnchorRunID, IssuedAt: rec.IssuedAt, IssuedBy: rec.IssuedBy,
		ContentHash: rec.ContentHash, Supersedes: rec.Supersedes,
		Redacted: rec.Redacted, WithheldCount: rec.WithheldCount,
	}
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	rec, err := s.cfg.Store.GetReport(r.Context(), r.PathValue("id"))
	if err != nil {
		s.failStore(w, r, err)
		return
	}

	// The document as issued, byte for byte, plus its hash so a circulated
	// copy can be checked against it (VM-UI-F-1110).
	switch r.URL.Query().Get("format") {
	case "markdown":
		var rep report.Report
		if err := decodeReport(rec.Content, &rep); err != nil {
			s.fail(w, r, http.StatusInternalServerError, "unreadable report", err.Error(),
				"the stored document is immutable; regenerate under a new identifier")
			return
		}
		md := report.Render(rep)
		// The credential guard runs on this path too: the rendered document is
		// the artifact that travels furthest.
		s.writeText(w, r, md)
	default:
		s.write(w, r, http.StatusOK, map[string]any{
			"summary": reportSummary(rec),
			"report":  rec.Content,
		})
	}
}

// writeText sends a rendered document, guarded exactly as JSON is.
func (s *Server) writeText(w http.ResponseWriter, r *http.Request, body []byte) {
	if err := report.AssertNoCredentials("report.md", body); err != nil {
		s.log.Error("api: REFUSED a rendered report containing credential material",
			"path", r.URL.Path, "error", err)
		s.fail(w, r, http.StatusInternalServerError, "response withheld",
			"the rendered report contained credential material and was refused",
			"this is a defect: the value must be removed at the producer")
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// decodeReport parses a stored report document.
func decodeReport(raw json.RawMessage, into *report.Report) error {
	return json.Unmarshal(raw, into)
}
