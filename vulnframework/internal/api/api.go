package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
)

// Config is what a server needs.
type Config struct {
	Store store.Store
	// Calibration drives the score decomposition and the provenance flags. The
	// interface must show the same caveats the reports do, from the same
	// source.
	Calibration score.Calibration
	Policy      policy.Config

	// Auth establishes who is asking. Required: the client is never the access
	// control point (VM-UI-F-802), so there is no "no authenticator" mode that
	// silently grants everything.
	Auth Authenticator

	// AccessLog records who looked at what (VM-UI-F-805), including the
	// requests that were REFUSED — which are the ones an incident review
	// reads.
	//
	// Nil disables it, and that is a deliberate configuration rather than a
	// default: where the records go, how long they are kept and whether they
	// must be tamper-evident are deployment decisions (D6). What is not a
	// deployment decision is whether refusals are recorded, which is why
	// that lives in the middleware rather than in the implementation.
	AccessLog AccessLog

	// UnavailableScoringInputs names the declared scoring inputs no feed
	// answers in this deployment. Passed in rather than assumed so the caveat
	// CLEARS when the feeds are wired.
	UnavailableScoringInputs []string

	// Demo marks a server serving seeded demonstration data. Surfaced in
	// /v1/health so a reader can never mistake the demo for a fleet.
	Demo bool

	// Registry is the first-party module registry (VM-F-601). Nil means none
	// is configured, and the wave view says so rather than inferring
	// ownership from findings — which would make the interface a second
	// source of truth about who owns a module.
	Registry *firstparty.Registry

	// Wave2Trigger is the configured trigger, shown on the wave view because
	// it decides whether a merge is sufficient (VM-UI-F-705).
	Wave2Trigger string

	Logger *slog.Logger
	Clock  func() time.Time
}

// Server is the HTTP surface.
type Server struct {
	cfg     Config
	mux     *http.ServeMux
	gen     *report.Generator
	score   *score.Scorer
	log     *slog.Logger
	webhook WebhookConfig
}

// New builds a server and registers its routes.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("api: a store is required")
	}
	if cfg.Auth == nil {
		return nil, fmt.Errorf("api: an authenticator is required — the client is never the " +
			"access control point (VM-UI-F-802), so there is no mode that grants everything")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}

	gen := report.NewGenerator(cfg.Store, cfg.Calibration)
	gen.UnavailableScoringInputs = cfg.UnavailableScoringInputs
	gen.Clock = cfg.Clock

	s := &Server{
		cfg: cfg, mux: http.NewServeMux(), gen: gen,
		score: score.New(cfg.Calibration), log: cfg.Logger,
	}
	s.routes()
	return s, nil
}

// Handler returns the server's handler with middleware applied.
//
// The access log wraps withPrincipal rather than sitting inside it. That
// ordering is the substance: a request refused BEFORE a principal is
// established is still a request somebody made, and somebody repeatedly
// failing authentication is precisely what the log is for. Inside, it would
// see only what got past.
func (s *Server) Handler() http.Handler {
	return s.recoverPanic(s.withAccessLog(s.withPrincipal(s.mux)))
}

func (s *Server) now() time.Time { return s.cfg.Clock().UTC() }

func (s *Server) routes() {
	// Go's pattern-based routing: the method and the path are in one place, so
	// a handler cannot be reachable by a method it does not implement.
	s.mux.HandleFunc("GET /v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /v1/schema/openapi.json", s.handleOpenAPI)

	s.mux.HandleFunc("GET /v1/runs", s.handleRuns)
	s.mux.HandleFunc("GET /v1/runs/latest", s.handleLatestRun)
	s.mux.HandleFunc("GET /v1/runs/compare", s.handleCompare)
	s.mux.HandleFunc("GET /v1/runs/{id}", s.handleRun)
	s.mux.HandleFunc("GET /v1/runs/{id}/snapshot", s.handleSnapshot)

	s.mux.HandleFunc("GET /v1/findings", s.handleFindings)
	s.mux.HandleFunc("GET /v1/findings/facets", s.handleFacets)
	s.mux.HandleFunc("GET /v1/findings/{fp}", s.handleFinding)
	s.mux.HandleFunc("GET /v1/findings/{fp}/timeline", s.handleTimeline)
	s.mux.HandleFunc("GET /v1/findings/{fp}/attempts", s.handleAttempts)

	s.mux.HandleFunc("GET /v1/repos", s.handleRepos)
	s.mux.HandleFunc("GET /v1/repos/{repo...}", s.handleRepo)

	s.mux.HandleFunc("GET /v1/coverage", s.handleCoverage)
	s.mux.HandleFunc("GET /v1/waves", s.handleWaves)
	s.mux.HandleFunc("GET /v1/metrics/trends", s.handleTrends)

	s.mux.HandleFunc("GET /v1/reports", s.handleReports)
	s.mux.HandleFunc("GET /v1/reports/{id}", s.handleReport)
}

// --- middleware --------------------------------------------------------------

type principalKey struct{}

// withPrincipal establishes who is asking before any handler runs.
//
// Server-side, always: authorisation is never the client's to decide
// (VM-UI-F-802). A request whose principal cannot be established is refused
// rather than treated as public, because "we could not find out" and "no
// privileges" are different facts and only one of them is safe to guess.
func (s *Server) withPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.cfg.Auth.Authenticate(r)
		if err != nil {
			s.fail(w, r, http.StatusUnauthorized, "not authenticated", err.Error(),
				"sign in through the organisation identity provider and retry")
			return
		}
		// Handed to the access log before the privilege check, so a caller
		// the identity provider named but did not grade is recorded WITH
		// their identity. An undetermined privilege logged anonymously would
		// make a misconfigured group mapping impossible to attribute.
		recordPrincipal(r.Context(), p)

		if !p.Determined() {
			s.fail(w, r, http.StatusForbidden, "privilege undetermined",
				"the identity provider did not return a privilege level for this caller",
				"this fails closed rather than defaulting to public; ask an administrator to "+
					"assign a level")
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func principalFrom(ctx context.Context) Principal {
	p, _ := ctx.Value(principalKey{}).(Principal)
	return p
}

func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("api: panic", "panic", v, "path", r.URL.Path,
					"stack", string(debug.Stack()))
				s.fail(w, r, http.StatusInternalServerError, "internal error",
					"the request could not be completed",
					"retry; if it persists this is a defect and the server log has the detail")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// --- writing -----------------------------------------------------------------

// write encodes a response, refusing to send one that contains credential
// material.
//
// The guard runs on EVERY response, including error bodies. The structural
// guarantee comes first — no type in dto.go has a field capable of holding a
// credential — and this is the second line, for the case where a credential
// reaches a free-text field: a triage narrative quoting a diff, a verification
// log, a cause string. It fails CLOSED: a 500 with no body is recoverable, and
// a leaked credential is not.
func (s *Server) write(w http.ResponseWriter, r *http.Request, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		s.log.Error("api: encoding response", "error", err, "path", r.URL.Path)
		http.Error(w, `{"error":"encoding failed"}`, http.StatusInternalServerError)
		return
	}
	if err := model.AssertNoCredential("api:"+r.URL.Path, encoded); err != nil {
		// Loud, and the response is not sent. The alternative — send it and
		// log a warning — has been the mechanism of every credential leak that
		// was "known about".
		s.log.Error("api: REFUSED a response containing credential material",
			"path", r.URL.Path, "error", err)
		http.Error(w, `{"error":"response withheld","detail":"the response contained `+
			`credential material and was refused","remedy":"this is a defect: the value must `+
			`be removed at the producer, not filtered here"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// The interface is read-only and same-origin; no caching, because a stale
	// finding list is a wrong finding list.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, msg, detail, remedy string) {
	s.write(w, r, status, Error{Error: msg, Detail: detail, Remedy: remedy})
}

// failStore maps a store error to a status, keeping the distinctions the store
// went to the trouble of making.
func (s *Server) failStore(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.fail(w, r, http.StatusNotFound, "not found", err.Error(),
			"check the identifier; identifiers are stable and are never reused")
	case errors.Is(err, store.ErrScopeRequired):
		s.fail(w, r, http.StatusBadRequest, "scope required", err.Error(),
			"pass scope=open, scope=all, or scope=run&run=<id>; it is never defaulted because "+
				"a count is meaningless without saying which findings it counts")
	default:
		var lease *store.ErrLeaseRequired
		if errors.As(err, &lease) {
			s.fail(w, r, http.StatusConflict, "lease required", err.Error(),
				"this transition needs a live lease; it is refused rather than half-applied")
			return
		}
		s.log.Error("api: store", "error", err, "path", r.URL.Path)
		s.fail(w, r, http.StatusInternalServerError, "query failed", err.Error(),
			"retry; if it persists the server log has the detail")
	}
}

// --- query parameters --------------------------------------------------------

// intParam reads a bounded integer parameter.
func intParam(r *http.Request, name string, def, max int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a number, got %q", name, raw)
	}
	if n < 0 {
		return 0, fmt.Errorf("%s must not be negative", name)
	}
	if max > 0 && n > max {
		// Refused, not clamped: a client that asked for ten thousand and
		// silently got five hundred would paginate wrongly and never know.
		return 0, fmt.Errorf("%s of %d exceeds the maximum of %d", name, n, max)
	}
	return n, nil
}

// boolParam reads a tri-state parameter: absent, true or false. Absent is a
// third answer, not false.
func boolParam(r *http.Request, name string) (*bool, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return nil, nil
	}
	switch strings.ToLower(raw) {
	case "true", "1", "yes":
		v := true
		return &v, nil
	case "false", "0", "no":
		v := false
		return &v, nil
	default:
		return nil, fmt.Errorf("%s must be true or false, got %q", name, raw)
	}
}

// listParam reads a repeated or comma-separated multi-select parameter.
func listParam(r *http.Request, name string) []string {
	var out []string
	for _, raw := range r.URL.Query()[name] {
		for _, part := range strings.Split(raw, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func timeParam(r *http.Request, name string) (*time.Time, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be an RFC3339 timestamp, got %q", name, raw)
	}
	t = t.UTC()
	return &t, nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	h := Health{OK: true, Backend: backendName(s.cfg.Store), Demo: s.cfg.Demo}
	// Degradation is named rather than implied. A deployment with no
	// exploitation feeds scores every finding from three of five inputs, and
	// the interface has to be able to say so at the top of the page rather
	// than leaving the reader to infer it from an absent field.
	h.Degraded = append(h.Degraded, s.cfg.UnavailableScoringInputs...)
	if !s.cfg.Calibration.StaticAnalysis.Calibrated {
		h.Degraded = append(h.Degraded, "static-analysis thresholds are uncalibrated (VM-OQ-06)")
	}
	if !s.cfg.Calibration.SLA.Calibrated {
		h.Degraded = append(h.Degraded, "SLA windows are provisional (VM-OQ-02)")
	}
	s.write(w, r, http.StatusOK, h)
}

func backendName(s store.Store) string {
	switch s.(type) {
	case *store.Memory:
		return "memory"
	case *store.Postgres:
		return "postgres"
	default:
		return "unknown"
	}
}
