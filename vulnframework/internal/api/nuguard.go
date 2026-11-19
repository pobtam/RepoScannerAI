package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/nuguardopt"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/store"
)

// NuGuard controls (VM-UI-F-1201..1212).
//
// Security owners turn NuGuard on or off for the fleet, a repository or one
// scan, and choose its tools and posture, within the ceiling the operator set
// on the scan worker. Engineers see the settings and status read-only; the
// public sees none of it.
//
// The API still holds no credential and never talks to NuGuard. What it says
// about the service comes from the status row the scan worker writes; what it
// stores is settings, which the scan worker resolves and clips at scan time.
// Every write passes the five gates scans.go describes, and every change is an
// audit row: who, when, before, after and the reason given.

// statusStaleAfter is how old the worker's status may be before the
// interface says the status is unknown rather than show it as current.
const statusStaleAfter = 15 * time.Minute

// NuGuardStatusView is the scan worker's last word on NuGuard.
type NuGuardStatusView struct {
	// Reported is false when no scan worker has written a status.
	Reported bool `json:"reported"`
	// Stale is true when the last status is older than 15 minutes. Then
	// StaleNote says so, and the values below are left out, never shown as
	// current.
	Stale     bool       `json:"stale"`
	StaleNote string     `json:"stale_note,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`

	Reachable             *bool    `json:"reachable,omitempty"`
	ServiceVersion        string   `json:"service_version,omitempty"`
	PinnedVersion         string   `json:"pinned_version,omitempty"`
	VersionOK             *bool    `json:"version_ok,omitempty"`
	ToolsAllowedByService []string `json:"tools_allowed_by_service,omitempty"`
	LastError             string   `json:"last_error,omitempty"`
}

// NuGuardFleetView is the fleet setting in force.
type NuGuardFleetView struct {
	// Set is false when no one has set it in the interface: the settings
	// shown are the scan worker's flag defaults.
	Set       bool             `json:"set"`
	Settings  nuguardopt.Fleet `json:"settings"`
	ChangedBy string           `json:"changed_by,omitempty"`
	ChangedAt *time.Time       `json:"changed_at,omitempty"`
}

// NuGuardOverrideView is one repository's override.
type NuGuardOverrideView struct {
	Repo           string    `json:"repo"`
	Mode           string    `json:"mode"`
	Tools          []string  `json:"tools,omitempty"`
	IncludePosture *bool     `json:"include_posture,omitempty"`
	ChangedBy      string    `json:"changed_by"`
	ChangedAt      time.Time `json:"changed_at"`
}

// NuGuardAuditView is one settings change.
type NuGuardAuditView struct {
	ID    int64  `json:"id"`
	Scope string `json:"scope"`
	Repo  string `json:"repo,omitempty"`
	// Before and After are the settings as JSON; absent Before is "not set",
	// absent After is "cleared".
	Before    json.RawMessage `json:"before,omitempty"`
	After     json.RawMessage `json:"after,omitempty"`
	ChangedBy string          `json:"changed_by"`
	ChangedAt time.Time       `json:"changed_at"`
	Reason    string          `json:"reason,omitempty"`
}

// NuGuardView is the AI scanning page.
type NuGuardView struct {
	// Configured is false when the scan worker has no NuGuard URL, or no
	// worker has reported: then Note is the one line the interface shows,
	// and nothing else here is meaningful.
	Configured bool              `json:"configured"`
	Note       string            `json:"note,omitempty"`
	Status     NuGuardStatusView `json:"status"`
	// Ceiling is what the operator allows and the worker's defaults; absent
	// when no worker has reported one.
	Ceiling       *nuguardopt.Ceiling   `json:"ceiling,omitempty"`
	Selectable    []string              `json:"selectable"`
	Fleet         NuGuardFleetView      `json:"fleet"`
	OverrideCount int                   `json:"override_count"`
	Overrides     []NuGuardOverrideView `json:"overrides"`
	Audit         []NuGuardAuditView    `json:"audit"`
	// CanEdit is true for a security owner on a configured deployment.
	CanEdit bool `json:"can_edit"`
}

// NuGuardAuditPage is a page of settings history.
type NuGuardAuditPage struct {
	Entries []NuGuardAuditView `json:"entries"`
	// Next is the cursor for the next page; empty at the end.
	Next string `json:"next,omitempty"`
}

// NuGuardScanOptions is one scan's effective NuGuard options.
type NuGuardScanOptions struct {
	RunID string     `json:"run_id"`
	RunAt *time.Time `json:"run_at,omitempty"`
	// Effective is absent where the scan recorded none (NuGuard not
	// configured, or a scan from before they were recorded); Note says so.
	Effective    *nuguardopt.Effective     `json:"effective,omitempty"`
	NotRequested []nuguardopt.NotRequested `json:"not_requested,omitempty"`
	Note         string                    `json:"note,omitempty"`
}

// RepoNuGuardView is a repository's NuGuard setting.
type RepoNuGuardView struct {
	Repo       string               `json:"repo"`
	Configured bool                 `json:"configured"`
	Note       string               `json:"note,omitempty"`
	Override   *NuGuardOverrideView `json:"override,omitempty"`
	// Effective is what a scan started now with no options of its own would
	// use, and where each part comes from.
	Effective nuguardopt.Effective `json:"effective"`
	// Recent are the last ten scans' effective options, newest first.
	Recent  []NuGuardScanOptions `json:"recent"`
	CanEdit bool                 `json:"can_edit"`
}

// NuGuardPreview is what a scan would use.
type NuGuardPreview struct {
	Repo       string                `json:"repo"`
	Configured bool                  `json:"configured"`
	Effective  nuguardopt.Effective  `json:"effective"`
	Clips      []nuguardopt.ClipNote `json:"clips"`
	// Note says the preview used a ceiling the worker reported long ago.
	Note string `json:"note,omitempty"`
}

// --- reading -------------------------------------------------------------------

// requireEngineer refuses the public: NuGuard's settings and status are for
// engineers and up (VM-UI-F-1212).
func (s *Server) requireEngineer(w http.ResponseWriter, r *http.Request) bool {
	if principalFrom(r.Context()).Recipient.Level < report.LevelEngineer {
		s.fail(w, r, http.StatusForbidden, "not permitted",
			"NuGuard's settings and status are visible to engineers and security owners",
			"ask a security owner")
		return false
	}
	return true
}

// nuguardState is what the worker last reported, and whether it is current.
type nuguardState struct {
	status     store.NuGuardStatus
	reported   bool
	stale      bool
	configured bool
}

func (s *Server) nuguardState(ctx context.Context) (nuguardState, error) {
	st, ok, err := s.cfg.Store.NuGuardStatus(ctx)
	if err != nil {
		return nuguardState{}, err
	}
	out := nuguardState{status: st, reported: ok}
	if ok {
		out.stale = s.now().Sub(st.CheckedAt) > statusStaleAfter
		out.configured = st.Configured
	}
	return out, nil
}

func (n nuguardState) view() NuGuardStatusView {
	v := NuGuardStatusView{Reported: n.reported}
	if !n.reported {
		return v
	}
	at := n.status.CheckedAt
	v.CheckedAt = &at
	v.PinnedVersion = n.status.PinnedVersion
	if n.stale {
		v.Stale = true
		v.StaleNote = "status unknown: the scan worker has not reported since " + at.Format(time.RFC3339)
		return v
	}
	if n.status.Configured {
		reach, ok := n.status.Reachable, n.status.VersionOK
		v.Reachable, v.VersionOK = &reach, &ok
		v.ServiceVersion = n.status.ServiceVersion
		v.ToolsAllowedByService = n.status.ToolsAllowedByService
		v.LastError = n.status.LastError
	}
	return v
}

func overrideView(rec store.NuGuardRepoOverrideRecord) NuGuardOverrideView {
	return NuGuardOverrideView{
		Repo: rec.Repo, Mode: string(rec.Override.Mode), Tools: rec.Override.Tools,
		IncludePosture: rec.Override.IncludePosture, ChangedBy: rec.ChangedBy, ChangedAt: rec.ChangedAt,
	}
}

func auditViews(entries []store.NuGuardAuditEntry) []NuGuardAuditView {
	out := make([]NuGuardAuditView, 0, len(entries))
	for _, e := range entries {
		out = append(out, NuGuardAuditView{ID: e.ID, Scope: e.Scope, Repo: e.Repo, Before: e.Before, After: e.After,
			ChangedBy: e.ChangedBy, ChangedAt: e.ChangedAt, Reason: e.Reason})
	}
	return out
}

func (s *Server) handleNuGuard(w http.ResponseWriter, r *http.Request) {
	if !s.requireEngineer(w, r) {
		return
	}
	view, err := s.nuguardView(r.Context())
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	s.write(w, r, http.StatusOK, view)
}

func (s *Server) nuguardView(ctx context.Context) (NuGuardView, error) {
	n, err := s.nuguardState(ctx)
	if err != nil {
		return NuGuardView{}, err
	}
	out := NuGuardView{
		Configured: n.configured, Status: n.view(), Selectable: append([]string{}, nuguardopt.Selectable...),
		Overrides: []NuGuardOverrideView{}, Audit: []NuGuardAuditView{},
	}
	if !n.configured {
		out.Note = nuguardopt.NotConfigured
		if !n.reported {
			out.Note += " (no scan worker has reported)"
		}
	}
	if n.reported && n.configured {
		c := n.status.Ceiling
		out.Ceiling = &c
		out.Fleet = NuGuardFleetView{Settings: c.Defaults}
	}
	if rec, ok, err := s.cfg.Store.NuGuardSettings(ctx); err != nil {
		return out, err
	} else if ok {
		at := rec.ChangedAt
		out.Fleet = NuGuardFleetView{Set: true, Settings: rec.Settings, ChangedBy: rec.ChangedBy, ChangedAt: &at}
	}
	if out.Fleet.Settings.Tools == nil {
		out.Fleet.Settings.Tools = []string{}
	}
	overrides, err := s.cfg.Store.NuGuardRepoOverrides(ctx)
	if err != nil {
		return out, err
	}
	for _, o := range overrides {
		out.Overrides = append(out.Overrides, overrideView(o))
	}
	out.OverrideCount = len(overrides)
	audit, err := s.cfg.Store.NuGuardAudit(ctx, "", 0, 20)
	if err != nil {
		return out, err
	}
	out.Audit = auditViews(audit)
	p := principalFrom(ctx)
	out.CanEdit = n.configured && p.Recipient.Level >= report.LevelSecurityOwner
	return out, nil
}

func (s *Server) handleNuGuardAudit(w http.ResponseWriter, r *http.Request) {
	if !s.requireEngineer(w, r) {
		return
	}
	var before int64
	if c := r.URL.Query().Get("cursor"); c != "" {
		n, err := strconv.ParseInt(c, 10, 64)
		if err != nil || n <= 0 {
			s.fail(w, r, http.StatusBadRequest, "bad cursor", "cursor must be the next value of a previous page", "")
			return
		}
		before = n
	}
	repo := r.URL.Query().Get("repo")
	if repo != "" && !repoNameRe.MatchString(repo) {
		s.fail(w, r, http.StatusBadRequest, "bad query", "repo must be owner/name", "")
		return
	}
	const pageSize = 50
	entries, err := s.cfg.Store.NuGuardAudit(r.Context(), repo, before, pageSize+1)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	out := NuGuardAuditPage{}
	if len(entries) > pageSize {
		entries = entries[:pageSize]
		out.Next = strconv.FormatInt(entries[pageSize-1].ID, 10)
	}
	out.Entries = auditViews(entries)
	s.write(w, r, http.StatusOK, out)
}

// repoNuGuard answers GET /v1/repos/{repo}/nuguard.
func (s *Server) repoNuGuard(w http.ResponseWriter, r *http.Request, name string) {
	if !s.requireEngineer(w, r) {
		return
	}
	ctx := r.Context()
	if _, err := s.cfg.Store.GetRepo(ctx, name); err != nil {
		s.failStore(w, r, err)
		return
	}
	n, err := s.nuguardState(ctx)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	out := RepoNuGuardView{Repo: name, Configured: n.configured, Recent: []NuGuardScanOptions{}}
	if !n.configured {
		out.Note = nuguardopt.NotConfigured
	}
	if rec, ok, err := s.cfg.Store.NuGuardRepoOverride(ctx, name); err != nil {
		s.failStore(w, r, err)
		return
	} else if ok {
		v := overrideView(rec)
		out.Override = &v
	}
	out.Effective, _, err = store.ResolveNuGuard(ctx, s.cfg.Store, n.ceiling(), name, nil)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	results, err := s.cfg.Store.ScanResults(ctx, name, 10)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	for _, res := range results {
		out.Recent = append(out.Recent, s.scanOptions(ctx, res))
	}
	out.CanEdit = n.configured && principalFrom(ctx).Recipient.Level >= report.LevelSecurityOwner
	s.write(w, r, http.StatusOK, out)
}

func (s *Server) scanOptions(ctx context.Context, res store.RepoScanResult) NuGuardScanOptions {
	o := NuGuardScanOptions{RunID: res.RunID, Effective: res.EffectiveNuGuard, NotRequested: res.ToolsNotRequested}
	if run, err := s.cfg.Store.GetRun(ctx, res.RunID); err == nil {
		at := run.StartedAt
		o.RunAt = &at
	}
	if o.Effective == nil {
		o.Note = "this scan recorded no NuGuard options: NuGuard was not configured, or the scan predates them"
	}
	return o
}

// ceiling is the ceiling the worker last reported; not configured when it
// has reported none.
func (n nuguardState) ceiling() nuguardopt.Ceiling {
	if !n.reported || !n.configured {
		return nuguardopt.Ceiling{}
	}
	return n.status.Ceiling
}

func (s *Server) handleNuGuardPreview(w http.ResponseWriter, r *http.Request) {
	if !s.requireEngineer(w, r) {
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	repo := q.Get("repo")
	if !repoNameRe.MatchString(repo) || strings.Contains(repo, "..") {
		s.fail(w, r, http.StatusBadRequest, "bad query", "repo must be owner/name", "")
		return
	}
	if _, err := s.cfg.Store.GetRepo(ctx, repo); err != nil {
		s.failStore(w, r, err)
		return
	}
	n, err := s.nuguardState(ctx)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	var req *nuguardopt.Request
	if q.Has("nuguard") || q.Has("tools") || q.Has("include_posture") || q.Has("keep_sbom") {
		req = &nuguardopt.Request{Mode: nuguardopt.RequestMode(orDefault(q.Get("nuguard"), "default"))}
		if q.Has("tools") {
			req.Tools = []string{}
			for _, t := range strings.Split(q.Get("tools"), ",") {
				if t = strings.TrimSpace(t); t != "" {
					req.Tools = append(req.Tools, t)
				}
			}
		}
		if q.Has("include_posture") {
			b, err := strconv.ParseBool(q.Get("include_posture"))
			if err != nil {
				s.fail(w, r, http.StatusBadRequest, "bad query", "include_posture must be true or false", "")
				return
			}
			req.IncludePosture = &b
		}
		if q.Has("keep_sbom") {
			b, err := strconv.ParseBool(q.Get("keep_sbom"))
			if err != nil {
				s.fail(w, r, http.StatusBadRequest, "bad query", "keep_sbom must be true or false", "")
				return
			}
			req.KeepSBOM = b
		}
		if errs := nuguardopt.ValidateRequest(n.ceiling(), *req); len(errs) > 0 {
			s.failFields(w, r, errs, n.ceiling())
			return
		}
	}
	eff, clips, err := store.ResolveNuGuard(ctx, s.cfg.Store, n.ceiling(), repo, req)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	out := NuGuardPreview{Repo: repo, Configured: n.configured, Effective: eff, Clips: clips}
	if out.Clips == nil {
		out.Clips = []nuguardopt.ClipNote{}
	}
	if n.stale {
		out.Note = "the scan worker has not reported since " + n.status.CheckedAt.Format(time.RFC3339) +
			"; this uses the ceiling it reported then, and the worker checks again when it scans"
	}
	s.write(w, r, http.StatusOK, out)
}

// failFields refuses input above the ceiling or outside the rules: 422,
// naming each field, why, and the ceiling.
func (s *Server) failFields(w http.ResponseWriter, r *http.Request, errs []nuguardopt.FieldError, c nuguardopt.Ceiling) {
	var parts []string
	for _, e := range errs {
		parts = append(parts, e.Error())
	}
	ceiling := "NuGuard is not configured"
	if c.Configured {
		ceiling = fmt.Sprintf("tools %s; posture %s; timeout at most %d seconds",
			listOrNone(c.AllowTools), map[bool]string{true: "allowed", false: "not allowed"}[c.AllowPosture], c.MaxTimeoutS)
	}
	recordSubject(r.Context(), "refused: "+strings.Join(parts, "; "))
	s.fail(w, r, http.StatusUnprocessableEntity, "not allowed", strings.Join(parts, "; "),
		"the operator's ceiling is: "+ceiling)
}

func listOrNone(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return strings.Join(l, ", ")
}

// --- writing -------------------------------------------------------------------

// settingsRate is how many NuGuard settings changes one person may make a
// minute.
const settingsRate = 10

// guardSettingsWrite runs the five gates' first four for a settings change:
// the security-owner level, same origin, the CSRF token and the rate limit.
func (s *Server) guardSettingsWrite(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !s.checkOwnerWrite(w, r, "changing NuGuard's settings needs the security-owner level",
		"ask a security owner to change it", "change settings from this application's own pages") {
		return "", false
	}
	who := principalFrom(r.Context()).Recipient.ID
	n, err := s.cfg.Store.CountNuGuardChanges(r.Context(), who, s.now().Add(-time.Minute))
	if err != nil {
		s.failStore(w, r, err)
		return "", false
	}
	if n >= settingsRate {
		w.Header().Set("Retry-After", "60")
		s.fail(w, r, http.StatusTooManyRequests, "too many settings changes",
			"at most "+strconv.Itoa(settingsRate)+" NuGuard settings changes a minute per person", "wait a minute and retry")
		return "", false
	}
	return who, true
}

// configuredCeiling refuses a change on a deployment without NuGuard.
func (s *Server) configuredCeiling(w http.ResponseWriter, r *http.Request) (nuguardState, bool) {
	n, err := s.nuguardState(r.Context())
	if err != nil {
		s.failStore(w, r, err)
		return n, false
	}
	if !n.configured {
		s.fail(w, r, http.StatusConflict, "NuGuard is not configured", nuguardopt.NotConfigured,
			"the operator sets -nuguard-url on the scan worker; until then there is nothing to change")
		return n, false
	}
	return n, true
}

func reasonOf(p *string) (string, error) {
	if p == nil {
		return "", nil
	}
	reason := strings.TrimSpace(*p)
	if len(reason) > 500 {
		return "", fmt.Errorf("reason is longer than 500 characters")
	}
	return reason, nil
}

func (s *Server) handleNuGuardSettings(w http.ResponseWriter, r *http.Request) {
	who, ok := s.guardSettingsWrite(w, r)
	if !ok {
		return
	}
	var body struct {
		Enabled        *bool    `json:"enabled"`
		Tools          []string `json:"tools"`
		IncludePosture *bool    `json:"include_posture"`
		TimeoutS       *int     `json:"timeout_s"`
		Reason         *string  `json:"reason"`
	}
	if err := strictJSON(r, &body); err != nil {
		s.fail(w, r, http.StatusBadRequest, "bad request", err.Error(),
			`send {"enabled", "tools", "include_posture", "timeout_s", "reason"?} and nothing else`)
		return
	}
	if body.Enabled == nil || body.Tools == nil || body.IncludePosture == nil || body.TimeoutS == nil {
		s.fail(w, r, http.StatusBadRequest, "bad request", "enabled, tools, include_posture and timeout_s are all required",
			"the fleet setting is replaced whole; send every field")
		return
	}
	reason, err := reasonOf(body.Reason)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "bad request", err.Error(), "")
		return
	}
	n, ok := s.configuredCeiling(w, r)
	if !ok {
		return
	}
	f := nuguardopt.Fleet{Enabled: *body.Enabled, Tools: body.Tools, IncludePosture: *body.IncludePosture, TimeoutS: *body.TimeoutS}
	if errs := nuguardopt.ValidateFleet(n.status.Ceiling, f); len(errs) > 0 {
		s.failFields(w, r, errs, n.status.Ceiling)
		return
	}
	if _, err := s.cfg.Store.SetNuGuardSettings(r.Context(), f, who, reason, s.now()); err != nil {
		s.failStore(w, r, err)
		return
	}
	recordSubject(r.Context(), fmt.Sprintf("NuGuard fleet settings: enabled=%v tools=%s posture=%v timeout=%ds",
		f.Enabled, strings.Join(f.Tools, ","), f.IncludePosture, f.TimeoutS))
	view, err := s.nuguardView(r.Context())
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	s.write(w, r, http.StatusOK, view)
}

// putRepoNuGuard answers PUT /v1/repos/{repo}/nuguard.
func (s *Server) putRepoNuGuard(w http.ResponseWriter, r *http.Request, name string) {
	who, ok := s.guardSettingsWrite(w, r)
	if !ok {
		return
	}
	var body struct {
		Mode           string   `json:"mode"`
		Tools          []string `json:"tools"`
		IncludePosture *bool    `json:"include_posture"`
		Reason         *string  `json:"reason"`
	}
	if err := strictJSON(r, &body); err != nil {
		s.fail(w, r, http.StatusBadRequest, "bad request", err.Error(),
			`send {"mode": "inherit"|"on"|"off", "tools"?, "include_posture"?, "reason"?} and nothing else`)
		return
	}
	reason, err := reasonOf(body.Reason)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "bad request", err.Error(), "")
		return
	}
	ctx := r.Context()
	if _, err := s.cfg.Store.GetRepo(ctx, name); err != nil {
		s.failStore(w, r, err)
		return
	}
	n, ok := s.configuredCeiling(w, r)
	if !ok {
		return
	}
	o := nuguardopt.RepoOverride{Mode: nuguardopt.RepoMode(body.Mode), Tools: body.Tools, IncludePosture: body.IncludePosture}
	if errs := nuguardopt.ValidateRepo(n.status.Ceiling, o); len(errs) > 0 {
		s.failFields(w, r, errs, n.status.Ceiling)
		return
	}
	if _, err := s.cfg.Store.SetNuGuardRepoOverride(ctx, name, &o, who, reason, s.now()); err != nil {
		s.failStore(w, r, err)
		return
	}
	recordSubject(ctx, fmt.Sprintf("NuGuard override for %s: mode=%s tools=%s", name, o.Mode, strings.Join(o.Tools, ",")))
	s.repoNuGuard(w, r, name)
}

// scanNuGuardBody is the optional NuGuard part of a scan request.
type scanNuGuardBody struct {
	Mode           string   `json:"mode"`
	Tools          []string `json:"tools"`
	IncludePosture *bool    `json:"include_posture"`
	KeepSBOM       bool     `json:"keep_sbom"`
}

// scanNuGuard validates a scan request's NuGuard options against the
// ceiling the worker last reported. Nil in, nil out: today's behaviour.
func (s *Server) scanNuGuard(w http.ResponseWriter, r *http.Request, b *scanNuGuardBody) (*nuguardopt.Request, bool) {
	if b == nil {
		return nil, true
	}
	n, err := s.nuguardState(r.Context())
	if err != nil {
		s.failStore(w, r, err)
		return nil, false
	}
	req := &nuguardopt.Request{Mode: nuguardopt.RequestMode(b.Mode), Tools: b.Tools, IncludePosture: b.IncludePosture,
		KeepSBOM: b.KeepSBOM}
	if errs := nuguardopt.ValidateRequest(n.ceiling(), *req); len(errs) > 0 {
		s.failFields(w, r, errs, n.ceiling())
		return nil, false
	}
	return req, true
}

// --- the stored AI-SBOM --------------------------------------------------------

// repoAISBOM answers GET /v1/repos/{repo}/ai-sbom/{run_id}. The stored copy
// only: the API never asks NuGuard, which deletes results after its own
// retention period, and holds no key to ask with.
func (s *Server) repoAISBOM(w http.ResponseWriter, r *http.Request, name, runID string) {
	if !s.requireEngineer(w, r) {
		return
	}
	switch r.URL.Query().Get("format") {
	case "", "json":
	case "cyclonedx":
		s.fail(w, r, http.StatusNotImplemented, "CycloneDX is not available",
			"the AI-SBOM is stored as NuGuard returned it; no CycloneDX converter is built yet",
			"download format=json")
		return
	default:
		s.fail(w, r, http.StatusBadRequest, "bad query", "format must be json or cyclonedx", "")
		return
	}
	sb, ok, err := s.cfg.Store.GetAISBOM(r.Context(), runID, name)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	if !ok {
		s.fail(w, r, http.StatusNotFound, "no AI-SBOM", "run "+runID+" kept no AI-SBOM for "+name,
			"ask for one with the scan option \"Keep the AI-SBOM\"")
		return
	}
	if sb.Document == nil {
		s.fail(w, r, http.StatusNotFound, "AI-SBOM not stored", sb.Withheld,
			"raise -nuguard-sbom-max-bytes on the scan worker, or accept that this repository's AI-SBOM is not kept")
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="ai-sbom-%s-%s.json"`,
		strings.ReplaceAll(name, "/", "_"), runID))
	w.Header().Set("X-AI-SBOM-SHA256", sb.SHA256)
	recordSubject(r.Context(), "AI-SBOM "+name+" "+runID)
	s.write(w, r, http.StatusOK, sb.Document)
}

// --- NuGuard on the run and finding views ---------------------------------------

// KnownTools are the adapters a finding can be found by: the "found by"
// filter's values (VM-UI-F-1207).
var KnownTools = []string{"actions-pin", "gitleaks", "gosec", "govulncheck", "npm-audit", "nuguard",
	"osv-scanner", "semgrep", "staticcheck", "trivy"}

func knownTool(t string) bool {
	for _, k := range KnownTools {
		if k == t {
			return true
		}
	}
	return false
}

// runNuGuard is each planned repository's NuGuard options in a run, where
// the scan recorded any.
func (s *Server) runNuGuard(ctx context.Context, runID string) ([]RunNuGuard, error) {
	plan, err := s.cfg.Store.PlanEntries(ctx, runID)
	if err != nil {
		return nil, err
	}
	var out []RunNuGuard
	for _, e := range plan {
		results, err := s.cfg.Store.ScanResults(ctx, e.Repo, 50)
		if err != nil {
			return nil, err
		}
		for _, res := range results {
			if res.RunID == runID && res.EffectiveNuGuard != nil {
				out = append(out, RunNuGuard{Repo: e.Repo, Effective: *res.EffectiveNuGuard, NotRequested: res.ToolsNotRequested})
				break
			}
		}
	}
	return out, nil
}

// nuguardDetail reads a NuGuard finding's annotations, which the adapter
// tags "nuguard/<version>/<key>", into its own section; nil for a finding
// NuGuard did not report.
func (s *Server) nuguardDetail(ctx context.Context, f model.Finding) *NuGuardDetail {
	found := false
	for _, t := range f.Provenance.Tools {
		found = found || t == "nuguard"
	}
	if !found {
		return nil
	}
	d := &NuGuardDetail{Rule: deref(f.Identity.RuleID), Function: deref(f.Location.Function), LastRun: f.Provenance.LastSeenRun}
	for k, v := range f.Annotations {
		parts := strings.SplitN(k, "/", 3)
		if len(parts) != 3 || parts[0] != "nuguard" {
			continue
		}
		d.Version = parts[1]
		switch parts[2] {
		case "source_tool":
			d.SubTool = v
		case "owasp_llm_ref":
			d.OWASPLLMRef = v
		case "owasp_asi_ref":
			d.OWASPASIRef = v
		case "mitre_atlas_technique":
			d.MITREAtlasTechnique = v
		case "scanned":
			d.Scanned = v
		}
	}
	if results, err := s.cfg.Store.ScanResults(ctx, f.Repo, 50); err == nil {
		for _, res := range results {
			if res.RunID == d.LastRun {
				d.Effective = res.EffectiveNuGuard
				break
			}
		}
	}
	if d.Effective == nil {
		d.Note = "the scan that last observed it recorded no NuGuard options (it predates them)"
	}
	return d
}
