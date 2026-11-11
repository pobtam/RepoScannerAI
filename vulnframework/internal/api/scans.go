package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/nuguardopt"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/store"
)

// Scan requests: the interface's first write actions.
//
// A request only inserts a row into the scan queue (migration 0017). The API
// never runs a scanner and never holds the GitHub token; the scan worker
// does the work. Every write passes, in order:
//
//  1. the role check: only the security_owner level may request scans;
//  2. the cross-site check: the browser must say the request came from this
//     origin (Sec-Fetch-Site), or, from a browser that does not send that
//     header, an Origin matching this server;
//  3. the CSRF token, an HMAC of the caller and the hour, sent in a custom
//     header (which a cross-site page cannot send without a CORS preflight
//     this server never answers);
//  4. the rate limit, per caller per minute;
//  5. strict input: a repository name and nothing else.
//
// Every request, refused or not, is in the access log; every request that
// names a repository is also a row in scan_requests, the audit record of who
// asked for what and when.

// ScanRequestView is one scan request as the interface shows it.
type ScanRequestView struct {
	ID          string     `json:"id"`
	Repo        string     `json:"repo"`
	BatchID     string     `json:"batch_id,omitempty"`
	Source      string     `json:"source"`
	RequestedBy string     `json:"requested_by"`
	RequestedAt time.Time  `json:"requested_at"`
	Status      string     `json:"status"`
	Reason      string     `json:"reason,omitempty"`
	RunID       string     `json:"run_id,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	RetryOf     string     `json:"retry_of,omitempty"`
	// NuGuard is what the request asked of NuGuard; absent asked nothing,
	// and the repository and fleet settings applied (VM-UI-F-1204).
	NuGuard *nuguardopt.Request `json:"nuguard,omitempty"`
}

// ScanRequestResult is the answer to a scan request.
type ScanRequestResult struct {
	Request ScanRequestView `json:"request"`
	// Merged is true when the repository already had a queued or running
	// request, which is returned instead of queueing a second scan.
	Merged bool `json:"merged"`
}

// ScanBatchResult is the answer to "scan all included repositories".
type ScanBatchResult struct {
	BatchID  string            `json:"batch_id"`
	Requests []ScanRequestView `json:"requests"`
	Queued   int               `json:"queued"`
	Merged   int               `json:"merged"`
}

// CSRFToken is the token a write must carry in X-CSRF-Token.
type CSRFToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CSRFHeader is the header a write carries its token in.
const CSRFHeader = "X-CSRF-Token"

func viewOf(r store.ScanRequest) ScanRequestView {
	return ScanRequestView{
		ID: r.ID, Repo: r.Repo, BatchID: r.BatchID, Source: string(r.Source), RequestedBy: r.RequestedBy,
		RequestedAt: r.RequestedAt, Status: string(r.Status), Reason: r.Reason, RunID: r.RunID,
		StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, RetryOf: r.RetryOf, NuGuard: r.NuGuard,
	}
}

// --- CSRF ---------------------------------------------------------------------

func (s *Server) csrfKey() []byte {
	s.csrfOnce.Do(func() {
		if len(s.cfg.CSRFKey) > 0 {
			s.csrfSecret = s.cfg.CSRFKey
			return
		}
		// A key per process: tokens issued before a restart stop working,
		// and the interface fetches a new one. Nothing else depends on it.
		s.csrfSecret = make([]byte, 32)
		_, _ = rand.Read(s.csrfSecret)
	})
	return s.csrfSecret
}

func (s *Server) csrfFor(principal string, window int64) string {
	mac := hmac.New(sha256.New, s.csrfKey())
	fmt.Fprintf(mac, "%s\x1f%d", principal, window)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Server) handleCSRF(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	window := s.now().Unix() / 3600
	s.write(w, r, http.StatusOK, CSRFToken{
		Token:     s.csrfFor(p.Recipient.ID, window),
		ExpiresAt: time.Unix((window+2)*3600, 0).UTC(),
	})
}

// validCSRF accepts a token for this hour or the previous one, so a token
// fetched just before the hour turns is still good.
func (s *Server) validCSRF(principal, token string) bool {
	if token == "" {
		return false
	}
	window := s.now().Unix() / 3600
	for _, wdw := range []int64{window, window - 1} {
		if hmac.Equal([]byte(token), []byte(s.csrfFor(principal, wdw))) {
			return true
		}
	}
	return false
}

// --- the checks every write passes ---------------------------------------------

// sameOrigin reports whether a write came from this application's own pages.
func (s *Server) sameOrigin(r *http.Request) (bool, string) {
	switch site := r.Header.Get("Sec-Fetch-Site"); site {
	case "same-origin":
		return true, ""
	case "":
		// A browser that does not send Sec-Fetch-Site still sends Origin on
		// a POST. No Origin either: not a browser request from our pages.
		origin := r.Header.Get("Origin")
		if origin == "" {
			return false, "the request carries neither Sec-Fetch-Site nor Origin"
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false, "the request's Origin is malformed"
		}
		if s.cfg.PublicOrigin != "" && strings.EqualFold(strings.TrimSuffix(origin, "/"), strings.TrimSuffix(s.cfg.PublicOrigin, "/")) {
			return true, ""
		}
		if strings.EqualFold(u.Host, r.Host) {
			return true, ""
		}
		return false, "the request's Origin (" + origin + ") is not this application"
	default:
		return false, "the browser reports the request came from another site (Sec-Fetch-Site: " + site + ")"
	}
}

// checkOwnerWrite runs checks 1-3, shared by every write: the
// security-owner level, the same origin and the CSRF token. needs, ask and
// from word the refusals for the write in hand.
func (s *Server) checkOwnerWrite(w http.ResponseWriter, r *http.Request, needs, ask, from string) bool {
	p := principalFrom(r.Context())
	if p.Recipient.Level < report.LevelSecurityOwner {
		s.fail(w, r, http.StatusForbidden, "not permitted", needs, ask)
		return false
	}
	if ok, why := s.sameOrigin(r); !ok {
		s.fail(w, r, http.StatusForbidden, "cross-site request refused", why, from)
		return false
	}
	if !s.validCSRF(p.Recipient.ID, r.Header.Get(CSRFHeader)) {
		s.fail(w, r, http.StatusForbidden, "missing or invalid CSRF token",
			"a write must carry "+CSRFHeader+" from GET /v1/csrf",
			"reload the page and retry")
		return false
	}
	return true
}

// guardWrite runs checks 1-4. It writes the refusal and returns false when
// the request may not proceed.
func (s *Server) guardWrite(w http.ResponseWriter, r *http.Request) (store.ScanSource, string, bool) {
	p := principalFrom(r.Context())
	if !s.cfg.ScanRequests {
		s.fail(w, r, http.StatusServiceUnavailable, "scan requests are off",
			"this deployment has no scan worker (the demonstration has none)",
			"run real mode or the deployed stack, where a scan worker drains the queue")
		return "", "", false
	}
	if !s.checkOwnerWrite(w, r, "requesting a scan needs the security-owner level",
		"ask a security owner to request it", "request scans from this application's own pages, or with vfctl") {
		return "", "", false
	}
	n, err := s.cfg.Store.CountScanRequests(r.Context(), p.Recipient.ID, s.now().Add(-time.Minute))
	if err != nil {
		s.failStore(w, r, err)
		return "", "", false
	}
	if n >= s.scanRate() {
		w.Header().Set("Retry-After", "60")
		s.fail(w, r, http.StatusTooManyRequests, "too many scan requests",
			"at most "+strconv.Itoa(s.scanRate())+" scan requests a minute per person",
			"wait a minute and retry; a scan already queued for a repository is not queued twice")
		return "", "", false
	}
	return store.SourceWeb, p.Recipient.ID, true
}

func (s *Server) scanRate() int {
	if s.cfg.ScanRatePerMinute > 0 {
		return s.cfg.ScanRatePerMinute
	}
	return 10
}

var repoNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)

// --- handlers ----------------------------------------------------------------

func (s *Server) handleScanRequest(w http.ResponseWriter, r *http.Request) {
	source, who, ok := s.guardWrite(w, r)
	if !ok {
		return
	}
	var body struct {
		Repo    string           `json:"repo"`
		NuGuard *scanNuGuardBody `json:"nuguard"`
	}
	if err := strictJSON(r, &body); err != nil {
		s.fail(w, r, http.StatusBadRequest, "bad request", err.Error(),
			`send {"repo": "owner/name"}, optionally with "nuguard": {"mode", "tools"?, "include_posture"?, "keep_sbom"?}, and nothing else`)
		return
	}
	if !repoNameRe.MatchString(body.Repo) || strings.Contains(body.Repo, "..") {
		recordSubject(r.Context(), "refused: malformed repository name")
		s.fail(w, r, http.StatusBadRequest, "bad request", "repo must be owner/name",
			"use the repository's full name as the registry lists it")
		return
	}
	ctx := r.Context()
	if _, err := s.cfg.Store.GetRepo(ctx, body.Repo); err != nil {
		recordSubject(ctx, "repo="+body.Repo+" refused: not registered")
		s.fail(w, r, http.StatusNotFound, "not a registered repository", body.Repo+" is not in the registry",
			"register it, or connect the GitHub account that owns it and run discovery")
		return
	}
	if why, err := s.refusal(ctx, body.Repo); err != nil {
		s.failStore(w, r, err)
		return
	} else if why != "" {
		s.recordRefusal(ctx, body.Repo, "", source, who, why)
		recordSubject(ctx, "repo="+body.Repo+" refused: "+why)
		s.fail(w, r, http.StatusConflict, "this repository is not scanned", why,
			"include it again (vfctl repo include) and rediscover, then retry")
		return
	}

	ng, ok := s.scanNuGuard(w, r, body.NuGuard)
	if !ok {
		return
	}

	got, merged, err := s.cfg.Store.EnqueueScan(ctx, store.ScanRequest{
		ID: store.NewScanRequestID(s.now()), Repo: body.Repo, Source: source,
		RequestedBy: who, RequestedAt: s.now(), Status: store.ScanQueued,
		RetryOf: retryOf(ctx, s.cfg.Store, body.Repo), NuGuard: ng,
	})
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	status := http.StatusCreated
	if merged {
		status = http.StatusOK
		recordSubject(ctx, "repo="+body.Repo+" merged into "+got.ID)
	} else {
		recordSubject(ctx, "repo="+body.Repo+" queued "+got.ID)
	}
	s.write(w, r, status, ScanRequestResult{Request: viewOf(got), Merged: merged})
}

func (s *Server) handleScanAll(w http.ResponseWriter, r *http.Request) {
	source, who, ok := s.guardWrite(w, r)
	if !ok {
		return
	}
	// No body, or {"nuguard": {...}}: one scan-level option for every
	// repository in the batch (VM-UI-F-1204).
	var body struct {
		NuGuard *scanNuGuardBody `json:"nuguard"`
	}
	if err := optionalJSON(r, &body); err != nil {
		s.fail(w, r, http.StatusBadRequest, "bad request", err.Error(),
			`send no body, or {"nuguard": {"mode", "tools"?, "include_posture"?, "keep_sbom"?}} and nothing else`)
		return
	}
	ng, ok := s.scanNuGuard(w, r, body.NuGuard)
	if !ok {
		return
	}
	ctx := r.Context()
	names, err := s.cfg.Store.RepoNames(ctx)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	out := ScanBatchResult{BatchID: "batch_" + store.NewScanRequestID(s.now())[3:], Requests: []ScanRequestView{}}
	for _, name := range names {
		repo, err := s.cfg.Store.GetRepo(ctx, name)
		if err != nil {
			s.failStore(w, r, err)
			return
		}
		if repo.Archived {
			continue // not included; "scan all included" does not ask for it
		}
		got, merged, err := s.cfg.Store.EnqueueScan(ctx, store.ScanRequest{
			ID: store.NewScanRequestID(s.now()), Repo: name, BatchID: out.BatchID, Source: source,
			RequestedBy: who, RequestedAt: s.now(), Status: store.ScanQueued, NuGuard: ng,
		})
		if err != nil {
			s.failStore(w, r, err)
			return
		}
		if merged {
			out.Merged++
		} else {
			out.Queued++
		}
		out.Requests = append(out.Requests, viewOf(got))
	}
	recordSubject(ctx, fmt.Sprintf("all included repositories: batch %s, %d queued, %d merged", out.BatchID, out.Queued, out.Merged))
	s.write(w, r, http.StatusCreated, out)
}

func (s *Server) handleScanList(w http.ResponseWriter, r *http.Request) {
	q := store.ScanQuery{Repo: r.URL.Query().Get("repo"), Limit: 50}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			s.fail(w, r, http.StatusBadRequest, "bad query", "limit must be 1-500", "")
			return
		}
		q.Limit = n
	}
	list, err := s.cfg.Store.ScanRequests(r.Context(), q)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	out := make([]ScanRequestView, 0, len(list))
	for _, x := range list {
		out = append(out, viewOf(x))
	}
	s.write(w, r, http.StatusOK, out)
}

// refusal says why a registered repository may not be scanned, or "".
func (s *Server) refusal(ctx context.Context, name string) (string, error) {
	return store.ScanRefusal(ctx, s.cfg.Store, name)
}

// recordRefusal keeps a refused request as an audit row. A failure to record
// it is logged, not returned: the refusal itself stands either way.
func (s *Server) recordRefusal(ctx context.Context, repo, batch string, source store.ScanSource, who, why string) {
	_, _, err := s.cfg.Store.EnqueueScan(ctx, store.ScanRequest{
		ID: store.NewScanRequestID(s.now()), Repo: repo, BatchID: batch, Source: source,
		RequestedBy: who, RequestedAt: s.now(), Status: store.ScanRefused, Reason: why,
	})
	if err != nil {
		s.log.Error("recording a refused scan request", "repo", repo, "error", err)
	}
}

// retryOf links a new request to the repository's last interrupted, failed or
// timed-out one, so the record shows it as a retry.
func retryOf(ctx context.Context, st store.Store, repo string) string {
	last, err := st.ScanRequests(ctx, store.ScanQuery{Repo: repo, Limit: 1})
	if err != nil || len(last) == 0 {
		return ""
	}
	switch last[0].Status {
	case store.ScanInterrupted, store.ScanFailed, store.ScanTimedOut:
		return last[0].ID
	}
	return ""
}

// strictJSON decodes exactly one JSON object with only known fields, from a
// small body.
func strictJSON(r *http.Request, into any) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1025))
	if err != nil {
		return err
	}
	if len(raw) > 1024 {
		return errors.New("the body is larger than 1 KB")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("the body is not the expected JSON: %w", err)
	}
	if dec.More() {
		return errors.New("the body has more than one JSON value")
	}
	return nil
}

// optionalJSON is strictJSON for a body that may also be empty.
func optionalJSON(r *http.Request, into any) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1025))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return strictJSON(r, into)
}

func emptyBody(r *http.Request) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 2))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) > 0 {
		return errors.New("this request takes no body")
	}
	return nil
}
