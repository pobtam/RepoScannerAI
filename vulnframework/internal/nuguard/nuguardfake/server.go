// Package nuguardfake is a local stand-in for the NuGuard Remote Scan API, so
// the client and the adapter are tested end to end with no NuGuard service,
// no network and no real key. It is modelled on internal/gh/ghfake.
//
// It answers the way the service does where that matters: a bearer key or
// 401; Prefer: wait answered 200 with a finished job, else 202 queued; a job
// that runs for a scripted number of polls; an Idempotency-Key that returns
// the original job, released only for worker_lost and credential_unavailable;
// a result that is 409 until the job ends; 429 with Retry-After; readiness and
// capabilities. Each failure mode the adapter must turn into a coverage gap
// can be scripted per repository.
package nuguardfake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
)

// Script is what a scan of one repository does.
type Script struct {
	// Result is a ScanResult document to serve, as captured. Its job block is
	// rewritten to describe the job actually submitted.
	Result []byte
	// ErrorCode makes the job end Status (default failed) with this code and
	// no result.
	ErrorCode string
	Status    string
	// ErrorDetail is the job error's detail; a misbehaving service can be
	// made to say anything in it. EchoToken makes it, and the result, quote
	// the GitHub token the job was submitted with.
	ErrorDetail string
	EchoToken   bool
	// CommitSHA overrides the commit the job reports scanning; empty reports
	// the ref that was requested, as the service does for a SHA.
	CommitSHA string
	// Version overrides the result's provenance.nuguard_version.
	Version string
	// Polls is how many status reads answer running before the job ends.
	// Zero ends it within the submission's Prefer: wait.
	Polls int
	// Hang keeps the job running until it is cancelled.
	Hang bool
	// Then is what a resubmission under a released key does; nil repeats this
	// script without its ErrorCode.
	Then *Script
	// SBOM is the AI-SBOM served when include_sbom is asked; nil serves a
	// small generated one.
	SBOM []byte
}

// Submission is one POST /v1/scans as the fake received it.
type Submission struct {
	RepoURL        string
	Ref            string
	IdempotencyKey string
	Prefer         string
	Options        map[string]any
	ClientRef      string
	// GitHubToken is the github_token body field. Recorded so a test can
	// assert the token arrived there and nowhere else.
	GitHubToken string
}

type job struct {
	id        string
	repoURL   string
	ref       string
	clientRef string
	key       string
	token     string
	script    *Script
	polls     int
	status    string
	options   map[string]any
}

// Server is the fake.
type Server struct {
	*httptest.Server

	mu sync.Mutex
	// APIKey is the bearer key the fake accepts.
	APIKey string
	// Version is what capabilities and every result report, unless a script
	// overrides it; ToolsAllowed is the capabilities' tools_allowed.
	Version      string
	ToolsAllowed []string
	// NotReady makes readiness answer 503.
	NotReady bool
	// Narrow serves only the tools a submission asked for, as the service
	// does. Off by default: a captured result is then replayed verbatim,
	// whatever was asked, which is what the fixtures record.
	Narrow bool
	// RateLimitOnce makes the next submission answer 429 with this
	// Retry-After, in seconds, once.
	RateLimitOnce int
	// Scripts maps a repository URL to its script; Default serves the rest.
	Scripts map[string]*Script
	Default *Script
	// later holds further scripts per repository URL: each new job (not a
	// replay under an idempotency key) takes the next, and the last repeats.
	later map[string][]*Script

	jobs        map[string]*job
	byKey       map[string]string
	seq         int
	submissions []Submission
	cancels     []string
	requests    []string
	headers     []http.Header
}

// New starts a fake accepting apiKey and reporting version.
func New(apiKey, version string) *Server {
	s := NewHandler(apiKey, version)
	s.Server = httptest.NewServer(s)
	return s
}

// NewHandler builds a fake that is not yet listening, for a standalone
// server (cmd/nuguardfake).
func NewHandler(apiKey, version string) *Server {
	return &Server{
		APIKey: apiKey, Version: version,
		ToolsAllowed: []string{"nga-rules", "atlas", "semgrep", "osv", "grype", "checkov", "trivy", "supply-chain"},
		Scripts:      map[string]*Script{},
		later:        map[string][]*Script{},
		jobs:         map[string]*job{},
		byKey:        map[string]string{},
	}
}

// Script registers what a scan of repoURL does. Registering a second script
// for the same repository queues it: the first job gets the first, the next
// job the next, and the last one repeats.
func (s *Server) Script(repoURL string, sc *Script) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Scripts[repoURL]; ok {
		s.later[repoURL] = append(s.later[repoURL], sc)
		return s
	}
	s.Scripts[repoURL] = sc
	return s
}

// Submissions lists every scan submission, in order.
func (s *Server) Submissions() []Submission {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Submission(nil), s.submissions...)
}

// Cancels lists the job ids a cancel was asked for.
func (s *Server) Cancels() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cancels...)
}

// Requests lists every request as "METHOD path".
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// SetNotReady changes readiness while the server is serving.
func (s *Server) SetNotReady(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.NotReady = v
}

// Headers lists every request's headers, in order.
func (s *Server) Headers() []http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]http.Header(nil), s.headers...)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	s.headers = append(s.headers, r.Header.Clone())

	path := r.URL.Path
	switch {
	case path == "/v1/healthz":
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
		return
	case path == "/v1/readyz":
		if s.NotReady {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "failing": []string{"tools"}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "failing": []string{}})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+s.APIKey {
		w.Header().Set("WWW-Authenticate", "Bearer")
		problem(w, http.StatusUnauthorized, "unauthorized", "a valid API key is required")
		return
	}

	switch {
	case path == "/v1/capabilities" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"nuguard_version": s.Version, "service_version": s.Version,
			"tools": []any{}, "tools_allowed": s.ToolsAllowed, "network_default": true,
			"llm_available": false, "allowed_git_hosts": []string{"github.com"}, "limits": map[string]any{},
		})
	case path == "/v1/scans" && r.Method == http.MethodPost:
		s.submit(w, r)
	case strings.HasPrefix(path, "/v1/scans/"):
		rest := strings.TrimPrefix(path, "/v1/scans/")
		id, action, _ := strings.Cut(rest, "/")
		j, ok := s.jobs[id]
		if !ok {
			problem(w, http.StatusNotFound, "not_found", "no such job")
			return
		}
		switch {
		case action == "" && r.Method == http.MethodGet:
			s.advance(j)
			writeJSON(w, http.StatusOK, s.jobDoc(j))
		case action == "result" && r.Method == http.MethodGet:
			s.result(w, j)
		case action == "cancel" && r.Method == http.MethodPost:
			s.cancels = append(s.cancels, id)
			if !terminal(j.status) {
				j.status = "cancelled"
			}
			writeJSON(w, http.StatusAccepted, s.jobDoc(j))
		default:
			problem(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		}
	default:
		problem(w, http.StatusNotFound, "not_found", "")
	}
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request) {
	if s.RateLimitOnce > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(s.RateLimitOnce))
		s.RateLimitOnce = 0
		problem(w, http.StatusTooManyRequests, "rate_limited", "slow down")
		return
	}
	var body struct {
		RepoURL         string         `json:"repo_url"`
		Ref             string         `json:"ref"`
		GitHubToken     string         `json:"github_token"`
		Options         map[string]any `json:"options"`
		ClientReference string         `json:"client_reference"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RepoURL == "" {
		problem(w, http.StatusUnprocessableEntity, "invalid_request", "repo_url is required")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	s.submissions = append(s.submissions, Submission{
		RepoURL: body.RepoURL, Ref: body.Ref, IdempotencyKey: key, Prefer: r.Header.Get("Prefer"),
		Options: body.Options, ClientRef: body.ClientReference, GitHubToken: body.GitHubToken,
	})

	sc := s.Scripts[body.RepoURL]
	if sc == nil {
		sc = s.Default
	}
	if sc == nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_request", "the fake has no script for "+body.RepoURL)
		return
	}
	if id, ok := s.byKey[key]; ok && key != "" {
		prev := s.jobs[id]
		released := prev.status == "failed" && (prev.script.ErrorCode == "worker_lost" || prev.script.ErrorCode == "credential_unavailable")
		if !released {
			writeJSON(w, http.StatusOK, s.jobDoc(prev))
			return
		}
		sc = prev.script.Then
		if sc == nil {
			next := *prev.script
			next.ErrorCode, next.Status = "", ""
			sc = &next
		}
	}

	if q := s.later[body.RepoURL]; len(q) > 0 && sc == s.Scripts[body.RepoURL] {
		// This script is spent; the next job gets the next one.
		s.Scripts[body.RepoURL] = q[0]
		if len(q) > 1 {
			s.later[body.RepoURL] = q[1:]
		} else {
			delete(s.later, body.RepoURL)
		}
	}

	s.seq++
	j := &job{
		id: fmt.Sprintf("scn_FAKE%022d", s.seq), repoURL: body.RepoURL, ref: body.Ref,
		clientRef: body.ClientReference, key: key, token: body.GitHubToken, script: sc, polls: sc.Polls, status: "queued",
		options: body.Options,
	}
	s.jobs[j.id] = j
	if key != "" {
		s.byKey[key] = j.id
	}
	if j.polls == 0 && !sc.Hang {
		// Finished within the Prefer: wait.
		s.advance(j)
		writeJSON(w, http.StatusOK, s.jobDoc(j))
		return
	}
	w.Header().Set("Location", "/v1/scans/"+j.id)
	writeJSON(w, http.StatusAccepted, s.jobDoc(j))
}

// advance moves a job one poll towards its end.
func (s *Server) advance(j *job) {
	if terminal(j.status) || j.script.Hang {
		if !terminal(j.status) {
			j.status = "running"
		}
		return
	}
	if j.polls > 0 {
		j.polls--
		j.status = "running"
		return
	}
	switch {
	case j.script.ErrorCode != "":
		j.status = orDefault(j.script.Status, "failed")
	case j.script.Status != "":
		j.status = j.script.Status
	default:
		var doc struct {
			Job struct {
				Status string `json:"status"`
			} `json:"job"`
		}
		_ = json.Unmarshal(j.script.Result, &doc)
		j.status = orDefault(doc.Job.Status, "succeeded")
	}
}

func (s *Server) jobDoc(j *job) map[string]any {
	commit := j.script.CommitSHA
	if commit == "" {
		commit = j.ref
	}
	doc := map[string]any{
		"id": j.id, "status": j.status, "phase": nil, "repo_url": j.repoURL,
		"ref_requested": nullable(j.ref), "commit_sha": nil, "client_reference": nullable(j.clientRef),
		"created_at": "2026-11-03T00:00:00Z", "started_at": nil, "finished_at": nil, "error": nil,
		"links": map[string]string{"self": "/v1/scans/" + j.id, "result": "/v1/scans/" + j.id + "/result"},
	}
	if j.status != "queued" {
		doc["commit_sha"] = nullable(commit)
	}
	if j.status == "running" {
		doc["phase"] = "analyzing"
	}
	if j.status == "failed" || j.status == "cancelled" {
		code := j.script.ErrorCode
		if j.status == "cancelled" && code == "" {
			code = "cancelled"
		}
		detail := orDefault(j.script.ErrorDetail, "scripted by the fake")
		if j.script.EchoToken {
			detail += " (token " + j.token + ")"
		}
		doc["error"] = map[string]any{
			"type": "https://nuguard.ai/problems/" + code, "title": code, "status": 500, "code": code,
			"detail": detail,
		}
	}
	return doc
}

func (s *Server) result(w http.ResponseWriter, j *job) {
	switch j.status {
	case "succeeded", "partial":
	case "expired":
		problem(w, http.StatusGone, "expired", "the result passed its retention time")
		return
	case "queued", "running":
		problem(w, http.StatusConflict, "not_finished", "the job has not finished")
		return
	default:
		problem(w, http.StatusNotFound, "not_found", "the job has no result")
		return
	}
	var doc map[string]any
	if err := json.Unmarshal(j.script.Result, &doc); err != nil {
		problem(w, http.StatusInternalServerError, "error", "the scripted result does not parse")
		return
	}
	doc["job"] = s.jobDoc(j)
	if prov, ok := doc["provenance"].(map[string]any); ok {
		prov["nuguard_version"] = orDefault(j.script.Version, s.Version)
	}
	if cov, ok := doc["coverage"].(map[string]any); ok && j.script.EchoToken {
		cov["gaps"] = []any{"clone used token " + j.token}
	}
	if s.Narrow {
		narrow(doc, j.options)
	}
	if keep, _ := j.options["include_sbom"].(bool); keep {
		sbom := j.script.SBOM
		if sbom == nil {
			sbom = []byte(`{"bomFormat":"NuGuard-AI-SBOM","specVersion":"1","components":[{"type":"model-provider","name":"openai"}]}`)
		}
		doc["sbom"] = json.RawMessage(sbom)
	}
	writeJSON(w, http.StatusOK, doc)
}

// narrow serves only what the submission asked for, as the service does:
// the tool runs and findings of the tools in options.tools. A captured
// result names every tool it ran; with Narrow, a scan that asked for fewer
// is not answered with the others' findings.
func narrow(doc map[string]any, options map[string]any) {
	asked, ok := options["tools"].([]any)
	if !ok {
		return
	}
	want := map[string]bool{}
	for _, t := range asked {
		if s, ok := t.(string); ok {
			want[s] = true
		}
	}
	if cov, ok := doc["coverage"].(map[string]any); ok {
		if runs, ok := cov["tool_runs"].([]any); ok {
			kept := []any{}
			for _, r := range runs {
				if m, ok := r.(map[string]any); ok && want[fmt.Sprint(m["tool"])] {
					kept = append(kept, r)
				}
			}
			cov["tool_runs"] = kept
		}
	}
	if findings, ok := doc["findings"].([]any); ok {
		kept := []any{}
		for _, f := range findings {
			m, ok := f.(map[string]any)
			if !ok {
				continue
			}
			if src, ok := m["source_tool"].(string); ok && src != "" && !want[src] {
				continue
			}
			kept = append(kept, f)
		}
		doc["findings"] = kept
	}
}

func terminal(status string) bool { return status != "queued" && status != "running" }

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func problem(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, map[string]any{
		"type": "https://nuguard.ai/problems/" + code, "title": code, "status": status, "code": code, "detail": detail,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
