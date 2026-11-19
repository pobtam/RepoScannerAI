// Package ghfake is a local stand-in for the parts of GitHub's REST API that
// discovery and download use, so they are tested end to end with no network
// and no real token.
//
// It answers the way GitHub does where that matters: /user/repos is paged by
// a Link header with no total; a fine-grained token gets no X-OAuth-Scopes
// header and a classic one does; a token's expiry arrives in GitHub's own
// non-RFC-3339 format; a rate limit is a 403 with x-ratelimit-remaining: 0;
// and a tarball's top-level directory is owner-repo-sha, as GitHub names it.
// Anything else (including any write) is answered 405 and recorded, so a test
// can assert that nothing tried.
package ghfake

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Repo is one repository the fake account can reach.
type Repo struct {
	FullName  string
	OwnerType string // "User" or "Organization"
	Private   bool
	Archived  bool
	Fork      bool
	SizeKB    int
	Language  string
	// Dir is a directory whose files become the tarball. Empty serves 404
	// for the download, which is how a broken download is simulated.
	Dir string
	// Commit is the head of the default branch. Empty derives a fixed one
	// from the name (CommitOf).
	Commit string
}

// CommitOf is the head commit the fake reports for a repository.
func CommitOf(r Repo) string {
	if r.Commit != "" {
		return r.Commit
	}
	sum := sha1.Sum([]byte("ghfake:" + r.FullName))
	return hex.EncodeToString(sum[:])
}

// Server is the fake.
type Server struct {
	// Server is set when the fake runs in-process for a test (New). A
	// standalone fake (cmd/ghfake) leaves it nil and sets BaseURL.
	*httptest.Server
	// BaseURL is the address clients reach the fake at, used for Link
	// headers when the fake is not an httptest server.
	BaseURL string

	mu sync.Mutex
	// Account and Token are what /user answers and what Authorization must
	// carry. Classic, when set, makes the token a classic one with these
	// scopes; Expiry, when set, is sent in GitHub's format.
	Account string
	Token   string
	Classic []string
	Expiry  time.Time
	Repos   []Repo
	// PageSize is how many repositories each page of /user/repos holds.
	PageSize int
	// RateLimitOnce makes the next request a rate limit with this reset
	// delay, once.
	RateLimitOnce time.Duration

	requests []string
	refused  []string
}

// New starts a fake for account, accepting token.
func New(account, token string, repos ...Repo) *Server {
	s := &Server{Account: account, Token: token, Repos: repos, PageSize: 2}
	s.Server = httptest.NewServer(s)
	return s
}

// ServeHTTP makes the fake an http.Handler, for a standalone server.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.serve(w, r) }

func (s *Server) base() string {
	if s.BaseURL != "" {
		return s.BaseURL
	}
	return s.Server.URL
}

// Requests lists every request as "METHOD path", in order.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// Refused lists requests answered 405 because they were not reads.
func (s *Server) Refused() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.refused...)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.refused = append(s.refused, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		http.Error(w, `{"message":"the fake GitHub is read-only"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.RateLimitOnce > 0 {
		reset := time.Now().Add(s.RateLimitOnce).Unix()
		s.RateLimitOnce = 0
		s.mu.Unlock()
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset, 10))
		http.Error(w, `{"message":"API rate limit exceeded"}`, http.StatusForbidden)
		return
	}
	s.mu.Unlock()

	if r.Header.Get("Authorization") != "Bearer "+s.Token {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		return
	}

	switch {
	case r.URL.Path == "/user":
		if s.Classic != nil {
			w.Header().Set("X-OAuth-Scopes", strings.Join(s.Classic, ", "))
		}
		if !s.Expiry.IsZero() {
			w.Header().Set("GitHub-Authentication-Token-Expiration", s.Expiry.UTC().Format("2006-01-02 15:04:05 MST"))
		}
		writeJSON(w, map[string]any{"login": s.Account})
	case r.URL.Path == "/user/repos":
		s.serveRepos(w, r)
	case strings.HasPrefix(r.URL.Path, "/repos/") && strings.Contains(r.URL.Path, "/tarball"):
		s.serveTarball(w, r)
	case strings.HasPrefix(r.URL.Path, "/repos/") && strings.HasSuffix(r.URL.Path, "/commits/HEAD"):
		s.serveHead(w, r)
	default:
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}
}

func (s *Server) serveRepos(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	size := s.PageSize
	start := (page - 1) * size
	end := start + size
	if start > len(s.Repos) {
		start = len(s.Repos)
	}
	if end > len(s.Repos) {
		end = len(s.Repos)
	}
	if end < len(s.Repos) {
		q := r.URL.Query()
		q.Set("page", strconv.Itoa(page+1))
		w.Header().Set("Link", fmt.Sprintf(`<%s/user/repos?%s>; rel="next"`, s.base(), q.Encode()))
	}
	var out []map[string]any
	for _, repo := range s.Repos[start:end] {
		owner, _, _ := strings.Cut(repo.FullName, "/")
		ownerType := repo.OwnerType
		if ownerType == "" {
			ownerType = "User"
		}
		out = append(out, map[string]any{
			"full_name": repo.FullName, "default_branch": "main", "private": repo.Private,
			"archived": repo.Archived, "fork": repo.Fork, "size": repo.SizeKB, "language": repo.Language,
			"owner": map[string]any{"login": owner, "type": ownerType},
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, out)
}

// serveHead answers the head commit, as GitHub does for the SHA media type.
func (s *Server) serveHead(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/repos/"), "/commits/HEAD")
	repo := s.repo(name)
	if repo == nil {
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		return
	}
	if r.Header.Get("Accept") == "application/vnd.github.sha" {
		w.Header().Set("Content-Type", "application/vnd.github.sha")
		_, _ = w.Write([]byte(CommitOf(*repo)))
		return
	}
	writeJSON(w, map[string]any{"sha": CommitOf(*repo)})
}

func (s *Server) repo(name string) *Repo {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Repos {
		if s.Repos[i].FullName == name {
			return &s.Repos[i]
		}
	}
	return nil
}

// serveTarball serves the tree at the default branch, or at its head commit
// by id; any other ref is unknown, as it would be on GitHub.
func (s *Server) serveTarball(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/repos/")
	name, ref, _ := strings.Cut(rest, "/tarball")
	ref = strings.TrimPrefix(ref, "/")
	repo := s.repo(name)
	if repo == nil || repo.Dir == "" || (ref != "" && ref != CommitOf(*repo)) {
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		return
	}
	b, err := Tarball(strings.ReplaceAll(name, "/", "-")+"-"+CommitOf(*repo)[:7], repo.Dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-gzip")
	_, _ = w.Write(b)
}

// Tarball builds a gzipped tar of dir under a single top-level directory,
// as GitHub's tarball endpoint does.
func Tarball(top, dir string) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		name := top + "/"
		if rel != "." {
			name += filepath.ToSlash(rel)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = name
		if d.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.Type().IsRegular() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			_, err = tw.Write(b)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
