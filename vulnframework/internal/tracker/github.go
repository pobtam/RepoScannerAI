package tracker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// GitHubConfig configures the GitHub Issues backend (VM-ADR-06: the recommended
// primary, because it is colocated with the pull requests remediation opens).
type GitHubConfig struct {
	Owner   string
	Repo    string
	BaseURL string // defaults to the public API
	Token   string
}

// GitHub is the GitHub Issues backend.
type GitHub struct {
	http Doer
	cfg  GitHubConfig
}

func NewGitHub(d Doer, cfg GitHubConfig) *GitHub { return &GitHub{http: d, cfg: cfg} }

func (g *GitHub) Name() string { return "github" }

func (g *GitHub) base() string {
	if g.cfg.BaseURL != "" {
		return strings.TrimRight(g.cfg.BaseURL, "/")
	}
	return "https://api.github.com"
}

// fingerprintMarker is the carrier (VM-AD §13.2).
//
// An HTML comment is invisible in the rendered issue but present in the body
// the search API indexes, so the fingerprint survives someone rewriting the
// title — which is the failure mode title matching has (VM-F-805).
func fingerprintMarker(fp string) string { return "<!-- vf:fp:" + fp + " -->" }

// fingerprintLabel is the secondary carrier. Labels are queryable cheaply and
// survive body edits, so the two carriers fail independently.
func fingerprintLabel(fp string) string {
	if len(fp) > 12 {
		fp = fp[:12]
	}
	return "vf-fp-" + fp
}

func (g *GitHub) Find(ctx context.Context, fingerprint string) (Ref, bool, error) {
	// Searched by marker, scoped to the repository. Never `in:title`.
	q := fmt.Sprintf(`repo:%s/%s is:issue "vf:fp:%s"`, g.cfg.Owner, g.cfg.Repo, fingerprint)
	endpoint := g.base() + "/search/issues?q=" + url.QueryEscape(q)

	var out struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Number  int    `json:"number"`
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}
	if err := g.call(ctx, http.MethodGet, endpoint, nil, &out); err != nil {
		return Ref{}, false, err
	}
	if len(out.Items) == 0 {
		return Ref{}, false, nil
	}
	it := out.Items[0]
	return Ref{Backend: g.Name(), ID: fmt.Sprintf("%d", it.Number), URL: it.HTMLURL}, true, nil
}

func (g *GitHub) Create(ctx context.Context, spec Spec) (Ref, error) {
	if err := spec.Validate(); err != nil {
		return Ref{}, err
	}
	body := map[string]any{
		"title":  spec.Title,
		"body":   spec.Body + "\n\n" + fingerprintMarker(spec.Fingerprint) + "\n",
		"labels": append(append([]string{}, spec.Labels...), fingerprintLabel(spec.Fingerprint)),
	}
	if spec.Assignee != "" {
		body["assignees"] = []string{spec.Assignee}
	}

	var out struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/issues", g.base(), g.cfg.Owner, g.cfg.Repo)
	if err := g.call(ctx, http.MethodPost, endpoint, body, &out); err != nil {
		return Ref{}, err
	}
	return Ref{Backend: g.Name(), ID: fmt.Sprintf("%d", out.Number), URL: out.HTMLURL}, nil
}

func (g *GitHub) Comment(ctx context.Context, ref Ref, text string) error {
	if err := assertCommentSafe(text); err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/issues/%s/comments", g.base(), g.cfg.Owner, g.cfg.Repo, ref.ID)
	return g.call(ctx, http.MethodPost, endpoint, map[string]any{"body": text}, nil)
}

func (g *GitHub) Transition(ctx context.Context, ref Ref, st TicketState) error {
	state := "open"
	if st == StateClosed {
		state = "closed"
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/issues/%s", g.base(), g.cfg.Owner, g.cfg.Repo, ref.ID)
	return g.call(ctx, http.MethodPatch, endpoint, map[string]any{"state": state}, nil)
}

func (g *GitHub) Link(ctx context.Context, child, parent Ref) error {
	return g.Comment(ctx, child, "Part of "+parent.URL)
}

func (g *GitHub) call(ctx context.Context, method, endpoint string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		// Last check before the bytes leave the process.
		if err := assertCommentSafe(string(encoded)); err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.cfg.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return do(g.http, req, out)
}
