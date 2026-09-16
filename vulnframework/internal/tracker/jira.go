package tracker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// JiraConfig configures the Jira backend.
//
// FingerprintField is a dedicated, indexed custom field (VM-AD §13.2). It is
// required: without it Jira has nowhere to carry the fingerprint that can be
// queried, and idempotency would fall back to text matching, which VM-F-805
// forbids.
type JiraConfig struct {
	BaseURL          string
	Project          string
	IssueType        string
	FingerprintField string
	Token            string
	Email            string
}

// Jira is the Jira backend.
type Jira struct {
	http Doer
	cfg  JiraConfig
}

func NewJira(d Doer, cfg JiraConfig) *Jira {
	if cfg.IssueType == "" {
		cfg.IssueType = "Task"
	}
	return &Jira{http: d, cfg: cfg}
}

func (j *Jira) Name() string { return "jira" }

func (j *Jira) base() string { return strings.TrimRight(j.cfg.BaseURL, "/") + "/rest/api/3" }

func (j *Jira) requireField() error {
	if j.cfg.FingerprintField == "" {
		return fmt.Errorf("tracker: jira needs an indexed fingerprint field (VM-AD §13.2); " +
			"without one, ticket lookup would fall back to matching summary text, which VM-F-805 forbids")
	}
	return nil
}

func (j *Jira) Find(ctx context.Context, fingerprint string) (Ref, bool, error) {
	if err := j.requireField(); err != nil {
		return Ref{}, false, err
	}
	// JQL against the indexed field. Never `summary ~ ...`.
	jql := fmt.Sprintf(`project = %q AND %s = %q`, j.cfg.Project, j.cfg.FingerprintField, fingerprint)

	var out struct {
		Issues []struct {
			Key  string `json:"key"`
			Self string `json:"self"`
		} `json:"issues"`
	}
	body := map[string]any{"jql": jql, "maxResults": 1, "fields": []string{"key"}}
	if err := j.call(ctx, http.MethodPost, j.base()+"/search", body, &out); err != nil {
		return Ref{}, false, err
	}
	if len(out.Issues) == 0 {
		return Ref{}, false, nil
	}
	it := out.Issues[0]
	return Ref{Backend: j.Name(), ID: it.Key, URL: j.browseURL(it.Key, it.Self)}, true, nil
}

func (j *Jira) Create(ctx context.Context, spec Spec) (Ref, error) {
	if err := spec.Validate(); err != nil {
		return Ref{}, err
	}
	if err := j.requireField(); err != nil {
		return Ref{}, err
	}

	fields := map[string]any{
		"project":              map[string]string{"key": j.cfg.Project},
		"issuetype":            map[string]string{"name": j.cfg.IssueType},
		"summary":              spec.Title,
		"description":          spec.Body + "\n\nvf:fp:" + spec.Fingerprint + "\n",
		"labels":               append(append([]string{}, spec.Labels...), fingerprintLabel(spec.Fingerprint)),
		j.cfg.FingerprintField: spec.Fingerprint,
	}

	var out struct {
		Key  string `json:"key"`
		Self string `json:"self"`
	}
	if err := j.call(ctx, http.MethodPost, j.base()+"/issue", map[string]any{"fields": fields}, &out); err != nil {
		return Ref{}, err
	}
	return Ref{Backend: j.Name(), ID: out.Key, URL: j.browseURL(out.Key, out.Self)}, nil
}

func (j *Jira) Comment(ctx context.Context, ref Ref, text string) error {
	if err := assertCommentSafe(text); err != nil {
		return err
	}
	return j.call(ctx, http.MethodPost, j.base()+"/issue/"+ref.ID+"/comment",
		map[string]any{"body": text}, nil)
}

// Transition closes an issue by name.
//
// Jira transitions are workflow-specific, so the framework asks for the
// transition whose name matches and does not invent an identifier: a numeric id
// guessed here would move the issue somewhere unintended in a workflow nobody
// on this side has seen.
func (j *Jira) Transition(ctx context.Context, ref Ref, st TicketState) error {
	want := "Done"
	if st == StateOpen {
		want = "To Do"
	}

	var available struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			To   struct {
				Name string `json:"name"`
			} `json:"to"`
		} `json:"transitions"`
	}
	if err := j.call(ctx, http.MethodGet, j.base()+"/issue/"+ref.ID+"/transitions", nil, &available); err != nil {
		return err
	}
	for _, tr := range available.Transitions {
		if strings.EqualFold(tr.Name, want) || strings.EqualFold(tr.To.Name, want) {
			return j.call(ctx, http.MethodPost, j.base()+"/issue/"+ref.ID+"/transitions",
				map[string]any{"transition": map[string]string{"id": tr.ID}}, nil)
		}
	}
	return fmt.Errorf("tracker: jira issue %s has no transition to %q; "+
		"the project's workflow differs from the expected one and the ticket has been left as it is", ref.ID, want)
}

func (j *Jira) Link(ctx context.Context, child, parent Ref) error {
	return j.call(ctx, http.MethodPost, j.base()+"/issueLink", map[string]any{
		"type":         map[string]string{"name": "Relates"},
		"inwardIssue":  map[string]string{"key": child.ID},
		"outwardIssue": map[string]string{"key": parent.ID},
	}, nil)
}

func (j *Jira) browseURL(key, self string) string {
	if j.cfg.BaseURL != "" {
		return strings.TrimRight(j.cfg.BaseURL, "/") + "/browse/" + key
	}
	return self
}

func (j *Jira) call(ctx context.Context, method, endpoint string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if err := assertCommentSafe(string(encoded)); err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if j.cfg.Token != "" {
		req.SetBasicAuth(j.cfg.Email, j.cfg.Token)
	}
	return do(j.http, req, out)
}
