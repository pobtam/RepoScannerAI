package tracker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// LinearConfig configures the Linear backend.
type LinearConfig struct {
	TeamID   string
	Endpoint string
	Token    string
	// DoneStateID is the workflow state a closed ticket moves to. Like Jira's
	// transitions it is workflow-specific and must be configured, not guessed.
	DoneStateID string
}

// Linear is the Linear backend.
type Linear struct {
	http Doer
	cfg  LinearConfig
}

func NewLinear(d Doer, cfg LinearConfig) *Linear { return &Linear{http: d, cfg: cfg} }

func (l *Linear) Name() string { return "linear" }

func (l *Linear) endpoint() string {
	if l.cfg.Endpoint != "" {
		return l.cfg.Endpoint
	}
	return "https://api.linear.app/graphql"
}

// linearFingerprintLabel is Linear's carrier (VM-AD §13.2): a label plus a body
// marker, queried through the GraphQL filter.
func linearFingerprintLabel(fp string) string { return "vf:" + fp }

func (l *Linear) Find(ctx context.Context, fingerprint string) (Ref, bool, error) {
	const query = `query($filter: IssueFilter!) {
  issues(filter: $filter, first: 1) { nodes { id identifier url } }
}`
	vars := map[string]any{
		"filter": map[string]any{
			// Filtered on the label, then on the body marker — structured
			// carriers both. Title text is never consulted (VM-F-805).
			"or": []any{
				map[string]any{"labels": map[string]any{"name": map[string]any{"eq": linearFingerprintLabel(fingerprint)}}},
				map[string]any{"description": map[string]any{"contains": "vf:fp:" + fingerprint}},
			},
		},
	}

	var out struct {
		Data struct {
			Issues struct {
				Nodes []struct {
					ID         string `json:"id"`
					Identifier string `json:"identifier"`
					URL        string `json:"url"`
				} `json:"nodes"`
			} `json:"issues"`
		} `json:"data"`
	}
	if err := l.call(ctx, query, vars, &out); err != nil {
		return Ref{}, false, err
	}
	nodes := out.Data.Issues.Nodes
	if len(nodes) == 0 {
		return Ref{}, false, nil
	}
	return Ref{Backend: l.Name(), ID: nodes[0].ID, URL: nodes[0].URL}, true, nil
}

func (l *Linear) Create(ctx context.Context, spec Spec) (Ref, error) {
	if err := spec.Validate(); err != nil {
		return Ref{}, err
	}
	const mutation = `mutation($input: IssueCreateInput!) {
  issueCreate(input: $input) { issue { id identifier url } }
}`
	vars := map[string]any{
		"input": map[string]any{
			"teamId":      l.cfg.TeamID,
			"title":       spec.Title,
			"description": spec.Body + "\n\nvf:fp:" + spec.Fingerprint + "\n",
			"labels":      append(append([]string{}, spec.Labels...), linearFingerprintLabel(spec.Fingerprint)),
		},
	}

	var out struct {
		Data struct {
			IssueCreate struct {
				Issue struct {
					ID         string `json:"id"`
					Identifier string `json:"identifier"`
					URL        string `json:"url"`
				} `json:"issue"`
			} `json:"issueCreate"`
		} `json:"data"`
	}
	if err := l.call(ctx, mutation, vars, &out); err != nil {
		return Ref{}, err
	}
	iss := out.Data.IssueCreate.Issue
	if iss.ID == "" {
		return Ref{}, fmt.Errorf("tracker: linear returned no issue for %s", spec.Fingerprint)
	}
	return Ref{Backend: l.Name(), ID: iss.ID, URL: iss.URL}, nil
}

func (l *Linear) Comment(ctx context.Context, ref Ref, text string) error {
	if err := assertCommentSafe(text); err != nil {
		return err
	}
	const mutation = `mutation($input: CommentCreateInput!) { commentCreate(input: $input) { success } }`
	return l.call(ctx, mutation, map[string]any{
		"input": map[string]any{"issueId": ref.ID, "body": text},
	}, nil)
}

func (l *Linear) Transition(ctx context.Context, ref Ref, st TicketState) error {
	if st == StateClosed && l.cfg.DoneStateID == "" {
		return fmt.Errorf("tracker: linear needs a configured done state id to close %s; "+
			"guessing a workflow state would move the issue somewhere unintended", ref.ID)
	}
	const mutation = `mutation($id: String!, $input: IssueUpdateInput!) { issueUpdate(id: $id, input: $input) { success } }`
	input := map[string]any{}
	if st == StateClosed {
		input["stateId"] = l.cfg.DoneStateID
	}
	return l.call(ctx, mutation, map[string]any{"id": ref.ID, "input": input}, nil)
}

func (l *Linear) Link(ctx context.Context, child, parent Ref) error {
	return l.Comment(ctx, child, "Part of "+parent.URL)
}

func (l *Linear) call(ctx context.Context, query string, vars map[string]any, out any) error {
	payload, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		return err
	}
	if err := assertCommentSafe(string(payload)); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.endpoint(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if l.cfg.Token != "" {
		req.Header.Set("Authorization", l.cfg.Token)
	}

	// GraphQL answers 200 with an errors array, so a status check alone would
	// read a failed mutation as a success.
	var envelope json.RawMessage
	if err := do(l.http, req, &envelope); err != nil {
		return err
	}
	if len(envelope) == 0 {
		return nil
	}
	var errs struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(envelope, &errs) == nil && len(errs.Errors) > 0 {
		var msgs []string
		for _, e := range errs.Errors {
			msgs = append(msgs, e.Message)
		}
		return fmt.Errorf("tracker: linear: %s", strings.Join(msgs, "; "))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(envelope, out)
}
