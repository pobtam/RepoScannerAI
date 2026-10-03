package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// The credential-shape definition lives in the model (model.CredentialPatterns)
// because more than one boundary enforces it — the report that leaves the
// system, the ticket that carries a finding into an inbox, and the durable
// queue between them. A second copy here would mean two boundaries disagreeing
// about what a credential is, and the weaker one deciding.

// ErrCredentialInReport is returned when a rendered artifact contains something
// shaped like a live credential.
//
// Generation fails rather than scrubbing silently. A report that cannot be made
// safe should not be published, and a silent scrub would hide the fact that
// credential material reached the output boundary at all — which is itself the
// defect worth knowing about.
type ErrCredentialInReport struct {
	Artifact string
	Pattern  string
}

func (e *ErrCredentialInReport) Error() string {
	return fmt.Sprintf(
		"report: refusing to publish %s: it contains something matching %s. "+
			"A secret's value must never be written to a report, in any field (VM-F-263, VM-UI-F-105). "+
			"Find how credential material reached the output boundary rather than scrubbing it here",
		e.Artifact, e.Pattern)
}

// AssertNoCredentials scans a rendered artifact for credential material.
func AssertNoCredentials(artifact string, body []byte) error {
	var ce *model.ErrCredential
	if err := model.AssertNoCredential(artifact, body); err != nil {
		if errors.As(err, &ce) {
			return &ErrCredentialInReport{Artifact: ce.Artifact, Pattern: ce.Pattern}
		}
		return err
	}
	return nil
}

// Issued is a report that has been rendered, hashed and sealed (VM-ADR-15).
type Issued struct {
	Report Report `json:"report"`
	// JSON is the authoritative document; Markdown is rendered from it and is
	// never generated independently (principle P5).
	JSON     []byte `json:"-"`
	Markdown []byte `json:"-"`
	Hash     string `json:"content_hash"`
}

// Issue renders, guards and hashes a report.
//
// The hash covers the authoritative JSON, so a copy found in an email thread
// eighteen months later can be checked against the original. It is computed
// over the document with the hash field itself empty, so hashing is idempotent
// and a report's hash does not depend on whether it has been hashed before.
func Issue(rep Report) (Issued, error) {
	rep.ContentHash = ""

	body, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return Issued{}, fmt.Errorf("report: encoding: %w", err)
	}
	if err := AssertNoCredentials("fleet.json", body); err != nil {
		return Issued{}, err
	}

	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])

	rep.ContentHash = hash
	sealed, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return Issued{}, fmt.Errorf("report: encoding: %w", err)
	}

	md := Render(rep)
	if err := AssertNoCredentials("report.md", md); err != nil {
		return Issued{}, err
	}

	return Issued{Report: rep, JSON: sealed, Markdown: md, Hash: hash}, nil
}

// IDFor derives a report's identifier from its anchor and its query.
//
// Exported because it is the report's identity RULE, not an implementation
// detail: a caller preparing a re-issue has to be able to ask what identifier
// a query will produce before issuing it, and the alternative is reproducing
// this derivation somewhere it can drift.
func IDFor(rep Report) string {
	// Supersedes participates, so a re-issue of the same query against the
	// same run gets its own identifier instead of colliding with the report
	// it replaces.
	parts := []string{string(rep.Kind), rep.AnchorRun, rep.Repo, rep.Query.Template,
		string(rep.Query.Scope), rep.Query.Supersedes}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return fmt.Sprintf("R-%s-%s", rep.AnchorRun, hex.EncodeToString(sum[:])[:8])
}

// Publisher writes issued reports somewhere durable (VM-ADR-08).
//
// An interface so the system builds and tests with no repository, no
// credentials and no network; the git-backed implementation arrives with the
// GitHub App (VM-OQ-10).
type Publisher interface {
	Publish(ctx context.Context, path string, body []byte) error
}

// FakePublisher collects artifacts in memory.
type FakePublisher struct {
	mu  sync.Mutex
	got map[string][]byte
}

// NewFakePublisher builds an empty publisher.
func NewFakePublisher() *FakePublisher { return &FakePublisher{got: map[string][]byte{}} }

// Publish records an artifact.
func (p *FakePublisher) Publish(_ context.Context, path string, body []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.got == nil {
		p.got = map[string][]byte{}
	}
	cp := make([]byte, len(body))
	copy(cp, body)
	p.got[path] = cp
	return nil
}

// Get returns a published artifact.
func (p *FakePublisher) Get(path string) ([]byte, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, ok := p.got[path]
	return b, ok
}

// Paths returns every published path, sorted.
func (p *FakePublisher) Paths() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.got))
	for k := range p.got {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// All returns every published artifact.
func (p *FakePublisher) All() map[string][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string][]byte, len(p.got))
	for k, v := range p.got {
		out[k] = v
	}
	return out
}

// PublishRun writes a run's artifacts in the VM-AD §14.1 layout.
//
//	security-reports/runs/S-001247/fleet.json    authoritative
//	security-reports/runs/S-001247/fleet.md      rendered
//	security-reports/runs/S-001247/repos/<r>.md  rendered, one per repository
func PublishRun(ctx context.Context, p Publisher, fleet Issued, repos []Issued) error {
	base := "runs/" + fleet.Report.AnchorRun
	if err := p.Publish(ctx, base+"/fleet.json", fleet.JSON); err != nil {
		return err
	}
	if err := p.Publish(ctx, base+"/fleet.md", fleet.Markdown); err != nil {
		return err
	}
	for _, r := range repos {
		name := strings.ReplaceAll(r.Report.Repo, "/", "__")
		if err := p.Publish(ctx, base+"/repos/"+name+".md", r.Markdown); err != nil {
			return err
		}
		if err := p.Publish(ctx, base+"/repos/"+name+".json", r.JSON); err != nil {
			return err
		}
	}
	// latest.json points at the most recent run (VM-AD §14.1).
	pointer, err := json.MarshalIndent(map[string]string{
		"run":          fleet.Report.AnchorRun,
		"content_hash": fleet.Hash,
		"issued_at":    fleet.Report.IssuedAt.Format("2006-01-02T15:04:05Z07:00"),
	}, "", "  ")
	if err != nil {
		return err
	}
	return p.Publish(ctx, "latest.json", pointer)
}

// ReportStore is the persistence an issued report needs.
//
// Narrow on purpose: recording a report must not be able to change a finding.
type ReportStore interface {
	SaveReport(ctx context.Context, r store.Report) error
	GetReport(ctx context.Context, id string) (store.Report, error)
}

// Record persists an issued report so it can be cited later (VM-ADR-15),
// including the lineage when it replaces an earlier one.
//
// This is the step that was missing (OQ-AUDIT-04). Generate produced a report,
// Issue hashed it, PublishRun delivered the artifacts — and nothing wrote the
// RECORD, so store.Report had no producer anywhere outside tests. A report
// nobody can look up is not citable, and a report whose query was not stored
// cannot be regenerated to check that a quoted number is still the number the
// run produced.
//
// Immutability is the store's rule, not this function's: re-recording the same
// report is idempotent, and the same identifier with different content is
// refused there (it is the same rule for every caller, including the API).
//
// When Query.Supersedes is set, this is the writer store.Report.Supersedes
// never had. The field and the requirement have both existed since Phase 7b;
// the producer-coverage audit recorded the gap with an exemption rather than
// filling it with a plausible value, and this closes it.
//
// What supersession MEANS operationally — a corrected figure, a re-issue after
// a redaction change, a regeneration against a late-arriving scan — is not
// decided here and is not this function's to decide (D10). What is decided
// here is that the relationship, once asserted, is one a reader can follow:
//
//	the superseded report EXISTS, so the lineage does not point at nothing;
//	it is not the report itself, so the chain cannot be its own ancestor;
//	it is the same KIND and the same repository, because a fleet report does
//	  not replace a repository one and saying it does would be a claim about
//	  scope that nothing checks;
//	it is not already superseded, so the lineage cannot fork — which the
//	  store enforces as well, and which VM-UI-F-1108 depends on, since a
//	  relationship cannot be "stated" when there are two of them.
//
// The superseded report is never deleted and never modified. VM-UI-F-1108 is
// explicit about the first, and the second is what makes the archive worth
// keeping: a corrected figure is only meaningful beside the figure it
// corrected.
func Record(ctx context.Context, s ReportStore, issued Issued, issuedBy string) (store.Report, error) {
	rep := issued.Report
	supersedes := rep.Query.Supersedes
	if rep.ID == "" {
		return store.Report{}, fmt.Errorf("report: refusing to record a report with no identifier; " +
			"a record nothing can cite is not a record")
	}
	if issued.Hash == "" || len(issued.JSON) == 0 {
		return store.Report{}, fmt.Errorf("report: refusing to record %s with no content hash or "+
			"body; the hash is what makes a copy found later checkable", rep.ID)
	}
	query, err := json.Marshal(rep.Query)
	if err != nil {
		return store.Report{}, fmt.Errorf("report: encoding the query of %s: %w", rep.ID, err)
	}

	if err := checkIdentity(rep); err != nil {
		return store.Report{}, err
	}
	if supersedes != "" {
		if err := checkSupersedes(ctx, s, rep, supersedes); err != nil {
			return store.Report{}, err
		}
	}

	rec := store.Report{
		ID:            rep.ID,
		AnchorRunID:   rep.AnchorRun,
		Kind:          string(rep.Kind),
		Repo:          rep.Repo,
		Template:      rep.Query.Template,
		Query:         query,
		ContentHash:   issued.Hash,
		Content:       issued.JSON,
		IssuedAt:      rep.IssuedAt,
		IssuedBy:      issuedBy,
		Supersedes:    supersedes,
		Redacted:      rep.Redacted,
		WithheldCount: rep.WithheldCount,
	}
	if err := s.SaveReport(ctx, rec); err != nil {
		return store.Report{}, err
	}
	return rec, nil
}

// checkSupersedes refuses a lineage a reader could not follow.
//
// There is no "a report cannot supersede itself" check here, and its absence
// is deliberate. Supersedes participates in IDFor, so a report whose query
// names itself would have to have been given an identifier that its own query
// does not produce — which checkIdentity refuses for a much better reason.
// Mutating the self-check away changed nothing observable, which is how it was
// found to be a special case of something stronger.
func checkSupersedes(ctx context.Context, s ReportStore, rep Report, supersedes string) error {
	previous, err := s.GetReport(ctx, supersedes)
	if err != nil {
		return fmt.Errorf("report: %s claims to supersede %s, which could not be read: %w. "+
			"A lineage pointing at nothing is worse than none — the interface would state a "+
			"relationship that cannot be followed (VM-UI-F-1108)", rep.ID, supersedes, err)
	}

	if previous.Kind != string(rep.Kind) {
		return fmt.Errorf("report: %s is a %s report and %s is a %s report. A report of one kind "+
			"replacing another is a claim about scope that nothing downstream checks, and a "+
			"reader comparing the two would be comparing different populations",
			rep.ID, rep.Kind, supersedes, previous.Kind)
	}
	if previous.Repo != rep.Repo {
		return fmt.Errorf("report: %s covers %s and %s covers %s; one cannot replace the other",
			rep.ID, dashIfEmpty(rep.Repo), supersedes, dashIfEmpty(previous.Repo))
	}
	return nil
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "the whole fleet"
	}
	return s
}

// checkIdentity refuses a report whose identifier is not the one its query
// produces.
//
// A report's id is derived from its query so that the pair is a closed loop:
// the query is stored, regenerating it yields the same document, and the
// document is reachable under the same identifier. An id that does not derive
// from its query breaks every part of that at once — a regeneration lands
// under a different identifier, and a citation points at a report that cannot
// be reproduced.
//
// It also makes self-supersession unreachable. A report naming itself in
// Supersedes would have an identifier its own query does not produce, because
// Supersedes participates in the derivation.
func checkIdentity(rep Report) error {
	if want := IDFor(rep); rep.ID != want {
		return fmt.Errorf("report: %s carries an identifier its own query does not produce "+
			"(the query derives %s). The id, the query and the document are one loop: a report "+
			"whose id is not derived from its query cannot be regenerated under the identifier "+
			"somebody cited", rep.ID, want)
	}
	return nil
}
