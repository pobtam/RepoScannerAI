package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

// GitHub discovery records (migration 0016). Nothing here holds a token.

// GitHubConnection is what GitHub said about a token's account when it was
// connected.
type GitHubConnection struct {
	Account   string     `json:"account"`
	Kind      string     `json:"kind"`
	Scopes    []string   `json:"scopes,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	ReadOnly  string     `json:"read_only"`
	CheckedAt time.Time  `json:"checked_at"`
	CheckedBy string     `json:"checked_by"`
}

// DiscoveredRepo is one repository a discovery saw, and whether it is
// scanned. Reason is empty exactly when Included is true.
type DiscoveredRepo struct {
	Name          string    `json:"name"`
	Account       string    `json:"account"`
	Affiliation   string    `json:"affiliation"`
	Private       bool      `json:"private"`
	Archived      bool      `json:"archived"`
	Fork          bool      `json:"fork"`
	SizeKB        int       `json:"size_kb"`
	DefaultBranch string    `json:"default_branch"`
	Language      string    `json:"language,omitempty"`
	Included      bool      `json:"included"`
	Reason        string    `json:"reason,omitempty"`
	Detail        string    `json:"detail,omitempty"`
	DiscoveredAt  time.Time `json:"discovered_at"`
}

// RepoExclusion is a person's decision to leave a repository out.
type RepoExclusion struct {
	Name       string    `json:"name"`
	Reason     string    `json:"reason"`
	ExcludedBy string    `json:"excluded_by"`
	ExcludedAt time.Time `json:"excluded_at"`
}

// GitHubStore is the discovery half of the store. Both backends implement
// it; it is a separate interface so that a caller needing only discovery
// asks for only discovery.
type GitHubStore interface {
	// SaveGitHubConnection records (or refreshes) an account's connection.
	SaveGitHubConnection(ctx context.Context, c GitHubConnection) error
	// GitHubConnections lists every connected account, by name.
	GitHubConnections(ctx context.Context) ([]GitHubConnection, error)
	// ReplaceDiscovery replaces an account's discovered list with repos.
	// The account must be connected.
	ReplaceDiscovery(ctx context.Context, account string, repos []DiscoveredRepo) error
	// Discovery lists every discovered repository, by name.
	Discovery(ctx context.Context) ([]DiscoveredRepo, error)
	// SetExclusion excludes a repository; RemoveExclusion lifts it and
	// reports whether one existed.
	SetExclusion(ctx context.Context, e RepoExclusion) error
	RemoveExclusion(ctx context.Context, name string) (bool, error)
	Exclusions(ctx context.Context) ([]RepoExclusion, error)
}

var (
	_ GitHubStore = (*Memory)(nil)
	_ GitHubStore = (*Postgres)(nil)
)

// ErrNotConnected is returned when discovery is recorded for an account that
// was never connected.
var ErrNotConnected = errors.New("store: that GitHub account is not connected; run vfctl github connect first")

func validDiscovered(r DiscoveredRepo) error {
	if r.Name == "" || r.Account == "" {
		return fmt.Errorf("store: a discovered repository needs a name and an account")
	}
	if r.Included != (r.Reason == "") {
		return fmt.Errorf("store: %s: a repository is either included or skipped with a reason, not both", r.Name)
	}
	switch r.Affiliation {
	case "owner", "organization", "collaborator":
	default:
		return fmt.Errorf("store: %s: unknown affiliation %q", r.Name, r.Affiliation)
	}
	return nil
}

// --- memory ------------------------------------------------------------------

func (m *Memory) SaveGitHubConnection(_ context.Context, c GitHubConnection) error {
	if c.Account == "" {
		return fmt.Errorf("store: a connection needs an account")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ghConnections == nil {
		m.ghConnections = map[string]GitHubConnection{}
	}
	c.Scopes = append([]string(nil), c.Scopes...)
	m.ghConnections[c.Account] = c
	return nil
}

func (m *Memory) GitHubConnections(context.Context) ([]GitHubConnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]GitHubConnection, 0, len(m.ghConnections))
	for _, c := range m.ghConnections {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Account < out[j].Account })
	return out, nil
}

func (m *Memory) ReplaceDiscovery(_ context.Context, account string, repos []DiscoveredRepo) error {
	for _, r := range repos {
		if r.Account != account {
			return fmt.Errorf("store: %s belongs to %s, not %s", r.Name, r.Account, account)
		}
		if err := validDiscovered(r); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.ghConnections[account]; !ok {
		return ErrNotConnected
	}
	if m.discovered == nil {
		m.discovered = map[string]DiscoveredRepo{}
	}
	for name, r := range m.discovered {
		if r.Account == account {
			delete(m.discovered, name)
		}
	}
	for _, r := range repos {
		m.discovered[r.Name] = r
	}
	return nil
}

func (m *Memory) Discovery(context.Context) ([]DiscoveredRepo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]DiscoveredRepo, 0, len(m.discovered))
	for _, r := range m.discovered {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) SetExclusion(_ context.Context, e RepoExclusion) error {
	if e.Name == "" || e.Reason == "" || e.ExcludedBy == "" {
		return fmt.Errorf("store: an exclusion needs a repository, a reason and who decided it")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.exclusions == nil {
		m.exclusions = map[string]RepoExclusion{}
	}
	m.exclusions[e.Name] = e
	return nil
}

func (m *Memory) RemoveExclusion(_ context.Context, name string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.exclusions[name]
	delete(m.exclusions, name)
	return ok, nil
}

func (m *Memory) Exclusions(context.Context) ([]RepoExclusion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RepoExclusion, 0, len(m.exclusions))
	for _, e := range m.exclusions {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// --- postgres ----------------------------------------------------------------

const (
	qSaveGitHubConnection = `
INSERT INTO github_connections (account, kind, scopes, expires_at, read_only, checked_at, checked_by)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (account) DO UPDATE SET
  kind = EXCLUDED.kind, scopes = EXCLUDED.scopes, expires_at = EXCLUDED.expires_at,
  read_only = EXCLUDED.read_only, checked_at = EXCLUDED.checked_at, checked_by = EXCLUDED.checked_by`
	qGitHubConnections = `
SELECT account, kind, scopes::text, expires_at, read_only, checked_at, checked_by
FROM github_connections ORDER BY account`
	qInsertDiscovered = `
INSERT INTO discovered_repos (name, account, affiliation, private, archived, fork, size_kb,
  default_branch, language, included, reason, detail, discovered_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (name) DO UPDATE SET
  account = EXCLUDED.account, affiliation = EXCLUDED.affiliation, private = EXCLUDED.private,
  archived = EXCLUDED.archived, fork = EXCLUDED.fork, size_kb = EXCLUDED.size_kb,
  default_branch = EXCLUDED.default_branch, language = EXCLUDED.language,
  included = EXCLUDED.included, reason = EXCLUDED.reason, detail = EXCLUDED.detail,
  discovered_at = EXCLUDED.discovered_at`
	qDiscovery = `
SELECT name, account, affiliation, private, archived, fork, size_kb, default_branch, language,
  included, reason, detail, discovered_at
FROM discovered_repos ORDER BY name`
	qSetExclusion = `
INSERT INTO repo_exclusions (name, reason, excluded_by, excluded_at) VALUES ($1, $2, $3, $4)
ON CONFLICT (name) DO UPDATE SET reason = EXCLUDED.reason, excluded_by = EXCLUDED.excluded_by,
  excluded_at = EXCLUDED.excluded_at`
	qExclusions = `SELECT name, reason, excluded_by, excluded_at FROM repo_exclusions ORDER BY name`
)

func (p *Postgres) SaveGitHubConnection(ctx context.Context, c GitHubConnection) error {
	if c.Account == "" {
		return fmt.Errorf("store: a connection needs an account")
	}
	_, err := p.db.ExecContext(ctx, qSaveGitHubConnection, c.Account, c.Kind, pgTextArray(c.Scopes),
		nullTime(c.ExpiresAt), c.ReadOnly, c.CheckedAt.UTC(), c.CheckedBy)
	return err
}

func (p *Postgres) GitHubConnections(ctx context.Context) ([]GitHubConnection, error) {
	rows, err := p.db.QueryContext(ctx, qGitHubConnections)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GitHubConnection
	for rows.Next() {
		var (
			c       GitHubConnection
			scopes  string
			expires sql.NullTime
		)
		if err := rows.Scan(&c.Account, &c.Kind, &scopes, &expires, &c.ReadOnly, &c.CheckedAt, &c.CheckedBy); err != nil {
			return nil, err
		}
		c.Scopes = parseTextArray(scopes)
		if expires.Valid {
			t := expires.Time.UTC()
			c.ExpiresAt = &t
		}
		c.CheckedAt = c.CheckedAt.UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) ReplaceDiscovery(ctx context.Context, account string, repos []DiscoveredRepo) error {
	for _, r := range repos {
		if r.Account != account {
			return fmt.Errorf("store: %s belongs to %s, not %s", r.Name, r.Account, account)
		}
		if err := validDiscovered(r); err != nil {
			return err
		}
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM github_connections WHERE account = $1)`, account).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotConnected
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM discovered_repos WHERE account = $1`, account); err != nil {
		return err
	}
	for _, r := range repos {
		if _, err := tx.ExecContext(ctx, qInsertDiscovered, r.Name, r.Account, r.Affiliation, r.Private,
			r.Archived, r.Fork, r.SizeKB, r.DefaultBranch, r.Language, r.Included,
			nullString(r.Reason), nullString(r.Detail), r.DiscoveredAt.UTC()); err != nil {
			return fmt.Errorf("store: recording discovered %s: %w", r.Name, err)
		}
	}
	return tx.Commit()
}

func (p *Postgres) Discovery(ctx context.Context) ([]DiscoveredRepo, error) {
	rows, err := p.db.QueryContext(ctx, qDiscovery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DiscoveredRepo
	for rows.Next() {
		var (
			r              DiscoveredRepo
			reason, detail sql.NullString
		)
		if err := rows.Scan(&r.Name, &r.Account, &r.Affiliation, &r.Private, &r.Archived, &r.Fork,
			&r.SizeKB, &r.DefaultBranch, &r.Language, &r.Included, &reason, &detail, &r.DiscoveredAt); err != nil {
			return nil, err
		}
		r.Reason, r.Detail = reason.String, detail.String
		r.DiscoveredAt = r.DiscoveredAt.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) SetExclusion(ctx context.Context, e RepoExclusion) error {
	if e.Name == "" || e.Reason == "" || e.ExcludedBy == "" {
		return fmt.Errorf("store: an exclusion needs a repository, a reason and who decided it")
	}
	_, err := p.db.ExecContext(ctx, qSetExclusion, e.Name, e.Reason, e.ExcludedBy, e.ExcludedAt.UTC())
	return err
}

func (p *Postgres) RemoveExclusion(ctx context.Context, name string) (bool, error) {
	res, err := p.db.ExecContext(ctx, `DELETE FROM repo_exclusions WHERE name = $1`, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (p *Postgres) Exclusions(ctx context.Context) ([]RepoExclusion, error) {
	rows, err := p.db.QueryContext(ctx, qExclusions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RepoExclusion
	for rows.Next() {
		var e RepoExclusion
		if err := rows.Scan(&e.Name, &e.Reason, &e.ExcludedBy, &e.ExcludedAt); err != nil {
			return nil, err
		}
		e.ExcludedAt = e.ExcludedAt.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}
