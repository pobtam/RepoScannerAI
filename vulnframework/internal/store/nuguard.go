package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/wanaware/vulnframework/internal/nuguardopt"
)

// NuGuard controls (migration 0019): settings security owners choose within
// the operator's ceiling, their audit trail, the status the scan worker
// publishes, and stored AI-SBOMs (VM-UI-F-1201..1212).
//
// The API writes settings and reads the rest. Only the scan worker talks to
// NuGuard; what the API knows about the service it knows from the status row
// the worker writes.

// ToolNotRequested is a tool a scan did not ask for, with the reason
// ("nuguard": off for this repository). Neither ok nor failed.
type ToolNotRequested = nuguardopt.NotRequested

// NuGuardStatus is what the scan worker last found out about NuGuard.
type NuGuardStatus struct {
	// Configured is false when the worker has no -nuguard-url.
	Configured bool      `json:"configured"`
	Reachable  bool      `json:"reachable"`
	CheckedAt  time.Time `json:"checked_at"`
	// ServiceVersion is the NuGuard version the service reports; empty when
	// it could not be asked. PinnedVersion is config/tools.lock's.
	ServiceVersion string `json:"service_version,omitempty"`
	PinnedVersion  string `json:"pinned_version,omitempty"`
	VersionOK      bool   `json:"version_ok"`
	// ToolsAllowedByService is the service's own tool list; nil when unknown.
	ToolsAllowedByService []string           `json:"tools_allowed_by_service,omitempty"`
	Ceiling               nuguardopt.Ceiling `json:"ceiling"`
	// LastError is the last check's failure, sanitized as a gap detail is.
	LastError string `json:"last_error,omitempty"`
}

// NuGuardSettingsRecord is the fleet setting and who last set it.
type NuGuardSettingsRecord struct {
	Settings  nuguardopt.Fleet `json:"settings"`
	ChangedBy string           `json:"changed_by"`
	ChangedAt time.Time        `json:"changed_at"`
}

// NuGuardRepoOverrideRecord is one repository's override and who set it.
type NuGuardRepoOverrideRecord struct {
	Repo      string                  `json:"repo"`
	Override  nuguardopt.RepoOverride `json:"override"`
	ChangedBy string                  `json:"changed_by"`
	ChangedAt time.Time               `json:"changed_at"`
}

// NuGuardAuditEntry is one settings change. Before nil is "not set"; After
// nil is "cleared".
type NuGuardAuditEntry struct {
	ID        int64           `json:"id"`
	Scope     string          `json:"scope"` // fleet or repository
	Repo      string          `json:"repo,omitempty"`
	Before    json.RawMessage `json:"before"`
	After     json.RawMessage `json:"after"`
	ChangedBy string          `json:"changed_by"`
	ChangedAt time.Time       `json:"changed_at"`
	Reason    string          `json:"reason,omitempty"`
}

// AISBOM is an AI-SBOM a scan kept. Document is nil, and Withheld says why,
// when it was not stored (over the size cap).
type AISBOM struct {
	RunID          string          `json:"run_id"`
	Repo           string          `json:"repo"`
	CommitSHA      string          `json:"commit_sha"`
	NuGuardVersion string          `json:"nuguard_version"`
	SizeBytes      int64           `json:"size_bytes"`
	SHA256         string          `json:"sha256"`
	Document       json.RawMessage `json:"document,omitempty"`
	Withheld       string          `json:"withheld,omitempty"`
	StoredAt       time.Time       `json:"stored_at"`
}

// NuGuardStore is the NuGuard half of the store.
type NuGuardStore interface {
	// NuGuardStatus is the worker's last status row; ok is false when no
	// worker has written one.
	NuGuardStatus(ctx context.Context) (st NuGuardStatus, ok bool, err error)
	// PutNuGuardStatus replaces the status row. The scan worker's only.
	PutNuGuardStatus(ctx context.Context, st NuGuardStatus) error

	// NuGuardSettings is the fleet setting; ok is false when it has never
	// been set, and the worker's flag defaults apply.
	NuGuardSettings(ctx context.Context) (rec NuGuardSettingsRecord, ok bool, err error)
	// SetNuGuardSettings replaces the fleet setting and writes its audit row,
	// in one transaction.
	SetNuGuardSettings(ctx context.Context, f nuguardopt.Fleet, by, reason string, at time.Time) (NuGuardAuditEntry, error)

	// NuGuardRepoOverride is one repository's override; ok is false when it
	// has none.
	NuGuardRepoOverride(ctx context.Context, repo string) (rec NuGuardRepoOverrideRecord, ok bool, err error)
	// NuGuardRepoOverrides lists every override, by repository.
	NuGuardRepoOverrides(ctx context.Context) ([]NuGuardRepoOverrideRecord, error)
	// SetNuGuardRepoOverride sets a repository's override, or clears it when
	// o is nil, and writes the audit row, in one transaction.
	SetNuGuardRepoOverride(ctx context.Context, repo string, o *nuguardopt.RepoOverride, by, reason string, at time.Time) (NuGuardAuditEntry, error)

	// NuGuardAudit lists settings changes newest first, with id below
	// before (0: from the newest). repo "" lists every scope.
	NuGuardAudit(ctx context.Context, repo string, before int64, limit int) ([]NuGuardAuditEntry, error)
	// CountNuGuardChanges counts one person's changes since a time, for the
	// rate limit.
	CountNuGuardChanges(ctx context.Context, by string, since time.Time) (int, error)

	// PutAISBOM stores a kept AI-SBOM, or the reason it was not kept.
	PutAISBOM(ctx context.Context, s AISBOM) error
	// GetAISBOM returns the AI-SBOM a scan kept; ok is false when none was.
	GetAISBOM(ctx context.Context, runID, repo string) (s AISBOM, ok bool, err error)
}

var (
	_ NuGuardStore = (*Memory)(nil)
	_ NuGuardStore = (*Postgres)(nil)
)

// overrideClears reports whether an override says nothing: inherit, with no
// tools or posture of its own. Setting one clears the row.
func overrideClears(o *nuguardopt.RepoOverride) bool {
	return o == nil || (o.Mode == nuguardopt.RepoInherit && o.Tools == nil && o.IncludePosture == nil)
}

func validAISBOM(s AISBOM) error {
	if s.RunID == "" || s.Repo == "" || s.StoredAt.IsZero() {
		return errors.New("store: an AI-SBOM needs a run, a repository and a time")
	}
	if (s.Document == nil) == (s.Withheld == "") {
		return errors.New("store: an AI-SBOM is either stored or withheld with a reason")
	}
	return nil
}

func rawOrNil(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// --- memory ------------------------------------------------------------------

type memNuGuard struct {
	status    *NuGuardStatus
	settings  *NuGuardSettingsRecord
	overrides map[string]NuGuardRepoOverrideRecord
	audit     []NuGuardAuditEntry
	sboms     map[[2]string]AISBOM
}

func (m *Memory) NuGuardStatus(context.Context) (NuGuardStatus, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ng.status == nil {
		return NuGuardStatus{}, false, nil
	}
	return cloneStatus(*m.ng.status), true, nil
}

func (m *Memory) PutNuGuardStatus(_ context.Context, st NuGuardStatus) error {
	if st.CheckedAt.IsZero() {
		return errors.New("store: a NuGuard status needs the time it was checked")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c := cloneStatus(st)
	c.CheckedAt = c.CheckedAt.UTC()
	m.ng.status = &c
	return nil
}

// cloneStatus round-trips through JSON, as Postgres does, so neither backend
// hands out slices the caller can change under it.
func cloneStatus(st NuGuardStatus) NuGuardStatus {
	var out NuGuardStatus
	b, _ := json.Marshal(st)
	_ = json.Unmarshal(b, &out)
	return out
}

func (m *Memory) NuGuardSettings(context.Context) (NuGuardSettingsRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ng.settings == nil {
		return NuGuardSettingsRecord{}, false, nil
	}
	rec := *m.ng.settings
	rec.Settings.Tools = append([]string{}, rec.Settings.Tools...)
	return rec, true, nil
}

func (m *Memory) SetNuGuardSettings(_ context.Context, f nuguardopt.Fleet, by, reason string, at time.Time) (NuGuardAuditEntry, error) {
	if by == "" || at.IsZero() {
		return NuGuardAuditEntry{}, errors.New("store: a settings change needs who and when")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.Tools == nil {
		f.Tools = []string{}
	}
	var before json.RawMessage
	if m.ng.settings != nil {
		before = rawOrNil(m.ng.settings.Settings)
	}
	rec := NuGuardSettingsRecord{Settings: f, ChangedBy: by, ChangedAt: at.UTC()}
	m.ng.settings = &rec
	return m.appendAuditLocked(NuGuardAuditEntry{Scope: "fleet", Before: before, After: rawOrNil(f),
		ChangedBy: by, ChangedAt: at.UTC(), Reason: reason}), nil
}

func (m *Memory) appendAuditLocked(e NuGuardAuditEntry) NuGuardAuditEntry {
	e.ID = int64(len(m.ng.audit) + 1)
	m.ng.audit = append(m.ng.audit, e)
	return e
}

func (m *Memory) NuGuardRepoOverride(_ context.Context, repo string) (NuGuardRepoOverrideRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.ng.overrides[repo]
	return rec, ok, nil
}

func (m *Memory) NuGuardRepoOverrides(context.Context) ([]NuGuardRepoOverrideRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]NuGuardRepoOverrideRecord, 0, len(m.ng.overrides))
	for _, r := range m.ng.overrides {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repo < out[j].Repo })
	return out, nil
}

func (m *Memory) SetNuGuardRepoOverride(_ context.Context, repo string, o *nuguardopt.RepoOverride, by, reason string, at time.Time) (NuGuardAuditEntry, error) {
	if repo == "" || by == "" || at.IsZero() {
		return NuGuardAuditEntry{}, errors.New("store: an override change needs a repository, who and when")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ng.overrides == nil {
		m.ng.overrides = map[string]NuGuardRepoOverrideRecord{}
	}
	var before json.RawMessage
	if prev, ok := m.ng.overrides[repo]; ok {
		before = rawOrNil(prev.Override)
	}
	var after json.RawMessage
	if overrideClears(o) {
		delete(m.ng.overrides, repo)
	} else {
		m.ng.overrides[repo] = NuGuardRepoOverrideRecord{Repo: repo, Override: *o, ChangedBy: by, ChangedAt: at.UTC()}
		after = rawOrNil(*o)
	}
	return m.appendAuditLocked(NuGuardAuditEntry{Scope: "repository", Repo: repo, Before: before, After: after,
		ChangedBy: by, ChangedAt: at.UTC(), Reason: reason}), nil
}

func (m *Memory) NuGuardAudit(_ context.Context, repo string, before int64, limit int) ([]NuGuardAuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []NuGuardAuditEntry
	for i := len(m.ng.audit) - 1; i >= 0 && len(out) < limit; i-- {
		e := m.ng.audit[i]
		if (before > 0 && e.ID >= before) || (repo != "" && e.Repo != repo) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (m *Memory) CountNuGuardChanges(_ context.Context, by string, since time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.ng.audit {
		if e.ChangedBy == by && !e.ChangedAt.Before(since) {
			n++
		}
	}
	return n, nil
}

func (m *Memory) PutAISBOM(_ context.Context, s AISBOM) error {
	if err := validAISBOM(s); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ng.sboms == nil {
		m.ng.sboms = map[[2]string]AISBOM{}
	}
	s.StoredAt = s.StoredAt.UTC()
	m.ng.sboms[[2]string{s.RunID, s.Repo}] = s
	return nil
}

func (m *Memory) GetAISBOM(_ context.Context, runID, repo string) (AISBOM, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.ng.sboms[[2]string{runID, repo}]
	return s, ok, nil
}

// --- postgres ----------------------------------------------------------------

func (p *Postgres) NuGuardStatus(ctx context.Context) (NuGuardStatus, bool, error) {
	var raw []byte
	err := p.db.QueryRowContext(ctx, `SELECT status FROM nuguard_status WHERE id`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return NuGuardStatus{}, false, nil
	}
	if err != nil {
		return NuGuardStatus{}, false, fmt.Errorf("store: reading the NuGuard status: %w", err)
	}
	var st NuGuardStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return NuGuardStatus{}, false, fmt.Errorf("store: the NuGuard status is unreadable: %w", err)
	}
	st.CheckedAt = st.CheckedAt.UTC()
	return st, true, nil
}

func (p *Postgres) PutNuGuardStatus(ctx context.Context, st NuGuardStatus) error {
	if st.CheckedAt.IsZero() {
		return errors.New("store: a NuGuard status needs the time it was checked")
	}
	st.CheckedAt = st.CheckedAt.UTC()
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO nuguard_status (id, status, checked_at) VALUES (TRUE, $1, $2)
ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, checked_at = EXCLUDED.checked_at`, b, st.CheckedAt)
	if err != nil {
		return fmt.Errorf("store: writing the NuGuard status: %w", err)
	}
	return nil
}

func (p *Postgres) NuGuardSettings(ctx context.Context) (NuGuardSettingsRecord, bool, error) {
	var raw []byte
	var rec NuGuardSettingsRecord
	err := p.db.QueryRowContext(ctx, `SELECT settings, changed_by, changed_at FROM nuguard_settings WHERE id`).
		Scan(&raw, &rec.ChangedBy, &rec.ChangedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return rec, false, nil
	}
	if err != nil {
		return rec, false, fmt.Errorf("store: reading the NuGuard settings: %w", err)
	}
	if err := json.Unmarshal(raw, &rec.Settings); err != nil {
		return rec, false, fmt.Errorf("store: the NuGuard settings are unreadable: %w", err)
	}
	if rec.Settings.Tools == nil {
		rec.Settings.Tools = []string{}
	}
	rec.ChangedAt = rec.ChangedAt.UTC()
	return rec, true, nil
}

func (p *Postgres) SetNuGuardSettings(ctx context.Context, f nuguardopt.Fleet, by, reason string, at time.Time) (NuGuardAuditEntry, error) {
	if by == "" || at.IsZero() {
		return NuGuardAuditEntry{}, errors.New("store: a settings change needs who and when")
	}
	if f.Tools == nil {
		f.Tools = []string{}
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return NuGuardAuditEntry{}, err
	}
	defer tx.Rollback()
	var before []byte
	err = tx.QueryRowContext(ctx, `SELECT settings FROM nuguard_settings WHERE id FOR UPDATE`).Scan(&before)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return NuGuardAuditEntry{}, err
	}
	after := rawOrNil(f)
	if _, err := tx.ExecContext(ctx, `INSERT INTO nuguard_settings (id, settings, changed_by, changed_at)
VALUES (TRUE, $1, $2, $3)
ON CONFLICT (id) DO UPDATE SET settings = EXCLUDED.settings, changed_by = EXCLUDED.changed_by,
  changed_at = EXCLUDED.changed_at`, []byte(after), by, at.UTC()); err != nil {
		return NuGuardAuditEntry{}, fmt.Errorf("store: writing the NuGuard settings: %w", err)
	}
	e := NuGuardAuditEntry{Scope: "fleet", Before: canonical(before), After: after, ChangedBy: by, ChangedAt: at.UTC(), Reason: reason}
	if err := insertAudit(ctx, tx, &e); err != nil {
		return NuGuardAuditEntry{}, err
	}
	return e, tx.Commit()
}

// canonical re-encodes a stored JSON document so both backends return the
// same bytes (Postgres reorders and respaces JSONB).
func canonical(b []byte) json.RawMessage {
	if b == nil {
		return nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return json.RawMessage(b)
	}
	return rawOrNil(v)
}

func insertAudit(ctx context.Context, tx *sql.Tx, e *NuGuardAuditEntry) error {
	err := tx.QueryRowContext(ctx, `INSERT INTO nuguard_settings_audit
  (scope, repo, before, after, changed_by, changed_at, reason)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		e.Scope, nullString(e.Repo), nullJSON(e.Before), nullJSON(e.After), e.ChangedBy, e.ChangedAt, e.Reason).Scan(&e.ID)
	if err != nil {
		return fmt.Errorf("store: writing the NuGuard settings audit: %w", err)
	}
	return nil
}

func (p *Postgres) NuGuardRepoOverride(ctx context.Context, repo string) (NuGuardRepoOverrideRecord, bool, error) {
	rec, err := overrideRow(p.db.QueryRowContext(ctx,
		`SELECT repo, override, changed_by, changed_at FROM nuguard_repo_overrides WHERE repo = $1`, repo))
	if errors.Is(err, sql.ErrNoRows) {
		return rec, false, nil
	}
	if err != nil {
		return rec, false, fmt.Errorf("store: reading the NuGuard override of %s: %w", repo, err)
	}
	return rec, true, nil
}

func overrideRow(sc interface{ Scan(...any) error }) (NuGuardRepoOverrideRecord, error) {
	var rec NuGuardRepoOverrideRecord
	var raw []byte
	if err := sc.Scan(&rec.Repo, &raw, &rec.ChangedBy, &rec.ChangedAt); err != nil {
		return rec, err
	}
	rec.ChangedAt = rec.ChangedAt.UTC()
	return rec, json.Unmarshal(raw, &rec.Override)
}

func (p *Postgres) NuGuardRepoOverrides(ctx context.Context) ([]NuGuardRepoOverrideRecord, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT repo, override, changed_by, changed_at FROM nuguard_repo_overrides ORDER BY repo`)
	if err != nil {
		return nil, fmt.Errorf("store: listing NuGuard overrides: %w", err)
	}
	defer rows.Close()
	out := []NuGuardRepoOverrideRecord{}
	for rows.Next() {
		rec, err := overrideRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (p *Postgres) SetNuGuardRepoOverride(ctx context.Context, repo string, o *nuguardopt.RepoOverride, by, reason string, at time.Time) (NuGuardAuditEntry, error) {
	if repo == "" || by == "" || at.IsZero() {
		return NuGuardAuditEntry{}, errors.New("store: an override change needs a repository, who and when")
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return NuGuardAuditEntry{}, err
	}
	defer tx.Rollback()
	var before []byte
	err = tx.QueryRowContext(ctx, `SELECT override FROM nuguard_repo_overrides WHERE repo = $1 FOR UPDATE`, repo).Scan(&before)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return NuGuardAuditEntry{}, err
	}
	var after json.RawMessage
	if overrideClears(o) {
		if _, err := tx.ExecContext(ctx, `DELETE FROM nuguard_repo_overrides WHERE repo = $1`, repo); err != nil {
			return NuGuardAuditEntry{}, err
		}
	} else {
		after = rawOrNil(*o)
		if _, err := tx.ExecContext(ctx, `INSERT INTO nuguard_repo_overrides (repo, override, changed_by, changed_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (repo) DO UPDATE SET override = EXCLUDED.override, changed_by = EXCLUDED.changed_by,
  changed_at = EXCLUDED.changed_at`, repo, []byte(after), by, at.UTC()); err != nil {
			return NuGuardAuditEntry{}, fmt.Errorf("store: writing the NuGuard override of %s: %w", repo, err)
		}
	}
	e := NuGuardAuditEntry{Scope: "repository", Repo: repo, Before: canonical(before), After: after,
		ChangedBy: by, ChangedAt: at.UTC(), Reason: reason}
	if err := insertAudit(ctx, tx, &e); err != nil {
		return NuGuardAuditEntry{}, err
	}
	return e, tx.Commit()
}

func (p *Postgres) NuGuardAudit(ctx context.Context, repo string, before int64, limit int) ([]NuGuardAuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := p.db.QueryContext(ctx, `SELECT id, scope, repo, before::text, after::text, changed_by, changed_at, reason
FROM nuguard_settings_audit
WHERE ($1 = '' OR repo = $1) AND ($2 = 0 OR id < $2)
ORDER BY id DESC LIMIT $3`, repo, before, limit)
	if err != nil {
		return nil, fmt.Errorf("store: reading the NuGuard settings audit: %w", err)
	}
	defer rows.Close()
	var out []NuGuardAuditEntry
	for rows.Next() {
		var e NuGuardAuditEntry
		var r, b, a sql.NullString
		if err := rows.Scan(&e.ID, &e.Scope, &r, &b, &a, &e.ChangedBy, &e.ChangedAt, &e.Reason); err != nil {
			return nil, err
		}
		e.Repo = r.String
		if b.Valid {
			e.Before = canonical([]byte(b.String))
		}
		if a.Valid {
			e.After = canonical([]byte(a.String))
		}
		e.ChangedAt = e.ChangedAt.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *Postgres) CountNuGuardChanges(ctx context.Context, by string, since time.Time) (int, error) {
	var n int
	err := p.db.QueryRowContext(ctx, `SELECT count(*) FROM nuguard_settings_audit
WHERE changed_by = $1 AND changed_at >= $2`, by, since.UTC()).Scan(&n)
	return n, err
}

func (p *Postgres) PutAISBOM(ctx context.Context, s AISBOM) error {
	if err := validAISBOM(s); err != nil {
		return err
	}
	_, err := p.db.ExecContext(ctx, `INSERT INTO ai_sbom
  (run_id, repo, commit_sha, nuguard_version, size_bytes, sha256, document, withheld, stored_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (run_id, repo) DO UPDATE SET commit_sha = EXCLUDED.commit_sha,
  nuguard_version = EXCLUDED.nuguard_version, size_bytes = EXCLUDED.size_bytes, sha256 = EXCLUDED.sha256,
  document = EXCLUDED.document, withheld = EXCLUDED.withheld, stored_at = EXCLUDED.stored_at`,
		s.RunID, s.Repo, s.CommitSHA, s.NuGuardVersion, s.SizeBytes, s.SHA256, nullJSON(s.Document),
		nullString(s.Withheld), s.StoredAt.UTC())
	if err != nil {
		return fmt.Errorf("store: storing the AI-SBOM of %s in %s: %w", s.Repo, s.RunID, err)
	}
	return nil
}

func (p *Postgres) GetAISBOM(ctx context.Context, runID, repo string) (AISBOM, bool, error) {
	s := AISBOM{RunID: runID, Repo: repo}
	var doc, withheld sql.NullString
	err := p.db.QueryRowContext(ctx, `SELECT commit_sha, nuguard_version, size_bytes, sha256, document::text, withheld, stored_at
FROM ai_sbom WHERE run_id = $1 AND repo = $2`, runID, repo).
		Scan(&s.CommitSHA, &s.NuGuardVersion, &s.SizeBytes, &s.SHA256, &doc, &withheld, &s.StoredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AISBOM{}, false, nil
	}
	if err != nil {
		return AISBOM{}, false, fmt.Errorf("store: reading the AI-SBOM of %s in %s: %w", repo, runID, err)
	}
	if doc.Valid {
		s.Document = json.RawMessage(doc.String)
	}
	s.Withheld = withheld.String
	s.StoredAt = s.StoredAt.UTC()
	return s, true, nil
}

// ResolveNuGuard reads a repository's stored settings and resolves what its
// scan uses under ceiling, with req as the scan's own options (nil: none).
// The scan worker calls it for every repository it scans, and the API's
// preview calls it to say what a scan would use: one path, so the two
// cannot disagree (VM-UI-F-1204).
func ResolveNuGuard(ctx context.Context, st NuGuardStore, c nuguardopt.Ceiling, repo string, req *nuguardopt.Request) (nuguardopt.Effective, []nuguardopt.ClipNote, error) {
	var fleet *nuguardopt.Fleet
	if rec, ok, err := st.NuGuardSettings(ctx); err != nil {
		return nuguardopt.Effective{}, nil, err
	} else if ok {
		fleet = &rec.Settings
	}
	var override *nuguardopt.RepoOverride
	if rec, ok, err := st.NuGuardRepoOverride(ctx, repo); err != nil {
		return nuguardopt.Effective{}, nil, err
	} else if ok {
		override = &rec.Override
	}
	e, clips := nuguardopt.ResolveNuGuardOptions(c, fleet, override, req)
	return e, clips, nil
}
