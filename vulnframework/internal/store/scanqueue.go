package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/nuguardopt"
)

// The scan queue (migration 0017): scans requested from the interface, vfctl
// or the timer, claimed and run by the scan worker. The API only inserts.

// ScanStatus is where a request is.
type ScanStatus string

const (
	ScanQueued      ScanStatus = "queued"
	ScanRunning     ScanStatus = "running"
	ScanFinished    ScanStatus = "finished"
	ScanFailed      ScanStatus = "failed"
	ScanTimedOut    ScanStatus = "timed_out"
	ScanInterrupted ScanStatus = "interrupted"
	ScanRefused     ScanStatus = "refused"
)

// Active reports whether the request still holds its repository's slot.
func (s ScanStatus) Active() bool { return s == ScanQueued || s == ScanRunning }

// needsReason lists the outcomes that must say why.
func (s ScanStatus) needsReason() bool {
	return s == ScanFailed || s == ScanTimedOut || s == ScanInterrupted || s == ScanRefused
}

// ScanSource is who asked.
type ScanSource string

const (
	SourceWeb   ScanSource = "web"
	SourceVfctl ScanSource = "vfctl"
	SourceTimer ScanSource = "timer"
)

// ScanRequest is one requested scan of one repository.
type ScanRequest struct {
	ID          string     `json:"id"`
	Repo        string     `json:"repo"`
	BatchID     string     `json:"batch_id,omitempty"`
	Source      ScanSource `json:"source"`
	RequestedBy string     `json:"requested_by"`
	RequestedAt time.Time  `json:"requested_at"`
	Status      ScanStatus `json:"status"`
	Reason      string     `json:"reason,omitempty"`
	RunID       string     `json:"run_id,omitempty"`
	WorkerID    string     `json:"worker_id,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	HeartbeatAt *time.Time `json:"heartbeat_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	RetryOf     string     `json:"retry_of,omitempty"`
	// NuGuard is what the request asked of NuGuard; nil asked nothing, and
	// the repository and fleet settings apply (VM-UI-F-1204).
	NuGuard *nuguardopt.Request `json:"nuguard,omitempty"`
}

// ScanQuery selects requests, newest first.
type ScanQuery struct {
	Repo  string
	Limit int
}

// ScanQueue is the queue half of the store.
type ScanQueue interface {
	// EnqueueScan inserts a queued request, or, when the repository already
	// has a queued or running request, returns that one with merged=true.
	// Status refused may also be enqueued directly, as an audit record of a
	// refused request; it never merges and never holds the slot.
	EnqueueScan(ctx context.Context, r ScanRequest) (got ScanRequest, merged bool, err error)
	// ClaimScans moves the oldest queued request to running for workerID,
	// together with every other queued request in its batch, and returns
	// them. ok is false when nothing is queued.
	ClaimScans(ctx context.Context, workerID string, now time.Time) (claimed []ScanRequest, ok bool, err error)
	// HeartbeatScans records that workerID is still running these requests.
	HeartbeatScans(ctx context.Context, workerID string, ids []string, now time.Time) error
	// FinishScan records a running request's outcome. Only the worker that
	// claimed it may finish it, and only from running.
	FinishScan(ctx context.Context, id, workerID string, status ScanStatus, reason, runID string, now time.Time) error
	// InterruptStaleScans marks running requests whose heartbeat is older
	// than before as interrupted, with reason, and returns how many.
	InterruptStaleScans(ctx context.Context, before time.Time, reason string, now time.Time) (int, error)
	// InterruptWorkerScans marks every request workerID is running as
	// interrupted, for a worker that is stopping.
	InterruptWorkerScans(ctx context.Context, workerID, reason string, now time.Time) (int, error)
	// ScanRequests lists requests, newest first.
	ScanRequests(ctx context.Context, q ScanQuery) ([]ScanRequest, error)
	// GetScanRequest returns one request.
	GetScanRequest(ctx context.Context, id string) (ScanRequest, bool, error)
	// CountScanRequests counts requests by requester since a time, refused
	// ones included, for the rate limit.
	CountScanRequests(ctx context.Context, requestedBy string, since time.Time) (int, error)
}

var (
	_ ScanQueue = (*Memory)(nil)
	_ ScanQueue = (*Postgres)(nil)
)

// ErrScanNotRunning refuses to finish a request that is not running, or not
// this worker's.
var ErrScanNotRunning = errors.New("store: that scan request is not running under this worker")

// NewScanRequestID returns a time-ordered identifier.
func NewScanRequestID(now time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("sr_%s_%s", now.UTC().Format("20060102T150405.000Z"), hex.EncodeToString(b[:]))
}

func requestJSON(r *nuguardopt.Request) json.RawMessage {
	if r == nil {
		return nil
	}
	return rawOrNil(r)
}

func validScanRequest(r ScanRequest) error {
	if r.ID == "" || r.Repo == "" || r.RequestedBy == "" || r.RequestedAt.IsZero() {
		return fmt.Errorf("store: a scan request needs an id, a repository, a requester and a time")
	}
	switch r.Source {
	case SourceWeb, SourceVfctl, SourceTimer:
	default:
		return fmt.Errorf("store: unknown scan source %q", r.Source)
	}
	switch r.Status {
	case ScanQueued:
	case ScanRefused:
		if r.Reason == "" {
			return fmt.Errorf("store: a refused scan request must say why")
		}
	default:
		return fmt.Errorf("store: a scan request is enqueued as queued or refused, not %q", r.Status)
	}
	return nil
}

// --- memory ------------------------------------------------------------------

func (m *Memory) EnqueueScan(_ context.Context, r ScanRequest) (ScanRequest, bool, error) {
	if err := validScanRequest(r); err != nil {
		return ScanRequest{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scanRequests == nil {
		m.scanRequests = map[string]ScanRequest{}
	}
	if r.Status == ScanQueued {
		for _, x := range m.scanRequests {
			if x.Repo == r.Repo && x.Status.Active() {
				return x, true, nil
			}
		}
	}
	if _, dup := m.scanRequests[r.ID]; dup {
		return ScanRequest{}, false, fmt.Errorf("store: scan request %s already exists", r.ID)
	}
	m.scanRequests[r.ID] = r
	return r, false, nil
}

func (m *Memory) ClaimScans(_ context.Context, workerID string, now time.Time) ([]ScanRequest, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var queued []ScanRequest
	for _, x := range m.scanRequests {
		if x.Status == ScanQueued {
			queued = append(queued, x)
		}
	}
	if len(queued) == 0 {
		return nil, false, nil
	}
	sortScanOldestFirst(queued)
	head := queued[0]
	var out []ScanRequest
	for _, x := range queued {
		if x.ID == head.ID || (head.BatchID != "" && x.BatchID == head.BatchID) {
			t := now
			x.Status, x.WorkerID, x.StartedAt, x.HeartbeatAt = ScanRunning, workerID, &t, &t
			m.scanRequests[x.ID] = x
			out = append(out, x)
		}
	}
	return out, true, nil
}

func (m *Memory) HeartbeatScans(_ context.Context, workerID string, ids []string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		x, ok := m.scanRequests[id]
		if ok && x.Status == ScanRunning && x.WorkerID == workerID {
			t := now
			x.HeartbeatAt = &t
			m.scanRequests[id] = x
		}
	}
	return nil
}

func (m *Memory) FinishScan(_ context.Context, id, workerID string, status ScanStatus, reason, runID string, now time.Time) error {
	if err := validFinish(status, reason); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.scanRequests[id]
	if !ok || x.Status != ScanRunning || x.WorkerID != workerID {
		return ErrScanNotRunning
	}
	t := now
	x.Status, x.Reason, x.RunID, x.FinishedAt = status, reason, runID, &t
	m.scanRequests[id] = x
	return nil
}

func validFinish(status ScanStatus, reason string) error {
	switch status {
	case ScanFinished, ScanFailed, ScanTimedOut, ScanInterrupted, ScanRefused:
	default:
		return fmt.Errorf("store: %q is not a finishing status", status)
	}
	if status.needsReason() && strings.TrimSpace(reason) == "" {
		return fmt.Errorf("store: a %s scan must say why", status)
	}
	return nil
}

func (m *Memory) InterruptStaleScans(_ context.Context, before time.Time, reason string, now time.Time) (int, error) {
	return m.interrupt(func(x ScanRequest) bool {
		return x.HeartbeatAt == nil || x.HeartbeatAt.Before(before)
	}, reason, now)
}

func (m *Memory) InterruptWorkerScans(_ context.Context, workerID, reason string, now time.Time) (int, error) {
	return m.interrupt(func(x ScanRequest) bool { return x.WorkerID == workerID }, reason, now)
}

func (m *Memory) interrupt(match func(ScanRequest) bool, reason string, now time.Time) (int, error) {
	if strings.TrimSpace(reason) == "" {
		return 0, fmt.Errorf("store: an interruption must say why")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, x := range m.scanRequests {
		if x.Status == ScanRunning && match(x) {
			t := now
			x.Status, x.Reason, x.FinishedAt = ScanInterrupted, reason, &t
			m.scanRequests[id] = x
			n++
		}
	}
	return n, nil
}

func (m *Memory) ScanRequests(_ context.Context, q ScanQuery) ([]ScanRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ScanRequest
	for _, x := range m.scanRequests {
		if q.Repo == "" || x.Repo == q.Repo {
			out = append(out, x)
		}
	}
	sortScanOldestFirst(out)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func (m *Memory) GetScanRequest(_ context.Context, id string) (ScanRequest, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.scanRequests[id]
	return x, ok, nil
}

func (m *Memory) CountScanRequests(_ context.Context, requestedBy string, since time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, x := range m.scanRequests {
		if x.RequestedBy == requestedBy && !x.RequestedAt.Before(since) {
			n++
		}
	}
	return n, nil
}

func sortScanOldestFirst(s []ScanRequest) {
	sort.Slice(s, func(i, j int) bool {
		if !s[i].RequestedAt.Equal(s[j].RequestedAt) {
			return s[i].RequestedAt.Before(s[j].RequestedAt)
		}
		return s[i].ID < s[j].ID
	})
}

// --- postgres ----------------------------------------------------------------

const scanCols = `id, repo, batch_id, source, requested_by, requested_at, status, reason,
  run_id, worker_id, started_at, heartbeat_at, finished_at, retry_of, nuguard::text`

func scanRow(sc interface{ Scan(...any) error }) (ScanRequest, error) {
	var (
		r                                 ScanRequest
		batch, reason, run, worker, retry sql.NullString
		started, heartbeat, finished      sql.NullTime
		source, status                    string
		ng                                sql.NullString
	)
	if err := sc.Scan(&r.ID, &r.Repo, &batch, &source, &r.RequestedBy, &r.RequestedAt, &status, &reason,
		&run, &worker, &started, &heartbeat, &finished, &retry, &ng); err != nil {
		return r, err
	}
	if ng.Valid {
		r.NuGuard = &nuguardopt.Request{}
		if err := json.Unmarshal([]byte(ng.String), r.NuGuard); err != nil {
			return r, fmt.Errorf("store: scan request %s has unreadable NuGuard options: %w", r.ID, err)
		}
	}
	r.Source, r.Status = ScanSource(source), ScanStatus(status)
	r.BatchID, r.Reason, r.RunID, r.WorkerID, r.RetryOf = batch.String, reason.String, run.String, worker.String, retry.String
	r.RequestedAt = r.RequestedAt.UTC()
	for _, p := range []struct {
		src sql.NullTime
		dst **time.Time
	}{{started, &r.StartedAt}, {heartbeat, &r.HeartbeatAt}, {finished, &r.FinishedAt}} {
		if p.src.Valid {
			t := p.src.Time.UTC()
			*p.dst = &t
		}
	}
	return r, nil
}

func (p *Postgres) EnqueueScan(ctx context.Context, r ScanRequest) (ScanRequest, bool, error) {
	if err := validScanRequest(r); err != nil {
		return ScanRequest{}, false, err
	}
	insert := `INSERT INTO scan_requests (id, repo, batch_id, source, requested_by, requested_at, status, reason, retry_of,
  nuguard)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	if r.Status == ScanQueued {
		// The partial unique index decides: a second active request for the
		// repository is not inserted, and the existing one is returned.
		insert += ` ON CONFLICT (repo) WHERE status IN ('queued', 'running') DO NOTHING`
	}
	res, err := p.db.ExecContext(ctx, insert, r.ID, r.Repo, nullString(r.BatchID), string(r.Source),
		r.RequestedBy, r.RequestedAt.UTC(), string(r.Status), nullString(r.Reason), nullString(r.RetryOf),
		nullJSON(requestJSON(r.NuGuard)))
	if err != nil {
		return ScanRequest{}, false, fmt.Errorf("store: enqueueing a scan of %s: %w", r.Repo, err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return r, false, nil
	}
	row := p.db.QueryRowContext(ctx, `SELECT `+scanCols+` FROM scan_requests
WHERE repo = $1 AND status IN ('queued', 'running')`, r.Repo)
	existing, err := scanRow(row)
	if err != nil {
		return ScanRequest{}, false, fmt.Errorf("store: reading the active scan of %s: %w", r.Repo, err)
	}
	return existing, true, nil
}

func (p *Postgres) ClaimScans(ctx context.Context, workerID string, now time.Time) ([]ScanRequest, bool, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	var headID string
	var batch sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT id, batch_id FROM scan_requests WHERE status = 'queued'
ORDER BY requested_at, id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&headID, &batch)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	rows, err := tx.QueryContext(ctx, `UPDATE scan_requests
SET status = 'running', worker_id = $1, started_at = $2, heartbeat_at = $2
WHERE status = 'queued' AND (id = $3 OR ($4::text IS NOT NULL AND batch_id = $4))
RETURNING `+scanCols, workerID, now.UTC(), headID, batch)
	if err != nil {
		return nil, false, err
	}
	var out []ScanRequest
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			rows.Close()
			return nil, false, err
		}
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	sortScanOldestFirst(out)
	return out, true, nil
}

func (p *Postgres) HeartbeatScans(ctx context.Context, workerID string, ids []string, now time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := p.db.ExecContext(ctx, `UPDATE scan_requests SET heartbeat_at = $1
WHERE status = 'running' AND worker_id = $2 AND id = ANY($3::text[])`, now.UTC(), workerID, pgTextArray(ids))
	return err
}

func (p *Postgres) FinishScan(ctx context.Context, id, workerID string, status ScanStatus, reason, runID string, now time.Time) error {
	if err := validFinish(status, reason); err != nil {
		return err
	}
	res, err := p.db.ExecContext(ctx, `UPDATE scan_requests
SET status = $1, reason = $2, run_id = $3, finished_at = $4
WHERE id = $5 AND status = 'running' AND worker_id = $6`,
		string(status), nullString(reason), nullString(runID), now.UTC(), id, workerID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrScanNotRunning
	}
	return nil
}

func (p *Postgres) InterruptStaleScans(ctx context.Context, before time.Time, reason string, now time.Time) (int, error) {
	if strings.TrimSpace(reason) == "" {
		return 0, fmt.Errorf("store: an interruption must say why")
	}
	res, err := p.db.ExecContext(ctx, `UPDATE scan_requests SET status = 'interrupted', reason = $1, finished_at = $2
WHERE status = 'running' AND (heartbeat_at IS NULL OR heartbeat_at < $3)`, reason, now.UTC(), before.UTC())
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (p *Postgres) InterruptWorkerScans(ctx context.Context, workerID, reason string, now time.Time) (int, error) {
	if strings.TrimSpace(reason) == "" {
		return 0, fmt.Errorf("store: an interruption must say why")
	}
	res, err := p.db.ExecContext(ctx, `UPDATE scan_requests SET status = 'interrupted', reason = $1, finished_at = $2
WHERE status = 'running' AND worker_id = $3`, reason, now.UTC(), workerID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (p *Postgres) ScanRequests(ctx context.Context, q ScanQuery) ([]ScanRequest, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 1000
	}
	rows, err := p.db.QueryContext(ctx, `SELECT `+scanCols+` FROM scan_requests
WHERE ($1 = '' OR repo = $1) ORDER BY requested_at DESC, id DESC LIMIT $2`, q.Repo, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanRequest
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) GetScanRequest(ctx context.Context, id string) (ScanRequest, bool, error) {
	r, err := scanRow(p.db.QueryRowContext(ctx, `SELECT `+scanCols+` FROM scan_requests WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ScanRequest{}, false, nil
	}
	return r, err == nil, err
}

func (p *Postgres) CountScanRequests(ctx context.Context, requestedBy string, since time.Time) (int, error) {
	var n int
	err := p.db.QueryRowContext(ctx, `SELECT count(*) FROM scan_requests
WHERE requested_by = $1 AND requested_at >= $2`, requestedBy, since.UTC()).Scan(&n)
	return n, err
}

// ScanRefusal says why a repository may not be scanned on request, or "" if
// it may. Shared by the API, vfctl and the scan worker, so all three refuse
// the same repositories for the same stated reason.
func ScanRefusal(ctx context.Context, s Store, name string) (string, error) {
	repo, err := s.GetRepo(ctx, name)
	if err != nil {
		return "not a registered repository", nil
	}
	if !repo.Archived {
		return "", nil
	}
	exclusions, err := s.Exclusions(ctx)
	if err != nil {
		return "", err
	}
	for _, e := range exclusions {
		if e.Name == name {
			return "excluded by " + e.ExcludedBy + ": " + e.Reason, nil
		}
	}
	found, err := s.Discovery(ctx)
	if err != nil {
		return "", err
	}
	for _, d := range found {
		if d.Name == name && !d.Included {
			return "skipped at discovery: " + d.Detail, nil
		}
	}
	return "archived in the registry; it is not in scope", nil
}
