package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
)

// Postgres is the production findings store (VM-AD §3, §4.2).
//
// It takes an already-open *sql.DB rather than a DSN so the driver is chosen by
// the binary rather than by this package: the store needs no driver dependency
// of its own, and a caller can substitute one without changing this code.
type Postgres struct {
	db    *sql.DB
	clock func() time.Time
}

// NewPostgres wraps an open database handle.
func NewPostgres(db *sql.DB) *Postgres {
	return &Postgres{db: db, clock: func() time.Time { return time.Now().UTC() }}
}

// SetClock overrides the clock, for deterministic tests.
//
// The clock may be called concurrently: a sweep records results from many
// dispatch goroutines at once. Any replacement must be safe for concurrent use.
func (p *Postgres) SetClock(f func() time.Time) { p.clock = f }

func (p *Postgres) Migrate(ctx context.Context) error {
	migrations, err := LoadMigrations()
	if err != nil {
		return err
	}
	return migrateTo(ctx, p.db, len(migrations))
}

func (p *Postgres) MigrateTo(ctx context.Context, version int) error {
	return migrateTo(ctx, p.db, version)
}

func (p *Postgres) SchemaVersion(ctx context.Context) (int, error) {
	if _, err := p.db.ExecContext(ctx, schemaMigrationsDDL); err != nil {
		return 0, fmt.Errorf("store: creating schema_migrations: %w", err)
	}
	return schemaVersion(ctx, p.db)
}

func (p *Postgres) UpsertRepo(ctx context.Context, r Repo) error {
	_, err := p.db.ExecContext(ctx, qUpsertRepo,
		r.Name, r.Tier, pgTextArray(r.Languages), r.Archived, r.HasTestSuite,
		nullString(r.ModuleTopology), pgTextArray(r.Codeowners), r.HasLockfile)
	if err != nil {
		return fmt.Errorf("store: upsert repo %q: %w", r.Name, err)
	}
	return nil
}

func (p *Postgres) GetRepo(ctx context.Context, name string) (Repo, error) {
	var (
		r         Repo
		langs     string
		owners    sql.NullString
		topology  sql.NullString
		testSuite sql.NullBool
	)
	err := p.db.QueryRowContext(ctx, qGetRepo, name).
		Scan(&r.Name, &r.Tier, &langs, &r.Archived, &testSuite, &topology, &owners, &r.HasLockfile)
	if errors.Is(err, sql.ErrNoRows) {
		return Repo{}, fmt.Errorf("%w: repo %q", ErrNotFound, name)
	}
	if err != nil {
		return Repo{}, fmt.Errorf("store: get repo %q: %w", name, err)
	}
	r.Languages = parseTextArray(langs)
	r.Codeowners = parseTextArray(owners.String)
	r.HasTestSuite = testSuite.Bool
	r.ModuleTopology = topology.String
	return r, nil
}

func (p *Postgres) CreateRun(ctx context.Context, kind RunKind, trigger, image string, toolVersions map[string]string) (Run, error) {
	if !kind.Valid() {
		return Run{}, fmt.Errorf("store: invalid run kind %q", kind)
	}
	versions, err := json.Marshal(toolVersions)
	if err != nil {
		return Run{}, fmt.Errorf("store: encoding tool versions: %w", err)
	}

	// The sequence is allocated by the datastore, never derived from a
	// timestamp, so two runs starting in the same second remain distinct
	// (VM-F-112, VM-ADR-11).
	var seq int64
	if err := p.db.QueryRowContext(ctx, `SELECT nextval('run_seq_`+string(kind)+`')`).Scan(&seq); err != nil {
		return Run{}, fmt.Errorf("store: allocating %s sequence: %w", kind, err)
	}

	run := Run{
		ID:            FormatRunID(kind, seq),
		Kind:          kind,
		Seq:           seq,
		TriggerDetail: trigger,
		StartedAt:     p.clock(),
		ScannerImage:  image,
		ToolVersions:  toolVersions,
	}
	_, err = p.db.ExecContext(ctx, qInsertRun,
		run.ID, string(run.Kind), run.Seq, nullString(run.TriggerDetail),
		run.StartedAt, run.ScannerImage, versions)
	if err != nil {
		return Run{}, fmt.Errorf("store: insert run %s: %w", run.ID, err)
	}
	return run, nil
}

func (p *Postgres) FinishRun(ctx context.Context, runID string, planned, scanned, failed int) error {
	res, err := p.db.ExecContext(ctx, qFinishRun, p.clock(), planned, scanned, failed, runID)
	if err != nil {
		return fmt.Errorf("store: finish run %s: %w", runID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: run %q", ErrNotFound, runID)
	}
	return nil
}

// Runs lists runs newest first, by kind-scoped sequence (VM-ADR-11).
func (p *Postgres) Runs(ctx context.Context, q RunQuery) ([]Run, error) {
	rows, err := p.db.QueryContext(ctx, qRunsList, string(q.Kind), q.BeforeSeq, q.pageSize())
	if err != nil {
		return nil, fmt.Errorf("store: listing runs: %w", err)
	}
	defer rows.Close()

	var out []Run
	for rows.Next() {
		var (
			run      Run
			kind     string
			trigger  sql.NullString
			finished sql.NullTime
			versions []byte
			planned  sql.NullInt64
			scanned  sql.NullInt64
			failed   sql.NullInt64
		)
		if err := rows.Scan(&run.ID, &kind, &run.Seq, &trigger, &run.StartedAt, &finished,
			&run.ScannerImage, &versions, &planned, &scanned, &failed); err != nil {
			return nil, err
		}
		run.Kind = RunKind(kind)
		run.TriggerDetail = trigger.String
		if finished.Valid {
			t := finished.Time.UTC()
			run.FinishedAt = &t
		}
		run.StartedAt = run.StartedAt.UTC()
		_ = json.Unmarshal(versions, &run.ToolVersions)
		run.ReposPlanned, run.ReposScanned, run.ReposFailed =
			int(planned.Int64), int(scanned.Int64), int(failed.Int64)
		out = append(out, run)
	}
	return out, rows.Err()
}

// RemediationPRsForFinding returns every pull request that carried a finding.
func (p *Postgres) RemediationPRsForFinding(ctx context.Context, fp string) ([]RemediationPR, error) {
	rows, err := p.db.QueryContext(ctx, qPRsForFinding, fp)
	if err != nil {
		return nil, fmt.Errorf("store: reading remediation attempts for %s: %w", fp, err)
	}
	var branches []string
	for rows.Next() {
		var branch string
		if err := rows.Scan(&branch); err != nil {
			rows.Close()
			return nil, err
		}
		branches = append(branches, branch)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	out := make([]RemediationPR, 0, len(branches))
	for _, branch := range branches {
		pr, ok, err := p.GetRemediationPR(ctx, branch)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, pr)
		}
	}
	return out, nil
}

func (p *Postgres) GetRun(ctx context.Context, id string) (Run, error) {
	var (
		run      Run
		kind     string
		trigger  sql.NullString
		finished sql.NullTime
		versions []byte
		planned  sql.NullInt64
		scanned  sql.NullInt64
		failed   sql.NullInt64
	)
	err := p.db.QueryRowContext(ctx, qGetRun, id).Scan(
		&run.ID, &kind, &run.Seq, &trigger, &run.StartedAt, &finished,
		&run.ScannerImage, &versions, &planned, &scanned, &failed)
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, fmt.Errorf("%w: run %q", ErrNotFound, id)
	}
	if err != nil {
		return Run{}, fmt.Errorf("store: get run %s: %w", id, err)
	}
	run.Kind = RunKind(kind)
	run.TriggerDetail = trigger.String
	if finished.Valid {
		t := finished.Time.UTC()
		run.FinishedAt = &t
	}
	run.StartedAt = run.StartedAt.UTC()
	_ = json.Unmarshal(versions, &run.ToolVersions)
	run.ReposPlanned, run.ReposScanned, run.ReposFailed = int(planned.Int64), int(scanned.Int64), int(failed.Int64)
	return run, nil
}

func (p *Postgres) RecordScanResult(ctx context.Context, res RepoScanResult) error {
	_, err := p.db.ExecContext(ctx, qUpsertScanResult,
		res.RunID, res.Repo, string(res.Outcome),
		pgTextArray(res.ToolsOK), pgTextArray(res.ToolsFailed),
		nullString(res.FailureCause), nullString(res.FailureDetail),
		nullString(res.FailureOwner), res.DurationSec,
		nullString(res.CommitSHA), nullJSON(res.AIInventory))
	if err != nil {
		return fmt.Errorf("store: record scan result %s/%s: %w", res.RunID, res.Repo, err)
	}
	return nil
}

func (p *Postgres) ScanResults(ctx context.Context, repo string, limit int) ([]RepoScanResult, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.db.QueryContext(ctx, qScanResults, repo, limit)
	if err != nil {
		return nil, fmt.Errorf("store: scan results for %q: %w", repo, err)
	}
	defer rows.Close()

	var out []RepoScanResult
	for rows.Next() {
		var (
			r             RepoScanResult
			outcome       string
			ok, failed    string
			cause, detail sql.NullString
			owner         sql.NullString
			duration      sql.NullInt64
			commit, inv   sql.NullString
		)
		if err := rows.Scan(&r.RunID, &r.Repo, &outcome, &ok, &failed, &cause, &detail, &owner, &duration,
			&commit, &inv); err != nil {
			return nil, err
		}
		r.CommitSHA = commit.String
		if inv.Valid {
			r.AIInventory = json.RawMessage(inv.String)
		}
		r.Outcome = ScanOutcome(outcome)
		r.ToolsOK, r.ToolsFailed = parseTextArray(ok), parseTextArray(failed)
		r.FailureCause, r.FailureDetail, r.FailureOwner = cause.String, detail.String, owner.String
		r.DurationSec = int(duration.Int64)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) UpsertObservations(ctx context.Context, runID, repo string, raws []model.RawFinding) (UpsertStats, error) {
	var stats UpsertStats

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return stats, fmt.Errorf("store: begin upsert: %w", err)
	}
	defer tx.Rollback()

	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM runs WHERE id = $1)`, runID).Scan(&exists); err != nil {
		return stats, err
	}
	if !exists {
		return stats, fmt.Errorf("%w: run %q", ErrNotFound, runID)
	}

	now := p.clock()
	for _, raw := range raws {
		if err := fingerprint.Validate(raw); err != nil {
			return stats, err
		}
		fp := fingerprint.Compute(raw)

		var current sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT state FROM findings WHERE fingerprint = $1`, fp).Scan(&current)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return stats, fmt.Errorf("store: reading finding %s: %w", fp, err)
		}
		decision := PlanUpsert(model.State(current.String), current.Valid)

		switch {
		case decision.Create:
			if _, err := tx.ExecContext(ctx, qInsertFinding,
				fp, repo, string(raw.Category), []byte(`{}`), string(model.Detected),
				now, now, runID, runID); err != nil {
				return stats, fmt.Errorf("store: insert finding %s: %w", fp, err)
			}
			if err := recordTransitionTx(ctx, tx, fp, "", model.Detected, model.TransitionContext{
				Actor: model.ActorScanWorker, Cause: "first observation in " + runID, At: now,
			}); err != nil {
				return stats, err
			}
			stats.Created++

		case decision.Regress:
			if err := transitionTx(ctx, tx, fp, model.Verified, model.Regressed, model.TransitionContext{
				Actor: model.ActorScanWorker, Cause: "observed again in " + runID, At: now,
			}); err != nil {
				return stats, err
			}
			stats.Regressed++
			stats.Observed++

		default:
			stats.Observed++
		}

		if _, err := tx.ExecContext(ctx, qTouchFinding, now, runID, fp); err != nil {
			return stats, fmt.Errorf("store: touch finding %s: %w", fp, err)
		}
		// Seen again: whatever removal was recorded is no longer true.
		if _, err := tx.ExecContext(ctx, qClearRemoval, fp); err != nil {
			return stats, fmt.Errorf("store: clearing removal for %s: %w", fp, err)
		}

		source := SourceOf(fp, runID, now, raw)
		encoded, err := json.Marshal(source)
		if err != nil {
			return stats, fmt.Errorf("store: encoding observation: %w", err)
		}
		if _, err := tx.ExecContext(ctx, qUpsertObservation,
			fp, runID, raw.Tool, now, encoded, []byte(raw.Raw)); err != nil {
			return stats, fmt.Errorf("store: insert observation %s/%s: %w", fp, raw.Tool, err)
		}
		stats.Observations++
	}

	// Recompute the projection for every fingerprint this batch touched.
	for _, raw := range raws {
		fp := fingerprint.Compute(raw)
		if err := reprojectTx(ctx, tx, fp); err != nil {
			return stats, err
		}
	}

	return stats, tx.Commit()
}

func (p *Postgres) Reconcile(ctx context.Context, runID, repo string) (ReconcileStats, error) {
	var stats ReconcileStats

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return stats, fmt.Errorf("store: begin reconcile: %w", err)
	}
	defer tx.Rollback()

	var outcome string
	err = tx.QueryRowContext(ctx,
		`SELECT outcome FROM repo_scan_results WHERE run_id = $1 AND repo = $2`, runID, repo).Scan(&outcome)
	if errors.Is(err, sql.ErrNoRows) {
		return stats, fmt.Errorf("%w: no scan result for repo %q in run %q; reconciliation requires one (VM-ADR-12)",
			ErrNotFound, repo, runID)
	}
	if err != nil {
		return stats, err
	}

	rows, err := tx.QueryContext(ctx, qAbsentFindings, repo, runID)
	if err != nil {
		return stats, fmt.Errorf("store: reading absent findings: %w", err)
	}
	var absent []FindingState
	for rows.Next() {
		var f FindingState
		var state, category string
		if err := rows.Scan(&f.Fingerprint, &state, &category); err != nil {
			rows.Close()
			return stats, err
		}
		f.State = model.State(state)
		f.Category = model.Category(category)
		absent = append(absent, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return stats, err
	}

	actions := resolveGapLinks(PlanReconcile(ScanOutcome(outcome), absent), runID)
	now := p.clock()

	stateOf := map[string]model.State{}
	for _, f := range absent {
		stateOf[f.Fingerprint] = f.State
	}

	for _, a := range actions {
		if a.Verify {
			if err := transitionTx(ctx, tx, a.Fingerprint, stateOf[a.Fingerprint], model.Verified, model.TransitionContext{
				Actor:       model.ActorScanWorker,
				Cause:       "not observed by successful scan in " + runID + " (" + string(a.VerificationReason) + ")",
				At:          now,
				ScanOutcome: ScanOutcome(outcome),
			}); err != nil {
				return stats, err
			}
			// Verifying releases any lease: the remediation it was held for is
			// no longer wanted, and leaving it would keep the sweeper finding a
			// finding that is already closed (VM-AD §6.1.1).
			// The residual warning comes from the shared model rule, so both
			// backends word it identically: a warning phrased differently by
			// each would read as two different problems (OQ-AUDIT-02).
			residual := a.ResidualDetail
			if _, err := tx.ExecContext(ctx, qMarkVerified, now, string(a.VerificationReason),
				a.Fingerprint, residual != "", residual); err != nil {
				return stats, err
			}
			stats.Verified++
			continue
		}
		if a.SecretRemoved {
			if _, err := tx.ExecContext(ctx, qRecordRemoval, a.Fingerprint, runID, now); err != nil {
				return stats, fmt.Errorf("store: recording removal of %s: %w", a.Fingerprint, err)
			}
			stats.SecretsRemoved++
		}
		if _, err := tx.ExecContext(ctx, qMarkNotReobserved,
			a.NotReobserved, nullString(a.GapRunID), a.Fingerprint); err != nil {
			return stats, err
		}
		if a.NotReobserved {
			stats.NotReobserved++
		}
		if a.RetainedUnverified {
			stats.RetainedUnverified++
		}
	}
	return stats, tx.Commit()
}

func (p *Postgres) GetFinding(ctx context.Context, fp string) (model.Finding, error) {
	findings, err := p.queryFindings(ctx, qGetFinding, fp)
	if err != nil {
		return model.Finding{}, err
	}
	if len(findings) == 0 {
		return model.Finding{}, fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	return findings[0], nil
}

func (p *Postgres) ListFindings(ctx context.Context, q Query) ([]model.Finding, error) {
	if !q.Scope.Valid() {
		return nil, ErrScopeRequired
	}

	var (
		where []string
		args  []any
	)
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if q.Repo != "" {
		add("f.repo = $%d", q.Repo)
	}
	if q.Fingerprint != "" {
		add("f.fingerprint = $%d", q.Fingerprint)
	}
	if len(q.States) > 0 {
		add("f.state = ANY($%d)", pgTextArray(statesToStrings(q.States)))
	}
	if len(q.Categories) > 0 {
		add("f.category = ANY($%d)", pgTextArray(categoriesToStrings(q.Categories)))
	}

	switch q.Scope {
	case ScopeOpen:
		add("f.state <> ALL($%d)", pgTextArray(statesToStrings(model.StatesInPartition(model.PartitionResolved))))
	case ScopeRun:
		if q.RunID == "" {
			return nil, fmt.Errorf("store: scope %q requires a run identifier", ScopeRun)
		}
		add("EXISTS (SELECT 1 FROM finding_observations o WHERE o.fingerprint = f.fingerprint AND o.run_id = $%d)", q.RunID)
	}

	query := qListFindingsBase
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY f.fingerprint"
	if q.Limit > 0 {
		args = append(args, q.Limit)
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	return p.queryFindings(ctx, query, args...)
}

func (p *Postgres) queryFindings(ctx context.Context, query string, args ...any) ([]model.Finding, error) {
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: querying findings: %w", err)
	}
	defer rows.Close()

	var out []model.Finding
	for rows.Next() {
		var (
			f             model.Finding
			category      string
			state         string
			data          []byte
			reason        sql.NullString
			priority      sql.NullString
			firstRun      sql.NullString
			lastRun       sql.NullString
			notReobserved bool
			gapRun        sql.NullString
			verifiedBy    sql.NullString
			firstSeenAt   time.Time
			lastSeenAt    time.Time
			resolvedAt    sql.NullTime
			upstream      sql.NullString
		)
		if err := rows.Scan(&f.Fingerprint, &f.Repo, &category, &data, &state,
			&reason, &priority, &firstRun, &lastRun, &notReobserved, &gapRun, &verifiedBy,
			&firstSeenAt, &lastSeenAt, &resolvedAt, &upstream); err != nil {
			return nil, err
		}

		// data holds the materialised projection written by reproject.
		var projected model.Finding
		if len(data) > 0 {
			_ = json.Unmarshal(data, &projected)
		}
		projected.SchemaVersion = model.SchemaVersion
		projected.Fingerprint = f.Fingerprint
		projected.Repo = f.Repo
		projected.Category = model.Category(category)
		projected.State = model.State(state)
		if reason.Valid {
			rc := model.ReasonCode(reason.String)
			projected.ReasonCode = &rc
		}
		projected.Priority = model.Priority(priority.String)
		projected.Provenance.FirstSeenRun = firstRun.String
		projected.Provenance.LastSeenRun = lastRun.String
		projected.Derived.NotReobserved = notReobserved
		if gapRun.Valid {
			g := gapRun.String
			projected.Derived.GapRepoScan = &g
		}
		if verifiedBy.Valid {
			vr := model.VerificationReason(verifiedBy.String)
			projected.VerifiedReason = &vr
		}
		if upstream.Valid && upstream.String != "" {
			u := upstream.String
			projected.Refs.UpstreamFinding = &u
		}
		projected.FirstSeenAt = firstSeenAt.UTC()
		projected.LastSeenAt = lastSeenAt.UTC()
		if resolvedAt.Valid {
			t := resolvedAt.Time.UTC()
			projected.ResolvedAt = &t
		}
		out = append(out, projected)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The feeds' answers, joined at READ time in ONE query for the whole page
	// (OQ-AUDIT-01(b)). Not baked into the stored projection: EPSS
	// republishes daily, and a value frozen into the document would not change
	// until the next scan reprojected the finding.
	if len(out) > 0 {
		var ids []string
		seen := map[string]bool{}
		for i := range out {
			for _, id := range IntelIDs(out[i]) {
				if !seen[id] {
					seen[id] = true
					ids = append(ids, id)
				}
			}
		}
		intel, err := p.IntelFor(ctx, ids)
		if err != nil {
			return nil, err
		}
		for i := range out {
			ApplyIntelToFinding(&out[i], intel)
		}
	}

	// Proposals and removals, joined in the same way: they live outside the
	// document, which every scan rebuilds.
	if len(out) > 0 {
		if err := p.applySecretReviews(ctx, out); err != nil {
			return nil, err
		}
	}

	// The ticket reference is joined from the tickets table rather than read
	// from the finding document. The document is rebuilt from observations on
	// every scan; a reference kept inside it would be erased by the next run,
	// and the run after that would open a duplicate ticket (VM-F-804).
	if len(out) > 0 {
		refs, err := p.ticketURLs(ctx)
		if err != nil {
			return nil, err
		}
		prs, err := p.openPRURLs(ctx)
		if err != nil {
			return nil, err
		}
		for i := range out {
			if url, ok := refs[out[i].Fingerprint]; ok && url != "" {
				u := url
				out[i].Refs.Ticket = &u
			}
			if url, ok := prs[out[i].Fingerprint]; ok && url != "" {
				u := url
				out[i].Refs.PullRequest = &u
			}
		}
	}
	return out, nil
}

func (p *Postgres) Observations(ctx context.Context, fp string) ([]SourceObservation, error) {
	return observationsTx(ctx, p.db, fp)
}

func (p *Postgres) Transitions(ctx context.Context, fp string) ([]model.StateTransition, error) {
	rows, err := p.db.QueryContext(ctx, qTransitions, fp)
	if err != nil {
		return nil, fmt.Errorf("store: reading transitions: %w", err)
	}
	defer rows.Close()

	var out []model.StateTransition
	for rows.Next() {
		var (
			t     model.StateTransition
			from  sql.NullString
			to    string
			actor string
			cause sql.NullString
		)
		if err := rows.Scan(&t.Fingerprint, &from, &to, &actor, &cause, &t.At); err != nil {
			return nil, err
		}
		t.From = model.State(from.String)
		t.To = model.State(to)
		t.Actor = model.Actor(actor)
		t.Cause = cause.String
		t.At = t.At.UTC()
		out = append(out, t)
	}
	return out, rows.Err()
}

func (p *Postgres) ApplyTransition(ctx context.Context, fp string, to model.State, tc model.TransitionContext) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var current string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM findings WHERE fingerprint = $1`, fp).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: finding %q", ErrNotFound, fp)
		}
		return err
	}
	// The store stamps the time, not the caller — see Memory.transitionLocked.
	if tc.At.IsZero() {
		tc.At = p.clock()
	}
	if err := transitionTx(ctx, tx, fp, model.State(current), to, tc); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *Postgres) Close() error { return nil }

// --- transaction helpers ----------------------------------------------------

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func observationsTx(ctx context.Context, q queryer, fp string) ([]SourceObservation, error) {
	rows, err := q.QueryContext(ctx, qObservations, fp)
	if err != nil {
		return nil, fmt.Errorf("store: reading observations: %w", err)
	}
	defer rows.Close()

	var out []SourceObservation
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return nil, err
		}
		var o SourceObservation
		if err := json.Unmarshal(encoded, &o); err != nil {
			return nil, fmt.Errorf("store: decoding observation: %w", err)
		}
		o.ObservedAt = o.ObservedAt.UTC()
		out = append(out, o)
	}
	return out, rows.Err()
}

// transitionTx validates a state change against the model before applying it.
// Validation is never skipped for the database's convenience: an illegal
// transition must be rejected and logged, not silently applied (VM-F-152).
func transitionTx(ctx context.Context, tx *sql.Tx, fp string, from, to model.State, tc model.TransitionContext) error {
	// The lease-bound rule, read inside this transaction so a lease released
	// concurrently cannot slip a finding into the state (OQ-AUDIT-05).
	if LeaseBound(to) {
		var owner sql.NullString
		var expires sql.NullTime
		if err := tx.QueryRowContext(ctx, qGetLease, fp).Scan(&owner, &expires); err != nil {
			return err
		}
		lease := Lease{Fingerprint: fp, Owner: owner.String}
		if expires.Valid {
			at := expires.Time.UTC()
			lease.ExpiresAt = &at
		}
		if err := checkLeaseBound(fp, to, lease, tc.At); err != nil {
			return err
		}
	}
	rec, err := model.ApplyTransition(fp, from, to, tc)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, qSetState, string(to), fp); err != nil {
		return fmt.Errorf("store: setting state for %s: %w", fp, err)
	}
	return insertTransition(ctx, tx, rec)
}

func recordTransitionTx(ctx context.Context, tx *sql.Tx, fp string, from, to model.State, tc model.TransitionContext) error {
	rec, err := model.ApplyTransition(fp, from, to, tc)
	if err != nil {
		return err
	}
	return insertTransition(ctx, tx, rec)
}

func insertTransition(ctx context.Context, tx *sql.Tx, rec model.StateTransition) error {
	_, err := tx.ExecContext(ctx, qInsertTransition,
		rec.Fingerprint, nullString(string(rec.From)), string(rec.To),
		string(rec.Actor), nullString(rec.Cause), rec.At)
	if err != nil {
		return fmt.Errorf("store: recording transition for %s: %w", rec.Fingerprint, err)
	}
	return nil
}

// reprojectTx recomputes and stores the merged view of a finding.
//
// The projection is recomputed from the retained observations on every change
// rather than updated incrementally, which is what makes it order-independent
// (VM-AD §8.6).
func reprojectTx(ctx context.Context, tx *sql.Tx, fp string) error {
	obs, err := observationsTx(ctx, tx, fp)
	if err != nil {
		return err
	}
	// The derived block is computed separately and persisted into the same
	// document, so it must survive a reprojection. Losing it here would make
	// every SLA silently revert to uncomputed after the next scan.
	var existingDerived model.Derived
	var existingTriage *model.Triage
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT data FROM findings WHERE fingerprint = $1`, fp).Scan(&raw); err == nil && len(raw) > 0 {
		var prior model.Finding
		if json.Unmarshal(raw, &prior) == nil {
			existingDerived = prior.Derived
			existingTriage = prior.Triage
		}
	}
	p := Project(LatestPerSource(obs))

	view := model.Finding{
		Identity: model.Identity{
			PrimaryID: p.PrimaryID, Aliases: p.Aliases, RuleID: optionalString(p.RuleID),
		},
		Location: p.LocationOf(),
		Versions: model.Versions{
			Current: p.CurrentVersion, Fixed: p.FixedVersion, Introduced: p.IntroducedIn,
		},
		Classification: withFirstParty(p.Classification, p.FirstPartyPath),
		Provenance:     model.Provenance{Tools: p.Tools},
		Refs:           model.Refs{AdvisoryURL: optionalString(p.AdvisoryURL)},
		CredentialType: p.CredentialType,
		Description:    p.Description,
		Annotations:    p.Annotations,
		Derived:        existingDerived,
		Triage:         existingTriage,
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		return fmt.Errorf("store: encoding projection: %w", err)
	}

	_, err = tx.ExecContext(ctx, qSetProjection,
		encoded, p.ReachabilityConflict, nullString(p.ConflictDetail),
		pgTextArray(p.FixedCandidates), fp)
	if err != nil {
		return fmt.Errorf("store: storing projection for %s: %w", fp, err)
	}
	return nil
}

// --- small conversions ------------------------------------------------------

// nullTime renders an absent timestamp as SQL NULL. An absent date must not
// become the zero time: "no snapshot" and "a snapshot from year one" are
// different claims, and only one of them is true.
func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullJSON stores an absent document as NULL, so "not measured" stays
// distinguishable from an empty one.
func nullJSON(b json.RawMessage) any {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	return string(b)
}

// pgTextArray renders a Go slice as a Postgres text array literal. Written by
// hand so the store needs no driver-specific array type and therefore no
// driver dependency.
func pgTextArray(in []string) string {
	if len(in) == 0 {
		return "{}"
	}
	quoted := make([]string, len(in))
	for i, s := range in {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		quoted[i] = `"` + s + `"`
	}
	return "{" + strings.Join(quoted, ",") + "}"
}

// parseTextArray reads a Postgres text array literal.
func parseTextArray(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "{}" {
		return nil
	}
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")

	var (
		out     []string
		cur     strings.Builder
		inQuote bool
		escaped bool
	)
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			inQuote = !inQuote
		case r == ',' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func statesToStrings(in []model.State) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = string(s)
	}
	return out
}

func categoriesToStrings(in []model.Category) []string {
	out := make([]string, len(in))
	for i, c := range in {
		out[i] = string(c)
	}
	return out
}

// --- Planned scope (OQ-P2-02) ----------------------------------------------

func (p *Postgres) RecordPlan(ctx context.Context, entries []PlanEntry) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, e := range entries {
		if !e.State.Valid() {
			return fmt.Errorf("store: invalid dispatch state %q", e.State)
		}
		at := e.PlannedAt
		if at.IsZero() {
			at = p.clock()
		}
		if _, err := tx.ExecContext(ctx, qUpsertPlan,
			e.RunID, e.Repo, string(e.State), nullString(e.SkipReason), at); err != nil {
			return fmt.Errorf("store: recording plan for %s/%s: %w", e.RunID, e.Repo, err)
		}
	}
	return tx.Commit()
}

func (p *Postgres) MarkDispatched(ctx context.Context, runID, repo string) error {
	res, err := p.db.ExecContext(ctx, qMarkDispatched, p.clock(), runID, repo)
	if err != nil {
		return fmt.Errorf("store: marking %s dispatched: %w", repo, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: repo %q is not in the planned scope of %q", ErrNotFound, repo, runID)
	}
	return nil
}

func (p *Postgres) MarkSkipped(ctx context.Context, runID, repo, reason string) error {
	if reason == "" {
		return fmt.Errorf("store: skipping %s in %s requires a reason", repo, runID)
	}
	res, err := p.db.ExecContext(ctx, qMarkSkipped, reason, runID, repo)
	if err != nil {
		return fmt.Errorf("store: marking %s skipped: %w", repo, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: repo %q is not in the planned scope of %q", ErrNotFound, repo, runID)
	}
	return nil
}

func (p *Postgres) PlanEntries(ctx context.Context, runID string) ([]PlanEntry, error) {
	return p.scanPlan(ctx, qPlanEntries, runID)
}

func (p *Postgres) scanPlan(ctx context.Context, query, runID string) ([]PlanEntry, error) {
	rows, err := p.db.QueryContext(ctx, query, runID)
	if err != nil {
		return nil, fmt.Errorf("store: reading plan: %w", err)
	}
	defer rows.Close()

	var out []PlanEntry
	for rows.Next() {
		var (
			e          PlanEntry
			state      string
			reason     sql.NullString
			dispatched sql.NullTime
		)
		if err := rows.Scan(&e.RunID, &e.Repo, &state, &reason, &e.PlannedAt, &dispatched); err != nil {
			return nil, err
		}
		e.State = DispatchState(state)
		e.SkipReason = reason.String
		e.PlannedAt = e.PlannedAt.UTC()
		if dispatched.Valid {
			t := dispatched.Time.UTC()
			e.DispatchedAt = &t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *Postgres) CloseRun(ctx context.Context, runID string) (CloseStats, error) {
	stats := CloseStats{SkipReasons: map[string]int{}}

	if err := p.db.QueryRowContext(ctx, qCountProduced, runID).Scan(&stats.Produced); err != nil {
		return stats, fmt.Errorf("store: counting produced results: %w", err)
	}

	missing, err := p.scanPlan(ctx, qPlanWithoutResult, runID)
	if err != nil {
		return stats, err
	}

	for _, e := range missing {
		outcome, cause := planCloseAction(e)
		if err := p.RecordScanResult(ctx, RepoScanResult{
			RunID: runID, Repo: e.Repo, Outcome: outcome,
			FailureCause: cause,
			FailureOwner: "platform",
		}); err != nil {
			return stats, err
		}
		switch outcome {
		case model.ScanNoResult:
			stats.NoResult++
		default:
			stats.NotDispatched++
		}
		stats.SkipReasons[cause]++
	}
	return stats, nil
}

// --- Leases (VM-AD §6.2) ----------------------------------------------------

func (p *Postgres) AcquireLease(ctx context.Context, fp, owner string, expiresAt time.Time) error {
	if owner == "" {
		return fmt.Errorf("store: a lease requires an owner")
	}
	res, err := p.db.ExecContext(ctx, qAcquireLease, owner, expiresAt.UTC(), fp)
	if err != nil {
		return fmt.Errorf("store: acquiring lease on %s: %w", fp, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	return nil
}

func (p *Postgres) ReleaseLease(ctx context.Context, fp string) error {
	res, err := p.db.ExecContext(ctx, qReleaseLease, fp)
	if err != nil {
		return fmt.Errorf("store: releasing lease on %s: %w", fp, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	return nil
}

func (p *Postgres) GetLease(ctx context.Context, fp string) (Lease, error) {
	var (
		owner   sql.NullString
		expires sql.NullTime
	)
	err := p.db.QueryRowContext(ctx, qGetLease, fp).Scan(&owner, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Lease{}, fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	if err != nil {
		return Lease{}, fmt.Errorf("store: reading lease on %s: %w", fp, err)
	}
	l := Lease{Fingerprint: fp, Owner: owner.String}
	if expires.Valid {
		t := expires.Time.UTC()
		l.ExpiresAt = &t
	}
	return l, nil
}

func (p *Postgres) SweepExpiredLeases(ctx context.Context, now time.Time) (int, error) {
	rows, err := p.db.QueryContext(ctx, qExpiredLeases, string(model.AutoRemediating), now.UTC())
	if err != nil {
		return 0, fmt.Errorf("store: finding expired leases: %w", err)
	}
	var expired []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			rows.Close()
			return 0, err
		}
		expired = append(expired, fp)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, fp := range expired {
		if err := p.ApplyTransition(ctx, fp, model.Triaged, model.TransitionContext{
			Actor: model.ActorOrchestrator,
			Cause: "lease expired; reverting so a crashed worker cannot strand the finding (VM-F-158)",
			At:    now,
		}); err != nil {
			return 0, err
		}
		if err := p.ReleaseLease(ctx, fp); err != nil {
			return 0, err
		}
	}
	return len(expired), nil
}

// RepoNames lists every registered repository, sorted.
func (p *Postgres) RepoNames(ctx context.Context) ([]string, error) {
	rows, err := p.db.QueryContext(ctx, qRepoNames)
	if err != nil {
		return nil, fmt.Errorf("store: listing repositories: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// FleetCoverage derives each repository's coverage state from its scan history.
func (p *Postgres) FleetCoverage(ctx context.Context, kind RunKind, repos []string) ([]CoverageState, error) {
	out := make([]CoverageState, 0, len(repos))

	for _, repo := range repos {
		rows, err := p.db.QueryContext(ctx, qRepoScanHistory, repo, string(kind))
		if err != nil {
			return nil, fmt.Errorf("store: reading scan history for %s: %w", repo, err)
		}

		var (
			history   []RepoScanResult
			startedAt = map[string]time.Time{}
		)
		for rows.Next() {
			var (
				r       RepoScanResult
				outcome string
				cause   sql.NullString
				started time.Time
			)
			if err := rows.Scan(&r.RunID, &outcome, &cause, &started); err != nil {
				rows.Close()
				return nil, err
			}
			r.Repo = repo
			r.Outcome = ScanOutcome(outcome)
			r.FailureCause = cause.String
			history = append(history, r)
			startedAt[r.RunID] = started.UTC()
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}

		c := coverageFromHistory(repo, history, func(id string) (time.Time, bool) {
			at, ok := startedAt[id]
			return at, ok
		})
		out = append(out, c)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Repo < out[j].Repo })
	return out, nil
}

// SetTriage persists a finding's triage narrative (VM-F-301).
func (p *Postgres) SetTriage(ctx context.Context, fp string, t model.Triage) error {
	encoded, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("store: encoding triage: %w", err)
	}
	res, err := p.db.ExecContext(ctx, qSetTriage, encoded, fp)
	if err != nil {
		return fmt.Errorf("store: persisting triage for %s: %w", fp, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	return nil
}

// SetPriority persists the computed priority and reason code.
func (p *Postgres) SetPriority(ctx context.Context, fp string, pr model.Priority, reason *model.ReasonCode) error {
	if pr != "" && !pr.Valid() {
		return fmt.Errorf("store: invalid priority %q", pr)
	}
	var reasonArg any
	if reason != nil {
		if !reason.Valid() {
			return fmt.Errorf("store: invalid reason code %q", *reason)
		}
		reasonArg = string(*reason)
	}
	res, err := p.db.ExecContext(ctx, qSetPriority, nullString(string(pr)), reasonArg, fp)
	if err != nil {
		return fmt.Errorf("store: persisting priority for %s: %w", fp, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	return nil
}

// PreviousRun returns the run of the same kind immediately before seq.
func (p *Postgres) PreviousRun(ctx context.Context, kind RunKind, beforeSeq int64) (Run, error) {
	var (
		run                      Run
		k                        string
		trigger                  sql.NullString
		finished                 sql.NullTime
		versions                 []byte
		planned, scanned, failed sql.NullInt64
	)
	err := p.db.QueryRowContext(ctx, qPreviousRun, string(kind), beforeSeq).Scan(
		&run.ID, &k, &run.Seq, &trigger, &run.StartedAt, &finished,
		&run.ScannerImage, &versions, &planned, &scanned, &failed)
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, nil
	}
	if err != nil {
		return Run{}, fmt.Errorf("store: previous %s run before %d: %w", kind, beforeSeq, err)
	}
	run.Kind = RunKind(k)
	run.TriggerDetail = trigger.String
	if finished.Valid {
		t := finished.Time.UTC()
		run.FinishedAt = &t
	}
	run.StartedAt = run.StartedAt.UTC()
	_ = json.Unmarshal(versions, &run.ToolVersions)
	run.ReposPlanned, run.ReposScanned, run.ReposFailed = int(planned.Int64), int(scanned.Int64), int(failed.Int64)
	return run, nil
}

// SaveReport records an issued report (VM-ADR-15).
func (p *Postgres) SaveReport(ctx context.Context, r Report) error {
	existing, err := p.GetReport(ctx, r.ID)
	if err == nil {
		if existing.ContentHash != r.ContentHash {
			return fmt.Errorf("store: report %s is already issued with a different content hash (%s); "+
				"reports are immutable — issue a new report that supersedes it (VM-ADR-15)", r.ID, existing.ContentHash)
		}
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}

	if r.Supersedes != "" {
		if _, gerr := p.GetReport(ctx, r.Supersedes); gerr != nil {
			if errors.Is(gerr, ErrNotFound) {
				return fmt.Errorf("store: report %s claims to supersede %s, which does not exist. "+
					"A lineage pointing at nothing is worse than none: the interface would show a "+
					"relationship that cannot be followed (VM-UI-F-1108)", r.ID, r.Supersedes)
			}
			return gerr
		}
		// Checked here as well as by the unique index, so both backends refuse
		// it with the same words. The index is the guarantee; this is the
		// explanation.
		if existing, found, serr := p.SupersededBy(ctx, r.Supersedes); serr != nil {
			return serr
		} else if found && existing.ID != r.ID {
			return fmt.Errorf("store: report %s already supersedes %s. A second one would fork "+
				"the lineage with no defined winner, and the relationship VM-UI-F-1108 requires "+
				"to be stated could not be", existing.ID, r.Supersedes)
		}
	}

	_, err = p.db.ExecContext(ctx, qInsertReport,
		r.ID, r.AnchorRunID, r.Kind, nullString(r.Repo), r.Template,
		[]byte(r.Query), r.ContentHash, []byte(r.Content),
		r.IssuedAt.UTC(), nullString(r.IssuedBy), nullString(r.Supersedes),
		r.Redacted, r.WithheldCount)
	if err != nil {
		return fmt.Errorf("store: saving report %s: %w", r.ID, err)
	}
	return nil
}

// GetReport returns an issued report.
func (p *Postgres) GetReport(ctx context.Context, id string) (Report, error) {
	rows, err := p.db.QueryContext(ctx, qGetReport, id)
	if err != nil {
		return Report{}, fmt.Errorf("store: reading report %s: %w", id, err)
	}
	defer rows.Close()
	out, err := scanReports(rows)
	if err != nil {
		return Report{}, err
	}
	if len(out) == 0 {
		return Report{}, fmt.Errorf("%w: report %q", ErrNotFound, id)
	}
	return out[0], nil
}

// ReportsForRun lists the reports anchored to a run.
func (p *Postgres) ReportsForRun(ctx context.Context, runID string) ([]Report, error) {
	rows, err := p.db.QueryContext(ctx, qReportsForRun, runID)
	if err != nil {
		return nil, fmt.Errorf("store: reading reports for %s: %w", runID, err)
	}
	defer rows.Close()
	return scanReports(rows)
}

// SupersededBy returns the report that replaces id.
func (p *Postgres) SupersededBy(ctx context.Context, id string) (Report, bool, error) {
	if id == "" {
		return Report{}, false, nil
	}
	rows, err := p.db.QueryContext(ctx, qSupersededBy, id)
	if err != nil {
		return Report{}, false, fmt.Errorf("store: reading what supersedes %s: %w", id, err)
	}
	defer rows.Close()

	out, err := scanReports(rows)
	if err != nil {
		return Report{}, false, err
	}
	if len(out) == 0 {
		return Report{}, false, nil
	}
	if len(out) > 1 {
		// The unique index makes this unreachable, and it is checked anyway:
		// an invariant enforced in one place and assumed in another is an
		// invariant that survives exactly until somebody drops the index.
		return Report{}, false, fmt.Errorf(
			"store: %d reports claim to supersede %s. The lineage has forked and the relationship "+
				"VM-UI-F-1108 requires to be stated cannot be", len(out), id)
	}
	return out[0], true, nil
}

func scanReports(rows *sql.Rows) ([]Report, error) {
	var out []Report
	for rows.Next() {
		var (
			r                          Report
			repo, issuedBy, supersedes sql.NullString
			query, content             []byte
		)
		if err := rows.Scan(&r.ID, &r.AnchorRunID, &r.Kind, &repo, &r.Template,
			&query, &r.ContentHash, &content, &r.IssuedAt, &issuedBy, &supersedes,
			&r.Redacted, &r.WithheldCount); err != nil {
			return nil, err
		}
		r.Repo, r.IssuedBy, r.Supersedes = repo.String, issuedBy.String, supersedes.String
		r.Query, r.Content = query, content
		r.IssuedAt = r.IssuedAt.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetSLA persists the computed SLA position (VM-F-908).
func (p *Postgres) SetSLA(ctx context.Context, fp string, d model.Derived) error {
	encoded, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("store: encoding derived: %w", err)
	}
	res, err := p.db.ExecContext(ctx, qSetSLA, encoded, fp)
	if err != nil {
		return fmt.Errorf("store: persisting SLA for %s: %w", fp, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	return nil
}

// --- Tickets (VM-AD §13.2) --------------------------------------------------

// SaveTicket records or updates a finding's ticket.
func (p *Postgres) SaveTicket(ctx context.Context, t Ticket) error {
	if t.Fingerprint == "" {
		return fmt.Errorf("store: a ticket record needs a fingerprint; it is the idempotency key (VM-F-804)")
	}
	created := t.CreatedAt
	if created.IsZero() {
		created = p.clock()
	}
	var closed any
	if t.ClosedAt != nil {
		closed = t.ClosedAt.UTC()
	}
	_, err := p.db.ExecContext(ctx, qUpsertTicket,
		t.Fingerprint, t.Backend, t.Ref, t.URL,
		nullString(t.MirrorBackend), nullString(t.MirrorRef), created.UTC(), closed)
	if err != nil {
		return fmt.Errorf("store: saving ticket for %s: %w", t.Fingerprint, err)
	}
	if t.Reopened {
		// Explicit, because the upsert deliberately preserves closure: a
		// routine re-save must never silently reopen a closed ticket
		// (VM-F-806).
		if _, err := p.db.ExecContext(ctx, qReopenTicket, t.Fingerprint); err != nil {
			return fmt.Errorf("store: reopening ticket for %s: %w", t.Fingerprint, err)
		}
	}
	return nil
}

// GetTicket returns a finding's ticket record, if one is known.
func (p *Postgres) GetTicket(ctx context.Context, fingerprint string) (Ticket, bool, error) {
	var (
		t                   Ticket
		mirrorBackend, mRef sql.NullString
		closed              sql.NullTime
	)
	err := p.db.QueryRowContext(ctx, qGetTicket, fingerprint).Scan(
		&t.Fingerprint, &t.Backend, &t.Ref, &t.URL, &mirrorBackend, &mRef, &t.CreatedAt, &closed)
	if errors.Is(err, sql.ErrNoRows) {
		return Ticket{}, false, nil
	}
	if err != nil {
		return Ticket{}, false, fmt.Errorf("store: reading ticket for %s: %w", fingerprint, err)
	}
	t.MirrorBackend, t.MirrorRef = mirrorBackend.String, mRef.String
	t.CreatedAt = t.CreatedAt.UTC()
	if closed.Valid {
		at := closed.Time.UTC()
		t.ClosedAt = &at
	}
	return t, true, nil
}

// DeleteTicket removes the local record, leaving the backend untouched.
func (p *Postgres) DeleteTicket(ctx context.Context, fingerprint string) error {
	if _, err := p.db.ExecContext(ctx, qDeleteTicket, fingerprint); err != nil {
		return fmt.Errorf("store: deleting ticket for %s: %w", fingerprint, err)
	}
	return nil
}

// CloseTicket records that a finding's ticket was closed (VM-F-811).
func (p *Postgres) CloseTicket(ctx context.Context, fingerprint string, at time.Time) error {
	res, err := p.db.ExecContext(ctx, qCloseTicket, fingerprint, at.UTC())
	if err != nil {
		return fmt.Errorf("store: closing ticket for %s: %w", fingerprint, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: ticket for %q", ErrNotFound, fingerprint)
	}
	return nil
}

// ticketURLs returns every known ticket URL, keyed by fingerprint.
//
// Read separately from the finding document because the document is rebuilt
// from observations on every scan: a reference stored inside it would be erased
// by the next run and the run after that would open a duplicate ticket.
func (p *Postgres) ticketURLs(ctx context.Context) (map[string]string, error) {
	rows, err := p.db.QueryContext(ctx, qTicketURLs)
	if err != nil {
		return nil, fmt.Errorf("store: reading ticket references: %w", err)
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var fp, url string
		if err := rows.Scan(&fp, &url); err != nil {
			return nil, err
		}
		out[fp] = url
	}
	return out, rows.Err()
}

// --- Ticket operation queue (VM-F-812) --------------------------------------

func (p *Postgres) EnqueueTicketOp(ctx context.Context, op TicketOp) error {
	created := op.CreatedAt
	if created.IsZero() {
		created = p.clock()
	}
	_, err := p.db.ExecContext(ctx, qInsertTicketOp,
		op.Fingerprint, op.Kind, []byte(op.Payload), op.Attempts,
		op.NextAttemptAt.UTC(), nullString(op.LastError), created.UTC())
	if err != nil {
		return fmt.Errorf("store: queueing ticket op for %s: %w", op.Fingerprint, err)
	}
	return nil
}

func (p *Postgres) DueTicketOps(ctx context.Context, now time.Time, limit int) ([]TicketOp, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.db.QueryContext(ctx, qDueTicketOps, now.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("store: reading due ticket ops: %w", err)
	}
	defer rows.Close()

	var out []TicketOp
	for rows.Next() {
		var (
			op      TicketOp
			payload []byte
			lastErr sql.NullString
		)
		if err := rows.Scan(&op.ID, &op.Fingerprint, &op.Kind, &payload, &op.Attempts,
			&op.NextAttemptAt, &lastErr, &op.CreatedAt); err != nil {
			return nil, err
		}
		op.Payload = payload
		op.LastError = lastErr.String
		op.NextAttemptAt = op.NextAttemptAt.UTC()
		op.CreatedAt = op.CreatedAt.UTC()
		out = append(out, op)
	}
	return out, rows.Err()
}

func (p *Postgres) CompleteTicketOp(ctx context.Context, id int64) error {
	res, err := p.db.ExecContext(ctx, qCompleteTicketOp, id)
	if err != nil {
		return fmt.Errorf("store: completing ticket op %d: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: ticket op %d", ErrNotFound, id)
	}
	return nil
}

func (p *Postgres) RetryTicketOp(ctx context.Context, id int64, next time.Time, lastErr string) error {
	res, err := p.db.ExecContext(ctx, qRetryTicketOp, id, next.UTC(), nullString(lastErr))
	if err != nil {
		return fmt.Errorf("store: rescheduling ticket op %d: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: ticket op %d", ErrNotFound, id)
	}
	return nil
}

// --- Per-repository remediation lock (VM-AD §7.3, VM-F-503) -----------------

func (p *Postgres) AcquireRepoLock(ctx context.Context, repo, owner string, expiresAt time.Time) error {
	return p.AcquireRepoLockAt(ctx, repo, owner, expiresAt, p.clock())
}

func (p *Postgres) AcquireRepoLockAt(ctx context.Context, repo, owner string, expiresAt, now time.Time) error {
	if owner == "" {
		return fmt.Errorf("store: a repository lock needs an owner; an anonymous lock cannot be released or attributed")
	}
	res, err := p.db.ExecContext(ctx, qAcquireRepoLock, repo, owner, expiresAt.UTC(), now.UTC())
	if err != nil {
		return fmt.Errorf("store: acquiring the remediation lock on %s: %w", repo, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// No row changed: someone else holds an unexpired lock. Read it back so
		// the error names the holder.
		held, gerr := p.GetRepoLock(ctx, repo)
		if gerr != nil {
			return fmt.Errorf("%w: on %s", ErrRepoLocked, repo)
		}
		return fmt.Errorf("%w: held by %s until %s", ErrRepoLocked, held.Owner, held.ExpiresAt)
	}
	return nil
}

func (p *Postgres) ReleaseRepoLock(ctx context.Context, repo, owner string) error {
	held, err := p.GetRepoLock(ctx, repo)
	if err != nil {
		return err
	}
	if held.Owner == "" {
		return nil
	}
	if held.Owner != owner {
		return fmt.Errorf("store: %s cannot release %s's lock on %s; "+
			"releasing another worker's lock would reintroduce concurrent remediation mid-flight", owner, held.Owner, repo)
	}
	if _, err := p.db.ExecContext(ctx, qReleaseRepoLock, repo, owner); err != nil {
		return fmt.Errorf("store: releasing the remediation lock on %s: %w", repo, err)
	}
	return nil
}

func (p *Postgres) GetRepoLock(ctx context.Context, repo string) (RepoLock, error) {
	var (
		l         RepoLock
		expiresAt time.Time
	)
	err := p.db.QueryRowContext(ctx, qGetRepoLock, repo).Scan(&l.Repo, &l.Owner, &l.AcquiredAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RepoLock{}, nil
	}
	if err != nil {
		return RepoLock{}, fmt.Errorf("store: reading the remediation lock on %s: %w", repo, err)
	}
	exp := expiresAt.UTC()
	l.AcquiredAt = l.AcquiredAt.UTC()
	l.ExpiresAt = &exp
	return l, nil
}

func (p *Postgres) SweepExpiredRepoLocks(ctx context.Context, now time.Time) (int, error) {
	res, err := p.db.ExecContext(ctx, qSweepRepoLocks, now.UTC())
	if err != nil {
		return 0, fmt.Errorf("store: sweeping expired remediation locks: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// --- Remediation pull requests (VM-AD §11) ----------------------------------

func (p *Postgres) SaveRemediationPR(ctx context.Context, pr RemediationPR) error {
	if pr.Branch == "" {
		return fmt.Errorf("store: a remediation pull request needs a branch; it is the idempotency key (VM-F-502)")
	}
	opened := pr.OpenedAt
	if opened.IsZero() {
		opened = p.clock()
	}
	var closed any
	if pr.ClosedAt != nil {
		closed = pr.ClosedAt.UTC()
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, qUpsertRemediationPR,
		pr.Branch, pr.Repo, pr.FixGroupID, pr.Number, pr.URL, pr.State, opened.UTC(), closed,
		pr.Merged, pr.TicketRef, pr.TicketURL); err != nil {
		return fmt.Errorf("store: saving remediation pull request %s: %w", pr.Branch, err)
	}
	// Membership is replaced wholesale, so a group recomputed with a different
	// membership cannot leave stale rows behind claiming coverage it no longer
	// has.
	if len(pr.Findings) > 0 {
		if _, err := tx.ExecContext(ctx, qDeletePRFindings, pr.Branch); err != nil {
			return err
		}
		for _, fp := range pr.Findings {
			if _, err := tx.ExecContext(ctx, qInsertPRFinding, pr.Branch, fp); err != nil {
				return fmt.Errorf("store: linking %s to %s: %w", fp, pr.Branch, err)
			}
		}
	}
	return tx.Commit()
}

func (p *Postgres) GetRemediationPR(ctx context.Context, branch string) (RemediationPR, bool, error) {
	pr, err := p.scanRemediationPR(ctx, qGetRemediationPR, branch)
	if errors.Is(err, sql.ErrNoRows) {
		return RemediationPR{}, false, nil
	}
	if err != nil {
		return RemediationPR{}, false, err
	}
	return pr, true, nil
}

func (p *Postgres) RemediationPRForFinding(ctx context.Context, fingerprint string) (RemediationPR, bool, error) {
	pr, err := p.scanRemediationPR(ctx, qRemediationPRForFinding, fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return RemediationPR{}, false, nil
	}
	if err != nil {
		return RemediationPR{}, false, err
	}
	return pr, true, nil
}

func (p *Postgres) scanRemediationPR(ctx context.Context, query string, arg any) (RemediationPR, error) {
	var (
		pr        RemediationPR
		number    sql.NullInt64
		url       sql.NullString
		closed    sql.NullTime
		ticketRef sql.NullString
		ticketURL sql.NullString
		confirmed sql.NullTime
	)
	err := p.db.QueryRowContext(ctx, query, arg).Scan(
		&pr.Branch, &pr.Repo, &pr.FixGroupID, &number, &url, &pr.State, &pr.OpenedAt, &closed,
		&pr.Merged, &ticketRef, &ticketURL, &confirmed)
	if err != nil {
		return RemediationPR{}, err
	}
	pr.Number, pr.URL = int(number.Int64), url.String
	pr.TicketRef, pr.TicketURL = ticketRef.String, ticketURL.String
	pr.OpenedAt = pr.OpenedAt.UTC()
	if closed.Valid {
		at := closed.Time.UTC()
		pr.ClosedAt = &at
	}
	if confirmed.Valid {
		at := confirmed.Time.UTC()
		pr.ConfirmedAt = &at
	}

	rows, err := p.db.QueryContext(ctx, qPRFindings, pr.Branch)
	if err != nil {
		return RemediationPR{}, fmt.Errorf("store: reading pull request membership: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return RemediationPR{}, err
		}
		pr.Findings = append(pr.Findings, fp)
	}
	return pr, rows.Err()
}

func (p *Postgres) CloseRemediationPR(ctx context.Context, branch string, at time.Time, merged bool) error {
	res, err := p.db.ExecContext(ctx, qCloseRemediationPR, branch, at.UTC(), merged)
	if err != nil {
		return fmt.Errorf("store: closing remediation pull request %s: %w", branch, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: remediation pull request for branch %q", ErrNotFound, branch)
	}
	return nil
}

func (p *Postgres) ConfirmRemediationPR(ctx context.Context, branch string, at time.Time) error {
	res, err := p.db.ExecContext(ctx, qConfirmRemediationPR, branch, at.UTC())
	if err != nil {
		return fmt.Errorf("store: confirming remediation pull request %s: %w", branch, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: remediation pull request for branch %q", ErrNotFound, branch)
	}
	return nil
}

func (p *Postgres) UnconfirmedRemediationPRs(ctx context.Context, repo string, since time.Time, limit int) ([]RemediationPR, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := p.db.QueryContext(ctx, qUnconfirmedRemediationPRs, repo, since.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("store: reading unconfirmed pull requests for %s: %w", repo, err)
	}
	var branches []string
	for rows.Next() {
		var branch string
		if err := rows.Scan(&branch); err != nil {
			rows.Close()
			return nil, err
		}
		branches = append(branches, branch)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	// Through the single-row path, so membership is loaded the one way.
	out := make([]RemediationPR, 0, len(branches))
	for _, branch := range branches {
		pr, ok, err := p.GetRemediationPR(ctx, branch)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, pr)
		}
	}
	return out, nil
}

// --- Webhook health (OQ-P12-01) ---------------------------------------------

func (p *Postgres) RecordWebhookDelivery(ctx context.Context, at time.Time) error {
	if _, err := p.db.ExecContext(ctx, qRecordWebhookDelivery, at.UTC()); err != nil {
		return fmt.Errorf("store: recording a webhook delivery: %w", err)
	}
	return nil
}

func (p *Postgres) WebhookHealth(ctx context.Context) (WebhookHealth, error) {
	var h WebhookHealth
	err := p.db.QueryRowContext(ctx, qWebhookHealth).Scan(&h.LastDeliveryAt, &h.Deliveries)
	if errors.Is(err, sql.ErrNoRows) {
		// No delivery has ever arrived. The zero value says exactly that, and
		// WebhookHealth.Live reads it as "not live" rather than as "live since
		// the epoch".
		return WebhookHealth{}, nil
	}
	if err != nil {
		return WebhookHealth{}, err
	}
	h.LastDeliveryAt = h.LastDeliveryAt.UTC()
	return h, nil
}

// --- Exploitation intelligence (OQ-AUDIT-01(b)) -----------------------------

func (p *Postgres) SaveIntel(ctx context.Context, rows []Intel) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, row := range rows {
		if row.ID == "" {
			return fmt.Errorf("store: intelligence row with no identifier")
		}
		var epss any
		if row.EPSSAvailable {
			epss = row.EPSS
		}
		if _, err := tx.ExecContext(ctx, qUpsertIntel,
			row.ID, epss, row.EPSSAvailable, nullTime(row.EPSSAsOf),
			row.KEV, row.KEVAvailable, nullTime(row.KEVAsOf),
			row.FetchedAt.UTC(), pgTextArray(row.Sources)); err != nil {
			return fmt.Errorf("store: saving intelligence for %s: %w", row.ID, err)
		}
	}
	return tx.Commit()
}

func (p *Postgres) IntelFreshness(ctx context.Context) (IntelFreshness, error) {
	var kev, epss sql.NullTime
	if err := p.db.QueryRowContext(ctx, qIntelFreshness).Scan(&kev, &epss); err != nil {
		return IntelFreshness{}, fmt.Errorf("store: reading feed freshness: %w", err)
	}
	return IntelFreshness{KEV: kev.Time.UTC(), EPSS: epss.Time.UTC()}, nil
}

func (p *Postgres) IntelFor(ctx context.Context, ids []string) (map[string]Intel, error) {
	out := map[string]Intel{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := p.db.QueryContext(ctx, qIntelFor, pgTextArray(ids))
	if err != nil {
		return nil, fmt.Errorf("store: reading exploitation intelligence: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			row     Intel
			epss    sql.NullFloat64
			epssAt  sql.NullTime
			kevAt   sql.NullTime
			sources sql.NullString
		)
		if err := rows.Scan(&row.ID, &epss, &row.EPSSAvailable, &epssAt,
			&row.KEV, &row.KEVAvailable, &kevAt, &row.FetchedAt, &sources); err != nil {
			return nil, err
		}
		// A NULL epss stays zero with EPSSAvailable false: the column and the
		// flag express different facts and neither substitutes for the other.
		if epss.Valid {
			row.EPSS = epss.Float64
		}
		if epssAt.Valid {
			at := epssAt.Time.UTC()
			row.EPSSAsOf = &at
		}
		if kevAt.Valid {
			at := kevAt.Time.UTC()
			row.KEVAsOf = &at
		}
		row.FetchedAt = row.FetchedAt.UTC()
		row.Sources = parseTextArray(sources.String)
		out[row.ID] = row
	}
	return out, rows.Err()
}

// openPRURLs returns the open pull request URL per finding, for the projection.
func (p *Postgres) openPRURLs(ctx context.Context) (map[string]string, error) {
	rows, err := p.db.QueryContext(ctx, qOpenPRURLs)
	if err != nil {
		return nil, fmt.Errorf("store: reading remediation pull request references: %w", err)
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var fp, url string
		if err := rows.Scan(&fp, &url); err != nil {
			return nil, err
		}
		out[fp] = url
	}
	return out, rows.Err()
}

// OpenRemediationPRs returns a repository's open pull request records.
func (p *Postgres) OpenRemediationPRs(ctx context.Context, repo string) ([]RemediationPR, error) {
	rows, err := p.db.QueryContext(ctx, qOpenRemediationPRs, repo)
	if err != nil {
		return nil, fmt.Errorf("store: reading open remediation pull requests for %s: %w", repo, err)
	}
	var branches []string
	for rows.Next() {
		var (
			pr              RemediationPR
			number          sql.NullInt64
			url, tRef, tURL sql.NullString
			closed          sql.NullTime
			confirmed       sql.NullTime
		)
		if err := rows.Scan(&pr.Branch, &pr.Repo, &pr.FixGroupID, &number, &url, &pr.State,
			&pr.OpenedAt, &closed, &pr.Merged, &tRef, &tURL, &confirmed); err != nil {
			rows.Close()
			return nil, err
		}
		branches = append(branches, pr.Branch)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	// Re-read each through the single-row path so membership is loaded the one
	// way, rather than by a second query that could drift from it.
	out := make([]RemediationPR, 0, len(branches))
	for _, branch := range branches {
		pr, ok, err := p.GetRemediationPR(ctx, branch)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, pr)
		}
	}
	return out, nil
}

// --- Run parent tickets (VM-AD §13.3 row 1) ---------------------------------

func (p *Postgres) SaveRunTicket(ctx context.Context, t RunTicket) error {
	if t.RunID == "" {
		return fmt.Errorf("store: a run parent ticket needs a run identifier")
	}
	created := t.CreatedAt
	if created.IsZero() {
		created = p.clock()
	}
	if _, err := p.db.ExecContext(ctx, qUpsertRunTicket, t.RunID, t.Backend, t.Ref, t.URL, created.UTC()); err != nil {
		return fmt.Errorf("store: saving the run parent ticket for %s: %w", t.RunID, err)
	}
	return nil
}

func (p *Postgres) GetRunTicket(ctx context.Context, runID string) (RunTicket, bool, error) {
	var t RunTicket
	err := p.db.QueryRowContext(ctx, qGetRunTicket, runID).Scan(&t.RunID, &t.Backend, &t.Ref, &t.URL, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RunTicket{}, false, nil
	}
	if err != nil {
		return RunTicket{}, false, fmt.Errorf("store: reading the run parent ticket for %s: %w", runID, err)
	}
	t.CreatedAt = t.CreatedAt.UTC()
	return t, true, nil
}

// TicketByRef reverse-resolves a backend reference (OQ-P8-01).
func (p *Postgres) TicketByRef(ctx context.Context, backend, ref string) (Ticket, bool, error) {
	var (
		t                   Ticket
		mirrorBackend, mRef sql.NullString
		closed              sql.NullTime
	)
	err := p.db.QueryRowContext(ctx, qTicketByRef, backend, ref).Scan(
		&t.Fingerprint, &t.Backend, &t.Ref, &t.URL, &mirrorBackend, &mRef, &t.CreatedAt, &closed)
	if errors.Is(err, sql.ErrNoRows) {
		return Ticket{}, false, nil
	}
	if err != nil {
		return Ticket{}, false, fmt.Errorf("store: reverse-resolving ticket %s:%s: %w", backend, ref, err)
	}
	t.MirrorBackend, t.MirrorRef = mirrorBackend.String, mRef.String
	t.CreatedAt = t.CreatedAt.UTC()
	if closed.Valid {
		at := closed.Time.UTC()
		t.ClosedAt = &at
	}
	return t, true, nil
}

// SecretPaths returns files holding an unresolved secret finding (VM-F-854).
func (p *Postgres) SecretPaths(ctx context.Context, repo string) ([]string, error) {
	findings, err := p.ListFindings(ctx, Query{
		Scope: ScopeOpen, Repo: repo, Categories: []model.Category{model.CategorySecret},
	})
	if err != nil {
		return nil, err
	}
	return secretPathsOf(findings), nil
}

// SetUpstreamFinding records the upstream finding a consumer is blocked on.
func (p *Postgres) SetUpstreamFinding(ctx context.Context, fingerprint, upstream string) error {
	res, err := p.db.ExecContext(ctx, qSetUpstreamFinding, fingerprint, nullString(upstream))
	if err != nil {
		return fmt.Errorf("store: recording the upstream finding for %s: %w", fingerprint, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: finding %q", ErrNotFound, fingerprint)
	}
	return nil
}

// --- Dependency manifests (VM-F-602) ----------------------------------------

func (p *Postgres) RecordDeps(ctx context.Context, runID, repo string, deps []ModuleDep) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Replaced wholesale for the repository: a dependency that was dropped
	// must stop appearing, and merging would leave the repository listed as a
	// consumer of something it no longer uses — which a wave would then try to
	// advance.
	if _, err := tx.ExecContext(ctx, qDeleteRepoDeps, repo); err != nil {
		return fmt.Errorf("store: clearing dependencies for %s: %w", repo, err)
	}
	for _, d := range deps {
		if _, err := tx.ExecContext(ctx, qInsertDep, runID, repo, d.Module, d.Version, d.Direct, d.Replaced); err != nil {
			return fmt.Errorf("store: recording dependency %s for %s: %w", d.Module, repo, err)
		}
	}
	return tx.Commit()
}

func (p *Postgres) Dependents(ctx context.Context, module string) ([]ModuleDep, error) {
	return p.scanDeps(ctx, qDependents, module)
}

func (p *Postgres) AllDeps(ctx context.Context) ([]ModuleDep, error) {
	return p.scanDeps(ctx, qAllDeps)
}

func (p *Postgres) scanDeps(ctx context.Context, query string, args ...any) ([]ModuleDep, error) {
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: reading dependencies: %w", err)
	}
	defer rows.Close()

	var out []ModuleDep
	for rows.Next() {
		var d ModuleDep
		if err := rows.Scan(&d.RunID, &d.Repo, &d.Module, &d.Version, &d.Direct, &d.Replaced); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// applySecretReviews joins suppression proposals and secret removals onto a
// page of findings.
func (p *Postgres) applySecretReviews(ctx context.Context, out []model.Finding) error {
	fps := make([]string, 0, len(out))
	index := map[string]int{}
	for i := range out {
		if out[i].Category == model.CategorySecret {
			fps = append(fps, out[i].Fingerprint)
			index[out[i].Fingerprint] = i
		}
	}
	if len(fps) == 0 {
		return nil
	}
	proposals, err := proposalsFor(ctx, p.db, fps)
	if err != nil {
		return err
	}
	for fp, prop := range proposals {
		prop := prop
		out[index[fp]].SuppressionProposal = &prop
	}
	rows, err := p.db.QueryContext(ctx, qRemovalsFor, pgTextArray(fps))
	if err != nil {
		return fmt.Errorf("store: reading secret removals: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var fp string
		var r model.SecretRemoval
		if err := rows.Scan(&fp, &r.Run, &r.At); err != nil {
			return err
		}
		r.At = r.At.UTC()
		out[index[fp]].RemovedUnrotated = &r
	}
	return rows.Err()
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func proposalsFor(ctx context.Context, q querier, fps []string) (map[string]model.SuppressionProposal, error) {
	rows, err := q.QueryContext(ctx, qProposalsFor, pgTextArray(fps))
	if err != nil {
		return nil, fmt.Errorf("store: reading suppression proposals: %w", err)
	}
	defer rows.Close()
	out := map[string]model.SuppressionProposal{}
	for rows.Next() {
		var (
			fp                                string
			pr                                model.SuppressionProposal
			mech, status                      string
			sha, desc, decidedBy, withdrawnRn sql.NullString
			escalated, decided, withdrawn     sql.NullTime
		)
		if err := rows.Scan(&fp, &mech, &pr.Path, &sha, &desc, &status, &pr.ProposedRun, &pr.ProposedAt,
			&escalated, &decidedBy, &decided, &withdrawnRn, &withdrawn); err != nil {
			return nil, err
		}
		pr.Mechanism, pr.Status = model.AllowlistMechanism(mech), model.ProposalStatus(status)
		pr.ConfigSHA256, pr.Description = sha.String, desc.String
		pr.ProposedAt = pr.ProposedAt.UTC()
		pr.EscalatedAt = utcPtr(escalated)
		pr.DecidedBy, pr.DecidedAt = decidedBy.String, utcPtr(decided)
		pr.WithdrawnRun, pr.WithdrawnAt = withdrawnRn.String, utcPtr(withdrawn)
		out[fp] = pr
	}
	return out, rows.Err()
}

func utcPtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	u := t.Time.UTC()
	return &u
}

// ApplyAllowlist records one run's allowlist evidence (see Store).
func (p *Postgres) ApplyAllowlist(ctx context.Context, runID, repo string, allowlisted map[string]model.Allowlist, observed []string) (AllowlistStats, error) {
	var stats AllowlistStats
	seen := map[string]bool{}
	fps := make([]string, 0, len(allowlisted)+len(observed))
	for _, fp := range observed {
		seen[fp] = true
		fps = append(fps, fp)
	}
	for fp := range allowlisted {
		fps = append(fps, fp)
	}
	if len(fps) == 0 {
		return stats, nil
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return stats, fmt.Errorf("store: begin allowlist: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, qSecretStates, repo, pgTextArray(fps))
	if err != nil {
		return stats, fmt.Errorf("store: reading secret states: %w", err)
	}
	states := map[string]model.State{}
	for rows.Next() {
		var fp, state string
		if err := rows.Scan(&fp, &state); err != nil {
			rows.Close()
			return stats, err
		}
		states[fp] = model.State(state)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return stats, err
	}
	proposals, err := proposalsFor(ctx, tx, fps)
	if err != nil {
		return stats, err
	}

	var in []AllowlistInput
	for fp, state := range states {
		i := AllowlistInput{Fingerprint: fp, State: state, Observed: seen[fp]}
		if a, ok := allowlisted[fp]; ok {
			i.Allowlisted = &a
		}
		if pr, ok := proposals[fp]; ok {
			i.Proposal = &pr
		}
		in = append(in, i)
	}
	sort.Slice(in, func(i, j int) bool { return in[i].Fingerprint < in[j].Fingerprint })

	now := p.clock()
	for _, a := range PlanAllowlist(in) {
		switch {
		case a.Propose != nil:
			if a.To != "" {
				if err := transitionTx(ctx, tx, a.Fingerprint, states[a.Fingerprint], a.To, model.TransitionContext{
					Actor: model.ActorScanWorker, Cause: ProposalCause(*a.Propose, runID), At: now,
				}); err != nil {
					return stats, err
				}
			}
			if _, err := tx.ExecContext(ctx, qUpsertProposal, a.Fingerprint, string(a.Propose.Mechanism),
				a.Propose.Path, nullString(a.Propose.ConfigSHA256), nullString(a.Propose.Description),
				runID, now); err != nil {
				return stats, fmt.Errorf("store: recording proposal for %s: %w", a.Fingerprint, err)
			}
			stats.Proposed++
		case a.Withdraw:
			if a.To != "" {
				if err := transitionTx(ctx, tx, a.Fingerprint, states[a.Fingerprint], a.To, model.TransitionContext{
					Actor: model.ActorScanWorker, Cause: WithdrawalCause(proposals[a.Fingerprint], runID), At: now,
				}); err != nil {
					return stats, err
				}
				if _, err := tx.ExecContext(ctx, qClearResolved, a.Fingerprint); err != nil {
					return stats, err
				}
			}
			if _, err := tx.ExecContext(ctx, qWithdrawProposal, a.Fingerprint, runID, now); err != nil {
				return stats, err
			}
			stats.Withdrawn++
		}
	}
	return stats, tx.Commit()
}

// lockedProposal reads a finding's state and proposal inside a transaction.
func lockedProposal(ctx context.Context, tx *sql.Tx, fp string) (model.State, model.Category, *model.SuppressionProposal, error) {
	var state, category string
	err := tx.QueryRowContext(ctx, `SELECT state, category FROM findings WHERE fingerprint = $1 FOR UPDATE`, fp).Scan(&state, &category)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil, fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	if err != nil {
		return "", "", nil, err
	}
	proposals, err := proposalsFor(ctx, tx, []string{fp})
	if err != nil {
		return "", "", nil, err
	}
	if pr, ok := proposals[fp]; ok {
		return model.State(state), model.Category(category), &pr, nil
	}
	return model.State(state), model.Category(category), nil, nil
}

// EscalateProposal marks an unreviewed proposal overdue (see Store).
func (p *Postgres) EscalateProposal(ctx context.Context, fp string, at time.Time, cause string) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state, _, pr, err := lockedProposal(ctx, tx, fp)
	if err != nil {
		return err
	}
	if pr == nil || pr.Status != model.ProposalPending {
		return fmt.Errorf("%w: no pending suppression proposal for %q", ErrNotFound, fp)
	}
	if err := transitionTx(ctx, tx, fp, state, model.NeedsHuman, model.TransitionContext{
		Actor: model.ActorOrchestrator, Cause: cause, At: at,
	}); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, qEscalateProposal, fp, at); err != nil {
		return err
	}
	return tx.Commit()
}

// DecideSuppression records a human's decision on an open proposal (see Store).
func (p *Postgres) DecideSuppression(ctx context.Context, fp string, confirm bool, by string, at time.Time) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state, _, pr, err := lockedProposal(ctx, tx, fp)
	if err != nil {
		return err
	}
	var current model.SuppressionProposal
	if pr != nil {
		current = *pr
	}
	if err := decidable(fp, current, pr != nil, by); err != nil {
		return err
	}
	to, cause := decisionTransition(state, current, confirm, by)
	if to != "" {
		if err := transitionTx(ctx, tx, fp, state, to, model.TransitionContext{Actor: model.ActorHuman, Cause: cause, At: at}); err != nil {
			return err
		}
		if to == model.Suppressed {
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET resolved_at = $1 WHERE fingerprint = $2`, at, fp); err != nil {
				return err
			}
		}
	}
	status := model.ProposalRejected
	if confirm {
		status = model.ProposalConfirmed
	}
	if _, err := tx.ExecContext(ctx, qDecideProposal, fp, string(status), by, at); err != nil {
		return err
	}
	return tx.Commit()
}

// ConfirmRotation verifies a removed secret on a human's attestation (see Store).
func (p *Postgres) ConfirmRotation(ctx context.Context, fp, by string, at time.Time) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state, category, _, err := lockedProposal(ctx, tx, fp)
	if err != nil {
		return err
	}
	var r model.SecretRemoval
	err = tx.QueryRowContext(ctx, `SELECT run_id, removed_at FROM secret_removals WHERE fingerprint = $1`, fp).Scan(&r.Run, &r.At)
	removed := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := rotatable(fp, category, state, removed, by); err != nil {
		return err
	}
	if err := transitionTx(ctx, tx, fp, state, model.Verified, model.TransitionContext{
		Actor: model.ActorHuman, Cause: RotationCause(by, r), At: at, RotationConfirmedBy: by,
	}); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, qMarkVerified, at, string(model.VerifiedRotationConfirmed), fp, false, ""); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, qClearRemoval, fp); err != nil {
		return err
	}
	return tx.Commit()
}
