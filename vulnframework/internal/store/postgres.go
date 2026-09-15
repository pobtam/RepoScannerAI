package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
		nullString(r.ModuleTopology), pgTextArray(r.Codeowners))
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
		Scan(&r.Name, &r.Tier, &langs, &r.Archived, &testSuite, &topology, &owners)
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
		nullString(res.FailureOwner), res.DurationSec)
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
		)
		if err := rows.Scan(&r.RunID, &r.Repo, &outcome, &ok, &failed, &cause, &detail, &owner, &duration); err != nil {
			return nil, err
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
		var state string
		if err := rows.Scan(&f.Fingerprint, &state); err != nil {
			rows.Close()
			return stats, err
		}
		f.State = model.State(state)
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
			if _, err := tx.ExecContext(ctx, qMarkVerified, now, string(a.VerificationReason), a.Fingerprint); err != nil {
				return stats, err
			}
			stats.Verified++
			continue
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
		)
		if err := rows.Scan(&f.Fingerprint, &f.Repo, &category, &data, &state,
			&reason, &priority, &firstRun, &lastRun, &notReobserved, &gapRun, &verifiedBy); err != nil {
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
		out = append(out, projected)
	}
	return out, rows.Err()
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
	p := Project(LatestPerSource(obs))

	view := model.Finding{
		Identity:       model.Identity{PrimaryID: p.PrimaryID, Aliases: p.Aliases},
		Versions:       model.Versions{Current: p.CurrentVersion, Fixed: p.FixedVersion},
		Classification: p.Classification,
		Provenance:     model.Provenance{Tools: p.Tools},
		Refs:           model.Refs{AdvisoryURL: optionalString(p.AdvisoryURL)},
		CredentialType: p.CredentialType,
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

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
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
