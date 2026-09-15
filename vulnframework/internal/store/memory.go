package store

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
)

// Memory is an in-memory Store for offline testing (VM-AD §17: phases 0–2
// require no external infrastructure).
//
// It shares every invariant decision with the Postgres implementation through
// PlanUpsert, PlanReconcile and Project, and both are held to the same
// conformance suite.
type Memory struct {
	mu sync.Mutex

	schemaVersion int
	clock         func() time.Time

	repos       map[string]Repo
	runs        map[string]Run
	seq         map[RunKind]int64
	scanResults map[string][]RepoScanResult // keyed by repo, newest last

	findings     map[string]*memFinding
	observations map[string][]SourceObservation // keyed by fingerprint
	transitions  map[string][]model.StateTransition
}

type memFinding struct {
	Fingerprint    string
	Repo           string
	Category       model.Category
	State          model.State
	ReasonCode     *model.ReasonCode
	Priority       model.Priority
	FirstSeenAt    time.Time
	LastSeenAt     time.Time
	ResolvedAt     *time.Time
	NotReobserved  bool
	GapRunID       string
	VerifiedReason model.VerificationReason
	FirstSeenRun   string
	LastSeenRun    string
	Location       model.Location
	Module         string
	ModuleMajor    string
}

// NewMemory builds an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		clock:        func() time.Time { return time.Now().UTC() },
		repos:        map[string]Repo{},
		runs:         map[string]Run{},
		seq:          map[RunKind]int64{},
		scanResults:  map[string][]RepoScanResult{},
		findings:     map[string]*memFinding{},
		observations: map[string][]SourceObservation{},
		transitions:  map[string][]model.StateTransition{},
	}
}

// SetClock overrides the clock, for deterministic tests.
func (m *Memory) SetClock(f func() time.Time) { m.clock = f }

func (m *Memory) Migrate(ctx context.Context) error {
	migrations, err := LoadMigrations()
	if err != nil {
		return err
	}
	return m.MigrateTo(ctx, len(migrations))
}

func (m *Memory) MigrateTo(_ context.Context, version int) error {
	migrations, err := LoadMigrations()
	if err != nil {
		return err
	}
	if version < 0 || version > len(migrations) {
		return fmt.Errorf("store: target version %d is outside the available range 0..%d", version, len(migrations))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if version == 0 {
		m.repos = map[string]Repo{}
		m.runs = map[string]Run{}
		m.seq = map[RunKind]int64{}
		m.scanResults = map[string][]RepoScanResult{}
		m.findings = map[string]*memFinding{}
		m.observations = map[string][]SourceObservation{}
		m.transitions = map[string][]model.StateTransition{}
	}
	m.schemaVersion = version
	return nil
}

func (m *Memory) SchemaVersion(context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.schemaVersion, nil
}

func (m *Memory) UpsertRepo(_ context.Context, r Repo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.repos[r.Name] = r
	return nil
}

func (m *Memory) GetRepo(_ context.Context, name string) (Repo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.repos[name]
	if !ok {
		return Repo{}, fmt.Errorf("%w: repo %q", ErrNotFound, name)
	}
	return r, nil
}

func (m *Memory) CreateRun(_ context.Context, kind RunKind, trigger, image string, toolVersions map[string]string) (Run, error) {
	if !kind.Valid() {
		return Run{}, fmt.Errorf("store: invalid run kind %q", kind)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.seq[kind]++
	run := Run{
		ID:            FormatRunID(kind, m.seq[kind]),
		Kind:          kind,
		Seq:           m.seq[kind],
		TriggerDetail: trigger,
		StartedAt:     m.clock(),
		ScannerImage:  image,
		ToolVersions:  toolVersions,
	}
	m.runs[run.ID] = run
	return run, nil
}

func (m *Memory) FinishRun(_ context.Context, runID string, planned, scanned, failed int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[runID]
	if !ok {
		return fmt.Errorf("%w: run %q", ErrNotFound, runID)
	}
	at := m.clock()
	run.FinishedAt = &at
	run.ReposPlanned, run.ReposScanned, run.ReposFailed = planned, scanned, failed
	m.runs[runID] = run
	return nil
}

func (m *Memory) GetRun(_ context.Context, id string) (Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[id]
	if !ok {
		return Run{}, fmt.Errorf("%w: run %q", ErrNotFound, id)
	}
	return run, nil
}

func (m *Memory) RecordScanResult(_ context.Context, res RepoScanResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.runs[res.RunID]; !ok {
		return fmt.Errorf("%w: run %q", ErrNotFound, res.RunID)
	}
	// Replace any prior result for this (run, repo) so replay is idempotent.
	existing := m.scanResults[res.Repo]
	for i, r := range existing {
		if r.RunID == res.RunID {
			existing[i] = res
			return nil
		}
	}
	m.scanResults[res.Repo] = append(existing, res)
	return nil
}

func (m *Memory) ScanResults(_ context.Context, repo string, limit int) ([]RepoScanResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := m.scanResults[repo]
	out := make([]RepoScanResult, len(all))
	copy(out, all)
	sort.Slice(out, func(i, j int) bool { return out[i].RunID > out[j].RunID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) UpsertObservations(_ context.Context, runID, repo string, raws []model.RawFinding) (UpsertStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.runs[runID]; !ok {
		return UpsertStats{}, fmt.Errorf("%w: run %q", ErrNotFound, runID)
	}
	now := m.clock()

	var stats UpsertStats
	for _, raw := range raws {
		if err := fingerprint.Validate(raw); err != nil {
			return stats, err
		}
		fp := fingerprint.Compute(raw)

		existing, exists := m.findings[fp]
		var current model.State
		if exists {
			current = existing.State
		}
		decision := PlanUpsert(current, exists)

		switch {
		case decision.Create:
			f := &memFinding{
				Fingerprint:  fp,
				Repo:         repo,
				Category:     raw.Category,
				State:        model.Detected,
				FirstSeenAt:  now,
				LastSeenAt:   now,
				FirstSeenRun: runID,
				LastSeenRun:  runID,
				Module:       raw.Module,
				ModuleMajor:  raw.ModuleMajor,
				Location:     locationOf(raw),
			}
			m.findings[fp] = f
			m.recordTransition(fp, "", model.Detected, model.TransitionContext{
				Actor: model.ActorScanWorker, Cause: "first observation in " + runID, At: now,
			})
			stats.Created++

		case decision.Regress:
			if err := m.transition(fp, model.Regressed, model.TransitionContext{
				Actor: model.ActorScanWorker, Cause: "observed again in " + runID, At: now,
			}); err != nil {
				return stats, err
			}
			stats.Regressed++
			stats.Observed++

		default:
			stats.Observed++
		}

		f := m.findings[fp]
		f.LastSeenAt = now
		f.LastSeenRun = runID
		// Observation clears the derived absence flag: the finding is present.
		f.NotReobserved = false
		f.GapRunID = ""

		m.putObservation(SourceOf(fp, runID, now, raw))
		stats.Observations++
	}
	return stats, nil
}

// putObservation records one source's observation, replacing any prior
// observation from the same tool in the same run so replay is idempotent.
func (m *Memory) putObservation(o SourceObservation) {
	list := m.observations[o.Fingerprint]
	for i, prev := range list {
		if prev.RunID == o.RunID && prev.Tool == o.Tool {
			list[i] = o
			m.observations[o.Fingerprint] = list
			return
		}
	}
	m.observations[o.Fingerprint] = append(list, o)
}

func (m *Memory) Reconcile(_ context.Context, runID, repo string) (ReconcileStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	outcome, err := m.outcomeFor(runID, repo)
	if err != nil {
		return ReconcileStats{}, err
	}

	observed := map[string]bool{}
	for fp, obs := range m.observations {
		for _, o := range obs {
			if o.RunID == runID {
				observed[fp] = true
				break
			}
		}
	}

	var absent []FindingState
	for fp, f := range m.findings {
		if f.Repo != repo || observed[fp] {
			continue
		}
		absent = append(absent, FindingState{Fingerprint: fp, State: f.State})
	}
	sort.Slice(absent, func(i, j int) bool { return absent[i].Fingerprint < absent[j].Fingerprint })

	actions := resolveGapLinks(PlanReconcile(outcome, absent), runID)

	now := m.clock()
	var stats ReconcileStats
	for _, a := range actions {
		f := m.findings[a.Fingerprint]
		if a.Verify {
			if err := m.transitionLocked(a.Fingerprint, model.Verified, model.TransitionContext{
				Actor:       model.ActorScanWorker,
				Cause:       "not observed by successful scan in " + runID + " (" + string(a.VerificationReason) + ")",
				At:          now,
				ScanOutcome: outcome,
			}); err != nil {
				return stats, err
			}
			resolved := now
			f.ResolvedAt = &resolved
			f.VerifiedReason = a.VerificationReason
			f.NotReobserved = false
			f.GapRunID = ""
			stats.Verified++
			continue
		}
		f.NotReobserved = a.NotReobserved
		f.GapRunID = a.GapRunID
		if a.NotReobserved {
			stats.NotReobserved++
		}
		if a.RetainedUnverified {
			stats.RetainedUnverified++
		}
	}
	return stats, nil
}

func (m *Memory) outcomeFor(runID, repo string) (ScanOutcome, error) {
	for _, r := range m.scanResults[repo] {
		if r.RunID == runID {
			return r.Outcome, nil
		}
	}
	return "", fmt.Errorf("%w: no scan result for repo %q in run %q; reconciliation requires one (VM-ADR-12)",
		ErrNotFound, repo, runID)
}

func (m *Memory) GetFinding(_ context.Context, fp string) (model.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.findings[fp]
	if !ok {
		return model.Finding{}, fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	return m.materialise(f), nil
}

func (m *Memory) ListFindings(_ context.Context, q Query) ([]model.Finding, error) {
	if !q.Scope.Valid() {
		return nil, ErrScopeRequired
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []model.Finding
	for fp, f := range m.findings {
		if q.Repo != "" && f.Repo != q.Repo {
			continue
		}
		if q.Fingerprint != "" && fp != q.Fingerprint {
			continue
		}
		if len(q.States) > 0 && !containsState(q.States, f.State) {
			continue
		}
		if len(q.Categories) > 0 && !containsCategory(q.Categories, f.Category) {
			continue
		}
		switch q.Scope {
		case ScopeOpen:
			if model.PartitionOf(f.State) == model.PartitionResolved {
				continue
			}
		case ScopeRun:
			if q.RunID == "" {
				return nil, fmt.Errorf("store: scope %q requires a run identifier", ScopeRun)
			}
			if !m.observedIn(fp, q.RunID) {
				continue
			}
		}
		out = append(out, m.materialise(f))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func (m *Memory) observedIn(fp, runID string) bool {
	for _, o := range m.observations[fp] {
		if o.RunID == runID {
			return true
		}
	}
	return false
}

func (m *Memory) Observations(_ context.Context, fp string) ([]SourceObservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	obs := m.observations[fp]
	out := make([]SourceObservation, len(obs))
	copy(out, obs)
	sort.Slice(out, func(i, j int) bool {
		if out[i].RunID != out[j].RunID {
			return out[i].RunID < out[j].RunID
		}
		return out[i].Tool < out[j].Tool
	})
	return out, nil
}

func (m *Memory) Transitions(_ context.Context, fp string) ([]model.StateTransition, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.transitions[fp]
	out := make([]model.StateTransition, len(t))
	copy(out, t)
	// Ordered as Postgres orders them (ORDER BY at, id): by timestamp, with
	// insertion order breaking ties. The two backends must agree on history
	// order or the audit trail reads differently depending on where it is read.
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

func (m *Memory) ApplyTransition(_ context.Context, fp string, to model.State, tc model.TransitionContext) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.transitionLocked(fp, to, tc)
}

func (m *Memory) transition(fp string, to model.State, tc model.TransitionContext) error {
	return m.transitionLocked(fp, to, tc)
}

func (m *Memory) transitionLocked(fp string, to model.State, tc model.TransitionContext) error {
	f, ok := m.findings[fp]
	if !ok {
		return fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	// The store stamps the time, not the caller. The store is the authority on
	// when a change was recorded, and letting a caller's zero value fall through
	// to wall-clock now would make a controlled-clock store non-deterministic.
	if tc.At.IsZero() {
		tc.At = m.clock()
	}
	rec, err := model.ApplyTransition(fp, f.State, to, tc)
	if err != nil {
		return err
	}
	f.State = to
	m.transitions[fp] = append(m.transitions[fp], rec)
	return nil
}

func (m *Memory) recordTransition(fp string, from, to model.State, tc model.TransitionContext) {
	rec, err := model.ApplyTransition(fp, from, to, tc)
	if err != nil {
		return
	}
	m.transitions[fp] = append(m.transitions[fp], rec)
}

// materialise builds the merged finding view from the retained observations.
//
// The projection is recomputed here rather than stored incrementally, which is
// what makes it order-independent (VM-AD §8.6).
func (m *Memory) materialise(f *memFinding) model.Finding {
	obs := LatestPerSource(m.observations[f.Fingerprint])
	p := Project(obs)

	return model.Finding{
		SchemaVersion: model.SchemaVersion,
		Fingerprint:   f.Fingerprint,
		Repo:          f.Repo,
		Category:      f.Category,
		Identity: model.Identity{
			PrimaryID: p.PrimaryID,
			Aliases:   p.Aliases,
		},
		Location: f.Location,
		Versions: model.Versions{
			Current: p.CurrentVersion,
			Fixed:   p.FixedVersion,
		},
		Classification: p.Classification,
		Provenance: model.Provenance{
			Tools:        p.Tools,
			FirstSeenRun: f.FirstSeenRun,
			LastSeenRun:  f.LastSeenRun,
		},
		State:          f.State,
		ReasonCode:     f.ReasonCode,
		Priority:       f.Priority,
		VerifiedReason: optionalReason(f.VerifiedReason),
		Derived: model.Derived{
			NotReobserved: f.NotReobserved,
			GapRepoScan:   optionalString(f.GapRunID),
		},
		CredentialType: p.CredentialType,
	}
}

func (m *Memory) Close() error { return nil }

func locationOf(raw model.RawFinding) model.Location {
	loc := model.Location{
		Module:      raw.Module,
		ModuleMajor: raw.ModuleMajor,
	}
	if raw.Package != "" {
		p := raw.Package
		loc.Package = &p
	}
	if raw.Function != "" {
		fn := raw.Function
		loc.Function = &fn
	}
	if raw.File != "" {
		file := raw.File
		loc.File = &file
	}
	if raw.Line != 0 {
		line := raw.Line
		loc.Line = &line
	}
	return loc
}

func optionalReason(r model.VerificationReason) *model.VerificationReason {
	if r == "" {
		return nil
	}
	return &r
}

func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func containsState(list []model.State, s model.State) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func containsCategory(list []model.Category, c model.Category) bool {
	for _, v := range list {
		if v == c {
			return true
		}
	}
	return false
}
