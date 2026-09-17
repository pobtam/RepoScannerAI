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
	plan         map[string]map[string]PlanEntry // run id -> repo -> entry
	reports      map[string]Report

	tickets        map[string]Ticket // keyed by fingerprint
	repoLocks      map[string]RepoLock
	remediationPRs map[string]RemediationPR
	runTickets     map[string]RunTicket
	deps           map[string]map[string]ModuleDep
	ticketOps      []TicketOp
	nextOpID       int64
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
	// UpstreamFinding is the owner's fingerprint a blocked consumer waits on.
	// Held on the record rather than in the projected document, for the same
	// reason the ticket and pull request references are: the document is
	// rebuilt from observations on every scan.
	UpstreamFinding string
	Triage          *model.Triage
	SLAStatus       model.SLAStatus
	SLAWindowDays   int
	SLABreachDays   int
	AgeDays         int
	LeaseOwner      string
	LeaseExpiresAt  *time.Time
	FirstSeenRun    string
	LastSeenRun     string
	Location        model.Location
	Module          string
	ModuleMajor     string
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
		plan:         map[string]map[string]PlanEntry{},
		reports:      map[string]Report{},
	}
}

// SetClock overrides the clock, for deterministic tests.
//
// The clock may be called concurrently: a sweep records results from many
// dispatch goroutines at once. Any replacement must be safe for concurrent use.
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
		m.plan = map[string]map[string]PlanEntry{}
		m.reports = map[string]Report{}
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
			// A finding that verified while remediation was in flight must not
			// leave its lease behind: the lease sweeper would otherwise keep
			// finding it, and the worker's slot would never be returned
			// (VM-AD §6.1.1).
			f.LeaseOwner, f.LeaseExpiresAt = "", nil
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
			RuleID:    optionalString(p.RuleID),
		},
		Location: p.LocationOf(),
		Versions: model.Versions{
			Current:    p.CurrentVersion,
			Fixed:      p.FixedVersion,
			Introduced: p.IntroducedIn,
		},
		Classification: withFirstParty(p.Classification, p.FirstPartyPath),
		Provenance: model.Provenance{
			Tools:        p.Tools,
			FirstSeenRun: f.FirstSeenRun,
			LastSeenRun:  f.LastSeenRun,
		},
		Triage:         f.Triage,
		State:          f.State,
		ReasonCode:     f.ReasonCode,
		Priority:       f.Priority,
		VerifiedReason: optionalReason(f.VerifiedReason),
		FirstSeenAt:    f.FirstSeenAt,
		LastSeenAt:     f.LastSeenAt,
		ResolvedAt:     f.ResolvedAt,
		Derived: model.Derived{
			NotReobserved: f.NotReobserved,
			GapRepoScan:   optionalString(f.GapRunID),
			SLAStatus:     f.SLAStatus,
			SLAWindowDays: f.SLAWindowDays,
			SLABreachDays: f.SLABreachDays,
			AgeDays:       f.AgeDays,
		},
		CredentialType: p.CredentialType,
		Annotations:    p.Annotations,
		Refs: model.Refs{
			Ticket:      ticketRef(m.tickets, f.Fingerprint),
			PullRequest: prRef(m.remediationPRs, f.Fingerprint),
			// Dropped in Phase 8 when the ticket and pull request references
			// were added here, and unnoticed until the Producer-Coverage
			// Audit: the adapters populate it on 267 of 271 real findings and
			// the interface would have shown an empty advisory link on every
			// row.
			AdvisoryURL:     optionalString(p.AdvisoryURL),
			UpstreamFinding: optionalString(f.UpstreamFinding),
		},
	}
}

// ticketRef surfaces the ticket reference from the ticket table, never from the
// finding document. The document is rebuilt from observations on every scan;
// anything kept inside it is erased by the next run.
func ticketRef(tickets map[string]Ticket, fp string) *string {
	t, ok := tickets[fp]
	if !ok || t.URL == "" {
		return nil
	}
	url := t.URL
	return &url
}

// prRef surfaces the open pull request addressing a finding, from the
// remediation table rather than the finding document — which is rebuilt from
// observations on every scan.
func prRef(prs map[string]RemediationPR, fp string) *string {
	var best *RemediationPR
	for i := range prs {
		pr := prs[i]
		if !pr.Open() || pr.URL == "" {
			continue
		}
		for _, f := range pr.Findings {
			if f == fp && (best == nil || pr.Branch < best.Branch) {
				candidate := pr
				best = &candidate
			}
		}
	}
	if best == nil {
		return nil
	}
	url := best.URL
	return &url
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

// --- Planned scope (OQ-P2-02) ----------------------------------------------

func (m *Memory) RecordPlan(_ context.Context, entries []PlanEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range entries {
		if _, ok := m.runs[e.RunID]; !ok {
			return fmt.Errorf("%w: run %q", ErrNotFound, e.RunID)
		}
		if !e.State.Valid() {
			return fmt.Errorf("store: invalid dispatch state %q", e.State)
		}
		if e.PlannedAt.IsZero() {
			e.PlannedAt = m.clock()
		}
		if m.plan[e.RunID] == nil {
			m.plan[e.RunID] = map[string]PlanEntry{}
		}
		m.plan[e.RunID][e.Repo] = e
	}
	return nil
}

func (m *Memory) MarkDispatched(_ context.Context, runID, repo string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, err := m.planEntry(runID, repo)
	if err != nil {
		return err
	}
	at := m.clock()
	e.State, e.DispatchedAt, e.SkipReason = DispatchDispatched, &at, ""
	m.plan[runID][repo] = e
	return nil
}

func (m *Memory) MarkSkipped(_ context.Context, runID, repo, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, err := m.planEntry(runID, repo)
	if err != nil {
		return err
	}
	if reason == "" {
		// A skip with no reason is indistinguishable from a bug, and the gaps
		// view would have nothing to group by.
		return fmt.Errorf("store: skipping %s in %s requires a reason", repo, runID)
	}
	e.State, e.SkipReason = DispatchSkipped, reason
	m.plan[runID][repo] = e
	return nil
}

func (m *Memory) planEntry(runID, repo string) (PlanEntry, error) {
	entries, ok := m.plan[runID]
	if !ok {
		return PlanEntry{}, fmt.Errorf("%w: no plan for run %q", ErrNotFound, runID)
	}
	e, ok := entries[repo]
	if !ok {
		return PlanEntry{}, fmt.Errorf("%w: repo %q is not in the planned scope of %q", ErrNotFound, repo, runID)
	}
	return e, nil
}

func (m *Memory) PlanEntries(_ context.Context, runID string) ([]PlanEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []PlanEntry
	for _, e := range m.plan[runID] {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repo < out[j].Repo })
	return out, nil
}

func (m *Memory) CloseRun(ctx context.Context, runID string) (CloseStats, error) {
	m.mu.Lock()
	stats := CloseStats{SkipReasons: map[string]int{}}

	produced := map[string]bool{}
	for repo, results := range m.scanResults {
		for _, r := range results {
			if r.RunID == runID {
				produced[repo] = true
			}
		}
	}

	var missing []PlanEntry
	for _, e := range m.plan[runID] {
		if produced[e.Repo] {
			stats.Produced++
			continue
		}
		missing = append(missing, e)
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].Repo < missing[j].Repo })
	m.mu.Unlock()

	for _, e := range missing {
		outcome, cause := planCloseAction(e)
		if err := m.RecordScanResult(ctx, RepoScanResult{
			RunID: runID, Repo: e.Repo, Outcome: outcome,
			FailureCause: cause,
			// Never starting a scan, and losing a worker, are both the
			// platform's to answer for.
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

func (m *Memory) AcquireLease(_ context.Context, fp, owner string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.findings[fp]
	if !ok {
		return fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	if owner == "" {
		return fmt.Errorf("store: a lease requires an owner")
	}
	at := expiresAt.UTC()
	f.LeaseOwner, f.LeaseExpiresAt = owner, &at
	return nil
}

func (m *Memory) ReleaseLease(_ context.Context, fp string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.findings[fp]
	if !ok {
		return fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	f.LeaseOwner, f.LeaseExpiresAt = "", nil
	return nil
}

func (m *Memory) GetLease(_ context.Context, fp string) (Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.findings[fp]
	if !ok {
		return Lease{}, fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	return Lease{Fingerprint: fp, Owner: f.LeaseOwner, ExpiresAt: f.LeaseExpiresAt}, nil
}

func (m *Memory) SweepExpiredLeases(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var expired []string
	for fp, f := range m.findings {
		l := Lease{Owner: f.LeaseOwner, ExpiresAt: f.LeaseExpiresAt}
		if f.State == model.AutoRemediating && l.Expired(now) {
			expired = append(expired, fp)
		}
	}
	sort.Strings(expired)

	for _, fp := range expired {
		if err := m.transitionLocked(fp, model.Triaged, model.TransitionContext{
			Actor: model.ActorOrchestrator,
			Cause: "lease expired; reverting so a crashed worker cannot strand the finding (VM-F-158)",
			At:    now,
		}); err != nil {
			return 0, err
		}
		f := m.findings[fp]
		f.LeaseOwner, f.LeaseExpiresAt = "", nil
	}
	return len(expired), nil
}

// RepoNames lists every registered repository, sorted.
func (m *Memory) RepoNames(_ context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.repos))
	for n := range m.repos {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// FleetCoverage derives each repository's coverage state from its scan history.
func (m *Memory) FleetCoverage(_ context.Context, kind RunKind, repos []string) ([]CoverageState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Runs of the requested kind, newest first. Coverage is a fleet-wide
	// property, so it is measured against the fleet-wide run kind rather than
	// against advisory rescans that only ever touch a subset.
	var runIDs []string
	for id, r := range m.runs {
		if r.Kind == kind {
			runIDs = append(runIDs, id)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(runIDs)))

	order := map[string]int{}
	for i, id := range runIDs {
		order[id] = i
	}

	out := make([]CoverageState, 0, len(repos))
	for _, repo := range repos {
		var history []RepoScanResult
		for _, r := range m.scanResults[repo] {
			if _, ok := order[r.RunID]; ok {
				history = append(history, r)
			}
		}
		sort.Slice(history, func(i, j int) bool { return order[history[i].RunID] < order[history[j].RunID] })

		c := coverageFromHistory(repo, history)
		if c.LastQualifyingRun != "" {
			if run, ok := m.runs[c.LastQualifyingRun]; ok {
				at := run.StartedAt
				c.LastQualifyingAt = &at
			}
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repo < out[j].Repo })
	return out, nil
}

// SetTriage persists a finding's triage narrative (VM-F-301).
func (m *Memory) SetTriage(_ context.Context, fp string, t model.Triage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.findings[fp]
	if !ok {
		return fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	copied := t
	f.Triage = &copied
	return nil
}

// SetPriority persists the computed priority and reason code.
func (m *Memory) SetPriority(_ context.Context, fp string, p model.Priority, reason *model.ReasonCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.findings[fp]
	if !ok {
		return fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	if p != "" && !p.Valid() {
		return fmt.Errorf("store: invalid priority %q", p)
	}
	if reason != nil && !reason.Valid() {
		return fmt.Errorf("store: invalid reason code %q", *reason)
	}
	f.Priority, f.ReasonCode = p, reason
	return nil
}

// PreviousRun returns the run of the same kind immediately before seq.
func (m *Memory) PreviousRun(_ context.Context, kind RunKind, beforeSeq int64) (Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var best Run
	for _, r := range m.runs {
		if r.Kind != kind || r.Seq >= beforeSeq {
			continue
		}
		if best.ID == "" || r.Seq > best.Seq {
			best = r
		}
	}
	return best, nil
}

// SaveReport records an issued report (VM-ADR-15).
func (m *Memory) SaveReport(_ context.Context, r Report) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reports == nil {
		m.reports = map[string]Report{}
	}
	if existing, ok := m.reports[r.ID]; ok {
		// Immutable once issued. Re-issuing identical content is idempotent;
		// different content for the same identifier is a defect, because a
		// citation to that identifier would silently change meaning.
		if existing.ContentHash != r.ContentHash {
			return fmt.Errorf("store: report %s is already issued with a different content hash (%s); "+
				"reports are immutable — issue a new report that supersedes it (VM-ADR-15)", r.ID, existing.ContentHash)
		}
		return nil
	}
	m.reports[r.ID] = r
	return nil
}

// GetReport returns an issued report.
func (m *Memory) GetReport(_ context.Context, id string) (Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reports[id]
	if !ok {
		return Report{}, fmt.Errorf("%w: report %q", ErrNotFound, id)
	}
	return r, nil
}

// ReportsForRun lists the reports anchored to a run.
func (m *Memory) ReportsForRun(_ context.Context, runID string) ([]Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Report
	for _, r := range m.reports {
		if r.AnchorRunID == runID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// SetSLA persists the computed SLA position (VM-F-908).
func (m *Memory) SetSLA(_ context.Context, fp string, d model.Derived) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.findings[fp]
	if !ok {
		return fmt.Errorf("%w: finding %q", ErrNotFound, fp)
	}
	f.SLAStatus = d.SLAStatus
	f.SLAWindowDays = d.SLAWindowDays
	f.SLABreachDays = d.SLABreachDays
	f.AgeDays = d.AgeDays
	return nil
}

// --- Tickets (VM-AD §13.2) --------------------------------------------------

// SaveTicket records or updates a finding's ticket.
func (m *Memory) SaveTicket(_ context.Context, t Ticket) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tickets == nil {
		m.tickets = map[string]Ticket{}
	}
	if t.Fingerprint == "" {
		return fmt.Errorf("store: a ticket record needs a fingerprint; it is the idempotency key (VM-F-804)")
	}
	// Postgres enforces this with a foreign key. Memory has to enforce it too,
	// or a caller inventing a synthetic key passes here and fails only in
	// production — which is exactly what happened with pull request tickets:
	// a pull request is not a finding, and its ticket does not belong in this
	// table.
	if _, ok := m.findings[t.Fingerprint]; !ok {
		return fmt.Errorf("store: no finding %q; a ticket record must reference a real finding "+
			"(the Postgres backend enforces this with a foreign key, and the two must not diverge)", t.Fingerprint)
	}
	if existing, ok := m.tickets[t.Fingerprint]; ok && t.ClosedAt == nil && !t.Reopened {
		// A re-save must not silently reopen a closed ticket: closure is a fact
		// about the backend, not something a later create should overwrite.
		// Reopened is the explicit, deliberate exception (VM-F-806).
		t.ClosedAt = existing.ClosedAt
	}
	t.Reopened = false
	m.tickets[t.Fingerprint] = t
	return nil
}

// GetTicket returns a finding's ticket record, if one is known.
func (m *Memory) GetTicket(_ context.Context, fingerprint string) (Ticket, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tickets[fingerprint]
	return t, ok, nil
}

// DeleteTicket removes the local record, leaving the backend untouched.
func (m *Memory) DeleteTicket(_ context.Context, fingerprint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tickets, fingerprint)
	return nil
}

// CloseTicket records that a finding's ticket was closed (VM-F-811).
func (m *Memory) CloseTicket(_ context.Context, fingerprint string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tickets[fingerprint]
	if !ok {
		return fmt.Errorf("%w: ticket for %q", ErrNotFound, fingerprint)
	}
	when := at.UTC()
	t.ClosedAt = &when
	m.tickets[fingerprint] = t
	return nil
}

// --- Ticket operation queue (VM-F-812) --------------------------------------

func (m *Memory) EnqueueTicketOp(_ context.Context, op TicketOp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextOpID++
	op.ID = m.nextOpID
	if op.CreatedAt.IsZero() {
		op.CreatedAt = m.clock()
	}
	op.NextAttemptAt = op.NextAttemptAt.UTC()
	m.ticketOps = append(m.ticketOps, op)
	return nil
}

func (m *Memory) DueTicketOps(_ context.Context, now time.Time, limit int) ([]TicketOp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []TicketOp
	for _, op := range m.ticketOps {
		if op.NextAttemptAt.After(now.UTC()) {
			continue
		}
		out = append(out, op)
		if limit > 0 && len(out) == limit {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) CompleteTicketOp(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, op := range m.ticketOps {
		if op.ID == id {
			m.ticketOps = append(m.ticketOps[:i], m.ticketOps[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("%w: ticket op %d", ErrNotFound, id)
}

func (m *Memory) RetryTicketOp(_ context.Context, id int64, next time.Time, lastErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, op := range m.ticketOps {
		if op.ID == id {
			op.Attempts++
			op.NextAttemptAt = next.UTC()
			op.LastError = lastErr
			m.ticketOps[i] = op
			return nil
		}
	}
	return fmt.Errorf("%w: ticket op %d", ErrNotFound, id)
}

// --- Per-repository remediation lock (VM-AD §7.3, VM-F-503) -----------------

func (m *Memory) AcquireRepoLock(ctx context.Context, repo, owner string, expiresAt time.Time) error {
	return m.AcquireRepoLockAt(ctx, repo, owner, expiresAt, m.clock())
}

func (m *Memory) AcquireRepoLockAt(_ context.Context, repo, owner string, expiresAt, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if owner == "" {
		return fmt.Errorf("store: a repository lock needs an owner; an anonymous lock cannot be released or attributed")
	}
	if m.repoLocks == nil {
		m.repoLocks = map[string]RepoLock{}
	}

	if existing, ok := m.repoLocks[repo]; ok && existing.Held(now) && existing.Owner != owner {
		return fmt.Errorf("%w: held by %s until %s", ErrRepoLocked, existing.Owner, existing.ExpiresAt)
	}
	// Reentrant for the owner, and an expired lock is reclaimed here rather
	// than only by the sweeper: a worker must not wait a sweeper cycle to take
	// a lock nobody holds.
	acquired := now.UTC()
	if existing, ok := m.repoLocks[repo]; ok && existing.Owner == owner {
		acquired = existing.AcquiredAt
	}
	exp := expiresAt.UTC()
	m.repoLocks[repo] = RepoLock{Repo: repo, Owner: owner, AcquiredAt: acquired, ExpiresAt: &exp}
	return nil
}

func (m *Memory) ReleaseRepoLock(_ context.Context, repo, owner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.repoLocks[repo]
	if !ok {
		return nil
	}
	if existing.Owner != owner {
		return fmt.Errorf("store: %s cannot release %s's lock on %s; "+
			"releasing another worker's lock would reintroduce concurrent remediation mid-flight", owner, existing.Owner, repo)
	}
	delete(m.repoLocks, repo)
	return nil
}

func (m *Memory) GetRepoLock(_ context.Context, repo string) (RepoLock, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.repoLocks[repo], nil
}

func (m *Memory) SweepExpiredRepoLocks(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for repo, lock := range m.repoLocks {
		if !lock.Held(now) {
			delete(m.repoLocks, repo)
			n++
		}
	}
	return n, nil
}

// --- Remediation pull requests (VM-AD §11) ----------------------------------

func (m *Memory) SaveRemediationPR(_ context.Context, pr RemediationPR) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if pr.Branch == "" {
		return fmt.Errorf("store: a remediation pull request needs a branch; it is the idempotency key (VM-F-502)")
	}
	if m.remediationPRs == nil {
		m.remediationPRs = map[string]RemediationPR{}
	}
	if existing, ok := m.remediationPRs[pr.Branch]; ok {
		if pr.ClosedAt == nil {
			pr.ClosedAt = existing.ClosedAt
		}
		if pr.OpenedAt.IsZero() {
			pr.OpenedAt = existing.OpenedAt
		}
	}
	if pr.OpenedAt.IsZero() {
		pr.OpenedAt = m.clock()
	}
	pr.Findings = append([]string(nil), pr.Findings...)
	sort.Strings(pr.Findings)
	m.remediationPRs[pr.Branch] = pr
	return nil
}

func (m *Memory) GetRemediationPR(_ context.Context, branch string) (RemediationPR, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pr, ok := m.remediationPRs[branch]
	return pr, ok, nil
}

func (m *Memory) RemediationPRForFinding(_ context.Context, fingerprint string) (RemediationPR, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var (
		best  RemediationPR
		found bool
	)
	for _, pr := range m.remediationPRs {
		if !pr.Open() {
			continue
		}
		for _, fp := range pr.Findings {
			if fp != fingerprint {
				continue
			}
			// Deterministic when several match: the earliest branch wins, so
			// two backends cannot disagree about which pull request is "the"
			// one for a finding.
			if !found || pr.Branch < best.Branch {
				best, found = pr, true
			}
		}
	}
	return best, found, nil
}

func (m *Memory) CloseRemediationPR(_ context.Context, branch string, at time.Time, merged bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	pr, ok := m.remediationPRs[branch]
	if !ok {
		return fmt.Errorf("%w: remediation pull request for branch %q", ErrNotFound, branch)
	}
	when := at.UTC()
	pr.State, pr.ClosedAt, pr.Merged = "closed", &when, merged
	m.remediationPRs[branch] = pr
	return nil
}

func (m *Memory) OpenRemediationPRs(_ context.Context, repo string) ([]RemediationPR, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []RemediationPR
	for _, pr := range m.remediationPRs {
		if pr.Repo == repo && pr.Open() {
			out = append(out, pr)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Branch < out[j].Branch })
	return out, nil
}

// --- Run parent tickets (VM-AD §13.3 row 1) ---------------------------------

func (m *Memory) SaveRunTicket(_ context.Context, t RunTicket) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.RunID == "" {
		return fmt.Errorf("store: a run parent ticket needs a run identifier")
	}
	if m.runTickets == nil {
		m.runTickets = map[string]RunTicket{}
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = m.clock()
	}
	m.runTickets[t.RunID] = t
	return nil
}

func (m *Memory) GetRunTicket(_ context.Context, runID string) (RunTicket, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.runTickets[runID]
	return t, ok, nil
}

// TicketByRef reverse-resolves a backend reference (OQ-P8-01).
func (m *Memory) TicketByRef(_ context.Context, backend, ref string) (Ticket, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tickets {
		if t.Backend == backend && t.Ref == ref {
			return t, true, nil
		}
	}
	return Ticket{}, false, nil
}

// SecretPaths returns files holding an unresolved secret finding (VM-F-854).
func (m *Memory) SecretPaths(ctx context.Context, repo string) ([]string, error) {
	findings, err := m.ListFindings(ctx, Query{
		Scope: ScopeOpen, Repo: repo, Categories: []model.Category{model.CategorySecret},
	})
	if err != nil {
		return nil, err
	}
	return secretPathsOf(findings), nil
}

// secretPathsOf extracts the distinct file paths, shared by both backends so
// they cannot disagree about what counts.
func secretPathsOf(findings []model.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		if f.Location.File == nil || *f.Location.File == "" {
			continue
		}
		if !seen[*f.Location.File] {
			seen[*f.Location.File] = true
			out = append(out, *f.Location.File)
		}
	}
	sort.Strings(out)
	return out
}

// SetUpstreamFinding records the upstream finding a consumer is blocked on.
func (m *Memory) SetUpstreamFinding(_ context.Context, fingerprint, upstream string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.findings[fingerprint]
	if !ok {
		return fmt.Errorf("%w: finding %q", ErrNotFound, fingerprint)
	}
	f.UpstreamFinding = upstream
	return nil
}

// --- Dependency manifests (VM-F-602) ----------------------------------------

func (m *Memory) RecordDeps(_ context.Context, runID, repo string, deps []ModuleDep) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deps == nil {
		m.deps = map[string]map[string]ModuleDep{}
	}
	// Keyed by repository, replacing wholesale: a repository that dropped a
	// dependency must stop appearing as a consumer of it, and merging would
	// leave it there for ever.
	fresh := map[string]ModuleDep{}
	for _, d := range deps {
		d.RunID, d.Repo = runID, repo
		fresh[d.Module] = d
	}
	m.deps[repo] = fresh
	return nil
}

func (m *Memory) Dependents(_ context.Context, module string) ([]ModuleDep, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ModuleDep
	for _, byModule := range m.deps {
		if d, ok := byModule[module]; ok {
			out = append(out, d)
		}
	}
	sortDeps(out)
	return out, nil
}

func (m *Memory) AllDeps(_ context.Context) ([]ModuleDep, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ModuleDep
	for _, byModule := range m.deps {
		for _, d := range byModule {
			out = append(out, d)
		}
	}
	sortDeps(out)
	return out, nil
}

// sortDeps orders by repository then module, shared by both backends so an
// index built from either is identical — a wave plan derived from a different
// order would dispatch a different wave.
func sortDeps(in []ModuleDep) {
	sort.Slice(in, func(a, b int) bool {
		if in[a].Repo != in[b].Repo {
			return in[a].Repo < in[b].Repo
		}
		return in[a].Module < in[b].Module
	})
}
