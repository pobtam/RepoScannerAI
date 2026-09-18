package api

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
)

// The finding explorer's endpoints (VM-UI-F-4xx, VM-UI-F-5xx).

// parseSearch turns query parameters into a store query.
//
// Every dimension VM-UI-F-406 lists, and nothing is defaulted that changes
// which findings are counted: an unrecognised value is an error, not a silent
// omission, because a filter the server ignored shows the reader a list they
// did not ask for and gives them no way to tell.
func (s *Server) parseSearch(r *http.Request) (store.SearchQuery, error) {
	q := store.SearchQuery{}

	scope := r.URL.Query().Get("scope")
	if scope == "" {
		// Not defaulted here, but the interface's documented default is
		// "unresolved across all runs" (VM-UI-F-411), so the client always
		// sends one. Refusing is what makes that visible rather than
		// accidental.
		return q, fmt.Errorf("scope is required: one of open, all, run")
	}
	q.Scope = store.Scope(scope)
	if !q.Scope.Valid() {
		return q, fmt.Errorf("unknown scope %q; the corpora are open, all and run", scope)
	}
	q.RunID = r.URL.Query().Get("run")
	if q.Scope == store.ScopeRun && q.RunID == "" {
		// Refused here rather than by the store, so the reader gets the
		// parameter name and not an internal message.
		return q, fmt.Errorf("scope=run needs a run identifier: pass run=<id>")
	}

	f := store.Filter{}
	f.Repos = listParam(r, "repo")
	for _, raw := range listParam(r, "tier") {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return q, fmt.Errorf("tier must be a number, got %q", raw)
		}
		f.Tiers = append(f.Tiers, n)
	}
	f.Languages = listParam(r, "language")
	for _, raw := range listParam(r, "category") {
		c := model.Category(raw)
		if !c.Valid() {
			return q, fmt.Errorf("unknown category %q; the set is %v", raw, model.AllCategories)
		}
		f.Categories = append(f.Categories, c)
	}
	for _, raw := range listParam(r, "state") {
		st := model.State(raw)
		if !st.Valid() {
			return q, fmt.Errorf("unknown state %q", raw)
		}
		f.States = append(f.States, st)
	}
	for _, raw := range listParam(r, "reason") {
		f.Reasons = append(f.Reasons, model.ReasonCode(raw))
	}
	for _, raw := range listParam(r, "priority") {
		p := model.Priority(raw)
		if !p.Valid() {
			return q, fmt.Errorf("unknown priority %q; the bands are %v", raw, model.AllPriorities)
		}
		f.Priorities = append(f.Priorities, p)
	}
	for _, raw := range listParam(r, "severity") {
		sv := model.Severity(raw)
		if !sv.Valid() {
			return q, fmt.Errorf("unknown severity %q; the bands are %v", raw, model.AllSeverities)
		}
		f.Severities = append(f.Severities, sv)
	}
	for _, raw := range listParam(r, "reachable") {
		rc := model.Reachable(raw)
		if !rc.Valid() {
			return q, fmt.Errorf("unknown reachability %q; the tri-state is true, false or "+
				"unknown, and unknown is not false (VM-F-243)", raw)
		}
		f.Reachable = append(f.Reachable, rc)
	}
	for _, raw := range listParam(r, "depClass") {
		f.DepClasses = append(f.DepClasses, model.DepClass(raw))
	}

	var err error
	if f.Transitive, err = boolParam(r, "transitive"); err != nil {
		return q, err
	}
	if f.FirstParty, err = boolParam(r, "firstParty"); err != nil {
		return q, err
	}
	if f.Blocked, err = boolParam(r, "blocked"); err != nil {
		return q, err
	}
	if f.HasPR, err = boolParam(r, "hasPR"); err != nil {
		return q, err
	}
	if f.HasTicket, err = boolParam(r, "hasTicket"); err != nil {
		return q, err
	}
	if f.NotReobserved, err = boolParam(r, "notReobserved"); err != nil {
		return q, err
	}
	if f.SLABreached, err = boolParam(r, "slaBreached"); err != nil {
		return q, err
	}
	if f.FirstSeenFrom, err = timeParam(r, "firstSeenFrom"); err != nil {
		return q, err
	}
	if f.FirstSeenTo, err = timeParam(r, "firstSeenTo"); err != nil {
		return q, err
	}
	if f.LastSeenFrom, err = timeParam(r, "lastSeenFrom"); err != nil {
		return q, err
	}
	if f.LastSeenTo, err = timeParam(r, "lastSeenTo"); err != nil {
		return q, err
	}
	f.Text = strings.TrimSpace(r.URL.Query().Get("q"))
	q.Filter = f

	q.Sort = store.Sort{
		Field: store.SortField(orDefault(r.URL.Query().Get("sort"), string(store.SortPriority))),
		Dir:   store.SortDir(orDefault(r.URL.Query().Get("dir"), string(store.SortDesc))),
	}
	if !q.Sort.Field.Valid() {
		return q, fmt.Errorf("unknown sort %q; the orderings are %v", q.Sort.Field, store.AllSortFields)
	}
	if !q.Sort.Dir.Valid() {
		return q, fmt.Errorf("unknown direction %q; asc or desc", q.Sort.Dir)
	}
	q.Cursor = r.URL.Query().Get("cursor")

	limit, err := intParam(r, "limit", store.DefaultPageSize, store.MaxPageSize)
	if err != nil {
		return q, err
	}
	q.Limit = limit
	return q, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q, err := s.parseSearch(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "bad query", err.Error(),
			"correct the parameter; nothing is defaulted that would change which findings are counted")
		return
	}
	page, err := s.cfg.Store.Search(r.Context(), q)
	if err != nil {
		s.failStore(w, r, err)
		return
	}

	// The total, so filter and scope are separately legible (VM-UI-F-419).
	total, err := s.total(r.Context())
	if err != nil {
		s.failStore(w, r, err)
		return
	}

	p := principalFrom(r.Context())
	out := FindingPage{
		Matched: page.Matched, InCorpus: page.InCorpus, Total: total,
		NextCursor: page.Next, Sort: string(q.Sort.Field), Dir: string(q.Sort.Dir),
		Corpus: s.corpusOf(q, page, total),
	}
	for _, f := range page.Findings {
		dto := s.findingDTO(r.Context(), f, true)
		if !p.MaySeeFindingDetail(f) {
			dto = restrict(dto)
			out.RestrictedCount++
		}
		out.Findings = append(out.Findings, dto)
	}
	if out.Findings == nil {
		out.Findings = []Finding{}
	}
	s.write(w, r, http.StatusOK, out)
}

// total is every finding ever recorded, for the third figure.
func (s *Server) total(ctx context.Context) (int, error) {
	page, err := s.cfg.Store.Search(ctx, store.SearchQuery{Scope: store.ScopeAll, Limit: 1})
	if err != nil {
		return 0, err
	}
	return page.InCorpus, nil
}

// corpusOf states the corpus in words, with what it excludes (VM-UI-F-417/418).
func (s *Server) corpusOf(q store.SearchQuery, page store.Page, total int) Corpus {
	c := Corpus{Scope: string(q.Scope), RunID: q.RunID, ExcludedCount: total - page.InCorpus}
	switch q.Scope {
	case store.ScopeOpen:
		c.Description = "unresolved findings across all runs"
		c.Excludes = "verified, suppressed, declined and won't-fix findings, and findings " +
			"pending verification after a merge"
	case store.ScopeRun:
		c.Description = "findings observed in run " + q.RunID
		c.Excludes = "every finding not observed in that run, including unresolved findings the " +
			"run did not look for"
	default:
		c.Description = "every finding ever recorded"
		c.Excludes = ""
		c.ExcludedCount = 0
	}
	return c
}

func (s *Server) handleFacets(w http.ResponseWriter, r *http.Request) {
	q, err := s.parseSearch(r)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "bad query", err.Error(), "correct the parameter")
		return
	}
	counts, err := s.cfg.Store.Facets(r.Context(), q)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	s.write(w, r, http.StatusOK, facetsDTO(counts))
}

// facetsDTO renders the counts as ordered options, each stating whether
// selecting it would return anything.
func facetsDTO(c store.FacetCounts) Facets {
	strOpts := func(m map[string]int, order []string) []FacetOption {
		var out []FacetOption
		if len(order) > 0 {
			for _, k := range order {
				if n, ok := m[k]; ok {
					out = append(out, FacetOption{Value: k, Count: n, Disabled: n == 0})
				}
			}
			return out
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, FacetOption{Value: k, Count: m[k], Disabled: m[k] == 0})
		}
		return out
	}

	states := make([]string, 0, len(model.AllStates))
	for _, st := range model.AllStates {
		states = append(states, string(st))
	}
	sevs := make([]string, 0, len(model.AllSeverities))
	for _, sv := range model.AllSeverities {
		sevs = append(sevs, string(sv))
	}
	prios := make([]string, 0, len(model.AllPriorities))
	for _, p := range model.AllPriorities {
		prios = append(prios, string(p))
	}
	cats := make([]string, 0, len(model.AllCategories))
	for _, cc := range model.AllCategories {
		cats = append(cats, string(cc))
	}
	// Reachability in tri-state order, so "unknown" always renders between the
	// determinations rather than wherever the map iteration put it.
	reach := []string{string(model.ReachableTrue), string(model.ReachableUnknown), string(model.ReachableFalse)}

	tiers := make([]FacetOption, 0, len(c.Tiers))
	keys := make([]int, 0, len(c.Tiers))
	for k := range c.Tiers {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		tiers = append(tiers, FacetOption{
			Value: strconv.Itoa(k), Count: c.Tiers[k], Disabled: c.Tiers[k] == 0})
	}

	return Facets{
		Repos:      strOpts(c.Repos, nil),
		Tiers:      tiers,
		Languages:  strOpts(c.Languages, nil),
		Categories: strOpts(c.Categories, cats),
		States:     strOpts(c.States, states),
		Reasons:    strOpts(c.Reasons, nil),
		Priorities: strOpts(c.Priorities, prios),
		Severities: strOpts(c.Severities, sevs),
		Reachable:  strOpts(c.Reachable, reach),
		DepClasses: strOpts(c.DepClasses, nil),
	}
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	f, err := s.cfg.Store.GetFinding(r.Context(), r.PathValue("fp"))
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	p := principalFrom(r.Context())
	if !p.MaySeeFindingDetail(f) {
		// Refused, and said so: the reader learns the record exists and that
		// they may not open it, rather than being told it does not exist.
		s.fail(w, r, http.StatusForbidden, "restricted",
			fmt.Sprintf("a %s finding's detail is visible to the security owner group and the "+
				"owning repository's code owners (VM-UI-F-803)", f.Category),
			"ask the security owner group; the record is counted in every aggregate you can see")
		return
	}
	s.write(w, r, http.StatusOK, s.findingDTO(r.Context(), f, true))
}

// findingDTO renders a finding, with every honesty distinction intact.
func (s *Server) findingDTO(ctx context.Context, f model.Finding, withScore bool) Finding {
	out := Finding{
		Fingerprint: f.Fingerprint,
		Repo:        f.Repo,
		Category:    string(f.Category),
		Identity: Identity{
			PrimaryID: f.Identity.PrimaryID,
			Aliases:   emptyIfNil(f.Identity.Aliases),
			RuleID:    deref(f.Identity.RuleID),
		},
		Location: Location{
			Module: f.Location.Module, ModuleMajor: f.Location.ModuleMajor,
			Package: deref(f.Location.Package), Function: deref(f.Location.Function),
			File: deref(f.Location.File), Line: derefInt(f.Location.Line),
		},
		Versions: Versions{
			Current: f.Versions.Current, Fixed: f.Versions.Fixed, Introduced: f.Versions.Introduced,
		},
		Classification: classificationDTO(f.Classification),
		State:          string(f.State),
		Partition:      partitionOf(f.State),
		Priority:       string(f.Priority),
		CredentialType: f.CredentialType,
		SLA:            s.slaDTO(f),
		Observation:    observationDTO(f),
		Refs: Refs{
			Ticket: deref(f.Refs.Ticket), PullRequest: deref(f.Refs.PullRequest),
			AdvisoryURL: deref(f.Refs.AdvisoryURL), UpstreamFinding: deref(f.Refs.UpstreamFinding),
		},
		Provenance: Provenance{
			Tools: emptyIfNil(f.Provenance.Tools), ToolVersions: f.Provenance.ToolVersions,
		},
		Annotations: f.Annotations,
	}
	if f.ReasonCode != nil {
		out.ReasonCode = string(*f.ReasonCode)
	}
	if f.VerifiedReason != nil {
		out.VerifiedReason = string(*f.VerifiedReason)
	}
	if f.Triage != nil {
		out.Triage = &Triage{
			Description: f.Triage.Description, Impact: f.Triage.Impact,
			Remediation:            f.Triage.Remediation,
			FalsePositiveCandidate: f.Triage.FalsePositiveCandidate,
			FPReasoning:            deref(f.Triage.FPReasoning),
			TriagedAt:              f.Triage.TriagedAt, Model: f.Triage.Model,
		}
	}
	if withScore {
		out.Score = s.scoreDTO(ctx, f)
	}
	return out
}

// classificationDTO keeps "nobody looked" absent rather than zero.
func classificationDTO(c model.Classification) Classification {
	out := Classification{
		Severity: string(c.Severity), CVSS: c.CVSS,
		Reachable: string(reachableOrUnknown(c.Reachable)),
		DepClass:  string(c.DepClass), Transitive: c.Transitive,
		FirstPartyPath: deref(c.FirstPartyPath),
	}
	if c.EPSSAvailable {
		v := c.EPSS
		out.EPSS = &v
		out.EPSSAsOf = c.EPSSAsOf
	} else {
		out.ExploitIntelUnavailable = append(out.ExploitIntelUnavailable,
			"EPSS (exploit prediction): nothing answered for this finding's identifiers, so the "+
				"absence is not a score of zero")
	}
	if c.KEVAvailable {
		v := c.KEV
		out.KEV = &v
		out.KEVAsOf = c.KEVAsOf
	} else {
		out.ExploitIntelUnavailable = append(out.ExploitIntelUnavailable,
			"KEV (CISA known-exploited): the catalogue was not consulted for this finding, so the "+
				"absence is not a determination that it is unexploited")
	}
	return out
}

func reachableOrUnknown(r model.Reachable) model.Reachable {
	if r.Valid() {
		return r
	}
	return model.ReachableUnknown
}

// slaDTO renders the SLA position, including the two ways it can be absent.
func (s *Server) slaDTO(f model.Finding) SLA {
	out := SLA{
		Status: string(f.Derived.SLAStatus), WindowDays: f.Derived.SLAWindowDays,
		BreachDays: f.Derived.SLABreachDays, AgeDays: f.Derived.AgeDays,
		Computed:           f.Derived.SLAStatus != "",
		WindowsProvisional: !s.cfg.Calibration.SLA.Calibrated,
	}
	if !out.Computed {
		// The distinction OQ-P7-03 exists for: no status is not "within
		// window", it is nobody having computed one.
		out.Caveat = "no SLA has been computed for this finding, so it is neither within its " +
			"window nor breached — those figures are absent, not zero"
		return out
	}
	if out.WindowsProvisional {
		out.Caveat = "provisional: the remediation windows behind this figure have not been " +
			"reviewed by anyone (VM-OQ-02)"
	}
	return out
}

// observationDTO carries the absence-is-not-resolution block.
func observationDTO(f model.Finding) Observation {
	out := Observation{
		FirstSeenRun: f.Provenance.FirstSeenRun, LastSeenRun: f.Provenance.LastSeenRun,
		FirstSeenAt: f.FirstSeenAt, LastSeenAt: f.LastSeenAt, ResolvedAt: f.ResolvedAt,
		NotReobserved:    f.Derived.NotReobserved,
		GapRepoScan:      deref(f.Derived.GapRepoScan),
		ResidualPossible: f.Derived.ResidualPossible,
		ResidualDetail:   f.Derived.ResidualDetail,
	}
	if f.Derived.NotReobserved {
		// The words travel with the marker (VM-UI-F-423). A client that
		// invented its own wording would drift from the framework's, and this
		// is the sentence that stops a reader concluding "fixed".
		out.NotReobservedNote = "the most recent applicable run did not observe this finding " +
			"while it remains unresolved. That is AMBIGUOUS between remediation and a coverage " +
			"gap: check the coverage view for this repository before concluding it was fixed " +
			"(VM-ADR-12)"
		if out.GapRepoScan != "" {
			out.NotReobservedNote += ". A coverage gap in run " + out.GapRepoScan +
				" is recorded for this repository, which is the more likely explanation"
		}
	}
	return out
}

// scoreDTO recomputes the decomposition from the finding's own inputs.
//
// Recomputed rather than stored, because VM-UI-F-510 asks for the ARGUMENT
// behind the band and the pass persists only its conclusion. That makes the
// stored band and the recomputed one comparable, which is worth having: if
// they differ, the calibration changed since the finding was scored, and the
// response says so rather than presenting either number as current.
func (s *Server) scoreDTO(ctx context.Context, f model.Finding) *ScoreBreakdown {
	tier := 0
	if repo, err := s.cfg.Store.GetRepo(ctx, f.Repo); err == nil {
		tier = repo.Tier
	}
	res := s.score.Score(score.Input{
		Category: f.Category, Severity: f.Classification.Severity, CVSS: f.Classification.CVSS,
		EPSS: f.Classification.EPSS, KEV: f.Classification.KEV,
		EPSSAvailable: f.Classification.EPSSAvailable, KEVAvailable: f.Classification.KEVAvailable,
		EPSSAsOf: f.Classification.EPSSAsOf, KEVAsOf: f.Classification.KEVAsOf,
		Reachable: f.Classification.Reachable, DepClass: f.Classification.DepClass,
		Tier: tier, Now: s.now(),
	})
	out := &ScoreBreakdown{
		Score: res.Score, Priority: string(res.Priority), Base: res.Base,
		KEVBoost: res.KEVBoost, EPSSBoost: res.EPSSBoost,
		ReachMultiplier: res.ReachMultiplier, DepMultiplier: res.DepMultiplier,
		TierMultiplier: res.TierMultiplier, FanOutMult: res.FanOutMult,
		Explain: res.Explain, Caveat: res.Caveat,
		ThresholdsCalibrated: s.cfg.Calibration.StaticAnalysis.Calibrated,
		Recomputed:           true,
		Inputs: ScoreInputs{
			Available:   score.DeclaredInputs() - len(res.UnavailableInputs),
			Declared:    score.DeclaredInputs(),
			Unavailable: res.UnavailableInputs,
			Stale:       res.StaleInputs,
		},
	}
	if f.Priority != "" && f.Priority != res.Priority {
		out.DisagreesWithStored = true
		out.StoredPriority = string(f.Priority)
	}
	return out
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fp := r.PathValue("fp")
	f, err := s.cfg.Store.GetFinding(ctx, fp)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	if !principalFrom(ctx).MaySeeFindingDetail(f) {
		s.fail(w, r, http.StatusForbidden, "restricted",
			"this finding's detail is restricted (VM-UI-F-803)",
			"ask the security owner group")
		return
	}

	trail, err := s.cfg.Store.Transitions(ctx, fp)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	out := Timeline{Fingerprint: fp}
	for _, t := range trail {
		out.Transitions = append(out.Transitions, Transition{
			From: string(t.From), To: string(t.To), Actor: string(t.Actor),
			Cause: t.Cause, At: t.At,
		})
	}
	if out.Transitions == nil {
		out.Transitions = []Transition{}
	}

	// The observation history, INCLUDING the runs that did not see it
	// (VM-UI-F-503). A list of only the runs that observed it cannot show a
	// gap, and the gap is the interesting part.
	obs, err := s.observations(ctx, f)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	out.Observations = emptyIfNil(obs)
	s.write(w, r, http.StatusOK, out)
}

// observations builds the per-run history for one finding.
func (s *Server) observations(ctx context.Context, f model.Finding) ([]RunObservation, error) {
	results, err := s.cfg.Store.ScanResults(ctx, f.Repo, 50)
	if err != nil {
		return nil, err
	}
	// The runs that observed it, from the retained observations. Reading them
	// rather than asking per run is what lets the history show the runs that
	// did NOT see it — which is the interesting half (VM-UI-F-503).
	observed := map[string]bool{}
	obs, err := s.cfg.Store.Observations(ctx, f.Fingerprint)
	if err != nil {
		return nil, err
	}
	for _, o := range obs {
		observed[o.RunID] = true
	}

	out := make([]RunObservation, 0, len(results))
	for _, res := range results {
		run, err := s.cfg.Store.GetRun(ctx, res.RunID)
		if err != nil {
			continue
		}
		o := RunObservation{
			RunID: res.RunID, Kind: string(run.Kind), At: run.StartedAt,
			Observed: observed[res.RunID], Outcome: string(res.Outcome), Tools: res.ToolsOK,
		}
		if !o.Observed {
			if res.Outcome.Succeeded() {
				o.Note = "a complete scan did not observe it"
			} else {
				o.Note = "the scan did not qualify (" + string(res.Outcome) +
					"), so its silence says nothing about this finding (VM-ADR-12)"
			}
		}
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out, nil
}

func (s *Server) handleAttempts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fp := r.PathValue("fp")
	f, err := s.cfg.Store.GetFinding(ctx, fp)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	if !principalFrom(ctx).MaySeeFindingDetail(f) {
		s.fail(w, r, http.StatusForbidden, "restricted",
			"this finding's detail is restricted (VM-UI-F-803)", "ask the security owner group")
		return
	}
	// Every pull request that has ever carried this finding, open or closed:
	// the attempt history is the point, and only showing the open one hides
	// that two attempts were declined (VM-UI-F-508).
	prs, err := s.cfg.Store.RemediationPRsForFinding(ctx, fp)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	out := make([]Attempt, 0, len(prs))
	for _, pr := range prs {
		out = append(out, attemptDTO(pr))
	}
	s.write(w, r, http.StatusOK, out)
}

func attemptDTO(pr store.RemediationPR) Attempt {
	return Attempt{
		Branch: pr.Branch, FixGroupID: pr.FixGroupID, Repo: pr.Repo, Number: pr.Number,
		URL: pr.URL, State: pr.State, Merged: pr.Merged, OpenedAt: pr.OpenedAt,
		ClosedAt: pr.ClosedAt, Findings: pr.Findings, TicketURL: pr.TicketURL,
		ConfirmedAt: pr.ConfirmedAt,
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

var _ = time.Time{}
