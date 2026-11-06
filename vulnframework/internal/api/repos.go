package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// The repository views (VM-UI-F-6xx) and the coverage view (VM-UI-F-75x).

func (s *Server) handleRepos(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	names, err := s.cfg.Store.RepoNames(ctx)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	out := make([]RepoSummary, 0, len(names))
	for _, name := range names {
		sum, err := s.repoSummary(ctx, name)
		if err != nil {
			s.failStore(w, r, err)
			return
		}
		out = append(out, sum)
	}
	// Most open findings first, so the index is ordered by where the work is.
	sort.Slice(out, func(i, j int) bool {
		if out[i].OpenFindings != out[j].OpenFindings {
			return out[i].OpenFindings > out[j].OpenFindings
		}
		return out[i].Name < out[j].Name
	})
	s.write(w, r, http.StatusOK, out)
}

func (s *Server) repoSummary(ctx context.Context, name string) (RepoSummary, error) {
	repo, err := s.cfg.Store.GetRepo(ctx, name)
	if err != nil {
		return RepoSummary{}, err
	}
	out := RepoSummary{
		Name: repo.Name, Tier: repo.Tier, Languages: emptyIfNil(repo.Languages),
		HasTestSuite: repo.HasTestSuite, ModuleTopology: repo.ModuleTopology,
		Codeowners: repo.Codeowners, Archived: repo.Archived,
		BySeverity: map[string]int{}, ByCategory: map[string]int{},
	}
	if !repo.HasTestSuite {
		// Prominent, because it constrains what the framework may do here
		// (VM-UI-F-607): no test suite means no verification gate, so
		// automated remediation cannot be trusted and does not run.
		out.NoTestSuiteNote = "this repository has no test suite, so a remediation cannot be " +
			"verified here: automated fixes are not attempted and every finding needs a person"
	}

	open, err := s.cfg.Store.ListFindings(ctx, store.Query{Scope: store.ScopeOpen, Repo: name})
	if err != nil {
		return RepoSummary{}, err
	}
	for _, f := range open {
		out.OpenFindings++
		out.BySeverity[string(f.Classification.Severity)]++
		out.ByCategory[string(f.Category)]++
		if f.Derived.SLAStatus == model.SLABreached {
			out.SLABreached++
		}
		if f.Derived.NotReobserved {
			out.NotReobserved++
		}
	}

	results, err := s.cfg.Store.ScanResults(ctx, name, 1)
	if err != nil {
		return RepoSummary{}, err
	}
	if len(results) > 0 {
		out.LastScannedRun = results[0].RunID
		out.LastOutcome = string(results[0].Outcome)
		out.LastCommitSHA = results[0].CommitSHA
		if run, err := s.cfg.Store.GetRun(ctx, results[0].RunID); err == nil {
			at := run.StartedAt
			out.LastScannedAt = &at
		}
	}
	return out, nil
}

func (s *Server) handleRepo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := strings.TrimSuffix(r.PathValue("repo"), "/")
	if name == "" {
		s.fail(w, r, http.StatusBadRequest, "no repository", "the path must name a repository",
			"use /v1/repos to list them")
		return
	}
	// A repository name contains a slash, so the route is a wildcard and the
	// trend suffix is stripped here rather than by a second route.
	if strings.HasSuffix(name, "/trend") {
		s.repoTrend(w, r, strings.TrimSuffix(name, "/trend"))
		return
	}

	sum, err := s.repoSummary(ctx, name)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	out := RepoDetail{
		Repo:       sum,
		SLAWindows: emptyMapIfNil(s.cfg.Calibration.SLA.Windows),
		// Stated rather than implied: the windows in force belong on the view
		// that shows an age (VM-UI-F-612).
		SLAWindowsProvisional: !s.cfg.Calibration.SLA.Calibrated,
	}

	deps, err := s.cfg.Store.AllDeps(ctx)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	for _, d := range deps {
		if d.Repo != name {
			continue
		}
		out.Dependencies = append(out.Dependencies, Dependency{
			Module: d.Module, Version: d.Version, Direct: d.Direct, Replaced: d.Replaced,
		})
	}
	sort.Slice(out.Dependencies, func(i, j int) bool {
		return out.Dependencies[i].Module < out.Dependencies[j].Module
	})

	prs, err := s.cfg.Store.OpenRemediationPRs(ctx, name)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	for _, pr := range prs {
		out.OpenPRs = append(out.OpenPRs, attemptDTO(pr))
	}

	// Consumers of a first-party module this repository owns (VM-UI-F-606).
	consumers, err := s.consumersOf(ctx, name)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	out.Consumers = consumers

	hist, err := s.coverageHistory(ctx, []string{name}, 10)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	out.Coverage = emptyIfNil(hist)

	if out.AIComponents, err = s.aiComponents(ctx, name); err != nil {
		s.failStore(w, r, err)
		return
	}
	s.write(w, r, http.StatusOK, out)
}

// aiComponents reads the AI inventory the latest scan recorded.
func (s *Server) aiComponents(ctx context.Context, name string) (AIComponents, error) {
	results, err := s.cfg.Store.ScanResults(ctx, name, 1)
	if err != nil {
		return AIComponents{}, err
	}
	if len(results) == 0 {
		return AIComponents{Note: "not measured: this repository has not been scanned"}, nil
	}
	latest := results[0]
	out := AIComponents{RunID: latest.RunID}
	if len(latest.AIInventory) == 0 {
		out.Note = "not measured in the latest scan: the AI inventory comes from NuGuard, which is " +
			"opt-in and was not configured or did not run. Not measured is not none"
		return out, nil
	}
	var inv struct {
		Source              string         `json:"source"`
		RulepackSHA256      string         `json:"rulepack_sha256"`
		ImageDigest         string         `json:"image_digest"`
		NodeCounts          map[string]int `json:"node_counts"`
		EdgeCount           int            `json:"edge_count"`
		Frameworks          []string       `json:"frameworks"`
		ModelProviders      []string       `json:"model_providers"`
		PostureObservations map[string]int `json:"posture_observations"`
	}
	if err := json.Unmarshal(latest.AIInventory, &inv); err != nil {
		out.Note = "not measured: the recorded inventory could not be read"
		return out, nil
	}
	out.Measured = true
	out.Note = "an inventory signal, not findings: what " + inv.Source + " found of this repository's AI use"
	out.Source, out.RulepackSHA256, out.ImageDigest = inv.Source, inv.RulepackSHA256, inv.ImageDigest
	out.NodeCounts, out.EdgeCount = emptyMapIfNil(inv.NodeCounts), &inv.EdgeCount
	out.Frameworks, out.ModelProviders = emptyIfNil(inv.Frameworks), emptyIfNil(inv.ModelProviders)
	out.PostureObservations = inv.PostureObservations
	return out, nil
}

// consumersOf lists the repositories depending on a module this one owns.
func (s *Server) consumersOf(ctx context.Context, owner string) ([]Consumer, error) {
	deps, err := s.cfg.Store.AllDeps(ctx)
	if err != nil {
		return nil, err
	}
	// The modules this repository publishes, taken from the first-party
	// classification recorded on its own findings: the registry maps a module
	// to the repository that owns it, and the classification is where that
	// mapping has already been applied.
	owned := map[string]bool{}
	open, err := s.cfg.Store.ListFindings(ctx, store.Query{Scope: store.ScopeAll, Repo: owner})
	if err != nil {
		return nil, err
	}
	for _, f := range open {
		if f.Classification.FirstPartyPath != nil && f.Repo == owner && f.Location.Module != "" {
			owned[f.Location.Module] = true
		}
	}
	if len(owned) == 0 {
		return nil, nil
	}

	var out []Consumer
	for _, d := range deps {
		if !owned[d.Module] || d.Repo == owner {
			continue
		}
		c := Consumer{Repo: d.Repo, Version: d.Version, Replaced: d.Replaced,
			Reachable: string(model.ReachableUnknown)}
		if repo, err := s.cfg.Store.GetRepo(ctx, d.Repo); err == nil {
			c.Tier = repo.Tier
		}
		if d.Replaced {
			c.Excluded = true
			c.Reason = "a replace directive points this consumer at a local path, so a version " +
				"bump would not change what it builds (VM-F-608)"
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repo < out[j].Repo })
	return out, nil
}

func (s *Server) repoTrend(w http.ResponseWriter, r *http.Request, name string) {
	ctx := r.Context()
	window, err := intParam(r, "window", 20, 200)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "bad query", err.Error(), "correct the parameter")
		return
	}
	results, err := s.cfg.Store.ScanResults(ctx, name, window)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	series := TrendSeries{Metric: "observed_findings", Kind: string(store.KindSweep),
		Note: "counts are per run of ONE kind; a run that did not cover the repository is marked " +
			"partial, because a dip caused by a failed scan looks identical to one caused by a fix"}
	var lastImage string
	for i := len(results) - 1; i >= 0; i-- {
		res := results[i]
		run, err := s.cfg.Store.GetRun(ctx, res.RunID)
		if err != nil {
			continue
		}
		page, err := s.cfg.Store.Search(ctx, store.SearchQuery{
			Scope: store.ScopeRun, RunID: res.RunID,
			Filter: store.Filter{Repos: []string{name}}, Limit: 1,
		})
		if err != nil {
			s.failStore(w, r, err)
			return
		}
		pt := TrendPoint{
			RunID: res.RunID, At: run.StartedAt, Value: float64(page.Matched),
			Partial: !res.Outcome.Succeeded(), ScannerImage: run.ScannerImage,
		}
		if lastImage != "" && run.ScannerImage != lastImage {
			pt.ScannerChanged = true
		}
		lastImage = run.ScannerImage
		series.Points = append(series.Points, pt)
	}
	if series.Points == nil {
		series.Points = []TrendPoint{}
	}
	s.write(w, r, http.StatusOK, series)
}

// --- coverage ----------------------------------------------------------------

func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	names, err := s.cfg.Store.RepoNames(ctx)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	states, err := s.cfg.Store.FleetCoverage(ctx, store.KindSweep, names)
	if err != nil {
		s.failStore(w, r, err)
		return
	}

	out := CoverageView{
		InScope: len(names),
		Warning: "a failed scan and a clean scan are indistinguishable in every aggregate on the " +
			"run overview. Findings in a repository with a gap are not absent because they were " +
			"fixed; nobody looked. Read the gaps here before believing a drop in counts " +
			"(VM-UI-F-757, VM-ADR-12)",
		Staleness: store.Staleness(states, s.now()),
	}
	out.Escalations = emptyIfNil(store.Escalations(states, s.cfg.EscalationThreshold()))

	runID := r.URL.Query().Get("run")
	for _, st := range states {
		if st.SweepsSinceQualifying == 0 {
			out.Complete++
			continue
		}
		gap, err := s.gapFor(ctx, st, runID)
		if err != nil {
			s.failStore(w, r, err)
			return
		}
		out.Gaps = append(out.Gaps, gap)
	}
	if out.Gaps == nil {
		out.Gaps = []CoverageGap{}
	}
	if out.InScope > 0 {
		out.Percent = float64(out.Complete) / float64(out.InScope) * 100
	}
	out.RunID = runID

	hist, err := s.coverageHistory(ctx, names, 10)
	if err != nil {
		s.failStore(w, r, err)
		return
	}
	out.History = emptyIfNil(hist)
	s.write(w, r, http.StatusOK, out)
}

// EscalationThreshold is the consecutive-failure count that escalates.
func (c Config) EscalationThreshold() int { return 2 }

// gapFor builds the gap record for a repository with no qualifying scan.
func (s *Server) gapFor(ctx context.Context, st store.CoverageState, runID string) (CoverageGap, error) {
	gap := CoverageGap{
		Repo:                 st.Repo,
		ConsecutiveRuns:      st.SweepsSinceQualifying,
		ConsecutiveDeferrals: st.ConsecutiveDeferrals,
		LastQualifyingRun:    st.LastQualifyingRun,
		Cause:                st.LastCause,
	}
	if st.LastQualifyingAt != nil {
		at := *st.LastQualifyingAt
		gap.LastQualifyingAt = &at
		gap.HoursWithoutData = s.now().Sub(at).Hours()
	} else {
		// No age exists. Substituting zero would read as freshly scanned,
		// which is the opposite of the truth.
		gap.NeverScanned = true
	}

	results, err := s.cfg.Store.ScanResults(ctx, st.Repo, 10)
	if err != nil {
		return gap, err
	}
	for _, res := range results {
		if runID != "" && res.RunID != runID {
			continue
		}
		if res.Outcome.Succeeded() {
			continue
		}
		gap.RunID = res.RunID
		gap.Outcome = string(res.Outcome)
		gap.Cause = res.FailureCause
		gap.Detail = res.FailureDetail
		gap.Owner = res.FailureOwner
		gap.ToolsOK = emptyIfNil(res.ToolsOK)
		gap.ToolsFailed = emptyIfNil(res.ToolsFailed)
		gap.Classification = "total"
		if len(res.ToolsOK) > 0 {
			// Partial: some signals remain current, and saying which is what
			// makes it actionable (VM-F-211, VM-F-212).
			gap.Classification = "partial"
		}
		if run, err := s.cfg.Store.GetRun(ctx, res.RunID); err == nil {
			gap.RunAt = run.StartedAt
		}
		break
	}

	// The findings this gap leaves unaccounted for, with the query that lists
	// them (VM-UI-F-755).
	page, err := s.cfg.Store.Search(ctx, store.SearchQuery{
		Scope: store.ScopeOpen, Limit: 1,
		Filter: store.Filter{Repos: []string{st.Repo}, NotReobserved: boolPtr(true)},
	})
	if err != nil {
		return gap, err
	}
	gap.NotReobserved = page.Matched
	gap.FindingsQuery = fmt.Sprintf("scope=open&repo=%s&notReobserved=true", st.Repo)
	return gap, nil
}

func boolPtr(v bool) *bool { return &v }

// coverageHistory renders recent outcomes per repository, newest first.
func (s *Server) coverageHistory(ctx context.Context, repos []string, depth int) ([]RepoCoverageHistory, error) {
	var out []RepoCoverageHistory
	for _, name := range repos {
		results, err := s.cfg.Store.ScanResults(ctx, name, depth)
		if err != nil {
			return nil, err
		}
		h := RepoCoverageHistory{Repo: name}
		for _, res := range results {
			h.Outcomes = append(h.Outcomes, string(res.Outcome))
			h.Runs = append(h.Runs, res.RunID)
		}
		h.Outcomes, h.Runs = emptyIfNil(h.Outcomes), emptyIfNil(h.Runs)
		out = append(out, h)
	}
	return out, nil
}

var _ = context.Background
