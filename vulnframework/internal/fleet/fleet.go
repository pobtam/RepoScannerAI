package fleet

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/wanaware/vulnframework/internal/feed"
	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/remediate"
	"github.com/wanaware/vulnframework/internal/remediate/guard"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/tracker"
	"github.com/wanaware/vulnframework/internal/triage"
)

// Options parameterises the fleet simulation.
type Options struct {
	Calibration score.Calibration
	Policy      policy.Config

	// Now is the simulation's "today". Rounds are laid out BACKWARDS from it,
	// so the newest round is recent and the oldest is weeks old — which is
	// what makes a staleness distribution real rather than asserted.
	Now time.Time

	// Rounds is how many sweeps to simulate. Below about six the budget
	// rotation has not had time to visit the whole fleet twice, and a
	// starvation claim over fewer rounds than that is not worth much.
	Rounds int

	// Budget is the API rate budget per round, in credits, at one credit per
	// scan.
	//
	// The point of this whole package is that it is SMALLER THAN THE FLEET.
	// With a budget that covers twenty repositories nothing is ever deferred,
	// the planner never has to choose, and the ordering that prevents
	// starvation is never exercised.
	Budget int
}

// DefaultRounds and DefaultBudget are the simulation's defaults.
//
// Twelve credits against twenty repositories means eight are deferred every
// round, so the whole fleet cannot be covered in fewer than two rounds and the
// planner has to rotate. Ten rounds is five full cycles — enough that a
// repository losing the lottery repeatedly would show up as a rising maximum
// age rather than as noise.
const (
	DefaultRounds = 10
	DefaultBudget = 12
)

// Round is what one simulated sweep did.
//
// Recorded per round rather than only in aggregate, because the question the
// whole exercise asks — does any repository starve — is about the SEQUENCE.
// A final-state snapshot cannot answer it: a fleet where one repository was
// skipped nine times running and scanned on the tenth looks identical, at the
// end, to one that rotated fairly.
type Round struct {
	Index int       `json:"index"`
	RunID string    `json:"run_id"`
	At    time.Time `json:"at"`

	// Aborted marks the round where the orchestrator planned the fleet and the
	// process died before dispatching anything.
	Aborted bool `json:"aborted"`

	Planned    int `json:"planned"`
	Dispatched int `json:"dispatched"`

	// Outcomes counts each scan outcome recorded against the plan.
	Outcomes map[string]int `json:"outcomes"`
	// Causes counts the reason each non-qualifying outcome was recorded with.
	// This is the taxonomy that matters operationally: "deferred for budget",
	// "never picked up" and "worker died" are three different problems with
	// three different owners, and they are all `not_dispatched` or `no_result`
	// at the outcome level.
	Causes map[string]int `json:"causes"`

	// Scanned names the repositories that got a QUALIFYING scan this round.
	Scanned []string `json:"scanned"`
	// PlanOrder is the order the planner chose, most-stale first.
	PlanOrder []string `json:"plan_order"`

	Staleness store.StalenessReport `json:"staleness"`
}

// Result is the whole simulation.
type Result struct {
	Repos    int     `json:"repos"`
	Rounds   []Round `json:"rounds"`
	Budget   int     `json:"budget"`
	Findings int     `json:"findings"`
	Registry *firstparty.Registry
}

// Seed runs the simulation into a store.
//
// It drives the REAL orchestrator, store, triage, scoring, policy, ticket,
// wave and report code over fabricated input. Nothing about the pipeline is
// mocked; what is fabricated is what the scanners reported.
func Seed(ctx context.Context, s *store.Memory, opts Options) (Result, error) {
	if opts.Rounds <= 0 {
		opts.Rounds = DefaultRounds
	}
	if opts.Budget <= 0 {
		opts.Budget = DefaultBudget
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}

	registry, err := firstparty.ParseRegistry([]byte(RegistryYAML))
	if err != nil {
		return Result{}, fmt.Errorf("fleet: registry: %w", err)
	}

	repos := Repos()
	for _, r := range repos {
		if err := s.UpsertRepo(ctx, r); err != nil {
			return Result{}, fmt.Errorf("fleet: registering %s: %w", r.Name, err)
		}
	}

	out := Result{Repos: len(repos), Budget: opts.Budget, Registry: registry}
	remote := gh.NewFake("main")
	tracked := tracker.NewFake("github")
	feeds := buildFeeds(opts.Now)

	week := 7 * 24 * time.Hour
	for i := 0; i < opts.Rounds; i++ {
		at := opts.Now.Add(-time.Duration(opts.Rounds-1-i) * week)
		round, err := runRound(ctx, s, roundArgs{
			Index: i, Total: opts.Rounds, At: at, Repos: repos, Registry: registry,
			Opts: opts, Remote: remote, Tracker: tracked, Feeds: feeds,
		})
		if err != nil {
			return out, err
		}
		out.Rounds = append(out.Rounds, round)
	}

	all, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
	if err != nil {
		return out, err
	}
	out.Findings = len(all)
	return out, nil
}

func buildFeeds(now time.Time) feed.Multi {
	kev, epss := feed.NewFakeKEV(), feed.NewFakeEPSS()
	for _, id := range KEVEntries() {
		kev.WithKEV(id, now.Add(-30*time.Hour))
	}
	for _, id := range NotListedInKEV() {
		kev.WithNotKEV(id, now.Add(-30*time.Hour))
	}
	for id, v := range EPSSEntries() {
		epss.WithEPSS(id, v, now.Add(-20*time.Hour))
	}
	return feed.Multi{Sources: []feed.Source{kev, epss}}
}

type roundArgs struct {
	Index, Total int
	At           time.Time
	Repos        []store.Repo
	Registry     *firstparty.Registry
	Opts         Options
	Remote       *gh.Fake
	Tracker      *tracker.Fake
	Feeds        feed.Multi
}

// abortedRoundIndex is the round where the orchestrator died after planning.
//
// A real event, and the only way to produce the `never_dispatched` cause: a
// repository that was planned and then neither dispatched nor deliberately
// skipped means dispatch ITSELF failed, which is a different problem from a
// budget deferral and from a worker dying. It is placed in the middle of the
// simulation so the rounds after it have to recover the whole fleet at once.
const abortedRoundIndex = 5

func runRound(ctx context.Context, s *store.Memory, a roundArgs) (Round, error) {
	clock := func() time.Time { return a.At }
	s.SetClock(clock)

	if a.Index == abortedRoundIndex {
		return abortedRound(ctx, s, a)
	}

	d := orchestrator.NewFakeDispatcher()
	findings := findingsForRound(a.Index, a.Total)
	manifests := Manifests()
	for _, repo := range a.Repos {
		d.WithFindings(repo.Name, toolsFor(repo), findings[repo.Name]...)
		if deps, ok := manifests[repo.Name]; ok {
			d.WithDeps(repo.Name, deps)
		}
	}
	injectGaps(d, a.Index, a.Total)

	o := orchestrator.New(s, d, orchestrator.NewRateBudget(a.Opts.Budget), orchestrator.Config{
		ScannerImage:   scannerImageFor(a.Index, a.Total),
		CreditsPerScan: 1,
		// Four at a time, so the dispatch order the planner chose is the order
		// that matters rather than being washed out by unbounded concurrency.
		MaxConcurrentScans: 4,
		// Three consecutive rounds without a qualifying scan escalates,
		// whatever the cause (VM-F-215). With a budget covering 12 of 20 this
		// should never fire from deferral alone — if it does, the ordering is
		// not rotating.
		EscalationThreshold: 3,
		ToolVersions: map[string]string{
			"govulncheck": "v1.8.0", "gosec": "v2.22.9",
			"gitleaks": "v8.28.0", "trivy": "v0.58.1", "osv-scanner": "v2.6.0",
		},
		PR:         a.Remote,
		FirstParty: a.Registry,
	})
	o.Clock = clock

	stats, err := o.Sweep(ctx, store.KindSweep, "cron", a.Repos, nil)
	if err != nil {
		return Round{}, fmt.Errorf("fleet: sweep %d: %w", a.Index+1, err)
	}

	if err := pipeline(ctx, s, a, o, stats, clock); err != nil {
		return Round{}, err
	}

	return recordRound(ctx, s, a, stats)
}

// abortedRound plans the fleet and closes the run without dispatching.
//
// This is what an orchestrator that died between planning and dispatch leaves
// behind, and it is the only shape that produces `never_dispatched`: the plan
// exists, the entries were never acted on, and coverage is measured against
// the plan rather than against what happened to report (OQ-P2-02).
func abortedRound(ctx context.Context, s *store.Memory, a roundArgs) (Round, error) {
	run, err := s.CreateRun(ctx, store.KindSweep, "cron", scannerImageFor(a.Index, a.Total), nil)
	if err != nil {
		return Round{}, fmt.Errorf("fleet: aborted round: creating the run: %w", err)
	}

	entries := make([]store.PlanEntry, 0, len(a.Repos))
	for _, r := range a.Repos {
		entries = append(entries, store.PlanEntry{
			RunID: run.ID, Repo: r.Name, State: store.DispatchPlanned, PlannedAt: a.At,
		})
	}
	if err := s.RecordPlan(ctx, entries); err != nil {
		return Round{}, fmt.Errorf("fleet: aborted round: recording the plan: %w", err)
	}
	if _, err := s.CloseRun(ctx, run.ID); err != nil {
		return Round{}, fmt.Errorf("fleet: aborted round: closing the run: %w", err)
	}

	round, err := recordRound(ctx, s, a, orchestrator.RunStats{
		RunID: run.ID, Planned: len(a.Repos),
	})
	if err != nil {
		return Round{}, err
	}
	round.Aborted = true
	return round, nil
}

// pipeline is everything that follows a sweep.
func pipeline(ctx context.Context, s *store.Memory, a roundArgs,
	o *orchestrator.Orchestrator, stats orchestrator.RunStats, clock func() time.Time) error {

	engine := policy.New(a.Opts.Policy)
	scorer := score.New(a.Opts.Calibration)
	tr := &triage.Triager{
		Client: triage.NewFakeClient(), Cache: triage.NewMemoryCache(),
		Model: "claude-sonnet-5", Clock: clock,
	}
	svc := &tracker.Service{Tracker: a.Tracker, Store: s, Clock: clock}

	for _, repo := range a.Repos {
		if _, err := o.EnrichPass(ctx, a.Feeds, repo.Name); err != nil {
			return fmt.Errorf("fleet: enrich %s: %w", repo.Name, err)
		}
		if _, err := o.TriageAndRoute(ctx, repo, tr, scorer, engine, fleetView{}); err != nil {
			return fmt.Errorf("fleet: triage %s: %w", repo.Name, err)
		}
		if _, err := o.TicketPass(ctx, orchestrator.TicketRequest{
			Repo: repo, RunID: stats.RunID, Service: svc, Policy: engine, View: fleetView{},
			ReportURL: "https://fleet.example/reports/" + stats.RunID + "/fleet.md",
		}); err != nil {
			return fmt.Errorf("fleet: tickets %s: %w", repo.Name, err)
		}
	}

	if err := blockConsumers(ctx, s, clock); err != nil {
		return err
	}
	if err := remediateFleet(ctx, s, a, o, engine, clock); err != nil {
		return err
	}
	if err := settlePullRequests(ctx, s, a, o, clock); err != nil {
		return err
	}
	return issueReport(ctx, s, a, stats, clock)
}

// recordRound reads back what the round did, THROUGH THE STORE.
//
// Through the store rather than from the orchestrator's return value, and that
// is deliberate: the report this feeds is a claim about what the system
// recorded, and reading it from the same place the interface reads it is what
// stops the report and the screens disagreeing.
func recordRound(ctx context.Context, s *store.Memory, a roundArgs, stats orchestrator.RunStats) (Round, error) {
	round := Round{
		Index: a.Index, RunID: stats.RunID, At: a.At,
		Planned: stats.Planned, Dispatched: stats.Dispatched,
		Outcomes: map[string]int{}, Causes: map[string]int{},
		PlanOrder: stats.PlanOrder,
	}

	for _, repo := range a.Repos {
		results, err := s.ScanResults(ctx, repo.Name, 50)
		if err != nil {
			return Round{}, fmt.Errorf("fleet: reading the outcomes for %s: %w", repo.Name, err)
		}
		var res store.RepoScanResult
		var found bool
		for _, r := range results {
			if r.RunID == stats.RunID {
				res, found = r, true
				break
			}
		}
		if !found {
			// A repository in scope with no recorded outcome at all would be
			// a hole in OQ-P2-02's guarantee: coverage is measured against
			// the PLAN, so every planned repository leaves a row whatever
			// happened to it. Refusing rather than counting it as clean.
			return Round{}, fmt.Errorf(
				"fleet: %s was in scope for run %s and has no recorded scan outcome; "+
					"coverage is measured against the plan, so this is a gap in the plan "+
					"record rather than a clean scan (OQ-P2-02)", repo.Name, stats.RunID)
		}

		round.Outcomes[string(res.Outcome)]++
		if res.Outcome.Succeeded() {
			round.Scanned = append(round.Scanned, repo.Name)
			continue
		}
		cause := res.FailureCause
		if cause == "" {
			cause = "(none recorded)"
		}
		round.Causes[cause]++
	}
	sort.Strings(round.Scanned)

	names := make([]string, 0, len(a.Repos))
	for _, r := range a.Repos {
		names = append(names, r.Name)
	}
	states, err := s.FleetCoverage(ctx, store.KindSweep, names)
	if err != nil {
		return Round{}, err
	}
	round.Staleness = store.Staleness(states, a.At)
	return round, nil
}

// --- the fabricated scanner output, round by round --------------------------

// findingsForRound is what the scanners reported in round i.
//
// The variation is the point: a finding that appears later, one that
// disappears from a COMPLETE scan and therefore verifies, and one that comes
// back afterwards and therefore regresses.
func findingsForRound(i, total int) map[string][]model.RawFinding {
	out := map[string][]model.RawFinding{}
	for repo, rs := range Baseline() {
		copied := make([]model.RawFinding, len(rs))
		copy(copied, rs)
		out[repo] = copied
	}

	// The late advisory, from the second-to-last round: two rounds, so every
	// repository carrying it is scanned at least once while it is present,
	// whatever order the planner chose.
	if i >= total-2 {
		for _, repo := range LateAdvisoryRepos {
			out[repo] = append(out[repo], LateAdvisoryFinding(repo))
		}
	}

	if i < total-4 {
		// Early rounds: two findings are not there yet, so later rounds can
		// show them as NEW rather than as having always been present.
		out[Org+"/internal-tools"] = dropByID(out[Org+"/internal-tools"], "G204")
		out[Org+"/merchant-portal"] = dropByID(out[Org+"/merchant-portal"], "slack-webhook")
	}

	// Findings that a merged pull request actually closed.
	//
	// Without these the fleet can reach MERGED and never VERIFIED, because
	// VERIFIED requires a later QUALIFYING scan to no longer observe the
	// finding — a merged pull request is not evidence (VM-F-533, VM-ADR-12).
	// A simulation that stopped at MERGED would leave the one transition the
	// whole verification design exists for untested.
	if i >= total-3 {
		out[Org+"/internal-tools"] = dropByID(out[Org+"/internal-tools"], AdvYAML.Tool)
		out[Org+"/data-pipeline"] = dropByID(out[Org+"/data-pipeline"], AdvCSV.Tool)
	}

	switch {
	case i == total-3, i == total-2:
		// Fixed out of band: it disappears from a complete scan and verifies,
		// attributed as external rather than as this framework's merge.
		out[Org+"/api-edge"] = dropByID(out[Org+"/api-edge"], "FLEET-K8S-001")
	case i == total-1:
		// It is BACK: a regression, which is a different failure from a new
		// finding and must render differently.
		out[Org+"/api-edge"] = dropByID(out[Org+"/api-edge"], "G402")
	}
	return out
}

func dropByID(rs []model.RawFinding, id string) []model.RawFinding {
	out := make([]model.RawFinding, 0, len(rs))
	for _, r := range rs {
		if r.PrimaryID == id {
			continue
		}
		out = append(out, r)
	}
	return out
}

// injectGaps makes specific rounds fail in specific, different ways.
//
// Each cause is produced at least twice across the simulation. Once is an
// anecdote: a gap taxonomy with one example of each kind proves the constant
// exists, not that the arithmetic holds when several occur together.
func injectGaps(d *orchestrator.FakeDispatcher, i, total int) {
	in := func(rounds ...int) bool {
		for _, r := range rounds {
			if i == r {
				return true
			}
		}
		return false
	}

	// Each fault is a condition lasting two consecutive dispatchable rounds,
	// not an event in one. Under a fair rotation no repository is deferred
	// twice running — whoever is deferred is the stalest next round — so each
	// fault occurs whatever order the planner chose. Pinned to one round, a
	// fault only fired if that repository happened to be scheduled then, and
	// the taxonomy test passed or failed on the planner's order rather than on
	// the behaviour it claims to test.

	if in(2, 3) {
		// A worker that starts and never reports, and a repository whose clone
		// fails: both `no_result`, dispatched and lost.
		d.WithSilentWorker(Org + "/legacy-billing")
		d.WithDispatchError(Org+"/docs-site",
			fmt.Errorf("clone failed: repository archived or access revoked"))
	}
	if in(3, 4) {
		// A scan that lost two of its three tools: partial, which does NOT
		// refresh coverage and does NOT verify anything.
		d.WithOutcome(Org+"/search-indexer", model.ScanPartial,
			[]string{"gitleaks"}, []string{"govulncheck", "gosec"})
		d.WithGaps(Org+"/search-indexer", scan.CoverageGap{
			Tool: "govulncheck", Classification: scan.GapPartial, Cause: "execution_failed",
			Detail: "exec: govulncheck: signal: killed (container exceeded its memory limit)",
			Owner:  scan.OwnerPlatform,
		})
	}
	if i >= 4 && i <= 7 {
		// go.mod truncated in round 4, repaired before round 8.
		d.WithOutcome(Org+"/batch-exports", model.ScanFailed, nil,
			[]string{"govulncheck", "gosec", "gitleaks", "trivy"})
		d.WithGaps(Org+"/batch-exports", scan.CoverageGap{
			Tool: "manifest", Classification: scan.GapTotal, Cause: "manifest_unreadable",
			Detail: "go.mod: unexpected EOF — the repository does not build",
			Owner:  scan.OwnerRepo,
		})
	}
	if in(6, 7) {
		d.WithSilentWorker(Org + "/sandbox-playground")
	}
	if in(7, 8) {
		d.WithOutcome(Org+"/merchant-portal", model.ScanPartial,
			[]string{"gitleaks", "trivy"}, []string{"osv-scanner"})
		d.WithGaps(Org+"/merchant-portal", scan.CoverageGap{
			Tool: "osv-scanner", Classification: scan.GapPartial, Cause: "execution_failed",
			Detail: "osv-scanner: lockfile not found; dependency coverage is incomplete",
			Owner:  scan.OwnerRepo,
		})
	}
	if i >= 8 {
		// An old toolchain directive, from round 8 to the end: never fixed
		// within the simulation.
		d.WithOutcome(Org+"/legacy-billing", model.ScanFailed, nil,
			[]string{"govulncheck", "gosec", "gitleaks", "trivy"})
		d.WithGaps(Org+"/legacy-billing", scan.CoverageGap{
			Tool: "govulncheck", Classification: scan.GapTotal, Cause: "toolchain_unsupported",
			Detail: "go.mod declares go 1.13; the pinned toolchain requires 1.21",
			Owner:  scan.OwnerRepo,
		})
		d.WithDispatchError(Org+"/docs-site",
			fmt.Errorf("worker pod evicted before it reported"))
	}
}

func toolsFor(r store.Repo) []string {
	tools := []string{"govulncheck", "gosec", "gitleaks", "trivy"}
	for _, l := range r.Languages {
		if l == "javascript" {
			return append(tools, "osv-scanner")
		}
	}
	return tools
}

// scannerImageFor changes the image partway through, so a step change in
// counts is attributable to the scanner rather than to the fleet
// (VM-UI-F-306).
func scannerImageFor(i, total int) string {
	if i >= total-3 {
		return "fleet-scanner@sha256:9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d"
	}
	return "fleet-scanner@sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"
}

// fleetView answers the policy engine's questions about surrounding state.
type fleetView struct{}

func (fleetView) HasOpenPullRequest(string) bool        { return false }
func (fleetView) IsFirstPartyOwner(string, string) bool { return false }

// --- the waves ---------------------------------------------------------------

// blockConsumers puts each wave's consumers into BLOCKED_UPSTREAM, pointing at
// the owner's finding.
//
// Two waves, driven by the same code. A consumer of BOTH shared modules is
// blocked on whichever upstream finding corresponds to the advisory it is
// carrying — which is the case that catches an implementation treating
// "blocked" as a flag on the repository rather than a relationship between two
// findings.
func blockConsumers(ctx context.Context, s *store.Memory, clock func() time.Time) error {
	waves := []struct {
		owner     string
		advisory  string
		consumers []string
	}{
		{OwnerCoreAuth, AdvCrypto.ID(), CoreAuthConsumers},
		{OwnerTelemetrySDK, AdvProto.ID(), TelemetryConsumers},
	}

	for _, w := range waves {
		upstream, err := findingID(ctx, s, w.owner, w.advisory)
		if err != nil {
			return err
		}
		if upstream == "" {
			continue
		}
		for _, consumer := range w.consumers {
			open, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeOpen, Repo: consumer})
			if err != nil {
				return err
			}
			for _, f := range open {
				if f.Identity.PrimaryID != w.advisory || f.State != model.Triaged {
					continue
				}
				if err := s.SetUpstreamFinding(ctx, f.Fingerprint, upstream); err != nil {
					return err
				}
				reason := model.ReasonBlockedUpstreamFirstParty
				if err := s.SetPriority(ctx, f.Fingerprint, f.Priority, &reason); err != nil {
					return err
				}
				if err := s.ApplyTransition(ctx, f.Fingerprint, model.BlockedUpstream,
					model.TransitionContext{
						Actor: model.ActorOrchestrator,
						Cause: "waiting on the upstream first-party fix in " + w.owner,
						At:    clock(),
					}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func findingID(ctx context.Context, s *store.Memory, repo, advisory string) (string, error) {
	open, err := s.ListFindings(ctx, store.Query{
		Scope: store.ScopeOpen, Repo: repo,
		Categories: []model.Category{model.CategoryDependency},
	})
	if err != nil {
		return "", err
	}
	for _, f := range open {
		if f.Identity.PrimaryID == advisory {
			return f.Fingerprint, nil
		}
	}
	return "", nil
}

// --- remediation and settlement ---------------------------------------------

func remediateFleet(ctx context.Context, s *store.Memory, a roundArgs,
	o *orchestrator.Orchestrator, engine *policy.Engine, clock func() time.Time) error {

	g, err := guard.New(guard.Config{DenyPaths: []string{
		".github/workflows/**", ".github/actions/**", "CODEOWNERS", "**/*.tf", "**/*.tfvars",
	}})
	if err != nil {
		return err
	}

	tc := remediate.NewFakeToolchain()
	for _, m := range []struct{ module, current, fixed, advisory string }{
		{"example.com/crypto-lib", "v0.31.0", "v0.32.0", AdvCrypto.ID()},
		{"example.com/proto-runtime", "v1.33.0", "v1.34.1", AdvProto.ID()},
		{"example.com/json-stream", "v2.1.0", "v2.2.0", AdvJSON.ID()},
		{"example.com/csv-reader", "v0.9.0", "v0.9.3", AdvCSV.ID()},
		{"example.com/yaml-parse", "v3.0.1", "v3.0.4", AdvYAML.ID()},
		{"example.com/http-router", "v1.12.4", "v1.12.9", AdvRouter.ID()},
		{"example.com/xml-codec", "v1.2.0", "v1.2.5", AdvLate.ID()},
	} {
		tc.WithModule(m.module, m.current).WithAdvisory(m.advisory, m.module, m.fixed)
	}

	for _, repo := range a.Repos {
		if !repo.HasTestSuite {
			// No verification gate is possible here. The framework does not
			// attempt a fix it cannot prove, and the interface says why.
			continue
		}
		worker := &remediate.Worker{
			Store: s, PR: a.Remote, Guard: g, Toolchain: tc,
			Owner: "fleet-fixworker", LeaseTTL: 30 * time.Minute, Clock: clock,
		}
		if _, err := o.RemediationPass(ctx, orchestrator.RemediationRequest{
			Repo: repo, Worker: worker, Policy: engine, View: fleetView{},
			Groups: remediate.GroupConfig{MaxPerPR: 3, MaxPerPRCode: 1},
			// Bounded, so the fleet has work still queued rather than nothing
			// outstanding — which is what a real fleet looks like.
			MaxGroups: 2,
		}); err != nil {
			return fmt.Errorf("fleet: remediating %s: %w", repo.Name, err)
		}
	}
	return nil
}

// settlePullRequests merges some of last round's pull requests through the
// webhook path, so the fleet shows the full lifecycle: PR_OPEN → MERGED →
// VERIFIED, and one REGRESSED.
func settlePullRequests(ctx context.Context, s *store.Memory, a roundArgs,
	o *orchestrator.Orchestrator, clock func() time.Time) error {

	if a.Index == 0 {
		return nil
	}
	if a.Index == a.Total-1 {
		// The last round's pull requests are left OPEN, so the fleet ends with
		// work in review. A simulation where everything settles by the final
		// round shows no PR_OPEN at all — and that is the state a reviewer
		// actually spends their time in.
		return nil
	}
	for _, repo := range a.Repos {
		prs, err := s.OpenRemediationPRs(ctx, repo.Name)
		if err != nil {
			return err
		}
		for i, pr := range prs {
			// Only LAST round's: a pull request opened in this round's
			// remediation pass has not been reviewed yet. Merging it in the
			// same round meant nothing was ever in review.
			if !pr.OpenedAt.Before(a.At) {
				continue
			}
			// Every other one, so the fleet has pull requests in review as
			// well as merged. A fleet where everything settles immediately
			// does not exercise the states a reviewer actually sees.
			if i%2 == 1 {
				continue
			}
			a.Remote.MergePR(repo.Name, pr.Number)
			// Through the WEBHOOK path, which is the primary one: a merge
			// discovered by reconciliation is the fallback, and seeding
			// through the fallback would leave the primary path unexercised
			// across the whole simulation.
			if _, err := o.ApplyWebhook(ctx, gh.Event{
				Kind: gh.EventPullRequestClosed, Repo: repo.Name, Number: pr.Number,
				Branch: pr.Branch, Merged: true,
				DeliveryID: fmt.Sprintf("fleet-%d-%s-%d", a.Index, repo.Name, pr.Number),
			}); err != nil {
				return fmt.Errorf("fleet: applying the merge webhook for %s: %w", repo.Name, err)
			}
		}
	}
	return nil
}

func issueReport(ctx context.Context, s *store.Memory, a roundArgs,
	stats orchestrator.RunStats, clock func() time.Time) error {

	gen := report.NewGenerator(s, a.Opts.Calibration)
	gen.Clock = clock
	gen.UnavailableScoringInputs = nil
	rep, err := gen.Generate(ctx, report.Query{
		Kind: report.KindFleet, AnchorRun: stats.RunID,
		Scope: store.ScopeAll, Template: "fleet.v1",
	})
	if err != nil {
		return fmt.Errorf("fleet: generating the report for %s: %w", stats.RunID, err)
	}
	issued, err := report.Issue(rep)
	if err != nil {
		return fmt.Errorf("fleet: issuing the report for %s: %w", stats.RunID, err)
	}
	if _, err := report.Record(ctx, s, issued, "orchestrator"); err != nil {
		return fmt.Errorf("fleet: recording the report for %s: %w", stats.RunID, err)
	}
	return nil
}
