// Package demo seeds a store by running the REAL pipeline over fabricated
// scanner output (see DEMO_DATA.go).
//
// Nothing here constructs a finding, a priority, a state or a count. The demo
// feeds invented scanner output into the same orchestrator, store, triage,
// scoring, policy, ticket, remediation and report code a real deployment runs,
// which means two things:
//
//	the demonstration cannot show a field the pipeline cannot produce — the
//	defect class this build spent twelve phases learning to detect; and
//
//	running the demo is itself a test that the pipeline works end to end with
//	no credentials, no network, no Docker and no scanners installed.
package demo

import (
	"context"
	"fmt"
	"strings"
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

// Result is what the seeding produced, for the caller to print.
type Result struct {
	Runs     []string
	Findings int
	Repos    int
	Reports  int
	PRs      int
	Gaps     int
	Waves    int
	Registry *firstparty.Registry
}

// Options parameterises the seeding.
type Options struct {
	Calibration score.Calibration
	Policy      policy.Config
	// Now is the demonstration's "today". The runs are laid out BACKWARDS from
	// it, so the newest run is recent and the oldest is weeks old — which is
	// what makes an SLA breach, a trend and a coverage streak real rather
	// than asserted.
	Now time.Time
	// Runs is how many sweeps to simulate.
	Runs int
}

// Seed populates a store. The store must be migrated.
func Seed(ctx context.Context, s *store.Memory, opts Options) (Result, error) {
	if opts.Runs <= 0 {
		opts.Runs = 6
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	registry, err := firstparty.ParseRegistry([]byte(RegistryYAML))
	if err != nil {
		return Result{}, fmt.Errorf("demo: registry: %w", err)
	}

	repos := Repos()
	for _, r := range repos {
		if err := s.UpsertRepo(ctx, r); err != nil {
			return Result{}, fmt.Errorf("demo: registering %s: %w", r.Name, err)
		}
	}

	if err := seedGitHub(ctx, s, repos, opts.Now); err != nil {
		return Result{}, err
	}

	out := Result{Repos: len(repos), Registry: registry}
	remote := gh.NewFake("main")
	tracked := tracker.NewFake("github")

	// The exploitation feeds, as fakes. Several advisories are in neither
	// catalogue, which is what lets the interface show an absent input as an
	// absence rather than as a zero.
	kev, epss := feed.NewFakeKEV(), feed.NewFakeEPSS()
	for _, id := range KEVEntries() {
		kev.WithKEV(id, opts.Now.Add(-30*time.Hour))
	}
	for _, id := range NotListedInKEV() {
		kev.WithNotKEV(id, opts.Now.Add(-30*time.Hour))
	}
	for id, v := range EPSSEntries() {
		epss.WithEPSS(id, v, opts.Now.Add(-20*time.Hour))
	}
	feeds := feed.Multi{Sources: []feed.Source{kev, epss}}

	// One sweep a week, oldest first.
	week := 7 * 24 * time.Hour
	for i := 0; i < opts.Runs; i++ {
		at := opts.Now.Add(-time.Duration(opts.Runs-1-i) * week)
		runID, err := seedRun(ctx, s, seedRunArgs{
			Index: i, Total: opts.Runs, At: at, Repos: repos, Registry: registry,
			Opts: opts, Remote: remote, Tracker: tracked, Feeds: feeds,
		})
		if err != nil {
			return out, err
		}
		out.Runs = append(out.Runs, runID)
	}

	// The tallies, read back through the store so the printed summary cannot
	// disagree with what the interface will show.
	all, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeAll})
	if err != nil {
		return out, err
	}
	out.Findings = len(all)
	for _, r := range repos {
		prs, err := s.OpenRemediationPRs(ctx, r.Name)
		if err != nil {
			return out, err
		}
		out.PRs += len(prs)
	}
	names, err := s.RepoNames(ctx)
	if err != nil {
		return out, err
	}
	states, err := s.FleetCoverage(ctx, store.KindSweep, names)
	if err != nil {
		return out, err
	}
	for _, st := range states {
		if st.SweepsSinceQualifying > 0 {
			out.Gaps++
		}
	}
	for _, runID := range out.Runs {
		reports, err := s.ReportsForRun(ctx, runID)
		if err != nil {
			return out, err
		}
		out.Reports += len(reports)
	}
	for _, f := range all {
		if f.State == model.BlockedUpstream {
			out.Waves++
		}
	}
	return out, nil
}

type seedRunArgs struct {
	Index, Total int
	At           time.Time
	Repos        []store.Repo
	Registry     *firstparty.Registry
	Opts         Options
	Remote       *gh.Fake
	Tracker      *tracker.Fake
	Feeds        feed.Multi
}

// seedRun performs one sweep and everything that follows it.
func seedRun(ctx context.Context, s *store.Memory, a seedRunArgs) (string, error) {
	clock := func() time.Time { return a.At }
	s.SetClock(clock)

	d := orchestrator.NewFakeDispatcher()
	findings := findingsForRun(a.Index, a.Total)
	manifests := Manifests()
	for _, repo := range a.Repos {
		if rs, ok := findings[repo.Name]; ok {
			d.WithFindings(repo.Name, toolsFor(repo), rs...)
			if deps, ok := manifests[repo.Name]; ok {
				d.WithDeps(repo.Name, deps)
			}
		}
	}

	// The coverage gaps, which are as much a part of the demonstration as the
	// findings: a repository nobody scanned is more urgent than one with
	// findings, and the interface must not bury it.
	switch {
	case a.Index == a.Total-1:
		// This week: the legacy repository's worker started and never
		// reported, and the checkout scan lost two of its three tools.
		d.WithSilentWorker("demo-org/legacy-reporting")
		d.WithOutcome("demo-org/checkout-web", model.ScanPartial,
			[]string{"gitleaks"}, []string{"govulncheck", "gosec"})
		d.WithGaps("demo-org/checkout-web", scan.CoverageGap{
			Tool: "govulncheck", Classification: scan.GapPartial, Cause: "execution_failed",
			Detail: "exec: govulncheck: signal: killed (container exceeded its memory limit)",
			Owner:  scan.OwnerPlatform,
		})
	case a.Index == a.Total-2:
		// Last week: the same repository failed to clone.
		d.WithDispatchError("demo-org/legacy-reporting",
			fmt.Errorf("clone failed: repository archived or access revoked"))
	}

	budget := orchestrator.NewRateBudget(500)
	if a.Index == a.Total-3 {
		// Three weeks ago the run ran out of API budget, so two repositories
		// were deferred rather than scanned — a different problem from a
		// failure, and one that must not read as a clean scan.
		budget = orchestrator.NewRateBudget(4)
	}

	o := orchestrator.New(s, d, budget, orchestrator.Config{
		ScannerImage:   scannerImageFor(a.Index, a.Total),
		CreditsPerScan: 1,
		ToolVersions: map[string]string{
			"govulncheck": "v1.8.0", "gosec": "v2.22.9", "gitleaks": "v8.28.0", "trivy": "v0.58.1",
		},
		PR:         a.Remote,
		FirstParty: a.Registry,
	})
	o.Clock = clock

	stats, err := o.Sweep(ctx, store.KindSweep, "cron", a.Repos, nil)
	if err != nil {
		return "", fmt.Errorf("demo: sweep %d: %w", a.Index+1, err)
	}

	engine := policy.New(a.Opts.Policy)
	scorer := score.New(a.Opts.Calibration)
	tr := &triage.Triager{
		Client: triage.NewFakeClient(), Cache: triage.NewMemoryCache(),
		Model: "claude-sonnet-5", Clock: clock,
	}
	svc := &tracker.Service{Tracker: a.Tracker, Store: s, Clock: clock}

	for _, repo := range a.Repos {
		if _, err := o.EnrichPass(ctx, a.Feeds, repo.Name); err != nil {
			return "", fmt.Errorf("demo: enrich %s: %w", repo.Name, err)
		}
		if _, err := o.TriageAndRoute(ctx, repo, tr, scorer, engine, demoView{}); err != nil {
			return "", fmt.Errorf("demo: triage %s: %w", repo.Name, err)
		}
		if _, err := o.TicketPass(ctx, orchestrator.TicketRequest{
			Repo: repo, RunID: stats.RunID, Service: svc, Policy: engine, View: demoView{},
			ReportURL: "https://demo.example/reports/" + stats.RunID + "/fleet.md",
		}); err != nil {
			return "", fmt.Errorf("demo: tickets %s: %w", repo.Name, err)
		}
	}

	// The first-party wave: the consumers of the shared module wait on the
	// owner's finding rather than each opening their own pull request.
	if err := blockConsumers(ctx, s, a, clock); err != nil {
		return "", err
	}

	// Remediation, for the repositories that can be verified. A repository
	// with no test suite is deliberately left out: there is no signal to
	// verify a fix against, so the framework does not attempt one.
	if err := remediateRepos(ctx, s, a, o, engine, clock); err != nil {
		return "", err
	}

	// A merge, so the demonstration has a finding pending verification and,
	// next week, a verified one — and one regression.
	if err := settleLastWeeksPullRequests(ctx, s, a, o, clock); err != nil {
		return "", err
	}

	// The report: issued, hashed and recorded, so the run has an immutable
	// snapshot and the interface can show history as history.
	gen := report.NewGenerator(s, a.Opts.Calibration)
	gen.Clock = clock
	gen.UnavailableScoringInputs = nil
	rep, err := gen.Generate(ctx, report.Query{
		Kind: report.KindFleet, AnchorRun: stats.RunID,
		Scope: store.ScopeAll, Template: "fleet.v1",
	})
	if err != nil {
		return "", fmt.Errorf("demo: generating the report for %s: %w", stats.RunID, err)
	}
	issued, err := report.Issue(rep)
	if err != nil {
		return "", fmt.Errorf("demo: issuing the report for %s: %w", stats.RunID, err)
	}
	if _, err := report.Record(ctx, s, issued, "orchestrator"); err != nil {
		return "", fmt.Errorf("demo: recording the report for %s: %w", stats.RunID, err)
	}
	return stats.RunID, nil
}

// findingsForRun is what the scanners reported in run i.
//
// The variation is the point: a finding that appears, one that disappears from
// a COMPLETE scan (and therefore verifies), one that comes back afterwards
// (and therefore regresses), and one that disappears from a FAILED scan (which
// verifies nothing at all).
func findingsForRun(i, total int) map[string][]model.RawFinding {
	out := map[string][]model.RawFinding{}
	for repo, rs := range Baseline() {
		copied := make([]model.RawFinding, len(rs))
		copy(copied, rs)
		out[repo] = copied
	}

	switch {
	case i < total-4:
		// The oldest runs: the G404 code finding is not there yet, so it
		// appears later and the run overview can show a NEW finding.
		out["demo-org/payments-api"] = dropByID(out["demo-org/payments-api"], "G404")
		out["demo-org/edge-proxy"] = dropByID(out["demo-org/edge-proxy"], "generic-api-key")
	case i == total-3:
		// The config finding is fixed out of band: it disappears from a
		// complete scan and verifies, attributed as external rather than as
		// this framework's merge.
		out["demo-org/payments-api"] = dropByID(out["demo-org/payments-api"], "DEMO-K8S-001")
	case i == total-2:
		out["demo-org/payments-api"] = dropByID(out["demo-org/payments-api"], "DEMO-K8S-001")
	case i == total-1:
		// This week the config finding is BACK: a regression, which is a
		// different failure from a new finding and must render differently.
		// The G401 code finding disappears because the pull request merged.
		out["demo-org/payments-api"] = dropByID(out["demo-org/payments-api"], "G401")
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

func toolsFor(r store.Repo) []string {
	tools := []string{"govulncheck", "gosec", "gitleaks", "trivy"}
	for _, l := range r.Languages {
		if l == "javascript" {
			return append(tools, "osv-scanner")
		}
	}
	return tools
}

// scannerImageFor changes the image partway through, so the trend can mark it:
// a step change in counts is uninterpretable without knowing whether the
// scanner changed (VM-UI-F-306).
func scannerImageFor(i, total int) string {
	if i >= total-2 {
		return "demo-scanner@sha256:2f8c1b9e4a7d6c5b3e2a1f0d9c8b7a6e5d4c3b2a1908f7e6d5c4b3a291807f6e"
	}
	return "demo-scanner@sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"
}

// blockConsumers puts the wave's consumers into BLOCKED_UPSTREAM, pointing at
// the owner's finding.
func blockConsumers(ctx context.Context, s *store.Memory, a seedRunArgs, clock func() time.Time) error {
	owner, err := s.ListFindings(ctx, store.Query{
		Scope: store.ScopeOpen, Repo: "demo-org/platform-common",
		Categories: []model.Category{model.CategoryDependency},
	})
	if err != nil {
		return err
	}
	var upstream string
	for _, f := range owner {
		if f.Identity.PrimaryID == "DEMO-2026-0003" {
			upstream = f.Fingerprint
		}
	}
	if upstream == "" {
		return nil
	}

	for _, repo := range []string{"demo-org/checkout-web", "demo-org/batch-jobs", "demo-org/edge-proxy"} {
		open, err := s.ListFindings(ctx, store.Query{Scope: store.ScopeOpen, Repo: repo})
		if err != nil {
			return err
		}
		for _, f := range open {
			if f.Identity.PrimaryID != "DEMO-2026-0003" || f.State != model.Triaged {
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
					Cause: "waiting on the upstream first-party fix in demo-org/platform-common",
					At:    clock(),
				}); err != nil {
				return err
			}
		}
	}
	return nil
}

// remediateRepos dispatches remediation where a fix can be verified.
func remediateRepos(ctx context.Context, s *store.Memory, a seedRunArgs,
	o *orchestrator.Orchestrator, engine *policy.Engine, clock func() time.Time) error {

	g, err := guard.New(guard.Config{DenyPaths: []string{
		".github/workflows/**", ".github/actions/**", "CODEOWNERS", "**/*.tf", "**/*.tfvars",
	}})
	if err != nil {
		return err
	}
	tc := remediate.NewFakeToolchain()
	for _, m := range []struct{ module, current, fixed, advisory string }{
		{"example.com/http-router", "v1.12.4", "v1.12.9", "DEMO-2026-0001"},
		{"example.com/yaml-parse", "v3.0.1", "v3.0.4", "DEMO-2026-0002"},
		{"example.com/crypto-lib", "v0.31.0", "v0.32.0", "DEMO-2026-0003"},
		{"example.com/proto-runtime", "v1.33.0", "v1.34.1", "DEMO-2026-0004"},
		{"example.com/log-shim", "v0.4.2", "v0.4.3", "DEMO-2026-0007"},
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
			Owner: "demo-fixworker", LeaseTTL: 30 * time.Minute, Clock: clock,
		}
		if _, err := o.RemediationPass(ctx, orchestrator.RemediationRequest{
			Repo: repo, Worker: worker, Policy: engine, View: demoView{},
			Groups: remediate.GroupConfig{MaxPerPR: 3, MaxPerPRCode: 1},
			// Bounded, so the demonstration has work still queued rather than
			// a fleet with nothing outstanding.
			MaxGroups: 2,
		}); err != nil {
			return fmt.Errorf("demo: remediating %s: %w", repo.Name, err)
		}
	}
	return nil
}

// settleLastWeeksPullRequests merges one pull request per run, through the
// webhook path, so the demonstration shows the full lifecycle: PR_OPEN →
// MERGED → VERIFIED.
func settleLastWeeksPullRequests(ctx context.Context, s *store.Memory, a seedRunArgs,
	o *orchestrator.Orchestrator, clock func() time.Time) error {

	if a.Index == 0 {
		return nil
	}
	for _, repo := range []string{"demo-org/payments-api", "demo-org/platform-common"} {
		prs, err := s.OpenRemediationPRs(ctx, repo)
		if err != nil {
			return err
		}
		if len(prs) == 0 {
			continue
		}
		pr := prs[0]
		a.Remote.MergePR(repo, pr.Number)
		if _, err := o.ApplyWebhook(ctx, gh.Event{
			Kind: gh.EventPullRequestClosed, Repo: repo, Number: pr.Number,
			Branch: pr.Branch, Merged: true, DeliveryID: fmt.Sprintf("demo-%s-%d", repo, pr.Number),
		}); err != nil {
			return fmt.Errorf("demo: applying the merge webhook for %s: %w", repo, err)
		}
	}
	return nil
}

// demoView is the policy store view. It reports nothing in progress and no
// first-party ownership beyond the registry's, because the registry is the
// only authority on ownership (VM-F-601).
type demoView struct{}

func (demoView) HasOpenPullRequest(string) bool        { return false }
func (demoView) IsFirstPartyOwner(string, string) bool { return false }

var _ policy.StoreView = demoView{}
var _ = scan.ModuleDep{}

// seedGitHub records a fabricated account connection and discovery, so the
// GitHub page has something to show: every demo repository as discovered and
// included, plus one of each skip reason. The decisions come from the real
// classifier, not from a hand-written list of outcomes.
func seedGitHub(ctx context.Context, s *store.Memory, repos []store.Repo, now time.Time) error {
	const account = "demo-user"
	expires := now.Add(23 * 24 * time.Hour)
	if err := s.SaveGitHubConnection(ctx, store.GitHubConnection{
		Account: account, Kind: "fine_grained", ExpiresAt: &expires,
		ReadOnly:  "fine-grained token: GitHub does not report its permissions, so grant only Contents and Metadata read-only; every request is also limited to GET by the client",
		CheckedAt: now.Add(-2 * time.Hour), CheckedBy: "demo",
	}); err != nil {
		return fmt.Errorf("demo: github connection: %w", err)
	}

	listed := func(name, ownerType string, mut func(*gh.AccountRepo)) gh.AccountRepo {
		r := gh.AccountRepo{FullName: name, DefaultBranch: "main", SizeKB: 2048, Private: true}
		r.Owner.Login, _, _ = strings.Cut(name, "/")
		r.Owner.Type = ownerType
		if mut != nil {
			mut(&r)
		}
		return r
	}
	var all []gh.AccountRepo
	for _, r := range repos {
		lang := ""
		if len(r.Languages) > 0 {
			lang = strings.ToUpper(r.Languages[0][:1]) + r.Languages[0][1:]
		}
		all = append(all, listed(r.Name, "Organization", func(a *gh.AccountRepo) { a.Language = lang }))
	}
	all = append(all,
		listed("demo-org/website-2019", "Organization", func(a *gh.AccountRepo) { a.Archived = true }),
		listed("demo-user/dotfiles", "User", func(a *gh.AccountRepo) { a.Fork = true; a.Private = false }),
		listed("demo-org/new-service", "Organization", func(a *gh.AccountRepo) { a.SizeKB = 0 }),
		listed("demo-org/ml-datasets", "Organization", func(a *gh.AccountRepo) { a.SizeKB = 9 << 20 }),
		listed("partner-co/shared-sdk", "Organization", nil),
		listed("a-friend/side-project", "User", nil),
	)
	excluded := map[string]string{"partner-co/shared-sdk": "vendor code we do not own"}
	if err := s.SetExclusion(ctx, store.RepoExclusion{
		Name: "partner-co/shared-sdk", Reason: excluded["partner-co/shared-sdk"], ExcludedBy: "demo", ExcludedAt: now.Add(-72 * time.Hour),
	}); err != nil {
		return err
	}

	var rows []store.DiscoveredRepo
	for _, d := range gh.Classify(account, all, gh.DiscoverOptions{Excluded: excluded}) {
		rows = append(rows, store.DiscoveredRepo{
			Name: d.Repo.FullName, Account: account, Affiliation: string(d.Affiliation),
			Private: d.Repo.Private, Archived: d.Repo.Archived, Fork: d.Repo.Fork, SizeKB: d.Repo.SizeKB,
			DefaultBranch: d.Repo.DefaultBranch, Language: d.Repo.Language,
			Included: d.Included, Reason: d.Reason, Detail: d.Detail, DiscoveredAt: now.Add(-2 * time.Hour),
		})
	}
	return s.ReplaceDiscovery(ctx, account, rows)
}
