package main

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/wanaware/vulnframework/internal/demo"
	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/remediate"
	"github.com/wanaware/vulnframework/internal/remediate/guard"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
)

// demoPass is one remediation pass over fabricated data.
//
// It assembles the REAL orchestrator, the REAL policy engine, the REAL
// grouping and the REAL remediation worker — with a fake code host and a fake
// toolchain behind them. What it exercises is therefore the dispatch path
// itself, which is the thing OQ-AUDIT-07 recorded as having no caller.
//
// Everything fabricated here is labelled as such on the way out. The binary
// says "demonstration data" in its first log line, because a pull-request
// count on a terminal is exactly the kind of figure that gets quoted.
type demoPass struct {
	store  *store.Memory
	engine *policy.Engine
	orch   *orchestrator.Orchestrator
	remote *gh.Fake
	guard  *guard.Guard
	log    *slog.Logger
}

func newDemoPass(ctx context.Context, log *slog.Logger, configDir string) (*demoPass, error) {
	log.Warn("fixworker: DEMONSTRATION MODE — every repository, finding and pull request below " +
		"is fabricated. Nothing is scanned, no repository is touched, and no pull request is opened")

	cal, err := score.LoadCalibration(filepath.Join(configDir, "calibration.yaml"))
	if err != nil {
		return nil, fmt.Errorf("loading calibration: %w", err)
	}
	pol, err := policy.LoadConfig(filepath.Join(configDir, "policy.yaml"))
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}
	engine := policy.New(pol)

	s := store.NewMemory()
	if err := s.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrating the in-memory store: %w", err)
	}
	if _, err := demo.Seed(ctx, s, demo.Options{
		Calibration: cal, Policy: pol, Now: time.Now().UTC(), Runs: 6,
	}); err != nil {
		return nil, fmt.Errorf("seeding the demonstration: %w", err)
	}

	g, err := guard.New(guard.Config{DenyPaths: pol.Defaults.DenyPaths})
	if err != nil {
		return nil, fmt.Errorf("building the path guard: %w", err)
	}

	// A fresh fake remote rather than the one the seeding used: this pass is
	// a NEW pass, and starting it with the demonstration's existing pull
	// requests would have it adopt work it did not do.
	remote := gh.NewFake("main")

	return &demoPass{
		store:  s,
		engine: engine,
		remote: remote,
		orch: orchestrator.New(s, orchestrator.NewFakeDispatcher(),
			orchestrator.NewRateBudget(500), orchestrator.Config{
				ScannerImage:   "vulnframework-scanner:v1",
				CreditsPerScan: 1,
				PR:             remote,
			}),
		guard: g,
		log:   log,
	}, nil
}

// claimable counts what policy would auto-remediate right now, without
// attempting anything.
//
// It reaches the same decision the pass does, through the same engine, rather
// than estimating. A dry run that counted differently from the real pass would
// be worse than no dry run: somebody would use it to decide whether to run the
// real one.
func (p *demoPass) claimable(ctx context.Context, repo store.Repo) (int, error) {
	// The same skip the real pass applies, and it has to be here rather than
	// only there.
	//
	// The first version of this reported one claimable finding for a
	// repository the real pass then skipped for having no test suite — which
	// is precisely the failure the comment above warns about, produced by the
	// code the comment is attached to. A dry run that disagrees with the pass
	// is worse than no dry run, because somebody uses it to decide whether to
	// run the pass.
	if !repo.HasTestSuite {
		return 0, nil
	}

	queued, err := p.store.ListFindings(ctx, store.Query{
		Scope: store.ScopeOpen, Repo: repo.Name, States: []model.State{model.Triaged},
	})
	if err != nil {
		return 0, err
	}

	pr := policy.Repo{
		Name: repo.Name, Tier: repo.Tier,
		Language:     policy.Language(primaryLanguage(repo)),
		HasTestSuite: repo.HasTestSuite,
	}

	n := 0
	for _, f := range queued {
		decision, err := p.engine.Evaluate(f, pr, passView{})
		if err != nil {
			// A hole in the table is not counted as claimable, and it is not
			// silently dropped either: the real pass records it in Unmatched
			// and so does the summary.
			continue
		}
		if decision.Outcome == policy.AutoRemediate {
			n++
		}
	}
	return n, nil
}

// run performs one pass for one repository.
func (p *demoPass) run(ctx context.Context, repo store.Repo, maxGroups int) (orchestrator.RemediationStats, error) {
	if !repo.HasTestSuite {
		// No verification gate is possible without a test suite, and the
		// framework does not attempt a fix it cannot prove (VM-F-504). This
		// is a skip with a reason, not an empty result — and claimable()
		// applies the same rule, so a dry run cannot promise work the pass
		// will not do.
		p.log.Info("fixworker: skipping, no test suite to verify a fix against", "repo", repo.Name)
		return orchestrator.RemediationStats{Outcomes: map[remediate.Outcome]int{}}, nil
	}

	worker := &remediate.Worker{
		Store: p.store, PR: p.remote, Guard: p.guard,
		Toolchain: demoToolchain(),
		Owner:     "fixworker", LeaseTTL: 30 * time.Minute,
		Clock: func() time.Time { return time.Now().UTC() },
	}
	return p.orch.RemediationPass(ctx, orchestrator.RemediationRequest{
		Repo: repo, Worker: worker, Policy: p.engine, View: passView{},
		Groups:    remediate.GroupConfig{MaxPerPR: 3, MaxPerPRCode: 1},
		MaxGroups: maxGroups,
	})
}

// passView answers the policy engine's questions about surrounding state.
type passView struct{}

func (passView) HasOpenPullRequest(string) bool        { return false }
func (passView) IsFirstPartyOwner(string, string) bool { return false }

func primaryLanguage(r store.Repo) string {
	if len(r.Languages) == 0 {
		return ""
	}
	return r.Languages[0]
}

// demoToolchain is the fabricated module registry the demonstration's
// advisories refer to.
//
// The REAL toolchain (internal/remediate/gotool) exists and is tested, and it
// is deliberately not used here: it would run `go build` and `go test` against
// a clone that does not exist, because the fake code host clones nothing. The
// honest demonstration is the dispatch path over a fake toolchain, which is
// what this is and what it says it is.
func demoToolchain() *remediate.FakeToolchain {
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
	return tc
}
