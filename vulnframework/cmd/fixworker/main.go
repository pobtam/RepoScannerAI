// Command fixworker performs ONE remediation pass and exits (OQ-AUDIT-07).
//
// `internal/orchestrator.RemediationPass` has been callable and tested since
// Phase 9b, and until now nothing outside tests and the demonstration invoked
// it. A function that nothing runs is indistinguishable from a feature nobody
// has used yet — which is the defect this build kept finding, one level up
// from a field.
//
// It does one pass and stops. That is deliberate:
//
//	A long-running loop would embed a cadence — how often, with what
//	concurrency, with what backoff — and those are deployment decisions, not
//	this binary's (D11, and OQ-AUDIT-07's second half). A process that runs
//	once and exits can be driven by cron, a Kubernetes Job, a queue consumer
//	or a person, and does not pretend to have answered a question nobody has
//	asked it.
//
//	It also makes failure legible. A pass that exits non-zero is a thing a
//	scheduler can see. A loop that keeps going after a failure needs its own
//	alerting to be visible at all, and that alerting is item 16 on the
//	human-action checklist.
//
// # What it refuses to do
//
// It will not run against real repositories without being given the pieces
// that make that safe, and there is no flag that assembles them for you. The
// code host, the toolchain and the sandbox are all constructor arguments with
// no defaults, and -demo is the only mode this build can actually run:
// everything else needs D4's credentials, D5's scanners and D2's proven
// sandbox. A -real flag that silently used fakes would be the worst possible
// thing here, because it would appear to work.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/remediate"
	"github.com/wanaware/vulnframework/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fixworker: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		demoMode = flag.Bool("demo", false,
			"run one pass over fabricated demonstration data in memory: no credentials, no network")
		repoName  = flag.String("repo", "", "repository to remediate; empty means every repository in scope")
		maxGroups = flag.Int("max-groups", 0,
			"bound the number of fix groups attempted per repository; 0 means every group")
		dryRun = flag.Bool("dry-run", false,
			"report what would be attempted and change nothing")
		timeout = flag.Duration("timeout", 30*time.Minute, "wall-clock bound for the whole pass")
		// A directory rather than two paths, and explicit rather than
		// discovered: a binary that hunted upwards for a config directory
		// would pick up a different one depending on where it was started.
		configDir = flag.String("config", "config", "directory holding calibration.yaml and policy.yaml")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if !*demoMode {
		// Fail-closed, and loudly. There is no configuration of this build
		// that can remediate a real repository: the GitHub App is not
		// installed (D4), no scanner is present (D5), the real toolchain has
		// never been run against anything outside testdata, and the sandbox
		// is unproven off Linux (D2).
		//
		// Refusing is the only honest answer. A binary that started up and
		// then found nothing to do would read as "there was no work", which
		// is a statement about the fleet rather than about this deployment.
		return errors.New(
			"fixworker has no non-demonstration mode in this build, and will not pretend to.\n" +
				"Remediating a real repository needs, in order: the Linux sandbox proof (D2), a\n" +
				"GitHub App with a key and write permission (D4), pinned scanners (D5), and the\n" +
				"first supervised agent run (D1). GO-LIVE-CHECKLIST.md sequences them.\n" +
				"Run with -demo to exercise the pass over fabricated data")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	pass, err := newDemoPass(ctx, log, *configDir)
	if err != nil {
		return err
	}

	repos, err := pass.repos(ctx, *repoName)
	if err != nil {
		return err
	}
	if len(repos) == 0 {
		// Not an error, and not silence either. An empty scope is a fact
		// worth printing: it is what a mistyped -repo looks like, and it is
		// also what a correctly-configured fleet with nothing to fix looks
		// like.
		log.Info("fixworker: no repository in scope", "repo_filter", *repoName)
		return nil
	}

	total := orchestrator.RemediationStats{Outcomes: map[remediate.Outcome]int{}}
	for _, repo := range repos {
		if *dryRun {
			claimable, err := pass.claimable(ctx, repo)
			if err != nil {
				return err
			}
			log.Info("fixworker: would attempt", "repo", repo.Name, "claimable", claimable)
			total.Claimable += claimable
			continue
		}

		stats, err := pass.run(ctx, repo, *maxGroups)
		if err != nil {
			// The pass stops. A worker that carried on after a failure would
			// report a partial result as a complete one, and the next run
			// would have no way to tell that half the fleet was skipped.
			return fmt.Errorf("remediating %s: %w", repo.Name, err)
		}
		log.Info("fixworker: pass complete",
			"repo", repo.Name,
			"claimable", stats.Claimable, "groups", stats.Groups,
			"attempted", stats.Attempted, "prs_opened", stats.PROpened,
			"unmatched", len(stats.Unmatched))
		merge(&total, stats)
	}

	report(log, total, *dryRun)
	return nil
}

// report prints what the pass did, naming every outcome separately.
//
// Separately, because "attempted 8, opened 3" invites the reader to assume the
// other five failed in one way. They did not: a group with nothing to do, a
// repository whose baseline was already failing, a verification that did not
// close the finding and a guard violation are four different operational
// problems with four different owners, and the whole point of the outcome
// enumeration is that they are counted apart.
func report(log *slog.Logger, stats orchestrator.RemediationStats, dryRun bool) {
	if dryRun {
		log.Info("fixworker: dry run complete", "claimable", stats.Claimable)
		return
	}

	outcomes := make([]string, 0, len(stats.Outcomes))
	for outcome := range stats.Outcomes {
		outcomes = append(outcomes, string(outcome))
	}
	sort.Strings(outcomes)

	args := []any{
		"claimable", stats.Claimable, "groups", stats.Groups,
		"attempted", stats.Attempted, "prs_opened", stats.PROpened,
	}
	for _, outcome := range outcomes {
		args = append(args, outcome, stats.Outcomes[remediate.Outcome(outcome)])
	}
	log.Info("fixworker: finished", args...)

	if len(stats.Unmatched) > 0 {
		// A hole in the policy table is loud and does not stop the pass
		// (VM-F-405). It is printed at WARN because the correct response is
		// to add a rule, not to wait for it to recur.
		log.Warn("fixworker: findings no policy rule decided about",
			"count", len(stats.Unmatched), "fingerprints", stats.Unmatched)
	}
}

func merge(into *orchestrator.RemediationStats, from orchestrator.RemediationStats) {
	into.Claimable += from.Claimable
	into.Groups += from.Groups
	into.Attempted += from.Attempted
	into.PROpened += from.PROpened
	for outcome, n := range from.Outcomes {
		into.Outcomes[outcome] += n
	}
	into.Unmatched = append(into.Unmatched, from.Unmatched...)
}

// repos resolves the scope of one pass.
func (p *demoPass) repos(ctx context.Context, filter string) ([]store.Repo, error) {
	names, err := p.store.RepoNames(ctx)
	if err != nil {
		return nil, err
	}
	var out []store.Repo
	for _, name := range names {
		repo, err := p.store.GetRepo(ctx, name)
		if err != nil {
			return nil, err
		}
		if repo.Archived {
			continue
		}
		if filter != "" && repo.Name != filter {
			continue
		}
		out = append(out, repo)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
