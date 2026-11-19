// Command scanworker scans one repository and reports the result (VM-AD §8.1).
//
//	input:  { run_id, repo, mode: "full"|"diff", base_sha?, head_sha?, commit? }
//	output: the normalised findings, dependency inventory and coverage gaps
//	exit:   0 on completion, including partial coverage; non-zero only on
//	        infrastructure failure
//
// The exit code is the contract that matters. A scanner that fails produces a
// coverage gap entry, not a job failure (VM-F-204) — a non-zero exit here means
// the worker itself could not run, and the orchestrator must be able to tell
// those apart.
//
// This worker holds no credential granting write access to any repository
// (VM-F-206).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "scanworker: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		runID     = flag.String("run", "", "run identifier, e.g. S-001247")
		repo      = flag.String("repo", "", "repository name, e.g. org/wanaware-api")
		dir       = flag.String("dir", ".", "path to the checkout")
		mode      = flag.String("mode", "full", "full | diff")
		baseSHA   = flag.String("base", "", "base commit, diff mode only")
		headSHA   = flag.String("head", "", "head commit, diff mode only")
		commit    = flag.String("commit", "", "the commit the checkout is at; empty reads it from the checkout's .git")
		changed   = flag.String("changed", "", "comma-separated changed files, diff mode only")
		languages = flag.String("languages", "", "comma-separated repository languages, e.g. go,javascript")
		tier      = flag.Int("tier", 3, "repository tier")
		lockPath  = flag.String("tools", "config/tools.lock", "path to tools.lock")
		lockfile  = flag.Bool("lockfile", false, "the repository has a committed dependency lockfile")
		testSuite = flag.Bool("test-suite", false, "the repository has an executable test suite")
		out       = flag.String("out", "-", "where to write the result document, or - for stdout")
		timeout   = flag.Duration("timeout", 15*time.Minute, "overall scan timeout (VM-NF-102)")
	)
	// NuGuard, the opt-in remote AI code-rule and inventory adapter. It is
	// given a GitHub token only if $VULNFRAMEWORK_GITHUB_TOKEN is set: the
	// same read-only token, never a write credential (VM-F-206).
	nuguardFlags := adapters.RegisterNuGuardFlags(flag.CommandLine)
	flag.Parse()

	if *runID == "" || *repo == "" {
		return fmt.Errorf("both -run and -repo are required")
	}

	lock, err := scan.LoadToolsLock(*lockPath)
	if err != nil {
		return err
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ng, err := nuguardFlags.Build(context.Background(), lock, adapters.OptionalToken("VULNFRAMEWORK_GITHUB_TOKEN"), log)
	if err != nil {
		return err
	}

	// Every scanner binary sits behind this interface, so the worker is
	// exercisable with a fake and no tools installed.
	reg, err := adapters.NewRegistryWith(runner.Exec{}, lock, adapters.Optional{NuGuard: ng})
	if err != nil {
		return err
	}

	profile := scan.RepoProfile{
		Repo:         *repo,
		Languages:    parseLanguages(*languages),
		Tier:         *tier,
		HasTestSuite: *testSuite,
		HasLockfile:  *lockfile,
	}

	opts := scan.RunOpts{
		Mode:         scan.Mode(*mode),
		BaseSHA:      *baseSHA,
		HeadSHA:      *headSHA,
		ChangedFiles: splitList(*changed),
		CommitSHA:    *commit,
	}
	if opts.CommitSHA == "" {
		// A tree with no .git has no commit to record; an adapter that needs
		// one (NuGuard) records a gap, and the others are unaffected.
		opts.CommitSHA, _ = scan.GitHead(*dir)
	}

	// A cancelled scan must still report what it has: the orchestrator needs
	// the coverage gap, not a truncated stream.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, *timeout)
	defer cancelTimeout()

	result, err := scan.NewWorker(reg).Scan(ctx, *runID, *repo, *dir, profile, opts)
	if err != nil {
		// A worker failure, not a scanner failure: this is the non-zero exit.
		return err
	}

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding result: %w", err)
	}
	encoded = append(encoded, '\n')

	if *out == "-" {
		_, err = os.Stdout.Write(encoded)
		return err
	}
	return os.WriteFile(*out, encoded, 0o644)
}

func parseLanguages(s string) []scan.Language {
	var out []scan.Language
	for _, l := range splitList(s) {
		out = append(out, scan.Language(strings.ToLower(l)))
	}
	return out
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
