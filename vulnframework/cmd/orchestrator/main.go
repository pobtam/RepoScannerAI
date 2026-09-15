// Command orchestrator plans runs, dispatches scan work, sweeps expired leases
// and budgets the external API rate (VM-AD §7).
//
// It is the only component permitted to write findings.state (VM-AD §7.1).
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	// The driver is chosen here rather than by internal/store, so the store
	// carries no driver dependency of its own.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
	"github.com/wanaware/vulnframework/internal/scan/runner"
	"github.com/wanaware/vulnframework/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "orchestrator: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dsn        = flag.String("dsn", os.Getenv("VULNFRAMEWORK_DSN"), "Postgres connection string")
		lockPath   = flag.String("tools", "config/tools.lock", "path to tools.lock")
		kind       = flag.String("kind", "sweep", "run kind: sweep | advisory | manual | rescan")
		trigger    = flag.String("trigger", "manual", "what triggered this run")
		workDir    = flag.String("workdir", "", "directory holding repository checkouts, named after the repo's last path element")
		concurrent = flag.Int("max-concurrent", 20, "maximum concurrent repository scans (VM-AD §7.3)")
		credits    = flag.Int("credits", 200, "API rate credits available to this run (VM-AD §7.2)")
		perScan    = flag.Int("credits-per-scan", 1, "credits reserved per repository scan")
		leaseFor   = flag.Duration("lease", 30*time.Minute, "remediation lease duration (VM-AD §6.2)")
		sweepEvery = flag.Duration("lease-sweep", time.Minute, "lease sweep interval")
		migrate    = flag.Bool("migrate", false, "apply pending migrations and exit")
	)
	flag.Parse()

	if *dsn == "" {
		return fmt.Errorf("-dsn or VULNFRAMEWORK_DSN is required")
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	db, err := sql.Open("pgx", *dsn)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	st := store.NewPostgres(db)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if *migrate {
		if err := st.Migrate(ctx); err != nil {
			return err
		}
		v, err := st.SchemaVersion(ctx)
		if err != nil {
			return err
		}
		log.Info("migrated", "schema_version", v)
		return nil
	}

	lock, err := scan.LoadToolsLock(*lockPath)
	if err != nil {
		return err
	}
	reg, err := adapters.NewRegistry(runner.Exec{}, lock)
	if err != nil {
		return err
	}

	toolVersions := map[string]string{}
	for _, name := range lock.Names() {
		toolVersions[name] = lock.MustVersion(name)
	}

	dispatcher := &orchestrator.LocalDispatcher{
		Worker: scan.NewWorker(reg),
		WorkDir: func(repo string) string {
			if *workDir == "" {
				return repo
			}
			return *workDir + "/" + lastPath(repo)
		},
	}

	o := orchestrator.New(st, dispatcher, orchestrator.NewRateBudget(*credits), orchestrator.Config{
		MaxConcurrentScans: *concurrent,
		CreditsPerScan:     *perScan,
		ScannerImage:       lock.Image,
		ToolVersions:       toolVersions,
		LeaseDuration:      *leaseFor,
	})

	// The lease sweeper runs alongside the sweep. It is the only thing
	// preventing a crashed remediation worker from stranding a finding in
	// AUTO_REMEDIATING permanently (VM-F-158).
	go o.RunLeaseSweeper(ctx, *sweepEvery, func(err error) {
		log.Error("lease sweep", "error", err)
	})

	repos, err := registry(ctx, st)
	if err != nil {
		return err
	}
	if len(repos) == 0 {
		return fmt.Errorf("no repositories registered; add them with vfctl before running a sweep")
	}

	stats, err := o.Sweep(ctx, store.RunKind(*kind), *trigger, repos, orchestrator.DefaultSelector)
	if err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))

	// A run that produced gaps is still a completed run: the gaps are the
	// output, not a failure (VM-F-204).
	log.Info("sweep complete",
		"run", stats.RunID,
		"planned", stats.Planned,
		"dispatched", stats.Dispatched,
		"skipped", stats.Skipped,
		"not_dispatched", stats.Close.NotDispatched,
		"no_result", stats.Close.NoResult)
	return nil
}

// registry returns the repositories in the fleet.
//
// Phase 4 reads them from the store; syncing the registry from GitHub is the
// gh package's job and needs an App installation (VM-OQ-10), which this phase
// deliberately does not require.
func registry(ctx context.Context, st *store.Postgres) ([]store.Repo, error) {
	names, err := st.RepoNames(ctx)
	if err != nil {
		return nil, err
	}
	var out []store.Repo
	for _, n := range names {
		r, err := st.GetRepo(ctx, n)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func lastPath(repo string) string {
	for i := len(repo) - 1; i >= 0; i-- {
		if repo[i] == '/' {
			return repo[i+1:]
		}
	}
	return repo
}
