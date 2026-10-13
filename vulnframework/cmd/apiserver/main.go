// Command apiserver serves the interface's API (VM-AD §7.4, VM-UI §6.2).
//
// Two modes, and they are not variations of each other:
//
//	-demo runs entirely in memory over fabricated data (internal/demo). No
//	credentials, no network, no Docker, no database. Every request is served to
//	one fixed identity, which is safe only because it binds to localhost and
//	the data is invented. /v1/health reports demo:true so the interface can say
//	which it is talking to.
//
//	-dsn runs against Postgres and requires a real authenticating proxy. There
//	is no mode that serves real data to an unauthenticated caller: the server
//	refuses to start without an authenticator, because the client is never the
//	access control point (VM-UI-F-802).
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	// The driver is chosen here rather than by internal/store, so the store
	// carries no driver dependency of its own.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/wanaware/vulnframework/internal/api"
	"github.com/wanaware/vulnframework/internal/demo"
	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/report"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "apiserver: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		addr     = flag.String("addr", "127.0.0.1:8080", "address to listen on")
		demoMode = flag.Bool("demo", false,
			"serve fabricated demonstration data from memory: no credentials, no network, no database")
		dsn        = flag.String("dsn", os.Getenv("VULNFRAMEWORK_DSN"), "Postgres connection string")
		calPath    = flag.String("calibration", "config/calibration.yaml", "path to calibration.yaml")
		policyPath = flag.String("policy", "config/policy.yaml", "path to policy.yaml")
		fpPath     = flag.String("firstparty", "", "path to the first-party module registry")
		webhookSec = flag.String("webhook-secret", os.Getenv("VULNFRAMEWORK_WEBHOOK_SECRET"),
			"GitHub webhook secret; without it no webhook endpoint is registered")
		userHeader  = flag.String("user-header", "X-Auth-User", "header the authenticating proxy sets")
		levelHeader = flag.String("level-header", "X-Auth-Level", "header carrying the privilege level")
		reposHeader = flag.String("repos-header", "X-Auth-Repos", "header carrying the caller's repositories")
		demoRuns    = flag.Int("demo-runs", 6, "how many weekly sweeps the demonstration simulates")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cal, err := score.LoadCalibration(*calPath)
	if err != nil {
		return fmt.Errorf("loading %s: %w", *calPath, err)
	}
	pol, err := policy.LoadConfig(*policyPath)
	if err != nil {
		return fmt.Errorf("loading %s: %w", *policyPath, err)
	}

	cfg := api.Config{Calibration: cal, Policy: pol, Logger: log}

	// Access logging (VM-UI-F-805), on in both modes.
	//
	// On in the demonstration too, because a control that is only enabled in
	// production is a control nobody has watched working. Where these records
	// go, how long they are kept and whether they must be tamper-evident are
	// deployment decisions (D6); a structured logger needs none of those
	// decided and is therefore the version that actually runs.
	cfg.AccessLog = api.SlogAccessLog{Logger: log}

	var registry *firstparty.Registry
	if *fpPath != "" {
		raw, err := os.ReadFile(*fpPath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", *fpPath, err)
		}
		if registry, err = firstparty.ParseRegistry(raw); err != nil {
			return fmt.Errorf("parsing %s: %w", *fpPath, err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch {
	case *demoMode:
		mem := store.NewMemory()
		if err := mem.Migrate(ctx); err != nil {
			return fmt.Errorf("preparing the in-memory store: %w", err)
		}
		log.Info("seeding DEMONSTRATION data — none of it is real scan output")
		res, err := demo.Seed(ctx, mem, demo.Options{
			Calibration: cal, Policy: pol, Runs: *demoRuns,
			Now: time.Now().UTC().Truncate(time.Hour),
		})
		if err != nil {
			return fmt.Errorf("seeding the demonstration: %w", err)
		}
		log.Info("demonstration data seeded",
			"repos", res.Repos, "runs", len(res.Runs), "findings", res.Findings,
			"open_pull_requests", res.PRs, "coverage_gaps", res.Gaps,
			"blocked_consumers", res.Waves, "reports", res.Reports)

		cfg.Store = mem
		cfg.Demo = true
		cfg.Registry = res.Registry
		cfg.Wave2Trigger = "tag"
		// One fixed identity. The demonstration has no identity provider, and
		// the alternative — serving every request as an undetermined
		// principal — would exercise the refusal path rather than the
		// interface.
		cfg.Auth = api.DemoAuth{Level: report.LevelSecurityOwner}
		// In the demonstration the feeds ANSWERED (through fakes), so the
		// scoring caveat clears where they did. A caveat that never clears is
		// decoration.
		cfg.UnavailableScoringInputs = nil

	case *dsn != "":
		db, err := sql.Open("pgx", *dsn)
		if err != nil {
			return fmt.Errorf("opening the database: %w", err)
		}
		defer db.Close()
		pg := store.NewPostgres(db)
		if err := pg.Migrate(ctx); err != nil {
			return fmt.Errorf("migrating: %w", err)
		}
		cfg.Store = pg
		cfg.Registry = registry
		cfg.Auth = api.HeaderAuth{
			UserHeader: *userHeader, LevelHeader: *levelHeader, ReposHeader: *reposHeader,
		}
		// Whether KEV and EPSS are available is what the orchestrator's
		// post-sweep pass has stored, not something this process can know at
		// startup. It used to be asserted here as "unavailable", which went
		// stale the moment the feeds were wired.
		cfg.ScoringInputsFromStore = true

	default:
		return errors.New("one of -demo or -dsn is required. " +
			"-demo serves fabricated data from memory with no credentials; " +
			"-dsn serves a real store and requires an authenticating proxy")
	}

	srv, err := api.New(cfg)
	if err != nil {
		return err
	}

	if *webhookSec != "" {
		o := orchestrator.New(cfg.Store, orchestrator.NewFakeDispatcher(),
			orchestrator.NewRateBudget(1000), orchestrator.Config{FirstParty: cfg.Registry})
		if err := srv.RegisterWebhook(api.WebhookConfig{
			Verifier: gh.NewWebhookVerifier(*webhookSec),
			Applier:  o,
			Log:      gh.NewDeliveryLog(),
		}); err != nil {
			return err
		}
		log.Info("webhook endpoint registered at POST /v1/webhooks/github")
	} else {
		// No endpoint at all, rather than one that accepts and discards: the
		// sender would record success (OQ-P12-02).
		log.Info("no webhook secret configured, so no webhook endpoint is registered; " +
			"pull request state will be carried by the bounded reconciliation fallback only")
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errs := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", *addr, "demo", *demoMode)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}
