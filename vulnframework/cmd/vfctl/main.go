// Command vfctl administers the fleet registry: the list of repositories a
// sweep plans over (VM-NF-501).
//
// The orchestrator reads its fleet from the registry and refuses to sweep an
// empty one. Syncing the registry from GitHub needs an App installation
// (VM-OQ-10); vfctl is the way to populate it without one, which is what a
// read-only, local deployment over hand-cloned repositories needs.
//
//	vfctl repo add org/api -languages go -tier 1 -test-suite
//	vfctl repo add org/web -languages javascript -lockfile
//	vfctl repo list
//	vfctl repo remove org/web
//	vfctl github connect      # token from $VULNFRAMEWORK_GITHUB_TOKEN or a hidden prompt
//	vfctl github discover
//
// vfctl writes only to the findings store. The github commands read from
// GitHub with the token in the environment, using GET requests only; the
// token is never stored.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	// The driver is chosen here rather than by internal/store, so the store
	// carries no driver dependency of its own.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/wanaware/vulnframework/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "vfctl: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("vfctl", flag.ContinueOnError)
	dsn := fs.String("dsn", os.Getenv("VULNFRAMEWORK_DSN"), "Postgres connection string")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: vfctl [-dsn DSN] repo|finding|github ...\n\n%s\n", usage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return fmt.Errorf("no command given")
	}
	if *dsn == "" {
		return fmt.Errorf("-dsn or VULNFRAMEWORK_DSN is required")
	}

	db, err := sql.Open("pgx", *dsn)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return Exec(ctx, store.NewPostgres(db), fs.Args(), os.Stdout)
}
