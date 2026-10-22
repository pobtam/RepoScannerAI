package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/store"
)

// Worker mode (-worker): the long-running scan worker.
//
// It drains the scan queue that the interface, vfctl and the daily timer fill,
// one request (or one batch) at a time, through the same sweep path as a
// one-shot run. In account mode it also rediscovers the account's
// repositories at start-up and every -discover-every, because it is the only
// component that holds the GitHub token: the token stays in this process's
// environment for as long as it runs, and stopping the worker removes it.

type workerConfig struct {
	orch          *orchestrator.Orchestrator
	pass          *postSweep
	account       *gh.TokenClient
	credits       int
	id            string
	discoverEvery time.Duration
	discover      gh.DiscoverOptions
}

func runWorker(ctx context.Context, log *slog.Logger, c workerConfig) error {
	id := c.id
	if id == "" {
		host, _ := os.Hostname()
		id = fmt.Sprintf("%s-%d-%s", host, os.Getpid(), time.Now().UTC().Format("20060102T150405Z"))
	}
	w := &orchestrator.ScanWorker{Orch: c.orch, ID: id, Credits: c.credits, Log: log}
	if c.pass != nil {
		w.AfterRun = func(ctx context.Context, runID string, repos []store.Repo) error {
			_, err := c.pass.Run(ctx, runID, repos)
			return err
		}
	}

	if c.account != nil {
		rediscover := func() {
			ds, err := c.orch.Discover(ctx, c.account, c.discover, "scan worker "+id)
			if err != nil {
				log.Error("discovery failed; scanning continues with the registry as it is", "error", err)
				return
			}
			log.Info("discovery complete", "account", ds.Account, "seen", ds.Seen, "included", ds.Included,
				"added", ds.Sync.Added, "archived", ds.Sync.Archived)
		}
		rediscover()
		if c.discoverEvery > 0 {
			go func() {
				t := time.NewTicker(c.discoverEvery)
				defer t.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						rediscover()
					}
				}
			}()
		}
	}

	n, err := w.Recover(ctx)
	if err != nil {
		return err
	}
	log.Info("scan worker started", "worker", id, "interrupted_from_previous_workers", n)
	return w.Run(ctx)
}
