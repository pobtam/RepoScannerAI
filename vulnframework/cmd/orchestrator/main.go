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

	"github.com/wanaware/vulnframework/internal/feed"
	"github.com/wanaware/vulnframework/internal/firstparty"
	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
	"github.com/wanaware/vulnframework/internal/scan/runner"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/triage"
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

		postPass   = flag.Bool("post-sweep", true, "after the sweep, enrich, triage, score and route each scanned repository")
		calPath    = flag.String("calibration", "config/calibration.yaml", "path to calibration.yaml")
		policyPath = flag.String("policy", "config/policy.yaml", "path to policy.yaml")
		// No defaults, as in internal/feed: a deployment must not acquire a
		// third-party dependency by omission. Unset, scores name KEV and EPSS
		// as unavailable rather than scoring them as zero.
		kevURL  = flag.String("kev-url", "", "CISA KEV catalogue URL; empty leaves KEV unavailable")
		epssURL = flag.String("epss-url", "", "FIRST EPSS snapshot URL (.csv.gz); empty leaves EPSS unavailable")
		// AI triage sends finding metadata to the Anthropic API, so it is off
		// unless a model is named here AND ANTHROPIC_API_KEY is set.
		triageModel  = flag.String("triage-model", "", "model for AI triage narratives; empty disables AI triage")
		triageTokens = flag.Int("triage-max-tokens", 8192, "response token bound for AI triage")
		// Which modules this organisation owns (VM-F-601). Without it no
		// finding is first-party, so none is deferred to its owner and no
		// wave forms.
		fpPath = flag.String("firstparty", "", "path to the first-party module registry; empty means none")

		// Account mode: one read-only GitHub token, every repository it
		// reaches. The token is read from the environment only, never from
		// a flag, so it is not in shell history or a process listing.
		githubMode    = flag.Bool("github", false, "account mode: discover the repositories $"+githubTokenEnv+" reaches, then download and scan each one (read-only)")
		githubAPI     = flag.String("github-api", "", "GitHub REST root; empty means api.github.com")
		downloadRoot  = flag.String("download-root", "", "account mode: where each repository is unpacked for its scan and deleted after; empty means a temporary directory")
		maxDownloadMB = flag.Int("max-download-mb", 512, "account mode: largest repository tarball to download")
		maxSizeMB     = flag.Int("max-size-mb", 1024, "account mode: skip repositories GitHub estimates larger than this")
		inclCollab    = flag.Bool("include-collaborator", false, "account mode: also scan repositories the account is only a collaborator on")
		inclForks     = flag.Bool("include-forks", false, "account mode: also scan forks")

		// Worker mode: drain the scan queue instead of running one sweep.
		workerMode    = flag.Bool("worker", false, "run as the scan worker: take requests from the scan queue one at a time until stopped")
		workerID      = flag.String("worker-id", "", "this worker's name in the queue; empty derives one from the host and process")
		scanTimeout   = flag.Duration("scan-timeout", 15*time.Minute, "worker mode: time limit per repository scan; a timeout is recorded as a coverage gap")
		discoverEvery = flag.Duration("discover-every", 24*time.Hour, "worker mode with -github: how often to rediscover the account's repositories")
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

	var owners *firstparty.Registry
	if *fpPath != "" {
		raw, err := os.ReadFile(*fpPath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", *fpPath, err)
		}
		if owners, err = firstparty.ParseRegistry(raw); err != nil {
			return fmt.Errorf("parsing %s: %w", *fpPath, err)
		}
	}

	toolVersions := map[string]string{}
	for _, name := range lock.Names() {
		toolVersions[name] = lock.MustVersion(name)
	}

	var dispatcher orchestrator.Dispatcher = &orchestrator.LocalDispatcher{
		Worker: scan.NewWorker(reg),
		WorkDir: func(repo string) string {
			if *workDir == "" {
				return repo
			}
			return *workDir + "/" + lastPath(repo)
		},
	}
	var account *gh.TokenClient
	if *githubMode {
		account = &gh.TokenClient{BaseURL: *githubAPI, Token: githubToken}
		root := *downloadRoot
		if root == "" {
			if root, err = os.MkdirTemp("", "vf-downloads-"); err != nil {
				return err
			}
			defer os.RemoveAll(root)
		} else if err := os.MkdirAll(root, 0o700); err != nil {
			return err
		}
		dispatcher = &orchestrator.DownloadDispatcher{
			Worker: scan.NewWorker(reg), GitHub: account, Root: root,
			MaxDownloadBytes: int64(*maxDownloadMB) << 20,
		}
	}

	if *workerMode {
		dispatcher = &orchestrator.TimeoutDispatcher{Inner: dispatcher, Limit: *scanTimeout}
	}

	o := orchestrator.New(st, dispatcher, orchestrator.NewRateBudget(*credits), orchestrator.Config{
		MaxConcurrentScans: *concurrent,
		CreditsPerScan:     *perScan,
		ScannerImage:       lock.Image,
		ToolVersions:       toolVersions,
		LeaseDuration:      *leaseFor,
		FirstParty:         owners,
	})

	// The lease sweeper runs alongside the sweep. It is the only thing
	// preventing a crashed remediation worker from stranding a finding in
	// AUTO_REMEDIATING permanently (VM-F-158).
	go o.RunLeaseSweeper(ctx, *sweepEvery, func(err error) {
		log.Error("lease sweep", "error", err)
	})

	// Loaded before the sweep so a bad configuration fails before any
	// scanning rather than after it.
	var pass *postSweep
	if *postPass {
		cal, err := score.LoadCalibration(*calPath)
		if err != nil {
			return err
		}
		pol, err := policy.LoadConfig(*policyPath)
		if err != nil {
			return err
		}
		windows, err := cal.SLAWindows()
		if err != nil {
			return err
		}
		// The windows the interface reports are calibration.yaml's; SLA
		// positions must be computed against the same ones.
		o.Config.SLAWindows = windows
		pass = &postSweep{
			Orch: o, Feeds: feeds(*kevURL, *epssURL), Triager: triager(*triageModel, *triageTokens),
			Scorer: score.New(cal), Policy: policy.New(pol),
			View: storeView{ctx: ctx, st: st, registry: owners, log: log}, Log: log,
		}
		if pass.Triager.Unavailable != "" {
			log.Warn("AI triage is off; findings are scored and routed without a narrative",
				"reason", pass.Triager.Unavailable)
		}
		if len(pass.Feeds.Sources) < 2 {
			log.Warn("exploitation feeds not fully configured; scores will name the missing inputs",
				"kev", *kevURL != "", "epss", *epssURL != "")
		}
	}

	if *workerMode {
		return runWorker(ctx, log, workerConfig{
			orch: o, pass: pass, account: account, credits: *credits, id: *workerID,
			discoverEvery: *discoverEvery,
			discover:      gh.DiscoverOptions{IncludeCollaborator: *inclCollab, IncludeForks: *inclForks, MaxSizeMB: *maxSizeMB},
		})
	}

	var discovered *orchestrator.DiscoverStats
	if account != nil {
		ds, err := o.Discover(ctx, account, gh.DiscoverOptions{
			IncludeCollaborator: *inclCollab, IncludeForks: *inclForks, MaxSizeMB: *maxSizeMB,
		}, "orchestrator")
		if err != nil {
			return fmt.Errorf("discovering repositories: %w", err)
		}
		discovered = &ds
		log.Info("discovery complete", "account", ds.Account, "seen", ds.Seen, "included", ds.Included,
			"skipped", ds.Skipped, "added", ds.Sync.Added, "archived", ds.Sync.Archived)
	}

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

	output := struct {
		Discovery  *orchestrator.DiscoverStats  `json:"discovery,omitempty"`
		Sweep      orchestrator.RunStats        `json:"sweep"`
		PostSweep  *PostSweepStats              `json:"post_sweep,omitempty"`
		Recoveries []orchestrator.RecoveryEvent `json:"recoveries,omitempty"`
	}{Discovery: discovered, Sweep: stats}
	if pass != nil {
		post, err := pass.Run(ctx, stats.RunID, repos)
		if err != nil {
			return fmt.Errorf("post-sweep pass for %s: %w", stats.RunID, err)
		}
		output.PostSweep = &post
	}
	// Recovery must be loud: a feed outage during enrichment is recorded
	// here, and a record nobody prints is a silent one.
	output.Recoveries = o.Recovery.Events()

	encoded, err := json.MarshalIndent(output, "", "  ")
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

// githubTokenEnv names the environment variable account mode reads its
// token from.
const githubTokenEnv = "VULNFRAMEWORK_GITHUB_TOKEN"

// githubToken reads the token at the moment of use. It is never stored,
// logged, or put on a command line.
func githubToken() (string, error) {
	t := os.Getenv(githubTokenEnv)
	if t == "" {
		return "", fmt.Errorf("%s is not set; account mode needs a read-only fine-grained token there", githubTokenEnv)
	}
	return t, nil
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

// feeds builds the exploitation-intelligence sources that have a URL. One
// client is shared so each catalogue is downloaded once per run.
func feeds(kevURL, epssURL string) feed.Multi {
	client := newFeedClient()
	var m feed.Multi
	if kevURL != "" {
		m.Sources = append(m.Sources, &feed.KEVSource{URL: kevURL, HTTP: client})
	}
	if epssURL != "" {
		m.Sources = append(m.Sources, &feed.EPSSSource{URL: epssURL, HTTP: client})
	}
	return m
}

// triager returns the live triager when AI triage is enabled and a key is
// present, and otherwise one that says which of the two is missing. Either
// way the pass scores and routes.
func triager(model string, maxTokens int) *triage.Triager {
	cache := triage.NewMemoryCache()
	switch {
	case model == "":
		return &triage.Triager{Cache: cache, Unavailable: "AI triage is not enabled (-triage-model is not set)"}
	case os.Getenv("ANTHROPIC_API_KEY") == "":
		return &triage.Triager{Cache: cache, Unavailable: "AI triage is enabled but ANTHROPIC_API_KEY is not set"}
	}
	return &triage.Triager{
		Cache: cache, Model: model,
		Client: &triage.HTTPClient{
			Model: model, MaxTokens: maxTokens,
			// Read at request time, never stored in a field or logged.
			Credential: func() (string, error) { return os.Getenv("ANTHROPIC_API_KEY"), nil },
		},
	}
}

func lastPath(repo string) string {
	for i := len(repo) - 1; i >= 0; i-- {
		if repo[i] == '/' {
			return repo[i+1:]
		}
	}
	return repo
}
