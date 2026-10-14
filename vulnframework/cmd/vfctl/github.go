package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/store"
)

// githubTokenEnv is where the token is read from. The token is never a
// flag: a flag lands in shell history and in every process listing.
const githubTokenEnv = "VULNFRAMEWORK_GITHUB_TOKEN"

// newGitHub builds the GitHub client a command uses; tests replace it with
// one pointed at a local fake.
var newGitHub = func() orchestrator.GitHubAccount {
	return &gh.TokenClient{BaseURL: os.Getenv("VULNFRAMEWORK_GITHUB_API"), Token: tokenOnce()}
}

// tokenOnce reads the token from the environment, or prompts for it once on
// a terminal with echo off. It is held only for this command's lifetime.
func tokenOnce() func() (string, error) {
	var (
		once  sync.Once
		token string
		err   error
	)
	return func() (string, error) {
		once.Do(func() {
			if token = strings.TrimSpace(os.Getenv(githubTokenEnv)); token != "" {
				return
			}
			token, err = promptToken()
		})
		return token, err
	}
}

// promptToken asks for the token on the terminal, with echo turned off so it
// is not left on the screen or in a recording of the session.
func promptToken() (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("%s is not set and there is no terminal to ask on", githubTokenEnv)
	}
	defer tty.Close()
	fmt.Fprint(tty, "GitHub token (input hidden): ")
	stty := func(arg string) error {
		cmd := osexec.Command("stty", arg)
		cmd.Stdin = tty
		return cmd.Run()
	}
	if err := stty("-echo"); err != nil {
		return "", fmt.Errorf("could not hide input on this terminal (%v); set %s instead", err, githubTokenEnv)
	}
	defer func() {
		_ = stty("echo")
		fmt.Fprintln(tty)
	}()
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("reading the token: %w", err)
	}
	return strings.TrimSpace(line), nil
}

const githubUsage = `  github connect
      Check a GitHub token and record its account, kind and expiry (never the
      token itself). The token is read from $VULNFRAMEWORK_GITHUB_TOKEN, or
      asked for with input hidden. Use a fine-grained personal access token
      with only Contents: read-only and Metadata: read-only. A classic token
      that grants write is refused.
  github discover [-include-collaborator] [-include-forks] [-max-size-mb N]
      List every repository the token reaches, decide which are scanned (each
      skipped one gets a reason), and register the included ones. Repositories
      that leave scope are archived, never deleted.
  github status
      Show the connected account, its expiry, and the last discovery.
  repo exclude NAME -reason TEXT [-as NAME]
      Leave a repository out of discovery, recorded with who and why. It is
      archived now and stays out until "repo include".
  repo include NAME
      Lift an exclusion. Takes effect at the next discovery.`

func githubCommand(ctx context.Context, st store.Store, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("github needs a subcommand\n%s", githubUsage)
	}
	switch args[0] {
	case "connect":
		if len(args) > 1 {
			return fmt.Errorf("github connect takes no arguments; the token comes from $%s or a prompt", githubTokenEnv)
		}
		return githubConnect(ctx, st, out)
	case "discover":
		return githubDiscover(ctx, st, args[1:], out)
	case "status":
		return githubStatus(ctx, st, out)
	default:
		return fmt.Errorf("unknown github subcommand %q\n%s", args[0], githubUsage)
	}
}

func githubConnect(ctx context.Context, st store.Store, out io.Writer) error {
	conn, err := newGitHub().Connect(ctx)
	if err != nil {
		return err
	}
	who := currentUser()
	if who == "" {
		who = "vfctl"
	}
	if err := st.SaveGitHubConnection(ctx, store.GitHubConnection{
		Account: conn.Account, Kind: conn.Kind, Scopes: conn.Scopes, ExpiresAt: conn.ExpiresAt,
		ReadOnly: conn.ReadOnly, CheckedAt: now(), CheckedBy: who,
	}); err != nil {
		return err
	}
	fmt.Fprintf(out, "connected %s (%s token)\n", conn.Account, strings.ReplaceAll(conn.Kind, "_", "-"))
	fmt.Fprintf(out, "  read-only: %s\n", conn.ReadOnly)
	fmt.Fprintf(out, "  expires:   %s\n", expiryText(conn.ExpiresAt))
	fmt.Fprintln(out, "The token was checked, not stored. Discovery and sweeps read it from $"+githubTokenEnv+".")
	return nil
}

func expiryText(t *time.Time) string {
	if t == nil {
		return "no expiry reported (a token without one is a standing credential; prefer one that expires)"
	}
	left := t.Sub(now())
	switch {
	case left <= 0:
		return t.Format("2006-01-02") + " — EXPIRED"
	case left < 14*24*time.Hour:
		return fmt.Sprintf("%s — in %d days; rotate it soon", t.Format("2006-01-02"), int(left.Hours()/24))
	default:
		return fmt.Sprintf("%s (in %d days)", t.Format("2006-01-02"), int(left.Hours()/24))
	}
}

func githubDiscover(ctx context.Context, st store.Store, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("github discover", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	collab := fs.Bool("include-collaborator", false, "also scan repositories the account only collaborates on")
	forks := fs.Bool("include-forks", false, "also scan forks")
	maxMB := fs.Int("max-size-mb", 1024, "skip repositories larger than this")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%v\n%s", err, githubUsage)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("github discover takes only flags\n%s", githubUsage)
	}

	o := orchestrator.New(st, nil, orchestrator.NewRateBudget(0), orchestrator.Config{})
	o.Clock = now
	who := currentUser()
	if who == "" {
		who = "vfctl"
	}
	stats, err := o.Discover(ctx, newGitHub(), gh.DiscoverOptions{
		IncludeCollaborator: *collab, IncludeForks: *forks, MaxSizeMB: *maxMB,
	}, who)
	if err != nil {
		return err
	}

	rows, err := st.Discovery(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "REPOSITORY\tSTATUS\tWHY")
	for _, r := range rows {
		if r.Account != stats.Account {
			continue
		}
		status := "scan"
		if !r.Included {
			status = "skip"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Name, status, r.Detail)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "\n%s: %d repositories, %d to scan, %d skipped%s. Registry: %d added, %d archived.\n",
		stats.Account, stats.Seen, stats.Included, stats.Seen-stats.Included, skipSummary(stats.Skipped),
		stats.Sync.Added, stats.Sync.Archived)
	return nil
}

func skipSummary(m map[string]int) string {
	if len(m) == 0 {
		return ""
	}
	var parts []string
	for reason, n := range m {
		parts = append(parts, fmt.Sprintf("%d %s", n, strings.ReplaceAll(reason, "_", " ")))
	}
	sort.Strings(parts)
	return " (" + strings.Join(parts, ", ") + ")"
}

func githubStatus(ctx context.Context, st store.Store, out io.Writer) error {
	conns, err := st.GitHubConnections(ctx)
	if err != nil {
		return err
	}
	if len(conns) == 0 {
		fmt.Fprintln(out, "No GitHub account connected. Run: vfctl github connect")
		return nil
	}
	rows, err := st.Discovery(ctx)
	if err != nil {
		return err
	}
	for _, c := range conns {
		fmt.Fprintf(out, "%s (%s token), checked %s by %s\n", c.Account, strings.ReplaceAll(c.Kind, "_", "-"),
			c.CheckedAt.Format("2006-01-02 15:04 MST"), c.CheckedBy)
		fmt.Fprintf(out, "  expires:   %s\n", expiryText(c.ExpiresAt))
		var seen, scan int
		var last time.Time
		for _, r := range rows {
			if r.Account != c.Account {
				continue
			}
			seen++
			if r.Included {
				scan++
			}
			if r.DiscoveredAt.After(last) {
				last = r.DiscoveredAt
			}
		}
		if seen == 0 {
			fmt.Fprintln(out, "  discovery: never run (vfctl github discover)")
			continue
		}
		fmt.Fprintf(out, "  discovery: %s — %d repositories, %d to scan, %d skipped\n",
			last.Format("2006-01-02 15:04 MST"), seen, scan, seen-scan)
	}
	return nil
}

func repoExclude(ctx context.Context, st store.Store, args []string, out io.Writer) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("repo exclude needs a repository name first\n%s", githubUsage)
	}
	name := args[0]
	fs := flag.NewFlagSet("repo exclude", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reason := fs.String("reason", "", "why it is excluded (required)")
	as := fs.String("as", "", "who is excluding it (default: your login)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("repo exclude needs -reason: an exclusion nobody can explain later is indistinguishable from a mistake")
	}
	who := *as
	if who == "" {
		who = currentUser()
	}
	if who == "" {
		return fmt.Errorf("could not tell who you are; pass -as NAME")
	}
	if err := st.SetExclusion(ctx, store.RepoExclusion{Name: name, Reason: *reason, ExcludedBy: who, ExcludedAt: now()}); err != nil {
		return err
	}
	if r, err := st.GetRepo(ctx, name); err == nil && !r.Archived {
		r.Archived = true
		if err := st.UpsertRepo(ctx, r); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "excluded %s (%s), recorded as %s; sweeps no longer plan it\n", name, *reason, who)
	return nil
}

func repoInclude(ctx context.Context, st store.Store, args []string, out io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("repo include takes one repository name\n%s", githubUsage)
	}
	ok, err := st.RemoveExclusion(ctx, args[0])
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s is not excluded", args[0])
	}
	fmt.Fprintf(out, "%s is no longer excluded; the next discovery decides whether it is scanned\n", args[0])
	return nil
}
