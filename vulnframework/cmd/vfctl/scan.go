package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/wanaware/vulnframework/internal/store"
)

// vfctl scan: request scans from the terminal, list them, and the timer's
// enqueue. Like the interface, these only insert into the scan queue; the
// scan worker runs them. None of them needs the GitHub token.

const scanUsage = `  scan request NAME [-as NAME]
      Queue a scan of one registered repository. If it is already queued or
      running, the existing request is shown instead (requests merge).
      Excluded, skipped and archived repositories are refused with the reason.
  scan list [-repo NAME] [-limit N]
      Recent scan requests and their status, newest first.
  scan enqueue -all [-source vfctl|timer] [-as NAME]
      Queue every included repository as one batch. The daily timer runs this
      with -source timer; the scan worker runs the batch as one sweep.`

func scanCommand(ctx context.Context, st store.Store, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("scan needs a subcommand\n%s", scanUsage)
	}
	switch args[0] {
	case "request":
		return scanRequest(ctx, st, args[1:], out)
	case "list":
		return scanList(ctx, st, args[1:], out)
	case "enqueue":
		return scanEnqueue(ctx, st, args[1:], out)
	default:
		return fmt.Errorf("unknown scan subcommand %q\n%s", args[0], scanUsage)
	}
}

func whoFrom(as string) (string, error) {
	if as != "" {
		return as, nil
	}
	if u := currentUser(); u != "" {
		return u, nil
	}
	return "", fmt.Errorf("could not tell who you are; pass -as NAME so the request is recorded against a person")
}

func scanRequest(ctx context.Context, st store.Store, args []string, out io.Writer) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("scan request needs a repository name first\n%s", scanUsage)
	}
	name := args[0]
	fs := flag.NewFlagSet("scan request", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	as := fs.String("as", "", "who is requesting (default: your login)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	who, err := whoFrom(*as)
	if err != nil {
		return err
	}
	if why, err := store.ScanRefusal(ctx, st, name); err != nil {
		return err
	} else if why != "" {
		_, _, _ = st.EnqueueScan(ctx, store.ScanRequest{
			ID: store.NewScanRequestID(now()), Repo: name, Source: store.SourceVfctl, RequestedBy: who,
			RequestedAt: now(), Status: store.ScanRefused, Reason: why,
		})
		return fmt.Errorf("%s is not scanned: %s", name, why)
	}
	got, merged, err := st.EnqueueScan(ctx, store.ScanRequest{
		ID: store.NewScanRequestID(now()), Repo: name, Source: store.SourceVfctl, RequestedBy: who,
		RequestedAt: now(), Status: store.ScanQueued,
	})
	if err != nil {
		return err
	}
	if merged {
		fmt.Fprintf(out, "%s already has a %s scan request (%s, by %s); not queued twice\n", name, got.Status, got.ID, got.RequestedBy)
		return nil
	}
	fmt.Fprintf(out, "queued %s for %s; the scan worker runs it next (vfctl scan list to follow it)\n", got.ID, name)
	return nil
}

func scanList(ctx context.Context, st store.Store, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("scan list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	repo := fs.String("repo", "", "only this repository")
	limit := fs.Int("limit", 20, "how many")
	if err := fs.Parse(args); err != nil {
		return err
	}
	list, err := st.ScanRequests(ctx, store.ScanQuery{Repo: *repo, Limit: *limit})
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintln(out, "No scan requests.")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "REQUESTED\tREPOSITORY\tSTATUS\tRUN\tBY\tWHY")
	for _, r := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.RequestedAt.Format("2006-01-02 15:04"), r.Repo,
			strings.ReplaceAll(string(r.Status), "_", " "), dash(r.RunID), r.RequestedBy, dash(r.Reason))
	}
	return tw.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func scanEnqueue(ctx context.Context, st store.Store, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("scan enqueue", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	all := fs.Bool("all", false, "every included repository")
	source := fs.String("source", "vfctl", "vfctl or timer")
	as := fs.String("as", "", "who is requesting (default: your login, or \"timer\")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*all {
		return fmt.Errorf("scan enqueue needs -all (to queue one repository, use scan request)\n%s", scanUsage)
	}
	src := store.ScanSource(*source)
	if src != store.SourceVfctl && src != store.SourceTimer {
		return fmt.Errorf("-source must be vfctl or timer")
	}
	who := *as
	if who == "" && src == store.SourceTimer {
		who = "timer"
	}
	who, err := whoFrom(who)
	if err != nil {
		return err
	}
	names, err := st.RepoNames(ctx)
	if err != nil {
		return err
	}
	batch := "batch_" + store.NewScanRequestID(now())[3:]
	queued, merged := 0, 0
	for _, name := range names {
		repo, err := st.GetRepo(ctx, name)
		if err != nil {
			return err
		}
		if repo.Archived {
			continue
		}
		_, m, err := st.EnqueueScan(ctx, store.ScanRequest{
			ID: store.NewScanRequestID(now()), Repo: name, BatchID: batch, Source: src,
			RequestedBy: who, RequestedAt: now(), Status: store.ScanQueued,
		})
		if err != nil {
			return err
		}
		if m {
			merged++
		} else {
			queued++
		}
	}
	fmt.Fprintf(out, "batch %s: %d queued, %d already queued or running\n", batch, queued, merged)
	return nil
}
