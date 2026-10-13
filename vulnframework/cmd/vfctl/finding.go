package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os/user"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// now is the clock decisions are recorded against; tests replace it.
var now = func() time.Time { return time.Now().UTC() }

// currentUser names the human a decision is recorded as, unless -as says
// otherwise.
var currentUser = func() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return ""
}

func findingCommand(ctx context.Context, st store.Store, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("finding needs a subcommand\n%s", usage)
	}
	switch args[0] {
	case "pending":
		if len(args) > 1 {
			return fmt.Errorf("finding pending takes no arguments")
		}
		return findingPending(ctx, st, out)
	case "confirm-suppression", "reject-suppression", "confirm-rotation":
		return findingDecision(ctx, st, args[0], args[1:], out)
	default:
		return fmt.Errorf("unknown finding subcommand %q\n%s", args[0], usage)
	}
}

func findingDecision(ctx context.Context, st store.Store, verb string, args []string, out io.Writer) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("finding %s needs a fingerprint first; see: vfctl finding pending", verb)
	}
	fp := args[0]
	fs := flag.NewFlagSet("finding "+verb, flag.ContinueOnError)
	fs.SetOutput(out)
	as := fs.String("as", currentUser(), "the human this decision is recorded as")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	by := strings.TrimSpace(*as)
	if by == "" {
		return fmt.Errorf("could not tell who you are; pass -as NAME so the decision is recorded against a person")
	}

	switch verb {
	case "confirm-suppression":
		if err := st.DecideSuppression(ctx, fp, true, by, now()); err != nil {
			return err
		}
		fmt.Fprintf(out, "suppressed %s, recorded as %s\n", fp, by)
	case "reject-suppression":
		if err := st.DecideSuppression(ctx, fp, false, by, now()); err != nil {
			return err
		}
		fmt.Fprintf(out, "rejected the suppression proposal for %s, recorded as %s; it stays open and will not be re-proposed while the allowlist is unchanged\n", fp, by)
	case "confirm-rotation":
		if err := st.ConfirmRotation(ctx, fp, by, now()); err != nil {
			return err
		}
		fmt.Fprintf(out, "recorded rotation of %s by %s; the finding is verified\n", fp, by)
	}
	return nil
}

// findingPending lists the secrets waiting on a human, oldest first.
func findingPending(ctx context.Context, st store.Store, out io.Writer) error {
	open, err := st.ListFindings(ctx, store.Query{Scope: store.ScopeOpen, Categories: []model.Category{model.CategorySecret}})
	if err != nil {
		return err
	}
	type row struct {
		since                         time.Time
		fp, repo, file, waiting, note string
	}
	var rows []row
	for _, f := range open {
		file := ""
		if f.Location.File != nil {
			file = *f.Location.File
		}
		if p := f.SuppressionProposal; p != nil && p.Status.Open() {
			note := fmt.Sprintf("%s %s", p.Mechanism, p.Path)
			if p.Description != "" {
				note += fmt.Sprintf(" (%s)", p.Description)
			}
			rows = append(rows, row{p.ProposedAt, f.Fingerprint, f.Repo, file, "suppression " + string(p.Status), note})
		}
		if r := f.RemovedUnrotated; r != nil {
			rows = append(rows, row{r.At, f.Fingerprint, f.Repo, file, "rotation unconfirmed", "left the files in " + r.Run})
		}
	}
	if len(rows) == 0 {
		fmt.Fprintln(out, "nothing is waiting on a human")
		return nil
	}
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].since.Equal(rows[j].since) {
			return rows[i].since.Before(rows[j].since)
		}
		return rows[i].fp < rows[j].fp
	})
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FINGERPRINT\tREPO\tFILE\tWAITING FOR\tSINCE\tEVIDENCE")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.fp, r.repo, r.file, r.waiting, r.since.Format(time.RFC3339), r.note)
	}
	return w.Flush()
}
