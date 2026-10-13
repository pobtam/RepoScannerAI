package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/store"
)

const usage = `commands:
  repo add NAME [-languages go,javascript] [-tier 1|2|3] [-lockfile] [-test-suite]
      Register a repository (-languages required; tier defaults to 3), or
      update one already registered, changing only the flags given; use
      -lockfile=false to clear a flag. NAME is the repository's full name
      (org/repo); a sweep run with -workdir DIR scans DIR/<last element of
      NAME>. Adding an archived repository restores it.
  repo list
      List every registered repository, archived ones included.
  repo remove NAME
      Archive a repository so sweeps no longer plan it. Its history is kept.
  finding pending
      List secrets awaiting a human: suppression proposals from a repository
      allowlist, and secrets removed from the files with rotation unconfirmed.
  finding confirm-suppression FINGERPRINT [-as NAME]
  finding reject-suppression FINGERPRINT [-as NAME]
      Decide a suppression proposal. Recorded as NAME (default: your login).
  finding confirm-rotation FINGERPRINT [-as NAME]
      Record that a secret removed from the files has been rotated, which
      closes it. Removal alone never does.`

// knownLanguages are the languages the scanner registry selects adapters for.
// A language outside this set would register cleanly and then match no
// adapter, so every sweep would report the repository scanned with nothing
// having looked at it.
var knownLanguages = map[string]bool{
	string(scan.LangGo):         true,
	string(scan.LangJavaScript): true,
}

// Exec runs one vfctl command against st. It is separate from main so the
// commands are tested against the in-memory store.
func Exec(ctx context.Context, st store.Store, args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "finding" {
		return findingCommand(ctx, st, args[1:], out)
	}
	if len(args) == 0 || args[0] != "repo" {
		return fmt.Errorf("unknown command %q\n%s", strings.Join(args, " "), usage)
	}
	if len(args) < 2 {
		return fmt.Errorf("repo needs a subcommand\n%s", usage)
	}
	switch args[1] {
	case "add":
		return repoAdd(ctx, st, args[2:], out)
	case "list":
		if len(args) > 2 {
			return fmt.Errorf("repo list takes no arguments")
		}
		return repoList(ctx, st, out)
	case "remove":
		return repoRemove(ctx, st, args[2:], out)
	default:
		return fmt.Errorf("unknown repo subcommand %q\n%s", args[1], usage)
	}
}

func repoAdd(ctx context.Context, st store.Store, args []string, out io.Writer) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("repo add needs a repository name first, e.g. repo add org/api -languages go")
	}
	name := args[0]
	if err := validName(name); err != nil {
		return err
	}

	fs := flag.NewFlagSet("repo add", flag.ContinueOnError)
	fs.SetOutput(out)
	languages := fs.String("languages", "", "comma-separated languages: go, javascript (required)")
	// 3 is the specification's default tier for an unclassified repository.
	tier := fs.Int("tier", 3, "repository tier: 1, 2 or 3")
	lockfile := fs.Bool("lockfile", false, "the repository commits a dependency lockfile (enables npm audit)")
	testSuite := fs.Bool("test-suite", false, "the repository has an executable test suite")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments %q; flags go after the name", fs.Args())
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	// Fields vfctl does not set — code owners, module topology — belong to
	// whoever did set them, so an update keeps them.
	repo, err := st.GetRepo(ctx, name)
	verb := "updated"
	isNew := errors.Is(err, store.ErrNotFound)
	if isNew {
		repo, verb = store.Repo{Name: name}, "added"
	} else if err != nil {
		return err
	} else if repo.Archived {
		verb = "restored"
	}

	// A new repository takes every flag, defaults included. An update changes
	// only the flags given: re-running add to switch on -lockfile must not
	// quietly reset a tier-1 repository to the default tier 3.
	if isNew || set["languages"] {
		langs, err := parseLanguages(*languages)
		if err != nil {
			return err
		}
		repo.Languages = langs
	}
	if isNew || set["tier"] {
		if *tier < 1 || *tier > 3 {
			return fmt.Errorf("tier must be 1, 2 or 3, got %d", *tier)
		}
		repo.Tier = *tier
	}
	if isNew || set["lockfile"] {
		repo.HasLockfile = *lockfile
	}
	if isNew || set["test-suite"] {
		repo.HasTestSuite = *testSuite
	}
	repo.Archived = false

	if err := st.UpsertRepo(ctx, repo); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s %s (tier %d, %s)\n", verb, name, repo.Tier, strings.Join(repo.Languages, ","))
	return nil
}

func repoList(ctx context.Context, st store.Store, out io.Writer) error {
	names, err := st.RepoNames(ctx)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		fmt.Fprintln(out, "no repositories registered; add one with: vfctl repo add org/repo -languages go")
		return nil
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTIER\tLANGUAGES\tLOCKFILE\tTEST SUITE\tSTATUS")
	for _, n := range names {
		r, err := st.GetRepo(ctx, n)
		if err != nil {
			return err
		}
		status := "active"
		if r.Archived {
			status = "archived"
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n",
			r.Name, r.Tier, strings.Join(r.Languages, ","), yesNo(r.HasLockfile), yesNo(r.HasTestSuite), status)
	}
	return w.Flush()
}

// repoRemove archives rather than deletes. Runs, scan results and findings
// reference the repository by name, so deleting it would either be refused by
// the database or leave history nobody can look up. Archiving takes it out of
// every future sweep's plan and keeps the record — the same choice SyncFleet
// makes for a repository GitHub no longer lists.
func repoRemove(ctx context.Context, st store.Store, args []string, out io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("repo remove takes exactly one repository name")
	}
	name := args[0]
	repo, err := st.GetRepo(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("%s is not registered", name)
	}
	if err != nil {
		return err
	}
	if repo.Archived {
		fmt.Fprintf(out, "%s is already archived\n", name)
		return nil
	}
	repo.Archived = true
	if err := st.UpsertRepo(ctx, repo); err != nil {
		return err
	}
	fmt.Fprintf(out, "archived %s; sweeps will no longer scan it, and its history is kept\n", name)
	return nil
}

func validName(name string) error {
	if name == "" || strings.ContainsAny(name, " \t\n") ||
		strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.Contains(name, "..") {
		return fmt.Errorf("invalid repository name %q; use the full name, e.g. org/api", name)
	}
	return nil
}

func parseLanguages(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("-languages is required (go, javascript); a repository with none matches no scanner")
	}
	seen := map[string]bool{}
	var out []string
	for _, l := range strings.Split(s, ",") {
		l = strings.ToLower(strings.TrimSpace(l))
		if l == "" || seen[l] {
			continue
		}
		if !knownLanguages[l] {
			return nil, fmt.Errorf("unknown language %q; supported: go, javascript", l)
		}
		seen[l] = true
		out = append(out, l)
	}
	sort.Strings(out)
	return out, nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
