package orchestrator

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/store"
)

// Account mode: one GitHub token, every repository it reaches.
//
// Discover asks GitHub what the token's account can see, decides what is
// scanned, records both, and brings the registry into line through
// SyncFleet. DownloadDispatcher then fetches each planned repository as a
// tarball, scans it, and deletes it. Nobody clones anything by hand, and
// nothing in this path can write to GitHub: the client sends only GET.

// GitHubAccount is what discovery needs from GitHub.
type GitHubAccount interface {
	Connect(ctx context.Context) (gh.Connection, error)
	AccountRepos(ctx context.Context) ([]gh.AccountRepo, error)
}

// DiscoverStats summarises one discovery.
type DiscoverStats struct {
	Account  string         `json:"account"`
	Seen     int            `json:"seen"`
	Included int            `json:"included"`
	Skipped  map[string]int `json:"skipped,omitempty"`
	Sync     FleetSyncStats `json:"sync"`
}

// Discover connects, lists, classifies, records, and syncs the registry. by
// names who ran it, for the connection record.
//
// The discovered list is recorded BEFORE the registry is synced, so that if
// the sync refuses (an empty fleet, which would archive everything) the
// reason is still visible in the list.
func (o *Orchestrator) Discover(ctx context.Context, account GitHubAccount, opts gh.DiscoverOptions, by string) (DiscoverStats, error) {
	var stats DiscoverStats
	now := o.clock()

	conn, err := account.Connect(ctx)
	if err != nil {
		return stats, fmt.Errorf("orchestrator: connecting to GitHub: %w", err)
	}
	stats.Account = conn.Account
	if err := o.Store.SaveGitHubConnection(ctx, store.GitHubConnection{
		Account: conn.Account, Kind: conn.Kind, Scopes: conn.Scopes, ExpiresAt: conn.ExpiresAt,
		ReadOnly: conn.ReadOnly, CheckedAt: now, CheckedBy: by,
	}); err != nil {
		return stats, err
	}

	repos, err := account.AccountRepos(ctx)
	if err != nil {
		return stats, fmt.Errorf("orchestrator: listing %s's repositories: %w", conn.Account, err)
	}

	exclusions, err := o.Store.Exclusions(ctx)
	if err != nil {
		return stats, err
	}
	if opts.Excluded == nil {
		opts.Excluded = map[string]string{}
	}
	for _, e := range exclusions {
		opts.Excluded[e.Name] = e.Reason
	}

	decided := gh.Classify(conn.Account, repos, opts)
	rows := make([]store.DiscoveredRepo, 0, len(decided))
	stats.Skipped = map[string]int{}
	for _, d := range decided {
		stats.Seen++
		if d.Included {
			stats.Included++
		} else {
			stats.Skipped[d.Reason]++
		}
		rows = append(rows, store.DiscoveredRepo{
			Name: d.Repo.FullName, Account: conn.Account, Affiliation: string(d.Affiliation),
			Private: d.Repo.Private, Archived: d.Repo.Archived, Fork: d.Repo.Fork, SizeKB: d.Repo.SizeKB,
			DefaultBranch: d.Repo.DefaultBranch, Language: d.Repo.Language,
			Included: d.Included, Reason: d.Reason, Detail: d.Detail, DiscoveredAt: now,
		})
	}
	if err := o.Store.ReplaceDiscovery(ctx, conn.Account, rows); err != nil {
		return stats, err
	}

	if stats.Seen > 0 && stats.Included == 0 {
		// GitHub listed repositories and every one was skipped, each with a
		// recorded reason. That is a decision, not the empty listing that
		// SyncFleet refuses (a revoked token and a lost page look the same as
		// "no repositories"), so the registry follows it: everything active is
		// archived, nothing is deleted.
		stats.Sync, err = o.archiveAll(ctx)
		return stats, err
	}
	stats.Sync, err = o.SyncFleet(ctx, gh.IncludedRepos(decided))
	return stats, err
}

func (o *Orchestrator) archiveAll(ctx context.Context) (FleetSyncStats, error) {
	var stats FleetSyncStats
	names, err := o.Store.RepoNames(ctx)
	if err != nil {
		return stats, err
	}
	for _, n := range names {
		r, err := o.Store.GetRepo(ctx, n)
		if err != nil {
			return stats, err
		}
		if r.Archived {
			continue
		}
		r.Archived = true
		if err := o.Store.UpsertRepo(ctx, r); err != nil {
			return stats, err
		}
		stats.Archived++
	}
	return stats, nil
}

// Downloader fetches a repository's tarball.
type Downloader interface {
	Download(ctx context.Context, repo, ref string, w io.Writer, maxBytes int64) (int64, error)
}

// CommitResolver resolves a repository's default branch to a commit. A
// Downloader that is also one (gh.TokenClient) has the tarball fetched at
// that commit, and the commit recorded on the scan, so every adapter, local
// or remote, scans the same tree.
type CommitResolver interface {
	HeadCommit(ctx context.Context, repo string) (string, error)
}

// DownloadDispatcher downloads each repository, scans it, and deletes it.
type DownloadDispatcher struct {
	Worker *scan.Worker
	GitHub Downloader
	// Root is where trees are unpacked, one directory per repository,
	// removed after its scan.
	Root string
	// MaxDownloadBytes caps the compressed tarball; MaxTreeBytes and
	// MaxFiles cap what it unpacks to. Zero means 512 MB, 4 GB and 200,000.
	MaxDownloadBytes int64
	MaxTreeBytes     int64
	MaxFiles         int
}

var _ Dispatcher = (*DownloadDispatcher)(nil)

// Dispatch downloads, unpacks, scans and deletes one repository.
//
// A download that fails is a coverage gap with cause download_failed, never
// a clean result and never a dropped repository: the run records that the
// repository was planned and not scanned, and why.
func (d *DownloadDispatcher) Dispatch(ctx context.Context, job Job) (scan.Result, error) {
	dir := filepath.Join(d.Root, filepath.FromSlash(job.Repo))
	if rel, err := filepath.Rel(d.Root, dir); err != nil || strings.HasPrefix(rel, "..") || !strings.Contains(job.Repo, "/") {
		return scan.Result{}, fmt.Errorf("orchestrator: %q is not a repository name this dispatcher can place", job.Repo)
	}
	defer os.RemoveAll(dir)

	// The commit first, then the tarball at that commit: a push between the
	// two would otherwise give the scan a tree that is not the commit it
	// records.
	ref := ""
	if cr, ok := d.GitHub.(CommitResolver); ok {
		sha, err := cr.HeadCommit(ctx, job.Repo)
		if err != nil {
			return downloadGap(job, dir, fmt.Errorf("resolving the head commit: %w", err)), nil
		}
		ref = sha
		job.Opts.CommitSHA = sha
	}
	if err := d.fetch(ctx, job.Repo, ref, dir); err != nil {
		return downloadGap(job, dir, err), nil
	}

	profile := job.Profile
	if langs, lockfile := rootLanguages(dir); len(langs) > 0 {
		// What is actually in the tree outranks what GitHub guessed at
		// discovery: the registry's languages for an account-mode repository
		// are GitHub's single primary language.
		profile.Languages, profile.HasLockfile = langs, lockfile
	}
	return d.Worker.Scan(ctx, job.RunID, job.Repo, dir, profile, job.Opts)
}

func downloadGap(job Job, dir string, err error) scan.Result {
	return scan.Result{
		RunID: job.RunID, Repo: job.Repo, Dir: dir, CommitSHA: job.Opts.CommitSHA,
		Outcome:     model.ScanFailed,
		ToolsFailed: []string{"download"},
		Gaps: []scan.CoverageGap{{
			Tool: "download", Classification: scan.GapTotal, Cause: "download_failed",
			Detail: err.Error(),
			// A failed download is the platform's to fix (credentials,
			// network, a size limit), not the repository owner's.
			Owner: scan.OwnerPlatform,
		}},
	}
}

func (d *DownloadDispatcher) fetch(ctx context.Context, repo, ref, dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(d.Root, ".download-*.tar.gz")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	maxDownload := d.MaxDownloadBytes
	if maxDownload <= 0 {
		maxDownload = 512 << 20
	}
	if _, err := d.GitHub.Download(ctx, repo, ref, tmp, maxDownload); err != nil {
		return err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return d.unpack(tmp, dir)
}

// errUnsafeEntry rejects a tarball entry that would land outside the tree.
var errUnsafeEntry = errors.New("unsafe path in tarball")

// unpack extracts a GitHub tarball into dir, dropping its single top-level
// directory. Only directories and regular files are written: a symlink or
// hard link in a repository is skipped, because following one out of the
// tree during a scan would read the scanner's own filesystem. Paths that
// would escape dir are refused, and the whole unpack fails past the size or
// file-count cap rather than leaving a partial tree that scans as clean.
func (d *DownloadDispatcher) unpack(r io.Reader, dir string) error {
	maxTree := d.MaxTreeBytes
	if maxTree <= 0 {
		maxTree = 4 << 30
	}
	maxFiles := d.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 200_000
	}

	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("the download is not a gzip tarball: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var written int64
	files := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading the tarball: %w", err)
		}

		// Strip the top-level directory FIRST, then clean what remains.
		// Cleaning first would let "top/../../x" collapse to "../x", whose
		// leading ".." would then be stripped as if it were the top level.
		raw := strings.TrimPrefix(hdr.Name, "./")
		if path.IsAbs(raw) {
			return fmt.Errorf("%w: %s", errUnsafeEntry, hdr.Name)
		}
		top, rest, found := strings.Cut(raw, "/")
		if top == ".." {
			return fmt.Errorf("%w: %s", errUnsafeEntry, hdr.Name)
		}
		if !found || strings.Trim(rest, "/") == "" {
			continue // the top-level directory itself
		}
		rest = path.Clean(rest)
		if path.IsAbs(rest) || rest == ".." || strings.HasPrefix(rest, "../") {
			return fmt.Errorf("%w: %s", errUnsafeEntry, hdr.Name)
		}
		target := filepath.Join(dir, filepath.FromSlash(rest))
		if rel, err := filepath.Rel(dir, target); err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("%w: %s", errUnsafeEntry, hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			files++
			if files > maxFiles {
				return fmt.Errorf("the repository has more than %d files", maxFiles)
			}
			if written+hdr.Size > maxTree {
				return fmt.Errorf("the repository unpacks to more than %d MB", maxTree>>20)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			n, err := io.Copy(f, io.LimitReader(tr, hdr.Size))
			f.Close()
			if err != nil {
				return err
			}
			written += n
		default:
			// Symlinks, hard links, devices: not written (see above).
		}
	}
}

// rootLanguages reads which scanner languages a tree's root declares, and
// whether a JavaScript lockfile is committed.
func rootLanguages(dir string) ([]scan.Language, bool) {
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	var langs []scan.Language
	if exists("go.mod") {
		langs = append(langs, scan.LangGo)
	}
	if exists("package.json") {
		langs = append(langs, scan.LangJavaScript)
	}
	lockfile := exists("package-lock.json") || exists("npm-shrinkwrap.json")
	return langs, lockfile
}
