package orchestrator_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/gh/ghfake"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/orchestrator"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/store"
)

// probe is a scanner that records what it was shown: the files in the tree it
// was pointed at, and the languages the profile carried. It finds nothing.
type probe struct {
	mu   sync.Mutex
	seen map[string]probeSaw // keyed by the repository part of the dir
}

type probeSaw struct {
	files []string
}

func (p *probe) Name() string                                         { return "probe" }
func (p *probe) Version() string                                      { return "v0" }
func (p *probe) Supports(scan.RepoProfile) bool                       { return true }
func (p *probe) Normalize(scan.RawOutput) ([]model.RawFinding, error) { return nil, nil }
func (p *probe) Run(_ context.Context, dir string, _ scan.RunOpts) (scan.RawOutput, error) {
	var files []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, path)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(files)
	p.mu.Lock()
	p.seen[filepath.Base(filepath.Dir(dir))+"/"+filepath.Base(dir)] = probeSaw{files: files}
	p.mu.Unlock()
	return scan.RawOutput{Tool: "probe", ToolVersion: "v0"}, nil
}

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// End to end, against a local GitHub: a token is connected, its account's
// repositories discovered and classified, the registry synced, and a sweep
// downloads, scans and deletes each included repository, with no clone made
// by hand and no write sent to GitHub.
func TestConnectDiscoverDownloadSweep(t *testing.T) {
	run(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()

		goRepo := tree(t, map[string]string{"go.mod": "module example.com/api\n\ngo 1.24\n", "main.go": "package main\n"})
		jsRepo := tree(t, map[string]string{"package.json": "{}\n", "package-lock.json": "{}\n", "src/index.js": "x\n"})
		fake := ghfake.New("octo", "fake-token",
			ghfake.Repo{FullName: "octo/api", SizeKB: 10, Language: "Go", Dir: goRepo},
			ghfake.Repo{FullName: "acme/web", OwnerType: "Organization", SizeKB: 10, Language: "JavaScript", Dir: jsRepo},
			ghfake.Repo{FullName: "octo/broken", SizeKB: 10}, // no Dir: its download fails
			ghfake.Repo{FullName: "octo/old", SizeKB: 10, Archived: true, Dir: goRepo},
			ghfake.Repo{FullName: "friend/tool", SizeKB: 10, Dir: goRepo},
		)
		defer fake.Close()
		client := &gh.TokenClient{
			BaseURL: fake.URL, HTTP: fake.Client(),
			Token: func() (string, error) { return "fake-token", nil },
		}

		p := &probe{seen: map[string]probeSaw{}}
		reg, err := scan.NewRegistry(p)
		if err != nil {
			t.Fatal(err)
		}
		root := t.TempDir()
		disp := &orchestrator.DownloadDispatcher{Worker: scan.NewWorker(reg), GitHub: client, Root: root}
		o := newOrchestrator(s, disp, orchestrator.NewRateBudget(100), orchestrator.Config{MaxConcurrentScans: 2, CreditsPerScan: 1})

		stats, err := o.Discover(ctx, client, gh.DiscoverOptions{}, "tester")
		if err != nil {
			t.Fatal(err)
		}
		if stats.Account != "octo" || stats.Seen != 5 || stats.Included != 3 {
			t.Fatalf("discovery = %+v", stats)
		}
		if stats.Skipped[gh.SkipArchived] != 1 || stats.Skipped[gh.SkipCollaborator] != 1 {
			t.Errorf("skips = %v", stats.Skipped)
		}

		// The connection is recorded, never the token.
		conns, _ := s.GitHubConnections(ctx)
		if len(conns) != 1 || conns[0].Account != "octo" || conns[0].CheckedBy != "tester" {
			t.Errorf("connections = %+v", conns)
		}
		discovered, _ := s.Discovery(ctx)
		if len(discovered) != 5 {
			t.Errorf("discovered %d, want all 5 with their decisions", len(discovered))
		}

		// The registry holds the included repositories, active.
		names, _ := s.RepoNames(ctx)
		if strings.Join(names, ",") != "acme/web,octo/api,octo/broken" {
			t.Fatalf("registry = %v", names)
		}
		var repos []store.Repo
		for _, n := range names {
			r, _ := s.GetRepo(ctx, n)
			repos = append(repos, r)
		}

		if _, err := o.Sweep(ctx, store.KindSweep, "test", repos, orchestrator.DefaultSelector); err != nil {
			t.Fatal(err)
		}

		// Each included repository that downloaded was scanned from its own
		// unpacked tree, without GitHub's top-level directory.
		if got := strings.Join(p.seen["octo/api"].files, ","); got != "go.mod,main.go" {
			t.Errorf("octo/api scanned %q", got)
		}
		if got := strings.Join(p.seen["acme/web"].files, ","); got != "package-lock.json,package.json,src/index.js" {
			t.Errorf("acme/web scanned %q", got)
		}

		// The one that could not be downloaded is a coverage gap with a
		// cause, not a missing row and not a clean scan.
		res, _ := s.ScanResults(ctx, "octo/broken", 1)
		if len(res) != 1 || res[0].Outcome != model.ScanFailed || res[0].FailureCause != "download_failed" {
			t.Errorf("octo/broken scan result = %+v", res)
		}
		for _, n := range []string{"octo/api", "acme/web"} {
			res, _ := s.ScanResults(ctx, n, 1)
			if len(res) != 1 || res[0].Outcome != model.ScanComplete {
				t.Errorf("%s scan result = %+v", n, res)
			}
		}

		// Trees are deleted after scanning: the clone cache holds private
		// code, so it holds it only while it is being scanned.
		left, _ := os.ReadDir(root)
		for _, e := range left {
			sub, _ := os.ReadDir(filepath.Join(root, e.Name()))
			if len(sub) > 0 {
				t.Errorf("left behind after the sweep: %s/%v", e.Name(), sub)
			}
		}

		if refused := fake.Refused(); len(refused) != 0 {
			t.Errorf("something tried to write to GitHub: %v", refused)
		}

		// A later discovery in which an included repository is now skipped
		// archives it; nothing is deleted.
		if err := s.SetExclusion(ctx, store.RepoExclusion{Name: "octo/broken", Reason: "test", ExcludedBy: "tester", ExcludedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if _, err := o.Discover(ctx, client, gh.DiscoverOptions{}, "tester"); err != nil {
			t.Fatal(err)
		}
		broken, err := s.GetRepo(ctx, "octo/broken")
		if err != nil || !broken.Archived {
			t.Errorf("an excluded repository is %+v, %v; want archived and kept", broken, err)
		}
	})
}

// The languages a sweep scans with come from the downloaded tree, not from
// GitHub's single-language guess at discovery.
func TestDownloadedTreeDecidesTheLanguages(t *testing.T) {
	both := tree(t, map[string]string{"go.mod": "module x\n", "package.json": "{}\n"})
	fake := ghfake.New("octo", "fake-token", ghfake.Repo{FullName: "octo/mixed", SizeKB: 1, Language: "Python", Dir: both})
	defer fake.Close()
	client := &gh.TokenClient{BaseURL: fake.URL, HTTP: fake.Client(), Token: func() (string, error) { return "fake-token", nil }}

	var got scan.RepoProfile
	capture := &captureAdapter{onRun: func(p scan.RepoProfile) { got = p }}
	reg, _ := scan.NewRegistry(capture)
	disp := &orchestrator.DownloadDispatcher{Worker: scan.NewWorker(reg), GitHub: client, Root: t.TempDir()}

	_, err := disp.Dispatch(context.Background(), orchestrator.Job{
		RunID: "S-1", Repo: "octo/mixed",
		Profile: scan.RepoProfile{Repo: "octo/mixed", Languages: []scan.Language{"python"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Languages) != 2 || got.Languages[0] != scan.LangGo || got.Languages[1] != scan.LangJavaScript {
		t.Errorf("scanned as %v, want [go javascript] from the tree", got.Languages)
	}
}

// captureAdapter records the profile its Supports was asked about.
type captureAdapter struct{ onRun func(scan.RepoProfile) }

func (c *captureAdapter) Name() string    { return "capture" }
func (c *captureAdapter) Version() string { return "v0" }
func (c *captureAdapter) Supports(p scan.RepoProfile) bool {
	c.onRun(p)
	return true
}
func (c *captureAdapter) Run(context.Context, string, scan.RunOpts) (scan.RawOutput, error) {
	return scan.RawOutput{Tool: "capture"}, nil
}
func (c *captureAdapter) Normalize(scan.RawOutput) ([]model.RawFinding, error) { return nil, nil }

// A tarball that tries to write outside its tree is refused as a whole.
func TestATarballEscapingItsTreeIsRefused(t *testing.T) {
	dir := tree(t, map[string]string{"ok.txt": "fine\n"})
	b, err := ghfake.Tarball("octo-evil-0123abc", dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"octo-evil-0123abc/../../escaped.txt", // cleans to ../escaped.txt
		"octo-evil-0123abc/sub/../../../escaped.txt",
		"../escaped.txt",
		"/tmp/escaped.txt",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			disp := &orchestrator.DownloadDispatcher{
				Worker: scan.NewWorker(mustRegistry(t, &probe{seen: map[string]probeSaw{}})),
				GitHub: staticDownloader(withEntry(t, b, name, "pwned\n")), Root: filepath.Join(root, "work"),
			}
			_ = os.MkdirAll(disp.Root, 0o755)
			res, err := disp.Dispatch(context.Background(), orchestrator.Job{RunID: "S-1", Repo: "octo/evil"})
			if err != nil {
				t.Fatal(err)
			}
			if res.Outcome != model.ScanFailed || len(res.Gaps) != 1 || !strings.Contains(res.Gaps[0].Detail, "unsafe path") {
				t.Errorf("result = %+v, want a download_failed gap naming the unsafe path", res)
			}
			for _, p := range []string{filepath.Join(root, "escaped.txt"), filepath.Join(root, "work", "escaped.txt"), filepath.Join(root, "work", "octo", "escaped.txt")} {
				if _, err := os.Stat(p); err == nil {
					t.Fatalf("a tarball entry was written outside the tree: %s", p)
				}
			}
		})
	}
}

// A symlink in a repository is not recreated: following one out of the tree
// during a scan would read the scanner's own filesystem.
func TestSymlinksInATarballAreNotRecreated(t *testing.T) {
	dir := tree(t, map[string]string{"ok.txt": "fine\n"})
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
		t.Skip("cannot create a symlink here:", err)
	}
	b, err := ghfake.Tarball("octo-links-0123abc", dir)
	if err != nil {
		t.Fatal(err)
	}
	p := &probe{seen: map[string]probeSaw{}}
	disp := &orchestrator.DownloadDispatcher{
		Worker: scan.NewWorker(mustRegistry(t, p)), GitHub: staticDownloader(b), Root: t.TempDir(),
	}
	if _, err := disp.Dispatch(context.Background(), orchestrator.Job{RunID: "S-1", Repo: "octo/links"}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.seen["octo/links"].files, ","); got != "ok.txt" {
		t.Errorf("scanned %q, want only ok.txt", got)
	}
}

type staticDownloader []byte

func (s staticDownloader) Download(_ context.Context, _, _ string, w io.Writer, _ int64) (int64, error) {
	n, err := w.Write(s)
	return int64(n), err
}

// withEntry returns the gzipped tarball b with one more regular file added.
func withEntry(t *testing.T, b []byte, name, body string) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(tw, tr); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func mustRegistry(t *testing.T, a scan.Adapter) *scan.Registry {
	t.Helper()
	r, err := scan.NewRegistry(a)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
