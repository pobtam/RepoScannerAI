package gotool_test

import (
	"archive/zip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/remediate/gotool"
	"github.com/wanaware/vulnframework/internal/sandbox"
)

// This file is the offline half of the toolchain's tests.
//
// Everything the real toolchain needs — a Go module proxy, a git repository,
// a dependency with two published versions — is built here from source trees
// checked into testdata/toolchain. Nothing reaches the network, nothing needs
// a credential, and nothing touches a repository that is not in this
// repository.
//
// The proxy is a `file://` GOPROXY, which is a documented Go feature rather
// than a trick: the module cache protocol is a directory layout, and building
// one is how a bump can be performed for real with no proxy to talk to.

// shared is the hermetic Go environment every test in this package runs under.
//
// One per package rather than one per test, because a module cache populated
// from scratch for each of twenty tests is twenty times the work for the same
// answer. It is still hermetic: nothing here is the developer's own GOPATH.
var shared struct {
	root     string
	proxyDir string
}

func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "vf-gotool-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "gotool tests: creating the temporary root: %v\n", err)
		os.Exit(1)
	}
	shared.root = root

	proxy, err := buildProxy(filepath.Join(root, "proxy"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "gotool tests: building the module proxy: %v\n", err)
		os.Exit(1)
	}
	shared.proxyDir = proxy

	code := m.Run()

	// -modcacherw is set below so this can succeed; without it the module
	// cache is read-only and the cleanup fails silently, leaving a copy
	// behind after every run.
	if err := os.RemoveAll(root); err != nil {
		fmt.Fprintf(os.Stderr, "gotool tests: cleaning up %s: %v\n", root, err)
	}
	os.Exit(code)
}

// goEnv is the environment the toolchain's commands need, and nothing else.
//
// It is also the sandbox's allowlist, which is the point: these are named one
// by one, so a variable the Go toolchain does not need cannot arrive by
// accident as the worker's environment grows.
func goEnv(t *testing.T) []string {
	t.Helper()

	set := func(k, v string) { t.Setenv(k, v) }
	set("GOPATH", filepath.Join(shared.root, "gopath"))
	set("GOCACHE", filepath.Join(shared.root, "gocache"))
	set("GOMODCACHE", filepath.Join(shared.root, "gomodcache"))
	set("GOPROXY", "file://"+filepath.ToSlash(shared.proxyDir))
	// No checksum database: there is no network, and the proxy is this
	// repository's own testdata. GONOSUMDB and GOPRIVATE are left unset
	// rather than wildcarded, so this is the only thing switched off.
	set("GOSUMDB", "off")
	set("GOFLAGS", "-mod=mod -modcacherw")
	// A pinned toolchain cannot go looking for another one to download.
	set("GOTOOLCHAIN", "local")
	set("HOME", filepath.Join(shared.root, "home"))

	if err := os.MkdirAll(filepath.Join(shared.root, "home"), 0o755); err != nil {
		t.Fatalf("creating the fixture home: %v", err)
	}

	return []string{
		"PATH", "HOME",
		"GOPATH", "GOCACHE", "GOMODCACHE", "GOPROXY", "GOSUMDB", "GOFLAGS", "GOTOOLCHAIN",
	}
}

// fixture copies a checked-in fixture repository into a temporary directory
// and makes it a git repository with one commit.
//
// A copy, because Apply rewrites go.mod: a test that bumped a dependency in
// testdata would leave the next test looking at the result of the last one.
//
// A git repository, because the toolchain reads what the TREE reports as
// changed, and `git status` against no repository reports nothing — which
// would make every guard inspect an empty change set.
func fixture(t *testing.T, name string) string {
	t.Helper()

	// Before anything else: the setup commands below are `go` and `git`, and
	// a `go mod tidy` run before GOPROXY points at the fixture proxy goes
	// looking for example.com on the internet. Calling this here as well as
	// in toolchainFor is harmless — t.Setenv is idempotent — and the
	// alternative is a test suite that passes only on a machine with network
	// access, which is the thing this package is built not to need.
	goEnv(t)

	dir := filepath.Join(t.TempDir(), name)
	src := filepath.Join("..", "..", "..", "testdata", "toolchain", name)
	if err := copyTree(src, dir); err != nil {
		t.Fatalf("copying fixture %s: %v", name, err)
	}

	// go.sum is not checked in: its hashes depend on the proxy built above,
	// and a stale committed hash would fail in a way that looked like a
	// tampered dependency. Materialising it here is what a real clone arrives
	// with already committed.
	if hasRequire(t, dir) {
		runFixtureCmd(t, dir, "go", "mod", "tidy")
	}

	runFixtureCmd(t, dir, "git", "init", "-q", "-b", "main")
	runFixtureCmd(t, dir, "git", "add", "-A")
	runFixtureCmd(t, dir, "git",
		"-c", "user.name=fixture",
		"-c", "user.email=fixture@example.invalid",
		"commit", "-q", "-m", "fixture")

	return dir
}

func hasRequire(t *testing.T, dir string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	return strings.Contains(string(b), "require")
}

// runFixtureCmd runs a setup command outside the sandbox.
//
// Deliberately outside: this is the fixture arriving in the state a real clone
// would already be in, not the thing under test. Nothing asserted anywhere
// depends on it having been confined.
func runFixtureCmd(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture setup %s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// toolchainFor builds a Toolchain confined to dir.
func toolchainFor(t *testing.T, dir string, rescan gotool.Rescanner, extraEnv ...string) *gotool.Toolchain {
	t.Helper()

	allowed := append(goEnv(t), extraEnv...)
	sb := sandbox.NewFake(sandbox.Policy{CloneDir: dir, AllowedEnv: allowed})
	tc, err := gotool.New(sb, rescan)
	if err != nil {
		t.Fatalf("gotool.New: %v", err)
	}
	return tc
}

// --- the module proxy --------------------------------------------------------

// proxyModule is one published release in the fixture proxy.
type proxyModule struct {
	path    string
	version string
	src     string
}

var proxyModules = []proxyModule{
	{"example.com/vulnmod", "v1.0.0", "vulnmod-v1.0.0"},
	{"example.com/vulnmod", "v1.2.0", "vulnmod-v1.2.0"},
	{"example.com/breakmod", "v1.0.0", "breakmod-v1.0.0"},
	{"example.com/breakmod", "v1.1.0", "breakmod-v1.1.0"},
}

// buildProxy writes a GOPROXY-protocol directory tree.
//
// The protocol is four files per version under <module>/@v/: the version
// list, an .info, the .mod, and a .zip whose entries are prefixed
// <module>@<version>/. Building it by hand is what makes `go get` work with
// no network at all.
func buildProxy(root string) (string, error) {
	byModule := map[string][]string{}
	for _, m := range proxyModules {
		dir := filepath.Join(root, filepath.FromSlash(m.path), "@v")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}

		src := filepath.Join("..", "..", "..", "testdata", "toolchain", "proxysrc", m.src)
		mod, err := os.ReadFile(filepath.Join(src, "go.mod"))
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dir, m.version+".mod"), mod, 0o644); err != nil {
			return "", err
		}

		info := fmt.Sprintf(`{"Version":%q,"Time":"2024-01-01T00:00:00Z"}`, m.version)
		if err := os.WriteFile(filepath.Join(dir, m.version+".info"), []byte(info), 0o644); err != nil {
			return "", err
		}
		if err := writeModuleZip(filepath.Join(dir, m.version+".zip"), m.path, m.version, src); err != nil {
			return "", err
		}
		byModule[m.path] = append(byModule[m.path], m.version)
	}

	for path, versions := range byModule {
		sort.Strings(versions)
		list := strings.Join(versions, "\n") + "\n"
		listPath := filepath.Join(root, filepath.FromSlash(path), "@v", "list")
		if err := os.WriteFile(listPath, []byte(list), 0o644); err != nil {
			return "", err
		}
	}
	return root, nil
}

func writeModuleZip(dest, modulePath, version, src string) error {
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		body, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			return err
		}
		w, err := zw.Create(modulePath + "@" + version + "/" + e.Name())
		if err != nil {
			return err
		}
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return zw.Close()
}

// --- small file helpers ------------------------------------------------------

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, body, 0o644)
	})
}

// snapshot reads every file in a tree, so a test can assert that an operation
// changed nothing. The git directory is excluded: reading an index is not
// reading the tree, and git rewrites its own bookkeeping for reasons that have
// nothing to do with the working copy.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		out[filepath.ToSlash(rel)] = string(body)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshotting %s: %v", dir, err)
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
