package scan_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/scan"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGitHeadReadsEveryLayout(t *testing.T) {
	sha := strings.Repeat("ab", 20)
	for name, files := range map[string]map[string]string{
		"detached": {".git/HEAD": sha + "\n"},
		"branch":   {".git/HEAD": "ref: refs/heads/main\n", ".git/refs/heads/main": sha + "\n"},
		"packed": {".git/HEAD": "ref: refs/heads/main\n",
			".git/packed-refs": "# pack-refs with: peeled fully-peeled sorted\n" + sha + " refs/heads/main\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for p, b := range files {
				write(t, filepath.Join(dir, p), b)
			}
			if got, err := scan.GitHead(dir); err != nil || got != sha {
				t.Errorf("GitHead = %q, %v", got, err)
			}
		})
	}
	t.Run("worktree", func(t *testing.T) {
		root := t.TempDir()
		main := filepath.Join(root, "main", ".git")
		write(t, filepath.Join(main, "refs", "heads", "feature"), sha+"\n")
		wt := filepath.Join(main, "worktrees", "feature")
		write(t, filepath.Join(wt, "HEAD"), "ref: refs/heads/feature\n")
		write(t, filepath.Join(wt, "commondir"), "../..\n")
		checkout := filepath.Join(root, "feature")
		write(t, filepath.Join(checkout, ".git"), "gitdir: "+wt+"\n")
		if got, err := scan.GitHead(checkout); err != nil || got != sha {
			t.Errorf("GitHead = %q, %v", got, err)
		}
	})
	t.Run("no .git", func(t *testing.T) {
		if _, err := scan.GitHead(t.TempDir()); !errors.Is(err, scan.ErrNoCommit) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("not a commit", func(t *testing.T) {
		dir := t.TempDir()
		write(t, filepath.Join(dir, ".git", "HEAD"), "garbage\n")
		if _, err := scan.GitHead(dir); err == nil {
			t.Error("garbage was accepted as a commit")
		}
	})
}

// Against a real repository, when git is installed: the same answer as git.
func TestGitHeadAgreesWithGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com", "GIT_CONFIG_GLOBAL=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "-b", "main")
	write(t, filepath.Join(dir, "a.txt"), "a\n")
	run("add", "a.txt")
	run("commit", "-q", "-m", "one")
	run("pack-refs", "--all")
	want := run("rev-parse", "HEAD")
	if got, err := scan.GitHead(dir); err != nil || got != want {
		t.Errorf("GitHead = %q, %v; git says %q", got, err, want)
	}
}
