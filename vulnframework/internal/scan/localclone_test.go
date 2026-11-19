package scan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGitHubRepoFromGitConfig(t *testing.T) {
	origin := func(url string) string {
		return "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = " + url +
			"\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n"
	}
	for _, tc := range []struct {
		name, config, want string // want "" is not ok
	}{
		{"https", origin("https://github.com/acme/agent"), "acme/agent"},
		{"https with .git", origin("https://github.com/acme/agent.git"), "acme/agent"},
		{"https with a trailing slash", origin("https://github.com/acme/agent/"), "acme/agent"},
		{"scp-like", origin("git@github.com:acme/agent.git"), "acme/agent"},
		{"scp-like without .git", origin("git@github.com:acme/agent"), "acme/agent"},
		{"ssh://", origin("ssh://git@github.com/acme/agent.git"), "acme/agent"},
		{"ssh:// with a port", origin("ssh://git@ssh.github.com:443/acme/agent.git"), "acme/agent"},
		{"a user and token are not kept", origin("https://someone:not-a-token@github.com/acme/agent.git"), "acme/agent"},
		{"quoted, with a comment", origin(`"https://github.com/acme/agent.git" # the main copy`), "acme/agent"},
		{"host in capitals", origin("https://GitHub.com/acme/agent"), "acme/agent"},
		{"not GitHub", origin("https://gitlab.com/acme/agent.git"), ""},
		{"GitHub Enterprise", origin("https://github.acme.example/acme/agent.git"), ""},
		{"a look-alike host", origin("https://github.com.evil.example/acme/agent"), ""},
		{"a local path", origin("/srv/git/agent.git"), ""},
		{"a file URL", origin("file:///srv/git/agent.git"), ""},
		{"too deep", origin("https://github.com/acme/agent/tree/main"), ""},
		{"an owner only", origin("https://github.com/acme"), ""},
		{"no origin", "[core]\n\tbare = false\n[remote \"upstream\"]\n\turl = https://github.com/acme/agent.git\n", ""},
		{"no remotes", "[core]\n\tbare = false\n", ""},
		{"empty", "", ""},
		{"several remotes: origin decides", "[remote \"upstream\"]\n\turl = https://github.com/upstream/agent.git\n" +
			origin("git@github.com:fork/agent.git") + "[remote \"backup\"]\n\turl = https://gitlab.com/acme/agent.git\n", "fork/agent"},
		{"several remotes: origin elsewhere", "[remote \"upstream\"]\n\turl = https://github.com/upstream/agent.git\n" +
			origin("https://gitlab.com/acme/agent.git"), ""},
		{"the first url is the fetch url", "[remote \"origin\"]\n\turl = https://github.com/acme/agent.git\n\turl = https://gitlab.com/acme/agent.git\n", "acme/agent"},
		{"the old section form", "[remote.origin]\n\turl = https://github.com/acme/agent.git\n", "acme/agent"},
		{"a remote named Origin is another remote", "[remote \"Origin\"]\n\turl = https://github.com/acme/agent.git\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner, name, ok := githubRepoFromGitConfig([]byte(tc.config))
			got := ""
			if ok {
				got = owner + "/" + name
			}
			if got != tc.want {
				t.Errorf("got %q (ok %v), want %q", got, ok, tc.want)
			}
		})
	}
}

// git runs git for a test fixture, with no user or system configuration.
func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+t.TempDir(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestReadLocalClone(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	ctx := context.Background()
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "first")

	if got := ReadLocalClone(ctx, dir); got != (LocalClone{WorkTree: WorkTreeClean}) {
		t.Errorf("a clean clone with no origin: %+v", got)
	}
	git(t, dir, "remote", "add", "origin", "git@github.com:acme/agent.git")
	if got := ReadLocalClone(ctx, dir); got != (LocalClone{GitHubRepo: "acme/agent", WorkTree: WorkTreeClean}) {
		t.Errorf("a clean clone of acme/agent: %+v", got)
	}

	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ReadLocalClone(ctx, dir).WorkTree; got != WorkTreeDirty {
		t.Errorf("a changed tracked file: %s, want dirty", got)
	}
	git(t, dir, "checkout", "-q", "--", "main.go")
	if err := os.WriteFile(filepath.Join(dir, "new.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ReadLocalClone(ctx, dir).WorkTree; got != WorkTreeDirty {
		t.Errorf("an untracked file, which the local tools scan too: %s, want dirty", got)
	}
}

func TestWorkTreeStateIsNeverCleanWithoutEvidence(t *testing.T) {
	ctx := context.Background()
	if got := WorkTreeState(ctx, t.TempDir()); got != WorkTreeUnknown {
		t.Errorf("a tree with no .git: %s, want unknown", got)
	}
	t.Setenv("PATH", t.TempDir()) // no git
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := WorkTreeState(ctx, dir); got != WorkTreeUnknown {
		t.Errorf("no git to ask: %s, want unknown", got)
	}
	if got := ReadLocalClone(ctx, dir); got.WorkTree != WorkTreeUnknown {
		t.Errorf("ReadLocalClone without git: %+v", got)
	}
}
