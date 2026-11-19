package scan

import (
	"bufio"
	"bytes"
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// LocalClone is what a scan of a local clone (real mode) knows about the
// clone beyond its files: where it lives on GitHub, and whether the tree on
// disk is the commit. A remote adapter (NuGuard) scans GitHub's copy of the
// commit, not the tree on disk, and needs both to say honestly what it
// scanned. Nothing here is a credential.
type LocalClone struct {
	// GitHubRepo is owner/name from the clone's origin remote, when that is
	// on github.com; empty when the clone has no origin or it is elsewhere.
	GitHubRepo string
	// WorkTree is WorkTreeClean, WorkTreeDirty or WorkTreeUnknown.
	WorkTree string
}

const (
	WorkTreeClean   = "clean"
	WorkTreeDirty   = "dirty"
	WorkTreeUnknown = "unknown"
)

// ReadLocalClone reads a clone's GitHub identity and working-tree state. It
// never changes the clone, which real mode mounts read-only.
func ReadLocalClone(ctx context.Context, dir string) LocalClone {
	lc := LocalClone{WorkTree: WorkTreeState(ctx, dir)}
	if _, common, err := gitDirs(dir); err == nil {
		if b, err := os.ReadFile(filepath.Join(common, "config")); err == nil {
			if owner, name, ok := githubRepoFromGitConfig(b); ok {
				lc.GitHubRepo = owner + "/" + name
			}
		}
	}
	return lc
}

// githubRepoFromGitConfig returns the github.com owner and name of the origin
// remote in a git config file. Only origin counts: another remote on GitHub
// (an upstream, a fork) is not where this clone's commits are pushed.
func githubRepoFromGitConfig(config []byte) (owner, name string, ok bool) {
	inOrigin := false
	sc := bufio.NewScanner(bytes.NewReader(config))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			inOrigin = originSection(line)
			continue
		}
		if !inOrigin {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(key), "url") {
			continue
		}
		// The first url is the one fetched from; the rest are push-only.
		return githubRepoFromURL(configValue(value))
	}
	return "", "", false
}

// originSection reports whether a section header opens [remote "origin"]
// (or the old [remote.origin]). The section name is case-insensitive; the
// remote's name is not.
func originSection(header string) bool {
	h := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(header, "["), "]"))
	if sect, sub, found := strings.Cut(h, " "); found {
		return strings.EqualFold(sect, "remote") && strings.TrimSpace(sub) == `"origin"`
	}
	sect, sub, found := strings.Cut(h, ".")
	return found && strings.EqualFold(sect, "remote") && strings.EqualFold(sub, "origin")
}

// configValue is a config value without its comment and quotes.
func configValue(v string) string {
	var out strings.Builder
	quoted := false
	for _, r := range strings.TrimSpace(v) {
		switch {
		case r == '"':
			quoted = !quoted
		case !quoted && (r == '#' || r == ';'):
			return strings.TrimSpace(out.String())
		default:
			out.WriteRune(r)
		}
	}
	return strings.TrimSpace(out.String())
}

var githubRepoPath = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// githubRepoFromURL reads owner/name from a remote URL on github.com: https,
// ssh:// and git@github.com:owner/name, with or without .git. A user or
// token in the URL is ignored, never returned.
func githubRepoFromURL(raw string) (owner, name string, ok bool) {
	var host, path string
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", "", false
		}
		switch strings.ToLower(u.Scheme) {
		case "https", "http", "ssh", "git", "git+ssh":
		default:
			return "", "", false
		}
		host, path = u.Hostname(), u.Path
	} else {
		// scp-like: [user@]host:owner/name
		hostPart, p, found := strings.Cut(raw, ":")
		if !found || strings.Contains(hostPart, "/") {
			return "", "", false
		}
		if _, h, hasUser := strings.Cut(hostPart, "@"); hasUser {
			hostPart = h
		}
		host, path = hostPart, p
	}
	switch strings.ToLower(host) {
	case "github.com", "ssh.github.com":
	default:
		return "", "", false
	}
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	if !githubRepoPath.MatchString(path) || strings.Contains(path, "..") {
		return "", "", false
	}
	owner, name, _ = strings.Cut(path, "/")
	return owner, name, true
}

// WorkTreeState says whether a clone's tree on disk differs from its commit:
// changed or untracked files the local tools scanned and GitHub does not
// have. It runs git status, read-only (no index refresh, no fsmonitor, no
// user or system config), and answers WorkTreeUnknown wherever it cannot be
// sure, never clean.
func WorkTreeState(ctx context.Context, dir string) string {
	git, err := exec.LookPath("git")
	if err != nil {
		return WorkTreeUnknown
	}
	if _, _, err := gitDirs(dir); err != nil {
		return WorkTreeUnknown
	}
	home, err := os.MkdirTemp("", "vf-gitstatus-")
	if err != nil {
		return WorkTreeUnknown
	}
	defer os.RemoveAll(home)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// safe.directory: the clone belongs to another user inside the scan
	// container, and git would otherwise refuse to read it.
	cmd := exec.CommandContext(ctx, git, "-c", "safe.directory=*", "-c", "core.fsmonitor=false",
		"-C", dir, "status", "--porcelain=v1", "--untracked-files=normal")
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "GIT_OPTIONAL_LOCKS=0",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil {
		return WorkTreeUnknown
	}
	if len(bytes.TrimSpace(out)) > 0 {
		return WorkTreeDirty
	}
	return WorkTreeClean
}
