package scan

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// commitID is a full commit id: SHA-1, or SHA-256 for a repository that uses
// it.
var commitID = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// ErrNoCommit is GitHead's answer for a checkout with no readable commit: a
// copied tree with no .git, an empty repository.
var ErrNoCommit = errors.New("scan: no commit recorded for this checkout")

// GitHead returns the commit a local checkout is at, read from its .git
// directory without running git: HEAD, the branch ref it names, or the
// packed refs. A .git file (a worktree or submodule) is followed to its
// directory. It reads; it never changes the checkout.
func GitHead(dir string) (string, error) {
	gitDir, common, err := gitDirs(dir)
	if err != nil {
		return "", err
	}
	head, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return "", ErrNoCommit
	}
	h := strings.TrimSpace(string(head))
	ref, symbolic := strings.CutPrefix(h, "ref:")
	if !symbolic {
		return checkCommit(h)
	}
	ref = strings.TrimSpace(ref)
	if strings.Contains(ref, "..") {
		return "", fmt.Errorf("scan: HEAD names an unusual ref %q", ref)
	}
	for _, d := range []string{gitDir, common} {
		if b, err := os.ReadFile(filepath.Join(d, filepath.FromSlash(ref))); err == nil {
			return checkCommit(strings.TrimSpace(string(b)))
		}
	}
	f, err := os.Open(filepath.Join(common, "packed-refs"))
	if err != nil {
		return "", ErrNoCommit // a branch with no commits yet
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if sha, name, ok := strings.Cut(line, " "); ok && name == ref {
			return checkCommit(sha)
		}
	}
	return "", ErrNoCommit
}

// gitDirs finds a checkout's git directory and the common directory its
// refs and config live in: the same for a plain clone, different for a
// worktree. A .git file (a worktree or submodule) is followed.
func gitDirs(dir string) (gitDir, common string, err error) {
	gitDir = filepath.Join(dir, ".git")
	fi, err := os.Stat(gitDir)
	if err != nil {
		return "", "", ErrNoCommit
	}
	if !fi.IsDir() {
		b, err := os.ReadFile(gitDir)
		if err != nil {
			return "", "", ErrNoCommit
		}
		target, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:")
		if !ok {
			return "", "", ErrNoCommit
		}
		target = strings.TrimSpace(target)
		if !filepath.IsAbs(target) {
			target = filepath.Join(dir, target)
		}
		gitDir = target
	}
	common = gitDir
	if b, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
		c := strings.TrimSpace(string(b))
		if !filepath.IsAbs(c) {
			c = filepath.Join(gitDir, c)
		}
		common = c
	}
	return gitDir, common, nil
}

func checkCommit(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !commitID.MatchString(s) {
		return "", fmt.Errorf("scan: %q is not a commit id", s)
	}
	return s, nil
}
