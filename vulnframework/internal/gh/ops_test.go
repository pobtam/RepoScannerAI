package gh_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/gh"
)

// The git half, against a real local remote.
//
// A bare repository on disk is a real git remote in every respect that matters
// here: it rejects a non-fast-forward push, it records commits with the author
// it was given, and it reports a working tree's changes. Using one keeps these
// tests offline and credential-free while exercising the actual git
// invocations rather than a model of them.

// remote creates a bare repository with one commit on main, and returns its
// path.
func remote(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	bare := filepath.Join(root, "remote.git")

	run(t, root, "git", "init", "--bare", "-b", "main", bare)

	seed := filepath.Join(root, "seed")
	run(t, root, "git", "clone", "-q", bare, seed)
	write(t, filepath.Join(seed, "README.md"), "# fixture\n")
	write(t, filepath.Join(seed, "app.go"), "package app\n\nfunc A() int { return 1 }\n")
	run(t, seed, "git", "add", "-A")
	run(t, seed, "git", "-c", "user.name=seed", "-c", "user.email=seed@example.invalid",
		"commit", "-q", "-m", "seed")
	run(t, seed, "git", "push", "-q", "origin", "main")

	return bare
}

// localOps builds a RESTOps whose remote is a path on disk.
func localOps(t *testing.T, bare string) *gh.RESTOps {
	t.Helper()
	return &gh.RESTOps{
		Token:    func(context.Context, string) (string, error) { return "token ghs_test", nil },
		CloneURL: func(string, string) string { return bare },
	}
}

func run(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func TestCloneBranchCommitAndPush(t *testing.T) {
	bare := remote(t)
	ops := localOps(t, bare)
	ctx := context.Background()

	dir := filepath.Join(t.TempDir(), "work")
	if err := ops.Clone(ctx, "org/api", "main", dir); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "app.go")); err != nil {
		t.Fatalf("the clone has no content: %v", err)
	}

	if err := ops.CreateBranch(ctx, dir, "security/fix-ab12cd"); err != nil {
		t.Fatalf("CreateBranch: %v", err)
	}

	write(t, filepath.Join(dir, "app.go"), "package app\n\nfunc A() int { return 2 }\n")
	write(t, filepath.Join(dir, "added.go"), "package app\n\n// Added by a fixer.\nfunc B() int { return 3 }\n")

	changed, err := ops.ChangedFiles(ctx, dir)
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	for _, want := range []string{"app.go", "added.go"} {
		if !containsString(changed, want) {
			t.Errorf("ChangedFiles = %v, missing %s. The guard inspects this list", changed, want)
		}
	}

	diff, err := ops.Diff(ctx, dir)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	// The added file especially: without intent-to-add it produces no diff at
	// all, and the content guard would inspect nothing.
	if !strings.Contains(string(diff), "func B()") {
		t.Fatalf("an added file's content is not in the diff, so the content guard sees "+
			"nothing of it:\n%s", diff)
	}

	if err := ops.Commit(ctx, dir, gh.Commit{
		Message:     "security: bump",
		AuthorName:  "wanaware-security[bot]",
		AuthorEmail: "security-bot@wanaware.invalid",
		Files:       changed,
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// VM-F-544: the change is attributable to the machine, not to whoever's
	// identity happened to be configured on the runner.
	author := run(t, dir, "git", "log", "-1", "--format=%an <%ae>")
	if !strings.Contains(author, "wanaware-security[bot]") {
		t.Errorf("the commit author is %q. A machine change attributed to a person makes `git log` "+
			"unreliable for the one question it is most often asked", strings.TrimSpace(author))
	}

	if err := ops.Push(ctx, dir, "org/api", "security/fix-ab12cd"); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if refs := run(t, bare, "git", "branch", "--list"); !strings.Contains(refs, "security/fix-ab12cd") {
		t.Fatalf("the branch is not on the remote:\n%s", refs)
	}
}

// TestARejectedPushIsAConflictAndIsNeverForced is the one where the wrong
// answer destroys somebody's work.
//
// A non-fast-forward rejection means another worker or a human moved the
// branch. The framework abandons the branch; it must never force, because a
// force here overwrites whatever moved it.
func TestARejectedPushIsAConflictAndIsNeverForced(t *testing.T) {
	bare := remote(t)
	ops := localOps(t, bare)
	ctx := context.Background()
	const branch = "security/fix-ab12cd"

	// A first worker pushes the branch.
	first := filepath.Join(t.TempDir(), "first")
	if err := ops.Clone(ctx, "org/api", "main", first); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if err := ops.CreateBranch(ctx, first, branch); err != nil {
		t.Fatalf("CreateBranch: %v", err)
	}
	write(t, filepath.Join(first, "app.go"), "package app\n\nfunc A() int { return 2 }\n")
	commit(t, ops, ctx, first, "first change")
	if err := ops.Push(ctx, first, "org/api", branch); err != nil {
		t.Fatalf("the first push failed: %v", err)
	}

	// A second worker cuts the same branch from the same base and gets there
	// afterwards, with different history.
	second := filepath.Join(t.TempDir(), "second")
	if err := ops.Clone(ctx, "org/api", "main", second); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if err := ops.CreateBranch(ctx, second, branch); err != nil {
		t.Fatalf("CreateBranch: %v", err)
	}
	write(t, filepath.Join(second, "app.go"), "package app\n\nfunc A() int { return 99 }\n")
	commit(t, ops, ctx, second, "second change")

	err := ops.Push(ctx, second, "org/api", branch)
	if err == nil {
		t.Fatal("a divergent push to a branch somebody else had already moved SUCCEEDED. " +
			"That is only possible with a force, which destroys the other worker's commit")
	}

	var conflict *gh.ErrConflict
	if !asConflict(err, &conflict) {
		t.Fatalf("a rejected push is not an *ErrConflict, so the worker cannot abandon the branch "+
			"and will treat it as a generic failure: %v", err)
	}
	if conflict.Branch != branch {
		t.Errorf("the conflict names branch %q", conflict.Branch)
	}

	// And the remote still has the first worker's commit.
	log := run(t, bare, "git", "log", "-1", "--format=%s", branch)
	if !strings.Contains(log, "first change") {
		t.Fatalf("the remote branch is no longer the first worker's commit: %q", strings.TrimSpace(log))
	}
}

// TestAPushFailureNeverCarriesTheTokenIntoAnError is the third layer of
// credential handling, and it is here because the cost of being wrong is a
// token in a log nobody reads until it matters.
//
// The push URL embeds the installation token. An error message is the one part
// of a failed command that reliably reaches a log.
func TestAPushFailureNeverCarriesTheTokenIntoAnError(t *testing.T) {
	const secret = "ghs_a_token_that_must_not_be_logged"
	bare := remote(t)

	ops := &gh.RESTOps{
		Token: func(context.Context, string) (string, error) { return "token " + secret, nil },
		// A URL shaped like the real one, pointing nowhere, so the push fails
		// with the credential in the command line.
		CloneURL: func(repo, token string) string {
			return "https://x-access-token:" + token + "@127.0.0.1:1/" + repo + ".git"
		},
	}
	ctx := context.Background()

	dir := filepath.Join(t.TempDir(), "work")
	if err := (&gh.RESTOps{
		Token:    func(context.Context, string) (string, error) { return "t", nil },
		CloneURL: func(string, string) string { return bare },
	}).Clone(ctx, "org/api", "main", dir); err != nil {
		t.Fatalf("Clone: %v", err)
	}

	err := ops.Push(ctx, dir, "org/api", "main")
	if err == nil {
		t.Fatal("a push to an unreachable remote succeeded")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the installation token is in the error message, which is the one part of a "+
			"failed command that reliably reaches a log:\n%v", err)
	}
	// And it still says WHAT was redacted. "REDACTED-URL" would also keep the
	// token out, but an operator reading a failed push needs to know it was
	// the authenticated GitHub remote rather than some other argument — which
	// is the difference between diagnosing a bad token and diagnosing a bad
	// path.
	if !strings.Contains(err.Error(), "x-access-token:REDACTED") {
		t.Errorf("the error does not show that the redacted argument was the authenticated push "+
			"URL, so a reader cannot tell which argument went missing: %v", err)
	}
}

// TestDiscardRefusesToRemoveTheWorld is a guard against the obvious accident.
func TestDiscardRefusesToRemoveTheWorld(t *testing.T) {
	ops := &gh.RESTOps{}
	for _, dir := range []string{"", "/"} {
		if err := ops.Discard(context.Background(), dir); err == nil {
			t.Errorf("Discard(%q) was accepted", dir)
		}
	}
}

func commit(t *testing.T, ops *gh.RESTOps, ctx context.Context, dir, message string) {
	t.Helper()
	if err := ops.Commit(ctx, dir, gh.Commit{
		Message: message, AuthorName: "bot", AuthorEmail: "bot@example.invalid",
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func asConflict(err error, target **gh.ErrConflict) bool {
	for err != nil {
		if c, ok := err.(*gh.ErrConflict); ok {
			*target = c
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
