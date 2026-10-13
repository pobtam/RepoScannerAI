package guard_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/remediate/guard"
	"github.com/wanaware/vulnframework/internal/testkeys"
)

// The guard is the only thing standing between an automated code change and the
// CI that gates it.
//
// An agent — or a bump worker with a bad fix candidate — that can edit
// `.github/workflows/**` can weaken the checks that review its own pull
// requests. That is a privilege-escalation loop, and it closes silently: the
// workflow change looks like part of the fix, the checks go green, and the
// next pull request inherits the weakened gate. Nothing downstream can detect
// it, because the thing that would have detected it is what was edited.
//
// It is built and proven here, on the deterministic worker, a phase before the
// agent harness exists (VM-F-508/510). Dependency bumps never touch a protected
// path, so there are no false positives to tune away, and Phase 10's agent
// inherits a guard that is already known to fire.

func testGuard(t *testing.T) *guard.Guard {
	t.Helper()
	g, err := guard.New(guard.Config{
		DenyPaths: []string{
			".github/workflows/**",
			".github/actions/**",
			"CODEOWNERS",
			"**/*.tf",
			"**/*.tfvars",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// --- Gate: a protected path is REJECTED, not trimmed ------------------------

// TestProtectedPathsAreRejected is the gate clause. The important half is what
// the guard does NOT do: it does not drop the offending file and push the rest.
// A trimmed change is a partial fix, which VM-F-506 forbids for a different
// reason and which here would also mean the violation went unreported.
func TestProtectedPathsAreRejected(t *testing.T) {
	g := testGuard(t)

	cases := []struct {
		name    string
		changed []string
		pattern string
	}{
		{"a CI workflow", []string{"go.mod", ".github/workflows/ci.yml"}, ".github/workflows/**"},
		{"a nested CI workflow", []string{".github/workflows/nested/deploy.yaml"}, ".github/workflows/**"},
		{"a composite action", []string{".github/actions/setup/action.yml"}, ".github/actions/**"},
		{"code ownership", []string{"CODEOWNERS"}, "CODEOWNERS"},
		{"terraform at the root", []string{"main.tf"}, "**/*.tf"},
		{"terraform nested", []string{"deploy/prod/cluster.tf"}, "**/*.tf"},
		{"terraform variables", []string{"deploy/prod/values.tfvars"}, "**/*.tfvars"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := g.CheckPaths(tc.changed)
			if err == nil {
				t.Fatal("the guard permitted a change to a protected path")
			}

			var denied *guard.ErrDeniedPath
			if !errors.As(err, &denied) {
				t.Fatalf("error is %T, want *guard.ErrDeniedPath; the caller must be able to tell a "+
					"guard violation from any other failure, because the response is different: discard and alert", err)
			}
			if denied.Pattern != tc.pattern {
				t.Errorf("matched pattern %q, want %q", denied.Pattern, tc.pattern)
			}
			// The message must name the file and say what happens next. A guard
			// that fails without saying which file tripped it sends someone
			// hunting through a diff.
			msg := err.Error()
			for _, want := range []string{denied.Path, tc.pattern, "discard"} {
				if !strings.Contains(strings.ToLower(msg), strings.ToLower(want)) {
					t.Errorf("the message does not mention %q: %s", want, msg)
				}
			}
		})
	}
}

// TestGuardReportsEveryViolationNotOnlyTheFirst matters for the alert, not for
// the decision. The decision is already made — discard — but an operator
// reading it needs to know whether one file or forty were touched.
func TestGuardReportsEveryViolationNotOnlyTheFirst(t *testing.T) {
	g := testGuard(t)
	changed := []string{
		"go.mod",
		".github/workflows/ci.yml",
		"CODEOWNERS",
		"deploy/main.tf",
	}
	violations := g.Violations(changed)
	if len(violations) != 3 {
		t.Fatalf("got %d violations, want 3: %+v", len(violations), violations)
	}
	// Deterministic order, so an alert is comparable across runs.
	want := []string{".github/workflows/ci.yml", "CODEOWNERS", "deploy/main.tf"}
	for i, v := range violations {
		if v.Path != want[i] {
			t.Errorf("violation %d is %q, want %q", i, v.Path, want[i])
		}
	}
}

// --- No false positives on the case Phase 9 actually produces ---------------

// TestDependencyBumpsAreNotBlocked is why this guard can be built now. A
// deterministic bump touches manifests and lock files only, so the guard is
// provably silent on every change the deterministic worker makes — there is no
// tuning pressure to weaken it later, which is how guards die.
func TestDependencyBumpsAreNotBlocked(t *testing.T) {
	g := testGuard(t)
	bumps := [][]string{
		{"go.mod", "go.sum"},
		{"package.json", "package-lock.json"},
		{"services/api/go.mod", "services/api/go.sum"},
		{"go.mod", "go.sum", "internal/client/client.go"},
		// A file whose name merely resembles a protected one.
		{"docs/CODEOWNERS.md", "terraform-notes.txt", "workflows.go"},
		{".github/dependabot.yml"},
		{".github/ISSUE_TEMPLATE/bug.md"},
	}
	for _, changed := range bumps {
		if err := g.CheckPaths(changed); err != nil {
			t.Errorf("the guard blocked an ordinary change %v: %v", changed, err)
		}
	}
}

// TestPathNormalisationCannotEvadeTheGuard covers the evasion routes. A guard
// that matches on the literal string it is given can be walked around by any
// caller that spells the path differently, and `git diff --name-only` is not
// the only thing that ever feeds it.
func TestPathNormalisationCannotEvadeTheGuard(t *testing.T) {
	g := testGuard(t)
	evasions := []string{
		"./.github/workflows/ci.yml",
		".github/workflows/../workflows/ci.yml",
		".github//workflows//ci.yml",
		"/.github/workflows/ci.yml",
		".github\\workflows\\ci.yml",
		"a/../.github/workflows/ci.yml",
		".GITHUB/WORKFLOWS/CI.YML",
	}
	for _, path := range evasions {
		if err := g.CheckPaths([]string{path}); err == nil {
			t.Errorf("the guard was evaded by %q", path)
		}
	}
}

// TestGuardRefusesToBeEmpty is the configuration guard on the guard. An empty
// deny-list silently permits everything, and the symptom is indistinguishable
// from a working guard that nothing has tripped yet.
func TestGuardRefusesToBeEmpty(t *testing.T) {
	if _, err := guard.New(guard.Config{}); err == nil {
		t.Error("a guard with no deny-list was constructed; it would permit every path while looking installed")
	}
	if _, err := guard.New(guard.Config{DenyPaths: []string{"CODEOWNERS"}}); err == nil {
		t.Error("a deny-list missing CI workflow paths was accepted (VM-F-509)")
	}
	// The minimum set of VM-F-509 must be present: CI definitions, code
	// ownership, infrastructure-as-code.
	if _, err := guard.New(guard.Config{DenyPaths: []string{
		".github/workflows/**", "CODEOWNERS",
	}}); err == nil {
		t.Error("a deny-list with no infrastructure-as-code paths was accepted (VM-F-509)")
	}
}

// --- Diff content guards (VM-AD §11.2 step 6) -------------------------------

// TestSuppressionDirectivesAreRejected covers VM-F-507. A suppression closes a
// finding by asserting it does not matter, which is a judgement no automated
// worker is permitted to make. Proposing one is allowed; applying one is not.
func TestSuppressionDirectivesAreRejected(t *testing.T) {
	g := testGuard(t)
	diffs := map[string]string{
		"gosec":               "+\t//nolint:gosec\n",
		"nolint all":          "+// nolint\n",
		"govulncheck ignore":  "+//golang:ignore GO-2025-3106\n",
		"semgrep":             "+# nosemgrep\n",
		"gitleaks allowlist":  "+# gitleaks:allow\n",
		"staticcheck":         "+//lint:ignore SA9005 reason\n",
		"eslint":              "+// eslint-disable-next-line no-eval\n",
		"npm audit exception": "+  \"audit\": { \"exceptions\": [\"GHSA-xxxx\"] }\n",
	}
	for name, diff := range diffs {
		t.Run(name, func(t *testing.T) {
			err := g.CheckDiff([]byte(diff))
			if err == nil {
				t.Fatalf("the guard permitted a suppression directive: %s", diff)
			}
			var sup *guard.ErrSuppression
			if !errors.As(err, &sup) {
				t.Fatalf("error is %T, want *guard.ErrSuppression", err)
			}
		})
	}
}

// TestRemovedSuppressionIsNotAViolation is the direction check. Only ADDED
// lines are suppressions being applied; a diff that deletes one is a fix
// improving the codebase, and blocking it would make the guard an obstacle to
// the thing it is protecting.
func TestRemovedSuppressionIsNotAViolation(t *testing.T) {
	g := testGuard(t)
	diff := "--- a/x.go\n+++ b/x.go\n-\t//nolint:gosec\n+\tuse(safe)\n"
	if err := g.CheckDiff([]byte(diff)); err != nil {
		t.Errorf("the guard blocked the REMOVAL of a suppression: %v", err)
	}
}

// TestReintroducedCredentialIsRejected covers the other half of step 6. A fix
// that pastes a credential back into the tree — from a test fixture, a rolled
// back config, a merge — must not be pushed, and this is the same shared
// definition the report and the tracker use.
func TestReintroducedCredentialIsRejected(t *testing.T) {
	g := testGuard(t)
	diff := "--- a/config.yaml\n+++ b/config.yaml\n+aws_key: " + testkeys.AWSAccessKeyID() + "\n"
	err := g.CheckDiff([]byte(diff))
	if err == nil {
		t.Fatal("the guard permitted a reintroduced credential")
	}
	var cred *guard.ErrCredentialInDiff
	if !errors.As(err, &cred) {
		t.Fatalf("error is %T, want *guard.ErrCredentialInDiff", err)
	}
	// The error must not quote the credential it found. A guard that reports a
	// leak by repeating it has moved the leak into the log.
	if strings.Contains(err.Error(), testkeys.AWSAccessKeyID()) {
		t.Error("the guard's own error message contains the credential (VM-F-263)")
	}
}

// TestCheckIsUnconditional is principle P4 expressed as a test. The guard takes
// the diff, not a report of what the worker believes it changed: a worker that
// misreports its own change set — through a bug, or because an agent wrote the
// report — must not be able to talk its way past the inspection.
func TestCheckIsUnconditional(t *testing.T) {
	g := testGuard(t)

	// What the worker claims.
	claimed := []string{"go.mod", "go.sum"}
	// What the tree actually shows.
	actual := []string{"go.mod", "go.sum", ".github/workflows/ci.yml"}

	if err := g.CheckPaths(claimed); err != nil {
		t.Fatalf("the claimed set is clean: %v", err)
	}
	if err := g.CheckPaths(actual); err == nil {
		t.Fatal("the guard trusted a claim over the tree; enforcement is a post-change diff " +
			"inspection, never a prompt instruction or a self-report (VM-F-510)")
	}
}
