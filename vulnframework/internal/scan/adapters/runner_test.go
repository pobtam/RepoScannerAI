package adapters_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

// TestAdaptersRunOffline is the standing guarantee that the whole package is
// exercisable with no tools installed, no credentials and no network: every
// adapter's Run goes through the fake, and none touches a binary.
func TestAdaptersRunOffline(t *testing.T) {
	lock := testLock(t)
	fake := runner.NewFake()

	// Register a canned result for every external tool.
	for _, tool := range []string{"govulncheck", "gosec", "staticcheck", "osv-scanner",
		"gitleaks", "trivy", "semgrep", "npm-audit"} {
		fake.WithStdout(tool, []byte(`{}`))
	}

	for _, a := range adapters.All(fake, lock) {
		t.Run(a.Name(), func(t *testing.T) {
			// actions-pin reads the working tree rather than running a binary;
			// an absent .github/workflows is a clean result, not a failure.
			out, err := a.Run(context.Background(), t.TempDir(), scan.RunOpts{Mode: scan.ModeFull})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if out.Tool != a.Name() {
				t.Errorf("RawOutput.Tool = %q, want %q", out.Tool, a.Name())
			}
			if out.ToolVersion == "" {
				t.Error("RawOutput.ToolVersion is empty; a run record cannot explain a change in finding counts without it (VM-F-202)")
			}
		})
	}
}

// TestToolExecutionFailureIsDistinguishable covers the coverage-gap path. A
// scanner that could not be executed at all must be reported explicitly
// (VM-F-205); it must never look like a clean scan.
func TestToolExecutionFailureIsDistinguishable(t *testing.T) {
	lock := testLock(t)
	fake := runner.NewFake().WithFailure("govulncheck", errors.New("executable file not found in $PATH"))

	a := adapters.NewGovulncheck(fake, lock.MustVersion("govulncheck"))
	_, err := a.Run(context.Background(), t.TempDir(), scan.RunOpts{Mode: scan.ModeFull})
	if err == nil {
		t.Fatal("a tool that could not be executed returned no error; it would be recorded as a clean scan (VM-F-205)")
	}
	if !strings.Contains(err.Error(), "govulncheck") {
		t.Errorf("error does not name the tool that failed: %v", err)
	}
}

// TestNonZeroExitIsNotAnError covers the other half: scanners routinely exit
// non-zero because they found something. Treating that as an execution failure
// would turn every repository with a finding into a coverage gap.
func TestNonZeroExitIsNotAnError(t *testing.T) {
	lock := testLock(t)
	fake := runner.NewFake()
	fake.Results["gosec"] = runner.Result{Stdout: []byte(`{"Issues":[]}`), ExitCode: 1}

	a := adapters.NewGosec(fake, lock.MustVersion("gosec"))
	out, err := a.Run(context.Background(), t.TempDir(), scan.RunOpts{Mode: scan.ModeFull})
	if err != nil {
		t.Fatalf("a non-zero exit was reported as an execution failure: %v", err)
	}
	if out.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1 (preserved for the caller)", out.ExitCode)
	}
}

// TestAdaptersPinTheirVersions covers VM-F-202: every adapter reports the
// version pinned in config/tools.lock.
func TestAdaptersPinTheirVersions(t *testing.T) {
	lock := testLock(t)
	for _, a := range adapters.All(runner.NewFake(), lock) {
		if a.Version() == "" {
			t.Errorf("adapter %q reports no version; it is not pinned in config/tools.lock (VM-AD §8.3)", a.Name())
		}
	}
}

// --- Registry and adapter selection -----------------------------------------

func TestRegistryCoversTheToolMatrix(t *testing.T) {
	lock := testLock(t)
	reg, err := adapters.NewRegistry(runner.NewFake(), lock)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	// The VM-AD §8.2 tool matrix.
	want := []string{"actions-pin", "gitleaks", "gosec", "govulncheck", "npm-audit",
		"osv-scanner", "semgrep", "staticcheck", "trivy"}
	got := reg.Names()
	if len(got) != len(want) {
		t.Fatalf("registry holds %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("registry[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRegistryRejectsDuplicateNames(t *testing.T) {
	lock := testLock(t)
	fake := runner.NewFake()
	_, err := scan.NewRegistry(
		adapters.NewGosec(fake, lock.MustVersion("gosec")),
		adapters.NewGosec(fake, lock.MustVersion("gosec")),
	)
	if err == nil {
		t.Fatal("two adapters registered under one name; provenance would be ambiguous")
	}
}

// TestAdapterSelectionByProfile covers which tools run where. The selections
// that matter are the language-scoped ones and the lockfile gate.
func TestAdapterSelectionByProfile(t *testing.T) {
	lock := testLock(t)
	reg, err := adapters.NewRegistry(runner.NewFake(), lock)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	tests := []struct {
		name    string
		profile scan.RepoProfile
		want    []string
	}{
		{
			name:    "go service",
			profile: scan.RepoProfile{Languages: []scan.Language{scan.LangGo}, Tier: 1},
			want:    []string{"actions-pin", "gitleaks", "gosec", "govulncheck", "osv-scanner", "staticcheck", "trivy"},
		},
		{
			name:    "javascript app with a lockfile",
			profile: scan.RepoProfile{Languages: []scan.Language{scan.LangJavaScript}, HasLockfile: true},
			want:    []string{"actions-pin", "gitleaks", "npm-audit", "osv-scanner", "semgrep", "trivy"},
		},
		{
			name:    "javascript app without a lockfile",
			profile: scan.RepoProfile{Languages: []scan.Language{scan.LangJavaScript}},
			want:    []string{"actions-pin", "gitleaks", "osv-scanner", "semgrep", "trivy"},
		},
		{
			name:    "no recognised language",
			profile: scan.RepoProfile{},
			want:    []string{"actions-pin", "gitleaks", "trivy"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, a := range reg.For(tc.profile) {
				got = append(got, a.Name())
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("selected %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNPMAuditRequiresALockfile is called out separately: a repository with no
// committed lockfile is a coverage gap, not a clean result (VM-F-241).
// Reporting "no vulnerabilities" for an unresolvable dependency tree would be
// the most misleading output the adapter could produce.
func TestNPMAuditRequiresALockfile(t *testing.T) {
	lock := testLock(t)
	a := adapters.NewNPMAudit(runner.NewFake(), lock.MustVersion("npm-audit"))

	withLock := scan.RepoProfile{Languages: []scan.Language{scan.LangJavaScript}, HasLockfile: true}
	without := scan.RepoProfile{Languages: []scan.Language{scan.LangJavaScript}}

	if !a.Supports(withLock) {
		t.Error("npm-audit should run against a repository with a lockfile")
	}
	if a.Supports(without) {
		t.Error("npm-audit claimed a repository with no lockfile; that is a coverage gap, not a clean scan (VM-F-241)")
	}
}

// --- tools.lock -------------------------------------------------------------

func TestToolsLockPinsEveryAdapter(t *testing.T) {
	lock := testLock(t)
	for _, a := range adapters.All(runner.NewFake(), lock) {
		if _, ok := lock.Version(a.Name()); !ok {
			t.Errorf("config/tools.lock does not pin %q (VM-AD §8.3)", a.Name())
		}
	}
}

func TestParseToolsLockRejectsMalformedRecords(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"tool without a version", "tool govulncheck\n"},
		{"unknown record kind", "binary govulncheck v1.1.4\n"},
		{"duplicate pin", "tool gosec v2.21.4\ntool gosec v2.20.0\n"},
		{"image with two references", "image a b\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := scan.ParseToolsLock(strings.NewReader(tc.in)); err == nil {
				t.Error("ParseToolsLock accepted a malformed lock file")
			}
		})
	}
}

func TestParseToolsLockReadsCommentsAndBlanks(t *testing.T) {
	in := "# a comment\n\n  tool  gosec  v2.21.4  \nimage example.com/img:tag\n"
	lock, err := scan.ParseToolsLock(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseToolsLock: %v", err)
	}
	if got := lock.MustVersion("gosec"); got != "v2.21.4" {
		t.Errorf("gosec = %q, want v2.21.4", got)
	}
	if lock.Image != "example.com/img:tag" {
		t.Errorf("image = %q", lock.Image)
	}
}
