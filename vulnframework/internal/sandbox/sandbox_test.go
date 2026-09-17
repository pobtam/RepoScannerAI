package sandbox_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/sandbox"
)

// §15.2 isolation, and the other half of Phase 10a's capability-denial claim.
//
// The Fixer interface constrains what the agent can do TO THE FRAMEWORK: it
// returns a working tree and has no store, no credentials, no pull-request
// surface. It says nothing whatever about what the agent's PROCESS can reach —
// the network, the filesystem outside the clone, the environment it inherited.
// Until this holds, the agent is capability-denied on paper and
// capability-rich in practice.
//
// Every test here probes the boundary by trying to cross it. None of them
// inspects a policy struct: a policy that says "network denied" and a network
// that is actually denied are different claims, and only one of them is worth
// having.

func policy(t *testing.T) sandbox.Policy {
	t.Helper()
	return sandbox.Policy{
		CloneDir:    t.TempDir(),
		AllowedEnv:  []string{"PATH", "HOME", "LANG"},
		EgressAllow: []string{"api.anthropic.com:443"},
	}
}

// --- The environment allowlist ----------------------------------------------

// TestOnlyAllowlistedEnvironmentReachesTheProcess is the one boundary this
// package can enforce entirely in process, and it is the one that matters most
// for exfiltration: a CI runner's environment holds registry tokens, cloud
// credentials and signing keys, and an agent inherits all of them by default.
func TestOnlyAllowlistedEnvironmentReachesTheProcess(t *testing.T) {
	p := policy(t)
	// Things a real runner would have in scope.
	t.Setenv("AWS_SECRET_ACCESS_KEY", "REDACTED-FAKE-AWS-SECRET")
	t.Setenv("GITHUB_TOKEN", "REDACTED-FAKE-GITHUB-TOKEN")
	t.Setenv("NPM_TOKEN", "npm_secret")
	t.Setenv("PATH", "/usr/bin:/bin")

	env, err := sandbox.FilterEnv(p, os.Environ())
	if err != nil {
		t.Fatalf("FilterEnv: %v", err)
	}

	joined := strings.Join(env, "\n")
	for _, forbidden := range []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NPM_TOKEN",
		"REDACTED-FAKE-AWS-SECRET", "ghp_0000"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("%q reached the agent's environment; an agent inherits a runner's credentials "+
				"by default, and inheriting is the exfiltration", forbidden)
		}
	}
	if !strings.Contains(joined, "PATH=") {
		t.Error("the allowlist dropped PATH; the agent cannot run anything")
	}
}

// TestTheAllowlistCannotBeEmptiedIntoAWildcard is the configuration guard. An
// allowlist containing "*" or the empty string would pass everything through
// while reading, in a config file, as though isolation were configured.
func TestTheAllowlistCannotBeEmptiedIntoAWildcard(t *testing.T) {
	for _, bad := range []string{"*", "", "ALL"} {
		p := sandbox.Policy{CloneDir: t.TempDir(), AllowedEnv: []string{"PATH", bad}}
		if _, err := sandbox.FilterEnv(p, []string{"PATH=/bin", "SECRET=x"}); err == nil {
			t.Errorf("an allowlist entry %q was accepted; it would pass everything while looking configured", bad)
		}
	}
}

// --- The probe: the boundary is proven, not declared ------------------------

// TestVerifyProbesTheBoundaryRatherThanTrustingIt is the heart of this
// package.
//
// Verify runs a canary inside the sandbox that actively tries to do the three
// forbidden things. An implementation that returned "denied" without probing
// would be asserting its own configuration, which is exactly the class of
// self-confirming test this build has spent nine phases removing.
func TestVerifyProbesTheBoundaryRatherThanTrustingIt(t *testing.T) {
	p := policy(t)
	s := sandbox.NewFake(p)
	s.AllowEscape(sandbox.ProbeNetwork) // the sandbox leaks

	v, err := s.Verify(context.Background())
	// Verify fails CLOSED: it returns the detail and an error, so a caller
	// that only checks err cannot proceed with a leaky sandbox, and one that
	// only checks OK() cannot either.
	if err == nil {
		t.Fatal("Verify returned no error while the canary reached the network; a caller checking only " +
			"the error would run the agent unconfined")
	}
	if v.OK() {
		t.Fatal("Verify reported a sound boundary while the canary reached the network")
	}
	var notIsolated *sandbox.ErrNotIsolated
	if !errors.As(err, &notIsolated) {
		t.Errorf("error is %T, want *sandbox.ErrNotIsolated", err)
	}
	if v.NetworkDenied {
		t.Error("network reported denied while the probe got out")
	}
	// A failed verification names what got through: an operator needs to know
	// which boundary is open, not that one is.
	if !strings.Contains(strings.ToLower(v.Summary()), "network") {
		t.Errorf("the summary does not name the open boundary: %s", v.Summary())
	}

	// And every probe must actually have run. A Verify that skipped a probe
	// and reported denied is the same lie in a different place.
	if len(v.Probes) != len(sandbox.AllProbes) {
		t.Errorf("%d probes ran, want %d — a skipped probe reported as denied is not a boundary",
			len(v.Probes), len(sandbox.AllProbes))
	}
}

// TestASkippedProbeNeverReadsAsDenied is the subtle one. A probe that did not
// run produces no escape marker, which looks exactly like a probe that ran and
// was blocked. Treating absence as denial would make a broken sandbox verify.
func TestASkippedProbeNeverReadsAsDenied(t *testing.T) {
	s := sandbox.NewFake(policy(t)).SkipProbe(sandbox.ProbeWrite)
	v, err := s.Verify(context.Background())
	if err == nil || v.OK() {
		t.Fatal("a verification with a probe that never ran reported the boundary sound; a probe that " +
			"did not run is silent, and so is one that was blocked")
	}
	if !strings.Contains(v.Summary(), "not probed") {
		t.Errorf("the summary does not distinguish an unrun probe from a denied one: %s", v.Summary())
	}
}

func TestASoundSandboxDeniesAllThree(t *testing.T) {
	s := sandbox.NewFake(policy(t))
	v, err := s.Verify(context.Background())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !v.OK() {
		t.Fatalf("a sound sandbox did not verify: %s", v.Summary())
	}
	for _, probe := range sandbox.AllProbes {
		var found bool
		for _, r := range v.Probes {
			if r.Probe == probe {
				found = true
				if !r.Denied {
					t.Errorf("probe %s was not denied", probe)
				}
			}
		}
		if !found {
			t.Errorf("probe %s did not run", probe)
		}
	}
}

// --- No isolation means no run, loudly --------------------------------------

// TestUnisolatedSandboxRefusesToVerify is the default that matters. On a
// machine with no isolation mechanism available, the honest answer is that the
// boundary does not hold — not that it was not checked.
func TestUnisolatedSandboxRefusesToVerify(t *testing.T) {
	s := sandbox.Unisolated(policy(t))
	v, err := s.Verify(context.Background())
	if err == nil && v.OK() {
		t.Fatal("an unisolated sandbox verified; it would hand an agent the whole machine while " +
			"reporting that it was contained")
	}
	msg := strings.ToLower(v.Summary() + errText(err))
	for _, want := range []string{"no isolation"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say why: %s", msg)
		}
	}
}

// TestRealSandboxDetectsAMissingBackend covers the deployment case. The real
// implementation needs an OS mechanism — bubblewrap, sandbox-exec, a
// container — and where none is present it must fail closed rather than
// silently running the agent unconfined.
func TestRealSandboxDetectsAMissingBackend(t *testing.T) {
	p := policy(t)
	s, err := sandbox.New(p, sandbox.Options{Backends: []string{"definitely-not-installed"}})
	if err == nil {
		v, verr := s.Verify(context.Background())
		if verr == nil && v.OK() {
			t.Fatal("a sandbox with no available backend verified as sound")
		}
		return
	}
	if !strings.Contains(strings.ToLower(err.Error()), "no isolation backend") {
		t.Errorf("the error does not name the problem: %v", err)
	}
}

// --- The clone boundary ------------------------------------------------------

// TestCommandRunsInTheCloneAndNowhereElse covers the part that is enforceable
// in process regardless of backend: the working directory. It is not
// sufficient on its own — a process can use an absolute path — which is why
// the write probe exists, but it must still be right.
func TestCommandRunsInTheCloneAndNowhereElse(t *testing.T) {
	p := policy(t)
	s := sandbox.NewFake(p)

	cmd, err := s.Command(context.Background(), "echo", "hello")
	if err != nil {
		t.Fatalf("Command: %v", err)
	}
	if cmd.Dir != p.CloneDir {
		t.Errorf("command runs in %q, want the clone %q", cmd.Dir, p.CloneDir)
	}
	joined := strings.Join(cmd.Env, "\n")
	if strings.Contains(joined, "AWS_") || strings.Contains(joined, "TOKEN") {
		t.Errorf("the command inherited credentials: %s", joined)
	}
}

// TestCommandRefusesOutsideTheClone is the negative half.
func TestCommandRefusesOutsideTheClone(t *testing.T) {
	p := policy(t)
	p.CloneDir = ""
	s := sandbox.NewFake(p)
	if _, err := s.Command(context.Background(), "echo"); err == nil {
		t.Error("a sandbox with no clone directory produced a command; it would run in the caller's " +
			"working directory, which is the framework's own checkout")
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestProbesAreRealCommands guards against the probe set becoming decorative.
//
// Each probe has to be something that would actually succeed outside a
// sandbox. A probe that cannot succeed anywhere proves nothing when it fails.
func TestProbesAreRealCommands(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell available to validate the probes against")
	}
	for _, probe := range sandbox.AllProbes {
		script := sandbox.ProbeScript(probe, sandbox.Policy{
			CloneDir: t.TempDir(), EgressAllow: []string{"api.anthropic.com:443"},
		})
		if strings.TrimSpace(script) == "" {
			t.Errorf("probe %s has no script; it cannot have been run", probe)
		}
	}

	// The write probe must genuinely write outside the clone when nothing
	// stops it — otherwise a passing result means nothing.
	dir := t.TempDir()
	p := sandbox.Policy{CloneDir: dir, EgressAllow: []string{"api.anthropic.com:443"}}
	script := sandbox.ProbeScript(sandbox.ProbeWrite, p)
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("the write probe failed unsandboxed (%v); a probe that cannot succeed proves nothing "+
			"when it fails: %s", err, out)
	}
	if !strings.Contains(string(out), sandbox.ProbeEscaped) {
		t.Errorf("the write probe did not report an escape unsandboxed; output: %s", out)
	}
}

var _ = errors.Is
