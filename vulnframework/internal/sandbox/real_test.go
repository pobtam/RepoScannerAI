//go:build sandboxprobe

// Package sandbox's REAL isolation test (D2, OQ-P10b-01, OQ-P10b-02).
//
// Build-tagged, so it never runs in the ordinary suite. That is deliberate and
// is the opposite of the usual reason for a tag.
//
// Every other test in this package runs against sandbox.Fake, because this
// build is on macOS and the real implementation needs Linux namespaces. The
// fake's green tests are evidence about the HARNESS — that a leaked boundary
// is noticed, that a skipped probe never reads as a denial, that the agent
// refuses to start when isolation cannot be established. They are not evidence
// about isolation, and nothing in them could be.
//
// This file is the evidence about isolation, and it has never run. Running it
// is D2, and it needs a Linux machine with bubblewrap installed:
//
//	go test -tags sandboxprobe ./internal/sandbox/ -run TestTheRealSandbox -v
//
// # Why a build tag and not a skip
//
// A skip is the obvious choice and it is wrong here. `go test ./...` prints a
// skip as part of a passing run, and a skipped probe that reads as a pass is
// the exact lie sandbox.Verification.OK() exists to prevent one level down.
// The rule has to hold for the test that calls it too.
//
// With a tag, this file is either RUN or ABSENT. There is no state in which it
// appears to have answered and did not.
//
// # The rule this protects
//
// No real API key on any machine where this has not passed. Until it does, the
// agent's isolation is an assertion, and a credential handed to an unconfined
// process is a credential in reach of everything that process does.
package sandbox_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/sandbox"
)

// requireRealBackend fails — never skips — when no isolation backend exists.
//
// Failing is the point. This file is only ever built deliberately, so being
// built on a machine that cannot run it is a configuration error, and a
// configuration error that reported success would make the whole job
// decorative.
func requireRealBackend(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"bwrap", "sandbox-exec"} {
		if _, err := exec.LookPath(name); err == nil {
			return name
		}
	}
	t.Fatalf("no isolation backend (bwrap, sandbox-exec) is present on this %s machine, and this "+
		"file was built deliberately with -tags sandboxprobe. Refusing to report a pass: a probe "+
		"that did not run must never read as a denial", runtime.GOOS)
	return ""
}

func realPolicy(t *testing.T) sandbox.Policy {
	t.Helper()
	return sandbox.Policy{
		CloneDir:   t.TempDir(),
		AllowedEnv: []string{"PATH", "HOME"},
	}
}

// TestTheRealSandboxDeniesEveryBoundary is D2's first requirement: each probe
// RUNS and each is DENIED, against the real backend rather than the fake.
func TestTheRealSandboxDeniesEveryBoundary(t *testing.T) {
	backend := requireRealBackend(t)

	// The canary must exist OUTSIDE the boundary. Probing for an unset
	// variable proves nothing: it would be absent inside a sandbox and absent
	// without one.
	t.Setenv("VF_SANDBOX_CANARY_SECRET", "a-value-the-agent-must-not-read")

	s, err := sandbox.New(realPolicy(t), sandbox.Options{
		CanarySecret: "a-value-the-agent-must-not-read",
	})
	if err != nil {
		t.Fatalf("building the real sandbox: %v", err)
	}
	if s.Name() != backend {
		t.Fatalf("the sandbox chose backend %q, expected %q", s.Name(), backend)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	v, err := s.Verify(ctx)
	if err != nil {
		t.Fatalf("the real sandbox did not verify: %v\n%s", err, v.Summary())
	}

	// Every probe, named individually. An aggregate OK() would be satisfied
	// by a verification that ran two probes and called it three.
	if len(v.Probes) != len(sandbox.AllProbes) {
		t.Fatalf("%d probes ran, want %d: %s", len(v.Probes), len(sandbox.AllProbes), v.Summary())
	}
	for _, probe := range v.Probes {
		if !probe.Ran {
			t.Errorf("the %s probe did not run. A probe that did not run is not a denial", probe.Probe)
		}
		if !probe.Denied {
			t.Errorf("the %s boundary was CROSSED: %s", probe.Probe, probe.Detail)
		}
	}
	if !v.OK() {
		t.Fatalf("verification is not sound: %s", v.Summary())
	}
	t.Logf("real sandbox (%s): %s", backend, v.Summary())
}

// TestAnUndetectableEnvProbeDoesNotReportADenial is the assert-the-negative
// for the defect this file found.
//
// The environment probe used to append the canary to the CHILD's environment,
// past the allowlist that was supposed to remove it — and no isolation backend
// strips environment variables, so it could never report anything but an
// escape against a real sandbox. It reported a denial against the fake only
// because the fake runs no process.
//
// The boundary is enforced by FilterEnv, so proving it means: the variable is
// in the parent, absent from the allowlist, and must not arrive. If the parent
// does not have it, the probe cannot detect anything — and must say it did not
// run, rather than report a denial it never established.
func TestAnUndetectableEnvProbeDoesNotReportADenial(t *testing.T) {
	requireRealBackend(t)

	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T) sandbox.Policy
		canary  string
		wantFor string
	}{
		{
			name:    "the canary is not in the parent environment",
			setup:   func(t *testing.T) sandbox.Policy { os.Unsetenv(sandbox.CanaryVar); return realPolicy(t) },
			canary:  "a-value-nothing-exported",
			wantFor: "not set",
		},
		{
			name: "the canary is on the policy's allowlist",
			setup: func(t *testing.T) sandbox.Policy {
				t.Setenv(sandbox.CanaryVar, "permitted")
				p := realPolicy(t)
				p.AllowedEnv = append(p.AllowedEnv, sandbox.CanaryVar)
				return p
			},
			canary:  "permitted",
			wantFor: "allowlist",
		},
		{
			name:    "no canary is configured at all",
			setup:   func(t *testing.T) sandbox.Policy { return realPolicy(t) },
			canary:  "",
			wantFor: "nothing to look for",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.setup(t)
			s, err := sandbox.New(p, sandbox.Options{CanarySecret: tc.canary})
			if err != nil {
				t.Fatalf("building the real sandbox: %v", err)
			}

			v, err := s.Verify(context.Background())
			if err == nil {
				t.Fatal("verification succeeded with an environment probe that could not detect " +
					"a leak. A probe that cannot succeed outside the sandbox proves nothing when " +
					"it fails inside one")
			}

			var env *sandbox.ProbeResult
			for i := range v.Probes {
				if v.Probes[i].Probe == sandbox.ProbeEnv {
					env = &v.Probes[i]
				}
			}
			if env == nil {
				// Absent from the list is also correct: OK() requires every
				// probe to be present, so a missing one fails too.
				return
			}
			if env.Ran {
				t.Errorf("the environment probe reported that it RAN: %+v", *env)
			}
			if env.Denied {
				t.Fatalf("the environment probe reported a DENIAL it could not have established: %+v", *env)
			}
			if !strings.Contains(env.Detail, tc.wantFor) {
				t.Errorf("the probe does not say why it could not run: %q", env.Detail)
			}
		})
	}
}

// TestTheRealSandboxCannotWriteOutsideTheClone checks the filesystem boundary
// directly, rather than through the canary.
//
// Through the canary AND directly, because the canary runs `sh` and a backend
// that confined `sh` while leaving other processes free would pass the first
// and fail this.
func TestTheRealSandboxCannotWriteOutsideTheClone(t *testing.T) {
	requireRealBackend(t)
	p := realPolicy(t)

	s, err := sandbox.New(p, sandbox.Options{})
	if err != nil {
		t.Fatalf("building the real sandbox: %v", err)
	}

	outside := filepath.Join(t.TempDir(), "escaped")
	cmd, err := s.Command(context.Background(), "sh", "-c", "echo escaped > "+outside)
	if err != nil {
		t.Fatalf("building the command: %v", err)
	}
	_ = cmd.Run()

	if _, err := os.Stat(outside); err == nil {
		t.Fatalf("a confined process wrote %s, outside its clone directory", outside)
	}

	// And the clone IS writable, or the sandbox confines nothing by confining
	// everything — an agent that cannot write its own working tree does no
	// work, and a test that only checked the denial would pass on it.
	inside := filepath.Join(p.CloneDir, "allowed")
	cmd, err = s.Command(context.Background(), "sh", "-c", "echo ok > "+inside)
	if err != nil {
		t.Fatalf("building the command: %v", err)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the agent cannot write its own clone directory: %v\n%s", err, out)
	}
	if _, err := os.Stat(inside); err != nil {
		t.Fatalf("the write to the clone did not land: %v", err)
	}
}

// TestUnisolatedNeverVerifies is D2's third requirement: the harness refuses
// to start when isolation cannot be established.
//
// It runs here as well as against the fake, because this is the machine where
// the refusal matters. A deployment that could be coaxed into running the
// agent unconfined is the failure this whole package exists to prevent, and
// "we checked on a different machine" is not a proof about this one.
func TestUnisolatedNeverVerifies(t *testing.T) {
	requireRealBackend(t)

	s := sandbox.Unisolated(realPolicy(t))
	v, err := s.Verify(context.Background())
	if err == nil {
		t.Fatal("the unisolated sandbox verified. There is then a configuration in which the " +
			"agent runs with the runner's credentials, network and filesystem access, and nothing " +
			"reports it")
	}
	if v.OK() {
		t.Fatal("the unisolated sandbox reported a sound verification")
	}
	var notIsolated *sandbox.ErrNotIsolated
	if !asNotIsolated(err, &notIsolated) {
		t.Errorf("the refusal is not an *ErrNotIsolated, so a caller cannot recognise it: %v", err)
	}
}

// TestNoBackendIsARefusalNotADegradation checks that a machine without
// bubblewrap cannot be talked into running unconfined.
func TestNoBackendIsARefusalNotADegradation(t *testing.T) {
	requireRealBackend(t)

	_, err := sandbox.New(realPolicy(t), sandbox.Options{
		Backends: []string{"a-backend-that-does-not-exist"},
	})
	if err == nil {
		t.Fatal("a sandbox was built with no available backend. A sandbox that silently degrades " +
			"to no isolation is worse than none at all, because the deployment looks configured")
	}
}

func asNotIsolated(err error, target **sandbox.ErrNotIsolated) bool {
	for err != nil {
		if e, ok := err.(*sandbox.ErrNotIsolated); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
