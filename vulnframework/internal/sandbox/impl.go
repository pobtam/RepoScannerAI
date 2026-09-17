package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// Options configures the real sandbox.
type Options struct {
	// Backends are the isolation mechanisms to try, in order. Empty means the
	// platform defaults.
	Backends []string
	// CanarySecret is the value the environment probe looks for. It must be
	// present in the launching environment and absent inside the sandbox:
	// probing for an unset variable proves nothing.
	CanarySecret string
}

func (o Options) backends() []string {
	if len(o.Backends) > 0 {
		return o.Backends
	}
	// bubblewrap on Linux, sandbox-exec on macOS. Both are ordinary user-space
	// tools; neither requires the framework to be privileged.
	return []string{"bwrap", "sandbox-exec"}
}

// New builds a real sandbox, refusing if no isolation backend is available.
//
// Refusing is the point. A sandbox that silently degrades to "no isolation" is
// worse than none at all, because the deployment looks configured and the
// agent runs unconfined.
func New(p Policy, opts Options) (Sandbox, error) {
	if p.CloneDir == "" {
		return nil, fmt.Errorf("sandbox: a policy needs a clone directory; without one the agent runs " +
			"in the caller's working directory, which is the framework's own checkout")
	}
	for _, name := range opts.backends() {
		if path, err := exec.LookPath(name); err == nil {
			return &isolated{policy: p, backend: name, backendPath: path, opts: opts}, nil
		}
	}
	return nil, &ErrNotIsolated{
		Reason: fmt.Sprintf("no isolation backend found (tried %s)", strings.Join(opts.backends(), ", ")),
	}
}

// isolated is the real sandbox, backed by an OS mechanism.
type isolated struct {
	policy      Policy
	backend     string
	backendPath string
	opts        Options
}

func (s *isolated) Name() string   { return s.backend }
func (s *isolated) Policy() Policy { return s.policy }

func (s *isolated) Command(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	if s.policy.CloneDir == "" {
		return nil, fmt.Errorf("sandbox: no clone directory")
	}
	env, err := FilterEnv(s.policy, os.Environ())
	if err != nil {
		return nil, err
	}

	wrapped, wrappedArgs := s.wrap(name, args)
	cmd := exec.CommandContext(ctx, wrapped, wrappedArgs...)
	cmd.Dir = s.policy.CloneDir
	cmd.Env = env
	contain(cmd)
	return cmd, nil
}

// wrap builds the backend invocation.
//
// Deliberately minimal and explicit: a read-only root, a writable bind of the
// clone alone, no network namespace, and nothing inherited. Anything more
// permissive belongs in the policy where it can be reviewed, not in a default
// here where it cannot.
func (s *isolated) wrap(name string, args []string) (string, []string) {
	switch s.backend {
	case "bwrap":
		out := []string{
			"--unshare-all",       // no network, no IPC, no PID namespace sharing
			"--die-with-parent",   // the agent cannot outlive the harness
			"--ro-bind", "/", "/", // the world, read only
			"--bind", s.policy.CloneDir, s.policy.CloneDir, // the clone, writable
			"--tmpfs", "/tmp",
			"--chdir", s.policy.CloneDir,
			"--",
		}
		return s.backendPath, append(append(out, name), args...)
	case "sandbox-exec":
		return s.backendPath, append([]string{"-p", s.seatbeltProfile(), name}, args...)
	default:
		return name, args
	}
}

// seatbeltProfile is the macOS equivalent: deny by default, permit the clone.
func (s *isolated) seatbeltProfile() string {
	return fmt.Sprintf(`(version 1)
(deny default)
(allow process-exec process-fork)
(allow file-read*)
(deny file-write*)
(allow file-write* (subpath %q))
(deny network*)`, s.policy.CloneDir)
}

func (s *isolated) Verify(ctx context.Context) (Verification, error) {
	return runProbes(ctx, s, s.backend, s.opts.CanarySecret)
}

// Unisolated is a sandbox that confines nothing and says so.
//
// It exists so the absence of isolation is a value that can be passed around
// and refused, rather than a nil that silently means "unconfined". Verify
// never reports it as sound.
func Unisolated(p Policy) Sandbox { return &unisolated{policy: p} }

type unisolated struct{ policy Policy }

func (s *unisolated) Name() string   { return "none" }
func (s *unisolated) Policy() Policy { return s.policy }

func (s *unisolated) Command(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	if s.policy.CloneDir == "" {
		return nil, fmt.Errorf("sandbox: no clone directory")
	}
	env, err := FilterEnv(s.policy, os.Environ())
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = s.policy.CloneDir
	cmd.Env = env
	contain(cmd)
	return cmd, nil
}

func (s *unisolated) Verify(context.Context) (Verification, error) {
	err := &ErrNotIsolated{Reason: "this sandbox applies no isolation; only the environment allowlist holds"}
	return Verification{Backend: "none", Reason: err.Error()}, err
}

// runProbes executes every canary inside the sandbox.
func runProbes(ctx context.Context, s Sandbox, backend, canary string) (Verification, error) {
	v := Verification{Backend: backend}

	for _, probe := range AllProbes {
		script := ProbeScript(probe, s.Policy())
		cmd, err := s.Command(ctx, "sh", "-c", script)
		if err != nil {
			v.Probes = append(v.Probes, ProbeResult{Probe: probe, Ran: false, Detail: err.Error()})
			continue
		}
		if probe == ProbeEnv && canary != "" {
			// Injected OUTSIDE the allowlist on purpose: if the boundary holds
			// it will not arrive, and if it does arrive the boundary is open.
			cmd.Env = append(cmd.Env, "VF_SANDBOX_CANARY_SECRET="+canary)
		}
		out, err := cmd.CombinedOutput()
		escaped := strings.Contains(string(out), ProbeEscaped)
		v.Probes = append(v.Probes, ProbeResult{
			Probe: probe, Ran: true, Denied: !escaped,
			Detail: strings.TrimSpace(string(out)) + errSuffix(err),
		})
	}

	for _, r := range v.Probes {
		switch r.Probe {
		case ProbeNetwork:
			v.NetworkDenied = r.Ran && r.Denied
		case ProbeEnv:
			v.EnvDenied = r.Ran && r.Denied
		case ProbeWrite:
			v.WriteDenied = r.Ran && r.Denied
		}
	}
	if !v.OK() {
		return v, &ErrNotIsolated{Reason: v.Summary()}
	}
	return v, nil
}

func errSuffix(err error) string {
	if err == nil {
		return ""
	}
	return " (" + err.Error() + ")"
}

// --- Fake --------------------------------------------------------------------

// Fake is an in-memory sandbox whose boundaries can be made to leak.
//
// Per the standing sentinel it models the weakest permitted behaviour: a real
// sandbox can be misconfigured, and a backend can be present but ineffective.
// AllowEscape is how a test asks for that.
type Fake struct {
	mu      sync.Mutex
	policy  Policy
	escapes map[Probe]bool
	skip    map[Probe]bool
}

// NewFake builds a fake sandbox that denies everything.
func NewFake(p Policy) *Fake {
	return &Fake{policy: p, escapes: map[Probe]bool{}, skip: map[Probe]bool{}}
}

// AllowEscape makes a boundary leak.
func (f *Fake) AllowEscape(probes ...Probe) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range probes {
		f.escapes[p] = true
	}
	return f
}

// SkipProbe makes a probe fail to run, which must never read as denied.
func (f *Fake) SkipProbe(probes ...Probe) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range probes {
		f.skip[p] = true
	}
	return f
}

func (f *Fake) Name() string   { return "fake" }
func (f *Fake) Policy() Policy { return f.policy }

func (f *Fake) Command(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	if f.policy.CloneDir == "" {
		return nil, fmt.Errorf("sandbox: no clone directory; the command would run in the caller's " +
			"working directory, which is the framework's own checkout")
	}
	env, err := FilterEnv(f.policy, os.Environ())
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = f.policy.CloneDir
	cmd.Env = env
	// The fake confines nothing at the OS level, but it MUST reproduce the
	// process-group and wait-delay behaviour: a fake whose processes are
	// easier to kill than production's would hide exactly the bug this found.
	contain(cmd)
	return cmd, nil
}

func (f *Fake) Verify(context.Context) (Verification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	v := Verification{Backend: "fake"}
	for _, probe := range AllProbes {
		if f.skip[probe] {
			continue
		}
		v.Probes = append(v.Probes, ProbeResult{
			Probe: probe, Ran: true, Denied: !f.escapes[probe],
		})
	}
	for _, r := range v.Probes {
		switch r.Probe {
		case ProbeNetwork:
			v.NetworkDenied = r.Denied
		case ProbeEnv:
			v.EnvDenied = r.Denied
		case ProbeWrite:
			v.WriteDenied = r.Denied
		}
	}
	if !v.OK() {
		return v, &ErrNotIsolated{Reason: v.Summary()}
	}
	return v, nil
}
