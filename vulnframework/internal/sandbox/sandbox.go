// Package sandbox isolates the agent's PROCESS (VM-AD §15.2).
//
// Phase 10a made the agent capability-denied with respect to the framework:
// it is a Fixer, so it has no store, no credentials and no pull-request
// surface, and it cannot push whatever it decides to do. That guarantee is
// about the agent's RETURN VALUE.
//
// It says nothing about the agent's process. A headless model driving a shell
// inherits the environment it was launched with — a CI runner's registry
// tokens, cloud credentials and signing keys — can open a socket to anywhere,
// and can write to any path its user owns. Without this package the agent is
// capability-denied on paper and capability-rich in practice, and the gap is
// invisible: every framework-level test passes.
//
// Three boundaries, and the package's whole design follows from one decision
// about them: they are PROVEN, not declared. Verify runs a canary inside the
// sandbox that actively tries to cross each one. An implementation that
// reported "denied" from its own configuration would be asserting that it is
// configured, which is not the same claim and is the class of self-confirming
// test this build has spent its whole length removing.
package sandbox

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// Policy is what the agent's process is permitted.
type Policy struct {
	// CloneDir is the only directory the agent may write to.
	CloneDir string
	// AllowedEnv names the environment variables that reach the process.
	// Everything else is dropped, including anything added to the runner
	// later: an allowlist fails safe as the environment grows, a deny-list
	// does not.
	AllowedEnv []string
	// EgressAllow is the only network the agent may reach, as host:port. In
	// practice one entry: the model endpoint.
	EgressAllow []string
}

// Probe is one boundary the canary tries to cross.
type Probe string

const (
	// ProbeNetwork attempts egress to a host that is not the model endpoint.
	ProbeNetwork Probe = "network"
	// ProbeEnv attempts to read an environment variable outside the allowlist.
	ProbeEnv Probe = "env"
	// ProbeWrite attempts to write a file outside the clone.
	ProbeWrite Probe = "write"
)

// AllProbes is the closed set. Verify runs every one of them: a probe that is
// skipped and reported as denied is the same lie as one that never existed.
var AllProbes = []Probe{ProbeNetwork, ProbeEnv, ProbeWrite}

// ProbeEscaped is what a canary prints when it gets through. Its absence is
// not evidence — a probe that failed to run also prints nothing — which is why
// ProbeResult records Ran separately.
const ProbeEscaped = "VF_SANDBOX_ESCAPED"

// ProbeResult is one canary's outcome.
type ProbeResult struct {
	Probe  Probe  `json:"probe"`
	Ran    bool   `json:"ran"`
	Denied bool   `json:"denied"`
	Detail string `json:"detail,omitempty"`
}

// Verification is the result of probing every boundary.
type Verification struct {
	Backend       string        `json:"backend"`
	NetworkDenied bool          `json:"network_denied"`
	EnvDenied     bool          `json:"env_denied"`
	WriteDenied   bool          `json:"write_denied"`
	Probes        []ProbeResult `json:"probes"`
	Reason        string        `json:"reason,omitempty"`
}

// OK reports whether every boundary held AND every probe actually ran.
func (v Verification) OK() bool {
	if len(v.Probes) != len(AllProbes) {
		return false
	}
	for _, p := range v.Probes {
		if !p.Ran || !p.Denied {
			return false
		}
	}
	return v.NetworkDenied && v.EnvDenied && v.WriteDenied
}

// Summary names what is open, so an operator learns which boundary failed
// rather than that one did.
func (v Verification) Summary() string {
	if v.Reason != "" && len(v.Probes) == 0 {
		return v.Reason
	}
	var open []string
	for _, p := range v.Probes {
		switch {
		case !p.Ran:
			open = append(open, string(p.Probe)+" (probe did not run)")
		case !p.Denied:
			open = append(open, string(p.Probe)+" (escaped)")
		}
	}
	missing := map[Probe]bool{}
	for _, p := range AllProbes {
		missing[p] = true
	}
	for _, p := range v.Probes {
		delete(missing, p.Probe)
	}
	for p := range missing {
		open = append(open, string(p)+" (not probed)")
	}
	sort.Strings(open)

	if len(open) == 0 {
		return fmt.Sprintf("sandbox %s: network, environment and filesystem boundaries all held", v.Backend)
	}
	return fmt.Sprintf("sandbox %s: NOT sound — %s. %s",
		v.Backend, strings.Join(open, "; "), v.Reason)
}

// Sandbox confines a process.
type Sandbox interface {
	Name() string
	Policy() Policy
	// Command builds a confined command.
	Command(ctx context.Context, name string, args ...string) (*exec.Cmd, error)
	// Verify probes every boundary from inside the sandbox.
	Verify(ctx context.Context) (Verification, error)
}

// ErrNotIsolated reports a sandbox that cannot confine anything.
type ErrNotIsolated struct{ Reason string }

func (e *ErrNotIsolated) Error() string {
	return "sandbox: no isolation available: " + e.Reason +
		". Refusing rather than running the agent unconfined: an agent process inherits the runner's " +
		"credentials, can reach any host and can write any path, and none of that is visible to a " +
		"framework-level test (VM-AD §15.2)"
}

// FilterEnv reduces an environment to the allowlist.
//
// An allowlist rather than a deny-list, because the environment grows: a
// deny-list is correct only until someone adds a variable, and the failure is
// silent. A wildcard entry is refused for the same reason it would be
// tempting — it reads, in a configuration file, exactly like isolation.
func FilterEnv(p Policy, env []string) ([]string, error) {
	allow := map[string]bool{}
	for _, name := range p.AllowedEnv {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" || trimmed == "*" || strings.EqualFold(trimmed, "all") {
			return nil, fmt.Errorf(
				"sandbox: environment allowlist entry %q would pass everything through while reading "+
					"like a configured allowlist; name each variable the agent needs", name)
		}
		allow[trimmed] = true
	}

	var out []string
	for _, kv := range env {
		i := strings.IndexByte(kv, '=')
		if i < 0 {
			continue
		}
		if allow[kv[:i]] {
			out = append(out, kv)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ProbeScript renders the canary for a boundary.
//
// Each has to be something that genuinely succeeds outside a sandbox. A probe
// that cannot succeed anywhere proves nothing when it fails, and would turn
// the whole verification into a formality that always passes.
func ProbeScript(p Probe, policy Policy) string {
	switch p {
	case ProbeNetwork:
		// A host that is emphatically not the model endpoint. Deliberately an
		// address rather than a name, so a DNS block and a network block are
		// distinguishable: a sandbox that only breaks resolution still lets an
		// agent reach a hard-coded address.
		return `if command -v curl >/dev/null 2>&1; then
  curl --max-time 4 -s -o /dev/null http://1.1.1.1/ && echo ` + ProbeEscaped + `
else
  (exec 3<>/dev/tcp/1.1.1.1/80) 2>/dev/null && echo ` + ProbeEscaped + `
fi
exit 0`
	case ProbeEnv:
		return `if [ -n "$VF_SANDBOX_CANARY_SECRET" ]; then echo ` + ProbeEscaped + `; fi
exit 0`
	case ProbeWrite:
		// Outside the clone, in a place every user can write if nothing stops
		// them.
		return `t="${TMPDIR:-/tmp}/vf-sandbox-canary.$$"
if echo escaped > "$t" 2>/dev/null; then rm -f "$t"; echo ` + ProbeEscaped + `; fi
exit 0`
	default:
		return ""
	}
}

// CanaryEnv is the environment a probe runs with: the policy's allowlist plus
// the canary secret the env probe looks for.
//
// The secret is injected deliberately. Testing that an UNSET variable is
// unreadable proves nothing; the probe has to look for something that exists
// outside the boundary and must not exist inside it.
func CanaryEnv(p Policy, env []string) ([]string, error) {
	filtered, err := FilterEnv(p, env)
	if err != nil {
		return nil, err
	}
	return filtered, nil
}
