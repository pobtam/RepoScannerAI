package orchestrator

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/wanaware/vulnframework/internal/nuguardopt"
	"github.com/wanaware/vulnframework/internal/store"
)

// NuGuard control in the scan worker (VM-UI-F-1201..1204).
//
// Security owners choose NuGuard's settings in the interface; the API only
// stores them. The scan worker resolves them for every repository it scans,
// within the ceiling its own flags set, and passes the result on the job.
// It is also the only process that talks to NuGuard, so it publishes what
// it finds out about the service as a status row the API can read without
// holding a key.

// NuGuardProbe is what one status check found.
type NuGuardProbe struct {
	Reachable      bool
	ServiceVersion string
	// ToolsAllowed is the service's own tool list; nil when it could not be
	// asked.
	ToolsAllowed []string
	// Err is the failure, already sanitized; empty when the check passed.
	Err string
}

// NuGuardControl is the scan worker's NuGuard configuration.
type NuGuardControl struct {
	// Ceiling is what the operator's flags allow. Not configured (no
	// -nuguard-url) means NuGuard is unavailable everywhere.
	Ceiling nuguardopt.Ceiling
	// Pinned is config/tools.lock's NuGuard version.
	Pinned string
	// Probe checks the service; nil when NuGuard is not configured.
	Probe func(ctx context.Context) NuGuardProbe
	// Every is how often the status is re-checked. Zero means 5 minutes.
	// While the service cannot be reached it is re-checked every
	// RetryEvery instead (zero: 30 seconds), so a sidecar that starts just
	// after the worker is not shown as down for five minutes.
	Every      time.Duration
	RetryEvery time.Duration

	mu           sync.Mutex
	serviceTools []string
	reachable    bool
}

func (c *NuGuardControl) every() time.Duration {
	c.mu.Lock()
	reachable := c.reachable
	c.mu.Unlock()
	if !reachable {
		if c.RetryEvery > 0 {
			return c.RetryEvery
		}
		return 30 * time.Second
	}
	if c.Every > 0 {
		return c.Every
	}
	return 5 * time.Minute
}

// ceiling is the operator's ceiling, narrowed to what the service offered
// at the last check.
func (c *NuGuardControl) ceiling() nuguardopt.Ceiling {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.Ceiling
	if c.serviceTools != nil {
		out.ServiceTools = append([]string{}, c.serviceTools...)
	}
	return out
}

// PublishNuGuardStatus checks the service, when one is configured, and
// writes the status row: with no URL, one row saying it is not configured.
func (w *ScanWorker) PublishNuGuardStatus(ctx context.Context) error {
	c := w.NuGuard
	if c == nil {
		return nil
	}
	st := store.NuGuardStatus{Configured: c.Ceiling.Configured, PinnedVersion: c.Pinned}
	if c.Ceiling.Configured && c.Probe != nil {
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		p := c.Probe(pctx)
		cancel()
		st.Reachable, st.ServiceVersion, st.LastError = p.Reachable, p.ServiceVersion, p.Err
		st.VersionOK = p.ServiceVersion != "" &&
			strings.TrimPrefix(p.ServiceVersion, "v") == strings.TrimPrefix(c.Pinned, "v")
		st.ToolsAllowedByService = p.ToolsAllowed
		c.mu.Lock()
		if p.ToolsAllowed != nil {
			c.serviceTools = append([]string{}, p.ToolsAllowed...)
		}
		c.reachable = p.Reachable
		c.mu.Unlock()
	}
	st.Ceiling = c.ceiling()
	st.CheckedAt = w.Orch.clock()
	return w.Orch.Store.PutNuGuardStatus(ctx, st)
}

// publishNuGuardStatusEvery re-publishes the status until ctx ends.
func (w *ScanWorker) publishNuGuardStatusEvery(ctx context.Context) {
	if w.NuGuard == nil || !w.NuGuard.Ceiling.Configured {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(w.NuGuard.every()):
			if err := w.PublishNuGuardStatus(ctx); err != nil && ctx.Err() == nil {
				w.log().Error("NuGuard status", "error", err)
			}
		}
	}
}

// resolveNuGuard resolves each claimed repository's NuGuard options: its
// request's own options, then its override, the fleet's setting and the
// worker's defaults, clipped to the ceiling. Nothing when NuGuard is not
// configured, so a deployment without it scans exactly as before.
func (w *ScanWorker) resolveNuGuard(ctx context.Context, byRepo map[string]store.ScanRequest) (SweepOptions, error) {
	c := w.NuGuard
	if c == nil || !c.Ceiling.Configured {
		return SweepOptions{}, nil
	}
	ceiling := c.ceiling()
	out := SweepOptions{NuGuard: map[string]*nuguardopt.Effective{}}
	for name, r := range byRepo {
		e, _, err := store.ResolveNuGuard(ctx, w.Orch.Store, ceiling, name, r.NuGuard)
		if err != nil {
			return SweepOptions{}, err
		}
		out.NuGuard[name] = &e
	}
	return out, nil
}
