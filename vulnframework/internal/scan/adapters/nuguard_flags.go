package adapters

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/wanaware/vulnframework/internal/nuguardopt"
	"github.com/wanaware/vulnframework/internal/scan"
)

// NuGuardAPIKeyEnv names the environment variable the NuGuard API key is read
// from. Never a flag, so it is in no shell history or process listing.
const NuGuardAPIKeyEnv = "VULNFRAMEWORK_NUGUARD_API_KEY"

// NuGuardFlags are the NuGuard settings a command takes. The same flags on
// cmd/orchestrator and cmd/scanworker.
//
// -nuguard-allow-tools, -nuguard-allow-posture and -nuguard-max-timeout are
// the operator's ceiling: what security owners may choose in the interface,
// never more (VM-UI-F-1202). -nuguard-tools, -nuguard-include-posture and
// -nuguard-timeout are the defaults for a fleet never configured there, and
// must sit within the ceiling.
type NuGuardFlags struct {
	url, tools, allowTools *string
	posture, allowPosture  *bool
	timeout, maxTimeout    *time.Duration
	sbomMax                *int64
}

// RegisterNuGuardFlags adds the NuGuard flags to fs.
func RegisterNuGuardFlags(fs *flag.FlagSet) *NuGuardFlags {
	return &NuGuardFlags{
		url: fs.String("nuguard-url", "", "NuGuard Remote Scan service URL (https, or http to loopback); "+
			"empty leaves NuGuard off. The API key is read from $"+NuGuardAPIKeyEnv),
		tools: fs.String("nuguard-tools", "", "comma-separated NuGuard tools; empty means "+
			"nga-rules,atlas,semgrep (the AI code rules; dependencies, IaC and containers are this project's own tools' job)"),
		posture: fs.Bool("nuguard-include-posture", false, "ask NuGuard for posture observations, counted into the AI inventory (never findings)"),
		timeout: fs.Duration("nuguard-timeout", 10*time.Minute, "time limit for one repository's NuGuard scan, inside the scan's own limit"),
		allowTools: fs.String("nuguard-allow-tools", strings.Join(nuguardopt.Selectable, ","),
			"the NuGuard tools security owners may choose in the interface (of "+strings.Join(nuguardopt.Selectable, ", ")+"); "+
				"-nuguard-tools must be within it"),
		allowPosture: fs.Bool("nuguard-allow-posture", true, "whether security owners may ask NuGuard for posture observations"),
		maxTimeout: fs.Duration("nuguard-max-timeout", 10*time.Minute, "the longest NuGuard time limit security owners may set; "+
			"-nuguard-timeout must be within it"),
		sbomMax: fs.Int64("nuguard-sbom-max-bytes", 4<<20, "largest AI-SBOM a scan may keep; a larger one is not stored, and the scan says why"),
	}
}

// URL is -nuguard-url; empty means NuGuard is not configured.
func (f *NuGuardFlags) URL() string { return strings.TrimSpace(*f.url) }

// SBOMMaxBytes is -nuguard-sbom-max-bytes.
func (f *NuGuardFlags) SBOMMaxBytes() int64 { return *f.sbomMax }

// Ceiling is what the operator allows, with the defaults for a fleet never
// configured in the interface. It refuses a default above the ceiling, and a
// ceiling naming a tool users may not choose: either would let a scan run
// with what the operator said no to. With no -nuguard-url it is the ceiling
// of a deployment without NuGuard: nothing is allowed.
func (f *NuGuardFlags) Ceiling() (nuguardopt.Ceiling, error) {
	if f.URL() == "" {
		return nuguardopt.Ceiling{}, nil
	}
	allow, err := ParseNuGuardTools(*f.allowTools)
	if err != nil {
		return nuguardopt.Ceiling{}, fmt.Errorf("-nuguard-allow-tools: %w", err)
	}
	c := nuguardopt.Ceiling{Configured: true, AllowPosture: *f.allowPosture, MaxTimeoutS: int(f.maxTimeout.Seconds())}
	for _, t := range allow {
		if !nuguardopt.IsSelectable(string(t)) {
			return nuguardopt.Ceiling{}, fmt.Errorf("-nuguard-allow-tools: %q is not a tool users may choose (%s); "+
				"dependency, IaC and container scanning stay with this project's own tools", t, strings.Join(nuguardopt.Selectable, ", "))
		}
		c.AllowTools = append(c.AllowTools, string(t))
	}
	defaults, err := ParseNuGuardTools(*f.tools)
	if err != nil {
		return nuguardopt.Ceiling{}, err
	}
	c.Defaults = nuguardopt.Fleet{Enabled: true, IncludePosture: *f.posture, TimeoutS: int(f.timeout.Seconds())}
	for _, t := range defaults {
		c.Defaults.Tools = append(c.Defaults.Tools, string(t))
	}
	if *f.maxTimeout <= 0 {
		return nuguardopt.Ceiling{}, errors.New("-nuguard-max-timeout must be positive")
	}
	if errs := nuguardopt.ValidateFleet(c, c.Defaults); len(errs) > 0 {
		var why []string
		for _, e := range errs {
			why = append(why, map[string]string{"tools": "-nuguard-tools", "include_posture": "-nuguard-include-posture",
				"timeout_s": "-nuguard-timeout"}[e.Field]+": "+e.Why)
		}
		return nuguardopt.Ceiling{}, fmt.Errorf("a NuGuard default exceeds the operator's ceiling: %s", strings.Join(why, "; "))
	}
	return c, nil
}

// Build returns the configured adapter, or nil when -nuguard-url is empty. It
// checks the service: a version or tool the service refuses stops the
// program; a service that cannot be reached is logged, and each scan then
// records a coverage gap.
//
// githubToken is the read-only token the worker already holds, or nil to
// scan public repositories only.
func (f *NuGuardFlags) Build(ctx context.Context, lock scan.ToolsLock, githubToken func() (string, error), log *slog.Logger) (*NuGuard, error) {
	if _, err := f.Ceiling(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(*f.url) == "" {
		log.Info("NuGuard is off: no -nuguard-url, so the adapter is not registered and runs record no AI inventory")
		return nil, nil
	}
	a, err := NewNuGuardFromConfig(NuGuardConfig{
		URL: *f.url, Tools: *f.tools, IncludePosture: *f.posture, Timeout: *f.timeout,
		APIKey: nuguardAPIKey, GitHubToken: githubToken,
	}, lock.MustVersion("nuguard"))
	if err != nil {
		return nil, err
	}
	check, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := a.CheckService(check); err != nil {
		var refused *ErrNuGuardRefused
		if errors.As(err, &refused) {
			return nil, err
		}
		log.Warn("NuGuard could not be checked; starting anyway, and each scan records a coverage gap until it answers",
			"error", err.Error())
	}
	return a, nil
}

// nuguardAPIKey reads the key at the moment of use.
func nuguardAPIKey() (string, error) {
	k := os.Getenv(NuGuardAPIKeyEnv)
	if k == "" {
		return "", fmt.Errorf("%s is not set; NuGuard needs its API key there", NuGuardAPIKeyEnv)
	}
	return k, nil
}

// OptionalToken returns a function reading the token in env, or nil when env
// is unset: NuGuard then scans public repositories without one.
func OptionalToken(env string) func() (string, error) {
	if os.Getenv(env) == "" {
		return nil
	}
	return func() (string, error) {
		t := os.Getenv(env)
		if t == "" {
			return "", fmt.Errorf("%s is not set", env)
		}
		return t, nil
	}
}
