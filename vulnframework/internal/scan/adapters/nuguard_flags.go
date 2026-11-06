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

	"github.com/wanaware/vulnframework/internal/scan"
)

// NuGuardAPIKeyEnv names the environment variable the NuGuard API key is read
// from. Never a flag, so it is in no shell history or process listing.
const NuGuardAPIKeyEnv = "VULNFRAMEWORK_NUGUARD_API_KEY"

// NuGuardFlags are the NuGuard settings a command takes. The same four flags
// on cmd/orchestrator and cmd/scanworker.
type NuGuardFlags struct {
	url, tools *string
	posture    *bool
	timeout    *time.Duration
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
	}
}

// Build returns the configured adapter, or nil when -nuguard-url is empty. It
// checks the service: a version or tool the service refuses stops the
// program; a service that cannot be reached is logged, and each scan then
// records a coverage gap.
//
// githubToken is the read-only token the worker already holds, or nil to
// scan public repositories only.
func (f *NuGuardFlags) Build(ctx context.Context, lock scan.ToolsLock, githubToken func() (string, error), log *slog.Logger) (*NuGuard, error) {
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
