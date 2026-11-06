package adapters

import (
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/runner"
)

// All builds every adapter in the VM-AD §8.2 tool matrix, each pinned to its
// version from config/tools.lock.
//
// Adding a scanner means implementing scan.Adapter and adding one line here.
// Nothing downstream changes (VM-NF-502).
func All(r runner.CommandRunner, lock scan.ToolsLock) []scan.Adapter {
	return []scan.Adapter{
		NewGovulncheck(r, lock.MustVersion("govulncheck")),
		NewGosec(r, lock.MustVersion("gosec")),
		NewStaticcheck(r, lock.MustVersion("staticcheck")),
		NewOSVScanner(r, lock.MustVersion("osv-scanner")),
		NewGitleaks(r, lock.MustVersion("gitleaks")),
		NewTrivy(r, lock.MustVersion("trivy")),
		NewSemgrep(r, lock.MustVersion("semgrep")),
		NewNPMAudit(r, lock.MustVersion("npm-audit")),
		NewActionsPin(r, lock.MustVersion("actions-pin")),
	}
}

// NewRegistry builds a populated adapter registry.
func NewRegistry(r runner.CommandRunner, lock scan.ToolsLock) (*scan.Registry, error) {
	return scan.NewRegistry(All(r, lock)...)
}

// Optional holds the opt-in adapters a deployment configured. A nil field is
// an adapter that is off: not registered, not on the run's tool list, and
// nothing about any scan changes (VM-NF-502).
type Optional struct {
	// NuGuard is the remote AI code-rule and inventory adapter, configured
	// with -nuguard-url.
	NuGuard *NuGuard
}

// AllWith builds every adapter All does, plus the configured opt-in ones.
// The registry orders adapters by name, so a scan's tool set stays
// deterministic whatever is added.
func AllWith(r runner.CommandRunner, lock scan.ToolsLock, opt Optional) []scan.Adapter {
	out := All(r, lock)
	if opt.NuGuard != nil {
		out = append(out, opt.NuGuard)
	}
	return out
}

// NewRegistryWith builds a registry of every adapter plus the configured
// opt-in ones.
func NewRegistryWith(r runner.CommandRunner, lock scan.ToolsLock, opt Optional) (*scan.Registry, error) {
	return scan.NewRegistry(AllWith(r, lock, opt)...)
}
