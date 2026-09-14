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
