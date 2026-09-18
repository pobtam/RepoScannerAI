// Package remediate turns triaged findings into pull requests (VM-AD §11).
//
// The harness performs every repository-mutating operation. A worker — the
// deterministic bumper here, the agent in Phase 10 — produces a working tree
// and nothing else: it does not commit, push, or open a pull request. That
// separation is what keeps guard enforcement and credential handling out of any
// worker's reach (VM-AD §11.4), and it is why the guard can be trusted about an
// agent it was written before.
package remediate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/store"
)

// FallbackMaxPerPR bounds a group when configuration supplies no cap.
//
// A zero cap must not read as unlimited. That would produce exactly the
// oversized pull request VM-AD §10 rule 9 forbids, silently, from a
// configuration mistake rather than a decision.
const FallbackMaxPerPR = 8

// GroupConfig is the per-pull-request cap, from policy.defaults.
type GroupConfig struct {
	MaxPerPR     int
	MaxPerPRCode int
}

// FixGroup is the actionable unit: one pull request (VM-ADR-05).
type FixGroup struct {
	ID    string
	Repo  string
	Class policy.Class
	// Branch derives from ID, which makes re-running the same fix group
	// idempotent: the branch either exists (adopt) or does not (proceed). This
	// is the mechanism for VM-F-502.
	Branch   string
	Findings []model.Finding
}

// Fingerprints returns the group's membership, sorted.
func (g FixGroup) Fingerprints() []string {
	out := make([]string, 0, len(g.Findings))
	for _, f := range g.Findings {
		out = append(out, f.Fingerprint)
	}
	sort.Strings(out)
	return out
}

// Group partitions findings into fix groups under the cap (VM-AD §10 rule 9).
//
// Splitting rather than truncating is the whole point. A cap that emitted one
// oversized pull request would convert review into rubber-stamping — a
// twenty-finding pull request is approved or ignored, not read — and a cap that
// dropped the remainder would be worse still, because nothing would report the
// loss.
//
// Membership is decided by sorted fingerprint, so the same findings always
// produce the same groups whatever order they arrive in. Without that, a branch
// name could not serve as an idempotency key: each run would compute different
// membership, derive a different branch, and open a fresh pull request for work
// already in review.
func Group(repo string, findings []model.Finding, class policy.Class, cfg GroupConfig) []FixGroup {
	limit := cfg.MaxPerPR
	if isCodeClass(class) && cfg.MaxPerPRCode > 0 {
		// A source change is reviewed line by line in a way a manifest bump is
		// not, so several in one pull request makes each less likely to be read.
		limit = cfg.MaxPerPRCode
	}
	if limit <= 0 {
		limit = FallbackMaxPerPR
	}

	eligible := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		// A secret never enters a work order (VM-F-407). No automated change
		// remediates one: removing it from source leaves the credential live in
		// every clone, cache and backup, so the only remediation is rotation by
		// a human.
		if f.Category == model.CategorySecret {
			continue
		}
		eligible = append(eligible, f)
	}
	sort.Slice(eligible, func(i, j int) bool { return eligible[i].Fingerprint < eligible[j].Fingerprint })

	var out []FixGroup
	for start := 0; start < len(eligible); start += limit {
		end := start + limit
		if end > len(eligible) {
			end = len(eligible)
		}
		chunk := eligible[start:end]
		id := GroupID(repo, fingerprintsOf(chunk))
		out = append(out, FixGroup{
			ID: id, Repo: repo, Class: class,
			Branch:   BranchFor(id),
			Findings: append([]model.Finding(nil), chunk...),
		})
	}
	return out
}

// GroupID is sha256 over the repository and the sorted fingerprints (VM-AD
// §11.1).
//
// The repository participates because the same advisory in two repositories is
// two fix groups, and two branches with one name would push over each other.
func GroupID(repo string, fingerprints []string) string {
	sorted := append([]string(nil), fingerprints...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(repo + "\x1f" + strings.Join(sorted, "\x1f")))
	return hex.EncodeToString(sum[:])[:6]
}

// BranchFor renders the branch name for a group identity.
func BranchFor(id string) string { return "security/fix-" + id }

// WorkOrder is the bounded instruction both worker kinds consume (VM-AD §11.1).
type WorkOrder struct {
	RunID      string          `json:"run_id"`
	Repo       string          `json:"repo"`
	Mode       string          `json:"mode"`
	FixGroupID string          `json:"fix_group_id"`
	Branch     string          `json:"branch"`
	Findings   []model.Finding `json:"findings"`
	Policy     OrderPolicy     `json:"policy"`
	Budget     OrderBudget     `json:"budget"`

	BaselineRequired bool `json:"baseline_required"`
}

// OrderPolicy is the policy slice a worker is permitted to see.
type OrderPolicy struct {
	DenyPaths        []string `json:"deny_paths"`
	AllowMajor       bool     `json:"allow_major"`
	AllowSuppression bool     `json:"allow_suppression"`
	RequireTest      bool     `json:"require_test"`
}

// OrderBudget bounds an agentic run. It is carried on every order so the
// deterministic path and the agentic path share one shape.
type OrderBudget struct {
	MaxIterations   int `json:"max_iterations"`
	MaxWallClockSec int `json:"max_wall_clock_sec"`
}

// Targets derives the module bumps a group implies.
//
// The target version is the finding's fixed version, which the store's
// projection has already resolved to the HIGHEST candidate across sources
// (OQ-P1-02). Taking the lowest would close one source's advisory and leave
// another's open — a pull request that reads as a completed fix while the next
// scan immediately regresses the finding.
func (g FixGroup) Targets() []Target {
	byModule := map[string]Target{}
	for _, f := range g.Findings {
		if f.Location.Module == "" || f.Versions.Fixed == "" {
			continue
		}
		t := Target{
			Module:  f.Location.Module,
			From:    f.Versions.Current,
			To:      f.Versions.Fixed,
			Closes:  []string{f.Identity.PrimaryID},
			Finding: f.Fingerprint,
		}
		if existing, ok := byModule[t.Module]; ok {
			// Two findings in one module: bump once, to whichever version
			// closes both.
			if store.CompareVersions(existing.To, t.To) >= 0 {
				t.To = existing.To
			}
			t.Closes = append(existing.Closes, t.Closes...)
		}
		byModule[t.Module] = t
	}

	out := make([]Target, 0, len(byModule))
	for _, t := range byModule {
		sort.Strings(t.Closes)
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out
}

// Target is one module bump.
type Target struct {
	Module  string   `json:"module"`
	From    string   `json:"from"`
	To      string   `json:"to"`
	Closes  []string `json:"closes"`
	Finding string   `json:"finding"`
}

func (t Target) String() string { return fmt.Sprintf("%s %s → %s", t.Module, t.From, t.To) }

func fingerprintsOf(findings []model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Fingerprint)
	}
	return out
}

func isCodeClass(c policy.Class) bool {
	return c == policy.ClassCodeFix
}

// Expect names every identifier the re-scan must no longer report for a group.
//
// Advisory identifier, rule identifier and fingerprint, because the scanners
// report findings under different names and the gate must recognise its own
// group's findings whichever name comes back (OQ-AUDIT-06).
func Expect(g FixGroup) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	for _, f := range g.Findings {
		add(f.Identity.PrimaryID)
		if f.Identity.RuleID != nil {
			add(*f.Identity.RuleID)
		}
		add(f.Fingerprint)
		for _, alias := range f.Identity.Aliases {
			add(alias)
		}
	}
	sort.Strings(out)
	return out
}
