package remediate_test

import (
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/remediate"
)

// Fix-group cap (OQ-P6-01, VM-AD §10 rule 8).
//
// The clause is specific: a group exceeding the cap SPLITS into several pull
// requests. It never emits one oversized pull request. A twenty-finding pull
// request is not reviewed — it is approved or ignored — so a cap that silently
// widened under load would quietly convert review into rubber-stamping, and
// nothing in the system would report that it had happened.

func groupConfig() remediate.GroupConfig {
	return remediate.GroupConfig{MaxPerPR: 8, MaxPerPRCode: 1}
}

func depFindings(n int) []model.Finding {
	out := make([]model.Finding, n)
	for i := range out {
		out[i] = model.Finding{
			// Fingerprints deliberately unsorted on input, so the test proves
			// grouping imposes an order rather than inheriting one.
			Fingerprint: string(rune('z'-i)) + "00000000000000",
			Repo:        "org/wanaware-api",
			Category:    model.CategoryDependency,
			State:       model.Triaged,
			Priority:    model.P1,
			Location:    model.Location{Module: "golang.org/x/crypto"},
			Versions:    model.Versions{Current: "v0.35.0", Fixed: "v0.36.0"},
		}
	}
	return out
}

// TestOversizedGroupSplitsIntoSeveralPullRequests is the gate clause.
func TestOversizedGroupSplitsIntoSeveralPullRequests(t *testing.T) {
	findings := depFindings(20)

	groups := remediate.Group("org/wanaware-api", findings, policy.ClassDependencyMinor, groupConfig())

	if len(groups) != 3 {
		t.Fatalf("20 findings with a cap of 8 produced %d groups, want 3", len(groups))
	}
	total := 0
	for i, g := range groups {
		if len(g.Findings) > 8 {
			t.Errorf("group %d holds %d findings, exceeding the cap of 8; an oversized pull request is not "+
				"reviewed, it is approved or ignored (VM-AD §10 rule 8)", i, len(g.Findings))
		}
		if len(g.Findings) == 0 {
			t.Errorf("group %d is empty", i)
		}
		total += len(g.Findings)
	}
	if total != 20 {
		t.Errorf("the split covers %d findings, want 20; a split that drops findings is worse than an "+
			"oversized pull request, because nothing reports the loss", total)
	}

	// Each split group gets its own identity and therefore its own branch. Two
	// groups sharing a branch would push over each other.
	seen := map[string]bool{}
	for _, g := range groups {
		if g.ID == "" {
			t.Error("a group has no identity; the branch could not be derived (VM-F-502)")
		}
		if seen[g.Branch] {
			t.Errorf("two groups share branch %q; the second would push over the first", g.Branch)
		}
		seen[g.Branch] = true
		if !strings.HasPrefix(g.Branch, "security/fix-") {
			t.Errorf("branch %q does not follow the convention", g.Branch)
		}
	}
}

// TestGroupingIsDeterministic is what makes the branch name usable as an
// idempotency key. If membership depended on input order, the same findings
// would produce different groups — and therefore different branches — on every
// run, and each run would open a fresh pull request for work already in review.
func TestGroupingIsDeterministic(t *testing.T) {
	findings := depFindings(12)
	reversed := make([]model.Finding, len(findings))
	for i, f := range findings {
		reversed[len(findings)-1-i] = f
	}

	a := remediate.Group("org/wanaware-api", findings, policy.ClassDependencyMinor, groupConfig())
	b := remediate.Group("org/wanaware-api", reversed, policy.ClassDependencyMinor, groupConfig())

	if len(a) != len(b) {
		t.Fatalf("group counts differ by input order: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Errorf("group %d identity differs by input order: %s vs %s", i, a[i].ID, b[i].ID)
		}
		if a[i].Branch != b[i].Branch {
			t.Errorf("group %d branch differs by input order: %s vs %s", i, a[i].Branch, b[i].Branch)
		}
	}
}

// TestGroupIdentityIsDerivedFromMembership covers VM-F-502. Re-running the same
// fix group must land on the same branch; changing the membership must not.
func TestGroupIdentityIsDerivedFromMembership(t *testing.T) {
	five := depFindings(5)

	first := remediate.Group("org/a", five, policy.ClassDependencyMinor, groupConfig())
	again := remediate.Group("org/a", five, policy.ClassDependencyMinor, groupConfig())
	if first[0].ID != again[0].ID {
		t.Error("the same fix group produced two identities; every run would open a new pull request (VM-F-502)")
	}

	four := remediate.Group("org/a", five[:4], policy.ClassDependencyMinor, groupConfig())
	if four[0].ID == first[0].ID {
		t.Error("a different membership produced the same identity; one branch would carry two different changes")
	}

	// The repository participates: the same advisory in two repositories is two
	// fix groups, and they must not collide on one branch name.
	other := remediate.Group("org/b", five, policy.ClassDependencyMinor, groupConfig())
	if other[0].ID == first[0].ID {
		t.Error("two repositories produced the same fix group identity")
	}
}

// TestCodeFixesGetTheirOwnCap covers max_findings_per_pr_code. A source change
// is reviewed line by line in a way a manifest bump is not, so batching several
// into one pull request makes each less likely to be read.
func TestCodeFixesGetTheirOwnCap(t *testing.T) {
	findings := depFindings(4)
	for i := range findings {
		findings[i].Category = model.CategoryCode
	}

	groups := remediate.Group("org/a", findings, policy.ClassCodeFix, groupConfig())
	if len(groups) != 4 {
		t.Fatalf("4 code fixes with a code cap of 1 produced %d groups, want 4", len(groups))
	}
	for _, g := range groups {
		if len(g.Findings) != 1 {
			t.Errorf("a code-fix group holds %d findings, want 1", len(g.Findings))
		}
	}
}

// TestGroupRefusesAnUnsetCap is the configuration guard. A zero cap read as
// "unlimited" would produce exactly the oversized pull request the rule
// forbids, and it would do so silently.
func TestGroupRefusesAnUnsetCap(t *testing.T) {
	findings := depFindings(20)
	groups := remediate.Group("org/a", findings, policy.ClassDependencyMinor, remediate.GroupConfig{})
	for _, g := range groups {
		if len(g.Findings) > remediate.FallbackMaxPerPR {
			t.Errorf("an unset cap produced a group of %d; a missing cap must fall back to a bounded "+
				"default, never to unlimited", len(g.Findings))
		}
	}
}

// TestSecretFindingsNeverEnterAFixGroup covers VM-F-407. A secret is not
// remediated by a code change: removing it from source leaves the credential
// live everywhere it has already been copied, so the only remediation is
// rotation by a human.
func TestSecretFindingsNeverEnterAFixGroup(t *testing.T) {
	findings := depFindings(3)
	findings[1].Category = model.CategorySecret

	groups := remediate.Group("org/a", findings, policy.ClassDependencyMinor, groupConfig())
	for _, g := range groups {
		for _, f := range g.Findings {
			if f.Category == model.CategorySecret {
				t.Error("a secret finding entered a work order (VM-F-407); no automated change can remediate it, " +
					"and a pull request touching the file would not rotate the credential")
			}
		}
	}
}
