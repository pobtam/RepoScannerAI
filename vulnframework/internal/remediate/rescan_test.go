package remediate_test

import (
	"context"
	"testing"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/gh"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/remediate"
)

// OQ-AUDIT-06 — the verification gate asks about ITS OWN group.
//
// Every earlier test in this package remediated one group in a repository with
// one vulnerable module, and under that fixture "the re-scan is clean" and
// "this group's findings are gone" are the same sentence. They are not the
// same sentence in a real repository. A re-scan sees everything, so a gate that
// failed on anything the scanners still report would make a repository with
// two vulnerable modules permanently unremediable: group A fails because B is
// open, B fails because A is open, and the framework reports both as
// FIX_INEFFECTIVE for ever.
//
// The audit found this by being the first thing in the codebase to remediate a
// repository with twenty-six groups in it.

func otherModuleRaw(module, advisory, current, fixed string) model.RawFinding {
	return model.RawFinding{
		Repo: repo, Category: model.CategoryDependency,
		Module: module, ModuleMajor: "v1",
		Tool: "govulncheck", ToolVersion: "v1.8.0", PrimaryID: advisory,
		Versions: model.Versions{Current: current, Fixed: fixed},
		Classification: model.Classification{
			Severity: model.SeverityHigh, Reachable: model.ReachableTrue, DepClass: model.DepProduction,
		},
	}
}

func TestOneGroupVerifiesWhileAnotherModuleIsStillVulnerable(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	mine := cryptoRaw("govulncheck", "v0.36.0")
	theirs := otherModuleRaw("golang.org/x/text", "GO-2025-0777", "v1.2.0", "v1.3.0")
	_, fps := seed(t, s, mine, theirs)
	if len(fps) != 2 {
		t.Fatalf("seeded %d findings, want 2 (two modules)", len(fps))
	}

	remote := gh.NewFake("main")
	tc := remediate.NewFakeToolchain().
		WithModule("golang.org/x/crypto", "v0.35.0").
		WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0").
		// The other module is vulnerable and stays vulnerable: nothing in this
		// attempt touches it, and the re-scan will keep reporting it.
		WithModule("golang.org/x/text", "v1.2.0").
		WithAdvisory("GO-2025-0777", "golang.org/x/text", "v1.3.0")
	w := newWorker(t, s, remote, tc)

	// One group, holding only the crypto finding.
	mineFP := fingerprint.Compute(mine)
	group := groupOf(t, s, []string{mineFP})

	res, err := w.Remediate(ctx, group)
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if res.Outcome != remediate.OutcomePROpen {
		t.Fatalf("outcome = %s, want pr_open. The other module's advisory is not this group's "+
			"business, and failing on it makes a multi-module repository unremediable.\n%s",
			res.Outcome, res.Verification.Output)
	}
	if !res.Verification.RescanClean {
		t.Errorf("the re-scan reported %v as this group's remaining findings; the group's own "+
			"finding was %s", res.Verification.Remaining, mineFP)
	}
	// And the other module was NOT quietly bumped to make the gate pass.
	if got := tc.Version("golang.org/x/text"); got != "v1.2.0" {
		t.Errorf("golang.org/x/text is at %s; this attempt had no business touching it", got)
	}
}

// TestAGroupStillFailsOnItsOwnUnclosedAdvisory is the other half. Scoping the
// re-scan must not become a way to pass verification: the group's own finding
// still has to be gone.
func TestAGroupStillFailsOnItsOwnUnclosedAdvisory(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	mine := cryptoRaw("govulncheck", "v0.36.0")
	theirs := otherModuleRaw("golang.org/x/text", "GO-2025-0777", "v1.2.0", "v1.3.0")
	_, _ = seed(t, s, mine, theirs)

	remote := gh.NewFake("main")
	tc := remediate.NewFakeToolchain().
		WithModule("golang.org/x/crypto", "v0.35.0").
		WithAdvisory("GO-2025-3106", "golang.org/x/crypto", "v0.36.0").
		// The proxy has not mirrored v0.36.0, so the bump resolves short.
		WithCeiling("golang.org/x/crypto", "v0.35.5").
		WithModule("golang.org/x/text", "v1.2.0").
		WithAdvisory("GO-2025-0777", "golang.org/x/text", "v1.3.0")
	w := newWorker(t, s, remote, tc)

	group := groupOf(t, s, []string{fingerprint.Compute(mine)})
	res, err := w.Remediate(ctx, group)
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if res.Outcome == remediate.OutcomePROpen {
		t.Fatal("a bump that did not close this group's own advisory opened a pull request")
	}
	if res.Verification.RescanClean {
		t.Error("the re-scan reported clean while this group's advisory is still open")
	}
	if len(remote.OpenPRs(repo)) != 0 {
		t.Errorf("%d pull requests were opened despite a failed verification (VM-F-506)", len(remote.OpenPRs(repo)))
	}
}

// TestExpectNamesEveryIdentifierAScannerMightUse is the reason Expect collects
// more than one name per finding: two tools report one vulnerability under
// different identifiers, and the gate must recognise its own finding whichever
// name the re-scan comes back with.
func TestExpectNamesEveryIdentifierAScannerMightUse(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, fps := seed(t, s, cryptoRaw("govulncheck", "v0.36.0"), cryptoRaw("osv-scanner", "v0.35.5"))
	group := groupOf(t, s, fps)

	expect := remediate.Expect(group)
	want := []string{"GO-2025-3106", "GHSA-hcg3-q754-cr77", "CVE-2025-22869", fps[0]}
	for _, id := range want {
		var found bool
		for _, got := range expect {
			if got == id {
				found = true
			}
		}
		if !found {
			t.Errorf("Expect() omits %q; a re-scan reporting the finding under that name would "+
				"look like a different group's finding and pass unnoticed. got=%v", id, expect)
		}
	}

	// A group asked to close an advisory it does not hold must still fail.
	remote := gh.NewFake("main")
	tc := remediate.NewFakeToolchain().
		WithModule("golang.org/x/crypto", "v0.35.0").
		// The re-scan will report this under the GHSA name, which the group
		// also owns.
		WithAdvisory("GHSA-hcg3-q754-cr77", "golang.org/x/crypto", "v0.37.0")
	w := newWorker(t, s, remote, tc)
	res, err := w.Remediate(ctx, group)
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if res.Outcome == remediate.OutcomePROpen {
		t.Fatalf("the group verified while its own finding was still reported under an alias: %v",
			res.Verification.Remaining)
	}
}

var _ = policy.ClassDependencyMinor
