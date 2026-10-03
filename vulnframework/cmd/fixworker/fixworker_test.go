package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/wanaware/vulnframework/internal/store"
)

// cmd/fixworker exists because RemediationPass had no caller outside tests and
// the demonstration (OQ-AUDIT-07). A function nothing runs is indistinguishable
// from a feature nobody has used yet, which is this build's recurring defect
// one level up from a field.

func quietPass(t *testing.T) *demoPass {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// The configuration lives at the module root; tests run in the package
	// directory.
	pass, err := newDemoPass(context.Background(), log, filepath.Join("..", "..", "config"))
	if err != nil {
		t.Fatalf("newDemoPass: %v", err)
	}
	return pass
}

// TestTheDryRunAgreesWithThePass is the test this binary needed most, and it
// was written after the defect rather than before it.
//
// The first version reported a claimable finding for a repository the real
// pass then skipped for having no test suite. A dry run that disagrees with
// the pass is worse than no dry run: somebody reads it to decide whether to
// run the pass, and acts on a number the pass will not produce.
func TestTheDryRunAgreesWithThePass(t *testing.T) {
	ctx := context.Background()
	pass := quietPass(t)

	repos, err := pass.repos(ctx, "")
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	if len(repos) == 0 {
		t.Fatal("the demonstration seeded no repositories, so this proves nothing")
	}

	predicted := 0
	for _, repo := range repos {
		n, err := pass.claimable(ctx, repo)
		if err != nil {
			t.Fatalf("claimable(%s): %v", repo.Name, err)
		}
		predicted += n
	}

	actual := 0
	attempted := false
	for _, repo := range repos {
		stats, err := pass.run(ctx, repo, 0)
		if err != nil {
			t.Fatalf("run(%s): %v", repo.Name, err)
		}
		actual += stats.Claimable
		if stats.Attempted > 0 {
			attempted = true
		}
	}

	if predicted != actual {
		t.Fatalf("the dry run predicted %d claimable findings and the pass found %d. "+
			"Somebody reads the dry run to decide whether to run the pass", predicted, actual)
	}
	if predicted == 0 {
		t.Fatal("both agreed on zero, which they would also do if neither looked at anything")
	}
	if !attempted {
		t.Error("the pass attempted no fix group at all, so the dispatch path this binary exists " +
			"to exercise did not run")
	}
}

// TestARepositoryWithNoTestSuiteIsSkippedByBoth is the specific rule behind
// the agreement above, asserted on its own so a future change cannot restore
// the disagreement while keeping the totals equal by accident.
func TestARepositoryWithNoTestSuiteIsSkippedByBoth(t *testing.T) {
	ctx := context.Background()
	pass := quietPass(t)

	repos, err := pass.repos(ctx, "")
	if err != nil {
		t.Fatalf("repos: %v", err)
	}

	var untestable int
	for _, repo := range repos {
		if repo.HasTestSuite {
			continue
		}
		untestable++

		// There is no verification gate without a test suite, and the
		// framework does not attempt a fix it cannot prove (VM-F-504).
		n, err := pass.claimable(ctx, repo)
		if err != nil {
			t.Fatalf("claimable(%s): %v", repo.Name, err)
		}
		if n != 0 {
			t.Errorf("the dry run promised %d findings for %s, which has no test suite to verify "+
				"a fix against", n, repo.Name)
		}

		stats, err := pass.run(ctx, repo, 0)
		if err != nil {
			t.Fatalf("run(%s): %v", repo.Name, err)
		}
		if stats.Attempted != 0 {
			t.Errorf("the pass attempted %d fix groups in %s, which cannot verify a fix",
				stats.Attempted, repo.Name)
		}
	}

	if untestable == 0 {
		t.Skip("the demonstration has no repository without a test suite, so this rule is untested")
	}
}

// TestTheRepoFilterSelectsExactly guards the one flag that can silently do the
// wrong thing.
//
// A -repo that matched nothing and was treated as "everything" would run the
// whole fleet on a typo.
func TestTheRepoFilterSelectsExactly(t *testing.T) {
	ctx := context.Background()
	pass := quietPass(t)

	all, err := pass.repos(ctx, "")
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	if len(all) < 2 {
		t.Skip("fewer than two repositories; the filter cannot be shown to select")
	}

	one, err := pass.repos(ctx, all[0].Name)
	if err != nil {
		t.Fatalf("repos(filter): %v", err)
	}
	if len(one) != 1 || one[0].Name != all[0].Name {
		t.Fatalf("the filter selected %d repositories, want exactly %s", len(one), all[0].Name)
	}

	none, err := pass.repos(ctx, "demo-org/does-not-exist")
	if err != nil {
		t.Fatalf("repos(missing): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("a filter matching nothing selected %d repositories. A typo would then run the "+
			"whole fleet", len(none))
	}
}

// TestArchivedRepositoriesAreOutOfScope keeps remediation off repositories
// nobody maintains.
//
// The archived repository is CREATED here rather than looked for. The first
// version of this test walked the demonstration's repositories asserting that
// none in scope was archived — and the demonstration has no archived
// repository, so it asserted nothing at all and passed against a version of
// the filter that had been deleted.
func TestArchivedRepositoriesAreOutOfScope(t *testing.T) {
	ctx := context.Background()
	pass := quietPass(t)

	const name = "demo-org/retired-service"
	if err := pass.store.UpsertRepo(ctx, store.Repo{
		Name: name, Tier: 3, Languages: []string{"go"}, Archived: true, HasTestSuite: true,
	}); err != nil {
		t.Fatalf("registering the archived repository: %v", err)
	}

	repos, err := pass.repos(ctx, "")
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	for _, repo := range repos {
		if repo.Name == name {
			t.Fatal("an archived repository is in scope for remediation. Nobody is maintaining it, " +
				"and a pull request opened against it has no reviewer")
		}
	}

	// And the filter does not override the rule: naming an archived
	// repository explicitly must not resurrect it.
	named, err := pass.repos(ctx, name)
	if err != nil {
		t.Fatalf("repos(archived): %v", err)
	}
	if len(named) != 0 {
		t.Fatalf("naming an archived repository with -repo put it back in scope")
	}
}
