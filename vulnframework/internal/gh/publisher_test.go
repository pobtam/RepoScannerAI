package gh_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/gh"
)

// The git-backed report publisher (OQ-P7-02, VM-ADR-08).
//
// It replaces the fake from Phase 7, and it carries a coupling recorded at
// Phase 7b and never discharged: until identity→level exists (VM-UI-OQ-01),
// the privilege model is fail-closed against unauthenticated callers but
// TRUSTS an authenticated caller's self-asserted level.
//
// That was acceptable while the publisher was a fake and nothing left the
// process. It stops being acceptable the moment a real one exists, because a
// redacted pack would then be delivered to a real external recipient on trust.
// So the precondition is enforced in code rather than remembered.

// TestPublishingToAnExternalRecipientIsRefusedUntilIdentityIsBound is the
// named precondition from Phase 7b, made mechanical.
func TestPublishingToAnExternalRecipientIsRefusedUntilIdentityIsBound(t *testing.T) {
	p := gh.NewPublisher(gh.PublisherConfig{
		Repo: "org/security-reports", Branch: "main",
		// VM-UI-OQ-01 is open.
		IdentityBindingAvailable: false,
	}, gh.NewFakeGit())

	err := p.PublishFor(context.Background(), gh.Recipient{
		ID: "someone@partner.example", External: true, AssertedLevel: "security_owner",
	}, "runs/S-000001/fleet.md", []byte("# report"))

	if err == nil {
		t.Fatal("a redacted pack was published to an external recipient while the privilege model " +
			"still trusts a self-asserted level. The redaction is decorative until identity→level " +
			"exists (VM-UI-OQ-01)")
	}
	var unbound *gh.ErrIdentityUnbound
	if !errors.As(err, &unbound) {
		t.Fatalf("error is %T, want *gh.ErrIdentityUnbound", err)
	}
	// The refusal names both open questions, because whoever hits it needs to
	// know what would have to be true to proceed.
	for _, want := range []string{"VM-UI-OQ-01", "self-asserted"} {
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// TestPublishingInternallyIsAllowed is the other half: the precondition
// constrains EXTERNAL delivery, and blocking everything would stop the
// framework publishing its own reports to its own repository.
func TestPublishingInternallyIsAllowed(t *testing.T) {
	git := gh.NewFakeGit()
	p := gh.NewPublisher(gh.PublisherConfig{
		Repo: "org/security-reports", Branch: "main", IdentityBindingAvailable: false,
	}, git)

	if err := p.PublishFor(context.Background(), gh.Recipient{
		ID: "orchestrator", External: false,
	}, "runs/S-000001/fleet.md", []byte("# report")); err != nil {
		t.Fatalf("internal publication was refused: %v", err)
	}
	if got := git.File("runs/S-000001/fleet.md"); string(got) != "# report" {
		t.Errorf("the report was not written: %q", got)
	}
}

// TestPublishedReportsAreCommittedNotOverwritten covers VM-ADR-08. A report is
// immutable once issued (VM-ADR-15); publishing to a git repository is what
// makes that checkable years later, and an overwrite would destroy the
// property the storage choice exists for.
func TestPublishedReportsAreCommittedNotOverwritten(t *testing.T) {
	git := gh.NewFakeGit()
	p := gh.NewPublisher(gh.PublisherConfig{
		Repo: "org/security-reports", Branch: "main", IdentityBindingAvailable: true,
	}, git)
	ctx := context.Background()

	if err := p.Publish(ctx, "runs/S-000001/fleet.json", []byte(`{"id":"R-1"}`)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// The same path with different content is a different report, and
	// silently replacing it would make a citation ambiguous about which one it
	// refers to.
	err := p.Publish(ctx, "runs/S-000001/fleet.json", []byte(`{"id":"R-2"}`))
	if err == nil {
		t.Error("an issued report was overwritten. Reports are immutable (VM-ADR-15), and storing " +
			"them in git is what makes that checkable — an overwrite destroys the property the " +
			"storage choice exists for")
	}
	// Re-publishing identical content is idempotent: a retry after a network
	// failure must not fail.
	if err := p.Publish(ctx, "runs/S-000001/fleet.json", []byte(`{"id":"R-1"}`)); err != nil {
		t.Errorf("an identical re-publish failed: %v; a retry after a network failure is ordinary", err)
	}
	if n := git.Commits(); n != 1 {
		t.Errorf("%d commits for one distinct report, want 1", n)
	}
}

// TestAPublishFailureIsNotSilent is the honesty clause. A report that was not
// published, but reported as published, produces a citation to a document
// that does not exist.
func TestAPublishFailureIsNotSilent(t *testing.T) {
	git := gh.NewFakeGit().FailWith(errors.New("remote rejected: shallow update not allowed"))
	p := gh.NewPublisher(gh.PublisherConfig{
		Repo: "org/security-reports", Branch: "main", IdentityBindingAvailable: true,
	}, git)

	err := p.Publish(context.Background(), "runs/S-000001/fleet.json", []byte("{}"))
	if err == nil {
		t.Fatal("a failed publish reported success; the report would be cited and would not exist")
	}
	if !strings.Contains(err.Error(), "shallow update") {
		t.Errorf("the error loses the cause: %v", err)
	}
}
