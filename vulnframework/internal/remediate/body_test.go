package remediate_test

import (
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/remediate"
)

// Applied.Dropped was instance twelve of this build's recurring defect: a
// field a consumer would want and no producer wrote, and which — unusually
// for the set — no consumer read either. VM-AD §11.3 specifies the bisect
// that drops a bump and VM-F-543 requires a pull request to state anything
// deferred and why, and between them nothing did.
//
// These tests are the consumer side.

func bodyGroup() remediate.FixGroup {
	return remediate.FixGroup{
		ID: "ab12cd", Repo: "org/api", Branch: "security/fix-ab12cd",
		Findings: []model.Finding{{
			Fingerprint: "f1", Category: model.CategoryDependency,
			Identity: model.Identity{PrimaryID: "GHSA-aaaa-bbbb-cccc"},
			Priority: model.P1,
		}},
	}
}

// TestTheBodyNamesEveryDroppedBumpAndWhy is the requirement.
//
// A dropped bump leaves no trace in the diff: the module is simply at the
// version it was already at. A reviewer who is not told will read the pull
// request as remediating the whole group, and the finding the dropped module
// carried stays open behind a merged change that looks like a fix.
func TestTheBodyNamesEveryDroppedBumpAndWhy(t *testing.T) {
	targets := []remediate.Target{
		{Module: "example.com/safe", From: "v1.0.0", To: "v1.2.0", Closes: []string{"GHSA-aaaa-bbbb-cccc"}},
	}
	applied := remediate.Applied{
		Bumped: map[string]string{"example.com/safe": "v1.2.0"},
		Dropped: map[string]string{
			"example.com/breaks": "the batch failed to build with it included; isolated by bisection",
		},
	}

	body := remediate.Body(bodyGroup(), targets, applied, remediate.Verification{
		BuildOK: true, TestsOK: true, TidyOK: true, RescanClean: true,
	})

	if !strings.Contains(body, "example.com/breaks") {
		t.Fatalf("the dropped module is not named in the pull request body. It leaves no trace in "+
			"the diff either, so the reviewer has no way to learn of it:\n%s", body)
	}
	if !strings.Contains(body, "isolated by bisection") {
		t.Errorf("the body names the dropped module and not the reason. A reviewer is then told "+
			"something is missing and not why:\n%s", body)
	}
	if !strings.Contains(body, "remain open") {
		t.Errorf("the body does not say the dropped module's findings are still open, which is the "+
			"consequence the reviewer is deciding against:\n%s", body)
	}
}

// TestABodyWithNothingDroppedSaysNothingAboutDrops is assert-the-negative.
//
// A section that is always present, empty, is worse than none: a reviewer
// learns to skip it, and then skips the one that matters.
func TestABodyWithNothingDroppedSaysNothingAboutDrops(t *testing.T) {
	targets := []remediate.Target{
		{Module: "example.com/safe", From: "v1.0.0", To: "v1.2.0"},
	}
	applied := remediate.Applied{
		Bumped:  map[string]string{"example.com/safe": "v1.2.0"},
		Dropped: map[string]string{},
	}

	body := remediate.Body(bodyGroup(), targets, applied, remediate.Verification{
		BuildOK: true, TestsOK: true, TidyOK: true, RescanClean: true,
	})

	for _, phrase := range []string{"Attempted and dropped", "Not everything in this fix group"} {
		if strings.Contains(body, phrase) {
			t.Errorf("a pull request that dropped nothing still carries %q. A section that is always "+
				"there and usually empty is one a reviewer learns to skip:\n%s", phrase, body)
		}
	}
}

// TestTheBodyStatesTheVersionThatWasRESOLVED is the other half of the same
// honesty property.
//
// The target is what was asked for. A proxy that has not mirrored a tag
// resolves lower, and a table printing the request would state a bump that did
// not happen — in the one place a reviewer is most likely to take it on trust.
func TestTheBodyStatesTheVersionThatWasResolved(t *testing.T) {
	targets := []remediate.Target{
		{Module: "example.com/mod", From: "v1.0.0", To: "v1.9.0", Closes: []string{"GHSA-aaaa-bbbb-cccc"}},
	}
	applied := remediate.Applied{
		// The proxy had not mirrored v1.9.0.
		Bumped:  map[string]string{"example.com/mod": "v1.4.0"},
		Dropped: map[string]string{},
	}

	body := remediate.Body(bodyGroup(), targets, applied, remediate.Verification{
		BuildOK: true, TestsOK: true, TidyOK: true, RescanClean: true,
	})

	if !strings.Contains(body, "v1.4.0") {
		t.Fatalf("the body does not state the version the module actually resolved to:\n%s", body)
	}
	if strings.Contains(body, "**v1.9.0**") {
		t.Fatalf("the body states the version that was REQUESTED as though it had been applied. "+
			"The module is at v1.4.0:\n%s", body)
	}
}

// TestTheDroppedListIsStable keeps the same outcome rendering the same way.
//
// Map iteration order would make an unchanged bisect result look like a
// different one each run, and a pull request body that changes on its own is
// one nobody can diff.
func TestTheDroppedListIsStable(t *testing.T) {
	applied := remediate.Applied{
		Bumped: map[string]string{},
		Dropped: map[string]string{
			"example.com/c": "third", "example.com/a": "first", "example.com/b": "second",
		},
	}

	first := remediate.Body(bodyGroup(), nil, applied, remediate.Verification{})
	for i := 0; i < 20; i++ {
		if got := remediate.Body(bodyGroup(), nil, applied, remediate.Verification{}); got != first {
			t.Fatal("the same bisect outcome rendered two different bodies")
		}
	}

	a := strings.Index(first, "example.com/a")
	b := strings.Index(first, "example.com/b")
	c := strings.Index(first, "example.com/c")
	if !(a < b && b < c) {
		t.Errorf("the dropped modules are not in a stable order: a=%d b=%d c=%d", a, b, c)
	}
}

// TestTheFakeToolchainCanProduceADrop keeps the fake from being kinder than
// production.
//
// Four times in this build a fake has been milder than the system it stood
// for, and each time the gap was invisible until something real was plugged
// in. The real toolchain bisects and drops; the fake must be able to present
// the harness with the same outcome.
func TestTheFakeToolchainCanProduceADrop(t *testing.T) {
	tc := remediate.NewFakeToolchain().
		WithModule("example.com/safe", "v1.0.0").
		WithModule("example.com/breaks", "v1.0.0").
		WithUnbumpable("example.com/breaks", "the batch failed to build with it included")

	applied, err := tc.Apply(t.Context(), "/work", []remediate.Target{
		{Module: "example.com/safe", From: "v1.0.0", To: "v1.2.0"},
		{Module: "example.com/breaks", From: "v1.0.0", To: "v1.1.0"},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if _, dropped := applied.Dropped["example.com/breaks"]; !dropped {
		t.Fatalf("the fake cannot model a dropped bump: %+v", applied)
	}
	if got := applied.Bumped["example.com/safe"]; got != "v1.2.0" {
		t.Errorf("the harmless bump was not applied alongside the drop: %q", got)
	}
	if _, bumped := applied.Bumped["example.com/breaks"]; bumped {
		t.Error("a dropped module was also reported as bumped")
	}
	if got := tc.Version("example.com/breaks"); got != "v1.0.0" {
		t.Errorf("the dropped module did not stay at its original version: %q", got)
	}
}
