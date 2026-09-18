package remediate

import (
	"context"

	"github.com/wanaware/vulnframework/internal/model"
)

// Toolchain is the language-specific half of remediation (VM-AD §11.3).
//
// Behind an interface so the harness — which owns the guard, the state
// transitions and every repository mutation — is testable with no toolchain
// installed, no network and no credentials. The real implementation shells out
// to `go get`, `go mod tidy`, `go build` and `go test` exactly as §11.3
// specifies; nothing here infers anything (VM-ADR-09).
type Toolchain interface {
	// Baseline establishes the pre-change build and test state (VM-F-504).
	//
	// It runs BEFORE any change. A repository whose tests already fail cannot
	// be remediated: there is no signal to verify a fix against, so a
	// "successful" verification afterwards would mean nothing.
	Baseline(ctx context.Context, dir string) (Check, error)

	// Apply performs the bumps. It reports what it changed, from the TREE — the
	// guard inspects that, never a claim.
	Apply(ctx context.Context, dir string, targets []Target) (Applied, error)

	// TestInventory lists the test functions present in the tree.
	//
	// Taken before and after a change, it is what detects a build made green
	// by deleting the test that objected. It reads the TREE: an agent that
	// removed a test and did not mention it is precisely the case it exists
	// for, so nothing here consults any account of what changed.
	TestInventory(ctx context.Context, dir string) ([]string, error)

	// Collect reports what the tree currently shows as changed, for a fixer
	// that edits files directly rather than through a known set of targets.
	Collect(ctx context.Context, dir string) (Applied, error)

	// Verify runs the full post-change gate (VM-F-531): build, vet, test with
	// the race detector, tidy check, and a RE-RUN of the scanners that produced
	// these findings. The re-run is what distinguishes a fix from a change.
	//
	// expect names the identifiers THIS group must close — advisory ids, rule
	// ids, fingerprints. It is not decoration: a re-scan of a repository sees
	// every finding in it, and a verification that failed on any of them would
	// make a repository with two vulnerable modules unremediable, one group
	// blocking the next for ever. The gate asks whether the group's own
	// findings are gone (OQ-AUDIT-06).
	Verify(ctx context.Context, dir string, targets []Target, tools []string, expect []string) (Verification, error)
}

// Check is a build-and-test result. Output is verbatim: summarising away a
// failure is itself a defect (VM-F-532).
type Check struct {
	BuildOK bool
	TestsOK bool
	Output  string
}

// OK reports whether both build and tests passed.
func (c Check) OK() bool { return c.BuildOK && c.TestsOK }

// Applied is what a bump actually did.
type Applied struct {
	// Bumped is the version each module ended up at, which may differ from the
	// target: a proxy that has not mirrored a tag yet will resolve lower, and
	// that difference is the whole reason verification re-runs the scanners.
	Bumped map[string]string
	// Dropped names modules the bisect removed after a failure, with why
	// (VM-AD §11.3).
	Dropped map[string]string
	// ChangedFiles is what the tree reports.
	ChangedFiles []string
	// Diff is the change, for the content guard.
	Diff []byte
	// Output is verbatim tool output.
	Output string
}

// Verification is the post-change gate result.
type Verification struct {
	BuildOK bool
	TestsOK bool
	TidyOK  bool
	// RescanClean reports whether a re-run of the scanners that produced these
	// findings still sees them. This is the only evidence that the change is a
	// FIX rather than merely a change (VM-F-531).
	RescanClean bool
	// Remaining is what the re-scan still reports, so a failure names the
	// advisory rather than saying "verification failed".
	Remaining []string
	Output    string
}

// OK reports whether every gate passed.
func (v Verification) OK() bool { return v.BuildOK && v.TestsOK && v.TidyOK && v.RescanClean }

// FailureReason maps a failed verification to the reason code recorded on the
// finding.
//
// Order matters: a build failure explains a test failure, so reporting
// TESTS_FAILED for a repository that does not compile would send someone
// looking in the wrong place.
func (v Verification) FailureReason() model.ReasonCode {
	switch {
	case !v.BuildOK:
		return model.ReasonBuildFailed
	case !v.TestsOK:
		return model.ReasonTestsFailed
	default:
		// Tidy or re-scan: the change built and tested but did not close the
		// defect. NO_UPSTREAM_FIX would pause the SLA clock on a finding a
		// human could fix today (VM-NF-304), so it gets its own code.
		return model.ReasonFixIneffective
	}
}
