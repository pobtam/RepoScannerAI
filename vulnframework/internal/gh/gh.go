// Package gh is the repository and pull-request surface (VM-AD §3: app auth,
// installation tokens, PR ops).
//
// Everything that mutates a repository goes through this interface, which is
// what keeps credential handling and guard enforcement out of any worker's
// reach (VM-AD §11.4: the agent produces a working tree, the harness performs
// every repository-mutating operation).
package gh

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Commit is one logical fix (VM-F-505).
type Commit struct {
	Message string
	// Author is the framework's own identity, distinguishable from a human's
	// (VM-F-544). A machine change attributed to a person makes `git log`
	// unreliable for the one question it is most often asked: who did this.
	AuthorName  string
	AuthorEmail string
	Files       []string
}

// OpenRequest is a pull request to open.
type OpenRequest struct {
	Head  string
	Base  string
	Title string
	Body  string
	// Labels must identify the pull request as machine-generated (VM-F-542).
	Labels []string
	// Draft is unused in v1.0; pull requests are never auto-merged (VM-F-541).
	Draft bool
}

// PullRequest is an open pull request.
type PullRequest struct {
	Number int    `json:"number"`
	URL    string `json:"url"`
	Head   string `json:"head"`
	Base   string `json:"base"`
	State  string `json:"state"`
	// Merged distinguishes a pull request that landed from one a human closed
	// without merging. "closed" alone cannot express the difference, and the
	// difference decides between MERGED and DECLINED (VM-F-545).
	Merged bool `json:"merged"`
}

// PROps is every repository-mutating operation the framework performs.
type PROps interface {
	// DefaultBranch is the base for every remediation branch. Remediation never
	// pushes to it (VM-F-501).
	DefaultBranch(ctx context.Context, repo string) (string, error)
	Clone(ctx context.Context, repo, ref, dir string) error
	Discard(ctx context.Context, dir string) error

	BranchExists(ctx context.Context, repo, branch string) (bool, error)
	CreateBranch(ctx context.Context, dir, branch string) error

	// ChangedFiles and Diff are what the guard inspects. They report the TREE,
	// never a worker's account of what it changed (VM-F-510).
	ChangedFiles(ctx context.Context, dir string) ([]string, error)
	Diff(ctx context.Context, dir string) ([]byte, error)

	Commit(ctx context.Context, dir string, c Commit) error
	Push(ctx context.Context, dir, repo, branch string) error

	FindPR(ctx context.Context, repo, head string) (PullRequest, bool, error)
	// GetPR returns a pull request by number, whatever its state.
	//
	// This is what lets reconciliation discover that a human closed a pull
	// request without a webhook: the framework asks rather than waiting to be
	// told. A webhook later only makes it prompt instead of eventual.
	GetPR(ctx context.Context, repo string, number int) (PullRequest, bool, error)
	OpenPR(ctx context.Context, repo string, req OpenRequest) (PullRequest, error)
	ClosePR(ctx context.Context, repo string, number int, comment string) error
}

// ErrConflict is a rejected push: someone else moved the branch.
//
// Real remotes reject a non-fast-forward, so the framework must have an answer
// for it. The answer is never "force": a force-push here would overwrite
// another worker's work, or a human's.
type ErrConflict struct {
	Repo   string
	Branch string
}

func (e *ErrConflict) Error() string {
	return fmt.Sprintf(
		"gh: push to %s:%s was rejected as non-fast-forward. Another worker or a human moved the branch. "+
			"The branch is abandoned rather than force-pushed: a force here would destroy whatever moved it",
		e.Repo, e.Branch)
}

// ErrRateLimited is a rate-limited request.
type ErrRateLimited struct {
	RetryAfter time.Duration
}

func (e *ErrRateLimited) Error() string {
	return fmt.Sprintf("gh: rate limited, retry after %s", e.RetryAfter)
}

// ErrPRExists is returned when a pull request is already open for a head
// branch.
//
// Real GitHub answers 422 here rather than returning the existing pull request,
// so a caller that assumed success would crash on a perfectly ordinary retry.
// It carries the existing pull request so the caller can adopt it.
type ErrPRExists struct {
	Existing PullRequest
}

func (e *ErrPRExists) Error() string {
	return fmt.Sprintf("gh: a pull request is already open for head %s (#%d)", e.Existing.Head, e.Existing.Number)
}

// IsRateLimited reports whether err is a rate limit, and how long to wait.
func IsRateLimited(err error) (time.Duration, bool) {
	var rl *ErrRateLimited
	if errors.As(err, &rl) {
		return rl.RetryAfter, true
	}
	return 0, false
}
