package gh

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Fake is an in-memory PR-ops implementation that models GitHub's WEAKEST
// permitted behaviour, not a convenient one.
//
// This is deliberate and it is the standing sentinel from Phase 8: a fake that
// is kinder than production does not simplify a test, it deletes it. Phase 8's
// tracker fake deduplicated by fingerprint where no real tracker does, which
// made the duplicate-ticket gate unfalsifiable — the bug would have been
// invisible because the fake covered for it.
//
// So this fake does what GitHub does:
//
//	It opens DUPLICATE pull requests when the head branches differ, even if the
//	content is identical. Nothing on the remote side deduplicates by content;
//	branch-name derivation from the fix group is the framework's own mechanism
//	and has to be tested against a remote that will not help.
//
//	It answers 422, not success, when a pull request already exists for a head
//	branch. A caller that assumed success would break on an ordinary retry.
//
//	It REJECTS a non-fast-forward push. Two workers racing on one repository is
//	exactly the case the repo lock exists to prevent, and the remote's rejection
//	is what the framework sees when the lock fails.
//
//	It RATE LIMITS, and it FAILS MID-OPERATION — leaving a branch pushed with no
//	pull request, which is the partial state the next attempt must recognise
//	rather than duplicate.
type Fake struct {
	mu sync.Mutex

	defaultBranch string
	// branches maps repo -> branch -> the content marker last pushed, so a
	// second push of DIFFERENT content is a conflict and an identical re-push
	// is not.
	branches map[string]map[string]string
	prs      map[string][]PullRequest
	nextPR   int

	// worktrees maps a directory to its simulated state.
	trees map[string]*tree

	calls []string

	// failAfter fails every operation once this many have been made. Zero means
	// never. It stands in for a job killed mid-flight.
	failAfter int
	// rateLimitAfter rate-limits every operation after this many.
	rateLimitAfter int
	// pushRejections forces the next n pushes to be rejected as conflicts.
	pushRejections int
	failure        error
}

type tree struct {
	repo    string
	branch  string
	changed []string
	diff    []byte
	// pushed marks content as committed, so ChangedFiles reflects what a real
	// `git diff` would report.
	committed bool
	marker    string
}

// NewFake builds a fake remote with one repository at its default branch.
func NewFake(defaultBranch string) *Fake {
	return &Fake{
		defaultBranch: defaultBranch,
		branches:      map[string]map[string]string{},
		prs:           map[string][]PullRequest{},
		trees:         map[string]*tree{},
	}
}

// --- fault injection --------------------------------------------------------

// FailAfter makes every operation after n fail, standing in for a worker killed
// mid-operation.
func (f *Fake) FailAfter(n int) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failAfter = n
	return f
}

// RateLimitAfter rate-limits every operation after n.
func (f *Fake) RateLimitAfter(n int) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rateLimitAfter = n
	return f
}

// RejectNextPushes rejects the next n pushes as non-fast-forward.
func (f *Fake) RejectNextPushes(n int) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushRejections = n
	return f
}

// FailWith makes every operation fail with err until cleared with nil.
func (f *Fake) FailWith(err error) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failure = err
	return f
}

// Recover clears every injected fault, standing in for the service coming back.
func (f *Fake) Recover() *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failAfter, f.rateLimitAfter, f.pushRejections, f.failure = 0, 0, 0, nil
	return f
}

// record notes a call and applies any injected fault. Callers hold the lock.
func (f *Fake) record(op string) error {
	f.calls = append(f.calls, op)
	if f.failure != nil {
		return f.failure
	}
	if f.rateLimitAfter > 0 && len(f.calls) > f.rateLimitAfter {
		return &ErrRateLimited{RetryAfter: 2 * time.Second}
	}
	if f.failAfter > 0 && len(f.calls) > f.failAfter {
		return fmt.Errorf("gh: connection reset mid-operation on %s", op)
	}
	return nil
}

// Calls returns every operation attempted, in order.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// --- the interface ----------------------------------------------------------

func (f *Fake) DefaultBranch(_ context.Context, repo string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("DefaultBranch " + repo); err != nil {
		return "", err
	}
	return f.defaultBranch, nil
}

func (f *Fake) Clone(_ context.Context, repo, ref, dir string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("Clone " + repo); err != nil {
		return err
	}
	f.trees[dir] = &tree{repo: repo, branch: ref}
	return nil
}

func (f *Fake) Discard(_ context.Context, dir string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("Discard " + dir); err != nil {
		return err
	}
	delete(f.trees, dir)
	return nil
}

func (f *Fake) BranchExists(_ context.Context, repo, branch string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("BranchExists " + repo + ":" + branch); err != nil {
		return false, err
	}
	_, ok := f.branches[repo][branch]
	return ok, nil
}

func (f *Fake) CreateBranch(_ context.Context, dir, branch string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("CreateBranch " + branch); err != nil {
		return err
	}
	t, ok := f.trees[dir]
	if !ok {
		return fmt.Errorf("gh: no clone at %s", dir)
	}
	t.branch = branch
	return nil
}

func (f *Fake) ChangedFiles(_ context.Context, dir string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("ChangedFiles " + dir); err != nil {
		return nil, err
	}
	t, ok := f.trees[dir]
	if !ok {
		return nil, fmt.Errorf("gh: no clone at %s", dir)
	}
	return append([]string(nil), t.changed...), nil
}

func (f *Fake) Diff(_ context.Context, dir string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("Diff " + dir); err != nil {
		return nil, err
	}
	t, ok := f.trees[dir]
	if !ok {
		return nil, fmt.Errorf("gh: no clone at %s", dir)
	}
	return append([]byte(nil), t.diff...), nil
}

func (f *Fake) Commit(_ context.Context, dir string, c Commit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("Commit " + c.Message); err != nil {
		return err
	}
	t, ok := f.trees[dir]
	if !ok {
		return fmt.Errorf("gh: no clone at %s", dir)
	}
	if c.AuthorEmail == "" || c.AuthorName == "" {
		// A real remote accepts this; the framework must not produce it
		// (VM-F-544), so the fake refuses rather than quietly attributing a
		// machine change to nobody.
		return fmt.Errorf("gh: a commit must carry the framework's own identity (VM-F-544)")
	}
	t.committed = true
	return nil
}

func (f *Fake) Push(_ context.Context, dir, repo, branch string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("Push " + repo + ":" + branch); err != nil {
		return err
	}
	if f.pushRejections > 0 {
		f.pushRejections--
		return &ErrConflict{Repo: repo, Branch: branch}
	}
	t, ok := f.trees[dir]
	if !ok {
		return fmt.Errorf("gh: no clone at %s", dir)
	}
	if !t.committed {
		return fmt.Errorf("gh: nothing committed at %s", dir)
	}

	if f.branches[repo] == nil {
		f.branches[repo] = map[string]string{}
	}
	// A second push of DIFFERENT content to the same branch is what a real
	// remote rejects. An identical re-push is a no-op, which is what makes
	// branch-derived idempotency work at all.
	if existing, ok := f.branches[repo][branch]; ok && existing != t.marker {
		return &ErrConflict{Repo: repo, Branch: branch}
	}
	f.branches[repo][branch] = t.marker
	return nil
}

func (f *Fake) FindPR(_ context.Context, repo, head string) (PullRequest, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("FindPR " + repo + ":" + head); err != nil {
		return PullRequest{}, false, err
	}
	for _, pr := range f.prs[repo] {
		if pr.Head == head && pr.State == "open" {
			return pr, true, nil
		}
	}
	return PullRequest{}, false, nil
}

func (f *Fake) OpenPR(_ context.Context, repo string, req OpenRequest) (PullRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record("OpenPR " + repo + ":" + req.Head); err != nil {
		return PullRequest{}, err
	}
	if req.Head == "" || req.Head == f.defaultBranch {
		return PullRequest{}, fmt.Errorf("gh: refusing to open a pull request from %q (VM-F-501)", req.Head)
	}
	// 422, as GitHub answers, rather than returning the existing pull request.
	for _, pr := range f.prs[repo] {
		if pr.Head == req.Head && pr.State == "open" {
			return PullRequest{}, &ErrPRExists{Existing: pr}
		}
	}
	// No content-based deduplication. Two different head branches carrying an
	// identical change produce two pull requests, because that is what happens.
	f.nextPR++
	pr := PullRequest{
		Number: f.nextPR,
		URL:    fmt.Sprintf("https://github.com/%s/pull/%d", repo, f.nextPR),
		Head:   req.Head, Base: req.Base, State: "open",
	}
	f.prs[repo] = append(f.prs[repo], pr)
	return pr, nil
}

func (f *Fake) ClosePR(_ context.Context, repo string, number int, comment string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record(fmt.Sprintf("ClosePR %s#%d", repo, number)); err != nil {
		return err
	}
	for i, pr := range f.prs[repo] {
		if pr.Number == number {
			f.prs[repo][i].State = "closed"
			return nil
		}
	}
	return fmt.Errorf("gh: no pull request %s#%d", repo, number)
}

// --- inspection -------------------------------------------------------------

// Stage sets what the working tree will report as changed, and its diff. The
// worker's toolchain calls this in tests where a real bump would edit files.
func (f *Fake) Stage(dir string, changed []string, diff []byte, marker string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.trees[dir]; ok {
		t.changed, t.diff, t.marker = changed, diff, marker
	}
}

// OpenPRs returns every open pull request for a repository.
func (f *Fake) OpenPRs(repo string) []PullRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []PullRequest
	for _, pr := range f.prs[repo] {
		if pr.State == "open" {
			out = append(out, pr)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out
}

// AllPRs returns every pull request ever opened, open or closed.
func (f *Fake) AllPRs(repo string) []PullRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]PullRequest(nil), f.prs[repo]...)
}

// Branches returns the branch names that exist on the remote.
func (f *Fake) Branches(repo string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for b := range f.branches[repo] {
		out = append(out, b)
	}
	sort.Strings(out)
	return out
}

// CallsMatching counts recorded operations whose description contains s.
func (f *Fake) CallsMatching(s string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.Contains(c, s) {
			n++
		}
	}
	return n
}
