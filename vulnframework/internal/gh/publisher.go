package gh

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"
)

// Git is the minimal repository surface the publisher needs.
type Git interface {
	Read(ctx context.Context, path string) ([]byte, bool, error)
	Write(ctx context.Context, path string, content []byte, message string) error
}

// PublisherConfig configures the git-backed report publisher (VM-ADR-08).
type PublisherConfig struct {
	Repo   string
	Branch string
	// IdentityBindingAvailable records whether VM-UI-OQ-01 is closed — whether
	// anything maps a real identity to a privilege level.
	//
	// It is a field rather than an assumption because the coupling recorded at
	// Phase 7b has to be enforced rather than remembered: until identity→level
	// exists, the privilege model trusts an authenticated caller's
	// SELF-ASSERTED level, and a redacted pack delivered externally on that
	// basis is redacted in name only.
	IdentityBindingAvailable bool
}

// Recipient is who a publication is for.
type Recipient struct {
	ID string
	// External marks a recipient outside this organisation's trust boundary.
	External bool
	// AssertedLevel is what the caller CLAIMS. Named to make the claim
	// visible: nothing verifies it until VM-UI-OQ-01 closes.
	AssertedLevel string
}

// ErrIdentityUnbound refuses external delivery while privilege is self-asserted.
type ErrIdentityUnbound struct{ Recipient string }

func (e *ErrIdentityUnbound) Error() string {
	return fmt.Sprintf(
		"gh: refusing to publish to the external recipient %q. Until identity→level binding exists "+
			"(VM-UI-OQ-01) the privilege model trusts an authenticated caller's SELF-ASSERTED level, "+
			"so a redacted pack delivered externally is redacted in name only. This was acceptable "+
			"while the publisher was a fake and nothing left the process; it is not acceptable now "+
			"that it does. Named precondition from Phase 7b: both VM-OQ-10 and VM-UI-OQ-01 must close "+
			"before external delivery",
		e.Recipient)
}

// Publisher writes reports into a git repository (VM-ADR-08).
type Publisher struct {
	cfg PublisherConfig
	git Git
}

// NewPublisher builds a publisher.
func NewPublisher(cfg PublisherConfig, git Git) *Publisher {
	return &Publisher{cfg: cfg, git: git}
}

// Publish writes a report, refusing to overwrite a different one.
//
// A report is immutable once issued (VM-ADR-15), and storing reports as
// commits is what makes that checkable years later. Overwriting would destroy
// exactly the property the storage choice exists for: a citation to a path
// would become ambiguous about which document it named.
//
// Identical content is idempotent, because a retry after a network failure is
// ordinary and must not fail.
func (p *Publisher) Publish(ctx context.Context, path string, content []byte) error {
	existing, found, err := p.git.Read(ctx, path)
	if err != nil {
		return fmt.Errorf("gh: reading %s: %w", path, err)
	}
	if found {
		if bytes.Equal(existing, content) {
			return nil
		}
		return fmt.Errorf(
			"gh: refusing to overwrite %s: a different report is already published there. Reports are "+
				"immutable once issued (VM-ADR-15); issue a new report that supersedes it rather than "+
				"replacing this one, or a citation to this path becomes ambiguous about which document "+
				"it refers to", path)
	}
	if err := p.git.Write(ctx, path, content, "report: "+path); err != nil {
		return fmt.Errorf("gh: publishing %s: %w", path, err)
	}
	return nil
}

// PublishFor publishes on behalf of a recipient, enforcing the Phase 7b
// precondition for external delivery.
func (p *Publisher) PublishFor(ctx context.Context, to Recipient, path string, content []byte) error {
	if to.External && !p.cfg.IdentityBindingAvailable {
		return &ErrIdentityUnbound{Recipient: to.ID}
	}
	return p.Publish(ctx, path, content)
}

// --- Fake ---------------------------------------------------------------------

// FakeGit is an in-memory repository.
type FakeGit struct {
	mu      sync.Mutex
	files   map[string][]byte
	commits int
	failure error
}

// NewFakeGit builds an empty repository.
func NewFakeGit() *FakeGit { return &FakeGit{files: map[string][]byte{}} }

// FailWith makes every write fail, as a rejected push does.
func (g *FakeGit) FailWith(err error) *FakeGit {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failure = err
	return g
}

func (g *FakeGit) Read(_ context.Context, path string) ([]byte, bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	b, ok := g.files[path]
	return b, ok, nil
}

func (g *FakeGit) Write(_ context.Context, path string, content []byte, _ string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failure != nil {
		return g.failure
	}
	g.files[path] = append([]byte(nil), content...)
	g.commits++
	return nil
}

// File returns a published file.
func (g *FakeGit) File(path string) []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.files[path]
}

// Commits counts writes that landed.
func (g *FakeGit) Commits() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.commits
}

// Paths lists what has been published.
func (g *FakeGit) Paths() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for p := range g.files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
