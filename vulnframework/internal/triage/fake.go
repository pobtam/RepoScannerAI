package triage

import (
	"context"
	"fmt"
	"sync"

	"github.com/wanaware/vulnframework/internal/model"
)

// FakeClient is the offline inference client.
//
// Triage is the first component with a model in the loop, and it must still
// build, run and pass its tests with no credentials and no network. The fake
// also makes the adversarial cases testable: a real model cannot be asked
// reliably to fabricate an identifier on demand, but the validator has to be
// proved against one.
type FakeClient struct {
	mu sync.Mutex

	// Respond builds the response for a request. Nil returns a well-formed
	// verdict for every finding.
	Respond func(Request) ([]Verdict, error)

	requests []Request
}

// NewFakeClient builds a fake that answers every finding correctly.
func NewFakeClient() *FakeClient { return &FakeClient{} }

// Triage records the request and returns the configured response.
func (f *FakeClient) Triage(_ context.Context, req Request) ([]Verdict, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req)
	respond := f.Respond
	f.mu.Unlock()

	if respond != nil {
		return respond(req)
	}
	return WellFormed(req), nil
}

// Requests returns the requests made, in order.
func (f *FakeClient) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Request, len(f.requests))
	copy(out, f.requests)
	return out
}

// WellFormed returns a compliant verdict for every finding in a request.
func WellFormed(req Request) []Verdict {
	out := make([]Verdict, 0, len(req.Findings))
	for _, it := range req.Findings {
		out = append(out, Verdict{
			Fingerprint: it.Fingerprint,
			Description: fmt.Sprintf("A %s finding in %s.", it.Category, req.Profile.Repo),
			Impact:      "Impact depends on whether the affected path is exercised in production.",
			Remediation: remediationFor(it),
			Confidence:  "high",
		})
	}
	return out
}

func remediationFor(it Item) string {
	if it.Fixed != "" && it.Module != "" {
		return fmt.Sprintf("Upgrade %s to %s.", it.Module, it.Fixed)
	}
	return "Review the affected code path; no fixed version is published."
}

// MemoryCache is an in-memory triage cache (VM-F-306).
type MemoryCache struct {
	mu sync.Mutex
	m  map[string]model.Triage
}

// NewMemoryCache builds an empty cache.
func NewMemoryCache() *MemoryCache { return &MemoryCache{m: map[string]model.Triage{}} }

// Get returns a cached verdict.
func (c *MemoryCache) Get(_ context.Context, fp string) (model.Triage, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.m[fp]
	return t, ok, nil
}

// Put stores a verdict.
func (c *MemoryCache) Put(_ context.Context, fp string, t model.Triage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]model.Triage{}
	}
	c.m[fp] = t
	return nil
}

// Len reports how many verdicts are cached.
func (c *MemoryCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
