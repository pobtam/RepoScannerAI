// Package orchestrator plans runs, dispatches work, sweeps leases and budgets
// the external API rate (VM-AD §7).
//
// It is the only component permitted to write findings.state (VM-AD §7.1).
package orchestrator

import (
	"fmt"
	"sync"
)

// RateBudget is the central token-bucket lease over external API calls
// (VM-AD §7.2).
//
// GitHub's limits are per App installation, not per repository. Forty workers
// each calling the API independently exhaust the budget mid-sweep and fail the
// tail of the fleet non-deterministically — which is worse than being slow,
// because the failures land on different repositories each run and no
// repository is reliably covered.
//
// A worker requests credits before starting and returns what it did not use.
type RateBudget struct {
	mu        sync.Mutex
	available int
	inFlight  int
}

// NewRateBudget builds a budget with an initial credit allowance.
func NewRateBudget(credits int) *RateBudget {
	return &RateBudget{available: credits}
}

// ErrBudgetExhausted is returned when a request cannot be funded.
//
// It is a deliberate, reportable outcome rather than a failure: the caller
// records the repository as not dispatched with a budget reason, so a deferred
// scan is visible as a gap instead of vanishing (OQ-P2-02).
type ErrBudgetExhausted struct {
	Requested int
	Available int
}

func (e *ErrBudgetExhausted) Error() string {
	return fmt.Sprintf("rate budget exhausted: requested %d credits, %d available", e.Requested, e.Available)
}

// Acquire reserves n credits, or reports that the budget cannot fund them.
//
// It does not block. Blocking would turn budget exhaustion into a stalled sweep
// with no record of why; returning lets the planner record the skip and move on,
// and the deferred repositories are picked up by the next run.
func (b *RateBudget) Acquire(n int) error {
	if n <= 0 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.available < n {
		return &ErrBudgetExhausted{Requested: n, Available: b.available}
	}
	b.available -= n
	b.inFlight += n
	return nil
}

// Release returns unused credits.
func (b *RateBudget) Release(n int) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if n > b.inFlight {
		n = b.inFlight
	}
	b.inFlight -= n
	b.available += n
}

// Consume marks credits as spent: they are not returned to the pool.
func (b *RateBudget) Consume(n int) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if n > b.inFlight {
		n = b.inFlight
	}
	b.inFlight -= n
}

// Refresh resets the allowance from the observed remaining quota, as reported
// by the API's rate-limit headers (VM-AD §7.2).
func (b *RateBudget) Refresh(remaining int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if remaining < 0 {
		remaining = 0
	}
	b.available = remaining
}

// Available reports the credits currently free.
func (b *RateBudget) Available() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.available
}

// InFlight reports the credits currently reserved.
func (b *RateBudget) InFlight() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inFlight
}
