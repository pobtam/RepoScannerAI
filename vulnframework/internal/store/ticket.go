package store

import (
	"encoding/json"
	"time"
)

// Ticket is the local record of a finding's ticket (VM-AD §13.2).
//
// This record — not the backend query — is the primary idempotency mechanism.
// The backend query exists for reconciliation after data loss, because the
// record is a cache of a decision that was made elsewhere, and treating a cache
// miss as "no ticket exists" is how a system manufactures duplicates.
//
// It is stored in its own table rather than in the finding document. The
// document is rebuilt from observations on every scan, so a reference kept
// there would be erased by the next run and the following run would open a
// second ticket.
type Ticket struct {
	Fingerprint string `json:"fingerprint"`
	Backend     string `json:"backend"`
	Ref         string `json:"ref"`
	URL         string `json:"url"`

	// MirrorBackend and MirrorRef record the secondary ticket, if any. Nothing
	// is ever read back from it: mirroring is one-way (VM-AD §13.4).
	MirrorBackend string `json:"mirror_backend,omitempty"`
	MirrorRef     string `json:"mirror_ref,omitempty"`

	CreatedAt time.Time  `json:"created_at"`
	ClosedAt  *time.Time `json:"closed_at,omitempty"`

	// Reopened is a write-only flag asking SaveTicket to clear ClosedAt.
	//
	// Without it a re-save cannot express "this ticket is open again": the
	// upsert deliberately preserves closure, because a routine re-save must
	// never silently reopen something. Reopening is a decision (VM-F-806), so
	// it has to be said out loud.
	Reopened bool `json:"-"`
}

// TicketOp is a queued tracker operation (VM-F-812, VM-AD §13.5).
//
// The payload carries everything needed to replay the operation. A queue entry
// that records only that something failed cannot be retried, and the ticket is
// then lost with no trace of what it should have said.
type TicketOp struct {
	ID          int64           `json:"id"`
	Fingerprint string          `json:"fingerprint"`
	Kind        string          `json:"kind"`
	Payload     json.RawMessage `json:"payload"`

	Attempts      int       `json:"attempts"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	LastError     string    `json:"last_error,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// RepoLock is the per-repository remediation lock (VM-AD §7.3, VM-F-503).
//
// It is a row with an expiry rather than `pg_advisory_lock`. An advisory lock
// lives in a Postgres session, so the in-memory backend could not honour it at
// all, and a fake that enforces weaker rules than production makes every test
// using it a statement about the fake. The expiry also buys crash safety an
// advisory lock cannot: a worker that dies does not strand the repository.
type RepoLock struct {
	Repo       string     `json:"repo"`
	Owner      string     `json:"owner"`
	AcquiredAt time.Time  `json:"acquired_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
}

// Held reports whether the lock is claimed as of now, accounting for expiry.
func (l RepoLock) Held(now time.Time) bool {
	if l.Owner == "" {
		return false
	}
	return l.ExpiresAt == nil || now.Before(*l.ExpiresAt)
}

// RemediationPR is the record of a pull request opened for a fix group.
//
// Keyed on the branch, which derives from the fix group identity, so
// re-running remediation for the same group finds this row and cannot open a
// second pull request (VM-F-502).
type RemediationPR struct {
	Branch     string     `json:"branch"`
	Repo       string     `json:"repo"`
	FixGroupID string     `json:"fix_group_id"`
	Number     int        `json:"number"`
	URL        string     `json:"url"`
	State      string     `json:"state"`
	OpenedAt   time.Time  `json:"opened_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	// Merged distinguishes a pull request that landed from one a human closed.
	// The difference decides between MERGED and DECLINED (VM-F-545), and a
	// single "closed" state cannot express it.
	Merged bool `json:"merged"`
	// TicketRef and TicketURL are the pull request's own ticket (§13.3 row 2).
	// They live here rather than in their own table because the ticket exists
	// because the pull request does, and closes when it does.
	TicketRef string `json:"ticket_ref,omitempty"`
	TicketURL string `json:"ticket_url,omitempty"`
	// Findings is the group membership that produced this branch. It is stored
	// rather than recomputed: the membership is history, and recomputing it
	// from current findings would disagree the moment one changed state.
	Findings []string `json:"findings"`
}

// Open reports whether the pull request is still open.
func (p RemediationPR) Open() bool { return p.State == "open" }

// RunTicket is the parent ticket for one run (VM-AD §13.3 row 1).
//
// One per run, deliberately: it carries that run's counts and deltas, and the
// aggregated table standing in for the findings that got no ticket of their
// own. Sharing a parent across runs would attribute one run's numbers to
// another.
type RunTicket struct {
	RunID     string    `json:"run_id"`
	Backend   string    `json:"backend"`
	Ref       string    `json:"ref"`
	URL       string    `json:"url"`
	CreatedAt time.Time `json:"created_at"`
}
