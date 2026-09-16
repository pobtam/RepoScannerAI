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
