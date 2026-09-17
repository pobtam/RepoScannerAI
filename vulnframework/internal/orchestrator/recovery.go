package orchestrator

import (
	"sort"
	"sync"
	"time"
)

// RecoveryKind names a class of self-healing action.
type RecoveryKind string

const (
	// RecoveryLeaseExpired — a finding lease lapsed and was reclaimed.
	RecoveryLeaseExpired RecoveryKind = "lease_expired"
	// RecoveryRepoLockExpired — a repository lock outlived its holder.
	RecoveryRepoLockExpired RecoveryKind = "repo_lock_expired"
	// RecoveryStranded — a finding sat in an active-looking state with no
	// mechanism able to move it (VM-AD §6.1.2).
	RecoveryStranded RecoveryKind = "stranded"
	// RecoveryTicketDrained — a ticket operation queued behind an outage was
	// replayed (VM-F-812).
	RecoveryTicketDrained RecoveryKind = "ticket_drained"
	// RecoveryPRStateSync — a pull request a human merged or closed was
	// discovered by asking rather than by a webhook (VM-F-545).
	RecoveryPRStateSync RecoveryKind = "pr_state_sync"
	// RecoveryAgentAbandoned — an agentic attempt was abandoned and its work
	// discarded.
	RecoveryAgentAbandoned RecoveryKind = "agent_abandoned"
)

// RecoveryEvent is one self-healing action, recorded.
type RecoveryEvent struct {
	Kind        RecoveryKind `json:"kind"`
	Repo        string       `json:"repo,omitempty"`
	Fingerprint string       `json:"fingerprint,omitempty"`
	// Reason says why the recovery fired, in words. Not a code: the value of
	// this record is that a human reading it understands what went wrong
	// upstream, and a code would have to be looked up.
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

// RecoveryLog accumulates recovery events.
//
// RECOVERY MUST BE LOUD. A self-heal that works silently is an observability
// coverage gap, and it is the one gap class this system had not hunted: every
// other kind of absence — an unscanned repository, an uncomputed SLA, a
// suppressed finding — is surfaced and named. A successful recovery was the
// exception, and a sweep quietly rescuing the same repository every hour is
// hiding a bug upstream of itself while presenting as reliability.
//
// The log is deliberately dumb. It accumulates, it reports counts by kind and
// by repository, and it does not decide what is alarming: the data has to start
// accumulating before anyone can calibrate a threshold against it, the same way
// annotations, uncalibrated thresholds and fan-out were recorded before they
// were used.
type RecoveryLog struct {
	mu     sync.Mutex
	events []RecoveryEvent
}

// Record adds an event.
func (l *RecoveryLog) Record(e RecoveryEvent) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	l.events = append(l.events, e)
}

// Events returns everything recorded, in order.
func (l *RecoveryLog) Events() []RecoveryEvent {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]RecoveryEvent(nil), l.events...)
}

// ByKind counts events per kind.
func (l *RecoveryLog) ByKind() map[RecoveryKind]int {
	out := map[RecoveryKind]int{}
	for _, e := range l.Events() {
		out[e.Kind]++
	}
	return out
}

// Repeating returns repositories recovered at least threshold times, most
// frequent first.
//
// This is the signal the whole log exists for: one recovery is the machinery
// working, and the same repository recovered every sweep is a defect wearing
// the machinery as a disguise.
func (l *RecoveryLog) Repeating(threshold int) []RepeatedRecovery {
	counts := map[string]map[RecoveryKind]int{}
	for _, e := range l.Events() {
		if e.Repo == "" {
			continue
		}
		if counts[e.Repo] == nil {
			counts[e.Repo] = map[RecoveryKind]int{}
		}
		counts[e.Repo][e.Kind]++
	}

	var out []RepeatedRecovery
	for repo, byKind := range counts {
		for kind, n := range byKind {
			if n >= threshold {
				out = append(out, RepeatedRecovery{Repo: repo, Kind: kind, Count: n})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Repo != out[j].Repo {
			return out[i].Repo < out[j].Repo
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

// RepeatedRecovery is one repository recovered repeatedly for one reason.
type RepeatedRecovery struct {
	Repo  string       `json:"repo"`
	Kind  RecoveryKind `json:"kind"`
	Count int          `json:"count"`
}
