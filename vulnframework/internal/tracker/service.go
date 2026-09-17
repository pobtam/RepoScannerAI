package tracker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// Service applies ticket decisions against a backend and the local record.
//
// It owns the idempotency chain, which is the whole substance of this phase:
// local record, then backend query, then create — in that order, and never
// skipping the middle step.
type Service struct {
	Tracker Tracker
	Store   store.Store
	Clock   func() time.Time

	// Backoff returns the delay before retry n. Nil means the default.
	Backoff func(attempt int) time.Duration
}

// ErrNotVerified is returned by CloseVerified for a finding that has not
// verified.
//
// Closing on anything less would let a merged-but-unconfirmed fix close the
// ticket, which is the failure VM-NF-303 and VM-ADR-12 both name: a merge is a
// claim about intent, and only a successful scan is evidence.
var ErrNotVerified = errors.New(
	"tracker: refusing to close a ticket for a finding that is not VERIFIED; " +
		"only a successful scan that no longer observes the finding may close it (VM-ADR-12, VM-F-811)")

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) backoff(attempt int) time.Duration {
	if s.Backoff != nil {
		return s.Backoff(attempt)
	}
	// Exponential, capped. The cap matters more than the curve: an outage that
	// lasts a day must not push the next attempt a week out.
	d := time.Minute << attempt
	if d > time.Hour {
		d = time.Hour
	}
	return d
}

// Ensure returns the finding's ticket, creating one only if none exists.
//
// The order is the guarantee:
//
//  1. the local record — the fast path, and the primary mechanism (VM-F-804);
//  2. the backend, queried by fingerprint — the reconciliation path, because a
//     lost record is not evidence that no ticket exists (VM-F-805);
//  3. create.
//
// Skipping step 2 is the whole duplicate-ticket failure mode: a restore, a
// migration or a bug loses the record, and the next run opens a second issue
// for a finding an engineer is already working on.
//
// A backend outage is not an error here. The operation is queued and the run
// continues (VM-F-812): failing the run would convert a third-party outage into
// a coverage gap.
func (s *Service) Ensure(ctx context.Context, spec Spec) (Ref, bool, error) {
	if err := spec.Validate(); err != nil {
		return Ref{}, false, err
	}

	// 1. The local record.
	if rec, ok, err := s.Store.GetTicket(ctx, spec.Fingerprint); err != nil {
		return Ref{}, false, err
	} else if ok {
		return Ref{Backend: rec.Backend, ID: rec.Ref, URL: rec.URL}, false, nil
	}

	// 2. The backend of record.
	ref, found, err := s.Tracker.Find(ctx, spec.Fingerprint)
	if err != nil {
		return Ref{}, false, s.queue(ctx, spec.Fingerprint, "create", spec, err)
	}
	if found {
		if err := s.record(ctx, spec.Fingerprint, ref); err != nil {
			return Ref{}, false, err
		}
		return ref, false, nil
	}

	// 3. Create.
	ref, err = s.Tracker.Create(ctx, spec)
	if err != nil {
		return Ref{}, false, s.queue(ctx, spec.Fingerprint, "create", spec, err)
	}
	if err := s.record(ctx, spec.Fingerprint, ref); err != nil {
		return Ref{}, false, err
	}
	return ref, true, nil
}

// CloseVerified closes the ticket of a finding that has verified (VM-F-811).
//
// The closing comment carries verified_reason, so the system of record people
// actually read says who fixed it. A ticket closed as "fixed by automation"
// when an engineer fixed it upstream is a false record, and the falsehood
// outlives the run that wrote it.
func (s *Service) CloseVerified(ctx context.Context, f model.Finding) error {
	if f.State != model.Verified {
		return fmt.Errorf("%w: %s is in state %s", ErrNotVerified, f.Fingerprint, f.State)
	}

	rec, ok, err := s.Store.GetTicket(ctx, f.Fingerprint)
	if err != nil {
		return err
	}
	if !ok {
		// Nothing to close. Not an error: most findings never get a ticket.
		return nil
	}
	if rec.ClosedAt != nil {
		return nil
	}
	ref := Ref{Backend: rec.Backend, ID: rec.Ref, URL: rec.URL}

	body := ClosureComment(f)
	if err := s.Tracker.Comment(ctx, ref, body); err != nil {
		return s.queue(ctx, f.Fingerprint, "close", closePayload{Ref: ref, Body: body}, err)
	}
	if err := s.Tracker.Transition(ctx, ref, StateClosed); err != nil {
		return s.queue(ctx, f.Fingerprint, "close", closePayload{Ref: ref, Body: body}, err)
	}
	return s.Store.CloseTicket(ctx, f.Fingerprint, s.now())
}

// ClosureComment states why the ticket is closing, and who fixed it.
func ClosureComment(f model.Finding) string {
	reason := model.VerifiedExternal
	if f.VerifiedReason != nil {
		reason = *f.VerifiedReason
	}

	var attribution string
	switch reason {
	case model.VerifiedByFrameworkMerge:
		attribution = "This was merged by this framework's own remediation."
	case model.VerifiedByUpstream:
		attribution = "This was fixed upstream, by a first-party change in the module this repository consumes."
	default:
		attribution = "This was fixed outside this framework — by someone else, or because the code carrying it was deleted. " +
			"This framework claims no credit for it."
	}

	return fmt.Sprintf(
		"Closing: a successful scan of `%s` no longer observes this finding, so it is VERIFIED.\n\n"+
			"%s\n\n"+
			"`verified_reason=%s`\n\n"+
			"_Closure requires a successful scan. A finding that merely stopped being reported — because a scan "+
			"failed, or did not run — is retained, not resolved (VM-ADR-12)._\n",
		f.Repo, attribution, reason)
}

// Drain replays queued operations whose backoff has expired (VM-F-812).
//
// It returns the number applied. A failure reschedules rather than propagating:
// the drain is a background sweep, and one broken ticket must not stop the
// others from being created.
func (s *Service) Drain(ctx context.Context, now time.Time, limit int) (int, error) {
	ops, err := s.Store.DueTicketOps(ctx, now, limit)
	if err != nil {
		return 0, err
	}

	applied := 0
	for _, op := range ops {
		if err := s.apply(ctx, op); err != nil {
			next := now.Add(s.backoff(op.Attempts))
			if rerr := s.Store.RetryTicketOp(ctx, op.ID, next, err.Error()); rerr != nil {
				return applied, rerr
			}
			continue
		}
		if err := s.Store.CompleteTicketOp(ctx, op.ID); err != nil {
			return applied, err
		}
		applied++
	}
	return applied, nil
}

type closePayload struct {
	Ref  Ref    `json:"ref"`
	Body string `json:"body"`
}

// apply replays one queued operation.
//
// A queued create still goes through the full idempotency chain. The queue is a
// deferral, not a licence to skip the checks: by the time it drains, the ticket
// may already exist because a later run created it.
func (s *Service) apply(ctx context.Context, op store.TicketOp) error {
	switch op.Kind {
	case "create":
		var spec Spec
		if err := json.Unmarshal(op.Payload, &spec); err != nil {
			return fmt.Errorf("tracker: undecodable queued spec: %w", err)
		}
		if rec, ok, err := s.Store.GetTicket(ctx, spec.Fingerprint); err != nil {
			return err
		} else if ok {
			_ = rec
			return nil
		}
		ref, found, err := s.Tracker.Find(ctx, spec.Fingerprint)
		if err != nil {
			return err
		}
		if !found {
			if ref, err = s.Tracker.Create(ctx, spec); err != nil {
				return err
			}
		}
		return s.record(ctx, spec.Fingerprint, ref)

	case "reopen":
		var p closePayload
		if err := json.Unmarshal(op.Payload, &p); err != nil {
			return fmt.Errorf("tracker: undecodable queued reopen: %w", err)
		}
		if err := s.Tracker.Comment(ctx, p.Ref, p.Body); err != nil {
			return err
		}
		if err := s.Tracker.Transition(ctx, p.Ref, StateOpen); err != nil {
			return err
		}
		return s.Store.SaveTicket(ctx, store.Ticket{
			Fingerprint: op.Fingerprint, Backend: p.Ref.Backend, Ref: p.Ref.ID, URL: p.Ref.URL,
			CreatedAt: s.now(), Reopened: true,
		})

	case "close":
		var p closePayload
		if err := json.Unmarshal(op.Payload, &p); err != nil {
			return fmt.Errorf("tracker: undecodable queued closure: %w", err)
		}
		if err := s.Tracker.Comment(ctx, p.Ref, p.Body); err != nil {
			return err
		}
		if err := s.Tracker.Transition(ctx, p.Ref, StateClosed); err != nil {
			return err
		}
		return s.Store.CloseTicket(ctx, op.Fingerprint, s.now())

	default:
		return fmt.Errorf("tracker: unknown queued operation %q", op.Kind)
	}
}

func (s *Service) record(ctx context.Context, fingerprint string, ref Ref) error {
	return s.Store.SaveTicket(ctx, store.Ticket{
		Fingerprint: fingerprint,
		Backend:     ref.Backend,
		Ref:         ref.ID,
		URL:         ref.URL,
		CreatedAt:   s.now(),
	})
}

// queue defers an operation and reports success to the caller.
//
// The error is swallowed deliberately and deliberately visibly: it is recorded
// on the queue entry, where an operator can see a broken token as distinct from
// a rate limit. What must not happen is the run failing, because that turns a
// tracker outage into a scanning outage.
func (s *Service) queue(ctx context.Context, fingerprint, kind string, payload any, cause error) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("tracker: encoding queued %s: %w", kind, err)
	}
	// The payload is written to a durable store and read back later, so it is
	// one more place a credential could come to rest.
	if err := model.AssertNoCredential("queued ticket operation", body); err != nil {
		return err
	}
	return s.Store.EnqueueTicketOp(ctx, store.TicketOp{
		Fingerprint:   fingerprint,
		Kind:          kind,
		Payload:       body,
		NextAttemptAt: s.now().Add(s.backoff(0)),
		LastError:     cause.Error(),
		CreatedAt:     s.now(),
	})
}

// ErrNotRegressed is returned by Reopen for a finding that has not regressed.
//
// The symmetric guard to ErrNotVerified. Reopening a closed ticket on anything
// less than an observation would reopen settled work on no evidence, and the
// evidence for a regression is specific: a scan saw the finding again
// (VM-F-105).
var ErrNotRegressed = errors.New(
	"tracker: refusing to reopen a ticket for a finding that has not regressed; " +
		"a regression means a scan observed the finding again (VM-F-105, VM-F-806)")

// Reopen returns a regressed finding's ORIGINAL ticket to the open state
// (VM-F-806).
//
// It never creates. A new ticket for a recurrence discards the entire history
// of the first occurrence — what was tried, what was decided, who decided it —
// which is precisely the context a reviewer needs most when something comes
// back.
//
// It resolves through the same chain as Ensure: local record, then the backend
// by fingerprint. That matters after a restart, when nothing is cached and the
// record may itself have been lost: the durable path is the only path, and a
// version of this that depended on a warm cache would create duplicates
// exactly when a fresh process met a regression.
func (s *Service) Reopen(ctx context.Context, f model.Finding) (Ref, error) {
	if f.State != model.Regressed {
		return Ref{}, fmt.Errorf("%w: %s is in state %s", ErrNotRegressed, f.Fingerprint, f.State)
	}

	ref, found, err := s.locate(ctx, f.Fingerprint)
	if err != nil {
		return Ref{}, err
	}
	if !found {
		// No ticket ever existed for this finding. Not an error: most findings
		// never get one, and a regression does not change that.
		return Ref{}, nil
	}

	body := ReopenComment(f)
	if err := s.Tracker.Comment(ctx, ref, body); err != nil {
		return ref, s.queue(ctx, f.Fingerprint, "reopen", closePayload{Ref: ref, Body: body}, err)
	}
	if err := s.Tracker.Transition(ctx, ref, StateOpen); err != nil {
		return ref, s.queue(ctx, f.Fingerprint, "reopen", closePayload{Ref: ref, Body: body}, err)
	}

	// The durable record has to reflect the reopening, or the next cold start
	// reads the ticket as closed and the one after that opens a duplicate.
	return ref, s.Store.SaveTicket(ctx, store.Ticket{
		Fingerprint: f.Fingerprint, Backend: ref.Backend, Ref: ref.ID, URL: ref.URL,
		CreatedAt: s.now(), Reopened: true,
	})
}

// locate resolves a finding's ticket: local record first, backend second.
//
// The same chain as Ensure, for the same reason. A cache miss must degrade to a
// slower correct lookup, never to "no ticket exists" — treating absence as
// proof is the error that produces duplicates here and false resolutions
// elsewhere (VM-ADR-12).
func (s *Service) locate(ctx context.Context, fingerprint string) (Ref, bool, error) {
	if rec, ok, err := s.Store.GetTicket(ctx, fingerprint); err != nil {
		return Ref{}, false, err
	} else if ok {
		return Ref{Backend: rec.Backend, ID: rec.Ref, URL: rec.URL}, true, nil
	}
	return s.Tracker.Find(ctx, fingerprint)
}

// ReopenComment says what came back, and on what evidence.
func ReopenComment(f model.Finding) string {
	return fmt.Sprintf(
		"Reopening: a scan of `%s` observed this finding again, so it has REGRESSED.\n\n"+
			"This is the original ticket rather than a new one (VM-F-806): the history of the first "+
			"occurrence — what was tried, what was decided and by whom — is the context this recurrence "+
			"needs most.\n\n"+
			"_Regression means a scan saw it again, not that anyone inferred it had come back._\n",
		f.Repo)
}
