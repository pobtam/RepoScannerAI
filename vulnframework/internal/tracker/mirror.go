package tracker

import (
	"context"
	"fmt"
	"sync"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/store"
)

// Mirror wraps a primary tracker with a one-way copy into a secondary
// (VM-AD §13.4, VM-F-803).
//
// One-way is the design, not a simplification. If state were read back from the
// secondary, two systems would each be able to say a vulnerability is closed,
// and when they disagreed there would be no rule for which is right. The
// secondary is a window for people who plan their work there; the primary is
// the system of record.
type Mirror struct {
	Primary   Tracker
	Secondary Tracker
	// MirrorAt is the least severe priority that is mirrored. P2 and P3 noise
	// in a planning tool is how the mirror comes to be ignored.
	MirrorAt model.Priority

	// Resolver is the DURABLE reverse lookup from a primary reference to the
	// fingerprint that created it. The in-process index below is only a cache
	// in front of it.
	//
	// Without this, a restart emptied the index and every later comment was
	// skipped silently: the mirrored ticket simply stopped receiving updates
	// and nothing anywhere said so. A one-sided audit trail looks exactly like
	// a working one (OQ-P8-01).
	Resolver Resolver

	mu sync.Mutex
	// index caches primary ref id -> fingerprint, so the common case needs no
	// store round trip. It is a cache and nothing more: a miss falls through
	// to Resolver, never to a skip.
	index map[string]string
	errs  []error
}

// Resolver maps a primary ticket reference back to its finding.
type Resolver interface {
	FingerprintFor(ctx context.Context, backend, ref string) (string, bool, error)
}

// ResolverFunc adapts a function to Resolver.
type ResolverFunc func(ctx context.Context, backend, ref string) (string, bool, error)

func (f ResolverFunc) FingerprintFor(ctx context.Context, backend, ref string) (string, bool, error) {
	return f(ctx, backend, ref)
}

// StoreResolver reads the reverse lookup from the ticket record, which is the
// durable source of the mapping.
func StoreResolver(s interface {
	TicketByRef(ctx context.Context, backend, ref string) (store.Ticket, bool, error)
}) Resolver {
	return ResolverFunc(func(ctx context.Context, backend, ref string) (string, bool, error) {
		t, ok, err := s.TicketByRef(ctx, backend, ref)
		if err != nil || !ok {
			return "", false, err
		}
		return t.Fingerprint, true, nil
	})
}

// NewMirror builds a mirror. mirrorAt is the least severe priority copied.
func NewMirror(primary, secondary Tracker, mirrorAt model.Priority) *Mirror {
	return &Mirror{Primary: primary, Secondary: secondary, MirrorAt: mirrorAt, index: map[string]string{}}
}

func (m *Mirror) Name() string { return m.Primary.Name() }

// Find consults the primary only. The secondary is never a source of truth.
func (m *Mirror) Find(ctx context.Context, fingerprint string) (Ref, bool, error) {
	return m.Primary.Find(ctx, fingerprint)
}

func (m *Mirror) Create(ctx context.Context, spec Spec) (Ref, error) {
	ref, err := m.Primary.Create(ctx, spec)
	if err != nil {
		return Ref{}, err
	}
	m.remember(ref.ID, spec.Fingerprint)
	if m.shouldMirror(spec.Severity) {
		mirrored := spec
		// The mirrored ticket links back to the system of record, so a reader
		// who finds it in the planning tool can reach the real thing.
		mirrored.Body = spec.Body + "\n\n---\n\n_Mirrored from " + ref.URL +
			". That ticket is the system of record; this copy is not updated by anyone but the framework, " +
			"and nothing is ever read back from it (VM-AD §13.4)._\n"
		if _, err := m.Secondary.Create(ctx, mirrored); err != nil {
			m.note(fmt.Errorf("mirror create for %s: %w", spec.Fingerprint, err))
		}
	}
	return ref, nil
}

func (m *Mirror) Comment(ctx context.Context, ref Ref, body string) error {
	if err := m.Primary.Comment(ctx, ref, body); err != nil {
		return err
	}
	m.mirrorSide(ctx, ref, func(secondary Ref) error {
		return m.Secondary.Comment(ctx, secondary, body)
	})
	return nil
}

func (m *Mirror) Transition(ctx context.Context, ref Ref, st TicketState) error {
	if err := m.Primary.Transition(ctx, ref, st); err != nil {
		return err
	}
	m.mirrorSide(ctx, ref, func(secondary Ref) error {
		return m.Secondary.Transition(ctx, secondary, st)
	})
	return nil
}

func (m *Mirror) Link(ctx context.Context, child, parent Ref) error {
	return m.Primary.Link(ctx, child, parent)
}

// MirrorErrors returns the failures the secondary produced.
//
// They are collected rather than returned because a secondary failure must not
// fail the primary operation (VM-F-812) — but a silently swallowed failure is
// indistinguishable from a working mirror, so they are kept and reported.
func (m *Mirror) MirrorErrors() []error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]error(nil), m.errs...)
}

func (m *Mirror) shouldMirror(p model.Priority) bool {
	if m.Secondary == nil {
		return false
	}
	if m.MirrorAt == "" {
		return true
	}
	// Priorities sort lexically in the right direction: P0 < P1 < P2 < P3.
	return p != "" && p <= m.MirrorAt
}

// mirrorSide applies an operation to the secondary ticket for a primary ref.
//
// The secondary is located by the same fingerprint carrier the primary uses, so
// no second mapping table has to be kept correct.
func (m *Mirror) mirrorSide(ctx context.Context, primary Ref, fn func(Ref) error) {
	if m.Secondary == nil {
		return
	}
	fp, ok, err := m.fingerprintOf(ctx, primary)
	if err != nil {
		m.note(fmt.Errorf("mirror resolve for %s: %w", primary, err))
		return
	}
	if !ok {
		// Recorded, never swallowed. A skipped mirror update is invisible from
		// outside — the planning tool's copy simply diverges — so the one thing
		// that must not happen here is silence (OQ-P8-01).
		m.note(fmt.Errorf("mirror: cannot resolve primary reference %s to a finding; "+
			"the mirrored ticket was NOT updated and its copy is now behind", primary))
		return
	}
	secondary, found, err := m.Secondary.Find(ctx, fp)
	if err != nil {
		m.note(fmt.Errorf("mirror lookup for %s: %w", fp, err))
		return
	}
	if !found {
		return
	}
	if err := fn(secondary); err != nil {
		m.note(fmt.Errorf("mirror update for %s: %w", fp, err))
	}
}

// fingerprintOf recovers the fingerprint for a primary ref: cache, then the
// durable record.
//
// Never by parsing ticket text, which is the thing this package refuses to do
// anywhere else. A cache miss costs a store lookup, which is the correct price:
// a slower correct operation beats a dropped comment, because the dropped
// comment is undetectable.
func (m *Mirror) fingerprintOf(ctx context.Context, primary Ref) (string, bool, error) {
	m.mu.Lock()
	fp, ok := m.index[primary.ID]
	m.mu.Unlock()
	if ok {
		return fp, true, nil
	}
	if m.Resolver == nil {
		return "", false, nil
	}
	fp, ok, err := m.Resolver.FingerprintFor(ctx, primary.Backend, primary.ID)
	if err != nil || !ok {
		return "", false, err
	}
	// Warm the cache so the next update on this ticket is cheap again.
	m.remember(primary.ID, fp)
	return fp, true, nil
}

func (m *Mirror) remember(refID, fingerprint string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.index == nil {
		m.index = map[string]string{}
	}
	m.index[refID] = fingerprint
}

func (m *Mirror) note(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errs = append(m.errs, err)
}
