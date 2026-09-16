package tracker

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Fake is an in-memory tracker.
//
// It is held to the same rules as the real backends — it validates every spec,
// it locates by fingerprint and never by title — because a fake that is more
// permissive than production turns every test that uses it into a statement
// about the fake.
type Fake struct {
	mu      sync.Mutex
	name    string
	next    int
	byFP    map[string]Ref
	perFP   map[string][]Ref
	states  map[string]TicketState
	bodies  map[string]string
	notes   map[string][]string
	links   map[string]Ref
	creates int
	finds   int
	lastQ   string
	failure error
}

// NewFake returns an empty tracker named as the backend it stands in for.
func NewFake(name string) *Fake {
	return &Fake{
		name: name, byFP: map[string]Ref{}, perFP: map[string][]Ref{}, states: map[string]TicketState{},
		bodies: map[string]string{}, notes: map[string][]string{}, links: map[string]Ref{},
	}
}

func (f *Fake) Name() string { return f.name }

// FailWith makes every operation fail until cleared with nil. It stands in for
// a tracker outage, which must never fail a run (VM-F-812).
func (f *Fake) FailWith(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failure = err
}

func (f *Fake) Find(_ context.Context, fingerprint string) (Ref, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finds++
	f.lastQ = fingerprint
	if f.failure != nil {
		return Ref{}, false, f.failure
	}
	ref, ok := f.byFP[fingerprint]
	return ref, ok, nil
}

func (f *Fake) Create(_ context.Context, spec Spec) (Ref, error) {
	if err := spec.Validate(); err != nil {
		return Ref{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure != nil {
		return Ref{}, f.failure
	}
	// No deduplication, deliberately. GitHub, Jira and Linear will all happily
	// open a second issue carrying the same fingerprint — idempotency is this
	// framework's job, not theirs. A fake that quietly refused would make the
	// duplicate-ticket gate unfalsifiable: the bug would be invisible because
	// the fake compensated for it.
	f.next++
	ref := Ref{
		Backend: f.name,
		ID:      fmt.Sprintf("%d", f.next),
		URL:     fmt.Sprintf("https://%s.example/%s/%d", f.name, spec.Repo, f.next),
	}
	f.creates++
	if _, seen := f.byFP[spec.Fingerprint]; !seen {
		// Find returns the first ticket opened for a fingerprint, as a search
		// ordered by age would.
		f.byFP[spec.Fingerprint] = ref
	}
	f.perFP[spec.Fingerprint] = append(f.perFP[spec.Fingerprint], ref)
	f.states[ref.ID] = StateOpen
	f.bodies[ref.ID] = spec.Title + "\n" + spec.Body + "\n" + strings.Join(spec.Labels, ",")
	return ref, nil
}

func (f *Fake) Comment(_ context.Context, ref Ref, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure != nil {
		return f.failure
	}
	f.notes[ref.ID] = append(f.notes[ref.ID], body)
	return nil
}

func (f *Fake) Transition(_ context.Context, ref Ref, st TicketState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure != nil {
		return f.failure
	}
	if _, ok := f.states[ref.ID]; !ok {
		return fmt.Errorf("tracker: no such ticket %s", ref)
	}
	f.states[ref.ID] = st
	return nil
}

func (f *Fake) Link(_ context.Context, child, parent Ref) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure != nil {
		return f.failure
	}
	f.links[child.ID] = parent
	return nil
}

// --- inspection ------------------------------------------------------------

func (f *Fake) CreateCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.creates }
func (f *Fake) FindCount() int   { f.mu.Lock(); defer f.mu.Unlock(); return f.finds }

// LastFindQuery is what Find was last asked for. Tests assert it is the
// fingerprint, never title text (VM-F-805).
func (f *Fake) LastFindQuery() string { f.mu.Lock(); defer f.mu.Unlock(); return f.lastQ }

func (f *Fake) State(ref Ref) TicketState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.states[ref.ID]
}

func (f *Fake) OpenCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, st := range f.states {
		if st == StateOpen {
			n++
		}
	}
	return n
}

func (f *Fake) Comments(ref Ref) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.notes[ref.ID]...)
}

// TicketsFor returns every ticket opened for a fingerprint. More than one is
// the duplicate the idempotency chain exists to prevent.
func (f *Fake) TicketsFor(fingerprint string) []Ref {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Ref(nil), f.perFP[fingerprint]...)
}

func (f *Fake) Tickets() map[string]Ref {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]Ref{}
	for k, v := range f.byFP {
		out[k] = v
	}
	return out
}

// Everything returns every byte the fake was handed: titles, bodies, labels and
// comments. It is what the no-value assertions scan, because the question is
// not whether the model holds a secret but whether one reached the backend.
func (f *Fake) Everything() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(f.bodies))
	for k := range f.bodies {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		b.WriteString(f.bodies[k])
		b.WriteString("\n")
		for _, n := range f.notes[k] {
			b.WriteString(n)
			b.WriteString("\n")
		}
	}
	return b.String()
}
