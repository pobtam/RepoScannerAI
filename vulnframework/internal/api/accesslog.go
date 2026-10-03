package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Access logging (VM-UI-F-805).
//
// Nothing logged access until now: there was no record of who looked at what,
// which is the one question an incident review asks about a system holding
// secret findings. The requirement is a SHOULD and it was listed as absent,
// which is the honest state but not a resting place.
//
// Three decisions, each because the obvious version is wrong.
//
// **Refused requests are logged, and they are the important ones.** A log of
// successful reads answers "who read this" and not "who TRIED to". Somebody
// repeatedly asking for secret findings they cannot see is the signal; a log
// that only recorded what was served would be blind to exactly that, and
// blind by construction rather than by accident.
//
// **The log records the request, never the response.** A finding's identity,
// the privilege level and whether anything was withheld — never the body. An
// access log that quoted what was returned would become the thing it exists to
// protect: a second copy of every secret finding anybody looked at, in a file
// with different retention and different permissions.
//
// **The query string is recorded with its values dropped.** Which filters were
// used is operationally interesting; what somebody searched for can contain
// anything they typed, including something they should not have pasted.

// AccessEvent is one request, as the log records it.
type AccessEvent struct {
	At time.Time `json:"at"`
	// Principal is the caller's identity as the authenticator established it.
	// Empty where authentication itself failed, which is a distinct and
	// recorded case rather than an anonymous read.
	Principal string `json:"principal,omitempty"`
	// Level is the privilege the request was served at, or "undetermined".
	Level  string `json:"level"`
	Method string `json:"method"`
	Path   string `json:"path"`
	// Query names the filters used, without their values.
	Query []string `json:"query,omitempty"`
	// Status is the HTTP status the caller received.
	Status int `json:"status"`
	// Outcome classifies the request for a reader scanning a day of these.
	//
	// Separate from Status because the interesting partition is not the one
	// HTTP makes: a 403 on a secret finding and a 403 from an undetermined
	// privilege level are the same status and completely different events.
	Outcome AccessOutcome `json:"outcome"`
	// Duration is how long the request took.
	Duration time.Duration `json:"duration_ms"`
}

// AccessOutcome classifies a logged request.
type AccessOutcome string

const (
	// AccessServed is an ordinary successful read.
	AccessServed AccessOutcome = "served"
	// AccessUnauthenticated is a caller the authenticator could not identify.
	AccessUnauthenticated AccessOutcome = "unauthenticated"
	// AccessUndetermined is an identified caller whose privilege level the
	// identity provider did not supply. It fails closed, and it is logged
	// separately because it means the provider is misconfigured rather than
	// that somebody overreached.
	AccessUndetermined AccessOutcome = "privilege-undetermined"
	// AccessRefused is an identified caller refused a resource. This is the
	// one an incident review reads.
	AccessRefused AccessOutcome = "refused"
	// AccessNotFound is a request for something that does not exist.
	//
	// Its own outcome rather than folded into AccessRefused, because the two
	// mean different things and the whole file is built on keeping those
	// apart. A refusal says somebody asked for what they may not have; a
	// not-found says they asked for what is not there. Fifty of the second in
	// a minute is enumeration, and it would be invisible inside a count that
	// also included every legitimate authorisation refusal.
	AccessNotFound AccessOutcome = "not-found"
	// AccessFailed is a server-side failure.
	AccessFailed AccessOutcome = "failed"
)

// AccessLog records who looked at what.
//
// An interface because where these go is a deployment decision: a file, a
// collector, an append-only store with its own retention. The framework's job
// is to produce the events and to produce them for refusals too.
type AccessLog interface {
	Record(ctx context.Context, e AccessEvent)
}

// SlogAccessLog writes events to a structured logger.
//
// The default, because it needs nothing configured and is therefore the
// version that actually runs. Where the records must outlive the process or
// be tamper-evident, that is a deployment choice and a different
// implementation.
type SlogAccessLog struct{ Logger *slog.Logger }

// Record writes one event.
func (l SlogAccessLog) Record(_ context.Context, e AccessEvent) {
	if l.Logger == nil {
		return
	}
	args := []any{
		"principal", e.Principal,
		"level", e.Level,
		"method", e.Method,
		"path", e.Path,
		"status", e.Status,
		"outcome", string(e.Outcome),
		"duration_ms", e.Duration.Milliseconds(),
	}
	if len(e.Query) > 0 {
		args = append(args, "filters", strings.Join(e.Query, ","))
	}
	// A refusal is logged at WARN. An operator scanning for somebody probing
	// what they cannot see should not have to filter it out of every
	// successful read in the fleet.
	if e.Outcome == AccessServed {
		l.Logger.Info("access", args...)
		return
	}
	l.Logger.Warn("access", args...)
}

// MemoryAccessLog keeps events in memory, for tests and for the
// demonstration.
type MemoryAccessLog struct {
	mu     sync.Mutex
	events []AccessEvent
}

// Record appends an event.
func (l *MemoryAccessLog) Record(_ context.Context, e AccessEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

// Events returns what was recorded, in order.
func (l *MemoryAccessLog) Events() []AccessEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]AccessEvent(nil), l.events...)
}

// --- the middleware ----------------------------------------------------------

type principalHolderKey struct{}

// principalHolder carries the principal back OUT to the access log.
//
// The direction is what makes it necessary. Middleware passes context inwards,
// and the access log needs a value established further in than it sits.
type principalHolder struct {
	mu sync.Mutex
	p  Principal
}

func (h *principalHolder) set(p Principal) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.p = p
}

func (h *principalHolder) get() Principal {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.p
}

// recordPrincipal hands the established principal to the access log, if one is
// listening.
func recordPrincipal(ctx context.Context, p Principal) {
	if holder, ok := ctx.Value(principalHolderKey{}).(*principalHolder); ok {
		holder.set(p)
	}
}

// statusRecorder captures the status a handler wrote.
//
// Needed because http.ResponseWriter does not expose it, and a log that
// guessed 200 for everything would record a refusal as a successful read —
// which is the single most misleading thing an access log can do.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *statusRecorder) WriteHeader(code int) {
	if !w.written {
		w.status, w.written = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if !w.written {
		// A handler that writes a body without calling WriteHeader has
		// implicitly sent 200.
		w.status, w.written = http.StatusOK, true
	}
	return w.ResponseWriter.Write(b)
}

// withAccessLog records every request, served or refused.
//
// It wraps withPrincipal rather than sitting inside it, which is the whole
// point: a request refused BEFORE a principal is established is still a
// request somebody made, and it is the one worth looking at. A log that only
// saw what got past authentication would be blind to every attempt.
func (s *Server) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AccessLog == nil {
			next.ServeHTTP(w, r)
			return
		}

		started := s.now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		// A holder the inner middleware fills in.
		//
		// Reading principalFrom(r.Context()) here does not work and the
		// reason is easy to miss: withPrincipal forwards a NEW request
		// carrying a NEW context, so the principal never appears on the
		// context this middleware holds. The first version of this logged
		// every request — including successful reads by a fully privileged
		// caller — as "privilege-undetermined", which is the precise
		// blindness the comments above are about, produced by the code they
		// are attached to.
		//
		// A pointer rather than a value, because the point is to receive
		// something written after this line runs.
		holder := &principalHolder{}
		ctx := context.WithValue(r.Context(), principalHolderKey{}, holder)
		next.ServeHTTP(rec, r.WithContext(ctx))

		p := holder.get()
		event := AccessEvent{
			At:        started,
			Principal: p.Recipient.ID,
			Level:     levelName(p),
			Method:    r.Method,
			Path:      r.URL.Path,
			Query:     filterNames(r),
			Status:    rec.status,
			Outcome:   outcomeFor(rec.status, p),
			Duration:  s.now().Sub(started),
		}
		s.cfg.AccessLog.Record(r.Context(), event)
	})
}

// levelName renders the privilege a request was served at.
//
// "undetermined" rather than an empty string, and never the zero level: an
// undetermined privilege that logged as "public" would make a failed identity
// lookup indistinguishable from a legitimate anonymous read, in the record
// somebody consults precisely to tell those apart.
func levelName(p Principal) string {
	if !p.Determined() {
		return "undetermined"
	}
	return p.Level().String()
}

func outcomeFor(status int, p Principal) AccessOutcome {
	switch {
	case status == http.StatusUnauthorized:
		return AccessUnauthenticated
	case status == http.StatusForbidden && !p.Determined():
		// Refused before a privilege level existed: the identity provider did
		// not supply one. A misconfiguration, not an overreach, and an
		// operator who cannot tell them apart will chase the wrong thing.
		return AccessUndetermined
	case status == http.StatusForbidden:
		return AccessRefused
	case status == http.StatusNotFound:
		return AccessNotFound
	case status >= 500:
		return AccessFailed
	case status >= 400:
		return AccessRefused
	default:
		return AccessServed
	}
}

// filterNames returns the query parameter NAMES, never their values.
//
// Which filters somebody used is operationally interesting. What they typed
// into a search box is not the access log's business and can contain anything
// at all — including something that should never have been pasted into a
// browser, which is exactly the kind of thing that then lives for ever in a
// log file with its own retention policy.
func filterNames(r *http.Request) []string {
	q := r.URL.Query()
	if len(q) == 0 {
		return nil
	}
	out := make([]string, 0, len(q))
	for name := range q {
		out = append(out, name)
	}
	// Sorted, so two identical requests produce identical records and a diff
	// of a day's log is readable.
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
