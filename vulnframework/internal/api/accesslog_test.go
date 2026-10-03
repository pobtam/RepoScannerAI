package api_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/api"
	"github.com/wanaware/vulnframework/internal/report"
)

// rejectingAuth is an authenticator that cannot identify the caller, as a
// missing or expired session does.
type rejectingAuth struct{}

func (rejectingAuth) Authenticate(*http.Request) (api.Principal, error) {
	return api.Principal{}, errors.New("no session")
}

// undeterminedAuth, which stands in for an identity provider that answered
// without a privilege level, is declared in honesty_test.go and reused here.

// Access logging (VM-UI-F-805).
//
// The requirement is one line and the failure modes are not. An access log
// that recorded only successful reads would answer "who read this" and be
// blind to "who tried to" — and somebody probing what they cannot see is the
// thing an incident review is looking for.

// TestARefusedRequestIsLogged is the point of the whole feature.
func TestARefusedRequestIsLogged(t *testing.T) {
	h := newHarness(t)
	log := &api.MemoryAccessLog{}
	// An engineer who does not own the repository holding the secret finding.
	// They may count it and may not open it (VM-UI-F-803, VM-UI-F-804) —
	// which is a REFUSAL of an identified caller, and distinct from a caller
	// whose privilege level could not be established at all.
	srv := h.serverWithAccessLog(t, log,
		api.DemoAuth{Level: report.LevelEngineer, Repos: []string{"demo-org/not-this-one"}})

	// A secret finding, asked for by somebody who may not see it.
	req := httptest.NewRequest(http.MethodGet, "/v1/findings/"+h.SecretFP, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code < 400 {
		t.Fatalf("the request was served (%d); this test needs it refused", rec.Code)
	}

	events := log.Events()
	if len(events) != 1 {
		t.Fatalf("got %d access events for one request, want 1", len(events))
	}
	e := events[0]
	if e.Outcome != api.AccessRefused {
		t.Errorf("outcome = %q, want %q. A refusal recorded as an ordinary read is the single "+
			"most misleading entry an access log can carry", e.Outcome, api.AccessRefused)
	}
	if e.Status != rec.Code {
		t.Errorf("status = %d, want %d", e.Status, rec.Code)
	}
	if !strings.Contains(e.Path, h.SecretFP) {
		t.Errorf("the event does not record what was asked for: %q", e.Path)
	}
	if e.Level == "" {
		t.Error("the event records no privilege level")
	}
}

// TestASuccessfulReadIsLoggedAsServed is the ordinary case, and the partner
// that stops the test above from being satisfied by logging everything as a
// refusal.
func TestASuccessfulReadIsLoggedAsServed(t *testing.T) {
	h := newHarness(t)
	log := &api.MemoryAccessLog{}
	srv := h.serverWithAccessLog(t, log, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/repos", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/repos returned %d", rec.Code)
	}
	events := log.Events()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Outcome != api.AccessServed {
		t.Errorf("outcome = %q, want served", events[0].Outcome)
	}
	if events[0].Principal == "" {
		t.Error("a served request records no principal, so the log cannot answer who read it")
	}
}

// TestANotFoundIsItsOwnOutcome keeps enumeration visible.
//
// A request for something that does not exist and a request for something the
// caller may not have are different facts. Fifty of the first in a minute is
// somebody walking identifiers; inside a count that also held every
// legitimate authorisation refusal, it would be invisible.
func TestANotFoundIsItsOwnOutcome(t *testing.T) {
	h := newHarness(t)
	log := &api.MemoryAccessLog{}
	srv := h.serverWithAccessLog(t, log, nil)

	req := httptest.NewRequest(http.MethodGet,
		"/v1/findings/0000000000000000000000000000000000000000000000000000000000000000", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
	events := log.Events()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Outcome != api.AccessNotFound {
		t.Errorf("outcome = %q, want %q", events[0].Outcome, api.AccessNotFound)
	}
	if events[0].Outcome == api.AccessServed {
		t.Error("a request for something that does not exist was logged as a successful read")
	}
}

// TestAnUnauthenticatedRequestIsLogged is why the middleware wraps
// withPrincipal rather than sitting inside it.
//
// A request refused before a principal exists is still a request somebody
// made. Somebody failing authentication repeatedly is exactly what this
// record is for, and a log that sat inside the authentication boundary would
// be blind to it by construction.
func TestAnUnauthenticatedRequestIsLogged(t *testing.T) {
	h := newHarness(t)
	log := &api.MemoryAccessLog{}
	srv := h.serverWithAccessLog(t, log, rejectingAuth{})

	req := httptest.NewRequest(http.MethodGet, "/v1/findings", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
	events := log.Events()
	if len(events) != 1 {
		t.Fatalf("an unauthenticated request produced %d access events. A log that only sees "+
			"what gets past authentication cannot see anybody failing it", len(events))
	}
	if events[0].Outcome != api.AccessUnauthenticated {
		t.Errorf("outcome = %q, want %q", events[0].Outcome, api.AccessUnauthenticated)
	}
	if events[0].Principal != "" {
		t.Errorf("an unauthenticated request recorded principal %q", events[0].Principal)
	}
}

// TestAnUndeterminedPrivilegeIsItsOwnOutcome keeps a misconfiguration apart
// from an overreach.
//
// Both are 403. One means the identity provider did not supply a level, which
// is an administrator's problem; the other means somebody asked for what they
// cannot see, which is a security one. An operator who cannot tell them apart
// chases the wrong thing.
func TestAnUndeterminedPrivilegeIsItsOwnOutcome(t *testing.T) {
	h := newHarness(t)
	log := &api.MemoryAccessLog{}
	srv := h.serverWithAccessLog(t, log, undeterminedAuth{})

	req := httptest.NewRequest(http.MethodGet, "/v1/repos", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
	events := log.Events()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Outcome != api.AccessUndetermined {
		t.Errorf("outcome = %q, want %q: a provider that supplied no level and a caller who "+
			"overreached are the same status and different events",
			events[0].Outcome, api.AccessUndetermined)
	}
	if events[0].Level != "undetermined" {
		t.Errorf("level = %q. An undetermined privilege logged as 'public' makes a failed "+
			"identity lookup indistinguishable from a legitimate anonymous read, in the record "+
			"somebody consults precisely to tell those apart", events[0].Level)
	}
}

// TestTheLogRecordsFilterNamesAndNotTheirValues keeps the access log from
// becoming the thing it protects.
//
// Which filters somebody used is operationally interesting. What they typed
// into a search box can contain anything at all, including something that
// should never have been pasted into a browser — and a log file has its own
// retention and its own permissions.
func TestTheLogRecordsFilterNamesAndNotTheirValues(t *testing.T) {
	h := newHarness(t)
	log := &api.MemoryAccessLog{}
	srv := h.serverWithAccessLog(t, log, nil)

	const pasted = "REDACTED-AWS-EXAMPLE-KEY-ID"
	req := httptest.NewRequest(http.MethodGet,
		"/v1/findings?state=TRIAGED&q="+pasted, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	events := log.Events()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	e := events[0]

	if !contains(e.Query, "state") || !contains(e.Query, "q") {
		t.Errorf("the filters used were not recorded: %v", e.Query)
	}
	for _, field := range append([]string{e.Path}, e.Query...) {
		if strings.Contains(field, pasted) {
			t.Fatalf("a query VALUE reached the access log (%q). The log would then hold a copy "+
				"of whatever anybody typed, in a file with its own retention", field)
		}
	}
}

// TestTheFilterNamesAreSorted keeps a day's log diffable.
//
// Asserted as SORTED rather than merely stable across repeats. The first
// version ran the same request eight times and compared the orders, which
// relies on Go's map iteration randomisation actually differing within a
// handful of keys — so it passed against an unsorted implementation. A guard
// that depends on randomness to fail is a flaky guard, and a flaky guard is
// worse than none.
func TestTheFilterNamesAreSorted(t *testing.T) {
	h := newHarness(t)
	log := &api.MemoryAccessLog{}
	srv := h.serverWithAccessLog(t, log, nil)

	req := httptest.NewRequest(http.MethodGet,
		"/v1/findings?state=TRIAGED&repo=demo-org%2Fpayments-api&priority=P1&category=dependency", nil)
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

	events := log.Events()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	got := events[0].Query
	if len(got) != 4 {
		t.Fatalf("recorded %d filter names, want 4: %v", len(got), got)
	}

	want := append([]string(nil), got...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("the filter names are not sorted: %v. Two identical requests would then record "+
			"differently and a day's log could not be diffed", got)
	}
	// And the sort is not vacuous: the request supplies names that are not
	// already in order.
	if strings.Join(got, ",") != "category,priority,repo,state" {
		t.Fatalf("filter names = %v, want [category priority repo state]", got)
	}
}

// TestNoAccessLogMeansNoAccessLog is assert-the-negative on the configuration.
//
// Nil must disable it cleanly rather than panicking, because the demonstration
// and every existing test run without one.
func TestNoAccessLogMeansNoAccessLog(t *testing.T) {
	h := newHarness(t)
	srv := h.serverWithAccessLog(t, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/repos", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("a server with no access log returned %d", rec.Code)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
