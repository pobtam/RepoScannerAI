package feed_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/feed"
)

// These tests drive the real clients against a local server serving recorded
// fixtures. Nothing reaches CISA or FIRST, nothing needs a credential, and
// enabling the live feeds remains a human decision (D3).
//
// What is being tested is not "can it parse the happy path". It is the set of
// ways a feed client reports something it does not know:
//
//   - a feed that is down reading as a feed that answered and knew nothing;
//   - a truncated catalogue reading as a shorter one;
//   - an unlisted identifier reading as a measured-zero.
//
// Each of those produces a confident, wrong, decision-changing input to the
// scorer, and none of them looks like a failure from the outside.

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", "feeds", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return b
}

// serve returns a server that answers every request with body and status.
func serve(t *testing.T, status int, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// --- KEV ---------------------------------------------------------------------

func TestKEVReadsTheCatalogue(t *testing.T) {
	srv := serve(t, http.StatusOK, fixtureBytes(t, "kev.json"))
	src := &feed.KEVSource{URL: srv.URL}

	got, err := src.Lookup(context.Background(), []string{"CVE-2021-44228", "CVE-2019-0001"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	listed, ok := got["CVE-2021-44228"]
	if !ok {
		t.Fatal("the catalogue lists CVE-2021-44228 and the lookup did not answer for it")
	}
	if !listed.KEVAvailable || !listed.KEV {
		t.Fatalf("a listed CVE did not come back as known-exploited: %+v", listed)
	}
	if listed.KEVAsOf.IsZero() {
		t.Error("the catalogue date was not carried. A claim about exploitation with no date " +
			"cannot be qualified, and freshness is what D3 exists to decide")
	}

	// And the negative, which is a real measurement here and not silence:
	// KEV is a complete enumeration, so absence from it means checked and not
	// listed.
	unlisted, ok := got["CVE-2019-0001"]
	if !ok {
		t.Fatal("the lookup did not answer for an identifier the catalogue does not list. " +
			"KEV is exhaustive, so absence from it is a measurement — and a caller that gets no " +
			"answer cannot tell that apart from the catalogue not having been consulted")
	}
	if !unlisted.KEVAvailable {
		t.Error("an unlisted CVE came back as unavailable rather than as checked-and-not-listed")
	}
	if unlisted.KEV {
		t.Error("an unlisted CVE came back as known-exploited")
	}
}

// TestADownKEVIsNotAnEmptyCatalogue is the distinction the whole boundary
// rests on.
//
// An empty result means the source answered and knew none of the identifiers
// — which for KEV means "checked, not listed", and a not-listed is an input
// that LOWERS a priority. A feed that was unreachable producing that answer
// would quietly de-escalate every finding in the fleet.
func TestADownKEVIsNotAnEmptyCatalogue(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   []byte
	}{
		{"server error", http.StatusInternalServerError, []byte("upstream failure")},
		{"not found", http.StatusNotFound, []byte("")},
		{"rate limited", http.StatusTooManyRequests, []byte("slow down")},
		{"forbidden", http.StatusForbidden, []byte("")},
		{"not JSON", http.StatusOK, []byte("<html>maintenance</html>")},
		// The one that the other rows cannot catch. A publisher answering 503
		// with a cached copy of the catalogue produces a body that parses
		// perfectly — so only the STATUS distinguishes "here is the
		// catalogue" from "I am broken, here is something catalogue-shaped".
		// Without this row the parse check covers for the status check and a
		// stale error response reads as an authoritative "not listed".
		{"error status carrying a valid body", http.StatusServiceUnavailable, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			if body == nil {
				body = fixtureBytes(t, "kev.json")
			}
			srv := serve(t, tc.status, body)
			src := &feed.KEVSource{URL: srv.URL}

			got, err := src.Lookup(context.Background(), []string{"CVE-2021-44228"})
			if err == nil {
				t.Fatalf("a failing feed returned %d assessments and no error. An empty result "+
					"means the catalogue was consulted and did not list it, which lowers a "+
					"priority", len(got))
			}
			var unavailable *feed.ErrUnavailable
			if !errors.As(err, &unavailable) {
				t.Fatalf("the failure is not an *ErrUnavailable, so Multi will not count the "+
					"source as down: %v", err)
			}
			if unavailable.Source != "kev" {
				t.Errorf("the error names source %q", unavailable.Source)
			}
			if len(got) != 0 {
				t.Errorf("a failed lookup also returned %d assessments", len(got))
			}
		})
	}
}

// TestATruncatedKEVCatalogueIsRefused is the case that looks most like
// success.
//
// A document cut short is still well-formed JSON and parses into a valid,
// shorter catalogue. Every CVE after the cut then reads as "checked and not
// listed" — which is to say, as no longer being exploited.
func TestATruncatedKEVCatalogueIsRefused(t *testing.T) {
	full := fixtureBytes(t, "kev.json")
	// The publisher's own count, with two of the four entries removed: exactly
	// what a lost page or a cut transfer produces.
	truncated := []byte(`{"catalogVersion":"2026.09.28","dateReleased":"2026-09-28T14:00:00.0000Z",` +
		`"count":4,"vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10"},` +
		`{"cveID":"CVE-2023-4863","dateAdded":"2023-09-13"}]}`)
	if len(truncated) >= len(full) {
		t.Fatal("the fixture is not actually shorter")
	}

	srv := serve(t, http.StatusOK, truncated)
	src := &feed.KEVSource{URL: srv.URL}

	_, err := src.Lookup(context.Background(), []string{"CVE-2024-3400"})
	if err == nil {
		t.Fatal("a catalogue carrying half the entries it declares was accepted. Every CVE after " +
			"the cut then reads as no longer being exploited")
	}
	if !strings.Contains(err.Error(), "4") || !strings.Contains(err.Error(), "2") {
		t.Errorf("the refusal does not say how many entries were expected and how many arrived: %v", err)
	}
}

// TestACompleteKEVCatalogueIsAccepted is the non-vacuity partner.
//
// Without it, a client that refused every catalogue would pass the test above.
func TestACompleteKEVCatalogueIsAccepted(t *testing.T) {
	srv := serve(t, http.StatusOK, fixtureBytes(t, "kev.json"))
	src := &feed.KEVSource{URL: srv.URL}

	if _, err := src.Lookup(context.Background(), []string{"CVE-2021-44228"}); err != nil {
		t.Fatalf("a complete catalogue was refused, so the truncation check rejects everything: %v", err)
	}
}

// TestAKEVCatalogueWithoutAUsableDateIsRefused keeps an exploitation claim
// qualified — and keeps the two reasons it can be unqualified apart.
//
// A field the publisher stopped emitting and a field whose format changed are
// different operational problems with different owners: the first is a
// publication change to raise with CISA, the second is a parser this project
// has to update. Reporting both as "unrecognised format" sends the first one
// to the wrong person, and reporting both as "missing" sends the second.
func TestAKEVCatalogueWithoutAUsableDateIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, dateField, wantPhrase string
	}{
		{"the field is absent", "", "no release date"},
		{"the field is present and unreadable", `"dateReleased":"last Tuesday",`, "no recognised format"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"catalogVersion":"x",` + tc.dateField +
				`"count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`)
			srv := serve(t, http.StatusOK, body)
			src := &feed.KEVSource{URL: srv.URL}

			_, err := src.Lookup(context.Background(), []string{"CVE-2021-44228"})
			if err == nil {
				t.Fatal("a catalogue with no usable release date was accepted. Its age is then " +
					"unknown, and an unqualified exploitation claim outlives its correction")
			}
			if !strings.Contains(err.Error(), tc.wantPhrase) {
				t.Errorf("the refusal does not distinguish this case: want something containing "+
					"%q, got %v", tc.wantPhrase, err)
			}
		})
	}
}

func TestKEVWithNoURLConfiguredDoesNotSilentlyAnswer(t *testing.T) {
	src := &feed.KEVSource{}
	_, err := src.Lookup(context.Background(), []string{"CVE-2021-44228"})
	if err == nil {
		t.Fatal("an unconfigured source answered. An unconfigured feed that reports 'not listed' " +
			"is the quietest way for this system to be wrong")
	}
	// And it says what is wrong. Left to the transport, an empty URL surfaces
	// as "unsupported protocol scheme", which sends an operator looking at
	// the network for a configuration mistake. The explicit check is not
	// redundant with the transport error; it is the difference between a
	// diagnosable failure and a puzzling one.
	if !strings.Contains(err.Error(), "URL is configured") {
		t.Errorf("the failure does not say the source is unconfigured: %v", err)
	}
}

// --- EPSS --------------------------------------------------------------------

func TestEPSSReadsTheSnapshot(t *testing.T) {
	srv := serve(t, http.StatusOK, fixtureBytes(t, "epss.csv.gz"))
	src := &feed.EPSSSource{URL: srv.URL}

	got, err := src.Lookup(context.Background(), []string{"CVE-2021-44228", "CVE-2020-1234"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	scored, ok := got["CVE-2021-44228"]
	if !ok {
		t.Fatal("a scored CVE was not answered for")
	}
	if !scored.EPSSAvailable {
		t.Fatal("a scored CVE came back unavailable")
	}
	if scored.EPSS < 0.94 || scored.EPSS > 0.95 {
		t.Errorf("EPSS = %v, want the fixture's 0.944120", scored.EPSS)
	}
	if scored.EPSSAsOf.IsZero() {
		t.Error("the score_date was not carried, so the score's age is unknown")
	}
	if want := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC); !scored.EPSSAsOf.Equal(want) {
		t.Errorf("EPSSAsOf = %v, want %v", scored.EPSSAsOf, want)
	}
}

// TestAMeasuredZeroIsNotTheSameAsNotLookedUp is the tri-state at its sharpest.
//
// The fixture scores CVE-2020-1234 at exactly 0.000000. That is a
// MEASUREMENT: somebody ran the model and it came out negligible. An
// identifier nobody scored must not arrive looking the same, because the
// scorer treats the first as an input it has and the second as one it is
// missing — and says so beside the number.
func TestAMeasuredZeroIsNotTheSameAsNotLookedUp(t *testing.T) {
	srv := serve(t, http.StatusOK, fixtureBytes(t, "epss.csv.gz"))
	src := &feed.EPSSSource{URL: srv.URL}

	got, err := src.Lookup(context.Background(), []string{"CVE-2020-1234", "CVE-2099-9999"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	measured, ok := got["CVE-2020-1234"]
	if !ok {
		t.Fatal("a CVE scored at exactly zero was omitted. Zero is a measurement, and dropping it " +
			"turns 'measured and negligible' into 'nobody looked'")
	}
	if !measured.EPSSAvailable {
		t.Fatal("a CVE scored at zero came back as unavailable")
	}
	if measured.EPSS != 0 {
		t.Errorf("EPSS = %v, want 0", measured.EPSS)
	}

	if unscored, present := got["CVE-2099-9999"]; present {
		t.Fatalf("an identifier the snapshot does not score was answered for anyway: %+v.\n"+
			"EPSS is not an exhaustive enumeration, so absence from it means nobody scored it — "+
			"which is a different fact from a score of zero", unscored)
	}
}

// TestADownEPSSIsNotAnEmptySnapshot is the KEV distinction again, and it
// matters as much: an absent EPSS makes the scorer say so beside the number,
// where a zero would silently de-prioritise.
func TestADownEPSSIsNotAnEmptySnapshot(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   []byte
	}{
		{"server error", http.StatusInternalServerError, []byte("")},
		{"rate limited", http.StatusTooManyRequests, []byte("")},
		{"not gzip", http.StatusOK, []byte("cve,epss,percentile\nCVE-1,0.5,0.5\n")},
		// As for KEV: a body that parses cleanly behind an error status, so
		// the status check is the only thing that can object.
		{"error status carrying a valid body", http.StatusServiceUnavailable, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			if body == nil {
				body = fixtureBytes(t, "epss.csv.gz")
			}
			srv := serve(t, tc.status, body)
			src := &feed.EPSSSource{URL: srv.URL}

			got, err := src.Lookup(context.Background(), []string{"CVE-2021-44228"})
			if err == nil {
				t.Fatalf("a failing snapshot returned %d assessments and no error", len(got))
			}
			var unavailable *feed.ErrUnavailable
			if !errors.As(err, &unavailable) {
				t.Fatalf("the failure is not an *ErrUnavailable: %v", err)
			}
		})
	}
}

// TestATruncatedEPSSSnapshotIsRefused is the gzip equivalent of the KEV
// truncation case.
func TestATruncatedEPSSSnapshotIsRefused(t *testing.T) {
	full := fixtureBytes(t, "epss.csv.gz")
	cut := full[:len(full)/2]

	srv := serve(t, http.StatusOK, cut)
	src := &feed.EPSSSource{URL: srv.URL}

	_, err := src.Lookup(context.Background(), []string{"CVE-2021-44228"})
	if err == nil {
		t.Fatal("a snapshot cut in half was parsed. Every score after the cut is then " +
			"indistinguishable from an identifier nobody scored")
	}
}

// TestAnEPSSSnapshotTruncatedAfterTheHeaderIsRefused is the truncation case
// that the header check cannot see.
//
// A real snapshot is megabytes long, so a cut transfer almost always arrives
// WITH its header and comment line intact and simply stops partway through
// the scores. The header check is then satisfied, the CSV parses, and every
// identifier after the cut comes back absent — which the scorer reads as
// "nobody scored it" and renders as a missing input.
//
// That is the quiet version of the failure: not an error anywhere, just a
// fleet whose exploitation predictions silently stop existing partway down
// the alphabet.
func TestAnEPSSSnapshotTruncatedAfterTheHeaderIsRefused(t *testing.T) {
	var body strings.Builder
	body.WriteString("#model_version:v1,score_date:2026-09-28T00:00:00+0000\n")
	body.WriteString("cve,epss,percentile\n")
	for i := 0; i < 4000; i++ {
		fmt.Fprintf(&body, "CVE-2026-%04d,0.1234,0.5678\n", i)
	}
	full := gzipOf(t, body.String())

	// Cut late, so the header is comfortably inside what arrives.
	cut := full[:len(full)*9/10]
	srv := serve(t, http.StatusOK, cut)
	src := &feed.EPSSSource{URL: srv.URL}

	_, err := src.Lookup(context.Background(), []string{"CVE-2026-3999"})
	if err == nil {
		t.Fatal("a snapshot cut off after its header was parsed. The header check is satisfied, " +
			"the rows that arrived parse, and every identifier after the cut reads as one nobody " +
			"scored")
	}
}

// TestAnEPSSSnapshotWithNoScoreDateIsRefused keeps every score qualified.
func TestAnEPSSSnapshotWithNoScoreDateIsRefused(t *testing.T) {
	body := gzipOf(t, "cve,epss,percentile\nCVE-2021-44228,0.9,0.99\n")
	srv := serve(t, http.StatusOK, body)
	src := &feed.EPSSSource{URL: srv.URL}

	if _, err := src.Lookup(context.Background(), []string{"CVE-2021-44228"}); err == nil {
		t.Fatal("a snapshot with no score_date was accepted. The age of every score in it is " +
			"then unknown, and freshness is the whole of what makes a prediction usable")
	}
}

// TestAnEPSSSnapshotInAnUnexpectedShapeIsRefused covers the publisher
// changing the format under the framework.
//
// Reading it anyway is the dangerous option: the columns would still parse as
// numbers and the scorer would receive confident values from a column that
// means something else.
func TestAnEPSSSnapshotInAnUnexpectedShapeIsRefused(t *testing.T) {
	body := gzipOf(t, "#model_version:v1,score_date:2026-09-28T00:00:00+0000\n"+
		"identifier;probability;rank\nCVE-2021-44228;0.9;0.99\n")
	srv := serve(t, http.StatusOK, body)
	src := &feed.EPSSSource{URL: srv.URL}

	if _, err := src.Lookup(context.Background(), []string{"CVE-2021-44228"}); err == nil {
		t.Fatal("a snapshot with no recognised header was parsed anyway. The columns still read " +
			"as numbers, so the scorer would get confident values from the wrong column")
	}
}

// TestAnUnparseableRowIsDroppedNotClamped is the no-repair rule.
//
// A score that is not a number is evidence the row was not produced by the
// process this system believes it was. Repairing it into something judgeable
// would turn a corrupt row into a scored finding.
func TestAnUnparseableRowIsDroppedNotClamped(t *testing.T) {
	body := gzipOf(t, "#model_version:v1,score_date:2026-09-28T00:00:00+0000\n"+
		"cve,epss,percentile\n"+
		"CVE-2021-44228,not-a-number,0.99\n"+
		"CVE-2023-4863,0.5,0.9\n")
	srv := serve(t, http.StatusOK, body)
	src := &feed.EPSSSource{URL: srv.URL}

	got, err := src.Lookup(context.Background(), []string{"CVE-2021-44228", "CVE-2023-4863"})
	if err != nil {
		t.Fatalf("one bad row made the whole snapshot unavailable: %v", err)
	}
	if bad, present := got["CVE-2021-44228"]; present {
		t.Fatalf("a row whose score is not a number produced an assessment: %+v", bad)
	}
	if good, present := got["CVE-2023-4863"]; !present || good.EPSS != 0.5 {
		t.Errorf("a good row beside a bad one was lost: %+v", good)
	}
	if src.Malformed() != 1 {
		t.Errorf("Malformed = %d, want 1. A dropped row that is not counted is a silent loss",
			src.Malformed())
	}
}

// --- the boundary above them -------------------------------------------------

// TestMultiRecordsARealSourceAsDown joins the live clients to the existing
// Multi, which is what the scorer actually consults.
//
// The point is that a source being down is RECORDED rather than absorbed: the
// pass continues, and the names of what did not answer travel with the result.
func TestMultiRecordsARealSourceAsDown(t *testing.T) {
	good := serve(t, http.StatusOK, fixtureBytes(t, "kev.json"))
	bad := serve(t, http.StatusServiceUnavailable, nil)

	multi := feed.Multi{
		Sources: []feed.Source{
			&feed.KEVSource{URL: good.URL},
			&feed.EPSSSource{URL: bad.URL},
		},
		Clock: func() time.Time { return time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC) },
	}

	got, stats, err := multi.Lookup(context.Background(), []string{"CVE-2021-44228"})
	if err != nil {
		t.Fatalf("Multi.Lookup: %v", err)
	}
	if len(stats.SourcesDown) != 1 || stats.SourcesDown[0] != "epss" {
		t.Fatalf("SourcesDown = %v, want [epss]. A source that did not answer must be named, or "+
			"the pass reads as one where nothing was found", stats.SourcesDown)
	}

	// The source that DID answer is not lost because the other one failed.
	a := got["CVE-2021-44228"]
	if !a.KEVAvailable || !a.KEV {
		t.Errorf("the working source's answer was lost: %+v", a)
	}
	if a.EPSSAvailable {
		t.Error("the failed source contributed an answer")
	}
}

// TestMultiDropsAnUnbelievableRowFromARealSource closes the loop on
// validation: a published row that parses and cannot be believed is dropped
// and counted, never clamped into range.
func TestMultiDropsAnUnbelievableRowFromARealSource(t *testing.T) {
	// 1.7 is outside 0..1. Clamping it to 1.0 would make a corrupt row the
	// most urgent finding in the fleet.
	body := gzipOf(t, "#model_version:v1,score_date:2026-09-28T00:00:00+0000\n"+
		"cve,epss,percentile\nCVE-2021-44228,1.7,0.99\n")
	srv := serve(t, http.StatusOK, body)

	multi := feed.Multi{
		Sources: []feed.Source{&feed.EPSSSource{URL: srv.URL}},
		Clock:   func() time.Time { return time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC) },
	}

	got, stats, err := multi.Lookup(context.Background(), []string{"CVE-2021-44228"})
	if err != nil {
		t.Fatalf("Multi.Lookup: %v", err)
	}
	if stats.Malformed != 1 {
		t.Errorf("Malformed = %d, want 1", stats.Malformed)
	}
	if a, present := got["CVE-2021-44228"]; present && a.EPSSAvailable {
		t.Fatalf("a score of 1.7 reached the scorer: %+v. Clamping it to 1.0 would make a corrupt "+
			"row the most urgent finding in the fleet", a)
	}
	if stats.Unknown != 1 {
		t.Errorf("Unknown = %d, want 1: the identifier ended the pass unanswered", stats.Unknown)
	}
}

// TestALiveSourceHonoursContextCancellation keeps a feed from outliving the
// run that asked it.
func TestALiveSourceHonoursContextCancellation(t *testing.T) {
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocked
	}))
	t.Cleanup(func() { close(blocked); srv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	src := &feed.KEVSource{URL: srv.URL}
	done := make(chan error, 1)
	go func() {
		_, err := src.Lookup(ctx, []string{"CVE-2021-44228"})
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled lookup returned successfully")
		}
		var unavailable *feed.ErrUnavailable
		if !errors.As(err, &unavailable) {
			t.Errorf("a cancelled lookup is not reported as the source being unavailable: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the lookup ignored its context and is still waiting on a publisher that will " +
			"never answer")
	}
}

func gzipOf(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(body)); err != nil {
		t.Fatalf("gzipping the fixture: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the gzip writer: %v", err)
	}
	return buf.Bytes()
}
