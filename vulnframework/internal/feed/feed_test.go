package feed_test

import (
	"context"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/feed"
)

// OQ-AUDIT-01(b) — the two inputs that most often change what a human does.
//
// The Producer-Coverage Audit found that the scorer declared five inputs and
// two of them were written by nothing. These tests are about the *shape* of
// the answer rather than the plumbing: every one of them exists because the
// obvious implementation collapses a distinction the framework depends on.

var now = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

func TestAnIdentifierInNeitherCatalogueIsAbsentNotZero(t *testing.T) {
	ctx := context.Background()
	kev := feed.NewFakeKEV().WithKEV("CVE-2025-0001", now.Add(-24*time.Hour))
	epss := feed.NewFakeEPSS().WithEPSS("CVE-2025-0001", 0.92, now.Add(-12*time.Hour))
	m := feed.Multi{Sources: []feed.Source{kev, epss}, Clock: func() time.Time { return now }}

	got, stats, err := m.Lookup(ctx, []string{"CVE-2025-0001", "CVE-2025-9999"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if a, ok := got["CVE-2025-9999"]; ok && a.Known() {
		t.Errorf("an identifier in neither catalogue came back as an answer: %+v. A zero-valued "+
			"entry reads as 'measured, harmless', which is how a feed's silence becomes good news", a)
	}
	if stats.Unknown != 1 || stats.Answered != 1 {
		t.Errorf("answered=%d unknown=%d, want 1 and 1", stats.Answered, stats.Unknown)
	}

	// And the known one carries BOTH answers and both dates.
	a := got["CVE-2025-0001"]
	if !a.KEVAvailable || !a.KEV {
		t.Errorf("the KEV answer was lost: %+v", a)
	}
	if !a.EPSSAvailable || a.EPSS != 0.92 {
		t.Errorf("the EPSS answer was lost: %+v", a)
	}
	if a.KEVAsOf.IsZero() || a.EPSSAsOf.IsZero() {
		t.Errorf("an answer arrived with no snapshot date: %+v", a)
	}
}

// TestCheckedAndNotListedIsAnAnswer is the distinction one level in. "Not in
// the KEV catalogue" is a measurement; "the catalogue did not answer" is not.
func TestCheckedAndNotListedIsAnAnswer(t *testing.T) {
	ctx := context.Background()
	kev := feed.NewFakeKEV().WithNotKEV("CVE-2025-0002", now.Add(-time.Hour))
	m := feed.Multi{Sources: []feed.Source{kev}, Clock: func() time.Time { return now }}

	got, stats, err := m.Lookup(ctx, []string{"CVE-2025-0002"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	a := got["CVE-2025-0002"]
	if !a.KEVAvailable {
		t.Fatal("a catalogue that answered 'not listed' is recorded as not having answered; the " +
			"score would then carry an unavailability caveat it has not earned")
	}
	if a.KEV {
		t.Error("'not listed' came back as listed")
	}
	if stats.Answered != 1 {
		t.Errorf("answered=%d, want 1: not-listed is an answer", stats.Answered)
	}
}

func TestASourceThatCannotAnswerIsNotASourceThatFoundNothing(t *testing.T) {
	ctx := context.Background()
	kev := feed.NewFakeKEV().WithKEV("CVE-2025-0003", now.Add(-time.Hour))
	epss := feed.NewFakeEPSS().Down("dial tcp: i/o timeout")
	m := feed.Multi{Sources: []feed.Source{kev, epss}, Clock: func() time.Time { return now }}

	got, stats, err := m.Lookup(ctx, []string{"CVE-2025-0003"})
	if err != nil {
		t.Fatalf("one source being down must not fail the pass: %v", err)
	}
	if len(stats.SourcesDown) != 1 || stats.SourcesDown[0] != "epss" {
		t.Errorf("sources_down = %v, want [epss]; a pass that scored without a feed and did not "+
			"say so leaves every priority in it quietly narrower", stats.SourcesDown)
	}
	a := got["CVE-2025-0003"]
	if !a.KEVAvailable {
		t.Error("the source that WAS up lost its answer because another was down")
	}
	if a.EPSSAvailable {
		t.Error("a source that could not answer produced an EPSS answer")
	}
}

func TestRowsThatCannotBeBelievedAreDroppedNotRepaired(t *testing.T) {
	ctx := context.Background()
	epss := feed.NewFakeEPSS().
		WithEPSS("CVE-2025-0010", 0.5, now.Add(-24*time.Hour)).
		// Out of range: 1.7 is not a probability. Clamping it to 1.0 would
		// turn a corrupt row into the most urgent finding in the fleet.
		WithMalformedRow("CVE-2025-0011", feed.Assessment{
			EPSS: 1.7, EPSSAvailable: true, EPSSAsOf: now.Add(-24 * time.Hour),
		}).
		// No snapshot date: a score whose age is unknown cannot be qualified.
		WithMalformedRow("CVE-2025-0012", feed.Assessment{EPSS: 0.3, EPSSAvailable: true}).
		// Dated in the future: whatever produced this row, it was not the
		// process this system believes it was.
		WithMalformedRow("CVE-2025-0013", feed.Assessment{
			EPSS: 0.3, EPSSAvailable: true, EPSSAsOf: now.Add(72 * time.Hour),
		})
	m := feed.Multi{Sources: []feed.Source{epss}, Clock: func() time.Time { return now }}

	ids := []string{"CVE-2025-0010", "CVE-2025-0011", "CVE-2025-0012", "CVE-2025-0013"}
	got, stats, err := m.Lookup(ctx, ids)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if stats.Malformed != 3 {
		t.Errorf("malformed=%d, want 3", stats.Malformed)
	}
	for _, bad := range ids[1:] {
		if a, ok := got[bad]; ok && a.Known() {
			t.Errorf("%s was believed: %+v", bad, a)
		}
	}
	if a := got["CVE-2025-0010"]; !a.EPSSAvailable || a.EPSS != 0.5 {
		t.Errorf("the believable row was lost alongside the bad ones: %+v", a)
	}
	if stats.Answered != 1 || stats.Unknown != 3 {
		t.Errorf("answered=%d unknown=%d, want 1 and 3: a dropped row leaves the identifier "+
			"UNKNOWN, which is the truth — it is not 'checked and negligible'", stats.Answered, stats.Unknown)
	}
}

// TestTheFresherSnapshotWinsRatherThanTheScarierOne is why Merge compares
// dates. Preferring the higher score would let a feed's stale row outlive its
// own correction: a vulnerability downgraded yesterday would keep the number it
// had last week, for ever.
func TestTheFresherSnapshotWinsRatherThanTheScarierOne(t *testing.T) {
	ctx := context.Background()
	old := feed.NewFake("mirror-a").WithEPSS("CVE-2025-0020", 0.97, now.Add(-30*24*time.Hour))
	fresh := feed.NewFake("mirror-b").WithEPSS("CVE-2025-0020", 0.04, now.Add(-24*time.Hour))
	m := feed.Multi{Sources: []feed.Source{old, fresh}, Clock: func() time.Time { return now }}

	got, _, err := m.Lookup(ctx, []string{"CVE-2025-0020"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if a := got["CVE-2025-0020"]; a.EPSS != 0.04 {
		t.Errorf("epss = %.4f, want 0.04 — the fresher snapshot. Taking the higher score means a "+
			"corrected downgrade never lands", a.EPSS)
	}

	// And in the other source order, so the result does not depend on which
	// mirror happens to be listed first.
	m2 := feed.Multi{Sources: []feed.Source{fresh, old}, Clock: func() time.Time { return now }}
	got2, _, err := m2.Lookup(ctx, []string{"CVE-2025-0020"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got2["CVE-2025-0020"].EPSS != 0.04 {
		t.Errorf("the answer depends on source order: %+v", got2["CVE-2025-0020"])
	}
}

// TestOneSourceDoesNotEraseAnothersField is the per-field half of Merge. KEV
// and EPSS are separate publications; a KEV source answering must not blank an
// EPSS score, and a finding can be known-exploited with no EPSS at all — the
// most urgent combination there is.
func TestOneSourceDoesNotEraseAnothersField(t *testing.T) {
	ctx := context.Background()
	kev := feed.NewFakeKEV().WithKEV("CVE-2025-0030", now.Add(-time.Hour))
	epss := feed.NewFakeEPSS() // publishes nothing for this identifier
	m := feed.Multi{Sources: []feed.Source{kev, epss}, Clock: func() time.Time { return now }}

	got, _, err := m.Lookup(ctx, []string{"CVE-2025-0030"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	a := got["CVE-2025-0030"]
	if !a.KEV || !a.KEVAvailable {
		t.Errorf("the KEV answer was erased by a source that had nothing to say: %+v", a)
	}
	if a.EPSSAvailable {
		t.Errorf("an EPSS answer was invented: %+v", a)
	}
}

// TestTheFeedsAreCVEKeyedAndSayNothingAboutGoIdentifiers records the fact that
// makes alias resolution mandatory rather than an optimisation.
func TestTheFeedsAreCVEKeyedAndSayNothingAboutGoIdentifiers(t *testing.T) {
	ctx := context.Background()
	kev := feed.NewFakeKEV().WithKEV("CVE-2023-48795", now.Add(-time.Hour))
	m := feed.Multi{Sources: []feed.Source{kev}, Clock: func() time.Time { return now }}

	// Asking with the Go identifier alone, as a caller that did not resolve
	// aliases would.
	got, stats, err := m.Lookup(ctx, []string{"GO-2023-2402"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 0 || stats.Answered != 0 {
		t.Errorf("a CVE-keyed catalogue answered to a GO- identifier: %+v. If the fake is kinder "+
			"than the real feed, every test of alias resolution passes for the wrong reason", got)
	}

	// With the alias included, the same vulnerability is found.
	got, stats, err = m.Lookup(ctx, []string{"GO-2023-2402", "CVE-2023-48795"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !got["CVE-2023-48795"].KEV || stats.Answered != 1 {
		t.Errorf("the alias lookup found nothing: %+v", got)
	}
}

func TestATruncatedPageIsNotAnAnswerForTheRest(t *testing.T) {
	ctx := context.Background()
	epss := feed.NewFakeEPSS().
		WithEPSS("CVE-2025-0040", 0.1, now.Add(-24*time.Hour)).
		WithEPSS("CVE-2025-0041", 0.2, now.Add(-24*time.Hour)).
		WithEPSS("CVE-2025-0042", 0.3, now.Add(-24*time.Hour)).
		TruncateAfter(1)
	m := feed.Multi{Sources: []feed.Source{epss}, Clock: func() time.Time { return now }}

	got, stats, err := m.Lookup(ctx, []string{"CVE-2025-0040", "CVE-2025-0041", "CVE-2025-0042"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("a silently truncated page produced %d answers", len(got))
	}
	if stats.Unknown != 2 {
		t.Errorf("unknown=%d, want 2: the identifiers the page never reached are UNKNOWN, and a "+
			"caller that filled them with zeroes would score two real advisories as negligible",
			stats.Unknown)
	}
}

func TestARateLimitedSourceDegradesRatherThanFailingThePass(t *testing.T) {
	ctx := context.Background()
	epss := feed.NewFakeEPSS().
		WithEPSS("CVE-2025-0050", 0.6, now.Add(-24*time.Hour)).
		FailAfter(1)
	m := feed.Multi{Sources: []feed.Source{epss}, Clock: func() time.Time { return now }}

	if _, stats, err := m.Lookup(ctx, []string{"CVE-2025-0050"}); err != nil || stats.Answered != 1 {
		t.Fatalf("first lookup: err=%v answered=%d", err, stats.Answered)
	}
	_, stats, err := m.Lookup(ctx, []string{"CVE-2025-0050"})
	if err != nil {
		t.Fatalf("a rate-limited source must degrade the pass, not fail it: %v", err)
	}
	if len(stats.SourcesDown) != 1 {
		t.Errorf("the rate limit was absorbed silently: %+v", stats)
	}
	if stats.Answered != 0 || stats.Unknown != 1 {
		t.Errorf("answered=%d unknown=%d: a rate-limited lookup knows nothing, and must not "+
			"report the identifier as checked", stats.Answered, stats.Unknown)
	}
}

func TestABatchTooLargeIsRefusedByTheSourceNotSilentlyTruncated(t *testing.T) {
	ctx := context.Background()
	epss := feed.NewFakeEPSS().WithEPSS("CVE-2025-0060", 0.5, now.Add(-24*time.Hour)).MaxBatch(2)
	m := feed.Multi{Sources: []feed.Source{epss}, Clock: func() time.Time { return now }}

	_, stats, err := m.Lookup(ctx, []string{"a", "b", "c", "CVE-2025-0060"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(stats.SourcesDown) != 1 {
		t.Errorf("an over-large batch was not reported as a failed source: %+v", stats)
	}
	if stats.Answered != 0 {
		t.Errorf("answered=%d after a refused batch", stats.Answered)
	}
}

// TestTheSourceIsAskedOnceForTheWholeBatch records the batching contract. Both
// real feeds are whole-file publications; a request per finding is how a rate
// limit is discovered in production rather than in a test.
func TestTheSourceIsAskedOnceForTheWholeBatch(t *testing.T) {
	ctx := context.Background()
	epss := feed.NewFakeEPSS()
	for _, id := range []string{"CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"} {
		epss.WithEPSS(id, 0.1, now.Add(-24*time.Hour))
	}
	m := feed.Multi{Sources: []feed.Source{epss}, Clock: func() time.Time { return now }}

	if _, _, err := m.Lookup(ctx, []string{"CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"}); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got := epss.Lookups(); got != 1 {
		t.Errorf("the source was queried %d times for five identifiers, want 1", got)
	}
}

// TestARowThatAnswersNothingIsNotAnAnswer is the case a real endpoint produces
// constantly: the identifier is echoed back with no score attached.
func TestARowThatAnswersNothingIsNotAnAnswer(t *testing.T) {
	ctx := context.Background()
	epss := feed.NewFakeEPSS().
		WithEmptyAnswer("CVE-2025-0070").
		WithEPSS("CVE-2025-0071", 0.3, now.Add(-24*time.Hour))
	m := feed.Multi{Sources: []feed.Source{epss}, Clock: func() time.Time { return now }}

	got, stats, err := m.Lookup(ctx, []string{"CVE-2025-0070", "CVE-2025-0071"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got["CVE-2025-0070"].Known() {
		t.Errorf("an echoed identifier with no score counted as an answer: %+v", got["CVE-2025-0070"])
	}
	if stats.Answered != 1 || stats.Unknown != 1 {
		t.Errorf("answered=%d unknown=%d, want 1 and 1", stats.Answered, stats.Unknown)
	}
}
