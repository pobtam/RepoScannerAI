package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/api"
	"github.com/wanaware/vulnframework/internal/report"
)

// Every honesty distinction the pipeline makes has to survive to the response.
//
// The failure mode is uniform and quiet: a distinction the API flattens
// becomes a distinction the interface cannot render, and the interface then
// shows a confident number that nobody can question. These tests read the
// RESPONSE, because that is what the client sees.

func TestAnUnavailableExploitInputIsAbsentNotZero(t *testing.T) {
	h := newHarness(t)

	var page struct {
		Findings []map[string]any `json:"findings"`
	}
	h.getJSON(t, "/v1/findings?scope=all&limit=500", &page)

	// EPSS and KEV are checked SEPARATELY. They are separate publications
	// with separate outages, and a test that required both to be missing
	// before it complained would pass while one of them silently rendered an
	// absence as a measurement — each check needs its own failing mutation.
	type side struct {
		key      string
		asOf     string
		wantWord string
	}
	sides := []side{{"epss", "epss_as_of", "EPSS"}, {"kev", "kev_as_of", "KEV"}}

	seen := map[string]struct{ present, absent bool }{}
	for _, f := range page.Findings {
		c, _ := f["classification"].(map[string]any)
		if c == nil {
			t.Fatalf("a finding carries no classification: %v", f)
		}
		var notes []string
		// Absent entirely when both inputs answered, which is the normal case
		// for a finding the catalogues list.
		if raw, ok := c["exploit_intel_unavailable"].([]any); ok {
			for _, note := range raw {
				notes = append(notes, note.(string))
			}
		}

		for _, sd := range sides {
			_, present := c[sd.key]
			explained := false
			for _, note := range notes {
				if strings.Contains(note, sd.wantWord) {
					explained = true
				}
			}
			state := seen[sd.key]
			if present {
				state.present = true
				if explained {
					t.Errorf("%v: %s is present AND declared unavailable; the response contradicts "+
						"itself", f["fingerprint"], sd.key)
				}
				if c[sd.asOf] == nil {
					t.Errorf("%v: %s arrived with no snapshot date. A score whose age is unknown "+
						"cannot be judged, and during an incident the age is the point",
						f["fingerprint"], sd.key)
				}
			} else {
				state.absent = true
				if !explained {
					t.Errorf("%v: %s is absent and nothing says why. A missing key a client "+
						"renders as zero is how a feed outage becomes good news (OQ-AUDIT-01)",
						f["fingerprint"], sd.key)
				}
			}
			seen[sd.key] = state
		}
	}

	for _, sd := range sides {
		if !seen[sd.key].absent {
			t.Errorf("no finding lacked %s; the fixture cannot prove the distinction survives", sd.key)
		}
		if !seen[sd.key].present {
			t.Errorf("no finding carried %s; the fixture cannot prove a present value is rendered", sd.key)
		}
	}
}

func TestANotReobservedFindingSaysWhyThatIsAmbiguous(t *testing.T) {
	h := newHarness(t)

	var page struct {
		Findings []api.Finding `json:"findings"`
	}
	h.getJSON(t, "/v1/findings?scope=open&notReobserved=true&limit=100", &page)
	if len(page.Findings) == 0 {
		t.Fatal("no finding is marked not-re-observed; the fixture's partial scan should have " +
			"produced one")
	}
	for _, f := range page.Findings {
		if !f.Observation.NotReobserved {
			t.Errorf("%s came back from a not-re-observed filter without the marker", f.Fingerprint)
		}
		note := f.Observation.NotReobservedNote
		if note == "" {
			t.Fatalf("%s is marked not-re-observed with no explanation. The marker alone reads as "+
				"'probably fixed', which is exactly the conclusion VM-UI-F-423 forbids", f.Fingerprint)
		}
		for _, want := range []string{"AMBIGUOUS", "coverage"} {
			if !strings.Contains(note, want) {
				t.Errorf("the explanation does not mention %q: %q", want, note)
			}
		}
		if f.State == "VERIFIED" {
			t.Errorf("%s is both not-re-observed and VERIFIED; absence is not resolution "+
				"(VM-ADR-12)", f.Fingerprint)
		}
	}
}

func TestARunOverviewSaysWhetherItIsASnapshotOrLive(t *testing.T) {
	h := newHarness(t)

	// The first run HAS an issued report, so its overview is the immutable
	// record — state as of that run (VM-UI-F-102).
	var snapshot api.Overview
	h.getJSON(t, "/v1/runs/"+h.RunID, &snapshot)
	if snapshot.Live {
		t.Error("a run with an issued report renders as live; the whole point of the snapshot is " +
			"that a finding fixed since the run still shows as open when viewing that run")
	}
	if snapshot.ContentHash == "" || snapshot.SnapshotID == "" {
		t.Errorf("the snapshot carries no identity: %+v. Without the hash a circulated copy "+
			"cannot be checked", snapshot)
	}

	// The latest run has no issued report, so its figures are live and it says
	// so (VM-UI-F-424).
	var live api.Overview
	h.getJSON(t, "/v1/runs/latest", &live)
	if !live.Live {
		t.Error("a run with no issued report renders as a snapshot")
	}
	if live.LiveNote == "" {
		t.Error("live figures are presented with no statement that they are live")
	}

	// And the two do not silently disagree about the same run: the snapshot's
	// counts come from the record, the live ones from the store now.
	if snapshot.Run.ID != h.RunID {
		t.Errorf("the overview is anchored to %q, want %q", snapshot.Run.ID, h.RunID)
	}
	if snapshot.Run.StartedAt.IsZero() {
		t.Error("the run identifier is rendered without its start time; neither alone identifies " +
			"a run (VM-UI-F-207a)")
	}
}

func TestAPartialRunIsMarkedEverywhereItAppears(t *testing.T) {
	h := newHarness(t)

	var runs api.RunPage
	h.getJSON(t, "/v1/runs", &runs)
	var sawPartial bool
	for _, r := range runs.Runs {
		if r.Partial {
			sawPartial = true
			if r.PartialNote == "" {
				t.Errorf("run %s is marked partial with no explanation", r.ID)
			}
		}
	}
	if !sawPartial {
		t.Fatal("no run is marked partial, though the fixture has a silent worker and a partial " +
			"scan; a run that did not cover its fleet must be marked in every history view " +
			"(VM-UI-F-307)")
	}

	// And in the trend, where the mistake is most expensive: a dip caused by a
	// failed scan looks identical to one caused by remediation.
	var series api.TrendSeries
	h.getJSON(t, "/v1/metrics/trends?metric=open", &series)
	if series.Kind == "" {
		t.Error("the series does not say which run kind it is drawn from (VM-UI-F-310)")
	}
	var partialPoint bool
	for _, p := range series.Points {
		if p.Partial {
			partialPoint = true
		}
	}
	if !partialPoint {
		t.Error("no trend point is marked partial; a reader would attribute the whole series to " +
			"remediation")
	}
	if !strings.Contains(series.Note, "partial") {
		t.Errorf("the series carries no note about partial runs: %q", series.Note)
	}
}

func TestTheCorpusIsStatedInWordsWithWhatItExcludes(t *testing.T) {
	h := newHarness(t)

	for _, tc := range []struct {
		path     string
		wantDesc string
	}{
		{"/v1/findings?scope=open", "unresolved"},
		{"/v1/findings?scope=all", "every finding"},
		{"/v1/findings?scope=run&run=" + h.RunID, "observed in run"},
	} {
		var page api.FindingPage
		h.getJSON(t, tc.path, &page)
		if !strings.Contains(page.Corpus.Description, tc.wantDesc) {
			t.Errorf("GET %s describes its corpus as %q, want something containing %q. A count "+
				"without its corpus is a different truth, not a smaller one (VM-UI-F-417)",
				tc.path, page.Corpus.Description, tc.wantDesc)
		}
		if page.Total == 0 {
			t.Errorf("GET %s reports a total of zero", tc.path)
		}
		// Matched, in-corpus and total are separate figures (VM-UI-F-419).
		if page.InCorpus > page.Total {
			t.Errorf("GET %s says %d in corpus of %d total", tc.path, page.InCorpus, page.Total)
		}
		if page.Corpus.Scope != strings.Split(strings.TrimPrefix(tc.path, "/v1/findings?scope="), "&")[0] {
			t.Errorf("GET %s reports scope %q", tc.path, page.Corpus.Scope)
		}
	}

	// The open corpus states what it leaves out, and how many records that is
	// (VM-UI-F-418).
	var open api.FindingPage
	h.getJSON(t, "/v1/findings?scope=open", &open)
	if open.Corpus.Excludes == "" {
		t.Error("the open corpus does not say what it excludes")
	}
	if open.Corpus.ExcludedCount == 0 {
		t.Error("the open corpus excludes nothing, though the fixture verified a finding; the " +
			"excluded count is how a reader knows the corpus is narrower than the archive")
	}
}

func TestFilteringSortingAndPaginationAreServerSide(t *testing.T) {
	h := newHarness(t)

	// A filter narrows, and the count reflects the filter rather than the page.
	var all, deps api.FindingPage
	h.getJSON(t, "/v1/findings?scope=all&limit=2", &all)
	h.getJSON(t, "/v1/findings?scope=all&category=dependency&limit=2", &deps)
	if deps.Matched >= all.Matched {
		t.Errorf("filtering by category did not narrow: %d of %d", deps.Matched, all.Matched)
	}
	if len(deps.Findings) > 2 {
		t.Errorf("a limit of 2 returned %d rows; the client must not have to trim", len(deps.Findings))
	}
	for _, f := range deps.Findings {
		if f.Category != "dependency" {
			t.Errorf("a category filter returned a %s finding", f.Category)
		}
	}

	// Pagination walks every matching row exactly once.
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 20; page++ {
		var p api.FindingPage
		path := "/v1/findings?scope=all&limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		h.getJSON(t, path, &p)
		for _, f := range p.Findings {
			if seen[f.Fingerprint] {
				t.Errorf("%s was served on two pages", f.Fingerprint)
			}
			seen[f.Fingerprint] = true
		}
		if p.NextCursor == "" {
			if len(seen) != p.Matched {
				t.Errorf("walked %d rows, the query matched %d", len(seen), p.Matched)
			}
			break
		}
		cursor = p.NextCursor
	}

	// Sorting is the server's: priority descending puts the most urgent first.
	var sorted api.FindingPage
	h.getJSON(t, "/v1/findings?scope=all&sort=priority&dir=desc&limit=100", &sorted)
	last := ""
	for _, f := range sorted.Findings {
		if f.Priority == "" {
			continue
		}
		if last != "" && f.Priority < last {
			t.Errorf("priority-descending returned %s after %s", f.Priority, last)
		}
		last = f.Priority
	}

	// Facet counts are for the whole matching set and include zero options.
	var facets api.Facets
	h.getJSON(t, "/v1/findings/facets?scope=all", &facets)
	var total int
	for _, opt := range facets.Categories {
		total += opt.Count
	}
	if total != sorted.Matched {
		t.Errorf("category facets sum to %d, the query matched %d", total, sorted.Matched)
	}
	var sawDisabled bool
	for _, opt := range facets.States {
		if opt.Count == 0 && opt.Disabled {
			sawDisabled = true
		}
	}
	if !sawDisabled {
		t.Error("no filter option is present-and-disabled; an option that disappears when it has " +
			"no results looks like a dimension that does not exist (VM-UI-F-408)")
	}
	// Reachability renders with unknown BETWEEN the determinations, so the
	// tri-state reads as a tri-state.
	if len(facets.Reachable) != 3 || facets.Reachable[1].Value != "unknown" {
		t.Errorf("reachability facets are %v; unknown must render between true and false, never "+
			"as an afterthought (VM-F-243)", facets.Reachable)
	}
}

func TestTheAPIRefusesWhatItCannotAnswerHonestly(t *testing.T) {
	h := newHarness(t)

	for _, tc := range []struct {
		path   string
		status int
		want   string
	}{
		{"/v1/findings", http.StatusBadRequest, "scope is required"},
		{"/v1/findings?scope=whatever", http.StatusBadRequest, "unknown scope"},
		{"/v1/findings?scope=run", http.StatusBadRequest, "run identifier"},
		{"/v1/findings?scope=all&limit=100000", http.StatusBadRequest, "maximum"},
		{"/v1/findings?scope=all&sort=whenever", http.StatusBadRequest, "unknown sort"},
		{"/v1/findings?scope=all&reachable=maybe", http.StatusBadRequest, "tri-state"},
		{"/v1/findings?scope=all&severity=SEVERE", http.StatusBadRequest, "unknown severity"},
		{"/v1/findings?scope=all&hasPR=perhaps", http.StatusBadRequest, "must be true or false"},
		{"/v1/findings/nosuchfingerprint", http.StatusNotFound, "not found"},
		{"/v1/runs/S-999999", http.StatusNotFound, "not found"},
		{"/v1/metrics/trends?metric=vibes", http.StatusBadRequest, "unknown metric"},
	} {
		status, body := h.get(t, tc.path)
		if status != tc.status {
			t.Errorf("GET %s = %d, want %d: %s", tc.path, status, tc.status, truncate(body, 300))
			continue
		}
		if !strings.Contains(strings.ToLower(string(body)), strings.ToLower(tc.want)) {
			t.Errorf("GET %s did not explain itself (%q not in body): %s", tc.path, tc.want,
				truncate(body, 300))
		}
		// Every error says what to do about it (VM-UI-F-903).
		var e api.Error
		if err := json.Unmarshal(body, &e); err != nil {
			t.Errorf("GET %s returned a non-JSON error: %s", tc.path, truncate(body, 200))
			continue
		}
		if e.Remedy == "" {
			t.Errorf("GET %s returned an error with no remedy: %+v. An error the reader cannot "+
				"act on teaches them the system is broken", tc.path, e)
		}
	}
}

func TestACoverageGapNamesItsOwnerAndWhatWasLost(t *testing.T) {
	h := newHarness(t)

	var view api.CoverageView
	h.getJSON(t, "/v1/coverage", &view)
	if len(view.Gaps) == 0 {
		t.Fatal("no coverage gaps, though the fixture has a silent worker and a partial scan")
	}
	if view.Warning == "" || !strings.Contains(view.Warning, "indistinguishable") {
		t.Errorf("the view does not state that a failed scan and a clean scan are "+
			"indistinguishable in every aggregate: %q (VM-UI-F-757)", view.Warning)
	}

	var sawPartial, sawNever bool
	for _, g := range view.Gaps {
		if g.Classification == "partial" {
			sawPartial = true
			if len(g.ToolsOK) == 0 {
				t.Errorf("a PARTIAL gap in %s names no surviving signal; partial without saying "+
					"what remains current is unactionable (VM-F-212)", g.Repo)
			}
			if len(g.ToolsFailed) == 0 {
				t.Errorf("a partial gap in %s names no lost signal", g.Repo)
			}
		}
		if g.NeverScanned {
			sawNever = true
			if g.HoursWithoutData != 0 {
				t.Errorf("%s has never been scanned and reports %v hours without data; an age "+
					"that does not exist must not be rendered as a number", g.Repo, g.HoursWithoutData)
			}
		}
		if g.ConsecutiveRuns == 0 {
			t.Errorf("gap in %s reports zero consecutive runs without data", g.Repo)
		}
		if g.FindingsQuery == "" {
			t.Errorf("gap in %s does not link to the findings it leaves unaccounted for "+
				"(VM-UI-F-755)", g.Repo)
		}
	}
	if !sawPartial {
		t.Error("no partial gap in the view; the distinction between total and partial is what " +
			"tells a reader whether anything is still current")
	}
	if !sawNever {
		t.Error("no never-scanned repository in the view")
	}
	if len(view.History) == 0 {
		t.Error("the view carries no per-repository history, so coverage decay is invisible " +
			"without reading individual gaps (VM-UI-F-756)")
	}
}

func TestAReportIsRunAnchoredImmutableAndHashed(t *testing.T) {
	h := newHarness(t)

	var reports []api.ReportSummary
	h.getJSON(t, "/v1/reports", &reports)
	if len(reports) == 0 {
		t.Fatal("no issued reports; the fixture issues one")
	}
	rep := reports[0]
	if rep.AnchorRunID == "" {
		t.Error("an issued report is not anchored to a run; a report anchored to 'now' cannot be " +
			"reproduced (VM-ADR-15)")
	}
	if rep.ContentHash == "" {
		t.Error("an issued report carries no content hash, so a circulated copy cannot be checked")
	}
	if rep.Template == "" {
		t.Error("an issued report does not say which template produced it")
	}

	// The document comes back as issued, and its hash is the hash of what
	// comes back.
	var doc struct {
		Summary api.ReportSummary `json:"summary"`
		Report  json.RawMessage   `json:"report"`
	}
	h.getJSON(t, "/v1/reports/"+rep.ID, &doc)
	var inner struct {
		ContentHash string `json:"content_hash"`
		AnchorRun   string `json:"anchor_run"`
	}
	if err := json.Unmarshal(doc.Report, &inner); err != nil {
		t.Fatalf("the stored document does not decode: %v", err)
	}
	if inner.ContentHash != rep.ContentHash {
		t.Errorf("the document declares hash %q and the record says %q", inner.ContentHash, rep.ContentHash)
	}
	if inner.AnchorRun != rep.AnchorRunID {
		t.Errorf("the document is anchored to %q and the record says %q", inner.AnchorRun, rep.AnchorRunID)
	}

	// And a markdown rendering of the same record.
	status, md := h.get(t, "/v1/reports/"+rep.ID+"?format=markdown")
	if status != http.StatusOK {
		t.Fatalf("markdown rendering = %d: %s", status, truncate(md, 300))
	}
	if !strings.Contains(string(md), rep.AnchorRunID) {
		t.Error("the rendered report does not name the run it is anchored to")
	}
}

func TestThereIsNoLiveReportOption(t *testing.T) {
	h := newHarness(t)

	// A run overview can be live, and says so. A REPORT cannot: the listing
	// contains only issued reports, each anchored to a completed run, and
	// there is no endpoint that issues one for "now" (VM-UI-F-1111).
	var reports []api.ReportSummary
	h.getJSON(t, "/v1/reports", &reports)
	for _, rep := range reports {
		if rep.AnchorRunID == "" {
			t.Errorf("report %s has no anchor", rep.ID)
		}
	}
	for _, path := range []string{"/v1/reports/current", "/v1/reports/live", "/v1/reports/latest"} {
		status, _ := h.get(t, path)
		if status == http.StatusOK {
			t.Errorf("GET %s succeeded; there is no reproducible 'current' report and offering "+
				"one invites a citation that cannot be checked", path)
		}
	}
}

func TestAnUndeterminedPrincipalIsRefusedRatherThanTreatedAsPublic(t *testing.T) {
	h := newHarness(t)
	replaceAuthWith(t, h, undeterminedAuth{})

	status, body := h.get(t, "/v1/findings?scope=all")
	if status != http.StatusForbidden {
		t.Errorf("a caller whose privilege could not be established got %d, want 403. Defaulting "+
			"to the least-privileged view would grant it to someone who should have none, and "+
			"'we could not find out' is not 'public'", status)
	}
	if !strings.Contains(string(body), "fails closed") {
		t.Errorf("the refusal does not explain itself: %s", truncate(body, 300))
	}
}

func TestTheWaveViewKeepsDependAndReachApart(t *testing.T) {
	h := newHarness(t)

	var waves []api.Wave
	h.getJSON(t, "/v1/waves", &waves)
	if len(waves) == 0 {
		t.Fatal("no waves, though the fixture blocks a consumer on an upstream first-party fix")
	}
	w := waves[0]
	if w.Module == "" || w.OwnerRepo == "" {
		t.Errorf("a wave does not name its module and owner: %+v", w)
	}
	if w.DependCount == 0 {
		t.Error("a wave with no dependants")
	}
	if w.Trigger != "tag" {
		t.Errorf("the wave trigger is %q; the configured trigger decides whether a merge is "+
			"sufficient and must be shown (VM-UI-F-705)", w.Trigger)
	}
	var namesTag bool
	for _, step := range w.Steps {
		if strings.Contains(step, "TAG") {
			namesTag = true
		}
	}
	if !namesTag {
		t.Errorf("with trigger=tag the steps do not call out the publication step: %v. A reader "+
			"who stops at the merge will believe the wave is done", w.Steps)
	}
	for _, c := range w.Consumers {
		if c.Reachable == "" {
			t.Errorf("consumer %s has no reachability; a consumer that reaches the vulnerable "+
				"code is a different thing from one that merely depends on the module and from "+
				"one nobody has determined (VM-UI-F-707)", c.Repo)
		}
	}
}

// --- auth doubles ------------------------------------------------------------

// undeterminedAuth stands in for an identity provider that answered without a
// privilege level.
type undeterminedAuth struct{}

func (undeterminedAuth) Authenticate(_ *http.Request) (api.Principal, error) {
	return api.Principal{Recipient: report.Undetermined("someone")}, nil
}

// TestNoResponseSendsNullWhereTheInterfaceIterates is the contract behind the
// generated client types.
//
// A nil Go slice marshals to `null`. The generated TypeScript for a required
// array says `string[]`, so a null type-checks on the client and crashes when
// iterated — in the one place the generated types were supposed to make safe.
// The rule at this boundary: a collection the interface iterates is always
// present and possibly empty, and a value that may be genuinely absent is an
// ABSENT KEY rather than a null.
func TestNoResponseSendsNullWhereTheInterfaceIterates(t *testing.T) {
	h := newHarness(t)

	// The endpoints whose own DTOs the interface iterates. The report DOCUMENT
	// is excluded: it is passed through verbatim by design (VM-ADR-15 makes it
	// immutable), and its own schema does use nulls.
	for _, path := range []string{
		"/v1/health",
		"/v1/findings?scope=all&limit=10",
		"/v1/findings/facets?scope=all",
		"/v1/findings/" + h.DepFP,
		"/v1/findings/" + h.DepFP + "/timeline",
		"/v1/findings/" + h.DepFP + "/attempts",
		"/v1/runs",
		"/v1/runs/latest",
		"/v1/repos",
		"/v1/repos/org/api",
		"/v1/coverage",
		"/v1/waves",
		"/v1/metrics/trends?metric=open",
		"/v1/reports",
	} {
		var body any
		h.getJSON(t, path, &body)
		if nulls := findNulls(body, ""); len(nulls) > 0 {
			t.Errorf("GET %s sends null at %v. A nil slice marshals to null, the generated "+
				"client type says it is an array, and the interface crashes iterating it",
				path, nulls)
		}
	}
}

// findNulls walks a decoded response and reports the paths holding null.
func findNulls(v any, path string) []string {
	var out []string
	switch typed := v.(type) {
	case nil:
		return []string{path}
	case map[string]any:
		for k, inner := range typed {
			out = append(out, findNulls(inner, path+"."+k)...)
		}
	case []any:
		for i, inner := range typed {
			out = append(out, findNulls(inner, fmt.Sprintf("%s[%d]", path, i))...)
		}
	}
	return out
}
