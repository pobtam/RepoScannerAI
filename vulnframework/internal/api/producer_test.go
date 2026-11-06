package api_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/api"
	"github.com/wanaware/vulnframework/internal/audit"
)

// The Producer-Coverage Audit at the LAST layer (OQ-AUDIT-04, extended).
//
// A field the pipeline never populates renders as an always-empty column, and
// an empty column looks exactly like a feature nobody has used yet — the
// hardest place to notice the defect and the most expensive to find. The two
// earlier censuses covered the finding schema and the store schema; this one
// covers the RESPONSE, because a field can survive both of those and still be
// dropped in the rendering.
//
// Ground truth is the real pipeline behind the server (see harness_test.go).
// Nothing here constructs a response.

// responseCensus is one endpoint's audit.
type responseCensus struct {
	name string
	path func(h *harness) string
	// typ is the response shape. A page or a list is censused over its
	// ELEMENTS, because a field populated on one row and absent on another is
	// populated.
	typ    reflect.Type
	pick   func(raw []byte) ([]json.RawMessage, error)
	exempt map[audit.FieldPath]audit.Exemption
}

func pickSelf(raw []byte) ([]json.RawMessage, error) {
	return []json.RawMessage{json.RawMessage(raw)}, nil
}

func pickField(field string) func([]byte) ([]json.RawMessage, error) {
	return func(raw []byte) ([]json.RawMessage, error) {
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return nil, err
		}
		inner, ok := envelope[field]
		if !ok {
			return nil, fmt.Errorf("the response has no %q field", field)
		}
		var items []json.RawMessage
		if err := json.Unmarshal(inner, &items); err != nil {
			return []json.RawMessage{inner}, nil
		}
		return items, nil
	}
}

func pickArray(raw []byte) ([]json.RawMessage, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	return items, nil
}

// populatedFields decodes a response into its Go type and reports which leaf
// fields carry a value.
//
// Through the TYPE rather than over raw JSON keys, so a field the server never
// writes is caught even though `omitempty` removed it from the document — which
// is precisely how an always-empty column hides.
func populatedFields(t *testing.T, typ reflect.Type, docs []json.RawMessage) map[audit.FieldPath]bool {
	t.Helper()
	written := map[audit.FieldPath]bool{}
	for _, doc := range docs {
		v := reflect.New(typ)
		if err := json.Unmarshal(doc, v.Interface()); err != nil {
			t.Fatalf("decoding a %s: %v\n%s", typ.Name(), err, truncate(doc, 400))
		}
		for f := range audit.Populated(v.Elem().Interface()) {
			written[f] = true
		}
	}
	return written
}

func TestEveryResponseFieldHasAProducer(t *testing.T) {
	h := newHarness(t)

	censuses := []responseCensus{
		{
			name: "api.Finding (list row)",
			path: func(h *harness) string { return "/v1/findings?scope=all&limit=500" },
			typ:  reflect.TypeOf(api.Finding{}),
			pick: pickField("findings"),
			exempt: map[audit.FieldPath]audit.Exemption{
				"Classification.Transitive": {
					Producer: "internal/scan/adapters (govulncheck, from trace depth)",
					Why:      "a boolean whose false value is indistinguishable from unwritten",
				},
				"Provenance.ToolVersions": {
					Producer: "nothing per FINDING — versions are recorded per RUN",
					Why: "OQ-AUDIT-03: the run carries scanner_image and tool_versions, and the " +
						"finding's provenance block has a field for them that no producer fills. " +
						"An honest gap: the interface reads the run's versions instead, and " +
						"filling this in from the run would duplicate a fact that can then " +
						"disagree with itself",
				},
				"Score.ThresholdsCalibrated": {
					Producer: "internal/score.Calibration once VM-OQ-06 is answered",
					Why: "false in this deployment, which is what the caveat beside every " +
						"priority says. It becomes true when someone reviews the thresholds",
				},
				"Triage.FalsePositiveCandidate": {
					Producer: "internal/triage when the model nominates a false positive",
					Why:      "the fake triage client nominates none in this corpus",
				},
				"Restricted": {
					Producer: "internal/api.restrict, for a caller below the security owner level",
					Why:      "this census runs as a security owner, who sees every record in full",
				},
				"Location.Function": {
					Producer: "internal/scan/adapters.NuGuard, opt-in and absent from this corpus; no default tool reports the enclosing symbol",
					Why:      "OQ-AUDIT-02: displayed where a tool names it, never guessed, and never part of identity",
				},
				"Location.Package": {
					Producer: "nothing — no pinned tool reports it",
					Why:      "OQ-AUDIT-02",
				},
				"Triage.FPReasoning": {
					Producer: "internal/triage, when the model nominates a false positive",
					Why:      "the fake triage client nominates none in this corpus",
				},
				"Score.DisagreesWithStored": {
					Producer: "internal/api.scoreDTO when the calibration changed since scoring",
					Why: "true only where the stored band and the recomputed one differ, which " +
						"this run does not produce — the calibration has not moved between the " +
						"scoring pass and the request",
				},
				"Score.StoredPriority": {
					Producer: "internal/api.scoreDTO alongside DisagreesWithStored",
					Why:      "as above",
				},
				"Score.Inputs.Stale": {
					Producer: "internal/score.Scorer over a snapshot older than the freshness window",
					Why:      "the feeds in this pipeline answered within the window",
				},
				"Versions.Introduced": {
					Producer: "internal/scan/adapters/osv.firstIntroduced",
					Why:      "only the OSV adapter reports it, and this pipeline's fixtures are govulncheck-shaped",
				},
				"Refs.UpstreamFinding": {
					Producer: "internal/store.SetUpstreamFinding via the first-party wave",
					Why:      "written on the blocked consumer only",
				},
				"Classification.FirstPartyPath": {
					Producer: "internal/firstparty.Registry.Classify at normalisation",
					Why:      "written for findings in a registered module",
				},
				"Annotations": {
					Producer: "internal/scan/adapters (semgrep, trivy)",
					Why:      "carried where a tool supplies extra fields; the fixtures here do not",
				},
				"SLA.BreachDays": {
					Producer: "internal/score.SLA",
					Why:      "zero until a window is exceeded; this run is one day old",
				},
			},
		},
		{
			name: "api.RunSummary",
			path: func(h *harness) string { return "/v1/runs" },
			typ:  reflect.TypeOf(api.RunSummary{}),
			pick: pickField("runs"),
		},
		{
			name: "api.CoverageGap",
			path: func(h *harness) string { return "/v1/coverage" },
			typ:  reflect.TypeOf(api.CoverageGap{}),
			pick: pickField("gaps"),
			exempt: map[audit.FieldPath]audit.Exemption{
				"ConsecutiveDeferrals": {
					Producer: "internal/store.coverageFromHistory for a budget-deferred repository",
					Why: "counts an unbroken run of deferrals; this fixture's gaps are a silent " +
						"worker and a partial scan, and neither is a deferral",
				},
				"HoursWithoutData": {
					Producer: "internal/api.gapFor from LastQualifyingAt",
					Why:      "cannot be computed with no last qualifying scan; NeverScanned says so instead",
				},
				"Detail": {
					Producer: "internal/scan.Worker's coverage gap detail",
					Why:      "the verbatim tool output of a failure; a silent worker produces none",
				},
			},
		},
		{
			name: "api.RepoSummary",
			path: func(h *harness) string { return "/v1/repos" },
			typ:  reflect.TypeOf(api.RepoSummary{}),
			pick: pickArray,
			exempt: map[audit.FieldPath]audit.Exemption{
				"Archived": {
					Producer: "internal/orchestrator.SyncFleet",
					Why:      "set when the fleet source stops listing a repository",
				},
				"SLABreached": {
					Producer: "internal/score.SLA via orchestrator.TriageAndRoute",
					Why:      "nothing in this two-day-old pipeline has passed its window yet",
				},
				"LastCommitSHA": {
					Producer: "internal/orchestrator.DownloadDispatcher (the resolved head) and " +
						"LocalDispatcher (scan.GitHead), recorded by Orchestrator.record",
					Why: "this pipeline dispatches through the fake, which has no checkout and so " +
						"no commit; both real producers are tested in internal/orchestrator",
				},
			},
		},
		{
			name: "api.Attempt",
			path: func(h *harness) string { return "/v1/findings/" + h.DepFP + "/attempts" },
			typ:  reflect.TypeOf(api.Attempt{}),
			pick: pickArray,
			exempt: map[audit.FieldPath]audit.Exemption{
				"ClosedAt": {
					Producer: "internal/store.CloseRemediationPR",
					Why:      "the pull request is open at the end of this pipeline",
				},
				"Merged": {
					Producer: "internal/orchestrator.applyPRClosure",
					Why:      "false while open",
				},
				"TicketURL": {
					Producer: "internal/orchestrator.ensurePRTickets",
					Why:      "written by the next ticket pass, after the pull request exists",
				},
				"ConfirmedAt": {
					Producer: "internal/orchestrator.ApplyWebhook / ReconcilePullRequests",
					Why:      "written when a delivery or a query vouches for the pull request (OQ-P12-01)",
				},
			},
		},
		{
			name: "api.Timeline",
			path: func(h *harness) string { return "/v1/findings/" + h.DepFP + "/timeline" },
			typ:  reflect.TypeOf(api.Timeline{}),
			pick: pickSelf,
		},
		{
			// The elements, separately: a census over the envelope treats a
			// slice as one leaf, and every field inside it would hide behind
			// the slice being non-empty — which is where FirstPartyPath hid.
			name: "api.Transition",
			path: func(h *harness) string { return "/v1/findings/" + h.DepFP + "/timeline" },
			typ:  reflect.TypeOf(api.Transition{}),
			pick: pickField("transitions"),
			exempt: map[audit.FieldPath]audit.Exemption{
				"From": {
					Producer: "internal/model.ApplyTransition",
					Why:      "empty for the creation transition into DETECTED, which has no from-state",
				},
				"ScanOutcome": {
					Producer: "nothing — the audit row does not retain the outcome",
					Why: "the scan outcome is recorded on the RUN and on the repository's scan " +
						"result, not on the transition. The field is here because a verification " +
						"is only legal against a qualifying scan (VM-ADR-12) and a reader of the " +
						"timeline wants to see which scan authorised it — an honest gap",
				},
			},
		},
		{
			name: "api.RunObservation",
			path: func(h *harness) string { return "/v1/findings/" + h.WebFP + "/timeline" },
			typ:  reflect.TypeOf(api.RunObservation{}),
			pick: pickField("observations"),
			exempt: map[audit.FieldPath]audit.Exemption{
				"Observed": {
					Producer: "internal/api.observations from the retained observations",
					Why: "a boolean; its false value is the interesting one and IS written here " +
						"(this repository's second scan was partial), but its true value is " +
						"indistinguishable from unwritten",
				},
			},
		},
		{
			name: "api.TrendSeries",
			path: func(h *harness) string { return "/v1/metrics/trends?metric=open" },
			typ:  reflect.TypeOf(api.TrendSeries{}),
			pick: pickSelf,
		},
		{
			name: "api.TrendPoint",
			path: func(h *harness) string { return "/v1/metrics/trends?metric=open" },
			typ:  reflect.TypeOf(api.TrendPoint{}),
			pick: pickField("points"),
			exempt: map[audit.FieldPath]audit.Exemption{
				"ScannerChanged": {
					Producer: "internal/api.handleTrends comparing consecutive scanner images",
					Why: "the image did not change between these runs. A trend that could not " +
						"mark the change would attribute a step change to remediation " +
						"(VM-UI-F-306)",
				},
			},
		},
		{
			name: "api.ReportSummary",
			path: func(h *harness) string { return "/v1/reports" },
			typ:  reflect.TypeOf(api.ReportSummary{}),
			pick: pickArray,
			exempt: map[audit.FieldPath]audit.Exemption{
				"Repo": {
					Producer: "internal/report.Generator for a per-repository report",
					Why:      "empty on a fleet report by definition",
				},
				"Supersedes": {
					Producer: "nothing — supersession is modelled and not driven",
					Why:      "OQ-P7b-02: an honest writer gap, recorded rather than guessed",
				},
				"Redacted": {
					Producer: "internal/report.Redact",
					Why:      "false for an unredacted report",
				},
				"WithheldCount": {
					Producer: "internal/report.Redact",
					Why:      "zero when nothing was withheld",
				},
			},
		},
	}

	for _, c := range censuses {
		t.Run(c.name, func(t *testing.T) {
			_, raw := h.get(t, c.path(h))
			docs, err := c.pick(raw)
			if err != nil {
				t.Fatalf("selecting the census subjects: %v\n%s", err, truncate(raw, 400))
			}
			if len(docs) == 0 {
				t.Fatalf("GET %s returned nothing to audit. An endpoint with no data cannot be "+
					"audited, and an unaudited response is where the next always-empty column "+
					"will be", c.path(h))
			}

			written := populatedFields(t, c.typ, docs)
			census := audit.Census{
				Schema: audit.Fields(c.typ), Written: written, Exempt: c.exempt,
			}
			if census.Exempt == nil {
				census.Exempt = map[audit.FieldPath]audit.Exemption{}
			}
			if un := census.Unwritten(); len(un) > 0 {
				t.Errorf("%d %s field(s) that NO producer fills, over %d documents:\n\n%s",
					len(un), c.name, len(docs), census.Report())
			}
			if len(census.UnknownExemptions()) > 0 {
				t.Errorf("%s: exemptions naming fields the response no longer has:\n%s",
					c.name, census.Report())
			}
			t.Logf("%s: %d fields, %d written, %d exempt (%d documents)",
				c.name, len(census.Schema), len(written), len(census.Exempt), len(docs))
		})
	}
}

// TestTheSchemaDeclaresEveryResponseType is the other half of UI-ADR-05: the
// client's types are generated from this document, so a response shape absent
// from it is a shape the client cannot see.
func TestTheSchemaDeclaresEveryResponseType(t *testing.T) {
	h := newHarness(t)

	var doc struct {
		OpenAPI    string `json:"openapi"`
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
		Paths map[string]json.RawMessage `json:"paths"`
	}
	h.getJSON(t, "/v1/schema/openapi.json", &doc)

	if doc.OpenAPI == "" {
		t.Fatal("the document declares no OpenAPI version")
	}
	for _, want := range []string{
		"Finding", "FindingPage", "Facets", "Timeline", "Attempt", "RunSummary", "RunPage",
		"Overview", "CoverageView", "CoverageGap", "RepoSummary", "RepoDetail", "Wave",
		"TrendSeries", "ReportSummary", "Error", "Classification", "SLA", "Observation",
		"ScoreBreakdown",
	} {
		if _, ok := doc.Components.Schemas[want]; !ok {
			names := make([]string, 0, len(doc.Components.Schemas))
			for n := range doc.Components.Schemas {
				names = append(names, n)
			}
			sort.Strings(names)
			t.Errorf("the schema does not declare %s. The client's types are generated from this "+
				"document, so a shape missing here is a shape the interface cannot type. have=%v",
				want, names)
		}
	}
	for _, path := range []string{"/v1/findings", "/v1/findings/{fp}", "/v1/runs", "/v1/coverage",
		"/v1/waves", "/v1/reports", "/v1/metrics/trends"} {
		if _, ok := doc.Paths[path]; !ok {
			t.Errorf("the schema does not declare the path %s", path)
		}
	}

	// The schema is generated from the Go types, so a field on a DTO must
	// appear in it. This is the check that fails when someone hand-edits one
	// and not the other — which UI-ADR-05 exists to prevent.
	var finding struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(doc.Components.Schemas["Finding"], &finding); err != nil {
		t.Fatalf("decoding the Finding schema: %v", err)
	}
	for _, field := range []string{"fingerprint", "classification", "sla", "observation",
		"credential_type", "score", "restricted"} {
		if _, ok := finding.Properties[field]; !ok {
			t.Errorf("the generated Finding schema has no %q property", field)
		}
	}
	// And a field that must NEVER appear.
	for _, forbidden := range []string{"value", "secret", "credential_value"} {
		if _, ok := finding.Properties[forbidden]; ok {
			t.Errorf("the schema declares a %q property on Finding; the record has nowhere to "+
				"hold a credential and neither may its schema", forbidden)
		}
	}
	_ = strings.TrimSpace
}
