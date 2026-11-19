package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"
)

// The schema the interface's types are GENERATED from (VM-UI-F-107,
// UI-ADR-05).
//
// Derived by reflection over the very structs the handlers return, so the
// contract cannot drift from the implementation: a field added to a DTO
// appears in the schema on the next build, and a field removed from a DTO
// disappears — which becomes a TypeScript compile error in the client rather
// than an undefined at runtime (VM-UI-NF-202).
//
// Hand-writing this document, or hand-writing the client's types, is the thing
// UI-ADR-05 forbids. Two hand-maintained definitions of one shape diverge, and
// the divergence surfaces as a blank column in the interface — which looks
// exactly like a feature nobody has used yet.

// schemaTypes are the response shapes the schema declares, in the order they
// appear in the document.
func schemaTypes() []any {
	return []any{
		Finding{}, FindingPage{}, Facets{}, FacetOption{}, Corpus{},
		Timeline{}, Transition{}, RunObservation{}, Attempt{},
		RunSummary{}, RunPage{}, Overview{}, Comparison{}, StateChange{},
		CoverageView{}, CoverageGap{}, RepoCoverageHistory{},
		RepoSummary{}, RepoDetail{}, Dependency{}, Consumer{}, AIComponents{},
		Wave{}, TrendSeries{}, TrendPoint{},
		ReportSummary{}, Health{}, Error{},
		GitHubView{}, GitHubAccount{}, DiscoveredRepo{}, ExcludedRepo{}, DiscoverySummary{},
		ScanRequestView{}, ScanRequestResult{}, ScanBatchResult{}, CSRFToken{},
		NuGuardView{}, NuGuardStatusView{}, NuGuardFleetView{}, NuGuardOverrideView{}, NuGuardAuditView{},
		NuGuardAuditPage{}, RepoNuGuardView{}, NuGuardScanOptions{}, NuGuardPreview{}, NuGuardDetail{},
		RunNuGuard{}, CoverageNotRequested{}, AISBOMRef{},
		Identity{}, Location{}, Versions{}, Classification{}, SLA{},
		Observation{}, Refs{}, Provenance{}, Triage{}, ScoreBreakdown{}, ScoreInputs{},
	}
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	doc, err := s.openAPI()
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "schema generation failed", err.Error(),
			"this is a defect: the schema is generated from the response types and cannot be "+
				"out of date, so a failure here means a type the generator cannot express")
		return
	}
	s.write(w, r, http.StatusOK, doc)
}

// openAPI assembles the document.
func (s *Server) openAPI() (map[string]any, error) {
	schemas := map[string]any{}
	for _, t := range schemaTypes() {
		rt := reflect.TypeOf(t)
		schema, err := jsonSchema(rt, schemas, 0)
		if err != nil {
			return nil, err
		}
		schemas[rt.Name()] = schema
	}

	ref := func(name string) map[string]any {
		return map[string]any{"$ref": "#/components/schemas/" + name}
	}
	jsonResponse := func(name, desc string) map[string]any {
		return map[string]any{
			"200": map[string]any{
				"description": desc,
				"content": map[string]any{
					"application/json": map[string]any{"schema": ref(name)},
				},
			},
		}
	}
	arrayResponse := func(name, desc string) map[string]any {
		return map[string]any{
			"200": map[string]any{
				"description": desc,
				"content": map[string]any{
					"application/json": map[string]any{
						"schema": map[string]any{"type": "array", "items": ref(name)},
					},
				},
			},
		}
	}

	paths := map[string]any{
		"/v1/health":                 get("health", "Liveness and what is degraded in this deployment", jsonResponse("Health", "health")),
		"/v1/findings":               get("findings", "Filtered, sorted, cursor-paginated findings", jsonResponse("FindingPage", "one page")),
		"/v1/findings/facets":        get("facets", "Per-option counts under the current filter", jsonResponse("Facets", "facet counts")),
		"/v1/findings/{fp}":          get("finding", "One finding's complete record", jsonResponse("Finding", "the finding")),
		"/v1/findings/{fp}/timeline": get("timeline", "State transitions and observation history", jsonResponse("Timeline", "the timeline")),
		"/v1/findings/{fp}/attempts": get("attempts", "Remediation attempt history", arrayResponse("Attempt", "the attempts")),
		"/v1/runs":                   get("runs", "Run history, newest first", jsonResponse("RunPage", "one page")),
		"/v1/runs/latest":            get("latestRun", "The most recent run's overview", jsonResponse("Overview", "the overview")),
		"/v1/runs/compare":           get("compareRuns", "Findings appearing, disappearing and changing between two runs", jsonResponse("Comparison", "the comparison")),
		"/v1/runs/{id}":              get("run", "A run's overview", jsonResponse("Overview", "the overview")),
		"/v1/runs/{id}/snapshot":     get("runSnapshot", "The immutable report issued for a run", jsonResponse("ReportSummary", "the snapshot")),
		"/v1/repos":                  get("repos", "Repository index", arrayResponse("RepoSummary", "the repositories")),
		"/v1/repos/{repo}":           get("repo", "Repository profile, dependencies, pull requests and consumers", jsonResponse("RepoDetail", "the repository")),
		"/v1/coverage":               get("coverage", "Coverage gaps, staleness and escalations", jsonResponse("CoverageView", "coverage")),
		"/v1/waves":                  get("waves", "First-party waves in flight", arrayResponse("Wave", "the waves")),
		"/v1/metrics/trends":         get("trends", "One metric over runs of one kind", jsonResponse("TrendSeries", "the series")),
		"/v1/reports":                get("reports", "Issued reports", arrayResponse("ReportSummary", "the reports")),
		"/v1/reports/{id}":           get("report", "One issued report, as issued", jsonResponse("ReportSummary", "the report")),
		"/v1/csrf":                   get("csrf", "A CSRF token for this caller, required in X-CSRF-Token on every write", jsonResponse("CSRFToken", "the token")),
		"/v1/scans":                  merge(get("scans", "Scan requests, newest first", arrayResponse("ScanRequestView", "the requests")), post("requestScan", "Queue a scan of one registered repository (security owners; same-origin; X-CSRF-Token; body {repo, nuguard?: {mode, tools?, include_posture?, keep_sbom?}})", jsonResponse("ScanRequestResult", "the request, or the one it merged into"))),
		"/v1/scans/all":              post("requestScanAll", "Queue a scan of every included repository as one batch (security owners; same-origin; X-CSRF-Token; no body, or {nuguard: {...}} for every repository in it)", jsonResponse("ScanBatchResult", "the batch")),
		"/v1/nuguard":                get("nuguard", "NuGuard status, the operator's ceiling, fleet settings, repository overrides and the last 20 changes (engineers and up)", jsonResponse("NuGuardView", "the AI scanning page")),
		"/v1/nuguard/settings":       put("putNuGuardSettings", "Replace the fleet's NuGuard settings within the ceiling (security owners; same-origin; X-CSRF-Token; body {enabled, tools, include_posture, timeout_s, reason?}; 422 names a field above the ceiling)", jsonResponse("NuGuardView", "the page after the change")),
		"/v1/nuguard/audit":          get("nuguardAudit", "Every NuGuard settings change, newest first (engineers and up; ?repo= to narrow, ?cursor= for the next page)", jsonResponse("NuGuardAuditPage", "one page")),
		"/v1/nuguard/preview":        get("nuguardPreview", "What a scan of ?repo= would use, with ?nuguard=&tools=&include_posture=&keep_sbom=, and any clip notes (engineers and up)", jsonResponse("NuGuardPreview", "the preview")),
		"/v1/repos/{repo}/nuguard":   merge(get("repoNuGuard", "A repository's NuGuard override, the effective options now, and the last ten scans' options (engineers and up)", jsonResponse("RepoNuGuardView", "the setting")), put("putRepoNuGuard", "Set or clear a repository's NuGuard override (security owners; same-origin; X-CSRF-Token; body {mode, tools?, include_posture?, reason?})", jsonResponse("RepoNuGuardView", "the setting after the change"))),
		"/v1/repos/{repo}/ai-sbom/{run_id}": get("repoAISBOM", "The AI-SBOM a scan kept, as NuGuard returned it (engineers and up; ?format=json; cyclonedx is 501), or 404 with the reason", map[string]any{
			"200": map[string]any{"description": "the AI-SBOM", "content": map[string]any{"application/json": map[string]any{
				"schema": map[string]any{"type": "object", "additionalProperties": true}}}},
		}),
		"/v1/github": get("github", "The connected GitHub account and every repository discovery saw, with whether it is scanned", jsonResponse("GitHubView", "the account view")),
	}

	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":   "Vulnerability framework API",
			"version": "1",
			"description": "Generated by reflection over the Go response types, so the schema " +
				"cannot drift from the implementation (VM-UI-F-107, UI-ADR-05). The client's " +
				"TypeScript types are generated from this document and are never hand-written.",
		},
		"paths":      paths,
		"components": map[string]any{"schemas": schemas},
	}, nil
}

func get(id, summary string, responses map[string]any) map[string]any {
	return map[string]any{
		"get": map[string]any{
			"operationId": id,
			"summary":     summary,
			"responses":   responses,
		},
	}
}

func post(id, summary string, responses map[string]any) map[string]any {
	return map[string]any{
		"post": map[string]any{
			"operationId": id,
			"summary":     summary,
			"responses":   responses,
		},
	}
}

func put(id, summary string, responses map[string]any) map[string]any {
	return map[string]any{
		"put": map[string]any{
			"operationId": id,
			"summary":     summary,
			"responses":   responses,
		},
	}
}

func merge(ops ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, o := range ops {
		for k, v := range o {
			out[k] = v
		}
	}
	return out
}

var timeType = reflect.TypeOf(time.Time{})

// jsonSchema renders a Go type as a JSON Schema fragment.
//
// Nullable pointers are rendered as OPTIONAL rather than as nullable unions,
// which is what the DTOs use them for: an absent EPSS means nothing answered,
// and the generated TypeScript type is then `epss?: number` — a value the
// client cannot read without acknowledging it may not be there.
func jsonSchema(t reflect.Type, schemas map[string]any, depth int) (map[string]any, error) {
	if depth > 12 {
		return nil, fmt.Errorf("api: schema nesting deeper than 12 at %s", t)
	}
	switch t {
	case timeType:
		return map[string]any{"type": "string", "format": "date-time"}, nil
	}
	switch t.Kind() {
	case reflect.Ptr:
		return jsonSchema(t.Elem(), schemas, depth+1)
	case reflect.String:
		return map[string]any{"type": "string"}, nil
	case reflect.Bool:
		return map[string]any{"type": "boolean"}, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}, nil
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}, nil
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			// A byte slice is a JSON document in these types (a stored
			// report), not a base64 string.
			return map[string]any{"type": "object", "additionalProperties": true}, nil
		}
		items, err := jsonSchema(t.Elem(), schemas, depth+1)
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "array", "items": items}, nil
	case reflect.Map:
		values, err := jsonSchema(t.Elem(), schemas, depth+1)
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "object", "additionalProperties": values}, nil
	case reflect.Interface:
		return map[string]any{}, nil
	case reflect.Struct:
		props := map[string]any{}
		var required []string
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			name, optional, skip := fieldName(f)
			if skip {
				continue
			}
			schema, err := jsonSchema(f.Type, schemas, depth+1)
			if err != nil {
				return nil, err
			}
			if f.Anonymous && f.Type.Kind() == reflect.Struct {
				// Embedded: flatten, as encoding/json does.
				if sub, ok := schema["properties"].(map[string]any); ok {
					for k, v := range sub {
						props[k] = v
					}
					continue
				}
			}
			props[name] = schema
			if !optional && f.Type.Kind() != reflect.Ptr {
				required = append(required, name)
			}
		}
		sort.Strings(required)
		out := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			out["required"] = required
		}
		return out, nil
	default:
		return nil, fmt.Errorf("api: cannot express %s in the schema", t.Kind())
	}
}

// fieldName reads the JSON name, whether it is omitted when empty, and whether
// it is skipped entirely.
func fieldName(f reflect.StructField) (name string, optional, skip bool) {
	tag := f.Tag.Get("json")
	if tag == "-" {
		return "", false, true
	}
	parts := strings.Split(tag, ",")
	name = parts[0]
	if name == "" {
		name = f.Name
	}
	for _, opt := range parts[1:] {
		if opt == "omitempty" {
			optional = true
		}
	}
	return name, optional, false
}

var _ = json.Marshal
