package model_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
)

// --- Gate: reachable is a tri-state string, never a boolean (VM-F-243) -----

// TestReachableRejectsJSONBooleans is the boundary enforcement of the
// tri-state. A producer that regresses to `"reachable": true` must fail loudly
// here rather than silently collapsing unknown into one of the known values —
// treating unknown as reachable lets transitive advisories dominate the P0
// queue, and treating it as unreachable hides real risk.
func TestReachableRejectsJSONBooleans(t *testing.T) {
	for _, literal := range []string{"true", "false"} {
		var r model.Reachable
		err := json.Unmarshal([]byte(literal), &r)
		if err == nil {
			t.Fatalf("reachable accepted the JSON boolean %s; VM-F-243 requires a tri-state string", literal)
		}
		var rb *model.ErrReachableBoolean
		if !errors.As(err, &rb) {
			t.Fatalf("got %T (%v), want *ErrReachableBoolean", err, err)
		}
	}
}

func TestReachableAcceptsTheThreeStrings(t *testing.T) {
	for _, want := range model.AllReachable {
		var r model.Reachable
		if err := json.Unmarshal([]byte(`"`+string(want)+`"`), &r); err != nil {
			t.Fatalf("reachable rejected %q: %v", want, err)
		}
		if r != want {
			t.Errorf("reachable = %q, want %q", r, want)
		}
	}
}

func TestReachableRejectsOtherValues(t *testing.T) {
	for _, bad := range []string{`"yes"`, `"TRUE"`, `""`, `1`, `null`, `["true"]`} {
		var r model.Reachable
		if err := json.Unmarshal([]byte(bad), &r); err == nil {
			t.Errorf("reachable accepted %s; the enumeration is closed", bad)
		}
	}
}

// TestReachableInsideAFindingRejectsBoolean proves the guard survives being
// nested in the real record, which is how it will actually be exercised.
func TestReachableInsideAFindingRejectsBoolean(t *testing.T) {
	payload := `{"schema_version":"findings.v1","fingerprint":"a3f9c21e8b7d4056",
	  "repo":"org/wanaware-api","category":"dependency",
	  "classification":{"severity":"HIGH","reachable":true}}`
	var f model.Finding
	if err := json.Unmarshal([]byte(payload), &f); err == nil {
		t.Fatal("a finding carrying a boolean reachable was accepted (VM-F-243)")
	}
}

func TestReachableStructFieldIsNotABool(t *testing.T) {
	ft, ok := reflect.TypeOf(model.Classification{}).FieldByName("Reachable")
	if !ok {
		t.Fatal("Classification has no Reachable field")
	}
	if ft.Type.Kind() == reflect.Bool {
		t.Error("Classification.Reachable is a bool; VM-F-243 requires the tri-state string")
	}
}

// --- Gate: no secret value is representable (VM-F-263, VM-F-264) -----------

// TestNoSecretValueFieldExists walks the entire Finding and RawFinding type
// graphs looking for anywhere a credential could be stored. Making the value
// unrepresentable is a stronger guarantee than a redaction step, which can be
// forgotten on a new code path.
func TestNoSecretValueFieldExists(t *testing.T) {
	// Field names that would carry, or could be used to carry, a credential.
	banned := []string{"value", "secret", "credential", "match", "plaintext", "token"}
	// Allowed because they name a class or a count, never a value.
	allowed := map[string]bool{
		"credentialtype": true,
		"tokenversions":  true,
	}

	var walk func(t *testing.T, typ reflect.Type, path string, depth int)
	walk = func(t *testing.T, typ reflect.Type, path string, depth int) {
		if depth > 8 {
			return
		}
		for typ.Kind() == reflect.Ptr || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			lower := strings.ToLower(f.Name)
			if !allowed[lower] {
				for _, b := range banned {
					if strings.Contains(lower, b) {
						t.Errorf("%s.%s: field name suggests it can carry a secret value (VM-F-263)", path, f.Name)
					}
				}
			}
			walk(t, f.Type, path+"."+f.Name, depth+1)
		}
	}

	walk(t, reflect.TypeOf(model.Finding{}), "Finding", 0)
	walk(t, reflect.TypeOf(model.RawFinding{}), "RawFinding", 0)
}

// TestSecretFindingMarshalsWithoutAValue checks the wire form of a fully
// populated secret finding: path, line and credential type, nothing more.
func TestSecretFindingMarshalsWithoutAValue(t *testing.T) {
	file, line := "config/settings.yaml", 17
	f := model.Finding{
		SchemaVersion:  model.SchemaVersion,
		Fingerprint:    "6c5bb9c18e0d1a6b",
		Repo:           "org/wanaware-api",
		Category:       model.CategorySecret,
		Identity:       model.Identity{PrimaryID: "aws-access-token"},
		Location:       model.Location{File: &file, Line: &line},
		Classification: model.Classification{Severity: model.SeverityCritical, Reachable: model.ReachableUnknown},
		State:          model.NeedsHuman,
		Priority:       model.P0,
		CredentialType: "aws_access_key_id",
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("a well-formed secret finding was rejected: %v", err)
	}

	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := strings.ToLower(string(b))
	// The record must name the credential class and its location, never a value.
	for _, banned := range []string{`"value"`, `"secret_value"`, `"match"`, `"plaintext"`} {
		if strings.Contains(out, banned) {
			t.Errorf("secret finding serialised a %s key: %s", banned, b)
		}
	}
	if !strings.Contains(out, "credential_type") {
		t.Error("secret finding did not record the credential type")
	}
}

// TestUnknownJSONKeysAreDroppedNotCarried proves a value field injected by a
// misbehaving producer cannot ride along inside the record: encoding/json
// discards unknown keys, and the struct offers nowhere to put one.
func TestUnknownJSONKeysAreDroppedNotCarried(t *testing.T) {
	payload := `{"schema_version":"findings.v1","fingerprint":"fp","repo":"r",
	  "category":"secret","value":"REDACTED-AWS-EXAMPLE-KEY-ID",
	  "classification":{"severity":"HIGH","reachable":"unknown"},"state":"NEEDS_HUMAN"}`
	var f model.Finding
	if err := json.Unmarshal([]byte(payload), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "REDACTED-AWS-EXAMPLE-KEY-ID") {
		t.Fatalf("an injected secret value survived a round trip: %s", b)
	}
}

// --- Schema version (VM-F-107) ---------------------------------------------

func TestSchemaVersionGate(t *testing.T) {
	if !model.SchemaSupported(model.SchemaVersion) {
		t.Fatalf("the current schema version %q is not supported", model.SchemaVersion)
	}
	for _, bad := range []string{"", "findings.v0", "findings.v2", "v1", "FINDINGS.V1"} {
		if model.SchemaSupported(bad) {
			t.Errorf("schema version %q should not be supported", bad)
		}
		err := model.ValidateSchemaVersion(bad)
		if err == nil {
			t.Errorf("ValidateSchemaVersion(%q) accepted an unsupported version", bad)
			continue
		}
		var use *model.ErrUnsupportedSchema
		if !errors.As(err, &use) {
			t.Errorf("ValidateSchemaVersion(%q): got %T, want *ErrUnsupportedSchema", bad, err)
		}
	}
}

// --- Categories (VM-F-108) --------------------------------------------------

func TestCategoriesAreExactlyTheFour(t *testing.T) {
	want := []model.Category{"dependency", "code", "secret", "config"}
	if len(model.AllCategories) != len(want) {
		t.Fatalf("AllCategories = %v, want exactly %v (VM-F-108)", model.AllCategories, want)
	}
	for i, c := range want {
		if model.AllCategories[i] != c {
			t.Errorf("AllCategories[%d] = %q, want %q", i, model.AllCategories[i], c)
		}
	}
	for _, bad := range []model.Category{"", "Dependency", "license", "sast"} {
		if bad.Valid() {
			t.Errorf("category %q should not be valid", bad)
		}
	}
}

// --- Reason codes (VM-F-157) ------------------------------------------------

func TestReasonCodeEnumerationIsClosed(t *testing.T) {
	// Transcribed from the normative list in VM-FR §5.3.
	want := []string{
		"NO_UPSTREAM_FIX", "BLOCKED_UPSTREAM_FIRST_PARTY", "MAJOR_BUMP_POLICY",
		"BUILD_FAILED", "TESTS_FAILED", "FIX_INEFFECTIVE", "NO_TEST_COVERAGE", "NEEDS_HUMAN_SECRET",
		"SUPPRESSION_PROPOSED", "DECLINED", "AGENT_GAVE_UP", "BUDGET_EXHAUSTED",
		"POLICY_ISSUE_ONLY",
	}
	if len(model.AllReasonCodes) != len(want) {
		t.Fatalf("got %d reason codes, want %d", len(model.AllReasonCodes), len(want))
	}
	for i, w := range want {
		if string(model.AllReasonCodes[i]) != w {
			t.Errorf("AllReasonCodes[%d] = %q, want %q", i, model.AllReasonCodes[i], w)
		}
	}
	if model.ReasonCode("").Valid() || model.ReasonCode("MADE_UP").Valid() {
		t.Error("the reason code enumeration is not closed")
	}
}

// TestFixIneffectiveDoesNotPauseTheSLA is why FIX_INEFFECTIVE exists as its own
// code rather than reusing NO_UPSTREAM_FIX.
//
// A finding whose bump built and tested but did not close the defect is fully
// actionable — most often the proxy has not mirrored the fully-closing version
// yet, and a human can act today. Reusing NO_UPSTREAM_FIX would pause its SLA
// clock (VM-NF-304), presenting a delay somebody owns as one nobody could have
// prevented.
func TestFixIneffectiveDoesNotPauseTheSLA(t *testing.T) {
	if model.ReasonFixIneffective.PausesSLA() {
		t.Error("FIX_INEFFECTIVE pauses the SLA clock; it must not — the finding is actionable, and " +
			"pausing the clock would be a false assurance that the delay is nobody's fault")
	}
	if !model.ReasonFixIneffective.Valid() {
		t.Error("FIX_INEFFECTIVE is not a member of the enumeration")
	}
}

// TestOnlyNoUpstreamFixPausesSLA covers VM-NF-304 and VM-F-909: a paused
// finding can never register as breached, and exactly one reason code pauses.
func TestOnlyNoUpstreamFixPausesSLA(t *testing.T) {
	for _, r := range model.AllReasonCodes {
		want := r == model.ReasonNoUpstreamFix
		if got := r.PausesSLA(); got != want {
			t.Errorf("%s.PausesSLA() = %v, want %v (VM-NF-304)", r, got, want)
		}
	}
}

// --- Severity and priority --------------------------------------------------

func TestSeverityAndPriorityEnumerations(t *testing.T) {
	for _, s := range model.AllSeverities {
		if !s.Valid() {
			t.Errorf("severity %q should be valid", s)
		}
	}
	for _, bad := range []model.Severity{"", "high", "SEVERE", "INFO"} {
		if bad.Valid() {
			t.Errorf("severity %q should not be valid", bad)
		}
	}
	if model.SeverityCritical.Rank() >= model.SeverityHigh.Rank() {
		t.Error("CRITICAL must rank above HIGH")
	}
	// Unknown is an absence, not a severity floor: it must sort after LOW
	// rather than among the known bands.
	if model.SeverityUnknown.Rank() <= model.SeverityLow.Rank() {
		t.Error("UNKNOWN must sort after LOW; it is an absence, not a band")
	}

	for _, p := range model.AllPriorities {
		if !p.Valid() {
			t.Errorf("priority %q should be valid", p)
		}
	}
	if model.P0.Rank() >= model.P3.Rank() {
		t.Error("P0 must rank above P3")
	}
	if model.Priority("P4").Valid() || model.Priority("").Valid() {
		t.Error("the priority enumeration is not closed")
	}
}

// --- Finding validation -----------------------------------------------------

func validFinding() model.Finding {
	return model.Finding{
		SchemaVersion: model.SchemaVersion,
		Fingerprint:   "d3fc3d1d38a3c94c",
		Repo:          "org/wanaware-api",
		Category:      model.CategoryDependency,
		Identity:      model.Identity{PrimaryID: "GO-2025-3106", Aliases: []string{"CVE-2025-22869"}},
		Classification: model.Classification{
			Severity: model.SeverityHigh, CVSS: 7.5, Reachable: model.ReachableTrue,
			DepClass: model.DepProduction, Transitive: true,
		},
		State:    model.PROpen,
		Priority: model.P1,
	}
}

func TestFindingValidate(t *testing.T) {
	ok := validFinding()
	if err := ok.Validate(); err != nil {
		t.Fatalf("a well-formed finding was rejected: %v", err)
	}

	tests := []struct {
		name string
		mut  func(*model.Finding)
	}{
		{"unsupported schema", func(f *model.Finding) { f.SchemaVersion = "findings.v2" }},
		{"empty fingerprint", func(f *model.Finding) { f.Fingerprint = "" }},
		{"empty repo", func(f *model.Finding) { f.Repo = "" }},
		{"invalid category", func(f *model.Finding) { f.Category = "license" }},
		{"invalid state", func(f *model.Finding) { f.State = "MADE_UP" }},
		{"invalid reachable", func(f *model.Finding) { f.Classification.Reachable = "yes" }},
		{"empty reachable", func(f *model.Finding) { f.Classification.Reachable = "" }},
		{"invalid severity", func(f *model.Finding) { f.Classification.Severity = "SEVERE" }},
		{"invalid priority", func(f *model.Finding) { f.Priority = "P9" }},
		{"invalid reason code", func(f *model.Finding) {
			r := model.ReasonCode("MADE_UP")
			f.ReasonCode = &r
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := validFinding()
			tc.mut(&f)
			if err := f.Validate(); err == nil {
				t.Error("Validate accepted an invalid finding")
			}
		})
	}
}

// TestFindingRoundTripsThroughJSON checks the record survives the wire in the
// shape VM-AD §4.1 specifies.
func TestFindingRoundTripsThroughJSON(t *testing.T) {
	want := validFinding()
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got model.Finding
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("round trip changed the record:\n want %+v\n got  %+v", want, got)
	}

	// Spot-check the wire names against the specification's example document.
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	for _, key := range []string{
		"schema_version", "fingerprint", "repo", "category", "identity",
		"location", "versions", "classification", "provenance", "triage",
		"state", "reason_code", "derived", "refs",
	} {
		if _, ok := raw[key]; !ok {
			t.Errorf("wire form is missing the %q key required by VM-AD §4.1", key)
		}
	}
}

// TestLineIsDisplayOnlyInTheRecord documents that the model carries a line
// number for human display while the fingerprint never consumes it (VM-F-102).
// The fingerprint half of this property is proved in the fingerprint package.
func TestLineIsDisplayOnlyInTheRecord(t *testing.T) {
	line := 42
	f := validFinding()
	f.Location.Line = &line
	if err := f.Validate(); err != nil {
		t.Fatalf("a finding carrying a line number was rejected: %v", err)
	}
}
