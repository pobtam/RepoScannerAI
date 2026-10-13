package audit_test

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/audit"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/scan/adapters"
)

// The Producer-Coverage Audit, layer one: what the ADAPTERS write.
//
// Ground truth is the captured scanner output in testdata/fixtures — real
// output from real pinned tools — put through the real adapters. Nothing here
// constructs a RawFinding, because a constructed finding is precisely what
// hid this defect three times.

const fixtures = "../../testdata/fixtures"

// realAdapterOutput runs every adapter over its captured fixtures and returns
// everything they produced.
func realAdapterOutput(t *testing.T) []model.RawFinding {
	t.Helper()

	type adapterCase struct {
		dir     string
		tool    string
		version string
		norm    func(scan.RawOutput) ([]model.RawFinding, error)
	}
	cases := []adapterCase{
		{"govulncheck", "govulncheck", "v1.8.0", adapters.NewGovulncheck(nil, "v1.8.0").Normalize},
		{"osv-scanner", "osv-scanner", "v2.6.0", adapters.NewOSVScanner(nil, "v2.6.0").Normalize},
		{"gosec", "gosec", "v2.22.9", adapters.NewGosec(nil, "v2.22.9").Normalize},
		{"staticcheck", "staticcheck", "2025.1.1", adapters.NewStaticcheck(nil, "2025.1.1").Normalize},
		{"gitleaks", "gitleaks", "v8.30.1", adapters.NewGitleaks(nil, "v8.30.1").Normalize},
		{"trivy", "trivy", "v0.67.2", adapters.NewTrivy(nil, "v0.67.2").Normalize},
		{"semgrep", "semgrep", "1.144.0", adapters.NewSemgrep(nil, "1.144.0").Normalize},
		{"npm-audit", "npm-audit", "10.9.4", adapters.NewNPMAudit(nil, "10.9.4").Normalize},
		{"actions-pin", "actions-pin", "v1", adapters.NewActionsPin(nil, "v1").Normalize},
	}

	var all []model.RawFinding
	for _, c := range cases {
		paths, err := filepath.Glob(filepath.Join(fixtures, c.dir, "*.json"))
		if err != nil {
			t.Fatalf("glob: %v", err)
		}
		var ran int
		for _, path := range paths {
			base := filepath.Base(path)
			// Skip the golden files and metadata: the inputs are what the
			// tools emitted, not what we recorded about them.
			if strings.Contains(base, ".golden.") || strings.Contains(base, ".meta.") {
				continue
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			raws, err := c.norm(scan.RawOutput{
				Tool: c.tool, ToolVersion: c.version, Repo: "org/wanaware-api",
				Dir: "/tmp/scan-7f21a/clone", Stdout: body, Aux: fixtureAux(t, c.tool, path),
			})
			if err != nil {
				// A parse failure here is itself a finding worth surfacing,
				// but it is the adapter suite's business, not the audit's.
				t.Logf("%s: %s did not parse: %v", c.tool, base, err)
				continue
			}
			ran++
			all = append(all, raws...)
		}
		if ran == 0 {
			t.Errorf("no fixtures ran for %s; the audit cannot speak for an adapter it never "+
				"executed, and a silently skipped adapter is exactly how an unwritten field survives",
				c.tool)
		}
	}
	if len(all) == 0 {
		t.Fatal("the real adapters produced no findings at all; the audit would trivially pass")
	}
	return all
}

// rawFindingExemptions are the RawFinding fields no adapter writes, each with
// the producer that does.
//
// Every entry is a CLAIM about another producer, and the claim is checkable —
// which is what separates an exemption from a dismissal. An entry whose field
// turns out to be written, or whose field no longer exists, fails the audit.
var rawFindingExemptions = map[audit.FieldPath]audit.Exemption{
	"Classification.FirstPartyPath": {
		Producer: "internal/firstparty.Registry.Classify",
		Why: "set during normalisation from ImportPath, which the adapters DO write. " +
			"This field is why the audit exists: it was read by policy rule 6 and written by " +
			"nothing for five phases",
	},
	// The four exploitation-intelligence fields are NOT an adapter's to write.
	//
	// A scanner reports what it found in a repository; whether the world is
	// exploiting that vulnerability today is a separate publication with its
	// own cadence and its own outages. They reach a FINDING through the intel
	// join (internal/store.ApplyIntel), whose producer is
	// internal/orchestrator.EnrichPass over internal/feed — and the finding
	// census proves that producer writes them.
	"Classification.EPSS": {
		Producer: "internal/orchestrator.EnrichPass via internal/feed (not an adapter)",
		Why: "exploitation intelligence is published separately from scan results and joined onto " +
			"the finding; an adapter that wrote it would be reporting something it cannot know",
	},
	"Classification.KEV": {
		Producer: "internal/orchestrator.EnrichPass via internal/feed (not an adapter)",
		Why:      "as above",
	},
	"Classification.EPSSAvailable": {
		Producer: "internal/orchestrator.EnrichPass via internal/feed (not an adapter)",
		Why:      "as above",
	},
	"Classification.KEVAvailable": {
		Producer: "internal/orchestrator.EnrichPass via internal/feed (not an adapter)",
		Why:      "as above",
	},
	"Classification.EPSSAsOf": {
		Producer: "internal/orchestrator.EnrichPass via internal/feed (not an adapter)",
		Why:      "the feed's snapshot date; a scanner has no snapshot",
	},
	"Classification.KEVAsOf": {
		Producer: "internal/orchestrator.EnrichPass via internal/feed (not an adapter)",
		Why:      "as above",
	},
	"Classification.Transitive": {
		Producer: "internal/scan/adapters (govulncheck only, from trace depth)",
		Why:      "a boolean whose false value is indistinguishable from unwritten",
	},
	// Location.Function and Location.Package.
	//
	// NOT exempted away: no code-analysis tool pinned in tools.lock emits
	// either. gosec, staticcheck and semgrep all report file, line and column
	// and nothing about the enclosing symbol — verified against the captured
	// fixtures, not assumed.
	//
	// The consequence is real and worth stating plainly: fingerprint.Location
	// PREFERS "Package#Function" for a code finding and falls back to the file
	// path, so that branch is unreachable and every code finding is
	// fingerprinted by file alone. Two occurrences of the same rule in
	// different functions of one file are therefore ONE finding. See
	// OQ-AUDIT-02.
	//
	// Deriving a function name by parsing gosec's code snippet would be a
	// guess feeding a fingerprint, which is the one place this system refuses
	// to guess.
	"Function": {
		Producer: "nothing — no pinned code-analysis tool reports it",
		Why:      "see OQ-AUDIT-02: the fingerprint's Package#Function branch is unreachable",
	},
	"Package": {
		Producer: "nothing — no pinned code-analysis tool reports it",
		Why:      "see OQ-AUDIT-02",
	},
}

// TestEveryRawFindingFieldHasAProducer is the audit.
func TestEveryRawFindingFieldHasAProducer(t *testing.T) {
	raws := realAdapterOutput(t)

	written := map[audit.FieldPath]bool{}
	for _, raw := range raws {
		for f := range audit.Populated(raw) {
			written[f] = true
		}
	}

	census := audit.Census{
		Schema:  audit.Fields(reflect.TypeOf(model.RawFinding{})),
		Written: written,
		Exempt:  rawFindingExemptions,
	}

	if un := census.Unwritten(); len(un) > 0 {
		t.Errorf("%d RawFinding field(s) are read by consumers and written by NO real adapter.\n\n"+
			"This is the defect this audit exists for: each one renders as an always-empty value "+
			"downstream and looks like a feature, and every test that constructs a finding will "+
			"pass.\n\n%s", len(un), census.Report())
	}
	if stale := census.StaleExemptions(); len(stale) > 0 {
		t.Errorf("exemptions that are no longer true — a comment asserting something false about "+
			"the system:\n%s", census.Report())
	}
	if unknown := census.UnknownExemptions(); len(unknown) > 0 {
		t.Errorf("exemptions naming fields the schema no longer has:\n%s", census.Report())
	}
	t.Logf("RawFinding: %d fields, %d written by real adapters, %d exempt",
		len(census.Schema), len(written), len(census.Exempt))
}

// TestTheAuditItselfFailsWhenAProducerStops is the audit's own guard.
//
// An audit that cannot fail is worse than none: it reports coverage nobody has.
// This mutates the producer output rather than the audit, which is the only
// way to check that the mechanism detects a stopped producer.
func TestTheAuditItselfFailsWhenAProducerStops(t *testing.T) {
	raws := realAdapterOutput(t)

	// Simulate a producer that stopped writing ImportPath — exactly the Phase
	// 11 defect, which a green suite did not notice.
	for i := range raws {
		raws[i].ImportPath = nil
	}

	written := map[audit.FieldPath]bool{}
	for _, raw := range raws {
		for f := range audit.Populated(raw) {
			written[f] = true
		}
	}
	census := audit.Census{
		Schema:  audit.Fields(reflect.TypeOf(model.RawFinding{})),
		Written: written,
		Exempt:  rawFindingExemptions,
	}

	var found bool
	for _, f := range census.Unwritten() {
		if f == "ImportPath" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the audit did not notice ImportPath going unwritten. It is the mechanism's own "+
			"failure mode: an audit that cannot fail reports coverage nobody has.\n%s", census.Report())
	}
}

// TestTheSchemaEnumerationReachesNestedFields guards the other half of the
// mechanism. A census over top-level fields only would call `Classification`
// populated the moment any one of its eight fields was, and the other seven
// would hide behind it — which is where FirstPartyPath hid.
func TestTheSchemaEnumerationReachesNestedFields(t *testing.T) {
	fields := audit.Fields(reflect.TypeOf(model.RawFinding{}))

	var names []string
	for _, f := range fields {
		names = append(names, string(f))
	}
	sort.Strings(names)
	joined := strings.Join(names, "\n")

	for _, want := range []string{
		"Classification.FirstPartyPath",
		"Classification.Reachable",
		"Classification.Severity",
		"Versions.Fixed",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the enumeration does not reach %q; a struct counted as one field hides every "+
				"unwritten field inside it", want)
		}
	}
	// And it must NOT report the containing struct as a field, or the struct
	// being non-zero would satisfy the audit for all of its contents.
	for _, mustNot := range []string{"\nClassification\n", "\nVersions\n"} {
		if strings.Contains("\n"+joined+"\n", mustNot) {
			t.Errorf("the enumeration reports %q as a leaf; its contents would hide behind it",
				strings.TrimSpace(mustNot))
		}
	}
}

// fixtureAux replays a capture's extra outputs where it recorded any: the
// gitleaks looks past a repository's allowlists, which are the only producer
// of RawFinding.Allowlisted.
func fixtureAux(t *testing.T, tool, path string) map[string][]byte {
	t.Helper()
	dir := strings.TrimSuffix(path, ".json") + ".aux"
	if tool != "gitleaks" {
		return nil
	}
	if _, err := os.Stat(dir); err != nil {
		return nil
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return b
	}
	return adapters.GitleaksFixtureAux(read("unfiltered.json"), read("config-bypass.json"),
		read("ignore-check.json"), read("gitleaks.toml"), read("gitleaksignore"))
}
