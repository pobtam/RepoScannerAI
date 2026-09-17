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
				Dir: "/work/repo", Stdout: body,
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
	"Classification.EPSS": {
		Producer: "not yet written by anything",
		Why: "VM-OQ-07 is open on the EPSS source. The scoring multiplier reads it and it is " +
			"always zero, which means EPSS contributes nothing to any priority today. Recorded " +
			"as a genuine gap rather than exempted away — see OQ-AUDIT-01",
	},
	"Classification.KEV": {
		Producer: "not yet written by anything",
		Why: "no KEV feed is wired. kev_boost is 3.0 in calibration and can never apply. " +
			"See OQ-AUDIT-01",
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
