package adapters_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
)

// Two kinds of fixture drift, deliberately not treated alike (Phase 3 gate).
//
//   A golden VALUE diff — the tool reported different findings — is expected
//   when the scanner image is rebuilt, and is accepted with -update.
//
//   A PARSE failure or a newly-seen field or shape is a gap in the adapter: it
//   means the normaliser did not know about part of the tool's real output.
//   Accepting that silently is how an adapter comes to return zero findings
//   against a real scan, which is indistinguishable from a clean repository.
//   These fail loudly, are never fixed by -update, and require a test covering
//   the new shape before the recorded shape is re-blessed with -update-shapes.

// --- Fixture metadata -------------------------------------------------------

type fixtureMeta struct {
	Tool         string `json:"tool"`
	ToolVersion  string `json:"tool_version"`
	Image        string `json:"image"`
	CapturedFrom string `json:"captured_from"`
}

func readMeta(t *testing.T, tool, name string) fixtureMeta {
	t.Helper()
	path := filepath.Join(fixtureDir, tool, name+".meta.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fixture %s/%s has no .meta.json: %v\n"+
			"Every fixture must record the tool version that produced it; re-run testdata/capture.sh", tool, name, err)
	}
	var m fixtureMeta
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return m
}

// TestEveryFixtureRecordsItsProducingVersion covers the Phase 3 constraint that
// a golden can never be read without knowing which tool build produced it.
func TestEveryFixtureRecordsItsProducingVersion(t *testing.T) {
	lock := testLock(t)

	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatalf("reading fixtures: %v", err)
	}
	for _, dir := range entries {
		if !dir.IsDir() {
			continue
		}
		tool := dir.Name()
		files, err := os.ReadDir(filepath.Join(fixtureDir, tool))
		if err != nil {
			t.Fatalf("reading %s: %v", tool, err)
		}
		for _, f := range files {
			n := f.Name()
			if !strings.HasSuffix(n, ".json") ||
				strings.HasSuffix(n, ".golden.json") ||
				strings.HasSuffix(n, ".meta.json") ||
				n == "package.json" {
				continue
			}
			name := strings.TrimSuffix(n, ".json")
			meta := readMeta(t, tool, name)

			if meta.ToolVersion == "" {
				t.Errorf("%s/%s: meta records no tool_version", tool, name)
			}
			if meta.Tool != tool {
				t.Errorf("%s/%s: meta names tool %q", tool, name, meta.Tool)
			}
			// The producing version must be the version this build pins, or the
			// fixture describes a scanner nobody is running.
			pinned, ok := lock.Version(tool)
			if !ok {
				t.Errorf("%s is not pinned in config/tools.lock", tool)
				continue
			}
			if !versionsAgree(pinned, meta.ToolVersion) {
				t.Errorf("%s/%s: captured from %q but config/tools.lock pins %q; re-capture or re-pin",
					tool, name, meta.ToolVersion, pinned)
			}
		}
	}
}

// versionsAgree compares a pinned version against a tool's self-reported one,
// tolerating the "v" prefix that some tools print and others do not.
func versionsAgree(pinned, reported string) bool {
	return strings.TrimPrefix(pinned, "v") == strings.TrimPrefix(reported, "v")
}

// --- Shape inventory: newly-seen fields are a gap, not an update -----------

// shapeOf returns the sorted set of JSON key paths in a document, with array
// indices collapsed so that a differing number of findings is not a shape
// change. Two captures of the same tool differ in values; a tool that starts
// emitting a new field differs in shape.
func shapeOf(doc any) []string {
	seen := map[string]bool{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch t := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				seen[p] = true
				walk(p, t[k])
			}
		case []any:
			for _, item := range t {
				walk(prefix+"[]", item)
			}
		}
	}
	walk("", doc)

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// decodeStream parses a fixture that may be a single document or a stream of
// concatenated documents, as govulncheck emits.
func decodeStream(b []byte) ([]any, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	var out []any
	for {
		var v any
		err := dec.Decode(&v)
		if err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return out, err
		}
		out = append(out, v)
	}
}

// TestFixtureShapesAreKnown is the gap detector.
//
// It records the set of key paths each fixture contains. A path that is not in
// the committed inventory means the tool emitted something the adapter has
// never been shown, which is a Phase-1 gap: write a test covering it, then
// re-bless with -update-shapes. Plain -update deliberately does not touch these.
func TestFixtureShapesAreKnown(t *testing.T) {
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatalf("reading fixtures: %v", err)
	}

	for _, dir := range entries {
		if !dir.IsDir() {
			continue
		}
		tool := dir.Name()
		files, _ := os.ReadDir(filepath.Join(fixtureDir, tool))
		for _, f := range files {
			n := f.Name()
			if !strings.HasSuffix(n, ".json") ||
				strings.HasSuffix(n, ".golden.json") ||
				strings.HasSuffix(n, ".meta.json") ||
				n == "package.json" {
				continue
			}
			name := strings.TrimSuffix(n, ".json")

			t.Run(tool+"/"+name, func(t *testing.T) {
				raw, err := os.ReadFile(filepath.Join(fixtureDir, tool, n))
				if err != nil {
					t.Fatalf("reading fixture: %v", err)
				}
				if len(strings.TrimSpace(string(raw))) == 0 {
					return // an empty error envelope has no shape
				}

				docs, err := decodeStream(raw)
				if err != nil {
					t.Fatalf("PARSE FAILURE in %s/%s: %v\n"+
						"This is an adapter gap, not a golden diff. -update will not fix it.", tool, name, err)
				}

				var paths []string
				seen := map[string]bool{}
				for _, d := range docs {
					for _, p := range shapeOf(d) {
						if !seen[p] {
							seen[p] = true
							paths = append(paths, p)
						}
					}
				}
				sort.Strings(paths)

				shapePath := filepath.Join(fixtureDir, tool, name+".shape.txt")
				body := strings.Join(paths, "\n") + "\n"

				if *updateShapes {
					if err := os.WriteFile(shapePath, []byte(body), 0o644); err != nil {
						t.Fatalf("writing shape: %v", err)
					}
					t.Logf("blessed %s (%d paths)", shapePath, len(paths))
					return
				}

				want, err := os.ReadFile(shapePath)
				if err != nil {
					t.Fatalf("no recorded shape for %s/%s.\n"+
						"If this fixture is new, review its fields, ensure a test covers them, then run:\n"+
						"  go test ./internal/scan/adapters -update-shapes", tool, name)
				}

				known := map[string]bool{}
				for _, p := range strings.Split(strings.TrimSpace(string(want)), "\n") {
					known[p] = true
				}
				var added []string
				for _, p := range paths {
					if !known[p] {
						added = append(added, p)
					}
				}
				if len(added) > 0 {
					t.Errorf("NEWLY-SEEN FIELDS in %s/%s — this is an adapter gap, not a value diff:\n  %s\n\n"+
						"The tool emitted fields the normaliser has never been shown. Decide whether each\n"+
						"one changes normalisation, add a test covering it, then re-bless with:\n"+
						"  go test ./internal/scan/adapters -update-shapes",
						tool, name, strings.Join(added, "\n  "))
				}
			})
		}
	}
}

// --- Envelope coverage ------------------------------------------------------

// TestEveryToolHasThreeEnvelopes covers the Phase 3 constraint that each tool is
// captured normal, empty and (where it can produce one) error.
//
// The empty envelope matters most: "no findings" and "the scan broke" must
// normalise differently, and only a captured empty result proves the adapter
// tells them apart.
func TestEveryToolHasThreeEnvelopes(t *testing.T) {
	// actions-pin has no external binary and cannot produce a tool-error
	// envelope; gitleaks, trivy and semgrep exit non-zero without a structured
	// error document, so their failure path is covered by the runner tests.
	wantEmpty := []string{"govulncheck", "gosec", "staticcheck", "osv-scanner",
		"gitleaks", "trivy", "semgrep", "npm-audit", "actions-pin"}
	wantError := []string{"govulncheck", "gosec", "staticcheck", "osv-scanner", "npm-audit"}

	for _, tool := range wantEmpty {
		if _, err := os.Stat(filepath.Join(fixtureDir, tool, "empty.json")); err != nil {
			t.Errorf("%s has no empty-envelope fixture: a clean scan must be covered as a shape", tool)
		}
	}
	for _, tool := range wantError {
		if _, err := os.Stat(filepath.Join(fixtureDir, tool, "error.json")); err != nil {
			t.Errorf("%s has no error-envelope fixture: a broken scan must be distinguishable from a clean one (VM-F-205)", tool)
		}
	}
}

// TestEmptyEnvelopesNormaliseCleanly is the property the empty capture exists
// to prove: a clean tree normalises without error and invents nothing. An
// adapter that errored here would turn every clean repository into a coverage
// gap; one that invented findings would be worse.
//
// govulncheck is the deliberate exception. A Go module with no dependencies and
// an empty main still carries the standard library advisories of the toolchain
// that built it, and reporting those is required (VM-F-223) — so for that tool
// "clean project" means every finding is a stdlib finding, not none at all.
func TestEmptyEnvelopesNormaliseCleanly(t *testing.T) {
	lock := testLock(t)
	for _, tc := range fixtureCases(t, lock) {
		if tc.fixture != "empty.json" {
			continue
		}
		t.Run(tc.tool, func(t *testing.T) {
			o := out(tc.tool, tc.repo, tc.dir, readFixture(t, tc.tool, tc.fixture))
			o.Aux = tc.aux
			got, err := tc.adapter.Normalize(o)
			if err != nil {
				t.Fatalf("a clean scan failed to normalise: %v", err)
			}

			if tc.tool == "govulncheck" {
				if len(got) == 0 {
					t.Skip("no toolchain advisories outstanding for this Go release")
				}
				for _, f := range got {
					if f.Module != "stdlib" {
						t.Errorf("a dependency-free module produced a finding in %q; only stdlib advisories are expected", f.Module)
					}
				}
				t.Logf("%d stdlib advisories for the pinned toolchain (VM-F-223)", len(got))
				return
			}

			if len(got) != 0 {
				t.Errorf("a clean scan produced %d findings", len(got))
			}
		})
	}
}

// TestErrorEnvelopesDoNotInventFindings covers the other half. A tool that
// failed must never normalise into findings: the caller records a coverage gap
// from the execution failure, and a normaliser that produced rows here would
// make the gap invisible.
func TestErrorEnvelopesDoNotInventFindings(t *testing.T) {
	lock := testLock(t)
	for _, tc := range fixtureCases(t, lock) {
		if tc.fixture != "error.json" {
			continue
		}
		t.Run(tc.tool, func(t *testing.T) {
			raw := readFixture(t, tc.tool, tc.fixture)
			o := out(tc.tool, tc.repo, tc.dir, raw)
			o.Aux = tc.aux
			got, err := tc.adapter.Normalize(o)
			if err != nil {
				// Refusing to parse a failure envelope is acceptable: the caller
				// already treats the non-zero exit as a gap.
				t.Logf("%s refuses its error envelope: %v", tc.tool, err)
				return
			}
			if len(got) != 0 {
				t.Errorf("a failed scan normalised into %d findings; the coverage gap would be invisible (VM-F-205)", len(got))
			}
		})
	}
}

// --- helper shared with adapters_test.go ------------------------------------

type fixtureCase struct {
	tool    string
	fixture string
	repo    string
	dir     string
	adapter scan.Adapter
	aux     map[string][]byte
}

func summarise(findings []model.RawFinding) string {
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "%s %s %s\n", f.Category, f.PrimaryID+f.RuleID+f.DetectorRuleID+f.CheckID, f.Module+f.File)
	}
	return b.String()
}
