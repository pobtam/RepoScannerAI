package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wanaware/vulnframework/internal/model"

	"github.com/wanaware/vulnframework/internal/scan"
)

// The manifest read (VM-F-602: at zero marginal cost, from what scanning
// already reads).
//
// This is what closes OQ-P11-01. Phase 11 built classification, waves and
// blast radius over an index nothing populated — the third instance of the
// same defect in one phase: a field a consumer reads that no producer writes.

func writeGoMod(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(body), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	return dir
}

func TestGoModYieldsDirectAndIndirectDependencies(t *testing.T) {
	dir := writeGoMod(t, `module github.com/wanaware/api

go 1.24

require (
	github.com/wanaware/common v1.4.0
	golang.org/x/crypto v0.35.0
)

require (
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
)

require github.com/wanaware/auth v0.9.1
`)

	deps, err := scan.ReadGoManifest(dir)
	if err != nil {
		t.Fatalf("ReadGoManifest: %v", err)
	}

	byModule := map[string]scan.ModuleDep{}
	for _, d := range deps {
		byModule[d.Module] = d
	}

	for _, want := range []struct {
		module  string
		version string
		direct  bool
	}{
		{"github.com/wanaware/common", "v1.4.0", true},
		{"golang.org/x/crypto", "v0.35.0", true},
		{"golang.org/x/net", "v0.17.0", false},
		{"golang.org/x/sys", "v0.18.0", false},
		{"github.com/wanaware/auth", "v0.9.1", true},
	} {
		got, ok := byModule[want.module]
		if !ok {
			t.Errorf("%s is missing from the manifest read", want.module)
			continue
		}
		if got.Version != want.version {
			t.Errorf("%s version = %q, want %q", want.module, got.Version, want.version)
		}
		if got.Direct != want.direct {
			t.Errorf("%s direct = %v, want %v — an indirect dependency is a real consumer relationship "+
				"but not one the repository declared", want.module, got.Direct, want.direct)
		}
	}
	if len(deps) != 5 {
		t.Errorf("read %d dependencies, want 5: %+v", len(deps), deps)
	}
}

// TestReplaceDirectivesAreDetected is the one VM-F-608 turns on.
//
// A consumer with a replace does not resolve the module from the registry at
// all, so a wave that bumped its requirement would change nothing that is
// actually built — and the bump would build, pass, and close a live finding.
// Phase 11 implemented that exclusion and had no way to learn the fact:
// nothing read a manifest, so `Replaced` was whatever a test set.
func TestReplaceDirectivesAreDetected(t *testing.T) {
	dir := writeGoMod(t, `module github.com/wanaware/web

go 1.24

require (
	github.com/wanaware/common v1.4.0
	golang.org/x/crypto v0.35.0
)

replace github.com/wanaware/common => ../common

replace (
	golang.org/x/crypto => github.com/wanaware/crypto-fork v0.35.1
)
`)

	deps, err := scan.ReadGoManifest(dir)
	if err != nil {
		t.Fatalf("ReadGoManifest: %v", err)
	}

	byModule := map[string]scan.ModuleDep{}
	for _, d := range deps {
		byModule[d.Module] = d
	}
	for _, module := range []string{"github.com/wanaware/common", "golang.org/x/crypto"} {
		d, ok := byModule[module]
		if !ok {
			t.Fatalf("%s missing", module)
		}
		if !d.Replaced {
			t.Errorf("%s is not marked replaced; a wave would bump a requirement that changes nothing "+
				"actually built, and the bump would pass and close a live finding (VM-F-608)", module)
		}
	}
}

// TestAMissingManifestIsNotAnError is the coverage-gap discipline applied
// here. A repository with no go.mod is a JavaScript repository, or a
// monorepo's root, or an empty checkout — none of which is a failure, and
// failing the scan over it would convert an ordinary shape into a gap.
func TestAMissingManifestIsNotAnError(t *testing.T) {
	deps, err := scan.ReadGoManifest(t.TempDir())
	if err != nil {
		t.Errorf("a missing manifest errored: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("a missing manifest yielded %d dependencies", len(deps))
	}
}

// TestMalformedManifestLinesAreSkippedNotGuessed is the honesty half. A line
// the parser does not understand is skipped, never interpreted: inventing a
// version for a line it could not read would put a wrong number into the
// index that every wave decision then rests on.
func TestMalformedManifestLinesAreSkippedNotGuessed(t *testing.T) {
	dir := writeGoMod(t, `module x

require (
	github.com/good/one v1.0.0
	this-line-has-no-version
	
	// a comment
	github.com/good/two v2.0.0 // indirect
)
`)
	deps, err := scan.ReadGoManifest(dir)
	if err != nil {
		t.Fatalf("ReadGoManifest: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("read %d dependencies, want 2 (the unparseable line skipped): %+v", len(deps), deps)
	}
	for _, d := range deps {
		if d.Version == "" {
			t.Errorf("%s has no version; a guessed version becomes a wave decision", d.Module)
		}
	}
}

// TestTheWorkerRecordsTheManifestItRead is the link between the parser and
// everything downstream, and it is the one most likely to be missing.
//
// ReadGoManifest can be perfect and Result.Deps still empty if nothing calls
// it. That is the exact shape of all three defects Phase 11 found: each
// component worked, and one was not connected to the next. A test that calls
// the parser directly — as every other test in this file does — cannot see it.
func TestTheWorkerRecordsTheManifestItRead(t *testing.T) {
	dir := writeGoMod(t, `module github.com/wanaware/api

go 1.24

require (
	github.com/wanaware/common v1.4.0
	golang.org/x/crypto v0.35.0
)

replace github.com/wanaware/common => ../common
`)

	// An adapter registry with one adapter that finds nothing: the manifest
	// read must not depend on any tool producing findings.
	reg, err := scan.NewRegistry(&silentAdapter{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	w := scan.NewWorker(reg)
	w.Clock = func() time.Time { return time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC) }

	res, err := w.Scan(context.Background(), "S-000001", "org/wanaware-api", dir,
		scan.RepoProfile{Languages: []scan.Language{scan.LangGo}}, scan.RunOpts{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(res.Deps) == 0 {
		t.Fatal("a scan of a repository with a go.mod recorded no dependencies. The parser works and " +
			"nothing calls it: the reverse-dependency index stays empty, every first-party wave is " +
			"inert, and every test that calls the parser directly still passes (OQ-P11-01)")
	}

	byModule := map[string]scan.ModuleDep{}
	for _, d := range res.Deps {
		byModule[d.Module] = d
	}
	if got, ok := byModule["github.com/wanaware/common"]; !ok || !got.Replaced {
		t.Errorf("the replace directive did not reach the scan result: %+v", got)
	}
	if got, ok := byModule["golang.org/x/crypto"]; !ok || got.Version != "v0.35.0" {
		t.Errorf("golang.org/x/crypto = %+v, want v0.35.0", got)
	}
}

// TestAScanOfARepositoryWithNoManifestIsStillAScan is the negative half. A
// JavaScript repository has no go.mod, and that must not become a failure or
// a coverage gap in the findings.
func TestAScanOfARepositoryWithNoManifestIsStillAScan(t *testing.T) {
	reg, err := scan.NewRegistry(&silentAdapter{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	w := scan.NewWorker(reg)
	res, err := w.Scan(context.Background(), "S-000001", "org/web", t.TempDir(),
		scan.RepoProfile{Languages: []scan.Language{scan.LangGo}}, scan.RunOpts{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Deps) != 0 {
		t.Errorf("a repository with no manifest yielded %d dependencies", len(res.Deps))
	}
	if res.Outcome != model.ScanComplete {
		t.Errorf("outcome = %s, want complete: a missing go.mod is an ordinary shape, not a gap",
			res.Outcome)
	}
}

// silentAdapter runs, succeeds, and finds nothing.
type silentAdapter struct{}

func (silentAdapter) Name() string                   { return "silent" }
func (silentAdapter) Version() string                { return "v0.0.1" }
func (silentAdapter) Supports(scan.RepoProfile) bool { return true }

func (silentAdapter) Run(context.Context, string, scan.RunOpts) (scan.RawOutput, error) {
	return scan.RawOutput{Tool: "silent", ToolVersion: "v0.0.1"}, nil
}

func (silentAdapter) Normalize(scan.RawOutput) ([]model.RawFinding, error) { return nil, nil }
