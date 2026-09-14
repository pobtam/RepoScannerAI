package model_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/wanaware/vulnframework"

// TestFoundationPackagesHaveNoInternalDependencies makes the VM-AD §3
// dependency rule executable rather than aspirational:
//
//	internal/model and internal/fingerprint have no dependencies on any other
//	internal package. Everything depends on them.
//
// model is held to the rule absolutely. fingerprint is permitted to import
// model and nothing else internal — §5 types Compute over model.RawFinding and
// §8.4 has adapters return []model.RawFinding, so one shared type is
// unavoidable; see BUILD-LOG assumption A2.
//
// The rule exists so that a change to the model does not ripple across five
// packages. A violation is a design error, not a style preference, which is why
// it fails the build rather than a linter.
func TestFoundationPackagesHaveNoInternalDependencies(t *testing.T) {
	root := repoRoot(t)

	cases := []struct {
		pkg     string
		allowed map[string]bool
	}{
		{pkg: "internal/model", allowed: map[string]bool{}},
		{pkg: "internal/fingerprint", allowed: map[string]bool{
			modulePath + "/internal/model": true,
		}},
	}

	for _, tc := range cases {
		t.Run(tc.pkg, func(t *testing.T) {
			dir := filepath.Join(root, filepath.FromSlash(tc.pkg))
			for _, imp := range internalImportsOf(t, dir) {
				if tc.allowed[imp.path] {
					continue
				}
				t.Errorf("%s imports %s — %s may not depend on it (VM-AD §3)",
					imp.file, imp.path, tc.pkg)
			}
		})
	}
}

// TestFoundationPackagesHaveNoExternalDependencies covers the Phase 0 gate
// clause "no external dependency": the foundation must build with the standard
// library alone, so it can be exercised offline and cannot inherit a supply
// chain risk of its own.
func TestFoundationPackagesHaveNoExternalDependencies(t *testing.T) {
	root := repoRoot(t)

	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "require") && !strings.HasPrefix(line, "require (") {
			t.Errorf("go.mod declares a dependency: %q — Phase 0 must have none", line)
		}
	}

	for _, pkg := range []string{"internal/model", "internal/fingerprint"} {
		dir := filepath.Join(root, filepath.FromSlash(pkg))
		for _, imp := range allImportsOf(t, dir) {
			// This module's own packages are governed by the layering test
			// above, not by this one.
			if imp.path == modulePath || strings.HasPrefix(imp.path, modulePath+"/") {
				continue
			}
			// Standard library import paths have no dot in their first segment.
			first, _, _ := strings.Cut(imp.path, "/")
			if strings.Contains(first, ".") {
				t.Errorf("%s imports the third-party package %s; Phase 0 is standard library only",
					imp.file, imp.path)
			}
		}
	}
}

type importRef struct {
	file string
	path string
}

func allImportsOf(t *testing.T, dir string) []importRef {
	t.Helper()
	fset := token.NewFileSet()
	// Test files are parsed too: a test dependency is still a dependency.
	pkgs, err := parser.ParseDir(fset, dir, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}

	var out []importRef
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			for _, spec := range file.Imports {
				path, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatalf("%s: bad import path %s", name, spec.Path.Value)
				}
				out = append(out, importRef{file: filepath.Base(name), path: path})
			}
		}
	}
	return out
}

func internalImportsOf(t *testing.T, dir string) []importRef {
	t.Helper()
	var out []importRef
	for _, imp := range allImportsOf(t, dir) {
		if strings.HasPrefix(imp.path, modulePath+"/internal/") {
			// A package's own external test file (package model_test) importing
			// the package under test is the test harness, not a dependency.
			if strings.HasSuffix(imp.file, "_test.go") && imp.path == modulePath+"/"+filepath.ToSlash(relTo(t, dir)) {
				continue
			}
			out = append(out, imp)
		}
	}
	return out
}

// relTo returns dir relative to the module root, in slash form.
func relTo(t *testing.T, dir string) string {
	t.Helper()
	rel, err := filepath.Rel(repoRoot(t), dir)
	if err != nil {
		t.Fatalf("rel: %v", err)
	}
	return filepath.ToSlash(rel)
}

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate go.mod above the test working directory")
		}
		dir = parent
	}
}
