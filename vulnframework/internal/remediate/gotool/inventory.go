package gotool

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// TestInventory lists the test functions present in the tree (VM-F-531's
// green-by-deletion check).
//
// It PARSES rather than executes, and that is the whole design decision.
//
// `go test -list` is the obvious implementation and it is wrong here, because
// it needs the package to compile. A tree that does not build would report an
// empty inventory, and an empty inventory read against a populated one says
// EVERY TEST WAS DELETED. The check whose job is to catch a build made green
// by removing the objecting test would therefore fire hardest exactly when the
// build is broken, and a real deletion would be indistinguishable from a
// compile error.
//
// Parsing has two further properties that matter. It runs none of the
// repository's code, so this is the one toolchain method that needs no
// sandbox. And it reads the TREE — not a fixer's account of what it changed —
// which is the point: an agent that removed a test and did not mention it is
// precisely the case this exists for.
func (t *Toolchain) TestInventory(_ context.Context, dir string) ([]string, error) {
	return ParseTestInventory(dir)
}

// ParseTestInventory walks dir and returns every test function in it, as
// "package/path:TestName", sorted.
//
// The name is qualified by directory because two packages may each declare a
// test of the same name, and an inventory that collapsed them would report no
// change when one of the two was deleted.
func ParseTestInventory(dir string) ([]string, error) {
	var out []string
	fset := token.NewFileSet()

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d.Name()) && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}

		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			// A test file that does not parse is reported, not skipped.
			// Skipping it would drop every test it declares from the
			// inventory, which reads downstream as a deletion — the system
			// would accuse a fixer of removing tests that are still there.
			return fmt.Errorf("gotool: parsing %s: %w", path, perr)
		}

		rel, rerr := filepath.Rel(dir, filepath.Dir(path))
		if rerr != nil {
			rel = filepath.Dir(path)
		}
		rel = filepath.ToSlash(rel)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !isTestFunc(fn) {
				continue
			}
			if alwaysSkips(fn) {
				// A test that unconditionally skips is a test that is gone.
				// Counting it present would let a fixer neuter a suite one
				// t.Skip at a time while the inventory reported no change —
				// a green-by-deletion that never deletes anything.
				continue
			}
			out = append(out, rel+":"+fn.Name.Name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(out)
	return out, nil
}

// isTestFunc reports whether fn is a test the `go test` runner would run.
//
// The SIGNATURE decides, not the name. That ordering was arrived at the hard
// way: this function originally also excluded anything called TestMain, which
// looked obviously right and was wrong twice over.
//
// It was redundant, because the entry point's parameter is a *testing.M and
// the signature check already rejects it — so the two checks masked each
// other, and a mutation that deleted the signature check went unnoticed.
//
// And it was incorrect. `func TestMain(t *testing.T)` is not an entry point;
// Go runs it as an ordinary test. Excluding it by name dropped a real test
// from the inventory, which is the worse direction to be wrong in: deleting
// that test would then be invisible to the check whose entire job is to
// notice.
func isTestFunc(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || fn.Body == nil {
		return false
	}
	name := fn.Name.Name
	if !strings.HasPrefix(name, "Test") {
		return false
	}
	// A test is Test<Something>: an upper-case or non-letter rune must follow,
	// so Testify or TestableThing is not counted.
	if rest := name[len("Test"):]; rest != "" && !startsUpperOrDigit(rest) {
		return false
	}
	if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
		return false
	}
	star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "testing" && sel.Sel.Name == "T"
}

func startsUpperOrDigit(s string) bool {
	r := rune(s[0])
	return !(r >= 'a' && r <= 'z')
}

// alwaysSkips reports whether the function's first statement is an
// unconditional t.Skip.
//
// Deliberately narrow: only a skip that cannot be avoided counts. A skip
// behind an `if` is a test that runs somewhere — short mode, a missing
// binary, the wrong platform — and calling that gone would make the inventory
// noisy enough to be ignored, which is the only way this check actually
// fails.
func alwaysSkips(fn *ast.FuncDecl) bool {
	for _, stmt := range fn.Body.List {
		expr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		switch sel.Sel.Name {
		case "Skip", "Skipf", "SkipNow":
			return true
		case "Helper", "Parallel", "Log", "Logf":
			// Preamble a skipping test may legitimately have before it skips.
			continue
		default:
			return false
		}
	}
	return false
}

// skipDir names directories whose contents are not the repository's own tests.
func skipDir(name string) bool {
	switch name {
	case ".git", "vendor", "node_modules", "testdata":
		// testdata is excluded because `go test` does not compile it: a Go
		// file under testdata is fixture material, and counting its tests
		// would report tests that can never run.
		return true
	}
	return strings.HasPrefix(name, ".")
}
