package gotool_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wanaware/vulnframework/internal/remediate/gotool"
)

// The test inventory is what detects a build made green by deleting the test
// that objected. Everything here is about the two ways it can fail silently:
// counting something that is not a test, so a deletion reads as no change, and
// failing to count something that is, so a deletion is never noticed.

func inventoryFixture(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "inventory")
	src := filepath.Join("..", "..", "..", "testdata", "toolchain", "inventory")
	if err := copyTree(src, dir); err != nil {
		t.Fatalf("copying the inventory fixture: %v", err)
	}
	return dir
}

func TestTheInventoryCountsTestsAndNothingElse(t *testing.T) {
	got, err := gotool.ParseTestInventory(inventoryFixture(t))
	if err != nil {
		t.Fatalf("ParseTestInventory: %v", err)
	}

	want := []string{".:TestOne", ".:TestThree", ".:TestTwo"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("inventory = %v, want %v", got, want)
	}
}

// TestTheInventoryExcludesEachNonTestForItsOwnReason is the no-masking rule
// applied to this check.
//
// The test above asserts the whole set at once, which would pass if two of
// these exclusions were broken in compensating directions. Each exclusion is a
// separate decision and gets its own assertion.
func TestTheInventoryExcludesEachNonTestForItsOwnReason(t *testing.T) {
	got, err := gotool.ParseTestInventory(inventoryFixture(t))
	if err != nil {
		t.Fatalf("ParseTestInventory: %v", err)
	}

	for _, c := range []struct{ name, why string }{
		{".:TestMain", "the fixture's TestMain takes a *testing.M, so it is the test binary's entry " +
			"point rather than a test. Counting it reports one more test than the tree can lose. " +
			"Note that the SIGNATURE is what excludes it — see TestATestMainTakingATIsAnOrdinaryTest."},
		{".:TestNotReally", "it is declared in a non-test file, so `go test` never sees it. Counting it " +
			"would report a test that cannot be deleted because it was never there."},
		{".:TestWrongSignature", "it takes no *testing.T, so it is not a test however it is named."},
		{".:helperNotATest", "it has a test's signature and not a test's name."},
		{".:BenchmarkThing", "a benchmark is not a test and does not run in the verification gate."},
		{".:ExampleTestNotReally", "an example is not a test for this purpose."},
		{".:TestSkipped", "a test that unconditionally skips is a test that is gone. Counting it present " +
			"would let a fixer neuter a suite one t.Skip at a time with the inventory reporting no change."},
	} {
		if contains(got, c.name) {
			t.Errorf("the inventory counted %s, which it must not: %s", c.name, c.why)
		}
	}
}

// TestATestMainTakingATIsAnOrdinaryTest is the test that broke the mask.
//
// The inventory originally excluded anything named TestMain, which read as
// obviously correct. It was redundant — the entry point takes a *testing.M,
// so the signature check already rejected it, and the two checks hid each
// other — and it was also wrong: Go runs `func TestMain(t *testing.T)` as an
// ordinary test.
//
// Excluding it by name therefore dropped a real test from the inventory,
// which is the worse direction to be wrong in. Deleting that test would have
// been invisible to the check whose whole job is to notice.
func TestATestMainTakingATIsAnOrdinaryTest(t *testing.T) {
	dir := inventoryFixture(t)
	sub := filepath.Join(dir, "ordinary")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("creating the package: %v", err)
	}
	body := "package ordinary\n\nimport \"testing\"\n\nfunc TestMain(t *testing.T) {}\n"
	if err := os.WriteFile(filepath.Join(sub, "m_test.go"), []byte(body), 0o644); err != nil {
		t.Fatalf("writing the test: %v", err)
	}

	got, err := gotool.ParseTestInventory(dir)
	if err != nil {
		t.Fatalf("ParseTestInventory: %v", err)
	}
	if !contains(got, "ordinary:TestMain") {
		t.Fatalf("a TestMain taking a *testing.T was excluded by name. Go runs it as an ordinary "+
			"test, so deleting it would now be invisible to the inventory: %v", got)
	}
}

// TestTheInventoryReadsATreeThatDoesNotCompile is the reason this parses
// rather than running `go test -list`.
//
// `go test -list` needs the package to compile. A tree that does not build
// would report an empty inventory, and an empty inventory compared against a
// populated one says every test was deleted — so the check written to catch a
// green-by-deletion would fire hardest exactly when the build is broken, and a
// real deletion would be indistinguishable from a compile error.
func TestTheInventoryReadsATreeThatDoesNotCompile(t *testing.T) {
	dir := inventoryFixture(t)
	before, err := gotool.ParseTestInventory(dir)
	if err != nil {
		t.Fatalf("ParseTestInventory: %v", err)
	}

	// A type error: the files still parse, so only a build would object.
	broken := "package inventory\n\nfunc Broken() int {\n\tvar s string = 1\n\treturn s\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "broken.go"), []byte(broken), 0o644); err != nil {
		t.Fatalf("writing the broken file: %v", err)
	}

	after, err := gotool.ParseTestInventory(dir)
	if err != nil {
		t.Fatalf("ParseTestInventory after breaking the build: %v", err)
	}
	if strings.Join(before, ",") != strings.Join(after, ",") {
		t.Fatalf("a tree that does not compile changed the inventory: %v → %v.\n"+
			"The inventory must be readable from a broken tree, or a compile error reads as a mass "+
			"deletion of tests", before, after)
	}
	if len(after) == 0 {
		t.Fatal("the inventory is empty, so the comparison above proved nothing")
	}
}

// TestAnUnparseableTestFileIsReportedNotSkipped is assert-the-negative.
//
// Skipping a file that will not parse is the tempting implementation and it is
// wrong: every test the file declares would drop out of the inventory, which
// downstream reads as a deletion. The system would accuse a fixer of removing
// tests that are still there.
func TestAnUnparseableTestFileIsReportedNotSkipped(t *testing.T) {
	dir := inventoryFixture(t)
	garbage := "package inventory\n\nfunc TestBroken(t *testing.T) { this is not Go\n"
	if err := os.WriteFile(filepath.Join(dir, "garbage_test.go"), []byte(garbage), 0o644); err != nil {
		t.Fatalf("writing the unparseable file: %v", err)
	}

	_, err := gotool.ParseTestInventory(dir)
	if err == nil {
		t.Fatal("a test file that does not parse was skipped silently. Every test it declares then " +
			"drops out of the inventory, which reads downstream as a deletion")
	}
	if !strings.Contains(err.Error(), "garbage_test.go") {
		t.Errorf("the error does not name the file that could not be parsed: %v", err)
	}
}

// TestDeletingATestIsVisible is the property the whole mechanism exists for.
func TestDeletingATestIsVisible(t *testing.T) {
	dir := inventoryFixture(t)
	before, err := gotool.ParseTestInventory(dir)
	if err != nil {
		t.Fatalf("ParseTestInventory: %v", err)
	}

	body := readFile(t, filepath.Join(dir, "b_test.go"))
	body = strings.Replace(body, "func TestThree(t *testing.T) {}", "", 1)
	if err := os.WriteFile(filepath.Join(dir, "b_test.go"), []byte(body), 0o644); err != nil {
		t.Fatalf("rewriting b_test.go: %v", err)
	}

	after, err := gotool.ParseTestInventory(dir)
	if err != nil {
		t.Fatalf("ParseTestInventory: %v", err)
	}
	if !contains(before, ".:TestThree") {
		t.Fatal("the fixture did not declare TestThree, so this proves nothing")
	}
	if contains(after, ".:TestThree") {
		t.Fatal("a deleted test is still in the inventory")
	}
}

// TestNeuteringATestWithSkipIsVisible is the same property one step subtler.
//
// Deleting a test is conspicuous in a diff. Adding one line to the top of it
// is not, and leaves a suite that reports success while asserting nothing.
func TestNeuteringATestWithSkipIsVisible(t *testing.T) {
	dir := inventoryFixture(t)
	body := readFile(t, filepath.Join(dir, "b_test.go"))
	body = strings.Replace(body,
		"func TestThree(t *testing.T) {}",
		"func TestThree(t *testing.T) { t.Skip(\"temporarily\") }", 1)
	if err := os.WriteFile(filepath.Join(dir, "b_test.go"), []byte(body), 0o644); err != nil {
		t.Fatalf("rewriting b_test.go: %v", err)
	}

	after, err := gotool.ParseTestInventory(dir)
	if err != nil {
		t.Fatalf("ParseTestInventory: %v", err)
	}
	if contains(after, ".:TestThree") {
		t.Fatal("a test neutered with an unconditional t.Skip is still counted present. " +
			"A suite can then be disarmed one line at a time with the inventory reporting no change")
	}
}

// TestAConditionalSkipIsNotADeletion is the other side, and it matters as much.
//
// A skip behind a condition is a test that runs somewhere — short mode, a
// missing binary, the wrong platform. Reporting those as deletions would make
// the inventory noisy on every ordinary repository, and a noisy check is one
// nobody reads, which is the only way this check actually fails.
func TestAConditionalSkipIsNotADeletion(t *testing.T) {
	dir := inventoryFixture(t)
	body := readFile(t, filepath.Join(dir, "b_test.go"))
	body = strings.Replace(body,
		"func TestThree(t *testing.T) {}",
		"func TestThree(t *testing.T) {\n\tif testing.Short() {\n\t\tt.Skip(\"short mode\")\n\t}\n}", 1)
	if err := os.WriteFile(filepath.Join(dir, "b_test.go"), []byte(body), 0o644); err != nil {
		t.Fatalf("rewriting b_test.go: %v", err)
	}

	after, err := gotool.ParseTestInventory(dir)
	if err != nil {
		t.Fatalf("ParseTestInventory: %v", err)
	}
	if !contains(after, ".:TestThree") {
		t.Fatal("a test that skips only in short mode was reported as gone")
	}
}

// TestTestdataIsNotScanned guards a false positive that would be permanent.
//
// `go test` does not compile anything under testdata, so a Go file there
// declares tests that can never run. Counting them would put entries in every
// inventory that no change could ever remove.
func TestTestdataIsNotScanned(t *testing.T) {
	dir := inventoryFixture(t)
	nested := filepath.Join(dir, "testdata")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("creating testdata: %v", err)
	}
	body := "package fixture\n\nimport \"testing\"\n\nfunc TestInsideTestdata(t *testing.T) {}\n"
	if err := os.WriteFile(filepath.Join(nested, "x_test.go"), []byte(body), 0o644); err != nil {
		t.Fatalf("writing the nested test: %v", err)
	}

	got, err := gotool.ParseTestInventory(dir)
	if err != nil {
		t.Fatalf("ParseTestInventory: %v", err)
	}
	if contains(got, "testdata:TestInsideTestdata") {
		t.Fatal("a test under testdata was counted. `go test` never compiles it, so it is an entry " +
			"no change can remove")
	}
}

// TestTestsAreQualifiedByPackage keeps two same-named tests distinguishable.
//
// Without the qualifier, deleting one of two identically-named tests in
// different packages leaves the set unchanged and the deletion invisible.
func TestTestsAreQualifiedByPackage(t *testing.T) {
	dir := inventoryFixture(t)
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("creating the sub package: %v", err)
	}
	body := "package sub\n\nimport \"testing\"\n\nfunc TestOne(t *testing.T) {}\n"
	if err := os.WriteFile(filepath.Join(sub, "s_test.go"), []byte(body), 0o644); err != nil {
		t.Fatalf("writing the sub test: %v", err)
	}

	got, err := gotool.ParseTestInventory(dir)
	if err != nil {
		t.Fatalf("ParseTestInventory: %v", err)
	}
	if !contains(got, ".:TestOne") || !contains(got, "sub:TestOne") {
		t.Fatalf("two same-named tests in different packages were not kept apart: %v", got)
	}
}
