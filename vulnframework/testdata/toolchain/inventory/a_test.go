package inventory

import "testing"

func TestOne(t *testing.T) {
	if TestNotReally(1) != 1 {
		t.Fatal("unreachable")
	}
}

func TestTwo(t *testing.T) {
	// Subtests are not separate tests for inventory purposes: deleting a
	// subtest is a source change the diff shows, whereas deleting the
	// function is what silently removes the objection.
	t.Run("sub", func(t *testing.T) {})
	t.Run("other", func(t *testing.T) {})
}

// TestSkipped is present in the tree and does nothing. A test that always
// skips is a test that is gone, and the inventory must say so — otherwise
// neutering a test reads as leaving it alone.
func TestSkipped(t *testing.T) {
	t.Skip("fixture: unconditionally skipped")
	t.Fatal("unreachable")
}

// TestWrongSignature takes no testing.T and is therefore not a test, however
// it is named.
func TestWrongSignature() {}

func helperNotATest(t *testing.T) { t.Helper() }
