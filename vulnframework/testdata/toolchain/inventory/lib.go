// Package inventory is a fixture for test-inventory extraction.
//
// Its point is the cases that are NOT tests. The inventory is what detects a
// build made green by deleting the test that objected, so counting something
// that is not a test, or missing something that is, both break the detection
// in the direction that matters.
package inventory

// TestNotReally is in a non-test file, so it is not a test however it is
// named. A reader of the tree that counted it would report a test that cannot
// be deleted, because it was never there.
func TestNotReally(n int) int { return n }
