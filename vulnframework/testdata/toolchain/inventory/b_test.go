package inventory

import (
	"os"
	"testing"
)

// TestMain is the test binary's entry point, not a test. Its parameter is a
// *testing.M, which is what distinguishes it — the name prefix alone would
// count it and report one more test than the tree can lose.
func TestMain(m *testing.M) { os.Exit(m.Run()) }

func TestThree(t *testing.T) {}

func BenchmarkThing(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = TestNotReally(i)
	}
}

func ExampleTestNotReally() {
	_ = TestNotReally(1)
	// Output:
}
