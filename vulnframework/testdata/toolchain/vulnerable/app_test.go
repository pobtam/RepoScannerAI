package vulnerable

import "testing"

func TestGreet(t *testing.T) {
	if got := Greet("world"); got != "hello world" {
		t.Fatalf("Greet(world) = %q", got)
	}
}

// TestDependencyVersion prints the linked version rather than asserting one,
// so the same fixture serves both before and after a bump.
func TestDependencyVersion(t *testing.T) {
	t.Logf("VF_LINKED_VERSION %s", DependencyVersion())
}
