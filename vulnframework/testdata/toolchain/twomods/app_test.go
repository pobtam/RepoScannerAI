package twomods

import "testing"

func TestDouble(t *testing.T) {
	if got := Double(21); got != 42 {
		t.Fatalf("Double(21) = %d, want 42", got)
	}
}

func TestGreet(t *testing.T) {
	if got := Greet("world"); got != "hello world" {
		t.Fatalf("Greet(world) = %q", got)
	}
}
