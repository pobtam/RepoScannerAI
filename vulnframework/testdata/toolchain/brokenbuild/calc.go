// Package brokenbuild is a fixture repository that does not compile.
//
// The defect is a type error rather than a syntax error, deliberately: the
// file still parses, so gofmt and go/parser are content with it and only a
// real build reports the problem. A fixture that failed to parse would be
// caught by cheaper means and would not exercise the build at all.
package brokenbuild

// Add does not compile: the return type does not admit the value.
func Add(a, b int) int {
	var sum string = a + b
	return sum
}
