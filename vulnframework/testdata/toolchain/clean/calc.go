// Package clean is a fixture repository whose build and tests both pass.
//
// It is the baseline every other fixture is a deviation from: a toolchain that
// cannot get a clean answer from this one is not measuring anything.
package clean

// Add returns the sum of two integers.
func Add(a, b int) int { return a + b }
