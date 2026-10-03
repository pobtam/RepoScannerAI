// Package twomods is a fixture repository with two outdated dependencies,
// one of whose upgrades does not compile.
//
// Bumping both at once fails. VM-AD §11.3 requires the batch to be bisected,
// the offending bump dropped and the remainder retried — so the correct
// outcome here is vulnmod upgraded, breakmod left where it was, and the
// reviewer told which one was dropped and why.
package twomods

import (
	"example.com/breakmod"
	"example.com/vulnmod"
)

// Double calls the function breakmod removes in its next release.
func Double(n int) int { return breakmod.Compute(n) }

// Greet calls the dependency whose upgrade is harmless.
func Greet(name string) string { return vulnmod.Greet(name) }

// DependencyVersion reports which vulnmod release was linked in.
func DependencyVersion() string { return vulnmod.Version() }
