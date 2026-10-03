// Package vulnerable is a fixture repository holding one dependency at an
// affected version.
//
// It is what a deterministic bump is performed against: the module is
// required at v1.0.0, the advisory closes at v1.2.0, and the repository's own
// test reports which version it actually linked against — so "the bump
// happened" is answered by the tree rather than by the bumper.
package vulnerable

import "example.com/vulnmod"

// Greet delegates to the dependency, so the dependency is genuinely linked.
// A requirement nothing imports is pruned, and the fixture would stop
// modelling anything.
func Greet(name string) string { return vulnmod.Greet(name) }

// DependencyVersion reports the version actually linked in.
func DependencyVersion() string { return vulnmod.Version() }
