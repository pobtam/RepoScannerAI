// Package vulnmod stands in for a dependency with a published advisory.
//
// Version 1.0.0 is the affected one. It is a fixture, so it is not actually
// vulnerable to anything; what matters is that the two versions are
// distinguishable from inside the consuming repository, so a test can tell a
// bump that happened from one that only appears to have.
package vulnmod

// Version reports which release this is, so the consumer can assert on it.
func Version() string { return "v1.0.0" }

// Greet is the API the consumer uses. It is unchanged across both versions:
// a dependency bump that closes an advisory usually does not break its
// callers, and the fixture must model the ordinary case.
func Greet(name string) string { return "hello " + name }
