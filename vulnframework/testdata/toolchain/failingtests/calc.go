// Package failingtests is a fixture repository that compiles and whose tests
// fail.
//
// VM-F-504: a repository in this state cannot be remediated, because there is
// no signal to verify a fix against. A clean verification afterwards would
// mean nothing.
package failingtests

// Add is deliberately wrong, so the failure is in the code rather than in the
// test: a fixture whose test is merely wrong would not model a repository
// whose build is untrustworthy.
func Add(a, b int) int { return a - b }
