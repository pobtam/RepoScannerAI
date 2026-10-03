// Package breakmod stands in for a dependency whose upgrade breaks its
// callers.
//
// VM-AD §11.3 requires that a batch of bumps which fails to build be bisected,
// the offending bump dropped and the remainder retried. Proving that needs a
// module where the newer version genuinely does not compile against the same
// call site, which is what this is.
package breakmod

// Compute is present in 1.0.0 and gone in 1.1.0.
func Compute(n int) int { return n * 2 }
