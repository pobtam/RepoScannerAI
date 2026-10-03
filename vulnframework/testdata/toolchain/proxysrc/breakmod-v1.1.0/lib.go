// Package breakmod stands in for a dependency whose upgrade breaks its
// callers.
//
// In 1.1.0 Compute is gone. Removing an exported function in a minor release
// is poor practice and entirely ordinary, which is why remediation has to
// survive it rather than assume it away.
package breakmod

// ComputeN replaces Compute and does not accept its call site.
func ComputeN(n, factor int) int { return n * factor }
