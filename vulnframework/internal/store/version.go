package store

import (
	"strconv"
	"strings"
)

// highestVersion returns the greatest version in a candidate set — the fix that
// fully closes the defect (VM-AD §8.6).
//
// Taking the lowest would ship a bump that closes one source's advisory while
// leaving another's open, which presents as a verified finding that the next
// scan immediately regresses.
func highestVersion(candidates []string) string {
	best := ""
	for _, c := range candidates {
		if best == "" || compareVersions(c, best) > 0 {
			best = c
		}
	}
	return best
}

// compareVersions orders two version strings, returning -1, 0 or 1.
//
// It is deliberately tolerant rather than strictly semver: the versions arriving
// here come from Go modules ("v0.36.0"), the Go toolchain ("go1.22.2") and npm
// ("1.7.9"), and a parser that rejected any of those would silently drop a fix
// candidate. Numeric components compare numerically; a release outranks a
// pre-release of the same numbers; anything unparseable falls back to a string
// comparison so the result is still total and deterministic.
func compareVersions(a, b string) int {
	an, apre := splitVersion(a)
	bn, bpre := splitVersion(b)

	for i := 0; i < len(an) || i < len(bn); i++ {
		var ai, bi int
		if i < len(an) {
			ai = an[i]
		}
		if i < len(bn) {
			bi = bn[i]
		}
		if ai != bi {
			if ai < bi {
				return -1
			}
			return 1
		}
	}

	// Equal numeric components: a release outranks a pre-release.
	switch {
	case apre == "" && bpre != "":
		return 1
	case apre != "" && bpre == "":
		return -1
	case apre != bpre:
		return strings.Compare(apre, bpre)
	}
	return 0
}

// splitVersion extracts the numeric components and any pre-release suffix,
// tolerating the "v" and "go" prefixes this system encounters.
func splitVersion(v string) ([]int, string) {
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "go")

	// A pre-release or build suffix begins at the first '-' or '+'.
	pre := ""
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		pre, s = s[i+1:], s[:i]
	}

	var nums []int
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			// Unparseable component: stop here and let the pre-release
			// comparison break the tie.
			if pre == "" {
				pre = part
			}
			break
		}
		nums = append(nums, n)
	}
	return nums, pre
}
