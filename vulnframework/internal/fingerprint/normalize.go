// Package fingerprint computes stable finding identities (VM-AD §5).
//
// It depends only on internal/model (VM-AD §3); the layering test in
// internal/model enforces that.
package fingerprint

import (
	"regexp"
	"strings"
)

// normalizePath canonicalises a path before it is hashed (VM-AD §5,
// "Normalisation before hashing"): convert separators to "/", strip a leading
// "./", trim whitespace.
//
// Case is preserved: paths are case-sensitive on the platforms scans run on,
// and lowercasing would collapse two genuinely distinct files.
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, "\\", "/")
	// Collapse repeated separators produced by naive path joins.
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	p = strings.TrimPrefix(p, "/")
	return p
}

// StripRepoRoot removes a repository root prefix from a path (VM-AD §5).
//
// Scanners are invoked against a clone directory whose absolute location
// differs between workers and between runs; leaving it in the hash would make
// the fingerprint a function of the checkout path.
func StripRepoRoot(path, root string) string {
	path = normalizePath(path)
	root = normalizePath(root)
	if root == "" {
		return path
	}
	if !strings.HasSuffix(root, "/") {
		root += "/"
	}
	return strings.TrimPrefix(path, root)
}

// normalizeIdent trims and lowercases an identifier, for the categories whose
// identity the specification says to lowercase (code, secret, config).
func normalizeIdent(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// normalizeUpper trims and uppercases an identifier, for dependency advisory
// identifiers.
func normalizeUpper(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

// Advisory identifier precedence (VM-AD §4.1, §5):
// GO-ID > GHSA > CVE > OSV > tool rule ID.
type idKind int

const (
	kindGo idKind = iota
	kindGHSA
	kindCVE
	kindOSV
	kindOther
)

var (
	reGo   = regexp.MustCompile(`^GO-\d{4}-\d+$`)
	reGHSA = regexp.MustCompile(`^GHSA-[23456789CFGHJMPQRVWXcfghjmpqrvwx]{4}-[23456789CFGHJMPQRVWXcfghjmpqrvwx]{4}-[23456789CFGHJMPQRVWXcfghjmpqrvwx]{4}$`)
	reCVE  = regexp.MustCompile(`^CVE-\d{4}-\d+$`)
	reOSV  = regexp.MustCompile(`^(OSV|GHSA|PYSEC|RUSTSEC|GO)-.+$`)
)

// classifyID assigns an advisory identifier to its precedence class.
func classifyID(id string) idKind {
	switch {
	case reGo.MatchString(id):
		return kindGo
	case reGHSA.MatchString(id):
		return kindGHSA
	case reCVE.MatchString(id):
		return kindCVE
	case reOSV.MatchString(id):
		return kindOSV
	default:
		return kindOther
	}
}

// ResolveAlias picks the canonical advisory identifier from a primary
// identifier and its alias set, by the fixed precedence GO-ID > GHSA > CVE >
// OSV > tool rule ID (VM-AD §4.1, §5).
//
// This must happen before fingerprinting. osv-scanner reports CVE-2025-22869
// and govulncheck reports GO-2025-3106 for the same defect; without alias
// resolution these produce two fingerprints and the deduplication requirement
// (VM-F-106) fails.
//
// Ties within a class are broken lexicographically so the result does not
// depend on the order a tool happened to list aliases in.
func ResolveAlias(primaryID string, aliases []string) string {
	best := ""
	bestKind := idKind(kindOther + 1)

	consider := func(raw string) {
		id := normalizeUpper(raw)
		if id == "" {
			return
		}
		k := classifyID(id)
		switch {
		case k < bestKind:
			best, bestKind = id, k
		case k == bestKind && (best == "" || id < best):
			best = id
		}
	}

	consider(primaryID)
	for _, a := range aliases {
		consider(a)
	}
	return best
}
