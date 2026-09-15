// Package adapters implements the scanner adapters (VM-AD §3, §8.2).
//
// Every adapter satisfies scan.Adapter. Run executes a pinned binary through a
// runner.CommandRunner, so the whole package is exercisable offline against
// captured fixtures; Normalize is a pure function of bytes, which is what makes
// those fixture tests meaningful (VM-AD §8.4).
package adapters

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
)

// relPath makes a tool-reported path repository-relative and canonical. Tools
// report paths inside an ephemeral clone directory whose location differs
// between workers and runs; leaving it in place would make the fingerprint a
// function of the checkout path.
func relPath(path, dir string) string {
	return fingerprint.StripRepoRoot(path, dir)
}

// moduleMajor derives the major-version component of a dependency's fingerprint
// location (VM-AD §5). The location survives patch bumps within a vulnerable
// range but not a major-version change, which is a genuinely different defect.
func moduleMajor(modulePath, version string) string {
	// Go encodes major versions from v2 onward in the import path, which is
	// authoritative when present.
	if i := strings.LastIndex(modulePath, "/v"); i >= 0 {
		if suffix := modulePath[i+1:]; isMajorSuffix(suffix) {
			return suffix
		}
	}
	// The Go standard library is versioned by toolchain release, not semver.
	if modulePath == "stdlib" || strings.HasPrefix(version, "go") {
		return "go1"
	}
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if v == "" {
		return ""
	}
	if dot := strings.Index(v, "."); dot > 0 {
		return "v" + v[:dot]
	}
	return "v" + v
}

func isMajorSuffix(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for _, r := range s[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// severityFromOSV maps an OSV database_specific severity band to the model
// enumeration. MODERATE is OSV's name for what the model calls MEDIUM.
func severityFromOSV(s string) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MODERATE", "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}

// severityFromOSVOrScore maps an OSV severity band, falling back to the CVSS
// base score where the advisory carries no band.
//
// The Go vulnerability database publishes no severity band, so for Go findings
// the group's max_severity is the only signal there is. The thresholds match
// the priority bands of VM-AD §9.4 so that a severity derived here and a
// priority computed there do not tell different stories.
func severityFromOSVOrScore(band string, score float64) model.Severity {
	if s := severityFromOSV(band); s != model.SeverityUnknown {
		return s
	}
	switch {
	case score >= 9.0:
		return model.SeverityCritical
	case score >= 7.0:
		return model.SeverityHigh
	case score >= 4.0:
		return model.SeverityMedium
	case score > 0:
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}

// severityFromBand maps a plain CRITICAL/HIGH/MEDIUM/LOW band.
func severityFromBand(s string) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM", "MODERATE":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}

// compact removes insignificant whitespace from a JSON document so that the
// retained raw output (VM-F-109) is stored in a stable form.
func compact(v json.RawMessage) json.RawMessage {
	var buf bytes.Buffer
	if err := json.Compact(&buf, v); err != nil {
		return v
	}
	return json.RawMessage(buf.Bytes())
}

// mustRaw marshals a value for retention as raw tool output. Adapters call this
// with a redacted view where the tool's own output carries secret material.
func mustRaw(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{"error":"raw output could not be marshalled"}`)
	}
	return json.RawMessage(b)
}

// sortFindings imposes a deterministic order on an adapter's output. Without
// it, map iteration in a normaliser would reorder findings between runs and the
// byte-for-byte fixture assertion would be meaningless.
func sortFindings(f []model.RawFinding) {
	sort.SliceStable(f, func(i, j int) bool {
		return sortKey(f[i]) < sortKey(f[j])
	})
}

func sortKey(f model.RawFinding) string {
	return strings.Join([]string{
		string(f.Category),
		fingerprint.Location(f),
		fingerprint.Identity(f),
	}, "\x1f")
}

// dedupe collapses findings that share a fingerprint, merging the reachability
// verdict upward. One tool reporting the same defect at module, package and
// symbol level must yield one finding, not three (VM-F-106).
func dedupe(in []model.RawFinding) []model.RawFinding {
	byFP := map[string]int{}
	var out []model.RawFinding
	for _, f := range in {
		fp := fingerprint.Compute(f)
		if idx, seen := byFP[fp]; seen {
			out[idx] = mergeReachability(out[idx], f)
			continue
		}
		byFP[fp] = len(out)
		out = append(out, f)
	}
	return out
}

// mergeReachability keeps the strongest reachability evidence. A symbol-level
// observation is positive proof the vulnerable code is called and outranks a
// module-level one, which proves only that the dependency is present.
func mergeReachability(a, b model.RawFinding) model.RawFinding {
	if reachRank(b.Classification.Reachable) > reachRank(a.Classification.Reachable) {
		a.Classification.Reachable = b.Classification.Reachable
	}
	// Prefer a populated fixed version over an empty one.
	if a.Versions.Fixed == "" && b.Versions.Fixed != "" {
		a.Versions.Fixed = b.Versions.Fixed
	}
	return a
}

func reachRank(r model.Reachable) int {
	switch r {
	case model.ReachableTrue:
		return 2
	case model.ReachableFalse:
		return 1
	default: // unknown
		return 0
	}
}
