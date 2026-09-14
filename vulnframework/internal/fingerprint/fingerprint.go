package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/wanaware/vulnframework/internal/model"
)

// Version is the fingerprint algorithm version (VM-AD §5).
//
// The version prefix is mandatory and participates in the hash. Changing the
// algorithm requires bumping this and running a migration that maps old
// identities to new; never silently redefine it, or every finding in the store
// silently becomes a different finding.
const Version = "v1"

// sep is the field separator inside the hashed payload. It is a unit separator
// rather than a printable character so that a field containing the separator
// cannot forge a different field boundary.
const sep = "\x1f"

// Length is the number of hex characters in a fingerprint (VM-AD §5).
const Length = 16

// Compute returns the stable identity of a finding (VM-AD §5).
//
//	sha256(version | repo | category | identity | location)[:16]
//
// The fingerprint incorporates repository identity, so the same advisory in two
// repositories yields two findings (VM-F-103). It never incorporates line
// numbers or byte offsets (VM-F-102).
func Compute(f model.RawFinding) string {
	parts := []string{
		Version,
		strings.TrimSpace(f.Repo),
		string(f.Category),
		Identity(f),
		Location(f),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, sep)))
	return hex.EncodeToString(sum[:])[:Length]
}

// Identity returns the category-specific identity component (VM-AD §5).
//
//	dependency — primary_id, uppercased, after alias resolution
//	code       — tool + ":" + rule_id, lowercased
//	secret     — detector_rule_id, lowercased
//	config     — check_id, lowercased
func Identity(f model.RawFinding) string {
	switch f.Category {
	case model.CategoryDependency:
		return ResolveAlias(f.PrimaryID, f.Aliases)
	case model.CategoryCode:
		return normalizeIdent(f.Tool) + ":" + normalizeIdent(f.RuleID)
	case model.CategorySecret:
		return normalizeIdent(f.DetectorRuleID)
	case model.CategoryConfig:
		return normalizeIdent(f.CheckID)
	default:
		// An unknown category still yields a deterministic identity rather than
		// an empty one, so that a malformed record cannot collide with every
		// other malformed record.
		return normalizeIdent(string(f.Category)) + ":" + normalizeIdent(f.PrimaryID)
	}
}

// Location returns the category-specific location component (VM-AD §5).
//
//	dependency — module_path + "@" + major version
//	code       — package import path + "#" + enclosing function,
//	             falling back to file path where there is no enclosing function
//	secret     — file path only
//	config     — file path + "#" + resource key
//
// Each choice is made so the identity survives movement that does not change
// the defect: a dependency location survives patch bumps within a vulnerable
// range, a code location survives reformatting and line shifts, and a secret
// location survives the credential moving down the file.
func Location(f model.RawFinding) string {
	switch f.Category {
	case model.CategoryDependency:
		return strings.TrimSpace(f.Module) + "@" + strings.TrimSpace(f.ModuleMajor)
	case model.CategoryCode:
		if fn := strings.TrimSpace(f.Function); fn != "" {
			return strings.TrimSpace(f.Package) + "#" + fn
		}
		return normalizePath(f.File)
	case model.CategorySecret:
		return normalizePath(f.File)
	case model.CategoryConfig:
		return normalizePath(f.File) + "#" + normalizeIdent(f.ResourceKey)
	default:
		return normalizePath(f.File)
	}
}

// Validate checks that a raw finding carries the inputs its category's
// fingerprint requires. A fingerprint computed from missing inputs is stable
// but meaningless, and would collide with every other finding missing the same
// inputs.
func Validate(f model.RawFinding) error {
	if strings.TrimSpace(f.Repo) == "" {
		return fmt.Errorf("fingerprint: empty repo")
	}
	if !f.Category.Valid() {
		return fmt.Errorf("fingerprint: invalid category %q", f.Category)
	}
	if id := Identity(f); id == "" || id == ":" {
		return fmt.Errorf("fingerprint: category %q has empty identity", f.Category)
	}
	switch f.Category {
	case model.CategoryDependency:
		if strings.TrimSpace(f.Module) == "" {
			return fmt.Errorf("fingerprint: dependency finding has empty module")
		}
	case model.CategoryCode:
		if strings.TrimSpace(f.Package) == "" && strings.TrimSpace(f.File) == "" {
			return fmt.Errorf("fingerprint: code finding has neither package nor file")
		}
	case model.CategorySecret, model.CategoryConfig:
		if strings.TrimSpace(f.File) == "" {
			return fmt.Errorf("fingerprint: %s finding has empty file path", f.Category)
		}
	}
	return nil
}
