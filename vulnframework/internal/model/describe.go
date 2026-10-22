package model

import (
	"fmt"
	"strings"
	"unicode"
)

// MaxDescriptionRunes bounds a scanner's description. Advisory details can
// run to pages; the summary a reader needs is the first part.
const MaxDescriptionRunes = 1000

// SafeDescription prepares a scanner's text for storage: whitespace
// collapsed, length bounded, and nothing kept that looks like credential
// material. A semgrep message can quote the matched code, and matched code can
// hold a key; such a description is dropped entirely rather than partly
// scrubbed, and the finding falls back to Describe (VM-F-263).
func SafeDescription(s string) string {
	s = strings.Join(strings.FieldsFunc(s, unicode.IsSpace), " ")
	if s == "" {
		return ""
	}
	if r := []rune(s); len(r) > MaxDescriptionRunes {
		s = strings.TrimRightFunc(string(r[:MaxDescriptionRunes-1]), unicode.IsSpace) + "…"
	}
	if AssertNoCredential("finding description", []byte(s)) != nil {
		return ""
	}
	return s
}

// DescriptionSourceDerived marks a description built by Describe rather than
// supplied by a scanner.
const DescriptionSourceDerived = "derived"

// Describe returns a finding's description and where it came from: the
// scanner's own text where one was recorded (the source is then the tools
// that reported it), otherwise an account built from the record's fields
// (source "derived"). Every finding has one; a reader is never left with an
// identifier alone.
func Describe(f Finding) (text, source string) {
	if f.Description != "" {
		return f.Description, strings.Join(f.Provenance.Tools, ", ")
	}
	return derivedDescription(f), DescriptionSourceDerived
}

func derivedDescription(f Finding) string {
	file := deref(f.Location.File)
	where := file
	if where != "" && f.Location.Line != nil && *f.Location.Line > 0 {
		where = fmt.Sprintf("%s:%d", file, *f.Location.Line)
	}
	rule := deref(f.Identity.RuleID)
	if rule == "" {
		rule = f.Identity.PrimaryID
	}
	tools := strings.Join(f.Provenance.Tools, " and ")
	if tools == "" {
		tools = "a scanner"
	}

	switch f.Category {
	case CategoryDependency:
		pkg := f.Location.Module
		if pkg == "" {
			pkg = "a dependency"
		}
		if f.Versions.Current != "" {
			pkg += " " + f.Versions.Current
		}
		id := f.Identity.PrimaryID
		if id == "" {
			id = "a published advisory"
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s is affected by %s.", pkg, id)
		if f.Versions.Fixed != "" {
			fmt.Fprintf(&b, " Upgrading to %s or later fixes it.", f.Versions.Fixed)
		} else {
			b.WriteString(" No fixed version is recorded.")
		}
		switch f.Classification.Reachable {
		case ReachableTrue:
			b.WriteString(" The vulnerable code is called from this repository.")
		case ReachableFalse:
			b.WriteString(" The vulnerable code was not found to be called from this repository.")
		}
		return b.String()

	case CategorySecret:
		kind := "a credential"
		if f.CredentialType != "" {
			kind = "a credential (" + f.CredentialType + ")"
		}
		loc := "this repository"
		if file != "" {
			loc = file
		}
		return fmt.Sprintf("Something that looks like %s is committed in %s. Treat it as exposed: "+
			"rotate it first, then remove it from the code.", kind, loc)

	case CategoryConfig:
		if where == "" {
			return fmt.Sprintf("Configuration check %s failed, reported by %s.", rule, tools)
		}
		return fmt.Sprintf("Configuration check %s failed in %s, reported by %s.", rule, where, tools)

	default: // code
		if where == "" {
			return fmt.Sprintf("Rule %s from %s flagged a security issue in this repository's code.", rule, tools)
		}
		return fmt.Sprintf("Rule %s from %s flagged a security issue at %s.", rule, tools, where)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
