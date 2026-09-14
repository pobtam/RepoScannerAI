// Package model defines the canonical finding record, its lifecycle states,
// reason codes, and severity/priority enumerations (VM-AD §4, §6).
//
// This package has no dependencies on any other internal package (VM-AD §3).
// Everything depends on it. If a change here forces edits across five packages,
// the model is wrong — stop and reconsider before proceeding.
package model

import "fmt"

// SchemaVersion is the current finding schema (VM-AD §4.1).
const SchemaVersion = "findings.v1"

// supportedSchemaVersions is the closed set this build understands.
// A record carrying anything else is rejected rather than best-effort parsed
// (VM-F-107) — a partially understood finding is worse than a refused one.
var supportedSchemaVersions = map[string]bool{
	SchemaVersion: true,
}

// SchemaSupported reports whether v is a schema version this build can process.
func SchemaSupported(v string) bool { return supportedSchemaVersions[v] }

// ErrUnsupportedSchema is returned for a record whose schema version this build
// does not support (VM-F-107).
type ErrUnsupportedSchema struct {
	Got string
}

func (e *ErrUnsupportedSchema) Error() string {
	return fmt.Sprintf("unsupported finding schema version %q (this build supports %q)", e.Got, SchemaVersion)
}

// ValidateSchemaVersion returns an error unless v is a supported schema version.
func ValidateSchemaVersion(v string) error {
	if !SchemaSupported(v) {
		return &ErrUnsupportedSchema{Got: v}
	}
	return nil
}
