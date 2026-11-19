package nuguard_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/wanaware/vulnframework/internal/nuguard"
)

// openapiPath finds NuGuard's published contract: NUGUARD_OPENAPI, else the
// NuGuard repository checked out beside this one.
func openapiPath() string {
	if p := os.Getenv("NUGUARD_OPENAPI"); p != "" {
		return p
	}
	// vulnerabilityAI/vulnframework/internal/nuguard -> the directory that
	// holds both checkouts.
	return filepath.Join("..", "..", "..", "..", "nuguard", "nuguard", "nuguard", "service", "openapi.json")
}

// TestEnumsMatchThePublishedContract checks every enum this client decodes
// against NuGuard's openapi.json, in both directions:
//
//   - a value this client knows that the contract no longer lists means the
//     service changed under us;
//   - a value the contract lists that this client does not know would be
//     rejected at run time by the strict decoding, so it must be added here,
//     and its meaning decided, before that service version is used.
//
// Skipped when the contract is not present (a checkout without the NuGuard
// repository beside it).
func TestEnumsMatchThePublishedContract(t *testing.T) {
	b, err := os.ReadFile(openapiPath())
	if err != nil {
		t.Skipf("NuGuard's openapi.json is not present (%v); set NUGUARD_OPENAPI to check the contract", err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	schemaEnum := func(name string) []string {
		var s struct {
			Enum []string `json:"enum"`
		}
		if err := json.Unmarshal(doc.Components.Schemas[name], &s); err != nil || len(s.Enum) == 0 {
			t.Fatalf("schema %s has no enum in the contract", name)
		}
		return s.Enum
	}
	// Enums declared inline on a property: ScanFinding.kind, and the items
	// of ScanOptions.tools (inside an anyOf with null).
	propEnum := func(schema, prop string) []string {
		var s struct {
			Properties map[string]struct {
				Enum  []string `json:"enum"`
				AnyOf []struct {
					Enum  []string `json:"enum"`
					Items struct {
						Enum []string `json:"enum"`
					} `json:"items"`
				} `json:"anyOf"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(doc.Components.Schemas[schema], &s); err != nil {
			t.Fatal(err)
		}
		p := s.Properties[prop]
		if len(p.Enum) > 0 {
			return p.Enum
		}
		for _, a := range p.AnyOf {
			if len(a.Enum) > 0 {
				return a.Enum
			}
			if len(a.Items.Enum) > 0 {
				return a.Items.Enum
			}
		}
		t.Fatalf("%s.%s has no enum in the contract", schema, prop)
		return nil
	}

	check := func(what string, contract []string, known []string) {
		t.Run(what, func(t *testing.T) {
			sort.Strings(contract)
			sort.Strings(known)
			in := func(set []string, v string) bool {
				i := sort.SearchStrings(set, v)
				return i < len(set) && set[i] == v
			}
			for _, v := range known {
				if !in(contract, v) {
					t.Errorf("this client knows %s %q, which the contract no longer lists", what, v)
				}
			}
			for _, v := range contract {
				if !in(known, v) {
					t.Errorf("the contract lists %s %q, which this client would reject; add it and decide what it means", what, v)
				}
			}
		})
	}
	check("scan status", schemaEnum("ScanStatus"), strs(nuguard.ScanStatuses))
	check("scan phase", schemaEnum("ScanPhase"), strs(nuguard.ScanPhases))
	check("severity", schemaEnum("Severity"), strs(nuguard.Severities))
	check("tool run status", schemaEnum("ToolRunStatus"), strs(nuguard.ToolRunStatuses))
	check("finding kind", propEnum("ScanFinding", "kind"), strs(nuguard.Kinds))
	check("tool name", propEnum("ScanOptions", "tools"), strs(nuguard.ToolNames))
}

func strs[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}
