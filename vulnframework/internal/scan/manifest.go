package scan

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// ModuleDep is one entry of a repository's dependency manifest.
//
// Read during scanning at zero marginal cost (VM-F-602): the clone is already
// on disk and the manifest is already parsed by the tools running against it.
// What was missing was anybody recording it.
type ModuleDep struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Direct  bool   `json:"direct"`
	// Replaced marks a `replace` directive affecting this module. It is the
	// fact VM-F-608 turns on, and go.mod is the only place it exists: a wave
	// that bumped a replaced requirement would change nothing that is
	// actually built, and the bump would pass and close a live finding.
	Replaced bool `json:"replaced"`
}

// ReadGoManifest reads a repository's go.mod.
//
// Hand-parsed rather than taken from golang.org/x/mod, to keep the dependency
// set at the two the module already has. The parser is deliberately
// conservative: a line it does not understand is SKIPPED, never guessed at.
// Inventing a version for an unreadable line would put a wrong number into the
// index that every subsequent wave decision rests on, and it would look
// exactly like a correct one.
//
// A missing manifest is not an error. A repository with no go.mod is a
// JavaScript repository, a monorepo root, or an empty checkout — none of which
// is a failure, and erroring would convert an ordinary shape into a coverage
// gap.
func ReadGoManifest(dir string) ([]ModuleDep, error) {
	f, err := os.Open(filepath.Join(dir, "go.mod"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var (
		deps      []ModuleDep
		replaced  = map[string]bool{}
		inRequire bool
		inReplace bool
	)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if i := strings.Index(line, "//"); i >= 0 {
			// Keep the comment for the indirect marker, drop it for parsing.
			if strings.Contains(line[i:], "indirect") {
				line = strings.TrimSpace(line[:i]) + " // indirect"
			} else {
				line = strings.TrimSpace(line[:i])
			}
		}
		if line == "" {
			continue
		}

		switch {
		case line == "require (":
			inRequire = true
			continue
		case line == "replace (":
			inReplace = true
			continue
		case line == ")":
			inRequire, inReplace = false, false
			continue
		case strings.HasPrefix(line, "require "):
			if d, ok := parseRequire(strings.TrimPrefix(line, "require ")); ok {
				deps = append(deps, d)
			}
			continue
		case strings.HasPrefix(line, "replace "):
			if module, ok := parseReplace(strings.TrimPrefix(line, "replace ")); ok {
				replaced[module] = true
			}
			continue
		}

		if inRequire {
			if d, ok := parseRequire(line); ok {
				deps = append(deps, d)
			}
		}
		if inReplace {
			if module, ok := parseReplace(line); ok {
				replaced[module] = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	for i := range deps {
		deps[i].Replaced = replaced[deps[i].Module]
	}
	return deps, nil
}

// parseRequire reads `module version [// indirect]`.
func parseRequire(line string) (ModuleDep, bool) {
	indirect := strings.Contains(line, "// indirect")
	if i := strings.Index(line, "//"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	fields := strings.Fields(line)
	if len(fields) != 2 {
		// Not a require line this parser understands. Skipped, not guessed.
		return ModuleDep{}, false
	}
	if !strings.HasPrefix(fields[1], "v") {
		return ModuleDep{}, false
	}
	return ModuleDep{Module: fields[0], Version: fields[1], Direct: !indirect}, true
}

// parseReplace reads `old [version] => new [version]` and returns the module
// being replaced.
func parseReplace(line string) (string, bool) {
	i := strings.Index(line, "=>")
	if i < 0 {
		return "", false
	}
	fields := strings.Fields(strings.TrimSpace(line[:i]))
	if len(fields) == 0 {
		return "", false
	}
	return fields[0], true
}
