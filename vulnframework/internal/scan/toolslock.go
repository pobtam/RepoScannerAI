package scan

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// ToolsLock is the parsed config/tools.lock (VM-AD §8.3). It pins every tool to
// an exact version and names the scanner image.
type ToolsLock struct {
	Tools map[string]string
	Image string
}

// Version returns the pinned version of a tool.
func (l ToolsLock) Version(tool string) (string, bool) {
	v, ok := l.Tools[tool]
	return v, ok
}

// MustVersion returns the pinned version of a tool, or the empty string. An
// adapter reporting an empty version is a defect, not a fallback: the run
// record would then be unable to explain a change in finding counts (VM-F-202).
func (l ToolsLock) MustVersion(tool string) string { return l.Tools[tool] }

// Names returns the pinned tool names, sorted.
func (l ToolsLock) Names() []string {
	out := make([]string, 0, len(l.Tools))
	for n := range l.Tools {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// LoadToolsLock reads a tools.lock from disk.
func LoadToolsLock(path string) (ToolsLock, error) {
	f, err := os.Open(path)
	if err != nil {
		return ToolsLock{}, fmt.Errorf("tools.lock: %w", err)
	}
	defer f.Close()
	return ParseToolsLock(f)
}

// ParseToolsLock reads the tools.lock format: whitespace-separated records, one
// per line, blank lines and # comments ignored.
func ParseToolsLock(r io.Reader) (ToolsLock, error) {
	lock := ToolsLock{Tools: map[string]string{}}
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		switch fields[0] {
		case "tool":
			if len(fields) != 3 {
				return ToolsLock{}, fmt.Errorf("tools.lock:%d: tool record needs a name and a version, got %q", line, text)
			}
			name, version := fields[1], fields[2]
			if prev, dup := lock.Tools[name]; dup {
				return ToolsLock{}, fmt.Errorf("tools.lock:%d: tool %q pinned twice (%s and %s)", line, name, prev, version)
			}
			lock.Tools[name] = version
		case "image":
			if len(fields) != 2 {
				return ToolsLock{}, fmt.Errorf("tools.lock:%d: image record needs one reference, got %q", line, text)
			}
			lock.Image = fields[1]
		default:
			return ToolsLock{}, fmt.Errorf("tools.lock:%d: unknown record kind %q", line, fields[0])
		}
	}
	if err := sc.Err(); err != nil {
		return ToolsLock{}, fmt.Errorf("tools.lock: %w", err)
	}
	return lock, nil
}
