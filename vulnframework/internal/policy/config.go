package policy

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/wanaware/vulnframework/internal/model"
)

// Action is what the table says to do with a class.
type Action string

const (
	ActionAuto             Action = "auto"
	ActionTicket           Action = "ticket"
	ActionRequireTestSuite Action = "require_test_suite"
)

// AllActions is the closed enumeration.
var AllActions = []Action{ActionAuto, ActionTicket, ActionRequireTestSuite}

// Valid reports whether a is a member of the closed enumeration.
func (a Action) Valid() bool {
	for _, v := range AllActions {
		if v == a {
			return true
		}
	}
	return false
}

// Config is the parsed policy table (VM-AD §10.1).
type Config struct {
	Version int `yaml:"version"`

	Defaults struct {
		MaxFindingsPerPR     int      `yaml:"max_findings_per_pr"`
		MaxFindingsPerPRCode int      `yaml:"max_findings_per_pr_code"`
		AutoMerge            bool     `yaml:"auto_merge"`
		DenyPaths            []string `yaml:"deny_paths"`
		AgentBudget          struct {
			MaxIterations   int `yaml:"max_iterations"`
			MaxWallClockSec int `yaml:"max_wall_clock_sec"`
		} `yaml:"agent_budget"`
	} `yaml:"defaults"`

	// Tiers is tier -> language -> class -> action.
	Tiers map[string]map[string]map[string]Action `yaml:"tiers"`

	Categories struct {
		Secret struct {
			Remediate string `yaml:"remediate"`
			Ticket    string `yaml:"ticket"`
			Severity  string `yaml:"severity"`
		} `yaml:"secret"`
	} `yaml:"categories"`
}

// LoadConfig reads and validates a policy file.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("policy: %w", err)
	}
	return ParseConfig(b)
}

// ParseConfig decodes and validates a policy table.
//
// Validation is what makes totality a property of the loaded config rather than
// a hope about it: a table missing any (tier, language, class) refuses to load,
// naming every gap. Discovering the hole at start-up is the whole point —
// discovering it at decision time would mean routing findings through it first.
func ParseConfig(b []byte) (Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("policy: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks the table covers its whole declared domain.
func (c Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("policy: unsupported version %d", c.Version)
	}

	var gaps []string
	for _, tier := range Tiers {
		langs, ok := c.Tiers[strconv.Itoa(tier)]
		if !ok {
			gaps = append(gaps, fmt.Sprintf("tier %d is absent", tier))
			continue
		}
		for _, lang := range Languages {
			classes, ok := langs[string(lang)]
			if !ok {
				gaps = append(gaps, fmt.Sprintf("tier %d has no %s", tier, lang))
				continue
			}
			for _, class := range Classes {
				action, ok := classes[string(class)]
				if !ok {
					gaps = append(gaps, fmt.Sprintf("tier %d / %s has no %s", tier, lang, class))
					continue
				}
				if !action.Valid() {
					gaps = append(gaps, fmt.Sprintf("tier %d / %s / %s has invalid action %q", tier, lang, class, action))
				}
			}
			// An entry for a class the engine does not know is a typo, and a
			// typo in a decision table silently removes a rule.
			for name := range classes {
				if !knownClass(name) {
					gaps = append(gaps, fmt.Sprintf("tier %d / %s declares unknown class %q", tier, lang, name))
				}
			}
		}
	}

	// Major bumps must not be auto by default (VM-F-406). This is checked here
	// rather than left to review: the table is editable, and an edit that turns
	// majors on would otherwise ship silently.
	for _, tier := range Tiers {
		for _, lang := range Languages {
			if c.Tiers[strconv.Itoa(tier)][string(lang)][string(ClassDependencyMajor)] == ActionAuto {
				gaps = append(gaps, fmt.Sprintf(
					"tier %d / %s auto-remediates %s; major-version upgrades are not automatic by default (VM-F-406)",
					tier, lang, ClassDependencyMajor))
			}
		}
	}

	// Secrets are never remediated, under any configuration (VM-F-407).
	if r := strings.ToLower(strings.TrimSpace(c.Categories.Secret.Remediate)); r != "never" {
		gaps = append(gaps, fmt.Sprintf(
			"categories.secret.remediate is %q; it must be \"never\" and is not overridable (VM-F-407)", r))
	}

	if len(gaps) > 0 {
		sort.Strings(gaps)
		return fmt.Errorf("policy: the decision table is not total:\n  %s", strings.Join(gaps, "\n  "))
	}
	return nil
}

func knownClass(name string) bool {
	for _, c := range Classes {
		if string(c) == name {
			return true
		}
	}
	return false
}

// Action returns the table's action for a (tier, language, class).
//
// A miss is an error naming exactly what was unmatched, never a default.
func (c Config) Action(tier int, lang Language, class Class) (Action, error) {
	langs, ok := c.Tiers[strconv.Itoa(tier)]
	if !ok {
		return "", &ErrUnmatched{Tier: tier, Language: lang, Class: class,
			Detail: fmt.Sprintf("no entry for tier %d", tier)}
	}
	classes, ok := langs[string(lang)]
	if !ok {
		return "", &ErrUnmatched{Tier: tier, Language: lang, Class: class,
			Detail: fmt.Sprintf("tier %d has no entry for language %q", tier, lang)}
	}
	action, ok := classes[string(class)]
	if !ok {
		return "", &ErrUnmatched{Tier: tier, Language: lang, Class: class,
			Detail: fmt.Sprintf("tier %d / %s has no entry for class %q", tier, lang, class)}
	}
	if !action.Valid() {
		return "", &ErrUnmatched{Tier: tier, Language: lang, Class: class,
			Detail: fmt.Sprintf("action %q is not one of auto, ticket, require_test_suite", action)}
	}
	return action, nil
}

// KnownState reports whether policy evaluates findings in this state.
func (c Config) KnownState(s model.State) bool {
	// Everything except DETECTED: policy runs after triage.
	return s.Valid() && s != model.Detected
}

// --- version parsing --------------------------------------------------------

type semver struct{ major, minor, patch int }

// parseVersion reads the version forms this system encounters: Go modules
// ("v0.36.0"), the Go toolchain ("go1.22.2") and npm ("1.7.9").
func parseVersion(s string) (semver, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return semver{}, false
	}
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "go")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}

	parts := strings.Split(s, ".")
	var out semver
	target := []*int{&out.major, &out.minor, &out.patch}
	for i := 0; i < len(target); i++ {
		if i >= len(parts) {
			break
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return semver{}, false
		}
		*target[i] = n
	}
	return out, true
}
