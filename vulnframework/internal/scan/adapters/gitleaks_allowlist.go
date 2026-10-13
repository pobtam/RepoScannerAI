package adapters

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
)

// Telling "allowlisted" from "removed".
//
// gitleaks stops reporting a secret in both cases, so the ordinary run cannot
// tell them apart. Three further looks can, each bypassing one mechanism, and
// none of them ever retains a credential: every run is --redact, and only the
// file, rule and line of a hit are kept (VM-F-263).
//
//	unfiltered     --config <defaults> --ignore-gitleaks-allow
//	               bypasses .gitleaks.toml and inline gitleaks:allow
//	config-bypass  --config <defaults>
//	               bypasses .gitleaks.toml only; what it adds over the
//	               ordinary run is the config's doing, and what the unfiltered
//	               run adds beyond it is an inline comment's
//	ignore-check   --source <absolute path of one file> per file named in
//	               .gitleaksignore
//
// .gitleaksignore cannot be bypassed by a flag: gitleaks reads it from the
// scanned directory whatever --gitleaks-ignore-path says. Its entries are
// gitleaks fingerprints — file:rule:line, no secret in them — so they name what
// they hide, but an entry can be stale. Each named file is therefore scanned
// on its own by absolute path; the fingerprint gitleaks then computes no
// longer matches the entry, so the hit is reported, and only an entry whose
// file, rule and line still hold a secret becomes evidence. This relies on how
// the pinned gitleaks forms fingerprints; a tools.lock bump must re-check it.

// The Aux keys the evidence travels under. NUL-prefixed so they cannot collide
// with a repository file. Exported for fixture tests, which replay captured
// output through them.
const (
	AuxGitleaksUnfiltered   = "\x00gitleaks/unfiltered.json"
	AuxGitleaksConfigBypass = "\x00gitleaks/config-bypass.json"
	AuxGitleaksIgnoreCheck  = "\x00gitleaks/ignore-check.json"
	gitleaksConfigFile      = ".gitleaks.toml"
	gitleaksIgnoreFile      = ".gitleaksignore"
)

// defaultGitleaksConfig is gitleaks' own default rule set and nothing else.
const defaultGitleaksConfig = "[extend]\nuseDefault = true\n"

func (a *Gitleaks) collectAllowlistEvidence(ctx context.Context, dir string) (map[string][]byte, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	cfg, err := os.CreateTemp("", "vf-gitleaks-defaults-*.toml")
	if err != nil {
		return nil, err
	}
	defer os.Remove(cfg.Name())
	if _, err := cfg.WriteString(defaultGitleaksConfig); err != nil {
		cfg.Close()
		return nil, err
	}
	if err := cfg.Close(); err != nil {
		return nil, err
	}

	aux := map[string][]byte{}
	run := func(key string, args ...string) error {
		res, err := a.Runner.Run(ctx, dir, "gitleaks", gitleaksArgs(args...)...)
		if err != nil {
			return err
		}
		aux[key] = res.Stdout
		return nil
	}
	if err := run(AuxGitleaksUnfiltered, "--config", cfg.Name(), "--ignore-gitleaks-allow"); err != nil {
		return nil, err
	}

	if b, err := os.ReadFile(filepath.Join(dir, gitleaksConfigFile)); err == nil {
		aux[gitleaksConfigFile] = b
		if err := run(AuxGitleaksConfigBypass, "--config", cfg.Name()); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	if b, err := os.ReadFile(filepath.Join(dir, gitleaksIgnoreFile)); err == nil {
		aux[gitleaksIgnoreFile] = b
		var checked []json.RawMessage
		for _, file := range ignoredFiles(parseIgnoreEntries(b)) {
			res, err := a.Runner.Run(ctx, dir, "gitleaks", gitleaksArgs(
				"--source", filepath.Join(abs, file), "--config", cfg.Name(), "--ignore-gitleaks-allow")...)
			if err != nil {
				return nil, err
			}
			var hits []json.RawMessage
			if len(bytes.TrimSpace(res.Stdout)) > 0 {
				if err := json.Unmarshal(res.Stdout, &hits); err != nil {
					return nil, fmt.Errorf("checking %s: %w", file, err)
				}
			}
			checked = append(checked, hits...)
		}
		encoded, err := json.Marshal(checked)
		if err != nil {
			return nil, err
		}
		aux[AuxGitleaksIgnoreCheck] = encoded
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return aux, nil
}

// allowlistedFindings builds findings for secrets only the looks past the
// allowlists found. It is a pure function of the bytes in out, like Normalize.
func (a *Gitleaks) allowlistedFindings(out scan.RawOutput, ordinary []gitleaksHit) ([]model.RawFinding, error) {
	unfilteredRaw, ok := out.Aux[AuxGitleaksUnfiltered]
	if !ok {
		return nil, nil
	}
	key := func(file, rule string) string { return file + "\x00" + rule }
	reported := map[string]bool{}
	for _, h := range ordinary {
		reported[key(relPath(h.File, out.Dir), h.RuleID)] = true
	}

	parse := func(name string, b []byte) ([]gitleaksHit, error) {
		var hits []gitleaksHit
		if len(bytes.TrimSpace(b)) == 0 {
			return nil, nil
		}
		if err := json.Unmarshal(b, &hits); err != nil {
			return nil, fmt.Errorf("gitleaks: parsing the %s report: %w", name, err)
		}
		return hits, nil
	}
	unfiltered, err := parse("unfiltered", unfilteredRaw)
	if err != nil {
		return nil, err
	}
	configBypass, err := parse("config-bypass", out.Aux[AuxGitleaksConfigBypass])
	if err != nil {
		return nil, err
	}
	ignoreCheck, err := parse("ignore-check", out.Aux[AuxGitleaksIgnoreCheck])
	if err != nil {
		return nil, err
	}

	config, hasConfig := out.Aux[gitleaksConfigFile]
	byConfig := map[string]bool{}
	for _, h := range configBypass {
		byConfig[key(relPath(h.File, out.Dir), h.RuleID)] = true
	}
	configEvidence := model.Allowlist{
		Mechanism: model.AllowlistConfig, Path: gitleaksConfigFile,
		ConfigSHA256: sha256Hex(config), Description: allowlistDescriptions(config),
	}

	var hidden []gitleaksHit
	evidence := map[string]*model.Allowlist{}
	for _, h := range unfiltered {
		file := relPath(h.File, out.Dir)
		k := key(file, h.RuleID)
		if reported[k] || evidence[k] != nil {
			continue
		}
		if hasConfig && byConfig[k] {
			e := configEvidence
			evidence[k] = &e
		} else {
			evidence[k] = &model.Allowlist{
				Mechanism: model.AllowlistInline, Path: file,
				Description: fmt.Sprintf("gitleaks:allow comment at line %d", h.StartLine),
			}
		}
		hidden = append(hidden, h)
	}

	ignore := out.Aux[gitleaksIgnoreFile]
	entries := parseIgnoreEntries(ignore)
	for _, h := range ignoreCheck {
		file := relPath(h.File, out.Dir)
		k := key(file, h.RuleID)
		entry, listed := entries[ignoreEntry{File: file, Rule: h.RuleID, Line: h.StartLine}]
		if !listed || reported[k] || evidence[k] != nil {
			continue
		}
		evidence[k] = &model.Allowlist{
			Mechanism: model.AllowlistIgnoreFile, Path: gitleaksIgnoreFile,
			ConfigSHA256: sha256Hex(ignore), Description: "entry " + entry,
		}
		h.File = file
		hidden = append(hidden, h)
	}

	return a.secretFindings(out, hidden, func(h gitleaksHit, file string) *model.Allowlist {
		return evidence[key(file, h.RuleID)]
	}), nil
}

type ignoreEntry struct {
	File, Rule string
	Line       int
}

// parseIgnoreEntries reads .gitleaksignore: one fingerprint per line,
// file:rule:line for the working tree. Commit-qualified entries
// (commit:file:rule:line) apply to history, which this run does not scan, and
// are skipped. An entry naming a path outside the repository is skipped too:
// it can hide nothing here, and must not make this scanner read beyond the
// clone.
func parseIgnoreEntries(b []byte) map[ignoreEntry]string {
	out := map[ignoreEntry]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(parts[2], "%d", &n); err != nil {
			continue
		}
		file := filepath.ToSlash(filepath.Clean(parts[0]))
		if filepath.IsAbs(file) || file == ".." || strings.HasPrefix(file, "../") {
			continue
		}
		out[ignoreEntry{File: file, Rule: parts[1], Line: n}] = line
	}
	return out
}

func ignoredFiles(entries map[ignoreEntry]string) []string {
	seen := map[string]bool{}
	var out []string
	for e := range entries {
		if !seen[e.File] {
			seen[e.File] = true
			out = append(out, e.File)
		}
	}
	sort.Strings(out)
	return out
}

var descriptionLine = regexp.MustCompile(`^\s*description\s*=\s*(?:"([^"]*)"|'([^']*)')`)

// allowlistDescriptions collects the descriptions of a config's allowlist
// tables, for the audit record. Best effort and never a decision input:
// detection is gitleaks' own behaviour, observed, not this parse.
func allowlistDescriptions(config []byte) string {
	var out []string
	inAllowlist := false
	sc := bufio.NewScanner(bytes.NewReader(config))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inAllowlist = strings.Contains(line, "allowlist")
			continue
		}
		if !inAllowlist {
			continue
		}
		if m := descriptionLine.FindStringSubmatch(line); m != nil {
			out = append(out, m[1]+m[2])
		}
	}
	return strings.Join(out, "; ")
}

func sha256Hex(b []byte) string {
	if b == nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// GitleaksFixtureAux assembles the Aux a real Run would have produced, from
// the files a fixture capture records. Test support: it keeps the key names in
// one place.
func GitleaksFixtureAux(unfiltered, configBypass, ignoreCheck, config, ignore []byte) map[string][]byte {
	aux := map[string][]byte{AuxGitleaksUnfiltered: unfiltered}
	if config != nil {
		aux[gitleaksConfigFile] = config
		aux[AuxGitleaksConfigBypass] = configBypass
	}
	if ignore != nil {
		aux[gitleaksIgnoreFile] = ignore
		aux[AuxGitleaksIgnoreCheck] = ignoreCheck
	}
	return aux
}
