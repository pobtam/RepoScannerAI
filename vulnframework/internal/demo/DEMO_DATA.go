// ============================================================================
//
//	DEMONSTRATION DATA — NOT REAL SCAN OUTPUT
//
// Every repository, advisory, credential and dependency named in this file is
// FABRICATED. None of it came from a scanner, none of it describes a real
// system, and none of the advisory identifiers is a real advisory. The
// organisation is called `demo-org` and the modules are called
// `example.com/...` precisely so that a screenshot, a copied number or a
// quoted finding from this data cannot be mistaken for a fleet's actual
// security position.
//
// It exists so the framework can be run and looked at with no credentials, no
// network, no Docker and no scanners installed.
//
// WHAT IT IS NOT:
//
//   - not a benchmark: the counts are chosen to make the interface's honesty
//     features visible, not to resemble a typical fleet;
//   - not a fixture for correctness tests: those use real captured scanner
//     output in testdata/fixtures, because a test whose input was invented is
//     a test of the invention;
//   - not a substitute for a supervised first run against a real repository,
//     which is a named human milestone (see FINAL-STATUS.md).
//
// HOW IT IS USED: this file supplies fabricated SCANNER OUTPUT, and the demo
// then runs the REAL pipeline over it — the real store, the real triage,
// scoring, policy, ticket, remediation and report passes. Nothing here
// constructs a finding, a priority or a state. That is deliberate: a demo that
// wrote its own findings could show a field the pipeline cannot produce, which
// is the defect class this build spent twelve phases learning to detect.
//
// ============================================================================
package demo

import (
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/store"
)

// Repos is the fabricated fleet.
//
// Deliberately uneven: different tiers, one JavaScript repository, one with no
// test suite (which constrains what the framework may do there), and one that
// will never produce a qualifying scan.
func Repos() []store.Repo {
	return []store.Repo{
		{
			Name: "demo-org/payments-api", Tier: 1, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-payments", "team-security"},
		},
		{
			Name: "demo-org/platform-common", Tier: 1, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-platform"},
		},
		{
			Name: "demo-org/checkout-web", Tier: 2, Languages: []string{"javascript", "go"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-checkout"},
		},
		{
			Name: "demo-org/batch-jobs", Tier: 2, Languages: []string{"go"},
			// No test suite: remediation cannot be verified here, so the
			// framework does not attempt it. The interface has to say so.
			HasTestSuite: false, ModuleTopology: "multi",
			Codeowners: []string{"team-data"},
		},
		{
			Name: "demo-org/legacy-reporting", Tier: 3, Languages: []string{"go"},
			HasTestSuite: false, ModuleTopology: "single",
			Codeowners: []string{"team-data"},
		},
		{
			Name: "demo-org/edge-proxy", Tier: 1, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-platform"},
		},
	}
}

// RegistryYAML declares which modules this fabricated organisation owns.
//
// The trigger is `tag`, so the demo shows the case where merging the upstream
// fix is NOT sufficient — the version has to be published before consumers can
// resolve it, and a reader who stops at the merge believes the wave is done.
const RegistryYAML = `version: 1
wave2_trigger: tag
modules:
  example.com/demo-org/platform-common: demo-org/platform-common
`

// Manifests is the dependency manifest each repository's scan read.
//
// This is what the reverse-dependency index is built from, and it is why the
// wave view can say that three repositories depend on one internal module —
// including one pinned to an older version and one with a replace directive
// that a version bump would not move.
func Manifests() map[string][]scan.ModuleDep {
	return map[string][]scan.ModuleDep{
		"demo-org/payments-api": {
			{Module: "example.com/demo-org/platform-common", Version: "v1.8.0", Direct: true},
			{Module: "example.com/crypto-lib", Version: "v0.31.0", Direct: true},
			{Module: "example.com/yaml-parse", Version: "v3.0.1", Direct: true},
			{Module: "example.com/http-router", Version: "v1.12.4", Direct: true},
			{Module: "example.com/log-shim", Version: "v0.4.2", Direct: false},
		},
		"demo-org/platform-common": {
			{Module: "example.com/crypto-lib", Version: "v0.31.0", Direct: true},
			{Module: "example.com/proto-runtime", Version: "v1.33.0", Direct: true},
		},
		"demo-org/checkout-web": {
			// Pinned two minors behind: the wave has to say the consumers are
			// on different versions, because a single-target bump may not
			// build for the laggard.
			{Module: "example.com/demo-org/platform-common", Version: "v1.6.2", Direct: true},
			{Module: "example.com/json-stream", Version: "v2.1.0", Direct: true},
		},
		"demo-org/batch-jobs": {
			// A replace directive: bumping the version would not change what
			// this repository builds, so the wave must EXCLUDE it and say why
			// rather than counting it as advanced (VM-F-608).
			{Module: "example.com/demo-org/platform-common", Version: "v1.8.0",
				Direct: true, Replaced: true},
			{Module: "example.com/csv-reader", Version: "v0.9.0", Direct: true},
		},
		"demo-org/edge-proxy": {
			{Module: "example.com/crypto-lib", Version: "v0.31.0", Direct: true},
			{Module: "example.com/http-router", Version: "v1.12.4", Direct: true},
		},
	}
}

// --- fabricated scanner output ----------------------------------------------

// dep builds a fabricated dependency finding.
func dep(repo, id, cve, module, current, fixed string, sev model.Severity,
	reach model.Reachable, class model.DepClass) model.RawFinding {
	f := model.RawFinding{
		Repo: repo, Category: model.CategoryDependency,
		PrimaryID: id, Aliases: []string{cve},
		Tool: "govulncheck", ToolVersion: "v1.8.0",
		Module: module, ModuleMajor: "v0",
		ImportPath: []string{repo, module},
		Versions:   model.Versions{Current: current, Fixed: fixed},
		Classification: model.Classification{
			Severity: sev, CVSS: cvssFor(sev), Reachable: reach, DepClass: class,
		},
		AdvisoryURL: "https://demo.example/advisories/" + id,
	}
	return f
}

// firstPartyDep is a finding inside the organisation's own shared module,
// reached through it by a consumer.
func firstPartyDep(repo, id, cve string, sev model.Severity, reach model.Reachable) model.RawFinding {
	f := dep(repo, id, cve, "example.com/crypto-lib", "v0.31.0", "v0.32.0", sev, reach, model.DepProduction)
	// The import path traverses the organisation's own module, which is what
	// makes this a first-party propagation rather than an independent finding.
	f.ImportPath = []string{repo, "example.com/demo-org/platform-common/crypto",
		"example.com/crypto-lib"}
	return f
}

func code(repo, rule, file string, line int, sev model.Severity) model.RawFinding {
	return model.RawFinding{
		Repo: repo, Category: model.CategoryCode,
		Tool: "gosec", ToolVersion: "v2.22.9", RuleID: rule, PrimaryID: rule,
		File: file, Line: line,
		Classification: model.Classification{
			Severity: sev, CVSS: cvssFor(sev), Reachable: model.ReachableUnknown,
		},
	}
}

// secret is a fabricated credential finding.
//
// It carries the DETECTOR and the credential CLASS and no value, because the
// record has nowhere to put one (VM-F-263) — which is the property the
// interface's disclosure test asserts.
func secret(repo, detector, credType, file string, line int) model.RawFinding {
	return model.RawFinding{
		Repo: repo, Category: model.CategorySecret,
		Tool: "gitleaks", ToolVersion: "v8.28.0",
		DetectorRuleID: detector, PrimaryID: detector,
		File: file, Line: line, CredentialType: credType,
		Classification: model.Classification{
			Severity: model.SeverityCritical, Reachable: model.ReachableUnknown,
		},
	}
}

func config(repo, check, file string, line int, sev model.Severity) model.RawFinding {
	return model.RawFinding{
		Repo: repo, Category: model.CategoryConfig,
		Tool: "trivy", ToolVersion: "v0.58.1", CheckID: check, PrimaryID: check,
		File: file, Line: line,
		Classification: model.Classification{Severity: sev, Reachable: model.ReachableUnknown},
	}
}

func cvssFor(s model.Severity) float64 {
	switch s {
	case model.SeverityCritical:
		return 9.1
	case model.SeverityHigh:
		return 7.5
	case model.SeverityMedium:
		return 5.4
	case model.SeverityLow:
		return 3.1
	default:
		return 0
	}
}

// --- the advisories, as the fabricated scanners reported them ---------------

// Baseline is what every run observes unless a later run drops it.
//
// The set is chosen so the interface has one of each thing to show: a
// known-exploited critical, a reachable high, an unreachable one, a
// development-only dependency, a transitive one, a code finding, a
// credential, a misconfiguration, and one advisory with NO fix available.
func Baseline() map[string][]model.RawFinding {
	transitive := dep("demo-org/payments-api", "DEMO-2026-0007", "CVE-DEMO-70007",
		"example.com/log-shim", "v0.4.2", "v0.4.3", model.SeverityMedium,
		model.ReachableUnknown, model.DepProduction)
	transitive.Classification.Transitive = true

	devOnly := dep("demo-org/checkout-web", "DEMO-2026-0008", "CVE-DEMO-70008",
		"example.com/json-stream", "v2.1.0", "v2.2.0", model.SeverityHigh,
		model.ReachableFalse, model.DepDevelopment)

	noFix := dep("demo-org/legacy-reporting", "DEMO-2026-0009", "CVE-DEMO-70009",
		"example.com/csv-reader", "v0.9.0", "", model.SeverityHigh,
		model.ReachableTrue, model.DepProduction)

	return map[string][]model.RawFinding{
		"demo-org/payments-api": {
			// Known-exploited and reachable: the top of any queue.
			dep("demo-org/payments-api", "DEMO-2026-0001", "CVE-DEMO-70001",
				"example.com/http-router", "v1.12.4", "v1.12.9",
				model.SeverityCritical, model.ReachableTrue, model.DepProduction),
			// Reachability unknown, which is neither reachable nor safe.
			dep("demo-org/payments-api", "DEMO-2026-0002", "CVE-DEMO-70002",
				"example.com/yaml-parse", "v3.0.1", "v3.0.4",
				model.SeverityHigh, model.ReachableUnknown, model.DepProduction),
			transitive,
			code("demo-org/payments-api", "G401", "internal/token/sign.go", 88, model.SeverityHigh),
			code("demo-org/payments-api", "G404", "internal/idgen/random.go", 23, model.SeverityMedium),
			secret("demo-org/payments-api", "aws-access-token", "aws_access_key",
				"deploy/staging.env", 4),
			config("demo-org/payments-api", "DEMO-K8S-001", "deploy/payments.yaml", 31,
				model.SeverityMedium),
		},
		"demo-org/platform-common": {
			// The upstream first-party finding three consumers wait on.
			dep("demo-org/platform-common", "DEMO-2026-0003", "CVE-DEMO-70003",
				"example.com/crypto-lib", "v0.31.0", "v0.32.0",
				model.SeverityCritical, model.ReachableTrue, model.DepProduction),
			dep("demo-org/platform-common", "DEMO-2026-0004", "CVE-DEMO-70004",
				"example.com/proto-runtime", "v1.33.0", "v1.34.1",
				model.SeverityMedium, model.ReachableFalse, model.DepProduction),
		},
		"demo-org/checkout-web": {
			// The same crypto advisory, reached THROUGH the organisation's own
			// shared module: this is the consumer the wave blocks.
			firstPartyDep("demo-org/checkout-web", "DEMO-2026-0003", "CVE-DEMO-70003",
				model.SeverityCritical, model.ReachableTrue),
			devOnly,
			code("demo-org/checkout-web", "G402", "server/proxy.go", 145, model.SeverityHigh),
		},
		"demo-org/batch-jobs": {
			// A consumer the wave cannot advance: its manifest replaces the
			// shared module with a local path.
			firstPartyDep("demo-org/batch-jobs", "DEMO-2026-0003", "CVE-DEMO-70003",
				model.SeverityCritical, model.ReachableUnknown),
			// No test suite in this repository, so nothing here can be
			// remediated automatically whatever its class.
			dep("demo-org/batch-jobs", "DEMO-2026-0005", "CVE-DEMO-70005",
				"example.com/csv-reader", "v0.9.0", "v0.9.4",
				model.SeverityHigh, model.ReachableTrue, model.DepProduction),
		},
		"demo-org/legacy-reporting": {noFix},
		"demo-org/edge-proxy": {
			firstPartyDep("demo-org/edge-proxy", "DEMO-2026-0003", "CVE-DEMO-70003",
				model.SeverityCritical, model.ReachableFalse),
			dep("demo-org/edge-proxy", "DEMO-2026-0006", "CVE-DEMO-70006",
				"example.com/http-router", "v1.12.4", "v1.12.9",
				model.SeverityCritical, model.ReachableTrue, model.DepProduction),
			secret("demo-org/edge-proxy", "generic-api-key", "api_key",
				"config/upstream.toml", 12),
		},
	}
}

// The fabricated advisory aliases are deliberately NOT valid CVE identifiers:
// `CVE-DEMO-70001` cannot collide with a real advisory, because a real one
// carries a numeric year. A plausible-looking CVE number in demonstration data
// eventually becomes a real advisory about something else, and then a reader
// follows it to a page describing a vulnerability this fleet does not have.
//
// KEVEntries and EPSSEntries are what the fabricated exploitation feeds say.
//
// Deliberately incomplete: several advisories are in NEITHER catalogue, so the
// interface has to render "nothing answered" as an absence rather than as a
// measurement of zero. That distinction is the one the Producer-Coverage Audit
// found missing, and the demo should show it working.
func KEVEntries() []string {
	return []string{"CVE-DEMO-70001", "CVE-DEMO-70003"}
}

// EPSSEntries maps an identifier to its fabricated exploit-prediction score.
func EPSSEntries() map[string]float64 {
	return map[string]float64{
		"CVE-DEMO-70001": 0.94,
		"CVE-DEMO-70003": 0.71,
		"CVE-DEMO-70002": 0.08,
		"CVE-DEMO-70006": 0.55,
		// 70004, 70005, 70007, 70008 and 70009 are in neither catalogue.
	}
}

// NotListedInKEV are advisories the catalogue was CHECKED for and does not
// list, which is an answer — distinct from the ones nothing answered about.
func NotListedInKEV() []string {
	return []string{"CVE-DEMO-70002", "CVE-DEMO-70006"}
}
