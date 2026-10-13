// Package fleet is a SYNTHETIC twenty-repository fleet, for exercising the
// fleet-level behaviour that six repositories cannot.
//
// # Everything in this package is fabricated
//
// Every repository, module, advisory, credential class and finding below is
// invented. None of it describes real code, nothing is scanned, no repository
// is contacted and no credential exists anywhere in it. It runs offline with
// the same discipline as `internal/demo`, and every screen it feeds says so.
//
// # Why it exists, and what it is NOT for
//
// It is not a bigger demonstration. The demonstration's job is to show what
// the interface looks like; this one's job is to make the FLEET logic strain:
//
//	planning under a budget smaller than the fleet, over many rounds, so
//	  staleness-first ordering has to be shown to prevent starvation rather
//	  than asserted;
//	every coverage-gap cause occurring often enough that the gap arithmetic
//	  and the staleness distribution are exercised rather than merely present;
//	two first-party waves whose consumers overlap the deferred set, so wave
//	  propagation has to survive a consumer that was not scanned this round;
//	one consumer excluded by a replace directive, because a version bump
//	  would not change what it builds (VM-F-608).
//
// Twenty rather than six because the behaviours above are invisible below the
// point where the budget cannot cover the fleet. At six repositories with any
// realistic budget, nothing is ever deferred and the ordering never has to
// decide anything.
package fleet

import (
	"github.com/wanaware/vulnframework/internal/fingerprint"
	"github.com/wanaware/vulnframework/internal/model"
	"github.com/wanaware/vulnframework/internal/scan"
	"github.com/wanaware/vulnframework/internal/store"
)

// Org is the fabricated organisation. Deliberately not "demo-org": a reader
// looking at two seeded stores must be able to tell which one they have.
const Org = "fleet-org"

// Repos is the twenty-repository fleet.
//
// The spread is chosen so that the fleet-level views have something to
// distinguish: five tier-1 repositories on the critical path, eight tier-2,
// seven tier-3 — and four with NO test suite, which is where remediation
// declines to act because it cannot verify a fix (VM-F-504).
func Repos() []store.Repo {
	return []store.Repo{
		// --- tier 1: the critical path --------------------------------------
		{
			Name: Org + "/core-auth", Tier: 1, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-identity", "team-security"},
		},
		{
			Name: Org + "/payments-gateway", Tier: 1, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-payments", "team-security"},
		},
		{
			Name: Org + "/ledger-service", Tier: 1, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-payments"},
		},
		{
			Name: Org + "/api-edge", Tier: 1, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-platform"},
		},
		{
			Name: Org + "/telemetry-sdk", Tier: 1, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-observability"},
		},

		// --- tier 2 ---------------------------------------------------------
		{
			Name: Org + "/checkout-ui", Tier: 2, Languages: []string{"javascript"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-checkout"},
		},
		{
			Name: Org + "/merchant-portal", Tier: 2, Languages: []string{"javascript"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-merchant"},
		},
		{
			Name: Org + "/notifications", Tier: 2, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-messaging"},
		},
		{
			Name: Org + "/search-indexer", Tier: 2, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "multi",
			Codeowners: []string{"team-search"},
		},
		{
			Name: Org + "/billing-worker", Tier: 2, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-payments"},
		},
		{
			Name: Org + "/partner-api", Tier: 2, Languages: []string{"go", "javascript"},
			HasTestSuite: true, ModuleTopology: "multi",
			Codeowners: []string{"team-partnerships"},
		},
		{
			Name: Org + "/inventory-svc", Tier: 2, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-supply"},
		},
		{
			Name: Org + "/admin-console", Tier: 2, Languages: []string{"javascript"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-internal"},
		},

		// --- tier 3 ---------------------------------------------------------
		{
			Name: Org + "/batch-exports", Tier: 3, Languages: []string{"go"},
			// No test suite: remediation cannot verify a fix here, so none is
			// attempted and the interface has to say why.
			HasTestSuite: false, ModuleTopology: "multi",
			Codeowners: []string{"team-data"},
		},
		{
			Name: Org + "/legacy-billing", Tier: 3, Languages: []string{"go"},
			HasTestSuite: false, ModuleTopology: "single",
			Codeowners: []string{"team-payments"},
		},
		{
			Name: Org + "/docs-site", Tier: 3, Languages: []string{"javascript"},
			HasTestSuite: false, ModuleTopology: "single",
			Codeowners: []string{"team-devrel"},
		},
		{
			Name: Org + "/internal-tools", Tier: 3, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-internal"},
		},
		{
			Name: Org + "/data-pipeline", Tier: 3, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "multi",
			Codeowners: []string{"team-data"},
		},
		{
			Name: Org + "/metrics-agent", Tier: 3, Languages: []string{"go"},
			HasTestSuite: true, ModuleTopology: "single",
			Codeowners: []string{"team-observability"},
		},
		{
			Name: Org + "/sandbox-playground", Tier: 3, Languages: []string{"javascript"},
			HasTestSuite: false, ModuleTopology: "single",
			Codeowners: []string{"team-devrel"},
		},
	}
}

// The two first-party modules the organisation owns, and their owners.
const (
	ModuleCoreAuth     = "example.com/" + Org + "/core-auth"
	ModuleTelemetrySDK = "example.com/" + Org + "/telemetry-sdk"

	OwnerCoreAuth     = Org + "/core-auth"
	OwnerTelemetrySDK = Org + "/telemetry-sdk"
)

// RegistryYAML declares the modules this fabricated organisation owns.
//
// Two of them, deliberately. One wave shows the mechanism; two show that the
// waves do not interfere — a repository consuming BOTH is blocked on two
// different upstream findings at once, and neither wave may claim the other's
// consumers.
const RegistryYAML = `version: 1
wave2_trigger: tag
modules:
  example.com/` + Org + `/core-auth: ` + Org + `/core-auth
  example.com/` + Org + `/telemetry-sdk: ` + Org + `/telemetry-sdk
`

// CoreAuthConsumers are the repositories that depend on the core-auth module.
//
// inventory-svc is in the list and is EXCLUDED from the wave by its replace
// directive — see Manifests. It is listed here because it is a consumer; it is
// excluded there because a version bump would not change what it builds.
var CoreAuthConsumers = []string{
	Org + "/payments-gateway",
	Org + "/ledger-service",
	Org + "/api-edge",
	Org + "/partner-api",
	Org + "/inventory-svc",
}

// TelemetryConsumers are the repositories that depend on the telemetry module.
//
// partner-api appears in both lists on purpose: it is blocked on two separate
// upstream findings, which is the case that catches a wave implementation
// treating "blocked" as a single flag rather than a relationship to a
// particular upstream finding.
var TelemetryConsumers = []string{
	Org + "/notifications",
	Org + "/search-indexer",
	Org + "/billing-worker",
	Org + "/metrics-agent",
	Org + "/data-pipeline",
	Org + "/partner-api",
}

// ReplaceExcluded is the consumer a version bump would not move.
const ReplaceExcluded = Org + "/inventory-svc"

// Manifests is the dependency manifest each repository's scan read.
//
// This is what the reverse-dependency index is built from. Three things in it
// are deliberate and are what the wave logic is tested against:
//
//	inventory-svc carries a REPLACE directive on the core-auth module, so a
//	  bump to the published version changes nothing it builds and the wave
//	  must exclude it with a reason rather than counting it as advanced;
//	consumers sit on DIFFERENT versions of the shared module, because a
//	  single-target bump may not build for the laggard;
//	partner-api consumes both first-party modules, so it belongs to two waves.
func Manifests() map[string][]scan.ModuleDep {
	m := map[string][]scan.ModuleDep{}

	// Wave A — core-auth, and its consumers on a spread of versions.
	versions := map[string]string{
		Org + "/payments-gateway": "v2.4.0",
		Org + "/ledger-service":   "v2.4.0",
		Org + "/api-edge":         "v2.2.1", // two minors behind
		Org + "/partner-api":      "v2.3.0",
		Org + "/inventory-svc":    "v2.4.0",
	}
	for _, consumer := range CoreAuthConsumers {
		dep := scan.ModuleDep{Module: ModuleCoreAuth, Version: versions[consumer], Direct: true}
		if consumer == ReplaceExcluded {
			// VM-F-608: the bump cannot reach this repository.
			dep.Replaced = true
		}
		m[consumer] = append(m[consumer], dep)
	}

	// Wave B — telemetry-sdk.
	for _, consumer := range TelemetryConsumers {
		m[consumer] = append(m[consumer], scan.ModuleDep{
			Module: ModuleTelemetrySDK, Version: "v1.9.2", Direct: true,
		})
	}

	// The owners' own dependencies: the third-party module whose advisory is
	// what propagates through the shared code.
	m[OwnerCoreAuth] = append(m[OwnerCoreAuth],
		scan.ModuleDep{Module: "example.com/crypto-lib", Version: "v0.31.0", Direct: true},
		scan.ModuleDep{Module: "example.com/jwt-parse", Version: "v1.4.0", Direct: true},
	)
	m[OwnerTelemetrySDK] = append(m[OwnerTelemetrySDK],
		scan.ModuleDep{Module: "example.com/proto-runtime", Version: "v1.33.0", Direct: true},
	)

	// Ordinary third-party dependencies, so the fleet is not made entirely of
	// first-party relationships.
	third := map[string][]scan.ModuleDep{
		Org + "/checkout-ui":        {{Module: "example.com/json-stream", Version: "v2.1.0", Direct: true}},
		Org + "/merchant-portal":    {{Module: "example.com/json-stream", Version: "v2.1.0", Direct: true}},
		Org + "/admin-console":      {{Module: "example.com/json-stream", Version: "v2.0.4", Direct: true}},
		Org + "/batch-exports":      {{Module: "example.com/csv-reader", Version: "v0.9.0", Direct: true}},
		Org + "/legacy-billing":     {{Module: "example.com/http-router", Version: "v1.12.4", Direct: true}},
		Org + "/internal-tools":     {{Module: "example.com/yaml-parse", Version: "v3.0.1", Direct: true}},
		Org + "/docs-site":          {{Module: "example.com/json-stream", Version: "v2.1.0", Direct: true}},
		Org + "/sandbox-playground": {{Module: "example.com/json-stream", Version: "v2.1.0", Direct: true}},
		Org + "/data-pipeline":      {{Module: "example.com/csv-reader", Version: "v0.9.0", Direct: true}},
		Org + "/search-indexer":     {{Module: "example.com/yaml-parse", Version: "v3.0.1", Direct: true}},
	}
	for repo, deps := range third {
		m[repo] = append(m[repo], deps...)
	}
	return m
}

// --- fabricated scanner output ----------------------------------------------

// The advisories this fabricated organisation's scanners report.
//
// Every one is invented, and the IDENTIFIER SHAPES are deliberate. The
// framework resolves an advisory to a canonical identifier by a fixed
// precedence — GO-ID > GHSA > CVE > OSV > tool rule id (VM-AD §4.1) — and a
// fixture whose identifiers match none of those namespaces never exercises
// that rule at all: every identifier falls into the "other" class and the
// winner is decided by the lexicographic tiebreak instead.
//
// So the aliases below are correctly shaped. Two carry a GHSA, which outranks
// a CVE; the rest carry a CVE, which outranks the tool's own identifier. The
// canonical identifier for each is therefore what CanonicalID computes, and
// that is what the store holds.
type Advisory struct {
	// Tool is the identifier the scanner reported it under.
	Tool string
	// Aliases are the published identifiers for the same defect.
	Aliases []string
}

// ID returns the canonical identifier, by the framework's own precedence rule.
//
// Computed rather than written down, so the fixture and the pipeline cannot
// disagree about what a finding will be filed under.
func (a Advisory) ID() string { return fingerprint.ResolveAlias(a.Tool, a.Aliases) }

var (
	// AdvCrypto propagates through core-auth: the WAVE advisory, reported in
	// the owner and in every consumer that reaches it. It carries a GHSA, so
	// its canonical identifier is the GHSA rather than the CVE.
	AdvCrypto = Advisory{"FLEET-2026-0001", []string{"CVE-2026-21001", "GHSA-2345-6789-cfgh"}}
	// AdvProto propagates through telemetry-sdk.
	AdvProto = Advisory{"FLEET-2026-0002", []string{"CVE-2026-21002"}}

	AdvJSON   = Advisory{"FLEET-2026-0003", []string{"CVE-2026-21003"}}
	AdvCSV    = Advisory{"FLEET-2026-0004", []string{"CVE-2026-21004"}}
	AdvYAML   = Advisory{"FLEET-2026-0005", []string{"CVE-2026-21005", "GHSA-34cf-67gh-9jmp"}}
	AdvRouter = Advisory{"FLEET-2026-0006", []string{"CVE-2026-21006"}}
	// AdvNoFix has no published fix, so policy must route it to a human
	// rather than attempt a bump to a version that does not exist.
	AdvNoFix = Advisory{"FLEET-2026-0008", []string{"CVE-2026-21008"}}
	// AdvLate is published near the end of the simulation, so the fleet ends
	// with fresh remediation work still in review rather than everything
	// settled — the state a reviewer actually spends their time in.
	AdvLate = Advisory{"FLEET-2026-0009", []string{"CVE-2026-21009"}}
)

// LateAdvisoryRepos carry AdvLate once it is published (see findingsForRound).
// Tier 2 and 3 with test suites, so remediation can act and verify.
var LateAdvisoryRepos = []string{
	Org + "/metrics-agent", Org + "/notifications", Org + "/billing-worker",
}

// LateAdvisoryFinding is AdvLate as reported in repo.
func LateAdvisoryFinding(repo string) model.RawFinding {
	return dep(repo, AdvLate, "example.com/xml-codec", "v1.2.0", "v1.2.5",
		model.SeverityHigh, model.ReachableTrue, model.DepProduction)
}

func dep(repo string, adv Advisory, module, current, fixed string, sev model.Severity,
	reach model.Reachable, class model.DepClass) model.RawFinding {
	return model.RawFinding{
		Repo: repo, Category: model.CategoryDependency,
		PrimaryID: adv.Tool, Aliases: adv.Aliases,
		Tool: "govulncheck", ToolVersion: "v1.8.0",
		Module: module, ModuleMajor: "v0",
		ImportPath: []string{repo, module},
		Versions:   model.Versions{Current: current, Fixed: fixed},
		Classification: model.Classification{
			Severity: sev, CVSS: cvssFor(sev), Reachable: reach, DepClass: class,
		},
		AdvisoryURL: "https://fleet.example/advisories/" + adv.Tool,
	}
}

// throughFirstParty is the same advisory reached THROUGH one of the
// organisation's own modules.
//
// The import path is what makes it a first-party propagation rather than an
// independent finding: the consumer does not depend on the vulnerable module
// directly, it depends on the shared module that does. Nothing else in the
// finding records that hop (VM-AD §12.2).
func throughFirstParty(repo string, adv Advisory, shared, module, current, fixed string,
	sev model.Severity, reach model.Reachable) model.RawFinding {
	f := dep(repo, adv, module, current, fixed, sev, reach, model.DepProduction)
	f.ImportPath = []string{repo, shared, module}
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

// secret carries the DETECTOR and the credential CLASS and no value, because
// the record has nowhere to put one (VM-F-263).
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

// Baseline is what every round observes unless a later round drops it.
//
// Roughly three findings per repository across all four categories. The
// density is deliberate: enough that the fleet views have to aggregate, few
// enough that a person can still read a repository's page and check the
// arithmetic by hand — which is the only way an aggregate is ever actually
// verified.
func Baseline() map[string][]model.RawFinding {
	out := map[string][]model.RawFinding{}
	add := func(f model.RawFinding) { out[f.Repo] = append(out[f.Repo], f) }

	// --- the wave advisories --------------------------------------------
	//
	// The SAME advisory in the owner and in every consumer. That is the
	// case the merge and the wave both have to get right: one defect, many
	// repositories, one upstream fix.
	add(dep(OwnerCoreAuth, AdvCrypto,
		"example.com/crypto-lib", "v0.31.0", "v0.32.0",
		model.SeverityCritical, model.ReachableTrue, model.DepProduction))
	for _, consumer := range CoreAuthConsumers {
		add(throughFirstParty(consumer, AdvCrypto,
			ModuleCoreAuth+"/signing", "example.com/crypto-lib", "v0.31.0", "v0.32.0",
			model.SeverityCritical, model.ReachableTrue))
	}

	add(dep(OwnerTelemetrySDK, AdvProto,
		"example.com/proto-runtime", "v1.33.0", "v1.34.1",
		model.SeverityHigh, model.ReachableTrue, model.DepProduction))
	for _, consumer := range TelemetryConsumers {
		add(throughFirstParty(consumer, AdvProto,
			ModuleTelemetrySDK+"/export", "example.com/proto-runtime", "v1.33.0", "v1.34.1",
			model.SeverityHigh, model.ReachableTrue))
	}

	// --- ordinary third-party dependency findings -------------------------
	for _, repo := range []string{
		Org + "/checkout-ui", Org + "/merchant-portal", Org + "/docs-site",
		Org + "/sandbox-playground",
	} {
		add(dep(repo, AdvJSON,
			"example.com/json-stream", "v2.1.0", "v2.2.0",
			model.SeverityHigh, model.ReachableFalse, model.DepDevelopment))
	}
	// A different version of the same module, so the merge has to key on the
	// MODULE rather than on the version string.
	add(dep(Org+"/admin-console", AdvJSON,
		"example.com/json-stream", "v2.0.4", "v2.2.0",
		model.SeverityHigh, model.ReachableUnknown, model.DepProduction))

	for _, repo := range []string{Org + "/batch-exports", Org + "/data-pipeline"} {
		add(dep(repo, AdvCSV,
			"example.com/csv-reader", "v0.9.0", "v0.9.3",
			model.SeverityMedium, model.ReachableUnknown, model.DepProduction))
	}
	for _, repo := range []string{Org + "/internal-tools", Org + "/search-indexer"} {
		add(dep(repo, AdvYAML,
			"example.com/yaml-parse", "v3.0.1", "v3.0.4",
			model.SeverityMedium, model.ReachableTrue, model.DepProduction))
	}

	// A transitive one: nothing imports it directly.
	transitive := dep(Org+"/legacy-billing", AdvRouter,
		"example.com/http-router", "v1.12.4", "v1.12.9",
		model.SeverityMedium, model.ReachableUnknown, model.DepProduction)
	transitive.Classification.Transitive = true
	add(transitive)

	// One with NO published fix: policy must route it to a human rather than
	// attempt a bump to a version that does not exist.
	noFix := dep(OwnerCoreAuth, AdvNoFix,
		"example.com/jwt-parse", "v1.4.0", "",
		model.SeverityHigh, model.ReachableTrue, model.DepProduction)
	add(noFix)

	// --- code findings ----------------------------------------------------
	add(code(Org+"/payments-gateway", "G401", "internal/crypto/hash.go", 42, model.SeverityHigh))
	add(code(Org+"/api-edge", "G402", "internal/api/server.go", 88, model.SeverityHigh))
	add(code(Org+"/ledger-service", "G404", "internal/ledger/id.go", 17, model.SeverityMedium))
	add(code(Org+"/notifications", "G404", "internal/send/retry.go", 55, model.SeverityMedium))
	add(code(Org+"/search-indexer", "G304", "internal/index/load.go", 23, model.SeverityMedium))
	add(code(Org+"/internal-tools", "G204", "cmd/runner/exec.go", 31, model.SeverityHigh))
	add(code(Org+"/billing-worker", "G401", "internal/billing/token.go", 64, model.SeverityHigh))
	add(code(Org+"/inventory-svc", "G104", "internal/stock/sync.go", 72, model.SeverityLow))
	add(code(Org+"/metrics-agent", "G404", "internal/sample/jitter.go", 19, model.SeverityMedium))
	add(code(Org+"/telemetry-sdk", "G402", "export/otlp/client.go", 41, model.SeverityHigh))
	add(code(Org+"/partner-api", "G107", "internal/webhook/fetch.go", 58, model.SeverityMedium))

	// --- secrets ----------------------------------------------------------
	//
	// Four, across tiers, so the privilege rules have something to hide from
	// an engineer who does not own the repository (VM-UI-F-803) — and the
	// counts still have to add up for them (VM-UI-F-804).
	add(secret(Org+"/legacy-billing", "generic-api-key", "api_key",
		"config/settings.yaml", 12))
	add(secret(Org+"/sandbox-playground", "aws-access-token", "cloud_key",
		"scripts/deploy.sh", 7))
	add(secret(Org+"/batch-exports", "private-key", "ssh_key",
		"deploy/keys/README.md", 3))
	add(secret(Org+"/merchant-portal", "slack-webhook", "webhook_url",
		"src/config/alerts.js", 19))

	// --- configuration ----------------------------------------------------
	add(config(Org+"/api-edge", "FLEET-K8S-001", "deploy/base/api-deployment.yaml", 31,
		model.SeverityMedium))
	add(config(Org+"/payments-gateway", "FLEET-K8S-002", "deploy/base/pay-deployment.yaml", 44,
		model.SeverityHigh))
	add(config(Org+"/admin-console", "FLEET-DOCKER-001", "Dockerfile", 3, model.SeverityLow))
	add(config(Org+"/data-pipeline", "FLEET-K8S-001", "deploy/pipeline.yaml", 22,
		model.SeverityMedium))
	add(config(Org+"/docs-site", "FLEET-ACTIONS-001", ".github/workflows/publish.yml", 14,
		model.SeverityMedium))
	add(config(Org+"/checkout-ui", "FLEET-DOCKER-002", "Dockerfile", 1, model.SeverityMedium))
	add(config(Org+"/inventory-svc", "FLEET-K8S-003", "deploy/inventory.yaml", 27, model.SeverityMedium))
	add(config(Org+"/core-auth", "FLEET-K8S-002", "deploy/base/auth-deployment.yaml", 38,
		model.SeverityHigh))
	add(config(Org+"/ledger-service", "FLEET-K8S-001", "deploy/ledger.yaml", 19, model.SeverityMedium))
	add(config(Org+"/notifications", "FLEET-ACTIONS-001", ".github/workflows/release.yml", 9,
		model.SeverityMedium))
	add(config(Org+"/telemetry-sdk", "FLEET-ACTIONS-001", ".github/workflows/ci.yml", 22,
		model.SeverityMedium))

	return out
}

// KEVEntries are the fabricated advisories the hostile KEV fake reports as
// known-exploited.
//
// Keyed on the CANONICAL identifier, computed by the same precedence rule the
// pipeline uses. Keyed on the tool's own identifier instead, the enrichment
// would silently match nothing and every score would carry a missing-input
// caveat for a feed that answered.
func KEVEntries() []string { return []string{AdvCrypto.ID()} }

// NotListedInKEV are the ones KEV was asked about and did not list — which is
// a MEASUREMENT, distinct from the ones nobody looked up.
func NotListedInKEV() []string {
	return []string{AdvProto.ID(), AdvJSON.ID()}
}

// EPSSEntries are the fabricated exploit-prediction scores.
//
// Deliberately not every advisory: the ones absent from both maps have no
// exploitation data at all, and every score computed from them must say which
// input was missing rather than treating absence as zero.
func EPSSEntries() map[string]float64 {
	return map[string]float64{
		AdvCrypto.ID(): 0.9412,
		AdvProto.ID():  0.1087,
		AdvCSV.ID():    0.0003,
	}
}
