# BUILD-LOG

Implementation log for the Automated Vulnerability Detection & Remediation
Framework (VM-AD §17, phases 0–12) and the Report Browser frontend (VM-UI §10,
U0–U10).

One entry per phase. A phase is recorded here only once its acceptance gate is
green.

| Phase | Status | Gate |
|---|---|---|
| **0** — module scaffold, `internal/model`, `internal/fingerprint` | **Green** | passing |
| **1** — scanner adapters + `testdata/fixtures` | **Green** | passing |
| **2** — `internal/store` + migrations | **Green** | passing (both backends) |
| 3–12 | Not started | |
| U0–U10 — frontend | Not started | |

---

## Phase 0 — Module scaffold, `internal/model`, `internal/fingerprint`

**Gate (VM-AD §17):** *Unit tests pass. Fingerprint is stable across reformatting
and unstable across genuine identity change. Illegal state transitions are
rejected. No external dependency.*

**Status: green.** 51 top-level tests, 197 including subtests. `go vet` clean,
`gofmt` clean, passes under `-race`.

### What landed

**`internal/model`** — no dependencies on any other internal package.

| File | Contents |
|---|---|
| `schema.go` | `findings.v1` version constant; unsupported versions rejected rather than best-effort parsed (VM-F-107) |
| `finding.go` | `Finding` (the VM-AD §4.1 record) and `RawFinding` (adapter output, pre-fingerprint); `Category` (VM-F-108); `Reachable` tri-state; `Classification`, `Provenance`, `Triage`, `Derived`, `Refs` |
| `state.go` | 13 states; the normative VM-AD §6.1 transition table; the VM-F-159 partition; `ValidateTransition` / `ApplyTransition`; typed errors |
| `reason.go` | The 12 reason codes of VM-FR §5.3 (VM-F-157); `PausesSLA` (VM-NF-304) |
| `severity.go` | `Severity` and `Priority` enumerations with ordering |

**`internal/fingerprint`** — depends only on `internal/model`.

| File | Contents |
|---|---|
| `fingerprint.go` | `Compute` per VM-AD §5: `sha256("v1" ǀ repo ǀ category ǀ identity ǀ location)[:16]`; per-category `Identity` and `Location` |
| `normalize.go` | Path and identifier normalisation; `ResolveAlias` implementing the GO > GHSA > CVE > OSV > rule-id precedence |

### Invariants made structural, not deferred

Each of these was verified by mutation — the invariant was deliberately broken
and the suite confirmed to fail before the code was restored:

| Invariant | Mechanism | Caught by |
|---|---|---|
| `reachable` is tri-state, never boolean (VM-F-243) | `Reachable.UnmarshalJSON` rejects JSON `true`/`false` outright | `TestReachableRejectsJSONBooleans`, `TestReachableInsideAFindingRejectsBoolean` |
| No secret value anywhere (VM-F-263/264) | No field in the `Finding` or `RawFinding` type graph can hold one; unrepresentable beats redactable | `TestNoSecretValueFieldExists`, `TestUnknownJSONKeysAreDroppedNotCarried` |
| Absence is not resolution (VM-ADR-12, VM-F-160) | `→ VERIFIED` is a guarded transition requiring `ScanOutcome == complete` | `TestVerificationRequiresSuccessfulScan` |
| Line numbers never fingerprinted (VM-F-102) | `Line` is carried on the record but never read by `Compute` | `TestLineNeverEntersTheHash`, `TestStableAcrossReformatting` |
| §3 dependency rule | Import-graph test parses both packages and fails the build on violation | `TestFoundationPackagesHaveNoInternalDependencies` |

The fingerprint algorithm is additionally locked by golden values
(`TestFingerprintGoldenValues`), independently verified against a from-scratch
implementation of the §5 construction. The fingerprint is the primary key of the
findings store: if it drifts, every finding becomes a new finding, every ticket
is orphaned, and MTTR resets. Changing it legitimately requires bumping
`fingerprint.Version` and writing a migration.

### Stubbed

Nothing in Phase 0 is stubbed. The `internal/model` and `internal/fingerprint`
packages are complete as specified.

The full VM-AD §3 directory tree exists, but every directory outside these two
packages is **empty** — `cmd/*`, `internal/scan`, `internal/store`,
`internal/policy`, `internal/report`, `deploy/`, `config/`, `testdata/` and the
rest are placeholders awaiting their phases. No stub implementations were
written, deliberately: an empty directory is honest about what exists, a stub
that compiles is not.

### Deferred to later phases

| Deferred | To |
|---|---|
| Logging of rejected transitions (VM-F-152) — `model` returns a typed error carrying full context; emitting it is the orchestrator's job | Phase 4 |
| Persisting state transitions (VM-F-153) — `ApplyTransition` returns the audit record but writes nothing | Phase 2 |
| Enforcing verification against `repo_scan_results` at the store boundary | Phase 2 |
| Redaction of secret values in normalisation (VM-F-264) — the model leaves nowhere to put one; the adapter must still not emit one into `RawFinding.Raw` | Phase 1 |
| Composite scoring and SLA computation (VM-AD §9.4, §9.5) — `model` defines the bands only; `internal/score` computes | Phase 5 |
| Alias table populated from OSV — `ResolveAlias` resolves a supplied alias set by precedence; sourcing the set is an adapter concern | Phase 1 |

### Assumptions made (VM-AD §18 / VM-UI §11 process)

**A1 — Module path is `github.com/wanaware/vulnframework`.** No specification
names one. Derived from the organisation implied by `org/wanaware-api`
throughout VM-AD. *Cheap to change now, expensive after Phase 2; flag if wrong.*

**A2 — `internal/fingerprint` may import `internal/model`, and nothing else
internal.** VM-AD §3 says both packages have "no dependencies on any other
internal package", but §5 types `Compute(f RawFinding)` and §8.4 has adapters
return `[]model.RawFinding` — one shared type is unavoidable. Resolution:
`model` is held to the rule absolutely (zero internal imports); `fingerprint` is
allowed exactly one edge, to `model`. The layering test encodes precisely this,
so any drift fails the build. The rule's stated intent — a model change must not
ripple across five packages — is preserved.

**A3 — Severity enumeration is `CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN`.** No
specification enumerates it. The first four are those used throughout
`report-browser-prototype.jsx`; `UNKNOWN` was added because a tool that reports
no severity must be representable rather than silently collapsing to `LOW`.
`UNKNOWN` sorts after `LOW` — it is an absence, not a severity floor.

**A4 — A partial scan does not verify. → CONFIRMED as the shipping floor
2026-09-14.** VM-ADR-12 requires a "successful" scan for `VERIFIED`; VM-AD §4.2
gives the outcome enum `complete | partial | failed`, and neither says which of
those counts as successful. Only `complete` verifies. Rationale: in a partial
scan the lost signal may be precisely the one that would have observed the
finding, which is the exact failure mode ADR-12 exists to prevent.

*Decision (owner, 2026-09-14): keep the narrow reading as the shipping floor
through Phase 2.* The refinement below is recorded as OQ-P1-01 and is **not to be
implemented now.**

**A5 — JSON `null` reachability is rejected rather than coerced to
`"unknown"`.** Absence of a value and a positive assertion of ignorance are
different claims, and the tri-state exists to keep them distinct.

### Open questions hit

**OQ-P0-01 — `WONT_FIX` is unreachable. → RESOLVED 2026-09-14.**

*Question as raised:* `WONT_FIX` is declared in the VM-AD §6 state enumeration
but appears in no row of the §6.1 transition table, so no finding can ever enter
it. Missing row, or remove the state?

*Decision (owner, 2026-09-14): keep the state.* It represents **accepted risk** —
a real, exploitable finding the organisation consciously chooses not to
remediate. Neither neighbouring state can express that: `DECLINED` is a rejected
fix on a still-unresolved finding, and `SUPPRESSED` is a false positive. It is
reached by a **human action only, never by policy**, so there is no policy
`wont_fix` outcome and **this does not block Phase 6**.

*Planned edit, deferred to the human write-actions work — not implemented now:*

| Change | Detail |
|---|---|
| VM-AD §6.1 transition table | Add `NEEDS_HUMAN → WONT_FIX`, trigger: human decision, actor: `human` |
| VM-FR §5.3 partition (VM-F-159) | `WONT_FIX` becomes its own **accepted risk** partition: resolved for SLA and queue purposes, **never folded into `VERIFIED`** — the risk is still present and must remain distinguishable in any count |

Both are **required changes to the specifications**, not just to code. Until they
land, `TestWontFixIsUnreachable` stays in place as a lock and will fail loudly if
a transition is added, as a prompt to update this log. The model currently
partitions `WONT_FIX` as unresolved; that moves to the new bucket with the same
edit.

**OQ-P0-02 — `MERGED` partitioning interacts with VM-OQ-09.** VM-F-159 makes
`MERGED` its own partition, which the model implements. VM-OQ-09 still asks how
it is *counted* in headline figures. The partition keeps the question askable
without prejudging it; the answer is needed before Phase 7 (reporting), and
VM-UI-OQ-09 must be answered identically or the interface and the reports will
disagree.

**OQ-P0-03 — documentation inconsistency. → FIXED 2026-09-14.** VM-AD's
reading-order note directed an implementing agent to "§16 (Build sequence)", but
§16 is Architecture Decision Records and §17 is the Build sequence. Corrected in
the specification to read §17 (VM-AD line 22). Phase 0 followed §17, which was
the right sequence. Still outstanding, cosmetic and unfixed: ADR-14 appears after
ADR-15 in §16.

### Carried forward to later phases

**OQ-P1-01 — verification from a partial scan, at tool granularity.** Deliberate
widening of A4, to be implemented later as a tested change, **not now**.

> Verify from a partial scan **iff** every tool in the finding's
> `provenance.tools` appears in that scan's `repo_scan_results.tools_ok`
> (equivalently: is disjoint from `tools_failed`).

*Rationale (owner, 2026-09-14):* the narrow floor has its own failure mode — if
any one tool is chronically flaky, a repository never verifies anything and open
counts inflate indefinitely. The tool-level reading fixes that while fully
honouring ADR-12, because the question ADR-12 actually asks is whether *the
scanner that would have observed this finding* ran successfully, not whether
every scanner did.

Acceptance when implemented: a finding whose detecting tool succeeded **verifies**
from a partial scan; a finding whose detecting tool failed **does not**. Both
directions must be tested. Requires `provenance.tools` to be reliably populated,
which Phase 1 establishes.

### How to run the gate

```
cd vulnframework
go vet ./... && go test ./... -race
```

---

## Phase 1 — Scanner adapters + `testdata/fixtures`

**Gate (VM-AD §17):** *Each adapter normalises its captured fixture to expected
output byte-for-byte. Alias resolution collapses the `govulncheck` and
`osv-scanner` reports of one defect to one fingerprint.*

**Status: green.** 81 top-level tests (180 with subtests) across the module.
`go vet` and `gofmt` clean, passes under `-race`. Still no external Go
dependency, and no test touches a binary, a network or a credential.

### What landed

**`internal/scan`** — the VM-AD §8.4 adapter contract: `Adapter`, `RepoProfile`,
`RunOpts`, `RawOutput`, a name-keyed `Registry` with profile-based selection,
and a `config/tools.lock` parser (VM-AD §8.3, VM-F-202).

**`internal/scan/runner`** — `CommandRunner` with two implementations: `Exec`
for real binaries and `Fake` for fixtures. A non-zero exit is a *result* (a
scanner exits non-zero because it found something); an execution failure is an
*error* (that is a coverage gap, VM-F-205). Conflating the two would turn every
repository with a finding into a coverage gap.

**`internal/scan/adapters`** — nine adapters, each with a fixture and a golden:

| Adapter | Category | Notes |
|---|---|---|
| `govulncheck` | dependency | The reachability authority for Go (VM-F-221). Collapses its own module/package/symbol messages to one finding. Reports severity `UNKNOWN` — the Go vulnerability database does not score advisories. |
| `osv-scanner` | dependency | Go + JavaScript. Carries CVSS; never asserts reachability. |
| `gosec` | code | Thresholds per tier (VM-F-224); honours `#nosec`. |
| `staticcheck` | code | Filtered to a security subset (see A7). |
| `gitleaks` | secret | **Redaction enforcement point** (VM-F-264). |
| `trivy` | config | Dockerfile + Kubernetes; only `FAIL` status is a finding. |
| `semgrep` | code | JavaScript; filtered to `category: security`. |
| `npm-audit` | dependency | Extracts GHSA from the advisory URL; dev/prod from `package.json`. |
| `actions-pin` | config | Internal check, no binary (VM-F-266). |

### The gate, and proof it can fail

Each clause was verified by mutation — the behaviour was deliberately broken and
the suite confirmed to fail, then restored:

| Mutation | Caught by |
|---|---|
| Alias resolution disabled | `TestCrossToolAliasCollapse` — "one defect produced two fingerprints" |
| Credential copied into retained raw output | `TestGitleaksRedactsCredentialMaterial` |
| Credential concatenated into `CredentialType` | `TestGitleaksRedactsCredentialMaterial` |
| Module-level findings treated as reachable | `TestGovulncheckReachability` + the golden |

The alias-collapse clause is genuinely exercised: the fixtures have govulncheck
report `GO-2025-3106` and osv-scanner report `GHSA-hcg3-q754-cr77` for the same
`golang.org/x/crypto` defect. The test asserts the two identifiers *differ*
before asserting the fingerprints *match*, so it cannot pass vacuously.

`TestCrossToolReachabilityDisagreement` records why the collapse matters: for the
shared fingerprint, govulncheck supplies reachability and no severity, while
osv-scanner supplies severity and no reachability. Merging those complementary
attributes is Phase 2's job and is only possible because the fingerprints agree.

### Secret redaction (VM-F-263/264)

gitleaks reports the matched credential verbatim in its `Secret` and `Match`
fields. The adapter never copies either into a finding, and the retained raw
output is a **reconstruction** from safe fields only (`redactedHit`), so there is
no path by which credential material can reach the store. The committed golden
file `testdata/fixtures/gitleaks/go-api.golden.json` is itself readable evidence:
it shows the path, line, credential class and `"redacted": true`, and no value.

This is the unit-level half of v1.0 acceptance criterion 8. The end-to-end half
(never appears in any report or ticket body) lands in Phases 7 and 8.

### Stubbed / deferred

| Item | To |
|---|---|
| Diff-scoped filtering — `RunOpts.Mode`/`ChangedFiles` are defined and semgrep passes `--baseline-commit`, but the code/secret/config vs dependency split (VM-AD §8.5) is applied by the scan worker | Phase 3 |
| Coverage-gap assembly — adapters distinguish execution failure from findings; building the gap record and its total/partial classification (VM-F-211/212) | Phase 3 |
| Repository profiling — `RepoProfile` is consumed but nothing populates it from a real checkout (VM-F-208) | Phase 3 |
| `first_party_path` classification during normalisation (VM-AD §12.2) | Phase 11 |
| Scanner image + digest — `tools.lock` pins versions; `image` is a placeholder until the image build exists | Phase 3 |
| `go mod verify`, Go workspace/multi-module handling (VM-F-225) | Phase 3 |
| gitleaks history scanning on a separate schedule (VM-F-262) | operational, post-Phase 3 |

### Assumptions made

**A6 — Fixtures are hand-authored to each tool's documented JSON schema, not
captured from real tool runs.** This is the one place Phase 1 departs from the
letter of VM-AD §8.4, which says to "store real captured tool output", and it is
worth stating plainly: Phases 0–2 are specified to run with no external infra, so
there is no scanner image from which to capture. Each fixture reproduces its
tool's real output shape (govulncheck's NDJSON `config`/`osv`/`finding` stream,
osv-scanner's `results[].packages[].vulnerabilities[]`, gosec's `Issues[]` with
string-typed `line`, npm audit's `auditReportVersion: 2` with heterogeneous
`via[]`, and so on), but they are constructed, not observed. **Action required in
Phase 3:** once the scanner image exists, re-capture every fixture from a real
run against the synthetic repositories and regenerate the goldens
(`go test ./internal/scan/adapters -update`). A golden diff at that point is
expected and informative — it is the adapters meeting reality.

**A7 — staticcheck's security subset is defined here, not by the specification.**
VM-AD §8.2 requires filtering "to the security rule subset only" but neither
enumerates it nor points at one, and staticcheck publishes no security
categorisation. `securityRelevantChecks` lists 13 checks, each with a stated
security consequence in the source. Without a filter, staticcheck's correctness
and style diagnostics would swamp the finding store — the same failure mode
VM-ADR-05 describes for ticket volume. *Reviewable list; expect it to change
during VM-OQ-06 calibration in Phase 5.*

**A8 — `RawOutput.Aux` carries auxiliary repository files into normalisation.**
`npm audit --json` does not record whether a vulnerable package is a
development-only dependency, but VM-F-242 requires that classification. Rather
than reading `package.json` inside `Normalize` (which would stop it being a pure
function of bytes and make the fixture tests meaningless), the file is supplied
in `RawOutput.Aux`. With no manifest the adapter classifies as `production`:
under-stating a development dependency is safe, over-stating a production one is
not.

**A9 — `actions-pin` is a ninth adapter, beyond the eight files listed in VM-AD
§3.** The §3 layout names eight adapter files, but the §8.2 tool matrix has a
ninth row — the internal Actions SHA-pinning check — and VM-F-266 is a MUST.
Implemented as `adapters/actionspin.go`. It is the one adapter with no external
binary; it satisfies the same interface so the scan worker treats it identically.

**A10 — npm dependency findings carry an empty `ModuleMajor`.** npm packages
encode no major version in their name and the audit report does not state the
installed version, so the package name alone locates the finding. Consequence:
a vulnerability in axios v1 and one in axios v2 would share a fingerprint where
the advisory id is the same. Acceptable — advisories are version-ranged, so
distinct majors almost always carry distinct advisory ids. *Revisit if
osv-scanner's JavaScript findings (which do carry the installed version) and
npm-audit's disagree in practice.*

**A11 — severity band mappings.** `MODERATE`→`MEDIUM` (OSV, npm);
semgrep `ERROR`/`WARNING`/`INFO`→`HIGH`/`MEDIUM`/`LOW`; staticcheck
`error`→`MEDIUM`, `warning`→`LOW`; secrets fixed at `CRITICAL` per VM-AD §9.4.
None of these mappings is specified.

### Open questions hit

**OQ-P1-02 — two tools, two severities, one fingerprint.** govulncheck and
osv-scanner produce the same fingerprint with different attributes: severity
`UNKNOWN` + reachability `true` from one, severity `HIGH` + reachability
`unknown` from the other. Phase 1 correctly has each adapter report only what its
tool knows, but **nothing yet specifies the merge rule**. The natural rule —
strongest reachability evidence wins, highest severity wins, union the tool list
— is implemented *within* one adapter's output (`mergeReachability`) but the
cross-adapter merge belongs in the store. **Needs deciding in Phase 2**, and it
should be written down rather than emerging from whichever adapter happens to
upsert last.

**OQ-P1-03 — `VM-OQ-06` remains open and now has a concrete surface.** The
staticcheck subset (A7) and the gosec `-severity/-confidence` defaults are the
thresholds VM-OQ-06 asks to calibrate. Both are configurable per tier as
required; only the defaults are guesses. Phase 5 shadow running is where they get
real numbers.

---

## Decisions taken between Phase 1 and Phase 2 (2026-09-14)

**A6 — hand-authored fixtures: plan accepted, with two added constraints on the
Phase 3 re-capture gate.**

1. **Separate expected diffs from gaps.** A golden **value** diff is expected and
   may be accepted via `-update`. A **parse failure, a newly-seen field, or a
   changed shape is a Phase-1 gap**, not an update: it means the hand-authored
   fixture did not reflect the tool's real output. Each such case requires a new
   test covering the newly-seen shape before the golden is regenerated. The
   re-capture must therefore report these two classes separately rather than
   presenting one undifferentiated diff.
2. **Multiple real samples per tool, from a pinned version.** Capture at least
   three envelopes per tool — **normal**, **empty** (no findings), and **error**
   (the tool's own failure envelope) — from the scanner version pinned in
   `config/tools.lock`, and record that version in each golden's metadata so a
   golden can never be read without knowing which tool build produced it.

**OQ-P1-02 — cross-adapter merge rule. → RESOLVED 2026-09-14.** Written into the
specification as **VM-AD §8.6 (normative)** and implemented in Phase 2. The
merged finding is a deterministic, order-independent projection over retained
per-source observations, recomputed on every change — never last-upsert-wins,
which would make the stored record a function of scan scheduling. Field rules,
the conservative `true`-over-`false` reachability resolution, the auditability
requirement, and the VM-ADR-12 consistency constraint are all in §8.6.

## Phase 2 — `internal/store` + migrations

**Gate:** *migrations apply and roll back cleanly; upsert creates an observation
rather than a duplicate; VERIFIED → observed → REGRESSED; a finding absent due to
a failed scan does not reach VERIFIED; and the cross-adapter projection is
deterministic under reordered/replayed upserts.*

**Status: green — all five clauses, against a real Postgres 16 as well as the
in-memory backend.** 114 top-level tests (266 with subtests) module-wide, vet and
gofmt clean, passes under `-race`.

### Two backends, one conformance suite

`Store` has two implementations: `Postgres` (production) and `Memory` (offline,
and the fake later phases will use). They share every invariant decision through
three pure functions — `PlanUpsert`, `PlanReconcile` and `Project` — and both are
run against the *same* conformance suite.

This is not belt-and-braces. A fake that enforces different rules than production
makes every test that uses it a statement about the fake. The suite immediately
earned its keep by catching a genuine divergence: `Memory` returned state history
in insertion order while Postgres returned it in `ORDER BY at, id`. Root cause was
that neither backend stamped the transition timestamp from its own clock, so a
caller omitting one got wall-clock time. Both fixed — the store is the authority
on when a change was recorded.

### The gate, and proof it can fail

| Mutation | Caught by |
|---|---|
| Verify regardless of scan outcome | `TestFailedScanDoesNotVerify` (both backends) |
| Last-upsert-wins for severity | `TestProjectIsOrderIndependent`, `TestSeverityIsMaxOverSuppliers` |
| `unknown` overrides a determination | `TestReachabilityRules`, `TestPriorSourceSurvivesAPartialScan` |
| Drop a source a later scan didn't re-observe | `TestPriorSourceSurvivesAPartialScan` |

Migrations are executed, not asserted structurally: `TestMigrationsApplyAndRollBack`
walks the full ladder up one version at a time, all the way back down, then up
again — a down migration that only works once is not a rollback, and the second
climb is what proves the database was genuinely returned to empty.

### Two real bugs found by the tests

1. **`verifyChecksums` panicked** on a short or corrupt recorded checksum
   (`want[:12]` on an 8-character value). A corrupt `schema_migrations` row
   crashed the migrator instead of reporting the problem. Fixed with a safe
   truncation; a regression test now tampers with a checksum both ways.
2. **The checksum guard blocks movement in both directions**, so a tampered row
   cannot be escaped by rolling back. Kept deliberately: a mismatch means nobody
   knows what is deployed, and auto-rolling-back on that basis could drop data on
   a wrong assumption. It requires a human. The test restores the row directly.

### Required specification changes made

**VM-AD §8.6 added (normative)** — the cross-source merge rule, per the 2026-09-14
decision. Deterministic order-independent projection over retained per-source
observations, field rules, conservative `true`-over-`false` reachability with
conflict recording, auditability, and the VM-ADR-12 consistency constraint.

**VM-AD §4.2 `finding_observations` primary key widened** from
`(fingerprint, run_id)` to `(fingerprint, run_id, tool)`. Two tools reporting one
defect in one run produce one fingerprint but two observations, and §8.6 requires
every per-source value be retained. The narrower key cannot hold both rows. This
is a **required change to the specification**, recorded in the migration's own
comment as well as here.

**VM-AD §4.2 `findings` gains `first_seen_run` / `last_seen_run` columns.** Both
are queried directly for delta reporting and run-scoped corpora, so they are
columns as well as JSON paths under `data.provenance`.

### Assumptions made

**A12 — the store takes an open `*sql.DB`, not a DSN.** The driver is chosen by
the binary (`cmd/*` blank-imports pgx in Phase 4), so `internal/store` carries no
driver dependency and a caller can substitute one without touching this package.
Postgres array literals are rendered and parsed by hand for the same reason.

**A13 — a finding absent from a *successful* scan verifies only from `MERGED`.**
The §6.1 table has exactly one edge into `VERIFIED`. An unresolved finding in any
other state that a successful scan no longer observes is flagged
`not_reobserved` and left alone — never closed (VM-F-163). *This is a real
signal, not a no-op: it surfaces findings fixed outside the framework's own
remediation path.* See OQ-P2-01.

**A14 — `Query.Scope` is required and returns `ErrScopeRequired` if absent**
(VM-ADR-14), rather than defaulting to open findings.

### Stubbed / deferred

| Item | To |
|---|---|
| Tables created but unused: `pr_scans`, `remediation_attempts`, `tickets`, `token_usage`, `module_deps`, `wave_consumers` | Phases 3, 8, 9, 11 |
| Lease management (`lease_owner`, `lease_expires_at`) — columns exist; the 60s sweeper is the orchestrator's | Phase 4 |
| Priority and SLA fields — columns exist; `internal/score` computes them | Phase 5 |
| Coverage-gap escalation on consecutive failures (VM-F-215) — `ScanResults` returns the history the streak is computed from | Phase 3/8 |
| Retention and partitioning for `finding_observations`, `module_deps`, `repo_scan_results` (VM-OQ-09, VM-OQ-15) | open |

### Open questions hit

**OQ-P2-01 — a finding fixed outside the framework never verifies.** The §6.1
table reaches `VERIFIED` only from `MERGED`. A finding a developer fixes by hand,
which a later successful scan no longer observes, stays `TRIAGED` with
`not_reobserved` set — correct under VM-F-163, but it accumulates forever and
nothing ever clears it. Either the table needs an edge (something like
`TRIAGED → VERIFIED` on repeated absence across N successful scans), or these
need a distinct presentation so they are not read as live risk. **Wanted before
Phase 7**, since it changes reported open counts.

**OQ-P2-02 — `Reconcile` is per repository and requires a scan result.** It
refuses to judge absence without knowing whether the scan succeeded, which is
correct, but it means the orchestrator must call it for every planned repository
including ones that failed entirely. A repository that was never dispatched at
all has no row and so is never reconciled — its findings keep the flags from the
previous run. **Phase 4 must decide** whether planning writes a `failed` row for
undispatched repositories; the store is ready either way.

### Running the gate

```
cd vulnframework
go test ./...                      # memory backend only, fully offline

docker run -d --name vf-pg-test -e POSTGRES_PASSWORD=vftest -e POSTGRES_USER=vftest \
  -e POSTGRES_DB=vftest -p 55432:5432 postgres:16-alpine
VULNFRAMEWORK_TEST_DSN="postgres://vftest:vftest@localhost:55432/vftest?sslmode=disable" \
  go test ./... -race            # both backends, including migrations
```

Without the DSN the Postgres backend and the migration-execution tests skip, and
the suite still passes offline as VM-AD §17 requires of phases 0–2.

---
