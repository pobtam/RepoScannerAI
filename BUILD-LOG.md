# BUILD-LOG

Implementation log for the Automated Vulnerability Detection & Remediation
Framework (VM-AD §17, phases 0–12) and the Report Browser frontend (VM-UI §10,
U0–U10).

One entry per phase. A phase is recorded here only once its acceptance gate is
green.

| Phase | Status | Gate |
|---|---|---|
| **0** — module scaffold, `internal/model`, `internal/fingerprint` | **Green** | passing |
| 1 — scanner adapters + fixtures | Not started | |
| 2 — store + migrations | Not started | |
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

**A4 — A partial scan does not verify.** VM-ADR-12 requires a "successful" scan
for `VERIFIED`; VM-AD §4.2 gives the outcome enum `complete | partial | failed`,
and neither says which of those counts as successful. Only `complete` verifies.
Rationale: in a partial scan the lost signal may be precisely the one that would
have observed the finding, which is the exact failure mode ADR-12 exists to
prevent. *Narrow reading; widen only with a stated reason.*

**A5 — JSON `null` reachability is rejected rather than coerced to
`"unknown"`.** Absence of a value and a positive assertion of ignorance are
different claims, and the tri-state exists to keep them distinct.

### Open questions hit

**OQ-P0-01 — `WONT_FIX` is unreachable.** It is declared in the VM-AD §6 state
enumeration but appears in no row of the §6.1 transition table, so no finding can
ever enter it. It is implemented (and partitioned as unresolved) but no
transition admits it. Either the table is missing a row — plausibly
`NEEDS_HUMAN → WONT_FIX` by human decision, parallel to
`FALSE_POSITIVE_CANDIDATE → SUPPRESSED` — or the state should be removed.
`TestWontFixIsUnreachable` locks the current reading and will fail loudly if a
transition is added, as a prompt to update this log. **Needs a decision before
Phase 6** (policy) — a `WONT_FIX` outcome would otherwise have no route.

**OQ-P0-02 — `MERGED` partitioning interacts with VM-OQ-09.** VM-F-159 makes
`MERGED` its own partition, which the model implements. VM-OQ-09 still asks how
it is *counted* in headline figures. The partition keeps the question askable
without prejudging it; the answer is needed before Phase 7 (reporting), and
VM-UI-OQ-09 must be answered identically or the interface and the reports will
disagree.

**OQ-P0-03 — documentation inconsistency, no impact.** VM-AD's reading-order
note directs an implementing agent to "§16 (Build sequence)", but §16 is
Architecture Decision Records and §17 is the Build sequence. Followed §17 as
instructed. Related: ADR-14 appears after ADR-15 in §16.

### How to run the gate

```
cd vulnframework
go vet ./... && go test ./... -race
```

---
