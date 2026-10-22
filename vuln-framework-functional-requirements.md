# Automated Vulnerability Detection & Remediation Framework
## Functional Requirements

| Field | Value |
|---|---|
| Document ID | VM-FR |
| Version | 0.3 |
| Status | Draft — for review |
| Date | 2026-09-02 |
| Owner | Platform / Security Engineering |
| Companion | `vuln-framework-architecture-design.md` (VM-AD) |
| Review cadence | Per release until v1.0, then quarterly |

### Revision history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-09-02 | Initial draft |
| 0.3 | 2026-09-02 | Report generation as a first-class subsystem (§5.12). Report identity, reproducibility anchoring, templates, formats, delivery, and access inheritance. |
| 0.2 | 2026-09-02 | Run identity (§5.2). Open/resolved classification and the absence-is-not-resolution rule (§5.3). Coverage history, gap classification and escalation (§5.4). Per-consumer reachability, module fan-out and version spread (§5.11). SLA status, coverage trending and same-kind deltas (§5.12, §5.15). Derived from prototype review; see VM-UI v0.2 §4.4, §4.7, §4.8. |

---

## 1. Purpose and scope

### 1.1 Purpose

This document specifies **what** the vulnerability detection and remediation framework must do. It is contract-level. It does not specify implementation, technology choices, or code structure; those are in the companion Architecture & Design document (VM-AD).

### 1.2 In scope

- Detection of vulnerabilities across all first-party GitHub repositories in the organisation
- Source languages: Go (primary), JavaScript/TypeScript with React (secondary)
- Finding classes: dependency vulnerabilities, source code defects, exposed secrets, container and infrastructure-as-code misconfiguration
- Automated triage, prioritisation, and false-positive nomination
- Automated remediation via pull request, subject to policy
- Reporting: found / fixed / not fixed, with deltas across runs
- Ticket creation for human-in-the-loop workflow
- Cost and token accounting

### 1.3 Out of scope

- Runtime / cluster posture scanning (GKE, node images, admission control) — separate system
- Penetration testing and manual security review
- Third-party SaaS vendor risk
- Customer-hosted or on-premises deployments — none exist
- Automatic merge of remediation pull requests (explicitly deferred; see VM-F-541)

### 1.4 Requirement conventions

Each requirement carries an ID, a normative keyword, a statement, and a verification method. `MUST` is binding for v1.0. `SHOULD` is expected but may be deferred with a recorded rationale. Verification methods are `unit`, `integration`, `e2e`, `inspection`, or `operational`.

---

## 2. Definitions

| Term | Definition |
|---|---|
| **Finding** | A single distinct vulnerability or defect in a single repository, uniquely identified by a fingerprint |
| **Fingerprint** | A stable, deterministic identifier for a finding that survives code movement and reformatting |
| **Observation** | A record that a given run detected a given finding |
| **Run** | One end-to-end execution of the pipeline against one or more repositories |
| **Sweep** | A scheduled run covering the entire repository fleet |
| **Work order** | The bounded instruction set handed to a remediation worker for one repository |
| **Fix group** | The set of findings a single pull request is intended to resolve |
| **Wave 1 / Wave 2** | The two stages of remediating a vulnerability that traverses a first-party shared module |
| **Tier** | A repository criticality classification that determines policy strictness |
| **Tracker** | The external issue-tracking system used for human-in-the-loop work |
| **Reachable** | A dependency vulnerability whose vulnerable symbol is provably called from repository code |

---

## 3. Actors and external interfaces

| Actor | Role |
|---|---|
| Platform engineer | Operates the framework, owns policy configuration |
| Repository CODEOWNER | Receives tickets, reviews and merges remediation pull requests |
| Security owner | Escalation point; watcher on all P0 tickets |
| Orchestrator | Internal control-plane actor that plans and dispatches work |
| Scan worker | Internal actor that executes deterministic scanners |
| Remediation worker | Internal actor that produces code changes |

| External system | Interface |
|---|---|
| GitHub | Repository read, branch write, pull request create, Issues API, webhooks |
| Vulnerability databases | OSV, GitHub Advisory Database, Go vulnerability database, NVD, CISA KEV |
| Tracker backends | GitHub Issues, Jira, Linear |
| Anthropic API | Triage inference and agentic remediation |

---

## 4. Configuration parameters

The framework MUST be configurable without code change. The following are parameters, not constants.

| Parameter | Description | Default |
|---|---|---|
| `org` | GitHub organisation name | *(required)* |
| `repo_selector` | Include / exclude patterns for fleet membership | all non-archived |
| `tiers` | Map of repository → tier (1, 2, 3) | 3 |
| `sweep_schedule` | Cron expression for the full sweep | `0 3 * * 1` |
| `tracker_backend` | `github` \| `jira` \| `linear` | `github` |
| `tracker_mirror` | Optional secondary backend for P0/P1 | none |
| `report_repo` | Repository holding rendered reports | `security-reports` |
| `first_party_modules` | Module path → owning repository | *(required)* |
| `wave2_trigger` | `tag` \| `merge` | `tag` |
| `sla` | Remediation window per severity per tier | see VM-NF-30x |
| `policy` | Per-tier, per-language remediation permissions | see VM-F-4xx |
| `token_ceiling` | Per-run token budget | unset (unlimited) |

---

## 5. Functional requirements

### 5.1 Finding model and identity (VM-F-1xx)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-101 | MUST | Every finding shall be assigned a fingerprint that is deterministic, stable across runs, and identical for the same underlying defect regardless of the tool that reported it. | unit |
| VM-F-102 | MUST | The fingerprint shall not incorporate line numbers, byte offsets, or any value that changes under reformatting or unrelated edits. | unit |
| VM-F-103 | MUST | The fingerprint shall incorporate the repository identity, so the same CVE in two repositories yields two findings. | unit |
| VM-F-104 | MUST | The system shall record, for every finding, every run in which it was observed, as a separate observation record. | integration |
| VM-F-105 | MUST | A finding previously in state `VERIFIED` that is observed again shall transition to `REGRESSED`, not be created anew. | integration |
| VM-F-106 | MUST | Findings reported by multiple tools that share a fingerprint shall be merged into one record, retaining the set of reporting tools as an attribute. | unit |
| VM-F-107 | MUST | The finding record shall carry a schema version, and the system shall reject records whose version it does not support. | unit |
| VM-F-108 | MUST | The finding categories shall be exactly: `dependency`, `code`, `secret`, `config`. | inspection |
| VM-F-109 | SHOULD | The finding record shall retain the raw tool output that produced it, for audit and re-triage. | inspection |

### 5.2 Run identity (VM-F-11x)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-111 | MUST | Every run shall be assigned a unique identifier consisting of a monotonically increasing sequence number and the run kind. | unit |
| VM-F-112 | MUST | The sequence number shall be allocated by the datastore, not derived from a timestamp, so that two runs starting in the same second remain distinct. | integration |
| VM-F-113 | MUST | Every run shall record its start timestamp and completion timestamp in UTC, independently of its identifier. | integration |
| VM-F-114 | MUST | Run identifiers shall be unique across all time and shall never be reused, including after a run is deleted or a partial run is discarded. | integration |
| VM-F-115 | MUST | Each run kind shall draw from its own sequence, so that sweep numbering is not consumed by higher-volume run kinds. | unit |
| VM-F-116 | MUST | Pull-request gate scans shall not consume run sequence numbers. They are recorded separately and referenced by pull request. | inspection |
| VM-F-117 | MUST | The run identifier shall be short enough to be spoken, written in a ticket, and typed from memory. | inspection |
| VM-F-118 | MUST | Every artifact produced by a run — report, ticket, pull request body, commit message, log line, metric label — shall carry the run identifier. | e2e |
| VM-F-119 | MUST | Run identifier and start timestamp shall be displayed together wherever a run is named. Neither alone is sufficient: the number is not self-dating and the timestamp is not unique. | inspection |

**Run kinds (normative):** `sweep`, `advisory`, `manual`, `rescan`.

**Identifier format:** `<kind-prefix>-<zero-padded sequence>`, for example `S-001247`. Prefixes: `S` sweep, `A` advisory, `M` manual, `R` rescan.

VM-F-116 exists because pull-request scans run per commit across the fleet and would consume several thousand sequence numbers per week, making sweep numbers sparse and unmemorable — which defeats VM-F-117.

### 5.3 Finding lifecycle (VM-F-15x)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-151 | MUST | Every finding shall be in exactly one state drawn from a closed enumeration. | unit |
| VM-F-152 | MUST | State transitions shall be validated against a transition table; illegal transitions shall be rejected and logged, not silently applied. | unit |
| VM-F-153 | MUST | Every state change shall be recorded with timestamp, actor, and cause. | integration |
| VM-F-154 | MUST | A finding in state `DECLINED` shall never be automatically re-remediated, in any subsequent run, unless a human explicitly resets it. | integration |
| VM-F-155 | MUST | A finding in state `PR_OPEN` shall not cause a second remediation attempt or a second pull request. | integration |
| VM-F-156 | MUST | Findings in `BLOCKED_UPSTREAM` shall remain open and shall be counted in reports; they shall not be closed or hidden. | integration |
| VM-F-157 | MUST | Where a finding is not fixed, the system shall record a reason code from a closed enumeration. | unit |
| VM-F-158 | MUST | Worker failure shall not leave a finding permanently in a transient state; transient states shall be lease-bound and shall revert on lease expiry. | integration |
| VM-F-159 | MUST | States shall be partitioned into a **resolved** set and an **unresolved** set, and the partition shall be defined once and used consistently by reporting, ticketing, metrics, and any user interface. | unit |
| VM-F-160 | MUST | **Absence is not resolution.** A finding shall transition to `VERIFIED` only where the scan that failed to observe it completed successfully for that repository. A finding absent because its repository or scanner failed shall retain its prior state. | integration |
| VM-F-161 | MUST | The system shall expose a derived attribute indicating that a finding was not re-observed in the most recent applicable run while remaining unresolved. | integration |
| VM-F-162 | MUST | A not-re-observed finding shall be traceable to the coverage gap that explains it, where one exists. | integration |
| VM-F-163 | MUST | No finding shall be automatically closed, suppressed, or removed on the basis of non-observation alone. | integration |

**State partition (normative, VM-F-159):**

| Partition | States |
|---|---|
| Resolved | `VERIFIED`, `SUPPRESSED` |
| Pending verification | `MERGED` — fix shipped, not yet confirmed absent by a successful scan |
| Unresolved | `DETECTED`, `TRIAGED`, `AUTO_REMEDIATING`, `PR_OPEN`, `BLOCKED_UPSTREAM`, `NEEDS_HUMAN`, `FALSE_POSITIVE_CANDIDATE`, `REGRESSED`, `DECLINED` |

`DECLINED` is unresolved: a reviewer rejecting an automated fix does not remove the vulnerability. `MERGED` is
its own partition because it is neither — counting it as resolved would let a bad patch close the record before
verification, and counting it as unresolved overstates outstanding work. See VM-OQ-09.

**Reason code enumeration (normative):**

`NO_UPSTREAM_FIX`, `BLOCKED_UPSTREAM_FIRST_PARTY`, `MAJOR_BUMP_POLICY`, `BUILD_FAILED`, `TESTS_FAILED`, `FIX_INEFFECTIVE`, `NO_TEST_COVERAGE`, `NEEDS_HUMAN_SECRET`, `SUPPRESSION_PROPOSED`, `DECLINED`, `AGENT_GAVE_UP`, `BUDGET_EXHAUSTED`, `POLICY_ISSUE_ONLY`

`FIX_INEFFECTIVE` means a remediation was applied, built and tested successfully, and the re-run of the scanners that produced the finding still reports it — most commonly a dependency proxy that has not yet mirrored the fully-closing version, so the bump resolved lower. It is distinct from `NO_UPSTREAM_FIX`, and the distinction is load-bearing: `NO_UPSTREAM_FIX` pauses the SLA clock (VM-NF-304) because nothing can be done, whereas a `FIX_INEFFECTIVE` finding is fully actionable and its clock must keep running. Reusing `NO_UPSTREAM_FIX` here would silently pause the SLA on findings that a human could fix today.

### 5.4 Detection — general (VM-F-2xx)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-201 | MUST | Scanner invocation shall be deterministic and shall not involve language-model inference. | inspection |
| VM-F-202 | MUST | All scanner binaries and rule sets shall be version-pinned; the versions in use shall be recorded in every run's output. | integration |
| VM-F-203 | MUST | Scan workers shall operate on all repositories in parallel, subject only to a configured concurrency limit. | e2e |
| VM-F-204 | MUST | A scanner failure in one repository shall not fail the run; it shall be recorded as a coverage gap for that repository. | integration |
| VM-F-205 | MUST | A scanner that could not be executed at all shall be reported explicitly as a coverage gap, not silently omitted. | integration |
| VM-F-206 | MUST | Scan workers shall hold no credential that grants write access to any repository. | inspection |
| VM-F-207 | MUST | The system shall support a diff-scoped mode in which code findings are restricted to files changed by a given pull request, while dependency findings remain repository-wide. | integration |
| VM-F-208 | MUST | The system shall detect and record, per repository, the language(s), build system, presence of a test suite, and module topology (single module, multi-module, workspace). | integration |
| VM-F-209 | MUST | Scanner output shall be normalised into a single common schema before storage. | unit |
| VM-F-210 | SHOULD | The system shall record a dependency inventory (SBOM) per repository, sufficient to answer "which repositories are affected by advisory X" without re-scanning. | integration |
| VM-F-211 | MUST | A coverage gap shall be classified as **total** (no scanner produced results for the repository) or **partial** (some scanners completed). The classification shall be recorded. | unit |
| VM-F-212 | MUST | A partial gap shall record which signals were lost and which remain current, so that surviving results are still usable. | integration |
| VM-F-213 | MUST | Per-repository scan outcome shall be persisted per run, retaining sufficient history to compute consecutive-failure count and last successful scan. | integration |
| VM-F-214 | MUST | Each coverage gap shall be attributed to an owner: platform for infrastructure causes (timeouts, rate limits, tool crashes), repository code owners for repository causes (build failure, missing lockfile). | inspection |
| VM-F-215 | MUST | Consecutive scan failures for a repository exceeding a configurable threshold shall escalate. A coverage gap that is only visible to someone who opens a dashboard is not surfaced. | integration |
| VM-F-216 | MUST | The count of findings not re-observed as a consequence of each gap shall be recorded and reported alongside it. | integration |

### 5.5 Detection — Go (VM-F-22x)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-221 | MUST | Dependency vulnerability detection for Go shall use reachability analysis and shall record, per finding, whether the vulnerable symbol is reachable from repository code. | integration |
| VM-F-222 | MUST | Where reachability is determinable, `reachable: false` shall be a distinct and lower priority from `reachable: true`. | unit |
| VM-F-223 | MUST | The declared Go toolchain version shall be checked against the current patch release, and toolchain-level standard library vulnerabilities shall be reported as findings. | integration |
| VM-F-224 | MUST | Static code analysis shall run at a severity and confidence threshold that is configurable per tier. | inspection |
| VM-F-225 | MUST | Multi-module repositories and Go workspaces shall be scanned in full; a workspace shall not be scanned as a single module. | integration |
| VM-F-226 | MUST | `replace` directives shall be detected and reported, as they invalidate dependency resolution assumptions. | integration |
| VM-F-227 | SHOULD | Modules with no upstream activity for a configurable period, or whose upstream repository is archived, shall be flagged as maintenance risk. | integration |

### 5.6 Detection — JavaScript / React (VM-F-24x)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-241 | MUST | Dependency scanning shall operate on the committed lockfile; a repository with no committed lockfile shall be reported as a coverage gap. | integration |
| VM-F-242 | MUST | Findings shall be classified as production-dependency or development-only-dependency, and this classification shall be an input to prioritisation. | unit |
| VM-F-243 | MUST | Where reachability cannot be determined, the finding shall record `reachable: unknown`; `unknown` shall never be treated as equivalent to `reachable: true` for prioritisation. | unit |
| VM-F-244 | MUST | The system shall record whether the repository has an executable test suite, and this shall gate agentic code remediation (VM-F-524). | integration |

### 5.7 Detection — secrets and configuration (VM-F-26x)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-261 | MUST | Secret detection shall run against the working tree on every run. | integration |
| VM-F-262 | SHOULD | Secret detection shall run against full commit history on a separate, less frequent schedule. | operational |
| VM-F-263 | MUST | A secret finding shall record only the file path, line number, and credential type. The matched value, any substring of it, and any hash or derivative of it shall never be stored, logged, transmitted to a tracker, or written to a report. | unit |
| VM-F-264 | MUST | Redaction shall be enforced in the normalisation layer, before the value reaches any store or downstream consumer. Prompt-level instruction shall not be relied upon as the control. | unit |
| VM-F-265 | MUST | Container build files and infrastructure manifests shall be scanned for misconfiguration where present. | integration |
| VM-F-266 | MUST | Third-party GitHub Actions referenced by mutable tag rather than commit SHA shall be reported as findings. | integration |

### 5.8 Triage and prioritisation (VM-F-3xx)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-301 | MUST | Triage shall produce, per finding: a plain-language description of the defect, an impact statement, a priority, and a remediation recommendation. | e2e |
| VM-F-302 | MUST | Triage shall not introduce any vulnerability identifier that does not appear verbatim in the scanner input. Fabricated identifiers, versions, or scores are a defect. | e2e |
| VM-F-303 | MUST | Where a value is unknown, triage shall record `unknown` and state where it would be obtained, rather than inferring it. | e2e |
| VM-F-304 | MUST | Priority shall be computed from a documented composite of: base severity, exploit-prediction score, known-exploited status, reachability, dependency class (production vs development), and repository tier. | unit |
| VM-F-305 | MUST | The composite scoring function shall be deterministic and implemented in code, not delegated to inference. | inspection |
| VM-F-306 | MUST | Triage results shall be cached against the fingerprint; an unchanged finding shall not be re-triaged on a subsequent run. | integration |
| VM-F-307 | MUST | Triage shall nominate findings it believes are not exploitable, with reasoning, as suppression proposals. It shall never apply a suppression. | e2e |
| VM-F-308 | MUST | Triage input shall be batched; per-finding inference calls are non-compliant. | inspection |
| VM-F-309 | MUST | All scanner output, advisory text, and repository content consumed during triage shall be treated as untrusted data. Instructions found within it shall not be executed. | e2e |

### 5.9 Policy engine (VM-F-4xx)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-401 | MUST | Every decision to remediate, to open a ticket, or to take no action shall be made by a deterministic policy engine, not by inference. | inspection |
| VM-F-402 | MUST | Policy shall be expressed in a declarative, version-controlled configuration file. | inspection |
| VM-F-403 | MUST | Policy shall be resolvable per repository tier, per language, and per finding class. | unit |
| VM-F-404 | MUST | The policy engine shall emit exactly one outcome per finding from a closed enumeration: `auto_remediate`, `open_ticket`, `escalate_p0`, `skip_in_progress`, `skip_declined`, `skip_suppressed`, `defer_upstream`. | unit |
| VM-F-405 | MUST | Every policy decision shall be recorded with the rule that produced it, for audit. | integration |
| VM-F-406 | MUST | Major-version dependency upgrades shall not be automatically remediated by default. | unit |
| VM-F-407 | MUST | Secret findings shall never be routed to remediation, under any policy configuration. This shall not be overridable. | unit |
| VM-F-408 | MUST | Policy shall enforce a maximum number of findings per pull request, configurable, with a separate and lower limit for code changes than for dependency bumps. | integration |

### 5.10 Remediation (VM-F-5xx)

> **Amended 22 October 2026: see `REMEDIATION-DESIGN.md`.** These
> requirements stand, with these changes:
> - **VM-F-501:** the branch and pull request are created only after a
>   recorded human approval of the exact diff (the review's requirement 1).
>   The pull request is no longer where a human first decides.
> - **VM-F-531:** a fix is also verified by a re-run of **all** scanners for
>   the repository, failing on any new finding, and by the non-CVE
>   regression checks in `REMEDIATION-DESIGN.md` §6.3.
> - **VM-F-534** (coverage delta) becomes MUST.
> - **VM-F-541** ("not automatically merged in v1.0") becomes permanent for
>   human-approved fixes: merging happens in GitHub under branch protection.
>   Any automatic merge is limited to the autonomy guardrails of
>   `REMEDIATION-DESIGN.md` §10 and needs a formal approval.
>
> New requirements (two risks with confidence, thresholds per severity, an
> approver role, the review page) are specified there and will be numbered
> VM-F-55x when the requirements are next revised.

#### General

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-501 | MUST | Remediation shall operate on a branch and shall deliver changes exclusively via pull request. Direct pushes to any default or protected branch are prohibited. | e2e |
| VM-F-502 | MUST | Branch names shall be derived from the fix group's identity such that re-running remediation for the same fix group is idempotent. | integration |
| VM-F-503 | MUST | Remediation shall be parallel across repositories and strictly serialised within a repository. | e2e |
| VM-F-504 | MUST | A baseline build and test result shall be established before any change is made. If the baseline is already failing, remediation for that repository shall abort with reason `BUILD_FAILED` or `TESTS_FAILED` and shall report the pre-existing failure. | integration |
| VM-F-505 | MUST | Each logical fix shall be a separate commit, with the finding identifier in the commit message. | inspection |
| VM-F-506 | MUST | Where a fix cannot be completed, the branch shall be discarded in full. A partial fix shall never be pushed. | integration |
| VM-F-507 | MUST | Remediation shall never apply a suppression directive. Where suppression is believed correct, it shall be proposed in the pull request body and the finding marked `SUPPRESSION_PROPOSED`. | e2e |
| VM-F-508 | MUST | Remediation shall never modify files on the configured deny-list. Violation shall hard-fail the job. | unit |
| VM-F-509 | MUST | The deny-list shall include, at minimum: CI workflow definitions, code ownership files, and infrastructure-as-code definitions. | inspection |
| VM-F-510 | MUST | Deny-list enforcement shall be implemented as a post-change diff inspection, not as prompt instruction. | unit |

#### Batch classes

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-521 | MUST | Dependency upgrades that require no source change shall be performed deterministically, without language-model inference. | inspection |
| VM-F-522 | MUST | Dependency upgrades requiring call-site adaptation shall be performed by an agentic worker, which shall consult upstream release documentation before adapting. | e2e |
| VM-F-523 | MUST | Source-level defect fixes shall be performed by an agentic worker and shall apply the minimal change that closes the defect. | e2e |
| VM-F-524 | MUST | An agentic source-level fix shall not be attempted in a repository with no executable test suite; the finding shall instead be routed to a ticket with reason `NO_TEST_COVERAGE`. | integration |
| VM-F-525 | MUST | For every agentic source-level fix, a test shall be added or extended that fails against the prior behaviour and passes against the new behaviour. Where this is not possible, the worker shall state why and describe the manual verification required. | e2e |
| VM-F-526 | MUST | Configuration and container fixes shall be remediated last, after code and dependency batches. | inspection |

#### Verification

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-531 | MUST | Every remediation shall be verified by, at minimum: a successful build, a successful test run, a clean dependency-manifest tidy check, and a re-run of the scanners that produced the findings being fixed. | e2e |
| VM-F-532 | MUST | Verification output shall be recorded verbatim. Summarising away a failure is a defect. | e2e |
| VM-F-533 | MUST | A finding shall only transition to `VERIFIED` when a subsequent scan of the merged default branch no longer observes it. Merging a pull request is not sufficient. | integration |
| VM-F-534 | SHOULD | Test coverage shall be compared against the pre-change baseline and the delta reported. | integration |

#### Pull requests

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-541 | MUST | Pull requests shall not be automatically merged in v1.0. | inspection |
| VM-F-542 | MUST | Pull requests shall be labelled to identify them as machine-generated. | integration |
| VM-F-543 | MUST | The pull request body shall state: findings addressed, changes made, residual risk, anything deferred and why, any breaking change, and explicit manual steps required of the reviewer. | e2e |
| VM-F-544 | MUST | Commits shall be attributable to the framework's own identity, distinguishable from human authorship. | inspection |
| VM-F-545 | MUST | A pull request closed without merge shall transition its findings to `DECLINED`. | integration |

### 5.11 First-party shared modules (VM-F-6xx)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-601 | MUST | The system shall maintain a registry mapping first-party module paths to their owning repository. | inspection |
| VM-F-602 | MUST | The system shall construct a reverse-dependency index across the fleet from the dependency manifests already read during scanning. | integration |
| VM-F-603 | MUST | Where a finding's vulnerable path traverses a first-party module, remediation shall target the owning repository only. | integration |
| VM-F-604 | MUST | Consumer repositories shall have the corresponding finding set to `BLOCKED_UPSTREAM` with a reference to the upstream fix. No consumer pull request shall be opened in Wave 1. | e2e |
| VM-F-605 | MUST | Consumers shall not receive individual tickets for a finding blocked upstream; a single upstream ticket shall list affected consumers. | integration |
| VM-F-606 | MUST | On publication of the upstream fix — merge or tag, per configuration — the system shall open consumer upgrade pull requests as a wave. | e2e |
| VM-F-607 | MUST | Wave 2 consumer upgrades shall be deterministic and shall not use inference. | inspection |
| VM-F-608 | MUST | A consumer with a `replace` directive affecting the module shall be excluded from the wave and reported for manual handling. | integration |
| VM-F-609 | MUST | Blocked findings shall be included in report counts under `not fixed` with reason `BLOCKED_UPSTREAM_FIRST_PARTY`. | integration |
| VM-F-610 | MUST | Reachability shall be determined and recorded **per consumer**, not inherited from the upstream finding. A repository may depend on a vulnerable shared module without executing the vulnerable path. | integration |
| VM-F-611 | MUST | Blast radius shall be reported as two distinct figures: consumers that depend on the module, and consumers that reach the vulnerable code. Dependency count alone overstates exposure. | e2e |
| VM-F-612 | MUST | Module fan-out shall be maintained as a standing artifact, queryable in the absence of any active finding, so exposure can be assessed before an advisory arrives. | integration |
| VM-F-613 | MUST | Version spread across consumers of a first-party module shall be detected and reported. Consumers on divergent versions cannot be advanced to a single target in one wave. | integration |
| VM-F-614 | MUST | Where the Wave 2 trigger is tag publication, a merged Wave 1 fix with no subsequent tag shall be detected and escalated. The pull request closes, the consumers stay blocked, and nothing otherwise signals it. | e2e |
| VM-F-615 | MUST | Wave 1 pull request age shall be reported together with the count of blocked consumers and of consumers reaching the vulnerable code. | e2e |

### 5.12 Reporting (VM-F-7xx)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-701 | MUST | Every run shall produce a fleet report and a per-repository report. | e2e |
| VM-F-702 | MUST | The machine-readable report shall be the authoritative artifact. Human-readable formats shall be rendered from it deterministically, never generated independently. | inspection |
| VM-F-703 | MUST | The fleet report shall state, at minimum: total found, total fixed, total not fixed, and the delta of each against the previous run. | e2e |
| VM-F-704 | MUST | Not-fixed counts shall be broken down by reason code. | e2e |
| VM-F-705 | MUST | New findings and regressions shall each be reported as distinct sections. | e2e |
| VM-F-706 | MUST | The report shall include a per-repository rollup: tier, language, found, fixed, open by severity, pull requests opened. | e2e |
| VM-F-707 | MUST | The report shall enumerate coverage gaps: repositories not scanned, scanners that failed, and the reason in each case. | e2e |
| VM-F-708 | MUST | The report shall record scanner image identity and all tool versions, so a change in finding counts can be attributed. | e2e |
| VM-F-709 | MUST | Reports shall be published to a stable, permanently addressable location. Expiring or signed-URL storage is non-compliant. | inspection |
| VM-F-710 | MUST | Report history shall be retained and diffable across runs. | operational |
| VM-F-711 | MUST | No report shall contain a secret value. | unit |
| VM-F-712 | MUST | The report shall include token and cost accounting per VM-F-9xx. | e2e |
| VM-F-713 | MUST | Deltas shall be computed against the previous run **of the same kind**. Comparing a full sweep against a single-repository manual run produces a meaningless figure. | unit |
| VM-F-714 | MUST | The report shall state scan coverage for the run as a percentage of the planned fleet, and shall trend it across runs. Coverage falling is a more serious signal than findings rising, and a single-run figure cannot show decay. | e2e |
| VM-F-715 | MUST | The report shall state SLA breach counts by severity and by repository. | e2e |
| VM-F-716 | MUST | The report shall state the count of findings not re-observed while unresolved, and shall not include them in any fixed or resolved figure. | e2e |
| VM-F-717 | MUST | Every count in a report shall be reproducible by a query the reader can execute. | inspection |
| VM-F-718 | MUST | The run identifier and start timestamp shall appear together on every report artifact. | inspection |

#### Report generation (VM-F-73x)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-731 | MUST | Report generation shall be a single subsystem. The automatic per-run report shall be one template invocation of it, not a separate implementation. | inspection |
| VM-F-732 | MUST | A report shall be generatable on demand by a user, on a schedule, or by the pipeline at run completion, through the same mechanism. | e2e |
| VM-F-733 | MUST | Every generated report shall receive a unique, permanent, citable identifier. | unit |
| VM-F-734 | MUST | Every report shall record the query that produced it: template, corpus scope, filters, run anchor, and generation timestamp. | integration |
| VM-F-735 | MUST | A report shall be anchored to a run. A report generated from live state cannot be reproduced and shall not be issued. | integration |
| VM-F-736 | MUST | Regenerating a report from a stored query against the same anchor shall produce identical content. Where it does not, that is a defect. | e2e |
| VM-F-737 | MUST | Reports shall be immutable once issued. A correction is a new report referencing the superseded one. | integration |
| VM-F-738 | MUST | Every report shall carry a content hash, so a circulated copy can be verified against the issued original. | unit |
| VM-F-739 | MUST | Reports shall be rendered from the authoritative machine-readable result set through shared templates. A second rendering path is non-compliant. | inspection |

#### Report content and audience (VM-F-74x)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-741 | MUST | The following templates shall be supported: fleet summary, repository digest, executive summary, audit evidence pack, remediation queue, first-party exposure, coverage attestation. | e2e |
| VM-F-742 | MUST | Each template shall declare its intended audience and shall omit detail that audience cannot act on. | inspection |
| VM-F-743 | MUST | The audit evidence pack shall include scanner image identity, tool versions, coverage attestation, and the explicit statement of what was not scanned. An evidence pack that omits coverage gaps misrepresents the assurance provided. | e2e |
| VM-F-744 | MUST | The coverage attestation template shall state, per repository, whether it was scanned, by which tools, and when it was last scanned successfully. | e2e |
| VM-F-745 | MUST | The repository digest shall be scoped to one repository and shall be suitable for delivery to its code owners without further editing. | e2e |
| VM-F-746 | MUST | The executive summary shall carry counts, trends, SLA posture, and coverage, and shall not enumerate individual findings. | inspection |
| VM-F-747 | MUST | Every report shall state its corpus scope in words, on the document. | inspection |

#### Report safety, access, and delivery (VM-F-75x)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-751 | MUST | No generated report shall contain a secret value, in any template, format, or delivery channel. | unit |
| VM-F-752 | MUST | A report shall inherit the visibility restrictions of its content. Where the generating user may see records the recipient may not, the report shall be redacted at generation and the redaction recorded on the document. | integration |
| VM-F-753 | MUST | A redacted report shall state that redaction occurred and how many records were withheld, so a reader is not misled by an incomplete count. | e2e |
| VM-F-754 | MUST | Generation shall be bounded in size and duration; an unbounded request shall be rejected with a stated limit rather than attempted. | integration |
| VM-F-755 | MUST | Every generation shall be logged with requesting user, query, and delivery target. | operational |
| VM-F-756 | MUST | Supported output formats shall include machine-readable structured data, repository-native Markdown, tabular export, and a fixed-layout document format for circulation. | e2e |
| VM-F-757 | MUST | Delivery targets shall include download, commit to the report repository, and attachment to a ticket. | integration |
| VM-F-758 | SHOULD | Scheduled report definitions shall be supported, with recipients and cadence, and shall reuse the same templates. | integration |
| VM-F-759 | MUST | A scheduled report that fails to generate shall raise a failure signal. Silent non-delivery of a security report is worse than no report, because absence is read as no news. | integration |

### 5.13 Ticketing (VM-F-8xx)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-801 | MUST | The tracker shall be pluggable. GitHub Issues, Jira, and Linear shall all be supported implementations of a single interface. | integration |
| VM-F-802 | MUST | The active backend shall be selectable by configuration without code change. | integration |
| VM-F-803 | MUST | An optional secondary backend shall be supported for mirroring high-severity tickets. Mirroring shall be one-way. | integration |
| VM-F-804 | MUST | Ticket creation shall be idempotent against the fingerprint. A finding shall never produce a second ticket. | integration |
| VM-F-805 | MUST | Idempotency shall be enforced by a durable stored reference and shall not rely on title or body text matching. | unit |
| VM-F-806 | MUST | A regressed finding shall reopen or comment on its original ticket, not create a new one. | integration |
| VM-F-807 | MUST | Ticket granularity shall be: one parent ticket per run; one ticket per pull request opened; one ticket per P0/P1 finding not automatically remediable; one ticket per secret finding. | integration |
| VM-F-808 | MUST | P2 and P3 findings that are not remediated shall be aggregated into the run's parent ticket and shall not receive individual tickets. | integration |
| VM-F-809 | MUST | Every ticket shall contain a link to the relevant report. | e2e |
| VM-F-810 | MUST | Tickets shall be assigned from repository code ownership where resolvable, and to a configured fallback where not. | integration |
| VM-F-811 | MUST | A ticket whose finding reaches `VERIFIED` shall be transitioned to closed. | integration |
| VM-F-812 | MUST | Tracker unavailability shall not fail a run; ticket operations shall be queued and retried. | integration |
| VM-F-813 | MUST | A coverage gap persisting beyond the configured consecutive-failure threshold shall receive a ticket, assigned per VM-F-214, idempotent on the repository and cause. | integration |
| VM-F-814 | MUST | A stalled first-party Wave 1 — open beyond a configurable age with blocked consumers — shall escalate as a single ticket referencing all blocked consumers, not one ticket per consumer. | integration |

### 5.14 Secret handling (VM-F-85x)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-851 | MUST | A secret finding shall be assigned maximum severity and state `NEEDS_HUMAN` on creation. | unit |
| VM-F-852 | MUST | A secret finding shall receive its own ticket immediately, never batched. | integration |
| VM-F-853 | MUST | Secret findings shall not abort the run. Remediation of other findings in the same repository shall proceed. | e2e |
| VM-F-854 | MUST | Where a proposed change would touch a file containing a flagged secret, that specific fix shall be abandoned. | integration |
| VM-F-855 | MUST | The system shall never rewrite commit history, and shall never remove a secret from a working tree as a remediation. | inspection |
| VM-F-856 | MUST | Ticket text shall state that removal from source does not constitute remediation and that credential rotation is required. | inspection |

### 5.15 Accounting and observability (VM-F-9xx)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-901 | MUST | Token consumption shall be recorded per job, broken down by input, output, cache read, and cache write. | integration |
| VM-F-902 | MUST | Token records shall be attributable to run, repository, stage, and model. | integration |
| VM-F-903 | MUST | Token records shall be joined to outcome, enabling cost per finding fixed and cost per abandoned attempt to be computed. | integration |
| VM-F-904 | MUST | Token accounting shall be reported per run and aggregated per repository. | e2e |
| VM-F-905 | MUST | No token ceiling shall be enforced in v1.0. The mechanism to enforce one shall exist and be disabled by configuration. | inspection |
| VM-F-906 | MUST | The system shall emit metrics sufficient to compute: mean time to remediation by severity, SLA compliance, open finding age distribution, scan coverage, and backlog trend. | operational |
| VM-F-907 | MUST | Every run shall be traceable end to end by run identifier through logs and stored records. | operational |
| VM-F-908 | MUST | SLA status shall be computed per finding from its age, priority, and repository tier, and shall be exposed rather than left to consumers to derive. | unit |
| VM-F-909 | MUST | SLA status shall distinguish: within window, approaching, breached, paused, and stopped. A paused finding shall never register as breached. | unit |
| VM-F-910 | MUST | Age shall be reported alongside SLA status, never alone. The same elapsed time is unremarkable at one priority and a breach at another. | inspection |
| VM-F-911 | MUST | Scan coverage percentage shall be an emitted metric, trended per run alongside finding counts. | operational |

### 5.16 Security of the framework itself (VM-F-10xx)

| ID | Norm | Requirement | Verify |
|---|---|---|---|
| VM-F-1001 | MUST | Repository credentials shall be scoped to a single repository and shall be short-lived. A worker acting on one repository shall hold no credential valid for another. | inspection |
| VM-F-1002 | MUST | Worker network egress shall be restricted to an explicit allow-list. | inspection |
| VM-F-1003 | MUST | Workers shall have no access to cloud instance metadata endpoints. | inspection |
| VM-F-1004 | MUST | Worker containers shall be ephemeral and shall not persist state between jobs. | inspection |
| VM-F-1005 | MUST | Remediation workers execute untrusted repository code and shall be isolated accordingly. | inspection |
| VM-F-1006 | MUST | Any content retrieved from an external source, including advisory text and upstream release notes, shall be treated as untrusted data. | e2e |
| VM-F-1007 | MUST | Framework behavioural constraints shall be enforced by the execution harness. Prompt content shall not be the sole control for any security property. | inspection |
| VM-F-1008 | MUST | Dependency integrity verification shall be performed after every dependency change. | integration |

---

## 6. Non-functional requirements

| ID | Norm | Requirement |
|---|---|---|
| VM-NF-101 | MUST | A diff-scoped pull request scan shall complete within 5 minutes for a repository of median size. |
| VM-NF-102 | SHOULD | A full-repository scan shall complete within 15 minutes per repository. |
| VM-NF-103 | MUST | A full fleet sweep shall complete within its scheduling interval. |
| VM-NF-201 | MUST | Concurrency shall be centrally budgeted so that fleet-wide parallelism does not exhaust external API rate limits. |
| VM-NF-202 | MUST | Rate-limit exhaustion shall degrade gracefully, deferring work rather than failing the run. |
| VM-NF-301 | MUST | Remediation SLA windows shall be configurable per severity and per tier. |
| VM-NF-302 | MUST | The SLA clock shall start at detection, not at triage or assignment. |
| VM-NF-303 | MUST | The SLA clock shall stop at `VERIFIED`, not at merge. |
| VM-NF-304 | MUST | The SLA clock shall pause where the reason code is `NO_UPSTREAM_FIX`. |
| VM-NF-401 | MUST | All state shall be durable; a crashed component shall not lose findings, tickets, or history. |
| VM-NF-402 | MUST | Runs shall be resumable or safely re-runnable; re-running shall not duplicate pull requests or tickets. |
| VM-NF-501 | MUST | Adding a repository shall require no code change. |
| VM-NF-502 | MUST | Adding a scanner shall require implementing one adapter interface and no change to downstream components. |
| VM-NF-503 | MUST | Adding a tracker backend shall require implementing one interface and no change to calling code. |

---

## 7. Acceptance criteria for v1.0

1. A scheduled sweep runs across the full fleet without manual intervention.
2. Findings are fingerprinted, deduplicated across tools, and stable across runs — demonstrated by a run against an unchanged repository producing zero new findings.
3. A fleet report is published with found / fixed / not fixed counts and deltas.
4. Tickets are created with correct granularity and are idempotent across three consecutive runs.
5. Deterministic dependency bumps produce merged, verified pull requests.
6. Agentic remediation produces at least one merged, verified source-level fix with an accompanying test.
7. A vulnerability in the shared common module produces exactly one Wave 1 pull request and, on publication, a complete Wave 2 consumer wave.
8. A planted test secret is detected, ticketed at maximum severity, never remediated, and never appears in any report or ticket body.
9. Token accounting is present and per-finding cost is computable.
10. The deny-list guard is demonstrated to hard-fail on an attempted CI workflow modification.
11. A repository whose scan fails does not cause its findings to be marked verified; they are reported as not re-observed and linked to the gap.
12. A repository failing scans for two consecutive runs produces an escalation without anyone opening a dashboard.
13. A first-party finding reports depend-count and reach-count as distinct figures, and a merged Wave 1 with no published tag is detected.
14. Deltas on a run overview compare against the previous run of the same kind.
15. An audit evidence pack is generated for a past run, contains the coverage attestation including unscanned repositories, and regenerates byte-identically from its stored query.
16. A report generated by a security owner and delivered to a non-privileged recipient is redacted, and states that redaction occurred.

---

## 8. Open questions

| ID | Question | Owner | Needed by |
|---|---|---|---|
| VM-OQ-01 | Tier assignment for each repository in the fleet. Policy is unusable until this exists. | Platform | Before Phase 6 |
| VM-OQ-02 | SLA windows per severity per tier. | Security | Before Phase 7 |
| VM-OQ-03 | Is the shared common module consumed by semantic version tag or pseudo-version? Determines the Wave 2 trigger and puts the release process on the remediation critical path if tagged. | Platform | Before Phase 11 |
| VM-OQ-04 | Fallback assignee where code ownership is unresolvable. | Platform | Before Phase 8 |
| VM-OQ-05 | Which tracker backend is primary at launch, and is a mirror required? | Platform | Before Phase 8 |
| VM-OQ-06 | Static analysis severity and confidence thresholds per tier. Defaults will be noisy; needs calibration during Phase 5 shadow running. | Security | Before Phase 6 |
| VM-OQ-07 | Retention period for reports and observation history. | Platform | Before Phase 7 |
| VM-OQ-08 | Does any repository lack a test suite entirely, and if so what is the remediation posture for it? | Platform | Before Phase 10 |
| VM-OQ-09 | How is `MERGED` counted in headline figures — resolved, unresolved, or its own bucket? It is genuinely neither, and the choice changes every reported total. | Security | Before Phase 7 |
| VM-OQ-10 | Consecutive-failure threshold for coverage gap escalation (VM-F-215). Two runs is the working default. | Platform | Before Phase 8 |
| VM-OQ-11 | Wave 1 stall threshold for escalation (VM-F-814), and whether it scales with blocked-consumer count. | Platform | Before Phase 11 |
| VM-OQ-12 | Should module fan-out influence priority? A P2 in a shared module reaching four tier-1 services may outrank a P1 in one tier-3 repository. The current scoring model cannot express this. | Security | Before Phase 5 |
| VM-OQ-13 | Are advisory and manual runs shown in run history by default, or filtered out unless requested? Useful for audit, noise when reading a sweep trend. | Platform | Before Phase 7 |
