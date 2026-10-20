# Decisions needed

Every item here is a decision the build deliberately did **not** make, because
making it would have been irreversible, safety-critical, an external contract,
or dependent on a credential nobody should issue to an automated build. In each
case the surrounding work was completed and the decision was designed around
rather than assumed.

Nothing in this list blocks running the framework or reading the interface.
Each one blocks a specific step towards production, and says which.

**`GO-LIVE-CHECKLIST.md` is the ordered version of this file**: the same
items, sequenced, each with its exact precondition, what unblocks it, and what
is already built for it. Read this one to understand a decision; read that one
to make them in a safe order.

**What changed since this was written.** The finishing pass built the CODE for
several of these and left every DECISION untouched, which is the distinction
the two documents keep. Where an item now has a real implementation waiting on
a human, it says so below.

---

## D1 — The first live agent run against a real repository

**Blocks:** using the agentic fixer on anything real.

The agentic remediation path is complete and tested against a hostile fake
agent. It has never been run against a real repository, and doing so is a
supervised human milestone rather than a build step.

**The decision:** who supervises it, on which repository, and what the
acceptance criteria are for letting it run unsupervised afterwards.

**What must be true first (in order):**

1. The sandbox's boundary probes pass against the REAL sandbox on Linux
   (`bwrap`), not the fake — see D2. Until then the isolation is unproven.
2. A real API key exists and is held where the harness can read it and the
   agent cannot. **No key should be issued to any machine where D2 has not
   passed.**
3. A repository is chosen whose blast radius from a bad change is acceptable,
   and whose test suite is meaningful.
4. A person watches the whole run and reads the diff before it is pushed.

**Why it was not done here:** a build cannot supervise itself, and an
unsupervised first agent run against a real repository is the single highest-
consequence action in the system.

---

## D2 — The Linux CI job that proves the sandbox

**Blocks:** D1, and therefore all agentic remediation.

`internal/sandbox` probes its own boundaries with canaries — a network call, an
environment read, a write outside the clone — and refuses to run an agent if
any probe did not run or did not deny. Every test of it runs against the
**fake** sandbox, because this build runs on macOS and the real implementation
needs Linux namespaces.

**The decision:** where that CI job runs, and who owns it.

**What it must prove:**

* each probe RUNS and is DENIED under `bwrap`;
* a skipped probe is never reported as a denial;
* the harness REFUSES to start when isolation cannot be established
  (`sandbox.Unisolated` must never verify);
* the process-tree containment holds — a child that outlives its parent is
  killed with the group (OQ-P10b-02, untestable on macOS because `sh` execs
  `sleep` directly rather than forking).

**Until it passes:** the agent path is code-complete and unproven. Treat the
fake's green tests as evidence about the harness, not about the isolation.

**Since written:** the probe suite and the CI job both exist
(`internal/sandbox/real_test.go` under the `sandboxprobe` build tag, and
`.github/workflows/sandbox-probe.yml`). The **macOS half now passes** on the
development machine — network, environment and filesystem boundaries all held
under `sandbox-exec`.

Writing it found a defect that made the environment probe incapable of ever
passing against a real backend: the canary was injected past the allowlist
into the child's own environment, and no isolation backend strips environment
variables. See BUILD-LOG, finishing pass.

What remains is Linux: real `bwrap`, and the orphan-pipe hazard that does not
reproduce on macOS.

---

## D3 — Live KEV and EPSS feeds

**Blocks:** priorities that can see whether a vulnerability is being exploited.

The exploitation-intelligence boundary is complete, with a hostile fake that
models stale snapshots, absent identifiers, malformed rows, truncation, rate
limits and outages. There is no live client: the interface has exactly one
implementation and it is the fake.

**The decisions:**

1. **Where the snapshots come from.** EPSS publishes a daily CSV; KEV is a
   single JSON catalogue. Both are third-party endpoints with their own
   outages.
2. **Where they are cached, and for how long.** A fetch on every run against a
   third party is a rate limit waiting to happen; a cache with no expiry is a
   stale answer presented as current.
3. **The freshness window.** `feed_freshness_days` is 7 in calibration. A
   stale answer is used and labelled rather than discarded, and somebody has to
   decide what "stale" means for their incident response.
4. **What to do when a feed is down for a day.** The framework already scores
   without it and says so on every affected number. Whether that is acceptable
   for a given fleet is a policy decision.

**Until then:** every priority in the system names the inputs it is missing,
inline, wherever it is rendered. The scorer's `kev_boost` and
`epss_coefficient` are configured and can never fire.

**Since written:** `feed.KEVSource` and `feed.EPSSSource` are implemented and
tested — a feed that is down is `*ErrUnavailable` and never an empty result, a
truncated catalogue is refused, an unlisted identifier is omitted rather than
zero-filled, a malformed row is dropped and counted.

**One thing to do before the decisions below.** The fixtures in
`testdata/feeds/` were written by hand to the publishers' documented formats
and NOT captured from the live services, because this build has no network.
Capture one real response from each endpoint and diff it first.

---

## D4 — GitHub App installation and credentials

**Blocks:** scanning or remediating anything real; the webhook path.

The GitHub surface is behind an interface with a hostile fake that opens
duplicate pull requests, rejects conflicting pushes, rate-limits and fails
mid-operation. The webhook verifier, the delivery log and the endpoint are
complete and tested.

**The decisions:**

1. **Creating the App** and its permission set: which repositories, and
   whether it may write branches everywhere it can read.
2. **Where the private key and the webhook secret live.** The framework reads
   them from the environment and holds them in one place; nothing else in the
   process can reach them.
3. **The public webhook endpoint.** Until one exists, the primary path for
   pull-request state is unreachable from outside the process and the bounded
   reconciliation fallback carries everything.
4. **The identity binding for report publication.** The publisher refuses to
   deliver externally until an identity binding exists
   (`ErrIdentityUnbound`) — a deliberate refusal, not a gap.

**Since written:** `gh.AppClient` and `gh.RESTOps` are implemented and tested
against recorded responses. The behaviours the hostile fake models all have
real counterparts: lost-page detection against the server's declared total,
rate limits in all three forms GitHub expresses them, 422-duplicate adoption,
`merged_at` as well as `merged`, and an empty listing refused as
`ErrEmptyFleet`.

---

## D5 — Real scanners, pinned and reproducible

**Blocks:** any finding about real code.

Nine adapters are implemented and tested against real captured tool output in
`testdata/fixtures`. The tools themselves are not installed here, and
`internal/remediate.Toolchain` — `go get`, `go mod tidy`, `go build`,
`go test -race` — has **no real implementation at all**: every remediation test
runs against `FakeToolchain`.

**The decisions:**

1. **The scanner image**, with every tool pinned by digest, so a change in
   finding counts is attributable to the fleet rather than to a silent tool
   upgrade.
2. **Who owns `config/tools.lock`** and what happens when a tool's output
   format changes — the adapter tests fail loudly on purpose.
3. **Building the real toolchain.** This is the largest single piece of unbuilt
   work in the repository, and OQ-AUDIT-06 showed why it matters: the fake's
   `Verify` answered a subtly different question from the one the interface
   asks, and no single-group test could see it.

**Since written:** the Go half of the third decision is **done**.
`internal/remediate/gotool` is the real toolchain — `go build`, `go vet`,
`go test -race`, `go get` with bisection, `go mod tidy`, and a re-run of the
scanners — proved against controlled fixture modules and a local module proxy,
under sandbox confinement.

VM-AD §11.3 also specifies JavaScript, and that is still unwritten
(OQ-FIN-01). A JavaScript repository cannot be remediated; remediation
declines it rather than getting it wrong.

---

## D6 — Authentication and authorisation in front of the API

**Blocks:** serving real data to anyone.

The API refuses to start without an authenticator and refuses to serve a
caller whose privilege level could not be established. It ships with two:
`HeaderAuth`, which trusts headers set by an authenticating proxy, and
`DemoAuth`, which grants one fixed identity and is only safe because the
demonstration binds to localhost and its data is invented.

**The decisions:**

1. **Which identity provider**, and how group membership maps to the three
   privilege levels (public, engineer, security owner).
2. **Where the proxy terminates.** `HeaderAuth` is safe only where a client
   cannot set those headers, which is a deployment property this code cannot
   check.
3. **Access logging.** VM-UI-F-805 asks for it and nothing logs access today.

**Since written:** the third decision's blocker is gone. **Access logging is
implemented** (VM-UI-F-805), and it records REFUSALS as well as reads — a log
of successful reads is blind to somebody probing what they cannot see. Where
the records go, how long they are kept and whether they must be tamper-evident
remain yours.

---

## D7 — SLA windows (VM-OQ-02)

**Blocks:** treating a breach count as a commitment.

The windows in `config/calibration.yaml` are the specification's working
defaults. `sla.calibrated` is `false`, and while it is false every breach
count in every report, ticket and screen carries a "provisional" qualifier
inline.

**The decision:** the actual windows per tier and priority, agreed with the
teams they bind. Then set `calibrated: true`, and the qualifier disappears
everywhere at once — which is the test that it was never decoration.

---

## D8 — Static-analysis thresholds (VM-OQ-06)

**Blocks:** trusting the P0/P1 routing.

`static_analysis.calibrated` is `false`. The thresholds are defaults and are
expected to be noisy. Every priority rendered anywhere says so.

**The decision:** run the shadow run the specification describes, review the
false-positive rate per tier, and set the thresholds. Same mechanism as D7:
the flag clears the caveat everywhere.

---

## D9 — Whether blast radius should influence priority (VM-OQ-12)

**Blocks:** nothing. It is recorded because the data is accumulating.

Blast radius is computed and stored on every finding and does **not** affect
the score (`fanout.enabled: false`). A vulnerability in a widely-consumed
shared module can therefore rank below one confined to a single repository,
and every report says so.

**The decision:** whether to enable it and with what weighting. The data to
decide with has been collected since the first sweep, which was the point of
recording it while it was inert.

---

## D10 — Report supersession

**Blocks:** nothing today; a correctness gap in the archive.

Reports are immutable and content-hashed. `store.Report.Supersedes` exists,
VM-UI-F-1108 requires both a superseded report and its replacement to remain
visible with the relationship stated — and **nothing writes the field**. The
producer-coverage audit records it as an honest writer gap rather than filling
it with a guess.

**The decision:** what supersession means operationally (a corrected figure? a
re-issue after a redaction change?) and which path sets it.

**Since written:** the MECHANISM is built. `report.Query.Supersedes` carries
the relationship, the store enforces that a report may be superseded at most
once across both backends, the superseded report is never deleted or modified,
and the interface states the relationship on both reports.

The decision below is untouched and is still yours: what supersession MEANS
operationally, and which path sets it. The mechanism consumes that decision.

---

## D11 — Production deployment

**Blocks:** production.

Not a decision this build can even frame usefully: where it runs, how the
orchestrator is scheduled, how workers are dispatched, what the database's
backup and retention policy is, who is paged when a sweep fails. Listed so it
is not mistaken for something already handled.

`FINAL-STATUS.md` lists what is real and what is a stub, which is the input to
this decision.

---

## D12 — Phase 1: what is scanned, how versions compare, and whose rules

Recorded 2026-10-19. Two parts are **decided**; the third is decided in
principle, with a per-language proposal **awaiting approval** before anything
is built.

### Decided

- **Exclusions.** `vendor/` is excluded from dependency and code scanning (its
  dependencies are declared by the parent manifest, and its code is someone
  else's) but **kept in secrets scanning**, because vendored files are
  committed and a secret in them is exposed. `node_modules/` and build output
  (`dist/`, `build/` when generated, `target/`, `.venv/`, `venv/`,
  `site-packages/`, `bower_components/`) are excluded **everywhere**: they are
  installed or generated, not authored. Every exclusion is reported with its
  reason and file count, never silent. Test folders are never excluded.
- **Version comparison.** `github.com/google/osv-scalibr/semantic`
  (Apache-2.0): the ecosystem-specific ordering osv-scanner itself uses (PEP
  440, Maven, RubyGems, SemVer, Go and others). A Go library, not a scanner.

### Decided in principle: no official semgrep-rules

The official `semgrep/semgrep-rules` repository is under the **Semgrep Rules
License v1.0**, which does not permit use in a product. Since this may become
one, it is not used, at any commit. Rules written for this project live in
this repository (`vulnframework/config/semgrep/rules/`).

The **semgrep engine** (Community Edition, `semgrep 1.177.0`, already pinned)
is **LGPL-2.1**. Running it unmodified as a separate program is compatible
with a product; shipping it in the scanner image means shipping its licence
text and offering its source. (Opengrep, the community fork, is also
LGPL-2.1 and a drop-in alternative if that ever matters.)

### Licences checked (2026-10-19, from each project's own LICENSE)

| Candidate | Kind | Licence | Usable in a product? |
|---|---|---|---|
| semgrep/semgrep-rules (official) | semgrep rules | Semgrep Rules License v1.0 | **No** |
| GitLab `sast-rules`, files marked MIT | semgrep rules | MIT | **Yes** |
| GitLab `sast-rules`, `go/` | semgrep rules (ported from gosec) | Apache-2.0 | Yes |
| GitLab `sast-rules`, `c/` | semgrep rules (ported from flawfinder) | GPL-2.0 | No (copyleft) |
| GitLab `sast-rules`, `rules/gitlab/` (most) | semgrep rules | GitLab Enterprise Edition licence | **No** |
| GitLab `sast-rules`, `rules/lgpl/` | semgrep rules | LGPL-3.0 | No (copyleft) |
| GitLab `sast-rules`, `rules/lgpl-cc/` | semgrep rules (from semgrep-rules) | LGPL-2.1 + Commons Clause (no selling) | **No** |
| trailofbits/semgrep-rules | semgrep rules | AGPL-3.0 | No |
| 0xdea/semgrep-rules (C/C++) | semgrep rules | MIT | Yes |
| elttam/semgrep-rules | semgrep rules | MIT | Yes |
| dgryski/semgrep-go | semgrep rules | MIT | Yes |
| mindedsecurity android rules | semgrep rules | GPL-3.0 | No |
| Bandit (Python) | tool | Apache-2.0 | Yes |
| eslint-plugin-security (JS) | ESLint plugin | Apache-2.0 | Yes |
| ESLint, typescript-eslint | tool, parser | MIT | Yes |
| eslint-plugin-no-unsanitized (JS) | ESLint plugin | MPL-2.0 | With care (file-level copyleft) |
| njsscan (JS) | tool | LGPL-3.0 | No (copyleft) |
| gosec (Go) | tool, **already used** | Apache-2.0 | Yes |
| staticcheck (Go) | tool, **already used** | MIT | Yes |
| RuboCop, `Security/*` cops (Ruby) | tool | MIT | Yes |
| Brakeman (Ruby) | tool | Brakeman Public Use License (Synopsys) | **No** (source-available) |
| Psalm taint analysis (PHP) | tool | MIT | Yes |
| Progpilot (PHP) | tool | MIT | Yes |
| phpcs-security-audit (PHP) | tool | GPL-3.0 | No |
| PMD (Java) | tool | BSD-style (with DARPA acknowledgement) | Yes |
| SpotBugs / find-sec-bugs (Java) | tool | LGPL-2.1 / LGPL-3.0 | No (copyleft, and needs a build) |
| .NET Roslyn analyzers (C#) | analyzers | MIT | Yes, but need `dotnet build` |
| Security Code Scan (C#) | analyzers | LGPL-3.0 | No |
| flawfinder, cppcheck (C/C++) | tools | GPL-2.0, GPL-3.0 | No (copyleft) |
| ShellCheck | tool | GPL-3.0 | No |
| detekt (Kotlin), clippy (Rust) | tools | Apache-2.0, MIT/Apache-2.0 | Yes, but almost no security checks |
| trivy (IaC, already used) | tool | Apache-2.0 | Yes |
| Checkov, KICS (IaC) | tools | Apache-2.0 | Yes |
| gitleaks (already used) | tool | MIT | Yes |

"Copyleft" tools could legally be run unmodified as separate programs, but
the brief asked for permissive licences, so they are excluded.

**A caution on GitLab's rules.** GitLab marks each rule file with its own
licence, and several MIT-marked sets are ports of rules from tools under other
licences (Bandit, Apache-2.0; find-sec-bugs, LGPL-3.0, for Java and Scala).
GitLab's own determination is that the ported files are MIT. We would rely on
each file's header, keep GitLab's LICENSE beside the copied files, and record
the source commit; **a legal review of the Java and Scala ports is advisable
before this ships as a product.**

### Coverage compared with the official rules

Rule counts are a rough proxy: a rule in one set may cover more or less than a
rule in another. Official = security-category rules in semgrep-rules
`develop`, counted 2026-10-19 (1,674 in total). GitLab = MIT/Apache rule files
at commit `53bf5cf6`.

| Language | Official rules | Permissive replacement available | Gain or loss |
|---|---:|---|---|
| Python | 269 | GitLab MIT: 73 (ports of Bandit's checks); or Bandit itself (31 check modules) | **Large loss**: framework rules (Django, Flask) mostly gone |
| JavaScript | 169 | GitLab MIT: 11; eslint-plugin-security: 15 | **Large loss** |
| TypeScript | 20 | same as JavaScript | Loss |
| Java | 119 | GitLab MIT: 55; PMD (few security rules) | Loss of about half |
| Scala | 26 | GitLab MIT: 87 | **Gain** |
| C# | 48 | GitLab MIT: 22 | Loss of about half |
| Go | 73 | gosec + staticcheck (already run); GitLab's Go rules are gosec ports, so they add nothing | Similar |
| Ruby | 92 | RuboCop `Security/*`: 7 cops | **Almost total loss** |
| PHP | 64 | Psalm taint analysis, Progpilot (whole-program taint, no rule count) | Different, possibly deeper; needs dependencies installed |
| Kotlin | 14 | none permissive | Gap unless we write rules |
| C / C++ | 12 | 0xdea/semgrep-rules (MIT) | Comparable for dangerous-function checks |
| Rust | 10 | none | Gap |
| Terraform, Dockerfile, Kubernetes YAML | 262 + 7 + 50 | trivy misconfig (already run) | No loss: trivy's own check set |
| Generic (mostly secrets) | 248 | gitleaks (already run) | No loss |
| AI / LLM | 107 | none | **Our own rules, Phase 3** |

### Proposal awaiting approval

1. **Vendor GitLab's MIT and Apache files** (Python, Java, Scala, C#,
   JavaScript) at a pinned commit into
   `vulnframework/config/semgrep/vendor/gitlab-sast-rules/`, with GitLab's
   LICENSE and a manifest of source paths. A test refuses any vendored file
   whose header is not MIT or Apache-2.0.
2. **Vendor 0xdea/semgrep-rules (MIT)** for C/C++ the same way.
3. **Write our own rules** where the permissive sets are thin, starting with
   JavaScript/TypeScript (eval and `Function`, `child_process` command
   injection, SQL built from strings, DOM XSS sinks, path traversal, SSRF,
   prototype pollution, weak crypto, JWT `none`), then Ruby and Kotlin. Each
   rule has a vulnerable and a safe test case.
4. **Add no new tool in Phase 1.** Bandit duplicates the GitLab Python ports;
   ESLint, RuboCop and Psalm each need a new adapter, fixtures and an image
   change, and Psalm needs a repository's dependencies installed. Revisit
   per language after the pilot, if our own rules fall short.
5. Where a language has **no** rules (Rust, Shell, Kotlin until written), the
   scan reports a coverage gap "no code rules for <language>", with that
   language's share of the repository, never a clean result.

**Open questions for you:** approve 1–5 as a whole, or say which of these to
change: Bandit, ESLint (with eslint-plugin-security), RuboCop and Psalm can
each be added as a tool instead of, or as well as, our own rules; and whether
to commission the legal review of GitLab's Java and Scala ports now or before
release.
