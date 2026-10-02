# FINISH-PLAN

Every item still outstanding in this repository, sorted into exactly two
buckets. Nothing is built until it appears here.

**The sorting rule.** An item is BUILDABLE-NOW only if real code can be
written for it *and proved against fakes or in-repo fixtures* with no
credential, no live network, no real repository and no human decision. If any
of those is needed, or if the item is ambiguous, it is NEEDS-HUMAN. Ambiguity
loses: a guess recorded as a build is the one failure mode this project exists
to avoid.

**Baseline measured before planning** (so the deltas at the end mean
something). Measured on 2026-10-02, `go test ./...` and `npm test`, both
green:

| | |
|---|---|
| Go tests, top level | **513** |
| Go test runs including subtests (`=== RUN`) | **1037** |
| Interface tests | **73** |
| Go packages with tests | 23 |
| `go build ./...`, `go vet`, `gofmt`, `tsc --noEmit` | clean |

(FINAL-STATUS.md records 519/816/67. The 67→73 difference is the six layout
guards added after it was written; the 519/816 figures were counted by a
different method than the `--- PASS` / `=== RUN` counts used here. The method
above is the one this plan will re-measure against at the end, so the delta is
like-for-like.)

---

## Inventory source

Every item below comes from one of: `FINAL-STATUS.md` §2 (what is fake,
stubbed or unproven), `FINAL-STATUS.md` §3 (human-action checklist),
`DECISIONS-NEEDED.md` D1–D11, or an open question recorded in `BUILD-LOG.md`.
Nothing has been invented for this plan, and nothing in those documents has
been left unsorted.

---

# BUILDABLE-NOW

In dependency order. Each is tests-first, mutation-verified, committed
separately, and green **offline** against its fake or fixture.

## B1 — The real Go toolchain behind `remediate.Toolchain`

*Closes:* the `FakeToolchain`-only row in FINAL-STATUS §2, the build half of
D5, FINAL-STATUS §3 item 3.
*Blocks:* nothing else here; it is first because it is the largest and because
"this fix works" is currently self-confirming.

`internal/remediate.Toolchain` has five methods and **no real
implementation**. Every remediation test proves the harness and not the build.
A new `internal/remediate/gotool` package implements it for Go:

| Method | Real implementation |
|---|---|
| `Baseline` | `go build ./...`, then `go test ./... -count=1`. Output verbatim. |
| `Apply` | `go get <module>@<version>` per target, then `go mod tidy`; resolved versions read back from `go list -m`, never assumed; changed files and diff read from `git`. |
| `TestInventory` | the tree parsed with `go/parser` — see the note below. |
| `Collect` | `git status --porcelain` + `git diff`, including untracked files. |
| `Verify` | `go build`, `go vet`, `go test -race -count=1`, a tidy check that compares `go.mod`/`go.sum` before and after, then a re-run of the scanners that produced the group's findings. |

Five decisions inside it that are not obvious, recorded here so they are
reviewable rather than discovered later:

1. **`TestInventory` parses, it does not execute.** `go test -list` needs the
   package to compile, so a tree that does not build would report an empty
   inventory — which reads as *every test was deleted*. Parsing with
   `go/parser` works on a non-compiling tree, runs none of the repository's
   code, and is the only one of the five methods that therefore needs no
   sandbox. A test whose body begins with an unconditional `t.Skip` counts as
   absent, matching the semantics `FakeToolchain.RemoveTest` already
   documents.
2. **A failed re-scan is not a clean re-scan.** If a scanner cannot be
   executed, `RescanClean` is **false** with the reason named. Absence of a
   report from a tool that did not run is not evidence the finding is gone.
   This is the single most important assertion in the item and gets its own
   mutation.
3. **Scoped to the group (OQ-AUDIT-06).** `Remaining` is the intersection of
   what the re-scan reports with `expect`. A repository with two vulnerable
   modules must not have one group block the other for ever.
4. **Bisect, and say so.** VM-AD §11.3 requires that a failing batch be
   bisected, the offending bump dropped, and the remainder retried.
   `Applied.Dropped` exists for this and — see B1a — nothing writes it and
   nothing reads it.
5. **Confined.** Per the standing rule that a repository's own build and test
   are arbitrary code execution, every command except `TestInventory` is built
   through `sandbox.Sandbox.Command`. A nil sandbox is **refused**, exactly as
   `agent.Client` refuses one. The egress consequence is recorded honestly in
   N6 below rather than worked around.

**Proved against:** new fixture Go modules under `testdata/toolchain/` — a
clean one, one whose tests already fail, one that does not compile, one with a
vulnerable dependency, one whose test prints its own environment, one written
to exercise inventory parsing. Module fetching is proved against a **local
`file://` module proxy** generated into a temp directory at test time, so
`go get` resolves, and resolves *lower than asked* when the proxy has not
mirrored the tag — the behaviour `FakeToolchain` models and the reason
verification re-scans at all. No network, no credential, no external
repository.

**The confinement proof is the fixture's own test.** `env-canary` prints
`os.Environ()` from inside a `go test` run; the assertion is that a secret
present in the parent environment and absent from the allowlist **did not
arrive**. That is assert-the-negative, and it fails if the toolchain is
changed to bypass the sandbox.

## B1a — `Applied.Dropped` gets a producer and a consumer

*Closes:* a **twelfth** instance of the recurring defect, found while planning
B1.

`Applied.Dropped` — "modules the bisect removed after a failure, with why" —
is written by nothing (`FakeToolchain` allocates the map and never fills it)
and **read by nothing**. VM-F-543 requires a pull request body to state
anything deferred and why; a module the bisect dropped is exactly that, and
the reviewer is currently not told.

B1's bisect writes it; `remediate.Body` renders it under residual risk; and
`FakeToolchain` gains a way to produce it so the harness tests can see the
path too. A fake that cannot produce a value the real implementation produces
is a fake kinder than production.

## B2 — Real HTTP client for the exploitation feeds

*Closes:* the "hostile fake only" row for KEV/EPSS in FINAL-STATUS §2; the
*code* half of D3.

`feed.Source` has exactly one implementation and it is the fake. Two real
ones, both `Source`:

* **KEV** — the CISA catalogue, one JSON document, parsed into
  `KEVAvailable`/`KEV`/`KEVAsOf`.
* **EPSS** — the daily CSV (gzipped), parsed into
  `EPSSAvailable`/`EPSS`/`EPSSAsOf`.

Both take an `*http.Client` and a base URL, so the tests drive them against
`httptest` servers serving **recorded fixture payloads** checked into
`testdata/fixtures/feeds/`. No live call, no credential, nothing to configure
to reach green.

What the tests must prove, beyond the happy path, because this is where a feed
client silently lies:

* a non-200, a timeout, a truncated body and a gzip error each produce
  `*feed.ErrUnavailable` — **not** an empty result. An empty result means the
  source answered and knew nothing, and the two must never collapse.
* an identifier the catalogue does not list is **omitted**, never zero-filled.
  `Lookup` returning `{EPSS: 0, EPSSAvailable: false}` for an unknown CVE and
  `{EPSS: 0, EPSSAvailable: true}` for a measured-negligible one are different
  facts and the existing `validate` already depends on the difference.
* a malformed row — EPSS outside 0..1, an empty identifier, a future date — is
  **dropped**, and `Multi` counts it in `Malformed`. The row is never clamped.
* a snapshot date is carried, because freshness is what D3 item 3 is about.

**Enabling them is still NEEDS-HUMAN** (N3): nothing wires these into the
scorer's configuration here, because where the snapshots come from, where they
are cached and what "stale" means are the three decisions D3 exists to
record. This item builds the client and leaves the switch to a person.

## B3 — Real HTTP client for the code host

*Closes:* the "hostile fake only" row for GitHub in FINAL-STATUS §2; the
*code* half of D4.

`gh.App` and `gh.PROps` have one implementation each and both are fakes. Real
ones:

* **`gh.App`** over the REST API: `Repositories` (paginated, and a truncated
  page must be detectable rather than silently short), `Tags`,
  `InstallationToken` via a signed App JWT.
* **`gh.PROps`** over `git` for the clone-side operations and REST for the
  pull-request ones.

Tested against `httptest` with recorded response fixtures, including the
nasty ones the fake already models and which the real client must map
correctly: **422 → `ErrPRExists` carrying the existing pull request**,
**non-fast-forward push → `ErrConflict`**, **403 + `Retry-After` →
`ErrRateLimited`**, and **an empty repository listing → `ErrEmptyFleet`**
rather than an instruction to archive the fleet.

JWT signing is tested with a **test-generated RSA key**, never a real one.

**Installation is still NEEDS-HUMAN** (N4).

## B4 — Real HTTP client for the triage model

*Closes:* the fake-model row for triage; the client half of D1's tooling.

`triage.Client` has one implementation and it is the fake. A real one over the
Anthropic Messages API, taking an `*http.Client` and a base URL and reading
its key from a function (never a field), so "was the key ever fetched" stays
an observable fact — the same pattern `agent.Client` already uses.

Tested against `httptest` with recorded response bodies. What it must prove:

* the request carries no credential value and no repository source
  (`model.AssertNoCredential` over the serialised body, as the agent prompt
  already gets);
* a response that is prose, truncated, or an object with a `priority` field is
  **rejected**, not leniently parsed — the existing validator's contract;
* a 429 and a 529 are distinguishable from a malformed response;
* batch size stays within `MinBatchSize`/`MaxBatchSize`.

**HARD STOP 1 holds:** no real API key, here or in any test. The key function
is never called with anything but a test value.

## B5 — Report supersession, the mechanism

*Closes:* the "field exists, nothing writes it" row; VM-UI-F-1108; the
mechanism half of D10.

`store.Report.Supersedes` is instance 10 of the recurring defect and is still
open. Build the **mechanism**, not the policy:

* a generation path that takes the report being replaced and sets
  `Supersedes`, validating that the two are the same kind, that a report
  cannot supersede itself, that the chain cannot cycle, and that a superseded
  report is **never deleted** (VM-UI-F-1108 is explicit);
* lineage readable in both directions through the API — what this replaces,
  and what replaced it;
* the relationship stated in the interface, beside both reports.

**What supersession *means* operationally stays NEEDS-HUMAN** (N10). The
mechanism consumes a decision; it does not make one. The audit exemption that
currently records the gap is replaced by a real producer, which is the test
that the mechanism is reachable rather than theoretical.

## B6 — `cmd/fixworker`

*Closes:* OQ-AUDIT-07's "`cmd/fixworker` is an empty directory".

`RemediationPass` is callable and tested; nothing invokes it outside tests and
the demonstration. A real `cmd/fixworker` binary that performs one pass and
exits, with flags for the store, the mode and the dry run.

**The schedule stays NEEDS-HUMAN** (N15): a binary that runs one pass is code;
deciding how often it runs, with what concurrency and who is paged when it
fails is deployment. Building the binary does not imply the schedule.

## B7 — The Linux sandbox proof job, written but not run

*Closes:* nothing on its own. Prepares D2.

D2 needs a Linux CI job with real `bwrap`. The **job and the test it runs** are
code and can be written here; only the *running* of it needs infrastructure.
So: a build-tagged probe test that exercises the real sandbox, and a CI
workflow that runs it on Linux.

The critical property, and the reason this is not just a file: on a machine
with no `bwrap` the test **skips loudly** and the skip is never reportable as
a pass. A skipped probe reading as a denial is precisely the lie
`sandbox.Verification.OK()` was written to prevent, and the same rule applies
one level up to the test that calls it.

**Whether it passes is still NEEDS-HUMAN** (N2). This item hands a person a
job to run, not a result.

## B8 — Access logging (VM-UI-F-805)

*Closes:* the "not implemented" row; the logging third of D6.

VM-UI-F-805 is a SHOULD and nothing logs access today. The identity is already
established server-side by the authenticator, so the record has a real
producer without any new decision: who, what resource, what privilege level,
what was withheld, when.

Explicitly in scope *because* it is self-contained; the identity *provider*
(N6) is not.

## B9 — The layout guards OQ-UI-04 names

*Closes:* OQ-UI-04, the open question left by the findings-table defect.

The findings table is the only view with a layout assertion, and the defect
that prompted it was invisible to 73 passing tests, a type checker and a
schema validator. The probe is already general enough to point at another
component. Extend it to the views OQ-UI-04 names — the run overview's figure
grid, the coverage strip, the wave graph — with the same rule as before: where
no browser exists the geometry half **skips loudly**.

---

# NEEDS-HUMAN

Not attempted. Each is sequenced in `GO-LIVE-CHECKLIST.md` with its exact
precondition.

| | Item | Why it cannot be done here |
|---|---|---|
| **N1** | The first live agent run (D1) | A build cannot supervise itself. Needs a real repository, a real key, and a person reading the diff. |
| **N2** | The Linux CI job *passing* (D2) | Needs a Linux runner with `bwrap`. B7 writes the job; running it needs infrastructure. |
| **N3** | Wiring the live feeds (D3) | B2 writes the clients. Where the snapshots come from, where they are cached, what "stale" means and what to do during an outage are four policy decisions. |
| **N4** | Installing the GitHub App (D4) | Needs an App, a private key, a webhook secret and a public endpoint. |
| **N5** | Pinning the scanner image by digest (D5) | Needs a registry and an owner for `config/tools.lock`. |
| **N6** | Identity provider in front of the API (D6) | Needs a provider and a group→privilege mapping. Also the deployment property `HeaderAuth` cannot check. |
| **N7** | SLA window calibration (D7) | **HARD STOP 5.** The windows are a commitment to teams. Inventing them is the exact failure the `calibrated: false` qualifier exists to prevent. |
| **N8** | Static-analysis thresholds (D8) | **HARD STOP 5.** Needs the shadow run and a real false-positive rate. |
| **N9** | Blast-radius weighting (D9) | **HARD STOP 5.** A product decision, with data deliberately accumulated inert. |
| **N10** | What supersession *means* (D10) | B5 builds the mechanism. Which path sets it, and on what event, is operational. |
| **N11** | Production deployment (D11) | Not framable here. |
| **N12** | Installing the real scanners | The adapters are tested against captured output; the tools are not installed and pinning them is N5. |
| **N13** | Enclosing symbol (OQ-AUDIT-02) | No pinned tool reports it. Not a coding gap — it is an absent input, correctly recorded with a test. |
| **N14** | Alias-search latency (OQ-API-01) | The 2-second 95th-percentile requirement needs a fleet-sized corpus to measure against. |
| **N15** | Scheduling remediation (OQ-AUDIT-07) | B6 builds the binary. Cadence, concurrency and paging are deployment. |
| **N16** | Postgres demonstration seeding | Deliberate. Seeding invented findings into a durable store is how invented findings get quoted as real. Not a gap. |
| **N17** | Write paths in the API (OQ-API-03) | A run trigger and a human reset are write paths into a system whose identity layer is N6. The interface is read-only on purpose; adding buttons before the authorisation behind them is backwards. |
| **N18** | Saved filters (VM-UI-F-414) | **Ambiguous, so it loses.** VM-UI-OQ-05 asks whether they are per-user or shared, and a shared store needs a naming convention. It also needs N17's write path and N6's identity. |
| **N19** | Run comparison `changed` states (OQ-API-02) | See the note below. |

### Note on N19, the one genuinely close call

OQ-API-02 — reconstructing a finding's state as of a past run from its audit
trail — is self-contained and needs no credential, which argues for
BUILDABLE-NOW. It is in NEEDS-HUMAN because the reconstruction is only sound
if the audit trail is known to be complete for every transition, and
establishing that is a correctness argument about historical data rather than
a piece of code. Building a `changed` set that is quietly wrong for findings
whose history predates a transition's audit entry would produce exactly the
confident-and-incorrect figure this system is built to refuse. It is recorded
in the checklist with the precondition that makes it buildable: an audit-trail
completeness proof over both backends.

---

## Order of work

B1 → B1a → B2 → B3 → B4 → B5 → B6 → B7 → B8 → B9, then the documents.

B1 first because it is the largest and because everything downstream of
"verified" currently rests on a fake agreeing with itself. B1a immediately
after, because B1 is what gives `Dropped` a producer and leaving it unread
would re-create the defect one layer along.

## What "done" means for each item

1. The gate is written **before** the code it gates.
2. Every check in it is **mutation-verified** — the behaviour is deliberately
   broken and the check is confirmed to fail. A check that cannot fail is not
   a check.
3. Each independent check gets its **own** mutation. Two checks that fail
   together are one check, and this build has four recorded cases of one
   masking another.
4. Every test asserts what must **not** happen, not only what must.
5. Green **offline**: no network, no credential, no external repository.
6. Committed separately, with `BUILD-LOG.md` updated.
