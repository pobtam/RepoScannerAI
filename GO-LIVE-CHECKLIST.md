# Go-live checklist

Everything between this build and a system running against real repositories.

`DECISIONS-NEEDED.md` says what each decision IS and why it was not made.
This says **in what order**, **what exactly unblocks each item**, and **what is
already done for it**. Nothing here has been attempted.

The ordering rule, and it is not arbitrary: **read-only before write, write
before agent, and no credential before the isolation that holds it is proven.**
Each item lists its preconditions explicitly, so a step taken out of order is
visible rather than discovered.

---

## Stage 0 — before any credential exists

### 0.1 Prove the sandbox on Linux — **D2, and the gate for everything else**

**Precondition:** none. This is first.

**What is already done.** `internal/sandbox` is implemented. The probe suite is
written (`internal/sandbox/real_test.go`, build tag `sandboxprobe`) and the CI
job is written (`.github/workflows/sandbox-probe.yml`). The macOS half has
**passed** on the development machine: network, environment and filesystem
boundaries all held under `sandbox-exec`.

**What you do.** Run the job on a Linux runner with `bubblewrap` installed:

```
go test -tags sandboxprobe -count=1 -v ./internal/sandbox/
```

**It must show:**

| | |
|---|---|
| each probe RUNS and is DENIED under real `bwrap` | `TestTheRealSandboxDeniesEveryBoundary` |
| a probe that cannot detect a leak reports "did not run", never a denial | `TestAnUndetectableEnvProbeDoesNotReportADenial` |
| the clone is writable and nothing outside it is | `TestTheRealSandboxCannotWriteOutsideTheClone` |
| `sandbox.Unisolated` can never verify | `TestUnisolatedNeverVerifies` |
| a machine with no backend REFUSES rather than degrading | `TestNoBackendIsARefusalNotADegradation` |
| an orphaned child is killed with the process group (OQ-P10b-02) | `TestTheProcessGroupIsKilledWithTheParent` — Linux only, absent elsewhere by build constraint |

The job also checks its own non-vacuity twice: that the probes can succeed
unconfined before trusting their denial, and that removing `bubblewrap` turns
the run red.

**Why it is first.** Until it passes, the agent's isolation is an assertion.
A credential handed to an unconfined process is a credential in reach of
everything that process does, and by the time anything notices, the
exfiltration has happened.

> **The rule this establishes: no real API key on any machine where this has
> not passed.**

**Owner decision:** where the job runs and who owns it.

---

## Stage 1 — looking, without touching

Nothing in this stage writes to a repository.

### 1.1 Install the real scanners and pin them — **D5**

**Precondition:** none.

**Already done.** Nine adapters, tested against real captured tool output in
`testdata/fixtures`. `config/tools.lock` pins every version.

**What you do.** Build the scanner image, pin every tool by digest, and record
the digest in `tools.lock`.

**Why pinned.** A change in finding counts has to be attributable to the fleet
rather than to a silent tool upgrade. The adapter tests fail loudly when a
tool's output format changes, which is the intended behaviour and not a
regression.

**Owner decision:** who owns `config/tools.lock`, and what happens when a
tool's format changes.

### 1.2 Install the GitHub App, read-only first — **D4**

**Precondition:** 1.1, so there is something to scan with.

**Already done.** `gh.AppClient` and `gh.RESTOps` are written and tested
against recorded responses: pagination with lost-page detection, the three
forms of rate limit, 422-duplicate adoption, `merged_at` as well as `merged`,
and an empty listing refused as `ErrEmptyFleet`.

**What you do.** Create the App with **read permissions only** for this stage.
Hold the private key where the framework reads it and nothing else can.

**Check before proceeding:** `Repositories()` returns the fleet you expect. An
empty listing is refused on purpose — acting on it would archive the whole
fleet and the next sweep would report complete coverage of nothing.

**Owner decision:** which repositories, and whether the App may eventually
write branches everywhere it can read.

### 1.3 Capture one real response from each feed, then wire them — **D3**

**Precondition:** none, but do it before 1.4 so the first real scores have the
inputs.

**Already done.** `feed.KEVSource` and `feed.EPSSSource` are written and
tested: a feed that is DOWN is `*ErrUnavailable` and never an empty result, a
truncated catalogue is refused, an unlisted identifier is omitted rather than
zero-filled, a malformed row is dropped and counted.

**What you do first — and this one is easy to skip.** The fixtures in
`testdata/feeds/` were **written by hand to the publishers' documented
formats, not captured from the live services**, because this build has no
network access. Capture one real response from each endpoint, diff it against
the sample, and replace it. If CISA or FIRST emit a field, an encoding or a
date format the samples do not contain, the client meets it for the first time
in production otherwise.

**Then decide**, and these are D3's four:

1. where the snapshots come from;
2. where they are cached and for how long — a fetch per run against a third
   party is a rate limit waiting to happen, and a cache with no expiry is a
   stale answer presented as current;
3. the freshness window (`feed_freshness_days`);
4. what to do when a feed is down for a day.

**You will know it worked** when the "missing scoring inputs" caveat
disappears from the scores — everywhere at once. If it does not, it was
decoration.

### 1.4 Put an identity provider in front of the API — **D6**

**Precondition:** none technically; required before anyone but you looks at
real data.

**Already done.** The API refuses to start without an authenticator and
refuses to serve a caller whose privilege level could not be established.
`HeaderAuth` reads a trusting proxy's headers. Access logging (VM-UI-F-805)
is implemented and records refusals as well as reads.

**What you do.** Choose the provider, map its groups to the three privilege
levels, and terminate it somewhere a client cannot set those headers —
which is a deployment property this code cannot check.

**Then decide where the access log goes.** `SlogAccessLog` writes to the
process logger, which needs nothing configured and is therefore the version
that runs. Retention and tamper-evidence are yours.

### 1.5 Provision PostgreSQL and run the first real sweep

**Precondition:** 1.1, 1.2, 1.4.

**Already done.** 13 migrations with a checksum guard; both backends held to
one conformance suite. Migration 0013 has been applied and rolled back against
real PostgreSQL.

**What you do.** Provision, migrate, schedule the orchestrator, and run one
sweep. **Read the coverage report before the findings report** — the first
sweep's interesting output is what it could not scan.

**Owner decision:** backup, retention, and how workers are dispatched.

---

## Stage 2 — writing to repositories

Nothing here runs a model.

### 2.1 Build the toolchain for every language you actually have

**Precondition:** 1.1.

**Already done.** `internal/remediate/gotool` is the real Go toolchain:
`go build`, `go vet`, `go test -race`, `go get` with bisection, `go mod tidy`,
and a re-run of the scanners. Proved against controlled fixture modules and a
local module proxy. **Go only.**

**What you do.** VM-AD §11.3 also specifies JavaScript (`npm ci` → targeted
upgrade → `npm run build` → `npm test`). If your fleet has JavaScript
repositories, that implementation does not exist and remediation will decline
them rather than get them wrong.

**Carry the three decisions across** when you write it: a re-scan that did not
happen is not a clean re-scan; verification must not modify the tree the guard
has already inspected; and the test inventory must be readable from a tree
that does not build.

### 2.2 Grant the App write permission, and run remediation in dry-run

> **Changed 22 October 2026 (`REMEDIATION-DESIGN.md`).** Write permission
> now goes only to the fix publisher (8b), and only after Phase 4's login and
> roles, the `fix_approver` role, and a signed risk acceptance exist. "Dry
> run" becomes 8a: validated proposals in our own database, with no GitHub
> writes at all.

**Precondition:** 0.1, 1.2, 2.1.

**What you do.** Widen the App's permissions to branch creation and pull
requests. Then:

```
./vulnframework/cmd/fixworker -dry-run -repo <one low-tier repository>
```

The dry run reports what WOULD be attempted and changes nothing. It is held by
test to agree with the pass exactly — it disagreed once, and that is why the
test exists.

### 2.3 One deterministic bump, watched

**Precondition:** 2.2.

**What you do.** One repository, low tier, owned by somebody who has agreed.
Run `fixworker` without `-dry-run`. Read the pull request in full: the diff,
the verification output, and the "Attempted and dropped" section if the bisect
dropped anything.

**Check:** the module is at the version the body states — the body reports what
was RESOLVED, not what was requested, and a proxy that has not mirrored a tag
resolves lower.

**Nothing is scheduled** until this has been done and reviewed at least twice.

### 2.4 Wire remediation to a schedule — **OQ-AUDIT-07**

**Precondition:** 2.3, twice.

**Already done.** `cmd/fixworker` performs one pass and exits, so it can be
driven by cron, a Job, a queue consumer or a person.

**Owner decision:** cadence, concurrency, and who is paged when a pass fails.

---

## Stage 3 — the agent

### 3.1 Issue the API key — **and only now**

**Preconditions:** 0.1 passed **on the machine that will hold the key**. Not a
sibling machine, not CI alone.

**What you do.** Hold it where the harness reads it and the agent cannot.
`triage.HTTPClient` and `agent.Client` both take the credential as a function
rather than a field, so "was a key ever fetched" is an observable fact.

### 3.2 The first supervised agent run — **D1**

**Preconditions:** 3.1, and 2.3 completed twice.

**The checklist, in order, from BUILD-LOG's Precondition 3:**

1. The sandbox proof is green on the machine that will run the agent.
2. One repository. Low tier, owned by somebody who has agreed to this.
3. One finding. A **source-level** fix, so the path exercised is the one the
   deterministic bumper cannot do.
4. Supervised — a person watching it run, not a scheduled job.
5. The pull request reviewed **by hand**, in full, including the diff the
   guard passed and the verification output.
6. The §11.4 prompt treated as a **revisable draft**. Expect to change it
   against what a real model does with it; that is the purpose of the run, not
   a sign it went wrong.
7. Nothing scheduled until 1–6 have been done at least twice, on two different
   repositories.

**Why it is last.** It is the single highest-consequence action in the system,
and a build cannot supervise itself.

---

## Stage 4 — making the numbers mean what they say

These do not block operation. They block **trusting** the figures.

### 4.1 Calibrate the SLA windows — **D7**

**Precondition:** 1.5, so there is real data.

Agree the actual windows per tier and priority with the teams they bind, then
set `sla.calibrated: true`. The "provisional" qualifier disappears from every
breach count in every report, ticket and screen **at once** — which is the test
that it was never decoration.

**This build must not invent these values.** They are a commitment to teams.

### 4.2 Calibrate the static-analysis thresholds — **D8**

**Precondition:** 1.5, plus the shadow run the specification describes.

Review the false-positive rate per tier, set the thresholds, set
`static_analysis.calibrated: true`. Same mechanism as 4.1.

### 4.3 Decide whether blast radius weights the score — **D9**

**Precondition:** several sweeps, so the data exists.

Blast radius is computed and stored on every finding and does not affect the
score (`fanout.enabled: false`). The data has been accumulating since the
first sweep, which was the point of recording it while it was inert.

### 4.4 Decide what supersession means — **D10**

**Precondition:** 1.5.

**Already done.** The mechanism is built and tested: `report.Query.Supersedes`
carries the relationship, the store enforces that a report may be superseded
at most once, the superseded report is never deleted or modified, and the
interface states the relationship on both.

**What you decide:** what supersession MEANS operationally — a corrected
figure, a re-issue after a redaction change, a regeneration against a
late-arriving scan — and which path sets it. The mechanism consumes that
decision; it does not make it.

### 4.5 Bind the publisher's identity — **D4 item 4**

The report publisher refuses to deliver externally until an identity binding
exists (`ErrIdentityUnbound`). That is a deliberate refusal, not a gap.

---

## Stage 5 — operating it

### 5.1 Measure the query layer against a real corpus — **OQ-API-01**

Text search scans JSONB expressions. It is correct; the **2-second 95th
percentile** requirement is unproven against a fleet-sized corpus. Measure it,
and add the alias index if it is not met.

### 5.2 Decide who is paged

When a sweep fails, when coverage decays, and when the recovery log shows the
same repository self-healing every hour. Every self-heal, sweep and drain
already records why it fired; nothing reads those records yet.

### 5.3 Build run comparison's `changed` set — **OQ-API-02**

**Precondition, and this is the point:** an audit-trail completeness proof over
both backends.

Appearing and disappearing findings are exact; `changed` is empty. The
reconstruction is only sound if the audit trail is known complete for every
transition — and a `changed` set that is quietly wrong for findings whose
history predates a transition's audit entry is exactly the confident,
incorrect figure this system refuses to produce. Establish the completeness
first; the code is the easy half.

### 5.4 Decide about saved filters — **VM-UI-F-414, VM-UI-OQ-05**

**Preconditions:** 1.4 (an identity to store them against) and a write path in
the API (OQ-API-03).

The requirement says "stored per user"; the open question asks whether they
should be shared across a team, which needs a store and a naming convention.
It was not built because it is ambiguous, and ambiguity loses.

### 5.5 Enclosing symbol — **OQ-AUDIT-02**

Not a coding gap. **No pinned tool reports the enclosing package or function**,
so code and secret findings are located to a FILE, and every verification that
could therefore hide a same-file twin says so. It closes when a tool that
reports it is pinned, not before.

---

## Not on this list, deliberately

**Seeding the PostgreSQL demonstration.** `--postgres` starts empty on
purpose. Seeding invented findings into a durable store is how invented
findings get quoted as real.

**A non-demonstration mode for `cmd/fixworker`.** It refuses outright rather
than starting up and finding nothing to do, which would read as a statement
about the fleet rather than about the deployment. It becomes available when
0.1, 1.2, 1.1 and 2.1 are done — which is what it tells you when you run it.

---

## The dependency graph, in one place

```
0.1  sandbox proof (Linux)  ─────────────────┐
                                             │
1.1  scanners pinned ──┬── 1.2 App (read) ───┼── 1.5 Postgres + first sweep
                       │                     │          │
1.3  feeds wired ──────┤                     │          ├── 4.1 SLA windows
                       │                     │          ├── 4.2 thresholds
1.4  identity provider ┘                     │          ├── 4.3 blast radius
                                             │          ├── 4.4 supersession
2.1  toolchain (per language) ───────────────┤          └── 5.x operating it
                       │                     │
2.2  App (write) + dry run ──── 2.3 one watched bump ──── 2.4 scheduled
                                             │
                        3.1 API key ─────────┘   (0.1 on THIS machine)
                                │
                        3.2 first supervised agent run   (2.3 done twice)
```
