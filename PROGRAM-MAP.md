# Program map

A guide to what this program is made of, what each piece does, and how
information moves through it. Written for a reader who is not a programmer.

It describes **what is actually in this repository**, read from the code rather
than from the design documents. Where the code and a specification disagree,
the code wins and the difference is noted.

A few words are used throughout and cannot be avoided:

* **Repository** (often shortened to *repo*) — one codebase. A company might
  have dozens or hundreds.
* **Finding** — one security problem in one repository. "This repository uses a
  library version with a known flaw" is a finding.
* **Run** — one pass over the fleet of repositories. Think of it as one
  inspection round.
* **Fleet** — all the repositories the program watches.
* **Pull request** — a proposed change to a codebase that a person reviews and
  approves before it takes effect.

---

## 1. One-paragraph summary

This program watches a set of codebases for security problems, decides which
ones matter, and where it safely can, proposes the fix itself as a change for a
human to approve. It runs a round of inspections, collects what nine different
inspection tools report, merges duplicate reports of the same problem into one,
adds outside context about whether that problem is being exploited in the real
world, scores it, and applies a written policy to decide what to do: fix it
automatically, raise a ticket for a person, escalate it, or wait for someone
else to fix the shared component it lives in. It then proves its own work by
re-inspecting: a problem counts as resolved only when a successful inspection
can no longer find it, not when a fix was merged. Everything it could *not* do
is reported as loudly as everything it did — which repositories failed to be
inspected, which numbers rest on missing information, and which findings
disappeared for reasons nobody has established. The last part is the unusual
one: the program is built so that no number is ever shown without stating what
it rests on.

---

## 2. The pieces

Each entry gives the name you would search for in the code, a plain sentence
about its job, and what goes in and comes out.

---

### The vocabulary

**`internal/model`**

Defines the words the whole program uses — what a finding is, the thirteen
states it can be in, the reasons it can be stuck, and the rules for moving
between states. It also holds the shared definition of "this text looks like a
password", which several other pieces use to refuse to print one.

* **In:** nothing. It is the dictionary.
* **Out:** the shapes and rules everything else is built from.

---

**`internal/fingerprint`**

Gives every finding a stable identity, so the same problem found twice is
recognised as one thing, and a genuinely different problem is recognised as
new.

It builds that identity from the repository, the kind of problem, the
vulnerability's identifier, and the location — deliberately **not** the line
number, so reformatting a file does not make the program think a new problem
appeared.

* **In:** one raw report from an inspection tool.
* **Out:** a short identifier, e.g. `1be7a0a5488737ec`.

---

### Looking at the code

**`internal/scan`, `internal/scan/adapters`, `internal/scan/runner`**

Runs the inspection tools against a copy of a repository and translates each
tool's output into the program's own vocabulary. There is one small translator
(an *adapter*) per tool — nine of them.

Two things it does that matter later. If a tool crashes, that becomes a
recorded **gap in coverage**, not a failed inspection — the other tools' results
still count, and the missing one is named. And it reads the repository's own
list of dependencies (its `go.mod` file), which is what later makes it possible
to say "eleven other repositories use this same component".

* **In:** a copy of a repository, and the list of which tools apply to it.
* **Out:** a list of raw findings, a list of coverage gaps, the dependency
  list, and which tools succeeded and which failed.

---

### Remembering

**`internal/store`**

The memory of the whole system. It holds every finding, every inspection round,
every state change, every ticket, every proposed fix and every issued report.

It exists in two interchangeable forms — one that keeps everything in memory
(`store.Memory`, used by the demonstration) and one that uses a real database
(`store.Postgres`). Both are held to the same test suite so they cannot behave
differently.

Two of its rules are worth knowing. When several tools report the same problem,
it *merges* their reports into one view rather than picking a winner. And it
owns the rule that **absence is not resolution**: a finding that an inspection
failed to see is only marked resolved if that inspection actually succeeded
(`store.PlanReconcile`).

* **In:** raw findings, inspection outcomes, decisions, tickets, reports.
* **Out:** the merged, current view of every finding, and the history behind
  it.

---

### Running the rounds

**`internal/orchestrator`**

The conductor. It decides which repositories to inspect, dispatches the work,
keeps track of what is in flight, and runs each stage of the pipeline in order.

It is the only part of the program allowed to change a finding's state. It also
performs the housekeeping that stops work getting silently lost: reclaiming
jobs from crashed workers, retrying tickets after an outage, and sweeping up
findings that look busy but that nothing is actually working on. Every one of
those recoveries records *why* it fired, so a problem that keeps self-healing
is visible rather than absorbed.

Its named stages (each is a "pass") are: `Sweep` (inspect), `EnrichPass` (add
outside context), `TriageAndRoute` (explain, score, decide), `TicketPass`
(raise tickets), `RemediationPass` (attempt fixes), `ReconcilePullRequests`
(check on proposed fixes), `SyncFleet` (check which repositories still exist).

* **In:** the list of repositories, and a budget for how many outside calls it
  may make.
* **Out:** a completed round, with everything it did and failed to do recorded.

---

### Deciding

**`internal/triage`**

Asks a language model to explain each finding in plain words — what it is, what
the impact could be, how to fix it — and stores that explanation.

Two deliberate limits. The model's explanation is **never** allowed to set the
priority; that is computed arithmetically elsewhere. And the program keeps
working if the model fails: a finding with no explanation is still scored and
still routed.

* **In:** findings that are new or have come back.
* **Out:** a written explanation attached to each finding.

---

**`internal/score`**

Turns each finding into a priority band (P0 to P3) using a fixed formula, so
two identical findings always get the same answer.

The formula declares **five** inputs: the base severity, whether the flaw is
known to be exploited, how likely exploitation is, whether the vulnerable code
is actually reachable, and how important the repository is. When an input is
missing, the score says so *next to the number* rather than quietly treating
the missing input as a zero.

* **In:** a finding's severity, exploitation context, reachability, dependency
  type, and the repository's importance tier.
* **Out:** a priority band, the arithmetic behind it, a deadline (SLA) status,
  and a note naming any input that did not answer.

---

**`internal/policy`**

Applies the written decision table: given this finding, in this repository, in
this state — fix it automatically, raise a ticket, escalate it, wait for an
upstream fix, or deliberately do nothing.

If no rule matches, it **fails loudly** rather than guessing. A gap in the table
is reported as a gap.

* **In:** a finding, the repository's profile, and what is already in progress.
* **Out:** a decision, plus the number of the rule that made it, so any
  decision can be traced back to the table.

> **Code vs. spec:** the design document (VM-AD §10) numbers nine rules. The
> decision engine implements rules 1–8. Rule 9 — the limit on how many fixes
> may share one pull request — lives in the fix-grouping code
> (`remediate.Group`) instead, because it is a decision about batching rather
> than about a single finding.

---

### Fixing

> **Changed 22 October 2026:** fixing is now Phase 8, automated but not
> autonomous: AI-prepared, validated proposals that a qualified person
> approves before anything reaches GitHub. See `REMEDIATION-DESIGN.md`, and
> `NOW-VS-LATER.md` for the plain-language version.

**`internal/remediate`** (with **`internal/remediate/guard`**)

The mechanical fixer. For an out-of-date dependency it works out the version
that actually closes the flaw, makes the change, proves it, and opens a pull
request for a person to review.

The order is fixed and the proof is the point: it checks the repository builds
*before* it changes anything (so it is not blamed for pre-existing breakage),
makes the change, then **re-runs the inspection tools** to confirm the problem
is gone. A change that builds and tests cleanly but does not remove the finding
is rejected. It never merges its own work.

The **guard** is a separate safety check that runs on the actual files on disk,
every time, before anything is pushed. It blocks changes to protected paths
(build pipelines, ownership files, infrastructure definitions), blocks anything
that merely silences a warning, and blocks anything that looks like a password.
It reads the files rather than trusting any account of what was changed.

* **In:** a group of findings to fix, and a copy of the repository.
* **Out:** a pull request, or a recorded reason why not.

---

**`internal/remediate/agent`** (with **`internal/sandbox`**)

The same machinery, but with a language model writing the change instead of a
version bump — for problems in the repository's own source code rather than in
its dependencies.

The design point is that the model is **structurally unable** to misbehave
rather than asked not to. It cannot reach the safety guard, cannot see the
credential, and cannot reach the network or write outside its working copy —
those limits are imposed by the surrounding harness. The sandbox does not
assume it is closed: it actively tests its own boundaries with harmless probes
before any model runs, and refuses to start if a probe did not run or did not
block.

There are extra checks for the ways a model can appear to succeed: deleting the
test that objected, marking a test as skipped, or reporting a fix it did not
make. All of them are checked against the files, not the model's account.

* **In:** a finding, a working copy, a time-and-cost budget.
* **Out:** a changed working copy and a report — or a refusal.

---

### Shared components across the fleet

**`internal/firstparty`**

Handles the case where the flaw is in a component the organisation wrote
itself, and several of its own repositories depend on it.

Fixing it once fixes it everywhere, but only in the right order: first the
shared component, then the repositories that use it. This piece works out who
is affected, and keeps two numbers separate — how many repositories *depend* on
the component, and how many actually *reach* the vulnerable code. It also
identifies repositories a fix cannot help (because they point at a local copy),
so they are flagged for a person instead of being counted as done.

* **In:** the dependency lists gathered during inspection, and a register of
  which components the organisation owns.
* **Out:** a "wave" — the upstream fix, the affected repositories, and the
  steps that clear it.

---

### Outside context

**`internal/feed`**

Asks the exploitation catalogues two questions about each vulnerability: is it
known to be exploited in the wild, and how likely is exploitation.

It is careful about not knowing. An identifier the catalogue has never heard of
is recorded as *unanswered*, which is a different fact from *measured as
harmless*. Answers that cannot be true (an impossible probability, a date in
the future) are discarded rather than repaired. An old answer is used and
labelled with its age rather than thrown away.

* **In:** the identifiers of the findings currently open.
* **Out:** exploitation context, each answer marked with its date, and a
  record of which questions nobody answered.

---

### Telling people

**`internal/tracker`**

Creates and updates tickets in whichever issue tracker the organisation uses —
GitHub Issues, Jira or Linear.

Its main job is not creating tickets but *not creating duplicates*: before
opening one it checks its own records and then asks the tracker itself, so a
lost record does not produce a second ticket for a problem someone is already
working on. If the tracker is down the work is queued and retried
automatically, and the round continues — a third-party outage does not become a
gap in the inspection.

* **In:** findings that policy decided need a person.
* **Out:** tickets, comments and closures in the tracker, and a link on each
  finding.

---

**`internal/report`**

Produces the written report for a round: the headline counts, what changed
since last time, the coverage position, and the caveats.

Each report is **fixed at the moment it is issued**, stamped with a fingerprint
of its own contents, and stored. That means a number quoted in a meeting months
later can be traced back to the exact round it came from and checked against
the original. Reports are also redacted by audience: the widest-circulated
version carries counts and coverage but no finding detail.

* **In:** a completed round.
* **Out:** a stored, unchangeable report in both machine and human-readable
  form.

---

**`internal/gh`**

Everything that talks to the code host (GitHub): which repositories exist,
cloning them, pushing branches, opening pull requests, receiving notifications
when a pull request is merged, and publishing reports to an archive.

The notification path is the primary way the program learns a fix was merged.
It verifies each notification cryptographically, ignores repeats, and ignores
messages that arrive out of order. A slower fallback checks anything the
notifications did not cover — and if no notification has arrived at all for a
while, the program treats its own notification path as broken, falls back to
asking directly, and **says so** rather than going quiet.

* **In:** notifications from the code host; requests from the rest of the
  program.
* **Out:** branches, pull requests, published reports, and the current state of
  proposed fixes.

---

### The interface

**`internal/api`**

The service the web interface talks to. Twenty addresses covering findings,
rounds, coverage, repositories, shared-component waves, trends and reports.

Three properties are enforced here rather than left to the interface. Searching
and filtering happen on this side, so the browser never has to download
everything. No response may contain anything shaped like a password — a
response that does is **refused**, not cleaned up and sent. And the shape of
every response is published in a machine-readable form, from which the
interface's own definitions are generated, so the two cannot drift apart.

* **In:** questions from the interface.
* **Out:** answers, each carrying its own caveats.

---

**`reportui/`** (the web interface)

The screens: a searchable finding explorer, a detail page per finding, a
per-round overview, coverage, repositories, shared-component waves, history and
trends, and the list of issued reports.

It is built to preserve distinctions rather than tidy them away. A missing
exploitation score reads "not looked up", never `0.00`. A finding the last
inspection did not see is marked, with an explanation that this is ambiguous.
A number computed from partial information carries its caveat beside it, so the
caveat survives being copied into an email. Every count links to the list that
produced it, so any figure on screen can be checked by clicking it.

* **In:** answers from the API.
* **Out:** the screens a person reads.

> **Code vs. spec:** the interface specification (VM-UI §7.1) names three
> off-the-shelf libraries for routing, tables and styling. None of the three is
> installed. The routing and the tables are hand-written and the styling is
> plain CSS; only the list-virtualisation library from that family is used.
> Two specified features are also absent: saving a filter for reuse, and
> logging who looked at what.

---

### Keeping the program honest

**`internal/audit`**

A test suite that inverts the usual question. Instead of asking "is this field
displayed?", it asks "**does any real code actually write this field?**" — and
answers by running the real pipeline and looking at what comes out.

It exists because the same defect kept recurring: a piece of information that
something reads and nothing writes. It looks identical to a feature nobody has
used yet, and no ordinary test catches it, because tests supply the value
themselves. This check found eleven instances during the build.

* **In:** the output of a real pipeline run.
* **Out:** a pass, or a list of fields nothing produces.

---

**`internal/demo`**

Builds the demonstration. It contains invented inspection results — invented
repositories, invented vulnerabilities — in a single clearly-labelled file, and
then feeds them through the **real** pipeline.

Nothing in it writes a finding, a priority or a state directly. That is
deliberate: a demonstration that made up its own conclusions could show
something the real program cannot produce.

* **In:** the invented tool output.
* **Out:** a fully populated system, with the awkward cases present on purpose
  — a failed inspection, a problem that came back, a deadline breach, a
  shared-component wave.

---

**`cmd/apiserver`, `cmd/orchestrator`, `cmd/scanworker`**

The three runnable programs: the service behind the web interface, the
conductor, and the inspection worker.

> **Code vs. spec:** four further command folders exist and are **empty** —
> `cmd/fixworker`, `cmd/bumpworker`, `cmd/triage` and `cmd/vfctl` (the
> command-line tool the specs describe for operators). The fixing and triage
> logic is fully built and tested as a library, but nothing yet runs either on
> a schedule, and there is no operator command line.

---

## 3. How data flows

Here is one finding's journey, end to end.

1. **A round begins.** The conductor (`orchestrator.Sweep`) works out which
   repositories are in scope, checks it has enough budget for outside calls,
   and dispatches an inspection job for each. Every repository it *planned* to
   inspect is recorded now, so one that is never reached cannot vanish
   silently.

2. **A repository is inspected.** A worker takes a copy of the repository and
   runs each applicable tool over it. Say `govulncheck` reports that a
   networking library has a known flaw. The worker also reads the repository's
   dependency list while the copy is on disk.

3. **Tool output is translated.** The matching adapter turns that tool's output
   into the program's own vocabulary: the identifier, the affected component,
   the current and fixed versions, the severity, and whether the vulnerable
   code is actually reachable.

4. **Duplicate reports are merged.** Two tools often report the same
   vulnerability under different names. The program builds a table of
   equivalent identifiers from the tools' own published cross-references and
   collapses them into one finding (`scan.AliasTable`). The result is given its
   stable identity (`fingerprint.Compute`).

5. **It is recorded.** The store keeps each tool's report separately and builds
   one merged view from them (`store.Project`). If this identity has been seen
   before, this is a new sighting of an existing finding; if not, it is newly
   **DETECTED**.

6. **Outside context is added** (`orchestrator.EnrichPass`). The exploitation
   catalogues are asked about this vulnerability's identifiers — including its
   alternative names, since the catalogues use different ones. An answer is
   stored with its date. No answer is stored as *no answer*.

7. **It is explained** (`orchestrator.TriageAndRoute`, `internal/triage`). A
   language model writes a plain description, the likely impact and a suggested
   remedy. The finding moves to **TRIAGED**.

8. **It is scored** (`internal/score`). The formula produces a priority band and
   a deadline. If the exploitation catalogues did not answer, the score carries
   a note saying which inputs are missing and that it should be read as a
   floor.

9. **A decision is made** (`internal/policy`). The decision table is consulted.
   Say this is a minor version bump, in a repository that has a test suite:
   the decision is *fix it automatically*, recorded with the number of the rule
   that decided.

10. **A ticket may be raised** (`orchestrator.TicketPass`). High-priority
    findings get their own ticket; lower-priority ones are gathered into a
    single ticket for the whole round, so the tracker is not flooded.

11. **A fix is attempted** (`orchestrator.RemediationPass`). The repository is
    locked so two fixers cannot collide. The finding is claimed, and only then
    does it move to **AUTO_REMEDIATING** — that state always means a worker is
    genuinely holding it. The fixer checks the repository already builds,
    applies the version bump, and then the guard inspects the resulting files.

12. **The fix is proved.** The tools are re-run. Only if the finding is
    genuinely gone — and the build and tests still pass — is a branch pushed
    and a pull request opened. The finding moves to **PR_OPEN**. If the bump
    resolved to a lower version than needed (a real and common occurrence), the
    re-inspection still sees the finding, the whole branch is discarded, and
    the finding goes to a person.

13. **A person reviews and merges.** The program never merges its own work.

14. **The merge is noticed.** The code host notifies the program, which moves
    the finding to **MERGED**. That is deliberately not "fixed": a merge is a
    statement of intent, not evidence.

15. **The next round proves it.** The repository is inspected again. The finding
    is not reported this time, and the inspection **completed successfully** —
    so it becomes **VERIFIED**, attributed to this program's own merge. Had the
    inspection failed or only partly run, the finding would have stayed exactly
    where it was, marked as not re-observed.

16. **It appears in the report.** The round's report is generated, fixed,
    fingerprinted and stored, and the interface can show that round's position
    as it stood then — not as it looks today.

### Where the journey branches

* **A password is found.** Step 9 short-circuits. A secret is escalated
  immediately whatever else is true, gets its own ticket regardless of
  priority, and is never batched — because the remedy is a person rotating a
  credential, and batching delays it. No automated fix is attempted. The value
  itself never enters the system at any point.

* **No test suite.** No automated fix is attempted, whatever the decision table
  says, because there would be no way to prove the change worked. The finding
  goes to a person and the interface says why.

* **The flaw is in a shared internal component.** The finding waits
  (**BLOCKED_UPSTREAM**) on the upstream fix rather than each repository
  opening its own pull request. If the wave cannot advance a particular
  repository — because it points at a local copy — that one is routed to a
  person instead of waiting forever for something that has already happened.

* **No fix exists yet.** The finding is parked as blocked, with the reason
  recorded. Notably, the program distinguishes *"nothing to do"* from
  *"tried and failed"*: a fix that applied, built, passed tests and still did
  not remove the problem gets its own reason code, and unlike the former it
  does **not** pause the deadline clock.

* **A person rejects the pull request.** The finding becomes **DECLINED** and is
  never automatically re-attempted. Only a human can put it back in the queue.

* **The inspection fails.** No finding in that repository is verified by that
  round. Its findings are marked *not re-observed*, the gap is recorded with a
  cause and an owner, and the round's report states that its numbers are lower
  than the truth rather than better.

### Where it loops back

* **A verified finding reappears.** A later inspection sees it again. It becomes
  **REGRESSED** — deliberately a different state from a new finding, because it
  means something undid a fix, which is a different problem.

* **A merged fix did not work.** The post-merge inspection still sees the
  finding, so instead of being verified it returns to **TRIAGED** and goes
  round again.

* **A fix attempt crashes.** The claim expires and the finding returns to the
  queue by itself. If something leaves a finding looking busy with nothing
  working on it, a sweep finds it and returns it, recording why.

* **A pull request is forgotten.** If a pull request's record is lost, the
  finding returns to the queue; re-planning produces the same branch name,
  which the fixer recognises and adopts rather than opening a second pull
  request.

---

## 4. Data sources

**The program collects data from 17 distinct outside sources.**

Counted by *distinct external system or artefact the program reads from*. The
code host is counted once even though it supplies three different kinds of
information, because it is one system with one set of credentials.

Not counted, because they are settings an operator writes rather than
information the program gathers: four configuration files (`config/tools.lock`,
`calibration.yaml`, `policy.yaml`, and the register of internally-owned
components, `firstparty.demo.yaml`).

---

### (a) Scanners — nine tools that inspect code and produce findings

All nine are **real**: real translators, run as real programs
(`internal/scan/runner` starts an actual process). What is missing is the tools
themselves, which are not installed here — so no finding in the demonstration
came from one. Each was built and tested against genuine captured output from
the real tool, kept in `testdata/fixtures`.

All nine are **read-only**. The inspection worker deliberately holds no
credential that would let it write to any repository.

| Tool (`Name()`) | What it contributes |
|---|---|
| `govulncheck` | Go dependency flaws, and — uniquely — whether the vulnerable code is actually reachable from this repository. |
| `osv-scanner` | Dependency flaws cross-checked against the open vulnerability database; catches what reachability analysis skips. |
| `gosec` | Insecure patterns in Go source code, such as weak randomness or unsafe handling of credentials. |
| `staticcheck` | Correctness problems in Go source, filtered to the security-relevant subset. |
| `gitleaks` | Passwords, keys and tokens committed into the code. Reports the *kind* of credential and where it is, never the value. |
| `trivy` | Misconfigurations, mostly in deployment and container definitions. |
| `semgrep` | Pattern-based source-code flaws, used for JavaScript and TypeScript. |
| `npm-audit` | JavaScript dependency advisories; noisier, used as a cross-check. |
| `actions-pin` | Build-pipeline steps pinned to a moving reference rather than an exact version — a supply-chain risk. |

---

### (b) Enrichment feeds — two sources that add context but inspect nothing

| Source | What it contributes | Status |
|---|---|---|
| **KEV** (CISA Known Exploited Vulnerabilities catalogue) | Whether this vulnerability is being exploited in the real world right now. | **Fake only.** The boundary is built (`internal/feed`); there is no live client. |
| **EPSS** (Exploit Prediction Scoring System) | A daily-published probability that this vulnerability will be exploited. | **Fake only.** Same boundary, no live client. |

Both are **read-only**.

These are the two most decision-changing inputs the scoring formula declares,
and neither is currently connected. The program's response is to name them as
missing on every affected number rather than to score as though the answer were
"no" (`score.UnavailableInputs`).

---

### (c) Six other sources of truth

| Source | What it contributes | Read or write | Status |
|---|---|---|---|
| **The code host** (`internal/gh`) | Three things: which repositories exist and their tags (`gh.App`); the current state of a proposed fix (`gh.PROps.GetPR`); and notifications when something is merged, pushed or tagged (`gh.WebhookVerifier`). | **Both.** It is also the only source the program *writes* to directly: branches, commits, pull requests and published reports. | **Mostly fake.** The notification verifier is real working cryptography and would accept real deliveries today. The rest — listing repositories, cloning, pushing, opening pull requests — exists only as an interface with a fake behind it. There is no HTTP client to GitHub anywhere in the code. |
| **The repository's own dependency list** (`scan.ReadGoManifest`) | The components each repository uses and at what versions, read directly from its `go.mod` file. This is what makes "eleven repositories share this component" answerable. | Read-only | **Real.** It reads and parses a real file. A missing or unreadable file is a recorded coverage gap, not a failure. |
| **The triage language model** (`triage.Client`) | The plain-English explanation of each finding. Never the priority. | Read-only, but note that finding metadata **leaves the machine** to reach it. | **Fake only.** `internal/triage` contains no HTTP client of any kind — the only implementation is `FakeClient`. |
| **The remediation agent model** (`agent.Client`) | Proposed source-code changes for problems a version bump cannot fix. | Writes to a working copy on disk. Never to the code host directly — the harness does that, after the guard has passed. | **Real client, never run.** It genuinely starts a headless model program inside the sandbox and reads back its output. No API key has ever been issued to it. It refuses to start unless the sandbox proves its own boundaries first. |
| **The issue tracker** (`tracker.Tracker`) | Whether a ticket already exists for a finding (`Find`) — which is what prevents duplicates. | **Both.** It creates tickets, comments and closes them. | **Real, unwired.** All three backends (GitHub Issues, Jira, Linear) are genuine HTTP clients against the real APIs. They need credentials, which are not configured. |
| **The local toolchain** (`remediate.Toolchain`) | Whether the repository builds and its tests pass, before and after a change — the evidence that a fix is a fix. | Reads the working copy; the build itself rewrites dependency files. | **Fake only.** This is the single largest unbuilt piece in the repository: the interface is defined and every test runs against `FakeToolchain`. |

---

### Summary of the count

| Group | Count |
|---|---|
| Scanners | 9 |
| Enrichment feeds | 2 |
| Other sources of truth | 6 |
| **Total** | **17** |

Of those 17, **two** can cause changes outside the program: the code host
(branches, pull requests, published reports) and the issue tracker (tickets).
The remaining fifteen are read-only, or write only to a temporary working copy
on the machine doing the work.

---

## 5. What is real and what is pretend right now

This map describes a program that is **complete and demonstrable, but has never
run against a real repository**. The distinction matters, and
`FINAL-STATUS.md` covers it in full. The short version:

**Genuinely working, end to end, with no credentials:** the vocabulary and
identity rules, the nine translators (against real captured tool output), both
forms of memory, the state machine, the conductor and all its stages, scoring,
the decision table, the mechanical fixer and its safety guard, the
shared-component waves, the ticket logic, the report generator, the API, and
the web interface. The demonstration exercises all of it.

**Present as a design with a deliberately hostile stand-in behind it:** the
language model that explains findings, the language model that writes fixes,
the exploitation catalogues, and the code host. "Hostile" means the stand-ins
were written to behave *worse* than the real thing — opening duplicate pull
requests, rejecting pushes, rate-limiting, serving stale data, returning
answers that cannot be true — so the program is tested against the awkward
cases rather than the convenient ones.

**Not built at all:** the real build-and-test toolchain (so "this fix works" is
currently the stand-in agreeing with itself); any live connection to GitHub;
any live exploitation feed; a scheduler to run the fixer automatically; access
logging; and the ability to generate a report from the interface.

**Built but unproven:** the sandbox that confines the model. Its real
implementation exists, but every test of it runs against the stand-in, because
this machine is a Mac and the real one needs Linux. Until a Linux test proves
its boundaries actually hold, no API key should reach any machine that runs it.

Three smaller honesty notes, since the map above would otherwise imply more
than is there:

* A finding's location is recorded down to the **file**, not the function — no
  inspection tool in use reports the enclosing function. This means verifying
  one problem in a file could hide a second one in the same file, and the
  program says so whenever that is possible.
* Tool versions are recorded per **round**, not per finding.
* Comparing two rounds reports what appeared and what disappeared exactly, but
  not what *changed state* — reconstructing a finding's state as of a past
  round has not been built.
