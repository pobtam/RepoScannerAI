# Decisions needed

Every item here is a decision the build deliberately did **not** make, because
making it would have been irreversible, safety-critical, an external contract,
or dependent on a credential nobody should issue to an automated build. In each
case the surrounding work was completed and the decision was designed around
rather than assumed.

Nothing in this list blocks running the framework or reading the interface.
Each one blocks a specific step towards production, and says which.

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

---

## D11 — Production deployment

**Blocks:** production.

Not a decision this build can even frame usefully: where it runs, how the
orchestrator is scheduled, how workers are dispatched, what the database's
backup and retention policy is, who is paged when a sweep fails. Listed so it
is not mistaken for something already handled.

`FINAL-STATUS.md` lists what is real and what is a stub, which is the input to
this decision.
