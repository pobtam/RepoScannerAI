# Remediation design: AI-assisted fixing (Phase 8)

Status: design, 22 October 2026. No code has changed for it yet.

This document brings AI-assisted fixing into the plan as Phase 8, under the
requirements a security review set for it (Aaron Lawvere, 24 September;
notes dated 22 October). The project was requested by Jeff, and these
requirements are the bar for it reaching production.

It supersedes parts of the original design:
- architecture §11, §11.4 and §15.3;
- functional requirements §5.10 (VM-F-501 to VM-F-545).

The change is a single one: **the human decision moves from the pull
request into the tool, and comes before anything is written to GitHub.**
Each original document now carries a note pointing here.

Companion documents:
- `NOW-VS-LATER.md`: the plain-language version, for Jeff.
- `SECURITY-READINESS.md`: answers to the review's questions.
- `DECISIONS-NEEDED.md` D14: the choices that are not ours to make.

---

## 1. The requirements

| # | Requirement (from the review) |
|---|---|
| 1 | Automated, not autonomous. AI does the legwork; a qualified person approves every change before anything merges. No fix merges without a recorded human approval, ever. |
| 2 | Per finding, the AI evaluates it (is it real, how likely to matter, with a confidence score), generates candidate fixes and weighs them against the full code, chooses one with reasons, and packages it: location, why it is a problem, exact lines changed, the fix, severity and confidence, ready to become a pull request. |
| 3 | Two separate risks per change: is the finding a risk, and is the fix a risk. Show the AI's confidence. Thresholds depend on severity: for a critical finding even 90% may not be enough. A risk engine around the error margin, and a formal risk acceptance before production use. |
| 4 | Fixes must not introduce new problems, including ones that are not known CVEs (for example a memory leak). |
| 5 | One review page with everything a reviewer needs. Review through the web app and a terminal command; reviewers do not go through GitHub to decide. |
| 6 | Approvers need developer or DevOps context. The tool restricts who can approve. |
| 7 | After approval, deployment and validation are automated. |
| 8 | Autonomous fixing only later, and only inside guardrails: specific CVE types, fix types, repositories, development environments. |
| 9 | Missing controls could mean about six more months before production; with them it is a marketable remediation tool. Ship something for feedback early, with clear answers ready. |

---

## 2. Where the code stands (gap analysis, 22 October 2026)

### 2.1 What exists

The original design built a complete remediation pipeline in its general
shape: fix groups, a worker that clones, takes a baseline, changes, guards,
verifies, commits, pushes and opens a pull request, a deterministic bumper,
an agent harness, a sandbox and a guard. Most of it runs only in
simulations.

| Piece | Where | Called from a deployed program? |
|---|---|---|
| Remediation worker (clone, baseline, fix, guard, verify, commit, push, open PR) | `internal/remediate/worker.go` | **No.** Constructed only in `cmd/fixworker/demo.go:151`, `internal/demo/demo.go:442` and `internal/fleet/fleet.go:659`, all with fakes |
| Remediation dispatch pass | `internal/orchestrator/remediation.go` | **No.** Called only from `cmd/fixworker/demo.go:157`, `internal/demo` and `internal/fleet`. The real-mode post-sweep pass deliberately stops at routing (`cmd/orchestrator/postsweep.go:24-34`) |
| Real Go toolchain (bump, build, vet, test, tidy, rescan) | `internal/remediate/gotool/` | **No.** Never constructed outside tests: built but never called |
| Agent harness and Claude Code client | `internal/remediate/agent/` | **No.** Never constructed outside tests: built but never called |
| Real GitHub write client (clone, branch, commit, push, open and close PR) | `internal/gh/ops.go` (`RESTOps`) | **No.** No program constructs it |
| GitHub App client | `internal/gh/rest.go` (`AppClient`) | **No** |
| Pull request closer for resolved findings | `internal/remediate/settle.go:39` (`Settle`) | **No.** No caller outside tests |
| Sandbox (bubblewrap on Linux, seatbelt on macOS) | `internal/sandbox/` | Only through the agent client, which is never called; Linux proof (D2) never run |
| Guard (deny paths, suppressions, credentials in added lines) | `internal/remediate/guard/guard.go` | Inside the worker only |
| Fix worker program | `cmd/fixworker/main.go` | Refuses to run without `-demo` (`main.go:79-95`) |
| `auto_merge` policy setting | `internal/policy/config.go:45`, `config/policy.yaml:21` (`false`) | Read by nothing |

### 2.2 Requirement by requirement

| # | Status | Evidence |
|---|---|---|
| 1 Human approval before merge | **Partly met, in a different place.** | No code merges anything (no merge call exists; `gh/gh.go:36` and `gh/ops.go:140` state "never auto-merged", VM-F-541). But the worker **pushes a branch and opens a pull request with no human approval** once verification passes (`worker.go:249` branch, `:349` commit, `:359` push, `:422` and `:510` open PR). The original design made the pull request the human gate. No fix-approval concept exists anywhere: the only human approval in the state machine is for suppressions (`model/state.go:169, 318, 351`). No recorded approval is checked before any write. |
| 2 Evaluate, generate candidates, choose with reasons, package | **Partly met.** | Evaluation: AI triage returns a description, impact, remediation text, a false-positive flag and a **confidence word** (`triage/triage.go:76-84`, `Confidence string`), not a number. Generation: the agent produces **one** working tree (`agent/harness.go`), and the deterministic bumper one set of bumps; no candidates are compared or chosen with reasons. Packaging: the PR body covers findings, changes, residual risk, deferrals and manual steps (VM-F-543); no confidence, and no "why this fix over the alternatives". |
| 3 Two risks, confidence, severity thresholds, risk engine | **Missing.** | No score for "is the finding real" or "is the fix safe"; no per-severity threshold; no error margin. Policy routes by tier, language and change class (`policy/config.go:170-190`, `config/policy.yaml:33-75`) to `auto_remediate`, `open_ticket` or `escalate`, without confidence. The composite score (`score/composite.go`) prioritises findings; it says nothing about fixes. |
| 4 No new problems, including non-CVE ones | **Partly met, Go only.** | The Go toolchain verifies with build, `vet`, `test -race -count=1` and `go mod tidy -diff` (`gotool/gotool.go:338-373`), and the agent harness refuses weakened tests or a missing new test (`agent/agent.go:129-141`). The rescan runs **only the scanners that produced the targeted findings** and checks only whether **those** identifiers remain (`gotool/rescan.go:20-58`, `gotool.go:382-404`): **new findings are not looked for**. Nothing checks leaks (memory, goroutines, file handles), performance or coverage (VM-F-534 is a SHOULD, not built). No toolchain exists for any language but Go. |
| 5 One review page; web app and terminal | **Missing.** | The UI shows remediation attempts on a finding (`/v1/findings/{fp}/attempts`), read-only, after the fact. No proposal view, no diff view, no approve or reject anywhere (web, API or vfctl). |
| 6 Restrict who can approve | **Missing.** | Roles stop at the report levels (`report.Level`; `api/auth.go:36-65`). No approver role, and the API has no write endpoints at all. |
| 7 Deployment and validation automated after approval | **Partly met.** | Post-merge verification exists in design and code: a finding becomes VERIFIED only when a later scan of the merged default branch no longer sees it (VM-F-533), and PR state is tracked by webhook with a reconciliation fallback (architecture §7.3.1). Nothing is wired to a real repository, and deployment itself is outside the tool. |
| 8 Autonomy only within guardrails | **Partly met, by accident.** | Fixing cannot run at all outside the demo (`cmd/fixworker/main.go:79-95`). There is no guardrail model (CVE types, fix types, repositories, environments) and no kill switch, because there is no autonomy to restrict. |

### 2.3 Writes without a recorded human approval

None of these is reachable from any deployed program today. All of them
would be, the moment a real GitHub client were wired in:

1. `remediate.Worker`: creates a branch, commits, pushes, and opens a pull
   request after automated verification only (`worker.go:249, 349, 359, 422,
   510`).
2. `remediate.Settle`: closes a pull request automatically when its
   findings resolve (`settle.go:82`).
3. The tracker service: creates tickets and comments (`tracker/service.go:134,
   237, 253, 341`; `orchestrator/tickets.go:171`). These are tickets, not
   code.
4. Report publishing: writes report files to a repository through
   `gh.Publisher` (`report/publish.go:185-209`, `report/deliver.go:55-233`).
   Not code changes, but writes.

**Nothing merges.** No merge call, auto-merge request or branch-protection
change exists in the code.

### 2.4 Places the AI could reach a write credential

- **The clone's `.git/config`.** `RESTOps.Clone` clones from
  `https://x-access-token:TOKEN@github.com/...` (`gh/ops.go:263-283`,
  `cloneURL` at `:447-452`). Git records that URL, token included, as the
  clone's `origin`. The worker then runs the fixer, and so the agent, in the
  same directory (`worker.go:173`). A write-capable installation token would
  sit in a file the agent's process can read. Mitigations today:
  - the sandbox denies the network (`sandbox/impl.go:87-124`);
  - the agent is told not to commit or push (architecture §11.4);
  - the guard refuses a diff whose added lines match a GitHub token pattern
    (`guard/guard.go:223-238`, `model/secret.go:25`).

  An encoded or split token would pass the guard. **Latent, not live**:
  nothing wires `RESTOps`. The design below removes the token from the
  working copy entirely.
- **The process environment.** The agent's environment is filtered to an
  allowlist (`sandbox.FilterEnv`, `sandbox/impl.go:68`), with
  `ANTHROPIC_API_KEY` added only after the sandbox verifies itself
  (`agent/client.go:69-113`). A canary probe checks the filtering
  (`sandbox/impl.go:235-250`). This is sound by design, but the Linux proof
  has never run (D2).
- **The read-only scanning token** (`VULNFRAMEWORK_GITHUB_TOKEN`) is read
  only by the orchestrator in account mode and passed to the download client
  (`cmd/orchestrator/main.go`, `gh/pat.go`). It never reaches a fixer.

### 2.5 What changes from the original design, and why

| Original | Now | Why |
|---|---|---|
| The worker opens a pull request once verification passes; the pull request is where a human decides (VM-F-541: "not automatically merged in v1.0"). | Nothing is written to GitHub until a qualified person approves a specific diff in the tool. The pull request carries exactly the approved diff. | Requirement 1 and 5: the decision belongs to a qualified approver, recorded, before any write; reviewers do not go through GitHub to decide. |
| One worker holds the installation token and also hosts the fixer. | Proposal generation (with the AI) and publication (with a write credential) are separate components that never share a process, a working copy or a credential. | Requirement 1 and section 2.4: the AI must never be able to reach a write credential. |
| One fix per group, validated by build, test and a rescan of the producing scanners. | Several candidate fixes, one chosen with reasons; validation adds a full rescan, a new-findings check and non-CVE regression checks. | Requirements 2 and 4. |
| Routing by tier, language and change class. | Plus a risk engine: two scores, confidence with an error margin, thresholds per severity. | Requirement 3. |

---

## 3. The shape of Phase 8

Three slices, in this order:

- **8a**: proposals only, nothing written anywhere but our database. After
  Phase 1, alongside Phase 3.
- **8b**: approval, then publication. After Phase 4, which brings the login
  and roles it needs.
- **8c**: limited autonomy, only with a formal approval.

The planned shape holds against the code, with three adjustments:

1. **Generation runs on a downloaded tarball, not a git clone.** The account
   mode built in the demo track already downloads repositories as tarballs
   with no credential on disk (`orchestrator/github.go`). Generation reuses
   it, which closes the `.git/config` token issue in section 2.4 by
   construction.
2. **8a's validation needs real build and test toolchains per language,** and
   only Go exists. 8a therefore starts with Go and JavaScript/TypeScript, and
   adds languages as their toolchains land (section 9). A finding in a
   language without a toolchain gets a proposal marked "not validated:
   needs expert review", never a validated one.
3. **The existing worker is split, not discarded.** Its baseline, guard and
   verification steps move into the proposal validator. Its commit, push and
   open-PR steps move into the publisher, which runs only for an approved
   proposal.

---

## 4. 8a: validated proposals, stored only in our database

### 4.1 Pipeline, per fix group

```
 sweep finds and triages ─► finding assessment (AI): real? impact? confidence
            │
            ▼
 candidate generation in the sealed sandbox, on a downloaded tarball
   - deterministic candidates (dependency bumps: patch, minor) — no AI
   - agent candidates (call-site changes, source fixes), up to N per group
            │
            ▼
 validation of EACH candidate (section 6) ─► evidence, verbatim
            │
            ▼
 choice: the AI ranks the candidates that passed, against the full code,
 and states why; an independent critic pass reviews the chosen diff
            │
            ▼
 risk engine (section 7): finding risk, fix risk, margins, verdict
            │
            ▼
 proposal stored: READY / NEEDS_EXPERT_REVIEW / FAILED_VALIDATION
            │
            ▼
 read-only review page and `vfctl fix show`
```

Nothing in 8a writes to GitHub, a tracker or any repository.

### 4.2 Candidate generation

- **Deterministic first.** A dependency finding with a fixed version gets the
  smallest patch or minor bump as a candidate, with no model involved
  (VM-F-521 kept). A major bump is a candidate only if policy allows majors
  for the tier, and is always marked as such.
- **Agent candidates** are produced when no deterministic candidate exists or
  the deterministic one fails validation. Up to `max_candidates` (default 3)
  per group, each asked to take a different approach. The agent sees:
  - the full repository tree, read-only, for weighing the fix against the
    code (requirement 2);
  - the finding records and the advisory text, treated as untrusted data
    (VM-F-309).

  The agent produces a working tree and a written rationale, and nothing
  else.
- **Budgets** per candidate (iterations, wall clock, tokens) as today
  (`agent/agent.go:89`), plus a per-group token ceiling.
- **Secrets never enter generation** (VM-F-407 kept). A secret finding gets a
  rotation proposal, which is a checklist, never a code change.

### 4.3 Choice and packaging

The chooser (an AI pass, separate from the generator) sees every candidate
that passed validation, with its evidence. It returns:
- the chosen candidate;
- a ranked list with reasons for each;
- a fix-confidence estimate.

A second, independent critic pass reviews only the chosen diff for
behavioural change, resource handling and error paths. Its objections are
shown on the review page.

A proposal packages exactly what requirement 2 lists:
- the location;
- why it is a problem (finding and advisory);
- the exact lines changed, as the diff;
- the fix rationale, and the alternatives with why they lost;
- severity and both confidences;
- the validation evidence;
- a ready-to-use pull request title and body (VM-F-543 content).

---

## 5. Data model

New tables, both backends (memory and Postgres), one migration. A proposal
is immutable once validated: any change creates a new proposal that
supersedes it.

```
fix_proposals
  id                  TEXT PK           -- fp_<sha256(fix_group, base_commit, diff)[:12]>
  fix_group_id        TEXT              -- existing derivation (VM-F-502)
  repo                TEXT  FK repos
  findings            TEXT[]            -- fingerprints
  base_commit         TEXT              -- the tarball's commit; staleness is measured against it
  status              TEXT  CHECK IN (generating, validating, ready,
                                       needs_expert_review, failed_validation,
                                       approved, rejected, superseded, stale,
                                       publishing, pr_open, merged, verified,
                                       closed_unmerged, reverted)
  generator           JSONB             -- deterministic | agent; model id; prompt and
                                        -- rules hashes; tool versions; image digest
  candidates          JSONB             -- each: id, diff, diff_sha256, rationale,
                                        -- validation summary, rank, why chosen or not
  chosen_candidate    TEXT
  diff                TEXT              -- the chosen diff, verbatim
  diff_sha256         TEXT
  finding_assessment  JSONB             -- is_real {p, low, high}, impact, reasoning, sources
  fix_assessment      JSONB             -- safe {p, low, high}, critic objections, reasoning
  risk                JSONB             -- finding_risk, fix_risk, severity, threshold
                                        -- applied, verdict, engine version
  validation_id       TEXT  FK validations
  pr_title, pr_body   TEXT
  created_at, updated_at, expires_at TIMESTAMPTZ

validations
  id, proposal_id, candidate_id
  steps               JSONB             -- each: name, command, exit, duration, passed,
                                        -- output (verbatim, size-capped, credential-checked)
  baseline            JSONB             -- the same steps before the change
  rescan              JSONB             -- tools run, findings before, after, new, gone
  regression_checks   JSONB             -- section 6.3, each with evidence
  outcome             TEXT  CHECK IN (passed, failed, incomplete)

fix_decisions                           -- 8b; append-only
  id, proposal_id
  decision            TEXT  CHECK IN (approve, reject, request_changes)
  approver            TEXT              -- identity from the identity provider
  approver_roles      TEXT[]            -- as asserted at decision time
  qualification       JSONB             -- code-owner match, team, attestation text
  diff_sha256         TEXT              -- must equal the proposal's
  view_sha256         TEXT              -- hash of the rendered review content the approver saw
  channel             TEXT  CHECK IN (web, vfctl)
  comment             TEXT  NOT NULL for reject and request_changes;
                                    required for approve on critical
  decided_at          TIMESTAMPTZ

fix_publications                        -- 8b; written only by the publisher
  id, proposal_id, decision_ids TEXT[]
  repo, branch, pr_number, pr_url
  pushed_diff_sha256  TEXT              -- must equal the approved diff_sha256
  credential_ref      TEXT              -- which credential, never the credential
  published_at, merged_at, verified_at, closed_at
```

Audit: every status change is a row in the existing `state_transitions`
pattern, with actor (system, AI component, person), cause and timestamp.
Access to the review page is already access-logged (`api/accesslog.go`).

---

## 6. Validation

Every candidate is validated before anyone sees it. Failures are stored and
shown with their verbatim output (VM-F-532 kept), never hidden or
summarised away.

### 6.1 Isolation

- **Generation and validation run in the sealed sandbox:** bubblewrap on
  Linux with no network namespace, filtered environment, the working tree
  only.
- **Dependency fetching is a separate step,** before sealing. It runs
  through an allowlisted package proxy (the language's registry only), into
  a cache that the sealed step mounts read-only. Builds need dependencies,
  and fetching them is the only network access the pipeline has; it never
  runs repository code.
- The sandbox's Linux proof (D2) is a precondition for 8a on real
  repositories.

### 6.2 Steps

| Step | What | Fails the candidate when |
|---|---|---|
| Baseline | Build and tests on the unchanged tree (VM-F-504) | The baseline itself fails: the proposal is marked "baseline broken", and the failure is shown |
| Guard | Deny paths, suppressions, credentials in added lines (`guard.go`, VM-F-508 to 510) | Any violation |
| Build | The language's build (section 9) | Non-zero exit |
| Static checks | The language's linters (`go vet`, staticcheck, eslint, type checker) on the changed files | A new diagnostic compared with the baseline |
| Tests | The full suite, with the race detector where the language has one | Any test that passed in the baseline fails; tests removed or weakened (`agent.go:129`) |
| New test | For a source fix, a test that fails before and passes after (VM-F-525) | Absent, without a stated reason |
| Manifest | `go mod tidy -diff`, lockfile consistency | Not tidy |
| Full rescan | **Every** scanner for the repository's components, not only the producing ones | The targeted findings remain, or **any new finding appears** in any category |
| Regression checks | Section 6.3 | A check fails, or exceeds its tolerance |

### 6.3 Non-CVE regressions (requirement 4)

No single tool finds every regression, so several checks run, each aimed at a
known kind of problem. Each one reports what it found and what it could not
check:

1. **Differential resource measurement.** The test suite runs baseline and
   changed, inside the sandbox's cgroup. The comparison covers:
   - peak resident memory;
   - live goroutines or threads at exit;
   - open file descriptors at exit;
   - wall time.

   A rise beyond a tolerance (default: 10% memory, any increase in leaked
   goroutines or descriptors) fails or flags the candidate. Variance is
   controlled by repeating each run (default 3) and comparing medians.
2. **Leak-pattern rules on the changed lines.** Our own rules flag:
   - response bodies, files and rows not closed;
   - `defer` inside loops;
   - contexts not cancelled (`go vet` lostcancel);
   - goroutines without an exit path;
   - unbounded caches and slices growing in loops.

   They run on the diff hunks, so they speak about the change, not the whole
   repository.
3. **Leak detection inside tests, where the language supports it.** For Go:
   the goroutine count at exit, and `goleak` where the repository already
   uses it. For JavaScript: `--detectOpenHandles`. These are reported, not
   added to the repository.
4. **The critic pass.** An independent AI review of the diff aimed at
   resource lifecycle, error paths and behavioural change. Its objections
   lower the fix confidence and are shown verbatim.
5. **Scope limits.** The diff touches only files the fix needs (VM-F-523,
   minimal change). Large diffs raise fix risk directly (section 7).

What this cannot promise: a leak that only appears under production load,
or in code the tests never run. The review page says so, beside the
coverage of the changed lines.

---

## 7. Risk engine

### 7.1 Two risks

- **Finding risk.** The probability that the finding is real and matters.
  Inputs:
  - the AI's assessment of whether it is real;
  - reachability (`classification.reachable`);
  - exploitation evidence (KEV, EPSS);
  - severity and tier;
  - whether the scanner's rule has a history of false positives in this
    fleet (from reviewers' decisions).
- **Fix risk.** The probability that the fix is wrong or harmful. Inputs:
  - validation outcome (a hard gate: a failed step means no "ready" verdict);
  - change class (deterministic patch < minor < agent call-site change <
    agent source change < major);
  - diff size and number of files;
  - test coverage of the changed lines;
  - the regression checks;
  - the critic's objections;
  - the chooser's stated confidence.

### 7.2 Confidence with an error margin

A model's stated confidence is not a probability. The engine therefore
reports each risk as an estimate with an interval, calibrated against
outcomes:

- **Before any history**, the estimate comes from fixed weights over the
  inputs above. It is labelled "uncalibrated", like every provisional figure
  in this system today, with a deliberately wide margin.
- **Each reviewer decision and each post-merge outcome** (verified, reverted,
  regression reported) is a labelled example. The engine fits a calibration
  per change class and severity (isotonic or logistic). It reports the
  interval from the number of examples behind it, for example "fix safe:
  0.94 (0.88 to 0.97, 140 examples)".
- **The engine version, the weights and the calibration data** are stored
  with every proposal, so a past verdict can be reproduced.

### 7.3 Thresholds per severity

Configured in `config/remediation.yaml`, versioned, and changed only through
review. The **lower bound** of the interval must clear the threshold, which
is how "even 90% may not be enough" for a critical finding becomes concrete.
Proposed defaults, to be decided (D14):

| Severity | Fix-safety lower bound for "ready" | Additional |
|---|---|---|
| Low | 0.80 | one approver |
| Medium | 0.85 | one approver |
| High | 0.90 | one approver who is a code owner of every changed file |
| Critical | 0.95, and never for an agent source change in the first release | two approvers: a code owner and a second developer or DevOps approver |

Below the threshold, or without calibration history, the verdict is **needs
expert review**. Such a proposal is still shown, with the same evidence, and
still needs approval, which only an expert approver (D14) may give. A failed
validation is **failed validation**: shown in full, and not approvable.

### 7.4 Formal risk acceptance

Before production use, the organisation signs a risk acceptance. It names:
- the thresholds;
- the calibration evidence behind them (from the 8a pilot);
- who may approve;
- the residual risks in section 6.3;
- the review interval.

It is stored in the repository (`RISK-ACCEPTANCE.md`) with signatures, and
its version is recorded on every published fix. The tool refuses to publish
in 8b while no accepted version exists for the deployment.

---

## 8. 8b: approval, then publication

### 8.1 Who may approve (requirement 6)

- **A new role, `fix_approver`,** separate from the report levels. Granted
  per person, through the identity provider group that Phase 4 maps.
- **To approve a given proposal,** the approver must also be:
  - a developer or DevOps engineer on the owning team;
  - a code owner (CODEOWNERS) of every changed file, for high and critical.

  The tool checks this at decision time and records the result.
- **Security staff without that context may comment,** and may reject, but
  may not approve. Rejecting a bad fix needs no code context; approving one
  does.
- **The person who changed the thresholds** in the current risk acceptance
  may not be the sole approver of a critical fix.

### 8.2 Deciding

- **Web:** the review page has Approve, Reject and Request changes. A
  rejection requires a comment.
- **Terminal:**
  - `vfctl fix list`, `vfctl fix show ID`;
  - `vfctl fix approve ID` and `vfctl fix reject ID --reason TEXT`.

  `show` prints the same content as the page. `approve` refuses unless
  `show` was run for the same diff hash in this session.
- **Every decision records:**
  - the approver's identity and roles;
  - their qualification check;
  - the proposal's diff hash;
  - a hash of the rendered content they were shown;
  - the channel and the time.

  A decision whose diff hash differs from the proposal's is refused.
- **A stale proposal cannot be approved.** If the repository's default
  branch has moved, the proposal is revalidated against the new head first,
  and the decision then applies to the new validation.

### 8.3 The publisher

A separate component (`cmd/fixpublisher`) and the only holder of a write
credential:

- **Its credential** is a GitHub App installation token minted per
  repository, 1-hour TTL, with permissions **contents: write** and **pull
  requests: write**, on opted-in repositories only. It has no
  administration and no workflow permission, and cannot change branch
  protection. It is never the read-only scanning token. It is never mounted
  into the generator, the validator, the agent or any AI component.
- **Its input** is one approved proposal, read from the database.
- **It reproduces the approved change exactly:** a fresh checkout at
  `base_commit`, the approved diff applied, and a check that the result
  hashes to `diff_sha256`. Any mismatch aborts.
- **It pushes the branch** `security/fix-<fix_group_id>` and opens a pull
  request with the approved title and body, labelled as machine-generated
  (VM-F-542), with the approver named and a link to the review page. One
  commit per logical fix (VM-F-505), with the framework's identity
  (VM-F-544).
- **The token is never written into the working copy.** It is supplied to
  the one git process through `GIT_ASKPASS` or an `http.extraheader`
  environment variable, never in a remote URL (fixing the pattern in
  `gh/ops.go:447`).
- **It never merges.**

### 8.4 Merging, deployment and validation (requirement 7)

- **At first, merging stays in GitHub,** under the repository's branch
  protection: required reviews and required status checks. The tool's
  approval is the decision; the GitHub merge is the deployment gate the
  team already owns.
- **After merge, everything is automatic:**
  - the merge is observed (webhook primary, reconciliation fallback;
    architecture §7.3.1);
  - the default branch is rescanned;
  - the finding becomes VERIFIED only when that scan no longer sees it
    (VM-F-533, kept);
  - a fix that reappears, or a revert, is recorded against the proposal.
    That feeds calibration, and for a dependency fix it reopens the
    finding.
- **Deployment to environments belongs to each team's CD.** The tool
  observes it read-only where a deployment status exists (GitHub
  deployments, CI checks), and reports a verified fix as "verified in
  default branch", not "deployed", until it can see the deployment.
- **Later (D14),** the publisher may enable GitHub auto-merge on an approved
  pull request once its required checks pass, so approval leads to merge
  with no second manual step. Branch protection still decides.

### 8.5 The review page (requirement 5)

One page per proposal, reachable from the finding and from a review queue.
Top to bottom:

1. **The verdict line:** ready, needs expert review, or failed validation;
   severity; finding risk and fix risk, each with its interval; the
   threshold applied; who may approve this one.
2. **The finding:** location (file and line, or module and version); what is
   wrong and why it matters; the advisory; reachability; KEV and EPSS; the
   AI's assessment of whether it is real, with reasons; the scanner's rule;
   how many reviewers rejected this rule elsewhere.
3. **The change:** the exact diff, side by side, with the changed lines'
   test coverage; files touched; whether it is deterministic or AI-written.
4. **Why this fix:** the rationale; the alternatives considered and why they
   lost; the critic's objections, verbatim.
5. **Evidence:** each validation step with pass or fail, and the verbatim
   output a click away; baseline compared with changed (tests, resources,
   diagnostics); the rescan (targeted findings gone, new findings: none, or
   listed).
6. **What it cannot tell you:** checks that did not run, and why; residual
   risks (section 6.3).
7. **Impact:** consumers of the module (first-party waves), the services
   built from the repository where known, and the pull request title and
   body that will be published.
8. **Decision:** Approve, Reject, Request changes, with the comment rules.
   Disabled, with the reason, for anyone not qualified for this proposal.

---

## 9. Build-and-test tooling per language

8a cannot validate a language without a toolchain that can fetch
dependencies, build and test it in the sandbox. Only Go has one, and it has
never run on a real repository.

| Language | Toolchain work | Estimate |
|---|---|---|
| Go | Wire `gotool` into the validator; module proxy for dependency fetch; resource measurement; leak rules; prove on 3-5 real repositories | **2-3 weeks** |
| JavaScript / TypeScript (npm, then yarn and pnpm) | Lockfile-respecting install through a registry proxy; `npm run build` if present; test-script detection (jest, vitest, mocha); `--detectOpenHandles`; type check | **3-4 weeks** |
| Python (pip, Poetry, uv) | Isolated environment per repository; lockfile install; pytest detection; native-extension builds; Python version selection | **4-5 weeks** |
| Java / Kotlin (Maven, Gradle) | JDK selection; wrapper handling; offline mode after dependency fetch; surefire and JUnit reports; long builds | **4-6 weeks** |
| C#, Ruby, PHP, Rust | Not before the pilot | each 3-5 weeks |

Shared work, once: candidate generation, the chooser and critic, the
validation record, the risk engine without calibration, the data model, the
read-only review page, and `vfctl fix list` and `show`. **About 5-6 weeks.**

**8a for Go and JavaScript/TypeScript: about 10-13 weeks of focused work.**
Each further language adds its row.

**8b** (approval, the role checks, publisher, credential, auditing, the
review page's decision controls): **about 4-5 weeks after Phase 4.**

Phase 4 itself (identity provider, roles, writable API) is 2-3 weeks and is
a prerequisite.

These estimates assume one engineer working with AI assistance, as this
project has been built. They exclude the waits that are not engineering: the
Linux sandbox proof (D2), the GitHub App with write permission (D4), the
pilot's calibration period (at least 4-6 weeks of real proposals before
thresholds mean anything), and the risk acceptance. Aaron's "about six more
months" is realistic for production with every control in place. A
read-only 8a on Go and JavaScript, for feedback, is the early shippable step
(requirement 9).

---

## 10. 8c: limited autonomy (only with formal approval)

Autonomy means publishing **and merging** without a per-change human
approval. It is allowed only inside all of these:

- **Fix types:** deterministic dependency bumps only (patch, then minor),
  never agent-written code, and never a major bump.
- **CVE types:** an allowlist by advisory class (for example, a fixed version
  exists, the dependency is direct, and the vulnerable symbol is reachable or
  the advisory is in KEV).
- **Repositories:** opted in individually by their owning team, tier 3
  first.
- **Environments:** development branches and environments; never a branch
  that deploys to production without that branch's own review.
- **Evidence:** every validation step passed, the fix-risk lower bound above
  the autonomy threshold (stricter than any manual threshold), and the
  calibration for that change class based on at least a set number of
  approved, verified examples.
- **Rate:** at most N autonomous changes per repository per day, and one
  open at a time.
- **Kill switch:** one flag, checked by the publisher before every write.
  It can be set from the web app and `vfctl fix autonomy off` by an admin,
  and is also off by default after any revert or verified regression.
- **Rollback:** an autonomous change that fails post-merge verification is
  reverted by a pull request that a person approves.

Every autonomous change is audited like an approved one, with "policy" as
the approver and the policy version recorded. 8c needs its own risk
acceptance.

---

## 11. Credentials and who holds them

| Credential | Permissions | Held by | Never reaches |
|---|---|---|---|
| Scanning token (fine-grained PAT, or App installation token for read) | Contents, Metadata: read | Orchestrator (account mode), at the moment of use | Generator, validator, AI, publisher |
| AI provider key | Model inference | Triage, candidate generator, chooser, critic, each inside the sandbox after it verifies | Anything with a GitHub credential |
| Publisher App key and installation tokens | Contents: write, Pull requests: write, opted-in repositories, 1-hour tokens | `fixpublisher` only | The working copy (no token in URLs), any AI component, logs |
| Database | Read/write | API, orchestrator, generator (proposals), publisher (publications) | The sandboxed processes |
| Identity provider | Sign-in | API, through the proxy | Everything else |

---

## 12. How each requirement is met

| # | Met by |
|---|---|
| 1 | Nothing is written to GitHub before a recorded approval (sections 8.2, 8.3). The publisher refuses unapproved, mismatched or stale diffs. It never merges; merging is in GitHub under branch protection. 8c is the only exception, and needs its own formal approval. |
| 2 | Finding assessment, several candidates, a chooser with reasons, a critic, and a packaged proposal with a ready pull request (sections 4.2, 4.3, 5). |
| 3 | Two risks, each with an interval and calibrated against outcomes; the lower bound must clear a per-severity threshold; the risk acceptance gates publication (section 7). |
| 4 | Baseline-compared builds, static checks, tests, a full rescan for new findings, and five non-CVE regression checks with their limits stated (section 6). |
| 5 | One review page, with the same content in `vfctl fix show`; decisions in both; no GitHub needed (sections 8.2, 8.5). |
| 6 | The `fix_approver` role, team and code-owner checks, and security staff limited to comment or reject (section 8.1). |
| 7 | Automatic publication after approval, automatic post-merge verification, and deployment observed read-only (section 8.4). |
| 8 | Section 10: fix, CVE, repository and environment allowlists, a rate limit and a kill switch, behind a formal approval. |
| 9 | 8a is shippable for feedback on Go and JavaScript before 8b exists, and SECURITY-READINESS.md has the answers ready. |
