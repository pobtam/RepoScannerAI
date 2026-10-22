# Security readiness

Plain answers to the questions a security review will ask, as of 22 October
2026. Where something is missing, this says so. References point to the
detail: `REMEDIATION-DESIGN.md` (RD), `DEPLOY.md`, `DECISIONS-NEEDED.md`.

## Is it production-ready?

**Scanning is close; fixing is not built.**

- **Scanning is not production-ready yet,** for four reasons:
  - It has run on a Mac against a real account, not in the cloud.
  - Its login is a single shared password behind an IP restriction, not
    company single sign-on.
  - It fully covers only Go and JavaScript.
  - It has no alerting.

  It is safe to run read-only for a pilot on the owner's own repositories,
  which is how it has been used.
- **AI-assisted fixing is not production-ready, and is not deployable at
  all today.** The fix worker refuses to run outside its demonstration mode
  (`cmd/fixworker/main.go:79-95`). The design that meets the review's
  requirements is written (RD) and not yet built.

## What risk does it add, as deployed today?

- **It reads every repository the key can reach.** Each is downloaded, and
  deleted after its scan. Private code exists on the scanning machine only
  during a scan.
- **It cannot write to GitHub.**
  - The only GitHub credential in the deployed system is a fine-grained,
    read-only token.
  - The client that uses it refuses any request other than GET or HEAD
    before it leaves the machine.
  - A classic token that grants write access is refused at connection.
  - It opens no pull requests, comments or tickets.
  - The web app's only write is **requesting a scan**: only the
    security-owner level, only from the app's own pages (cross-site requests
    refused, CSRF token required), rate-limited, and recorded with who asked,
    for which repository, and when. It adds a row to a queue; the API never
    runs a scanner.
- **It sends no code to an AI provider by default.** AI triage is off unless
  a model and key are configured. When on, it sends finding metadata
  (identifiers, file paths, versions), not source code or secret values.
- **Its stored data is findings,** which are a map of the organisation's
  weaknesses. The database is reachable only inside the deployment, behind
  the login and an IP-restricted firewall, on encrypted disks.

## How are AI mistakes contained?

| AI role | Today | When fixing is built (RD) |
|---|---|---|
| Triage (explains findings) | Off by default. What is sent to the AI is checked for credentials first (`triage/http.go:100`). A verdict that invents an identifier or tries to apply a suppression is rejected (`triage/validate.go:81-93`). It has no priority field: priority is computed from the scores, never taken from the model (`triage/triage.go:73`). | Adds a confidence with an error margin, calibrated against what reviewers decide. |
| Writing fixes | Not deployable. | Runs in a sealed sandbox with no network and no GitHub credential, on a downloaded copy of the code with no git history or remote. Every candidate is built, tested and rescanned before anyone sees it, and failures are shown, not hidden. A second, independent AI reviews the chosen change. Nothing it writes reaches GitHub without a qualified person's approval of that exact change. |
| Choosing between fixes | Not built. | Its reasons are shown. It cannot approve. |

The rule that holds throughout: an AI component never holds a credential
that can change anything outside our own database.

## Who can approve a fix?

- **Today:** nobody, because there is no approval and no fixing.
- **When built (8b):** only people with the `fix_approver` role who are
  developers or DevOps engineers on the team that owns the code. For high and
  critical findings they must be code owners of every changed file, and
  critical fixes need two approvers. Security staff without that context can
  comment or reject, not approve. The exact rule is decision D14.

## What is logged?

- **Today:**
  - every API request, with the identity, outcome and filters;
  - every state change of every finding, with its cause and actor;
  - every human decision on secrets (who, when, what);
  - every scan's tools and versions, and its coverage gaps;
  - the GitHub connection (account, token type, expiry; never the token).
- **When fixing is built:** every proposal, every candidate and its
  validation evidence verbatim, every decision, with:
  - the approver's identity and roles, and the qualification check;
  - a hash of the exact change approved;
  - a hash of exactly what they were shown;
  - every publication, with proof that the published change equals the
    approved one;
  - every post-merge verification.

## What credentials exist, and who holds them?

| Credential | Today | Held by | Can it change anything? |
|---|---|---|---|
| GitHub scanning token (fine-grained) | Yes | Secret Manager on the VM. The scan worker reads it when it starts and keeps it in its environment while it runs (root on the VM could read it from the container); stopping the worker removes it. Never written to disk or database; never seen by the API or the interface | No: read-only permissions, and the client sends only GET and HEAD |
| Login password | Yes | Secret Manager (bcrypt hash only) | It grants read access to the web app |
| Database password | Yes | Generated on the VM; the database is not published outside the deployment | Our own data only |
| AI provider key | Optional, off by default | Environment, when AI triage is turned on | Calls the AI provider only |
| GitHub App with write permission | **No** | Not created (D4) | When created for 8b: a separate publisher only, contents and pull requests on opted-in repositories, never merge, never shared with an AI component |

## What is still missing?

**For scanning in production:**
- company single sign-on and roles (Phase 4);
- full coverage of every language (Phase 1, in progress);
- AI-specific vulnerability checks (Phase 3);
- alerts and a scheduler with timeouts (Phase 5);
- the cloud deployment applied and run for a week (Phase 6);
- calibration of deadlines and thresholds during a pilot (Phase 7).

**For AI-assisted fixing:**
- everything in RD, none of it built yet:
  - proposals and their validation;
  - build-and-test toolchains per language (only Go exists, and it has never
    run on a real repository);
  - checks for non-CVE regressions such as leaks;
  - the risk engine and its calibration;
  - the approver role and review page;
  - the separate publisher.
- The Linux sandbox has never been proven on Linux (D2).
- A formal risk acceptance must be signed before any fix reaches
  production.

**Known weaknesses found in the existing code** (none reachable today):
- The original pipeline would push and open pull requests after automated
  checks, with no human approval. The new design replaces this.
- Its clone step puts a write-capable token in a file the AI's working
  copy can read. The guard would catch a plainly copied token, not an
  encoded one. The new design removes the token from the working copy
  entirely.
- Its rescan checks only that the targeted finding is gone, not that
  nothing new appeared.

**Timeline:** the review's estimate of about six months to production for
fixing, with every control, is realistic. The first useful slice for
feedback is read-only fix proposals for Go and JavaScript, about 10-13 weeks
after Phase 1 (`NOW-VS-LATER.md`).
