# What it does now, and what each step adds

For Jeff. Plain language; the engineering detail is in
`REMEDIATION-DESIGN.md`, and the security questions are answered in
`SECURITY-READINESS.md`. As of 22 October 2026.

## The short version

- **Today**, the tool finds vulnerabilities across every GitHub repository a
  read-only key can reach, ranks them, and shows them in a web app. It does
  not fix anything.
- **Fixing comes in three steps.** First the AI prepares and tests fixes
  that people can read but not apply. Then qualified people approve fixes,
  and only approved ones become pull requests. Much later, and only if the
  company formally agrees, a narrow set of routine fixes could apply
  themselves.
- **Nothing ever changes code without a recorded approval from a qualified
  person**, except that last, optional step, inside strict limits.

## What works today

- **Connect a GitHub account with a read-only key.** The tool lists every
  repository it can reach and says which it scans and why it skips the rest.
  It cannot change anything on GitHub. This has been run against a real
  account: 9 repositories found, 5 scanned, 4 skipped with reasons.
- **Scanning.** Each repository is downloaded, scanned and deleted:
  - known vulnerable dependencies;
  - risky code patterns;
  - leaked secrets;
  - configuration problems.

  Go and JavaScript repositories are covered fully. Other languages get the
  secret and configuration checks only, until the next step lands.
- **Ranking.** Each finding gets a priority and a deadline, using whether
  it's being exploited in the wild and whether the code actually reaches the
  vulnerable part.
- **A web app** shows findings, coverage, repositories and history, behind
  HTTPS and one login. It is ready to run on a Google Cloud VM; it has been
  run on a Mac, not yet in the cloud.

**What it cannot do yet:**
- scan every language fully;
- look for AI-specific vulnerabilities;
- fix anything;
- support more than one login, or roles.

## The steps from here

| Step | What it adds | What fixing looks like then |
|---|---|---|
| **Phase 1: every language** | Scans every part of a repository in every common language, and says plainly which parts it couldn't check. | No fixing. |
| **Phase 3: AI vulnerabilities** | Finds unsafe use of AI models in code: user input mixed into prompts, AI output run as code, AI agents with too much power, secrets sent to AI, no limits on usage. | No fixing. |
| **Optional: NuGuard for AI code** (built 3 November, off, awaiting your decision) | Asks NuGuard, a separate AI-security scanner, to check the same code for AI-specific problems, and lists the AI parts of each repository (agents, models, tools) as information, not as problems. Off until you agree and NuGuard publishes the release it depends on. It does not replace our own Phase 3 rules. Since 6 November, security owners can switch it on or off and choose its AI tools from the web app, within limits the operator sets; switching it off never closes what it found. **Not yet:** <br>- Python repositories (today it covers the same Go and JavaScript ones as everything else); <br>- NuGuard telling us when a scan is done instead of being asked repeatedly; <br>- NuGuard fetching the GitHub key from its own secret store instead of receiving it with each scan; <br>- letting people choose NuGuard's dependency, infrastructure-config and container scanners (osv, grype, trivy, checkov, supply chain): a separate decision, because our own tools already cover those and the adapter only reads NuGuard's code findings; <br>- the kept AI-SBOM in the CycloneDX standard format (it is kept and downloadable as NuGuard returns it); <br>- counts beside the "Found by" filter's options; <br>- in real mode (`./run.sh --real --nuguard`, built 11 November), NuGuard scanning your local copy directly. Today it downloads the repository from GitHub, so commits not yet pushed and repositories not on GitHub get no NuGuard scan. Covering them needs NuGuard's service to accept an uploaded copy of the code. | No fixing. |
| **Phase 8a: fix proposals** (after Phase 1, alongside Phase 3) | For each finding, the AI checks whether it's real and how much it matters. It writes a few possible fixes, tests each one in a sealed environment, picks the best with reasons, and rates its confidence. People read these in the web app or the terminal. | **Proposals only.** Nothing is sent to GitHub. People can see exactly what the fix would be, how it was tested, and how confident the system is, and can give feedback. This is the early version to show customers. |
| **Phase 4: proper sign-in** | Company sign-in (single sign-on), roles, and two-factor authentication. Needed before anyone can approve anything. | Still proposals only. |
| **Phase 8b: approved fixes** (after Phase 4) | A qualified developer or DevOps engineer approves or rejects each proposal, in the web app or the terminal. The tool records who approved what, and exactly what they saw. Only then does a separate part of the system open a pull request with exactly that change. | **Approved fixes become pull requests automatically.** Merging still happens in GitHub under each team's existing rules. After the merge, the tool rescans and confirms the problem is gone. |
| **Phase 5-6: running unattended in the cloud** | Scheduled scanning, alerts, and the cloud deployment made production-grade. | As in 8b, on a schedule. |
| **Phase 8c: limited autonomy** (later, only with formal approval) | For a narrow, agreed set of routine fixes (for example, a small version bump of a library with a known fix), in development environments and repositories that opt in, the tool may apply the fix itself. There is a daily limit and an off switch. | Routine fixes in agreed places apply themselves; everything else still needs a person. |

## Timing, honestly

- **Phase 1:** a few weeks.
- **Phase 8a for Go and JavaScript:** about 10-13 weeks of work after Phase
  1. That is the first version worth showing for feedback.
- **Phase 4:** 2-3 weeks.
- **Phase 8b:** about 4-5 weeks after Phase 4.
- **Before approved fixes can be used in production,** the system needs a
  few weeks of real proposals to measure how often it's right, and then a
  signed risk acceptance. The security review's estimate of about six months
  to production with all controls in place is realistic.

## What the security review asked for, in one line each

1. A person approves every fix before it can merge. **Yes, from 8b.**
2. The AI explains the finding, considers several fixes, picks one with
   reasons, and packages it. **Yes, from 8a.**
3. Two separate risk ratings, with confidence and stricter rules for serious
   problems. **Yes, from 8a; the ratings get more accurate as approvals
   accumulate.**
4. Fixes mustn't create new problems, even ones that aren't known
   vulnerabilities. **Tested several ways from 8a. Some kinds of problem only
   show up under real load, and the review page says so.**
5. One page with everything needed to decide, in the web app or the
   terminal. **Yes, from 8a (read-only) and 8b (decisions).**
6. Only qualified people can approve. **Yes, from 8b.**
7. After approval, the rest is automatic. **Yes, from 8b; deployment stays
   with each team's own pipeline.**
8. Autonomy only later and within limits. **8c, only with formal approval.**
