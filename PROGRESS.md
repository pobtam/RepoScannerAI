# PROGRESS

Unattended run on `real-repos`, started 2026-10-13. If a session restarts,
read this file first and resume from "Next".

## Current

- **Priority changed by you (2026-10-13):** build only what a bare-minimum
  NON-LOCAL demo needs, before resuming Phase 1. See "Demo track" below.
- **Phase:** demo track complete (D1-D3). Waiting on you for the cloud steps.
- **Waiting on you (2026-10-20):**
  - Phase 1 rule sources: approve DECISIONS-NEEDED D12 points 1-5.
  - Phase 3 AI scanner: choose from the NuGuard evaluation below.
  - The PROGRESS wording fix for item 3 (fairness check, 2026-10-19).
- **Next (when you say so):** resume the unattended plan at Phase 1
  (mixed-language scanning); the earlier plan for it is below.

## Phase 3 evaluation: NuGuard as the AI scanner (2026-10-20)

Read-only. Nothing integrated; no repository file changed except this one.
Everything ran in a throwaway image `vf-nuguard-eval:0.9.15` built FROM
`vulnframework-scanner:v1` (unchanged), with `--network none`, no LLM
credentials, sources mounted read-only, and `strace` recording connect().
Only `nuguard sbom generate` and `nuguard analyze` were run.

**What was tested**
- NuGuard v0.9.15 (latest release, 2026-10-04; PyPI `nuguard==0.9.15`).
- 12 fabricated cases, a vulnerable and a safe version of each Phase 3
  pattern in Python (OpenAI SDK, Flask), plus TypeScript vulnerable versions
  of patterns 1 and 2. No key-like strings.
- 3 public repositories, pinned: `anthropics/claude-quickstarts@9ec32b9`
  (MIT), `openai/openai-quickstart-python@ec8890d` (MIT),
  `simonw/llm@cbeeb8f` (Apache-2.0).
- Every case and repository was run twice.
- Working files (cases, scripts, outputs) are in the session scratchpad
  under `nuguard-eval/`; they are not in the repository.

**Does it work offline, with no credentials?** Yes, with caveats.
- `sbom generate` works fully offline and made no network attempt at all.
- `analyze` completes offline. Its AI checks (NGA structural rules, ATLAS
  graph checks, bundled semgrep rules) need no network.
- Its dependency checks do need the network: its own OSV lookup
  (api.osv.dev), and trivy, which it runs with the vulnerability scanner on
  and, on claude-quickstarts, against a container image named in the repo
  (`debian:12-slim`).
- **Offline, these fail silently.** The log warns, but `tool_status` reports
  `osv: ok, 0 findings` and `trivy: ok, 0 findings`. That is "clean because
  nothing looked", which this project does not accept.
- Packaging defect: `pip install nuguard==0.9.15` fails at start-up with
  `No module named 'cryptography'`; it needs the `[secrets]` extra.
- `analyze` exits 1 on any high finding and 2 on critical (by design,
  `--fail-on high`).

**The five patterns**

| Pattern | Caught? | Detail |
|---|---|---|
| 1. User input in prompts without separation | **No** | `nuguard-llm-prompt-injection-fstring` can never match: its `pattern-not` is identical to its `pattern`, and it only looks at `.chat(...)`. Verified on code written exactly in the rule's shape. `nuguard-llm-direct-user-input` matches only a request field written inline in the call. Missed in Python and TypeScript. |
| 2. Model output to eval / shell / SQL / HTML | **Partly** | Python: SQL only (`nuguard-sql-injection-via-llm`). `nuguard-eval-on-llm-output` can never match: it requires `eval(x)` AND `exec(x)` at once (verified). No shell or HTML rule for Python. TypeScript: `eval` and `execSync` caught by generic JavaScript rules, not AI-specific. |
| 3. Agent tools with shell or file-write and no allowlist | **Partly** | No source rule. NGA-012 ("agent can invoke tool without human approval") fires on framework agents in claude-quickstarts, but not on a plain OpenAI `tools=` agent (case P3). It does not distinguish shell or file-write tools, or an allowlist; some tool names were parsing artefacts (`'  Aenter  '`, `' Create Rw Context'`). |
| 4. Secrets or system prompts sent to the model | **No** | Nothing fired on credentials or `os.environ` in prompts. |
| 5. Missing token or call limits | **Hidden by default** | `nuguard-no-output-length-limit` fires on a missing `max_tokens`, but at INFO, and `analyze` reports medium and above unless `--min-severity info` is passed. Unbounded loops, missing timeouts and retries are not checked. |

**False alarms on the safe examples:** none from the pattern rules. But every
case, safe or vulnerable, gets the same 3-6 posture findings (NGA-002 "no output
guardrail", NGA-006 "missing authentication", NGA-009 "no audit logging",
NGA-026 rate limiting, NGA-027 security headers, ATLAS-NC-001 "model API
version not pinned"). On real repositories these dominate:
- NGA-002 fires once per model name string, so `simonw/llm` gets 37 high
  findings from its catalogue of model names, and claude-quickstarts 22.
- claude-quickstarts gets 12 "critical" supply-chain findings because its
  bundled threat-intel indicator for a "Bun downloader" matches any
  `bun run` script.

**Stability across two identical runs**
- **SARIF:** byte-identical in 15 of 15 pairs. Rule IDs are stable
  (`nga-NGA-006`, `atlas-ATLAS-NC-001`). But every SARIF result's location
  is the generated `sbom.json`, not the source file and line, and the semgrep
  rule IDs embed the install path
  (`semgrep-opt.uv-tools.nuguard.lib.python3.12...nuguard-sql-injection-via-llm`).
- **JSON:** the findings and their source locations (`/src/app.py:29`) are
  identical, but every `finding_id` ends in a different random hash on each
  run (`-9078c0cf` then `-282bc81f`), so it cannot be a fingerprint.

**Cost**
- Image size: +419 MB uncompressed (+129 MB compressed; scanner image
  433 MB, evaluation image 562 MB, 2 MB of which is strace). It needs Python
  3.12, installed beside the image's 3.11.
- Runtime per repository: `sbom generate` 1.7-7.8 s, `analyze` 6-24 s.

**Telemetry and network**
- No telemetry or analytics library in the code paths of the two commands.
- The LLM stays off with no key configured (`--no-llm` was also passed).
- Semgrep is launched with `--metrics off --disable-version-check`.
- Every network attempt seen (on port 53, all refused) came from the OSV
  lookup and from trivy. `sbom generate` made none.

**Licences**
- NuGuard: Apache-2.0. Its LICENSE file is the short notice form, which
  GitHub does not detect, but it is a valid grant; PyPI declares Apache-2.0.
- Bundled rule data (four semgrep rule files, about 43 rules) is
  NuGuard-authored under the same Apache-2.0; nothing comes from the
  official semgrep-rules.
- The bundled threat-intel file is a list of known-malicious package names
  with sources cited.
- All 99 installed Python packages are permissive (MIT, Apache, BSD, PSF,
  MPL-2.0 x2; python-dateutil dual Apache/BSD; isoduration ISC).

**Recommendation: our own rules for the five patterns.** If anything, take
only NuGuard's AI inventory later, and only after a separate check.
- NuGuard reliably catches about 1 of the 5 patterns as a finding (SQL from
  model output). Two of the rules that should cover patterns 1 and 2 cannot
  fire. Pattern 5 is hidden by default, and patterns 3 and 4 have no source
  rule.
- Its default findings are posture checks that fire identically on safe and
  vulnerable code, and on real repositories they bury everything else.
- Its random finding IDs and SBOM-only SARIF locations would need a
  translation layer before our fingerprints could rest on them.
- Its offline dependency checks report "ok, 0" when they could not run.
- **NuGuard plus our own rules** would mean carrying 419 MB and a second
  Python, and filtering out most of its output, to keep one SQL rule we
  would write anyway.
- **NuGuard alone** misses most of what Phase 3 is for.
- **What is worth keeping:** `sbom generate` is good at what Phase 3 calls
  "detect AI use": it found agents, tools, models, prompts and MCP servers
  in every repository, offline. If that inventory turns out to be better
  than our own SDK-import detection, it could be added later as a
  source-only signal, with `analyze` never run.
- Apache-2.0 also lets us adapt NuGuard's working rule ideas (the SQL rule
  and the JavaScript `eval` and exec rules) into our own rules with
  attribution.

**Decision needed from you:** our own rules only (recommended); our own
rules plus NuGuard's `sbom generate` as an AI inventory (a later, separate
check); NuGuard plus our own rules; or NuGuard alone.

## Ground rules in force

- No push, no history rewrite, no cloud CLI, no real keys, no real repos.
- Postgres tests use the throwaway `vf-pg-test` container on port 55432
  (`VULNFRAMEWORK_TEST_DSN=postgres://vftest:vftest@localhost:55432/vftest?sslmode=disable`).
  Never the real-mode `vulnframework-pg` / volume `vulnframework-pgdata`.
- Gate after each phase: `go build ./... && go vet ./... && gofmt -l .`,
  `go test ./... -race` with the DSN, `npm run typecheck && npm test` in
  reportui, and the demo smoke test.

## Phase 0: finish in-flight work

Plan, from reading the code (not the docs):

| Item | State found | Action |
|---|---|---|
| 2: allowlisted and removed secrets | Done in `de01629`: proposals, vfctl confirm/reject/confirm-rotation, re-escalation, overview counts (Overview.tsx:191-206), report counts. History question answered: the sweep runs `gitleaks detect --no-git`, current files only (REAL-REPOS.md §9). | None |
| 3: fleet simulation | Done in `998dc38`: data fixed, `diag_test.go` deleted, fleet tests pass with the planner's tie-break reversed. | None |
| 4: allowlist warning | Partial: REAL-REPOS.md §9 says "keep the paths narrow" but its own example allowlists `_test\.go$` and `^testdata/`. | Rewrite the example to exact files and make the warning explicit |
| Fake keys | 145 gitleaks hits in the committed tree. Real key formats: fake AWS pair, `ghp_`, `glpat-`, `xoxb-`, a PEM header, and AWS's documented example ID, across 16 files. False matches: 120 Go commit hashes in recorded govulncheck URLs, 1 advisory text in recorded osv output. | Central `internal/testkeys` assembles values at run time; fixture files carry placeholders expanded by the test loader and by capture.sh |

Phase 0 result: **done**.
- Fake keys: `internal/testkeys` assembles every value at run time; recorded
  gitleaks output and `testdata/repos/go-api/config/settings.yaml` hold
  `@@TESTKEY:name@@` placeholders, expanded by the test fixture loader and by
  `capture.sh` (which conceals them again after capturing). Verified: the
  gitleaks capture round trip in the image reproduces the committed fixture,
  and gitleaks over the tracked tree finds only the 121 false matches.
- Item 4: REAL-REPOS.md example now allowlists two exact files, with a
  warning against folders and patterns.
- New `scripts/smoke.sh` (`--real` adds a real-mode sweep of the fabricated
  repos into a throwaway database, `vf-smoke-pg`, whose data is a temp folder).

## Demo track (bare-minimum non-local demo)

Goal: on a GCP VM, a read-only GitHub key discovers your repos, the sweep
downloads and scans them with no hand-cloning, and the results are browsable
over HTTPS behind a login, from your IP only.

- **D1, GitHub key and discovery (core of Phase 2).**
  - `gh.TokenClient`: fine-grained PAT, GET-only transport (any other method
    is refused in code), `/user` on connect (account, classic scopes, expiry
    header), `/user/repos` paging by Link header, rate-limit waits.
  - Each repo is included or skipped with a reason (archived, empty, fork,
    too large, collaborator not opted in, excluded by you).
  - `SyncFleet` reused through a narrower `gh.Lister` interface: new repos
    added, vanished or skipped ones archived, never deleted.
  - Download as a GitHub tarball (GET only, no git credential on disk), safe
    extraction, size cap, deleted after the scan; failure = coverage gap
    `download_failed`. Languages set from the downloaded tree's root files.
  - Migration 0016 `github_discovery`: connection metadata (never the token)
    and the discovered list; both backends.
  - `vfctl github connect|status|discover`, `vfctl repo exclude|include`;
    orchestrator `-github`; read-only `GET /v1/github` and a UI page.
  - Tests against a local fake GitHub server; end-to-end connect -> discover
    -> download -> sweep.
  - **D1 result: done.** Commit "Account mode: a read-only GitHub token
    discovers, downloads and scans". Tests: gh (token client, paging, rate
    limits, write refusal, classification), store (both backends), the
    orchestrator end to end against `internal/gh/ghfake`, hostile tarballs
    (path escapes, symlinks), the compiled `orchestrator -github` against
    Postgres, vfctl commands, `/v1/github`, and the UI page. Found and fixed
    in passing: a path-traversal bug in my own first tarball extractor
    (cleaning before stripping the top directory).
- **D2, deployable package and minimal login (Phase 4/5 minimum).**
  Production images (API + built UI behind Caddy; sweep image on top of the
  scanner image), docker compose, HTTPS with basic auth at Caddy which strips
  client-sent identity headers and sets its own, a daily sweep timer.
  Verified locally with compose: no login -> 401, forged header -> 401.
  - **D2 result: done.** `deploy/`: Dockerfile (api on distroless, web on
    Caddy with the built UI, sweep on the pinned scanner image), compose
    stack, Caddyfile, env.example, build.sh, sweep.sh, test-stack.sh.
    `deploy/test-stack.sh` passes locally: no login / wrong password /
    forged headers all 401; login gets the UI and API; the API publishes no
    port; client identity headers are overwritten (API logs
    principal=admin level=security_owner); a sweep through the real sweep
    image discovers a fake account (ghfake), downloads and scans both
    fabricated repos (116 and 77 findings), planted secret reported and
    never served. Found and fixed while testing: `SITE_ADDRESS=:443` gives
    Caddy no name to issue a certificate for (handshake fails), so the site
    address must be a hostname or IP; `sweep.sh` must not pass arguments to
    `compose run` (they replace the command).
- **D3, GCP as code (Phase 6 minimum).** Terraform: VM, static IP, firewall
  to your IP, IAP SSH, Secret Manager for the token and login hash, disk
  snapshots. `terraform fmt/validate` only, via the official image. DEPLOY.md
  with exact steps, costs, teardown.

  - **D3 result: done.** `deploy/terraform/gcp/` (VM, VPC, firewall to
    your IP, IAP-only SSH, egress limited to ports 80/443/53, service
    account reading exactly two secrets, static IP, daily snapshots,
    startup script that builds and starts the stack and installs a daily
    sweep timer) and `DEPLOY.md`. `terraform fmt -check` and `validate`
    pass (hashicorp/terraform:1.9.8 image, no cloud login); the startup
    template renders and passes `bash -n`; the generated systemd unit was
    checked. Not run: plan/apply (forbidden; yours). Also added
    `deploy/vfctl.sh` (vfctl against the stack) and made the stack test
    repeatable (database in tmpfs). Found while testing: a database volume
    keeps the password it was created with, so regenerating `.env` on a
    VM with data locks the stack out of its database (DEPLOY.md warns).

## Demo of 2026-10-13 (GCP-Sec, at your request, before this run)

Real-mode sweep S-000001 of GCP-Sec (complete, 99 findings) and
GCP-AutoPenTest. Two defects to prove fixed in Phase 1:
1. `golang.org/x/net` GO-2026-6611 shows fixed version `1.26.9`, the stdlib's.
   osv `firstFixed` takes the first event across every `affected[]` entry
   without matching the package (osv.go:212-236).
2. GCP-AutoPenTest (Python + TypeScript, registered as `go`) is `partial`
   with govulncheck and staticcheck "ok": Go tools succeed on a repo with no
   Go module, which reads as "looked and found nothing".

## Decisions I made

- **121 remaining gitleaks matches are kept.** 120 are Go commit hashes in
  googlesource URLs inside recorded govulncheck output, 1 is prose inside a
  published advisory in recorded osv output. None is a credential format
  GitHub push protection matches; rewriting recorded tool output would make
  the fixtures no longer real output.
- **AWS's documented example key ID is also assembled at run time,** although
  scanners allowlist it: the rule says no complete key-like string.
- **internal/model's test builds its value locally,** not from testkeys,
  because model may import nothing internal (layering test).
- **Re-triage command not built.** You were asked whether to add
  `vfctl finding retriage`; no answer, and the brief says no extras. It is in
  the handoff as a suggestion.
- **The GitHub token is never stored, not even encrypted.** It is read from
  `VULNFRAMEWORK_GITHUB_TOKEN` (or a hidden prompt) at the moment of use;
  only the account, token kind, scopes and expiry are recorded. On the VM it
  comes from Secret Manager. Safer than encrypting it into the database,
  whose key would have to live next to it.
- **Read-only is enforced in code:** the token client's transport refuses
  every method but GET/HEAD before the network. GitHub exposes no API to
  read a fine-grained token's permissions, so they cannot be verified; a
  classic token's scopes can, and write scopes are refused.
- **Repositories are downloaded as tarballs, not cloned.** GET-only, no git
  credential written to disk, no `.git` directory to scan. Symlinks are not
  recreated; paths escaping the tree fail the download (a gap, not a scan).
- **All-skipped is a decision, empty is a failure.** If GitHub lists
  repositories and every one is skipped with a reason, discovery archives
  the registry; if GitHub lists none while the registry holds some, it
  refuses (the existing empty-fleet guard).
- **Minimal login = HTTP basic auth at Caddy over HTTPS,** one login at the
  security-owner level, plus the firewall limited to your IP (D3). Not the
  full Phase 4 (OIDC, roles, TOTP); the Caddyfile says where an identity
  provider goes. Chosen because the API was already built to trust an
  authenticating proxy, so no API code changed.
- **Secrets never pass through Terraform.** You create the token and
  login-hash secrets with gcloud before apply; Terraform only grants the
  VM read access, so neither is in Terraform state. The database password
  is generated on the VM at first boot.
- **The firewall refuses 0.0.0.0/0,** so the default certificate is Caddy's
  own (browser warning); Let's Encrypt would need the internet let in.
- **Egress is limited by port, not destination:** naming destinations needs
  Cloud NGFW Enterprise, a paid add-on.
- **Test stacks leave their Docker volumes** (`vf-d2test_*`,
  `vf-stacktest_*`): the rules forbid deleting volumes. Remove them with
  `docker volume rm $(docker volume ls -q | grep -E '^vf-(d2test|stacktest)_')`.
- **The smoke test's throwaway database is deleted after each run.** It is
  created by the script, in a temp folder, never a named Docker volume; the
  "never delete databases" rule is about yours.

## Open problems

(none)

## Only you can do

For the cloud demo, in order (details and exact commands in DEPLOY.md):
1. Allow the two old fake keys via the unblock links, then
   `git push -u origin main real-repos` (or copy the code to the VM).
2. `gcloud auth login && gcloud auth application-default login`.
3. Create a fine-grained GitHub token: Contents read-only, Metadata
   read-only.
4. Create the secrets `vulnframework-github-token` and
   `vulnframework-login-hash` (DEPLOY.md step 4).
5. `terraform init && terraform plan && terraform apply` in
   `deploy/terraform/gcp` with your project ID and IP. This costs money
   (~US$4/day while running).
6. Wait for first boot, open the URL, run the first sweep.
7. Afterwards: `terraform destroy`, delete snapshots and secrets, revoke the
   token (DEPLOY.md "Tear it all down").

Housekeeping on this Mac: the real-mode demo app (`./run.sh --real`, ports
8080/5173) is still running from earlier; and test volumes `vf-d2test_*`,
`vf-stacktest_*` can be removed when you like.

Earlier items:

- Push `real-repos` and `main` (origin is set to
  https://github.com/pobtampal/vulnerabilityAI.git). The fake keys are gone
  from the tree, but OLD commits still contain them, so push protection will
  still block until you allow them via the two unblock URLs from the first
  attempt (or rewrite history yourself). First commit with the pair:
  `d7c213b`; also in `1620f74`, `27016ab`, `de01629`, `9badcb0`.
