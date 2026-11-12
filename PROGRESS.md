# PROGRESS

Unattended run on `real-repos`, started 2026-10-13. If a session restarts,
read this file first and resume from "Next".

## Current

- **Priority changed by you (2026-10-13):** build only what a bare-minimum
  NON-LOCAL demo needs, before resuming Phase 1. See "Demo track" below.
- **Phase:** demo track complete (D1-D3). Waiting on you for the cloud steps.
- **Decided 2026-10-22:** D12 approved (points 1-5; legal review of GitLab's
  Java/Scala ports before release). Order: "Scan now" first, then Phase 1.
- **Decided 2026-10-20:** Phase 3 uses our own rules (option 2, D13);
  NuGuard's `sbom generate` may be added later as an inventory signal only,
  after a separate check. Evaluation image removed.
- **Done 2026-10-22:** "start a scan from the web app" (design below; commits
  c067d4d S1 queue, eaecf6a S2 worker, aa8c71e S3 API and security, b8fbf1e
  S4 interface/vfctl/deployment, 7f55adc ordering fix, and the docs commit).
  Verified:
  - unit and integration tests on both backends;
  - an end-to-end test through the compiled worker against the fake GitHub
    (finished, timed_out as a gap, refused, interrupted);
  - `deploy/test-stack.sh` through Caddy and the login (cross-site, missing
    CSRF and no login refused; a click scanned and finished; access log
    records who and which repository; stopping the worker removes it);
  - `scripts/smoke.sh --real` (the local worker over clones).

  Found and fixed on the way: scan results were ordered by run_id as text,
  so a sweep run sorted above a later manual run on both backends.
- **Done 2026-10-22, at your request:**
  - **History rewrite:** the fake keys were removed from git history and
    both branches pushed; the old history is kept locally as
    `backup/*-pre-rewrite`.
  - **Scan now on every row:** a "Scan now" button on each row of the
    repositories table (014fb06).
  - **A description on every finding:** the scanner's own text, credited to
    the tool; otherwise one built from the record, marked "derived". Shown
    under the identifier in the findings table and at the top of the finding
    page, and included in the CSV export. Verified by unit tests on both
    backends, the API and UI tests, and `scripts/smoke.sh --real`, where 198
    of 198 real findings carried the scanner's words.
- **Done 2026-10-27, at your request:**
  - **Settings file:** the local deployment stack's settings file (it held
    the account-mode settings) was lost when the temporary folder was
    cleared. It was rebuilt from the stack's own containers at
    `~/.config/vulnframework/demo/env`, outside the repository, mode 600;
    compose reads it as identical to what the containers hold. The login
    password's plain text was never stored, so it is lost: reset it as below.
  - **Docs:** REAL-REPOS.md section 10 explains keeping one database across
    sessions.
  - **Backups:** `scripts/db.sh backup|list|restore` (both the real-mode
    database and the stack), tested on a throwaway database: backup,
    restore, undo, corrupt-file refusal, worker-running refusal, start and
    stop. First backups taken: real mode, 140 findings; the stack, 165.
  - **`.gitignore`:** now also catches env files and dumps left in the
    repository by mistake.
- **Decided by you (2026-10-27):** the account-mode stack
  (https://localhost:18443, compose project `vf-demo`) is the main history.
  Real mode is for quick local trials; its backup is kept read-only in
  `~/.local/share/vulnframework/backups/archive/`. Noted in REAL-REPOS.md.
  - **New login password** for the stack, set with the new
    `deploy/login.sh reset`: random, kept in
    `~/.config/vulnframework/demo/login-password` (mode 600), never printed.
  - **Stack upgraded:** images rebuilt from the current code and the stack
    recreated. The database migrated from schema 16 to 17; 165 findings
    before and after (database and API). A backup taken just before,
    `demo-20261027-165847.dump`, was not needed. The images the old
    containers ran had already been pruned, so the fallback was the backup.
  - **Trend chart:** "Scan all included repositories" (and
    `vfctl scan enqueue -all`) now runs as a sweep, so it is a point on the
    trend; a single repository's scan stays a manual run, off it (a5e62f6).
    The chart is drawn in the design system's colours and follows dark
    mode; scanner changes are a ring and partial runs a solid dot, so they
    differ by shape as well as colour. Tests on both backends, UI tests.
- **Done 2026-11-11 (evening), at your request: NuGuard live in real mode,
  committed and reproducible.** Nothing pushed or merged.
  - **NuGuard commits** (`nuguard/nuguard`, branch
    `feature/remote-scan-service` from `develop` @ `ad7873ee`):
    - `96f03c63` P1 and P5: no-false-clean tool status, finding identity.
      One commit, because the two share `static_analyzer.py` hunk by hunk;
    - `c1cfba0c` P2: Semgrep rules that can fire;
    - `0d00e7df` P3 and P4: token without URL embedding, clone safety, and
      the **proxy fix**. Under a host policy, git keeps the `*_PROXY` and CA
      variables and still drops `GH_TOKEN`, `GITHUB_TOKEN` and `NUGUARD_*`;
      tested. The tree-API client keeps httpx `trust_env`; tested;
    - `04ad59d2` P6: packaging;
    - `b4c91ca2` the service;
    - `776b04cd` docs, including `remote-api.md` (proxy, native run with
      `NUGUARD_TOOLS_JSON` and `NUGUARD_IMAGE_DIGEST`) and
      `GATEWAY-DESIGN.md`, which the spec cites.
    - `CONTEXT.md` (a dated orientation note) and `.DS_Store` files left
      untracked. `.ng-src.tgz` deleted.
  - **NuGuard checks:**
    - ruff: no new errors. About 500 already exist on `develop`; one new
      import-order error was fixed;
    - mypy: clean (857 files);
    - contracts, service, analysis and sbom: 549 passed, 2 skipped;
    - full suite: 3449 passed, 66 skipped, 8 failed. The 8 failures are in
      pentest, and also fail on `develop` (macOS temporary folder is a
      symlink).
    - Found on the way: **Semgrep cannot share NuGuard's environment.** It
      fails on start-up over an OpenTelemetry version clash with NuGuard's
      lockfile, so every scan would report `semgrep: failed`. The image
      already isolates it; `nuguard-local.sh` now does too.
  - **vulnerabilityAI commits** (`feature/real-mode-nuguard`, from
    `b707be8`):
    - `6be7ec0` Go and UI: scan each clone's GitHub origin;
    - `bb0ad87` scripts: `run.sh --nuguard`, `nuguard-local.sh` as built
      earlier today, and the `launch.sh` credential scrub;
    - `a02d828` docs;
    - `aab16bf` `nuguard-local.sh`: lockfile with `uv`, Semgrep in its own
      environment, `git:<commit>` as the image digest, `tools.json`, a
      fuller `status`;
    - `4584c36` Ctrl-C clean-up in plain `--real`;
    - `213a154` the briefs in `nuguard-integration/`;
    - this documentation commit.
    - Archives `.vf-src.tgz`, `.b707be8.tgz` and `.rmn.tgz` deleted.
  - **vulnerabilityAI checks:**
    - `go vet` clean, and `go test ./...` on memory and on Postgres (a
      throwaway container, since removed);
    - UI typecheck, and 162 UI tests;
    - `scripts/test-real-cmdlines.sh`: the command lines are unchanged;
    - `smoke.sh --real` and `--real --nuguard-fake`: OK;
    - Ctrl-C in plain `--real`, on a throwaway database: the worker
      container, the API and the dev server all stopped.
  - **`uv` 0.13.7** was installed with Homebrew, with your approval.
  - **Backups:**
    - `~/.local/share/vulnframework/backups/real-20261111-160930.dump`,
      taken by hand (140 findings);
    - `real-20261111-161302.dump`, taken by `run.sh` before migrating schema
      17 to 19.
  - **Clones (step 5):**

    | Repository | GitHub origin | HEAD pushed | Dirty | Visibility | NuGuard will |
    |---|---|---|---|---|---|
    | pobtampal/GCP-AutoPenTest | github.com/pobtampal/GCP-AutoPenTest | yes, `bad9378` = `main` | no | public | scan |
    | pobtampal/GCP-Sec | github.com/pobtampal/GCP-Sec | yes, `912171d` = `main` | no | public | scan |

    No unregistered clones are in `~/clones`. No token was needed or used.
  - **Live sweep `S-000004`** (`./run.sh --real --nuguard ~/clones`):
    - NuGuard 0.9.15, built from the lockfile, source
      `git:776b04cd39ba717cf6f1efbf0ba6d4d9ef64d051`, clean, on
      127.0.0.1:8090 only. Semgrep 1.172.0 is reported by the service.
    - `GET /v1/nuguard`: configured, reachable, `version_ok`, fresh.
    - **GCP-Sec:** complete. `nuguard`, `nga-rules`, `atlas` and `semgrep`
      all ok. AI components measured: agent 1, model 1, privilege 4,
      deployment 8 and others; provider anthropic. Image
      `git:776b04cd…`, commit `912171d`.
    - **GCP-AutoPenTest:** partial. All four NuGuard parts ok, but `gosec`
      ("parsing report: unexpected end of JSON input") and `osv-scanner`
      failed. That is the existing escalation (`normalise_failed`, 4
      sweeps). AI components measured: agent 1, tool 1, 10 API endpoints
      and others. Image `git:776b04cd…`, commit `bad9378`.
    - `effective_nuguard` is recorded for both. The per-repository versions,
      including `nuguard/image`, go to finding provenance and the
      AI-components record, not to the run's `tool_versions`.
    - **NuGuard findings: none** (`found_by=nuguard`, in both scopes), with
      every NuGuard part ok. Posture findings are off by default.
  - **Not caused by NuGuard, but visible in this sweep:** on GCP-Sec, 80
    findings went VERIFIED to REGRESSED and 38 went to VERIFIED. All the
    VERIFIED-to-REGRESSED moves had been made by `M-000002` (22 October),
    whose trivy reported the same CVEs under CVE-only identities with no
    `go.mod` location. Those identities existed only in that run.
    `S-000004` restored the usual identities. The history now shows 80
    "regressions" that are artefacts. The cause in `M-000002` is not known.
  - **Controls, on GCP-Sec:**
    - NuGuard off (audit #1), then Scan now: `M-000003`, NuGuard not
      requested ("off for this repository"), no state changes;
    - restored to inherit (audit #2), then Scan now: `M-000004`, NuGuard and
      all its parts ok.
    - There were no NuGuard findings, so "kept open and flagged not
      re-observed" could not be exercised live. Unit and stack tests cover
      it.
  - **Restart test, on GCP-AutoPenTest:**
    - NuGuard stopped, then Scan now: `M-000005` partial, with `nuguard`
      failed, so a gap, not a clean result.
    - The status card went on showing "reachable" until the worker's next
      5-minute check (00:28:31Z), then showed unreachable.
    - NuGuard started: the card recovered in 18 seconds. `M-000006` ran
      NuGuard with every part ok.
    - The four manual scans caused no state changes.
  - **Interface:**
    - The layout probe uses fixtures only, so it cannot point at a running
      server.
    - Instead, headless Chrome loaded the running app: the NuGuard page,
      both repository pages (AI components panel) and a finding page all
      rendered without error text.
    - There is no NuGuard finding page to check.
  - **Stopped:** everything this session started, by Ctrl-C on the run and
    by name for the test containers. The containers and volumes match the
    starting state. `vf-demo`, `vf-pg-test` and `nuguard-service` were not
    touched.
  - **Not verified:**
    - a private repository with a token;
    - a real proxy;
    - a NuGuard finding end to end: none exist in these repositories;
    - a large repository's time limits;
    - Python repositories.
- **Built 2026-11-11, at your request: NuGuard in real mode**
  (branch `feature/real-mode-nuguard`, from `feature/nuguard-ui-controls`;
  committed later the same day, see above). `./run.sh --real --nuguard ~/clones` runs NuGuard on
  this Mac from the sibling checkout (`scripts/nuguard-local.sh`). It needs
  no NuGuard image. See REAL-REPOS.md §6a.
  - **Reachability experiment** (Docker Desktop 4.86.0, engine 29.7.2): a
    server bound only to the Mac's `127.0.0.1` **is** reachable from the
    scanner container at `host.docker.internal`, with or without
    `--add-host`. The NuGuard client still refuses plain http to that name,
    so option 1 was chosen: a loopback bridge, `cmd/loopbridge`, built and
    mounted like the orchestrator. It listens on the container's
    `127.0.0.1` and forwards to `host.docker.internal`. The client's
    loopback rule is unchanged and there is no new flag.
  - **The repository NuGuard scans** is the clone's github.com `origin`,
    read from `.git/config` (`githubRepoFromGitConfig`, with table tests).
    It is carried on `RunOpts.LocalClone`, filled by the `LocalDispatcher`
    only when NuGuard is configured.
    - With no GitHub origin: NuGuard not requested, "no GitHub origin;
      NuGuard needs the repository on GitHub".
    - With uncommitted changes, or a state that cannot be checked
      (`git status` in the container, read-only): every NuGuard finding is
      annotated "NuGuard scanned the committed state…". The note is shown
      on the finding page, and it clears on a clean rescan.
    - `ref_not_found` from a clone: gap `commit_not_on_github`, owner repo.
  - **Found and fixed:**
    - **The one-shot sweep ignored the stored NuGuard settings.** It called
      `Sweep` without resolving them, so the start-of-run sweep and the
      daily timer sweep would have scanned a repository switched off in
      the interface. It now resolves them as the worker does
      (`ResolveSweepNuGuard`). Without NuGuard configured, nothing changes.
    - **`run.sh`'s stop trap never ran.** It ends with `exec npm run dev`,
      which replaces the shell, so Ctrl-C left the scan worker container
      running. Fixed **only for `--nuguard`** (no exec there), so that
      real mode without it is exactly as before. `stop` now also ends the
      server `go run` leaves behind.
    - **`real_pg_up` returned during Postgres's first-start init**, so the
      migration failed about half the time on a new database (seen in the
      smoke test, 2 of 3 runs). It now waits for readiness over TCP.
      `real_migrate` still hides a failure behind its `| tail` (existing
      behaviour, left as it is).
  - **The API server and the interface's dev server never get a
    credential** (asked for after the first report). They start through
    `scripts/launch.sh`, which removes `VULNFRAMEWORK_NUGUARD_API_KEY` and
    `VULNFRAMEWORK_GITHUB_TOKEN` from their environment in every mode;
    neither reads them. The scan containers still get theirs by name.
    `scripts/test-real-cmdlines.sh` runs the launchers with both exported
    and recorders as `go` and `npm`, and fails if either arrives (checked to
    fail with the removal taken out). A live demo run with both exported
    showed neither in the running servers' environments.
  - **Backup before migrating:** `run.sh --real`, with or without
    `--nuguard`, runs `scripts/db.sh backup` first when the database's
    schema is older than the binary's. Checked on a throwaway database:
    - a new database: no backup;
    - a current one: no backup;
    - schema 18 under this schema-19 binary: backed up, with its path
      printed.
  - **Verified:**
    - `go vet`, and `go test ./...` on both backends;
    - `-race` on scan, adapters, orchestrator, api, nuguard,
      cmd/orchestrator and cmd/loopbridge;
    - UI typecheck and 162 tests;
    - `scripts/test-real-cmdlines.sh`: the container command lines without
      `--nuguard` match those recorded from the unchanged `real.sh`; the
      key and token are passed by name only;
    - `scripts/smoke.sh --real` green 3 times in a row, with the same
      output as before;
    - `scripts/smoke.sh --real --nuguard-fake` green.
  - **Real trial** with the real NuGuard 0.9.15 from the sibling checkout:
    - **Setup:** the public `openai/openai-quickstart-node` at `6e6e034`,
      registered as `trial/openai-quickstart-node`, so the origin decided
      the repository. It used a throwaway database (`vf-trial-pg`, since
      removed).
    - **The sweep:** complete, with `nuguard/nga-rules`, `nuguard/atlas`
      and `nuguard/semgrep` all ok, and the AI inventory recorded (4
      models, an agent, a prompt and a tool; providers openai and
      anthropic). NuGuard reported no findings for this repository.
    - **Scan now:** worked through the worker's bridge, and the status page
      showed NuGuard reachable at version 0.9.15.
    - **Ctrl-C:** stopped the worker, the API and, when the run had started
      it, NuGuard.
  - **Not verified:**
    - a private repository with a token;
    - a proxy;
    - a large repository's time limits;
    - Python repositories (the adapter covers Go and JavaScript);
    - `uv`, which was not installed then: the environment was built with
      pip from Python 3.12 (since rebuilt from the lockfile, see above).
  - **Observed once:** trivy failed to parse its own report on one of four
    repositories scanned at once in the smoke test ("unexpected end of JSON
    input"). It did not recur in four later runs.
  - **The NuGuard checkout is uncommitted work** (`ad7873ee` plus local
    changes, including the whole service). `status` says so.
  - **The sibling's own `.venv` does not import NuGuard:** macOS had marked
    its `.pth` files hidden, and Python 3.12 skips hidden ones. The script
    builds a separate environment and clears that flag, and leaves the
    sibling's `.venv` alone.
- **Built 2026-11-06, at your request: NuGuard controls in the interface**
  (branch `feature/nuguard-ui-controls`, from `feature/nuguard-adapter`).
  - **Committed:** the adapter work as `9042e4e` on `feature/nuguard-adapter`
    (the new brief asked for it to be committed first), and tool-aware
    reconciliation alone as `a71d69e`, as the brief asked. Everything else is
    **not committed**.
  - **What:**
    - **Tool-aware reconciliation** (VM-F-160/161): an absent finding
      verifies only if every source that observed it (adapter, or
      `nuguard/<tool>`) ran ok in that scan. Otherwise it keeps its state,
      flagged not re-observed and linked to the run. The same code covers
      every adapter.
    - **Resolution:** one pure function, `nuguardopt.ResolveNuGuardOptions`
      (scan request → repository → fleet → worker defaults, then clipped to
      the ceiling). The worker uses it at claim time, and the API's preview
      uses it through `store.ResolveNuGuard`.
    - **Ceiling flags:** `-nuguard-allow-tools`, `-nuguard-allow-posture`,
      `-nuguard-max-timeout` and `-nuguard-sbom-max-bytes`. The worker
      refuses to start with a default above the ceiling.
    - **The scan worker:**
      - publishes NuGuard's status every 5 minutes (every 30 seconds while
        unreachable);
      - skips NuGuard when it is off, recording it as not requested;
      - records the effective options and clip notes on every repository
        scan;
      - keeps the AI-SBOM when a scan asks, under a size cap.
    - **Migration 0019** (both backends): the settings, the overrides, an
      audit table, the status row, `scan_requests.nuguard`,
      `effective_nuguard` and `tools_not_requested` on scan results, and
      `ai_sbom`.
    - **API:**
      - `GET /v1/nuguard`, `PUT /v1/nuguard/settings`,
        `GET /v1/nuguard/audit`, `GET /v1/nuguard/preview`;
      - `GET` and `PUT /v1/repos/{repo}/nuguard`, and
        `GET /v1/repos/{repo}/ai-sbom/{run_id}`;
      - `nuguard` options on both scan requests, and `found_by` on findings.
    - **Interface:**
      - the "AI scanning (NuGuard)" page;
      - the repository section, the scanned commit and the AI-SBOM
        download;
      - scan options with a preview;
      - "Found by", the NuGuard section on a finding, and "not requested" on
        Coverage and the run page;
      - requirements VM-UI-F-1201..1212 in the UI spec.
  - **Verified:**
    - `go vet` and `go test ./...` on both backends;
    - `-race` on store, api, orchestrator, scan, nuguard and nuguardopt;
    - the UI typecheck and 161 tests, and `npm run probe:layout`;
    - `deploy/test-stack.sh` (STACK OK), built under the tag
      `nuguard-ui-test`. It covers: NuGuard off for a repository leaves its
      finding unchanged and flagged; an engineer is read-only and refused
      (403); fewer tools are recorded on the run;
    - `scripts/smoke.sh --real` (SMOKE OK);
    - the no-NuGuard worker golden still matches.
  - **Not verified:**
    - a real NuGuard service and image;
    - a live GitHub run;
    - Docker beyond the stack test above.
- **Built 2026-11-03, at your request: NuGuard as an opt-in remote adapter**
  (branch `feature/nuguard-adapter`, committed 2026-11-06 as `9042e4e`).
  - **What:**
    - a client for NuGuard's Remote Scan API (`internal/nuguard`) and a
      fake service (`nuguardfake`);
    - the adapter: code findings with our own fingerprints, each lost
      NuGuard tool its own gap, the AI inventory as a signal;
    - every adapter now scans one recorded commit (resolved before the
      download, or read from `.git`);
    - migration 0018 (`commit_sha`, `ai_inventory`), on both backends;
    - an "AI components detected" panel on the repository page;
    - flags on both commands and a compose sidecar.
  - **Verified:**
    - the Go suite on both backends, `-race` on scan, nuguard and
      orchestrator, and the 138 UI tests with the typecheck;
    - `scripts/smoke.sh` (demo);
    - `deploy/test-stack.sh` with a fake NuGuard in the sidecar's place:
      code finding, partial as a gap, down as a gap;
    - NuGuard's `openapi.json` enums, checked in both directions.
  - **Proof that NuGuard off changes nothing:** a golden captured before
    any change, `testdata/worker/no-nuguard.golden.json`, still matches.
  - **Not verified:**
    - a real NuGuard service: its service code is uncommitted upstream, and
      its image has never been built;
    - a live GitHub run;
    - the opt-in end-to-end test (`VF_NUGUARD_E2E=1`).
  - **Awaiting you:** the D13 amendment in DECISIONS-NEEDED.md.
- **Queued by you (2026-10-27):** after Phase 1 is committed, design
  accounts, login and workspaces (ACCOUNTS-DESIGN.md plus open questions in
  DECISIONS-NEEDED.md), then stop for review. No code for it until then.
- **Next:** Phase 1 (mixed-language scanning), unblocked (D12 decided).

## Start a scan from the web app (designed and built 2026-10-22)

Built before Phase 1, at your direction. As built, it follows this design
except for two changes:
- the worker also rediscovers the account (at start-up and every 24 hours),
  since the timer no longer holds the token;
- `ScanRefusal` is shared by the API, vfctl and the worker.

**A correction to the brief.** There are no existing Origin/Sec-Fetch checks
in the API or the Caddy front door. The only ones are in the local
development proxy (`reportui/scripts/local-auth.ts:104-120`), which decides
whether to add identity headers on a developer's machine. The API's only
write endpoint so far is the GitHub webhook, which is verified by signature.
This feature therefore adds cross-site protection in the API itself.

**Queue (migration 0017, both backends)**

```
scan_requests
  id            TEXT PK                -- sr_<time-ordered>
  repo          TEXT FK repos
  batch_id      TEXT                   -- one click on "scan all", or one timer firing
  source        TEXT CHECK IN (web, vfctl, timer)
  requested_by  TEXT                   -- the principal, or "timer"
  requested_at  TIMESTAMPTZ
  status        TEXT CHECK IN (queued, running, finished, failed, timed_out,
                               interrupted, refused)
  reason        TEXT                   -- for failed, timed_out, interrupted, refused
  run_id        TEXT FK runs           -- the run that scanned it
  worker_id     TEXT, started_at, heartbeat_at, finished_at TIMESTAMPTZ
  retry_of      TEXT FK scan_requests  -- a retry is a new request pointing at the old one
UNIQUE (repo) WHERE status IN ('queued','running')   -- duplicates merge
```

- **Merging duplicates:** a request for a repository with a queued or
  running request returns that request (HTTP 200, `merged: true`). The
  database enforces it with the partial unique index, so two API replicas
  cannot race.
- **Rate limit:** per principal, at most N requests a minute (default 10,
  `-scan-rate`), counted in `scan_requests`, so it survives an API restart.
  "Scan all" counts as one request.

**Worker**
- `orchestrator -worker` runs in the sweep image as a long-running compose
  service, `scanworker`.
- **It claims one request at a time** (`FOR UPDATE SKIP LOCKED` in Postgres,
  a mutex in memory), marks it running with a heartbeat, and checks the
  registry. An archived, excluded or unregistered repository is refused with
  the reason.
- **It scans through the existing path:** `Orchestrator.Sweep` over one
  repository, with the account-mode `DownloadDispatcher` (or the clones
  dispatcher in local real mode), then the same post-sweep pass. Results
  are recorded exactly as a sweep records them. One request is one run of
  kind `manual`; a batch ("Scan all included repositories" from the
  interface or vfctl, or the timer's) is one run of kind `sweep`. (Until
  2026-10-27 only the timer's batch was a sweep, so the trend had no points
  locally.)
- **Time limit:** `-scan-timeout` (default 15 minutes) per repository. A
  timeout records the scan as failed with the coverage-gap cause
  `scan_timed_out`, owner platform, so coverage counts it as a gap, never
  as clean. The request becomes `timed_out`.
- **Restarts:** at start-up, any `running` request whose heartbeat is older
  than 2 minutes becomes `interrupted`, reason "worker restarted during the
  scan". The interface offers Retry, which creates a new request with
  `retry_of` set. Nothing is silently lost, and nothing is marked done
  without a recorded run.
- **The daily timer** stops running a sweep itself. It enqueues a batch of
  every included repository (`vfctl scan enqueue --all --source timer`,
  which needs no token), and the worker drains it. One queue, one code path.

**Token handling**
- **On the VM,** the worker's systemd unit reads the token from Secret
  Manager at start-up (as the sweep unit does now) and passes it to the
  container by name.
- **Locally,** `deploy/scanworker.sh` reads `VULNFRAMEWORK_GITHUB_TOKEN` at
  start-up, like `sweep.sh`.
- **Either way, the token stays in the worker process's environment for as
  long as it runs.** That is the cost of a worker that can scan on demand.
  The API never sees it. Stopping the worker removes it:
  `docker compose stop scanworker`, or `systemctl stop vulnframework-scanworker`.
- **In `./run.sh --real`** (clones on disk), the worker scans the clones and
  needs no token.

**API (the first write actions in the interface)**
- `POST /v1/scans`, body `{"repo": "owner/name"}` only. Unknown fields are
  refused (strict decoding), and the name is validated against the registry.
  Returns the request (201, or 200 when merged).
- `POST /v1/scans/all`, no body: one batch over every included repository.
  This is a second endpoint, because "scan all" has no repository name. It
  is flagged here because the brief asked for "a repo name only".
- `GET /v1/scans?repo=&limit=`: request statuses, with links to the run.
- **Checks on both POSTs, in order:**
  1. the principal is determined and at `security_owner` level, otherwise
     403;
  2. the cross-site check: refused unless `Sec-Fetch-Site` is
     `same-origin`, or absent with an `Origin` matching the configured
     public origin; a cross-site request gets 403;
  3. the CSRF token: `X-CSRF-Token` must equal an HMAC of the principal and
     an hourly time window, issued by `GET /v1/csrf`. A custom header also
     forces a CORS preflight, which the API never answers, so no other site
     can send it;
  4. the rate limit, then queue or merge.
- **Audit:** each accepted, merged or refused request is a `scan_requests`
  row (who, which repository, when, outcome) and an access-log line.
  Refusals are logged too, as the access log does now.

**Interface**
- **A repository page** gets a Scan now button (security owners only;
  others see why it is disabled) and a status line. The status is queued,
  running (with the time it started), finished (linking to the run and the
  repository's findings), failed (with the reason), timed out, or
  interrupted (with Retry).
- **The repositories list** gets "Scan all included repositories" and a
  small queue panel. Both poll every 5 seconds while anything is queued or
  running.
- `vfctl scan request REPO`, `vfctl scan list` and
  `vfctl scan enqueue --all` give the same from the terminal.

**Tests (both backends):**
- queueing, merging duplicates, refusing excluded repositories;
- timeout becomes a gap; interrupted becomes retryable;
- role refusal, CSRF refusal, cross-site refusal, unknown fields refused,
  rate limit;
- the timer batch;
- end to end: a POST through the API, then the compiled worker downloads
  from `ghfake`, scans and records, and the request becomes finished with
  its run.

**Documentation:** the usage sections of REAL-REPOS.md and DEPLOY.md.

Estimate: about 1.5-2 weeks.

## Plan order (updated 2026-10-22)

AI-assisted fixing is now in scope as Phase 8, under the security review's
requirements (`REMEDIATION-DESIGN.md`; plain language in `NOW-VS-LATER.md`;
the review's questions answered in `SECURITY-READINESS.md`; decisions in
DECISIONS-NEEDED D14).

| Order | Phase | Notes |
|---|---|---|
| 1 | Phase 1: scan any language | **In progress next.** 8a needs it: proposals are per component |
| 2 | Phase 3: AI prompt vulnerability scanning | Our own rules (D13) |
| 2 | **Phase 8a: validated fix proposals** | Alongside Phase 3. Database only, no GitHub writes. Go and JavaScript/TypeScript toolchains first; about 10-13 weeks. Needs the Linux sandbox proof (D2) before running on real repositories |
| 3 | Phase 4: secure the service | Identity provider, roles (adds `fix_approver`), writable API |
| 4 | **Phase 8b: approval and publication** | After Phase 4. Separate publisher with its own write credential; merge stays in GitHub. About 4-5 weeks. Needs D4 (App with write permission), D14 and a signed risk acceptance before production use |
| 5 | Phase 5: scheduled, unattended scanning | |
| 6 | Phase 6: cloud VM | As code already (demo track D3) |
| 7 | Phase 7: pilot and go-live | Includes calibrating 8a's confidence from reviewer decisions |
| later | **Phase 8c: limited autonomy** | Only with its own formal approval, inside RD §10 |

Gap analysis highlights (RD §2):
- Nothing merges.
- The original worker pushes and opens pull requests with no human
  approval.
- The real Go toolchain, the agent harness, the GitHub write client and the
  pull-request closer are built but never called from any program.
- A latent write token sits in the clone's `.git/config` within the agent's
  reach.
- The rescan does not look for new findings.
- No confidence scores, approver role or review page exist.

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

**Decided (2026-10-20): option 2.** Our own rules now; NuGuard's
`sbom generate` may be added later as an inventory signal only, after a
separate check. Rules that adapt NuGuard's ideas credit it per Apache-2.0.
Recorded as DECISIONS-NEEDED D13.

### Draft upstream issue (not posted)

For github.com/NuGuardAI/nuguard. Two rules in
`nuguard/analysis/plugins/semgrep_rules/ai-security.yaml`, v0.9.15
(commit `fa3583c`), can never produce a finding.

> **Title:** Two semgrep rules in ai-security.yaml can never match
> (prompt-injection-fstring, eval-on-llm-output)
>
> **1. `nuguard-llm-prompt-injection-fstring` (line 7): exclusion equals the
> match.** The rule's `pattern-not` is the same pattern as its `pattern`, so
> every match is removed and the rule never fires:
>
> ```yaml
> patterns:
>   - pattern: |
>       $LLM.chat(..., messages=[..., {"role": "user", "content": f"...{$INPUT}..."}], ...)
>   - pattern-not: |
>       $LLM.chat(..., messages=[..., {"role": "user", "content": f"...{$INPUT}..."}], ...)
> ```
>
> Reproduce: `semgrep scan --config ai-security.yaml` on
>
> ```python
> def fstring_case(llm, user):
>     return llm.chat(messages=[{"role": "user", "content": f"Summarise {user}"}])
> ```
>
> No finding. Expected: one. Suggested fix: drop the `pattern-not`, or make
> it a `pattern-not-inside` for the validated case the comment describes.
> Separately, the pattern only covers `$LLM.chat(...)`, not
> `client.chat.completions.create(...)` or an f-string assigned to a
> variable first, which is how most code builds prompts.
>
> **2. `nuguard-eval-on-llm-output` (line 78): needs `eval` and `exec` at
> once.** Two `pattern:` entries under `patterns:` are a conjunction, so a
> match would have to be both `eval($X)` and `exec($X)`:
>
> ```yaml
> patterns:
>   - pattern: eval($LLM_OUTPUT)
>   - pattern: exec($LLM_OUTPUT)
> ```
>
> Reproduce on `def f(llm_output): return eval(llm_output)` and
> `def g(llm_output): exec(llm_output)`. No finding for either. Suggested
> fix: `pattern-either`. As written it would then flag any `eval`; tying it
> to model output (taint mode from the LLM call's return value) would make it
> say what its message says.
>
> Found with semgrep 1.177.0, offline. Thank you for NuGuard.

Other things seen, separate issues if wanted: `pip install nuguard==0.9.15`
fails at start-up without the `[secrets]` extra (`cryptography` is imported
but not a base dependency); offline, `analyze` reports `osv` and `trivy` as
`ok` with 0 findings when their lookups failed; `finding_id` hashes change
on every run.

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
| 3: fleet simulation | Done in `998dc38`: data fixed, `diag_test.go` deleted. The fleet tests pass with the planner unchanged; as a check, they also passed with the final name tie-break flipped on a scratch copy (not committed). The fairness fix from `21960c9` is intact: verified 2026-10-19 (no change to `ByCoverageStaleness` since; `TestRotationIsEvenWhenTheBudgetDoesNotDivideTheFleet` passes on memory and Postgres, and fails at 5-10 scans when the fairness step is removed). | None |
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

- **Settings and backups live outside the repository:** settings in
  `~/.config/vulnframework/`, backups in `~/.local/share/vulnframework/backups/`,
  both readable only by you. The repository's `.gitignore` gains patterns as
  a second line of defence only.
- **A restore swaps databases by renaming and never overwrites.** The
  replaced database is kept until you drop it. This costs disk space; it
  buys an undo for the one command that could otherwise lose history.
- **The stack's login was not reset on my own initiative.** Resetting means
  recreating its web container, and the stack had been stopped on purpose;
  the command is in the handoff.
- **Finding descriptions are the scanner's words, never edited.** Our
  fallback is labelled "derived", so it is never passed off as a tool's text.
  A description that matches a credential pattern is dropped whole, not
  partly scrubbed, because a semgrep message can quote the matched line.
  Descriptions are capped at 1000 characters. They are withheld from
  restricted findings along with the rest of the detail.
- **Existing findings get scanner text on their next scan.** The text is
  carried on each observation, and stored findings show the derived fallback
  until they are seen again. There is no backfill from the stored raw output:
  a rescan is the faithful source.
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
- **Every "scan all" batch is a sweep, not only the web's** (2026-10-27):
  `vfctl scan enqueue -all` asks for the same thing as the button, so the
  rule is "a batch is a sweep" rather than a list of sources. Side effect,
  intended: the Coverage page, which reads sweep runs, now counts them too.
- **NuGuard choices** (2026-11-03; deviations from the brief are also in
  the hand-over):
  - **Sidecar:** NuGuard runs in the scan worker's network namespace on
    loopback, not on the compose network. That needs neither TLS nor
    `trust_proxy`, and the key and token cross no network.
  - **Names:**
    - the gap cause for a failed clone reuses `download_failed` rather than
      adding `fetch_failed`;
    - annotation keys are version-tagged (`nuguard/0.9.15/fingerprint`), as
      `osv-scanner`'s are, not `nuguard.fingerprint`;
    - the empty fixture is `empty.json`, which the envelope tests require,
      not `empty-succeeded.json`.
  - **Interfaces:**
    - `GapReporter` is `SubTools(out) (ok, gaps, err)`, so a report names the
      NuGuard tools that ran as well as those lost;
    - `RunOpts` also gained `RunID`, which the idempotency key needs.
  - **Recording:**
    - the run's tool list is now the registered adapters, not every
      `tools.lock` entry, so an unconfigured NuGuard is not recorded on any
      run; today the two sets are identical;
    - the inventory shows on the repository page and API, not in issued
      reports, which are content-hashed under `fleet.v1`; adding it there
      needs a template version change of its own;
    - only the first coverage gap of a scan is stored (an existing Phase 1
      issue), so a scan with several NuGuard gaps stores the first.
  - **Time:** `-nuguard-timeout` defaults to 10 minutes, inside the
    15-minute scan limit, so a slow NuGuard cannot cost the local tools'
    results.
  - **Images:** `deploy/build.sh` and the compose file take `VF_IMAGE_TAG`
    (default `v1`). The stack test of this branch was built as
    `nuguard-test`, so your account-mode stack's `v1` images were not
    touched.
  - **Python (step 6) not done:** an adapter cannot see which other tools
    covered a repository, so the "NuGuard alone is not a full scan" gap
    needs a worker-level rule. Listed in NOW-VS-LATER.md.
- **Real-mode NuGuard choices** (2026-11-11):
  - **Option 1, the bridge**, because the experiment showed the Mac's
    loopback is reachable. The client's rule stays as it is, and no flag
    can widen it.
  - **NuGuard's own environment** lives in
    `~/.local/share/vulnframework/nuguard/venv`, not the checkout's `.venv`.
    `uv sync` would remove packages the developer installed there, and that
    `.venv` does not import. With `uv`, the install uses `--frozen`, so the
    checkout's lockfile is never rewritten.
  - **The checkout is found one level down too** (`../nuguard/nuguard`, the
    layout on this Mac). `NUGUARD_DIR` overrides.
  - **The settings file is rewritten on every start**, so the proxy and
    certificate variables passed through match the current shell. The key
    is made once.
  - **The rendering test runs the real functions** with `docker` and `go`
    replaced by recorders, rather than a separate dry-run mode, so it checks
    the code that runs.
  - **The working-tree note is a finding annotation**
    (`nuguard/<version>/scanned`), not a gap. A gap would mark the scan
    partial, though NuGuard did complete. An untracked file counts as a
    change, because the local tools scanned it.
  - **The origin decides the repository.** The registered name is used for
    everything else, and never for NuGuard in real mode.
  - **`--nuguard` keeps the shell alive** (no `exec`) so its clean-up runs.
    Without `--nuguard`, nothing about `run.sh`'s process changed.
- **NuGuard controls choices** (2026-11-06):
  - **"Not requested" is a third list** (`tools_not_requested`, JSON with a
    reason per tool) beside `tools_ok` and `tools_failed`. The coverage
    views and the outcome classification are unchanged, because they read
    only those two.
  - **A source is named** `adapter` or `adapter/sub-tool`. The sub-tool
    travels on a new `RawFinding.SubTool`, which is not identity. Only the
    NuGuard goldens changed (by that field).
  - **Legacy results:** a scan result that lists no tools at all (none
    from the scan worker) is judged by its outcome alone, as before. A
    result whose only list is "not requested" verifies nothing.
  - **The fake narrows only when asked** (`Narrow`, `-narrow`). Captured
    results are still replayed verbatim by default, which the existing
    tests and the stack test rely on.
  - **The adapter never counts an unasked tool as ok**, even if the service
    ran it.
  - **The resolution function is exported** (`ResolveNuGuardOptions`, in
    `internal/nuguardopt`): the API and the worker are different packages.
  - **The status re-check is 30 seconds while unreachable**, not a flat 5
    minutes: the sidecar starts just after the worker.
  - **Settings writes** pass the same role, origin and CSRF checks as scan
    requests (shared `checkOwnerWrite`), and have their own rate limit (10 a
    minute, counted from the audit). Without a configured NuGuard they
    answer 409.
  - **A scan request merged into one already queued keeps the queued one's
    NuGuard options**; the response shows them.
  - **"Found by" has no counts:** a facet over the tools needs new
    aggregation in both backends. Listed in NOW-VS-LATER.md.
  - **CycloneDX is 501** until a converter exists; JSON is served.
  - **Fixtures:** the configured views come from a Go test that drives the
    real server and worker (`TestNuGuardViewsFromTheRealServer`,
    `UPDATE_UI_FIXTURES=1`). Of the demo fixtures, only `coverage.json` was
    recaptured: a full recapture moved every date and lost the report
    supersession `reports.json` was captured with. `capture-fixtures.mjs`
    gained `ONLY=`.
- **A batch can cover fewer repositories than the fleet** and its point is
  not marked partial: a repository already queued on its own when Scan all
  is pressed merges into that request and runs separately. The timer's
  sweeps already behaved this way; the Coverage page shows the true
  coverage. Left as is.

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
