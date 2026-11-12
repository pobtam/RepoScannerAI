# Claude Code prompt: connect real mode to a locally running NuGuard

> Paste everything below the line into Claude Code, opened at the root of `vulnerabilityAI` **on your Mac** (Docker Desktop running, `../nuguard` checked out next to this repo).
> It builds on `feature/nuguard-ui-controls` (`b707be8`). Start a new branch from there.

---

## Task

Real mode (`./run.sh --real <clones>`) runs the scan worker inside the scanner image and has no NuGuard wiring. Only the Compose stack does, and that needs a NuGuard image that has never been built.

Add an **opt-in** `--nuguard` option to real mode. It starts NuGuard natively on the Mac with `nuguard serve` from the sibling checkout `../nuguard`, bound to loopback, and connects the containerised scan worker and the one-shot sweep to it. A real-mode trial then includes NuGuard with no NuGuard image.

Without `--nuguard`, real mode must behave **exactly** as it does today.

Before writing code, read:

1. `run.sh`, `scripts/real.sh` (`real_prepare_container`, `real_worker_start`, `real_sweep`, `real_need_docker`), `scripts/smoke.sh`, `scripts/db.sh`, `deploy/login.sh` (how a secret is created and read without being printed).
2. `REAL-REPOS.md`, `DEPLOY.md` ("NuGuard" and "NuGuard controls"), the 2026-11-03 to 2026-11-10 entries in `PROGRESS.md`, and the D13 amendment in `DECISIONS-NEEDED.md`.
3. `vulnframework/internal/nuguard/client.go`: the `base`/`loopback` rule, plain http only to a loopback host.
4. `vulnframework/internal/scan/adapters/nuguard.go` and `nuguard_flags.go`: how `RepoURL` is built (`https://<GitHubHost>/<opts.Repo>`), the ceiling flags, and `CheckService`.
5. `vulnframework/internal/nuguard/nuguardfake/cmd/nuguardfake`.
6. In `../nuguard`:
   - `documentation/docs/remote-api.md` (the service config, `nuguard serve`, `nuguard serve keygen`);
   - `nuguard/service/settings.py` (the validation: non-loopback bind needs TLS or `trust_proxy`; `passthrough_env`);
   - `nuguard/sbom/extractor/git_clone.py` (`_INHERITED_ENV`, the known proxy bug).

## Facts that shape the design (verify each one before relying on it)

- **NuGuard clones from GitHub.** It scans `repo_url` at a commit; it can't read the local clone.
  - A real-mode repository can be scanned by NuGuard only if the clone has a **github.com origin** and the scanned commit **exists on GitHub**.
  - Real-mode clones may have local-only commits, uncommitted changes, or no GitHub remote at all, like the fabricated `testdata/repos`. Each of these must become an honest coverage gap, never a silent miss and never a failed scan.
- **The repository URL.** Real mode's registered name (`vfctl repo add NAME`) need not be the GitHub `owner/name`. The adapter builds `RepoURL` from that name, which can point NuGuard at the wrong repository.
- **Reaching the Mac from the worker container.** The worker runs in a container started with `--add-host=host.docker.internal:host-gateway`, so NuGuard on the Mac's `127.0.0.1` isn't "loopback" from inside the container.
  - The client refuses plain `http` to a non-loopback host, so `http://host.docker.internal:<port>` is refused today.
  - Find out, **by experiment on this Mac**, whether a service bound to the Mac's `127.0.0.1` is reachable from the container through `host.docker.internal` on this Docker Desktop version. Record the result and the Docker Desktop version in `PROGRESS.md`.
- **Version and Semgrep.** `config/tools.lock` pins `nuguard 0.9.15`; the service must report the same version or `CheckService` refuses. NuGuard's own Semgrep must be the version NuGuard was tested with, inside NuGuard's virtual environment, separate from any Semgrep on the Mac.

## Ground rules (each needs a test or a scripted check)

1. **Opt-in, and no change without it.**
   - Without `--nuguard`, `run.sh --real`, `real_sweep`, `real_worker_start` and `scripts/smoke.sh --real` produce the same container command lines and the same results as before.
   - Prove the command lines with a test that renders them with and without the option. Make the rendering a function you can call in a dry-run mode, if it isn't already.
2. **NuGuard listens only on the Mac's loopback.**
   - Never bind `0.0.0.0` or a LAN address. Never set `trust_proxy` to get around NuGuard's own bind rule.
   - If the container can't reach the Mac's loopback through `host.docker.internal`, choose **one** of the following, in this order of preference, and explain the choice:
     1. **A bridge on loopback inside the container,** so the adapter still talks to `http://127.0.0.1:<port>` and the loopback rule stays untouched. Use a minimal forwarder: a small Go program built and mounted like the orchestrator binary. Don't install a package in the image or rebuild the image.
     2. **A narrowly scoped client exception:** a new flag, `-nuguard-allow-http-host=host.docker.internal`, that accepts plain http to **exactly that one host name**.
        - It's refused in combination with `-github` (account mode) or any non-real-mode use.
        - It's logged once at start-up as a local-trial setting.
        - Tests show that every other non-loopback host is still refused.
3. **Secrets stay secret.**
   - The NuGuard API key is generated by `nuguard serve keygen` once, stored under `~/.local/share/vulnframework/nuguard/` with mode `0600`, never inside either repository, and never printed after creation.
   - The service config holds only the key's SHA-256.
   - The key reaches the worker container with `-e VULNFRAMEWORK_NUGUARD_API_KEY` (name only, value from the environment), as `real.sh` already does for `ANTHROPIC_API_KEY`.
   - The GitHub token, needed only for private repositories, is optional. It's passed the same way from `VULNFRAMEWORK_GITHUB_TOKEN` and documented as read-only, fine-grained.
   - `set -x` must never be active around secrets.
4. **The scanned commit is the commit NuGuard scans.**
   - The worker passes `opts.CommitSHA` (read from the clone's HEAD, already implemented).
   - If the clone's working tree has **uncommitted changes**, record an annotation or gap note on the NuGuard results: "NuGuard scanned the committed state, not the working tree", because the local tools scanned the working tree.
   - If the commit isn't on GitHub, NuGuard answers `ref_not_found`. Map that to a gap whose detail says the commit isn't on GitHub (unpushed, or a local-only repository), with owner `repo`.
5. **The right repository on GitHub.**
   - Resolve the GitHub `owner/name` from the clone's `origin` remote: both the https and `git@github.com:` forms, with `.git` stripped. Read it from `<clone>/.git/config` inside the container (the clones are mounted read-only at `/repos`).
   - Fall back to the registered name only when it matches the origin.
   - With no github.com origin, NuGuard is **not requested** for that repository, with the reason "no GitHub origin; NuGuard needs the repository on GitHub", using the not-requested vocabulary from migration 0019. It isn't a failure.
   - Put the resolution in Go, as a pure function with table tests. Use the existing `RunOpts`/dispatcher path (`LocalDispatcher`), and don't add a credential to it.
6. **NuGuard's state is recorded.**
   - `scripts/nuguard-local.sh status` prints, and the first worker start logs: the `../nuguard` commit, whether its working tree is dirty, the service version, and the Semgrep version in its venv.
   - The NuGuard service is currently **uncommitted work** in `../nuguard`. Say so plainly in the status output whenever the tree is dirty, because a result from an uncommitted tree can't be reproduced later.
7. **Back up first.** Real mode's database will receive migrations 0018 and 0019 the first time the new orchestrator starts on it.
   - Before migrating, if the database's schema is older than the binary's, `run.sh --real` takes a `scripts/db.sh backup` and says where it is.
   - Check whether real mode already migrates on start (`real_migrate`) and add the backup step in front of it. This applies with or without `--nuguard`.

## Work, in order

### Step 1: `scripts/nuguard-local.sh` (start | stop | status | key)

Behaviour:

- **Locate NuGuard** at `NUGUARD_DIR`, defaulting to `../nuguard` relative to this repository. Fail clearly if `pyproject.toml` or `nuguard/service/` is missing.
- **Environment:** create or update NuGuard's environment with `uv sync --extra service --extra secrets` (fall back to a `python3 -m venv` plus `pip install -e ".[service,secrets]"` if `uv` is missing). Install `semgrep==<version>` into that venv. Use the version from NuGuard's own CI pin; find it in `../nuguard` rather than hard-coding it. Fail clearly if Python 3.12+ is missing, and say how to install it with Homebrew.
- **Key and config:**
  - On first run, generate the key with `nuguard serve keygen --id real-mode` and store the key and the config in `~/.local/share/vulnframework/nuguard/`, mode `0600`.
  - The config has:
    - `bind: 127.0.0.1` and `port: ${NUGUARD_PORT:-8090}`;
    - `git.allowed_hosts: [github.com]`;
    - `analysis_defaults.tools: [nga-rules, atlas, semgrep]`;
    - `llm.enabled: false`;
    - scratch and database paths under the same directory;
    - a `passthrough_env` that includes the proxy and CA variables only if they're set in this shell.
- **Start:**
  - Run `nuguard serve -c <config>` in the background, with the venv's `bin` first on `PATH` so NuGuard's workers use NuGuard's Semgrep.
  - Write a pid file and a log under the same directory.
  - Wait for `GET /v1/readyz` to return ok (up to 60 seconds). Then check that `/v1/capabilities` reports `nuguard_version` equal to the `tools.lock` pin. On a mismatch, stop the service and fail, naming both versions.
- **Stop:** stop the process from the pid file only. Never `pkill` by pattern, because a pattern can match the calling shell.
- **Status:** running or not, the port, readyz, the version, the venv's Semgrep version, the `../nuguard` commit and dirty state (ground rule 6), and the log path.
- **Key:** export the key into the caller's environment (`eval "$(scripts/nuguard-local.sh key)"` prints `export VULNFRAMEWORK_NUGUARD_API_KEY=…` only when stdout is not a terminal, and refuses otherwise). Follow `deploy/login.sh`'s conventions.
- **Port check:** if the port is taken by something that isn't this NuGuard, fail and name the port.

Add a `--help` that matches the style of `run.sh`'s.

### Step 2: Reachability from the worker container

Run the experiment described above (`host.docker.internal` to the Mac's `127.0.0.1`). Then implement ground rule 2's preferred option that works, with tests:

- **Option 1 (the forwarder):** a Go unit test for the forwarder. A `real.sh` change mounts and starts it before the orchestrator. The orchestrator gets `-nuguard-url http://127.0.0.1:<port>`.
- **Option 2 (the flag):** client tests for the exact-host exception and the combinations it refuses.

### Step 3: Wire `--nuguard` into real mode

- `run.sh --real --nuguard <clones>`:
  - starts NuGuard through `scripts/nuguard-local.sh start`, unless it's already running and healthy;
  - loads the key;
  - passes the NuGuard flags and env to **both** `real_worker_start` and `real_sweep`, through `real_prepare_container`, so both scan the same way;
  - on exit, stops NuGuard only if this run started it.
- **Ceiling flags:** `-nuguard-allow-tools`, `-nuguard-allow-posture` and `-nuguard-max-timeout` are set from environment variables, with the same defaults as `deploy/compose.yaml`. The interface's NuGuard controls then work in real mode within that ceiling.
- **`--nuguard` with `--no-sweep`:** works; the worker still has NuGuard.
- **`--nuguard` without `--real`:** an error with a one-line explanation.
- **Status line:** print what will happen before the sweep starts, for example: "NuGuard on (local, http://127.0.0.1:8090, version 0.9.15, tree dirty); repositories without a GitHub origin will show NuGuard as not requested."

### Step 4: Repository and commit resolution in Go (ground rules 4 and 5)

- A pure function `githubRepoFromGitConfig(configBytes []byte) (owner, name string, ok bool)`, with table tests covering:
  - https, `git@`, `ssh://`, with and without `.git`;
  - a non-GitHub host;
  - no origin;
  - several remotes.
- **Dirty-tree detection:** compare the index and working tree without running git in the container if git isn't in the image. Check the image first. If it can't be done reliably, record "working-tree state unknown" rather than claiming clean.
- **Wiring:**
  - In `LocalDispatcher` (real mode), set the NuGuard repository on the job from the resolution. Keep `opts.Repo` as the registered name for everything else. Add a separate non-secret field, for example `RunOpts.NuGuardRepo`, if one doesn't already exist.
  - The adapter uses it for `RepoURL`.
  - With no GitHub origin, the adapter is not requested, with the reason from ground rule 5.
- **Error mapping:** map NuGuard's `ref_not_found` for real mode to the "commit not on GitHub" gap, owner `repo`, with a test through `nuguardfake`.

### Step 5: Smoke test without the network

- `scripts/smoke.sh --real --nuguard-fake` runs the existing real-mode smoke with `nuguardfake` (`cmd/nuguardfake`) on the Mac's loopback in place of NuGuard, connected the same way as step 2.
  - The fabricated `testdata/repos` have no GitHub origin, so add one fixture clone whose `.git/config` has a github.com origin. Use a made-up repository the fake answers for.
- **Assertions:**
  - a repository with no origin shows NuGuard as **not requested**, with the reason;
  - the origin fixture gets NuGuard results, its AI inventory and the effective options;
  - a fake `ref_not_found` gives the "commit not on GitHub" gap;
  - without `--nuguard-fake`, the smoke output is identical to before.

### Step 6: A real trial

If Docker Desktop is running and the network allows it:

- clone one small **public** GitHub repository that uses an LLM SDK into a temporary clones folder;
- run `./run.sh --real --nuguard <folder>` against a **throwaway** real-mode database (the same approach as `smoke.sh --real`: its own Postgres container and temporary data, never `vulnframework-pg`);
- confirm that a NuGuard-enabled sweep records the AI inventory and NuGuard's sub-tools.

Record what happened in `PROGRESS.md`. If it couldn't run, say why.

### Step 7: Documentation

- **`REAL-REPOS.md`:** a "NuGuard in real mode" section covering:
  - prerequisites: Python 3.12+, `uv`, `../nuguard`;
  - what leaves the machine: NuGuard clones the repository from GitHub, plus the Semgrep rule download if any;
  - repositories with no GitHub origin or unpushed commits;
  - the key's location;
  - how to stop and reset (delete `~/.local/share/vulnframework/nuguard/`).
  - Update section 6 ("What leaves this machine") for `github.com` and `api.github.com` from NuGuard.
- **`USAGE.md`:** one paragraph and a pointer.
- **`PROGRESS.md`:** a dated entry with the reachability experiment's result, the option chosen, verification, and what wasn't verified.
- **`NOW-VS-LATER.md`:** NuGuard scanning a local tree directly (needs source-archive upload in NuGuard's API), so unpushed commits and non-GitHub repositories can be covered.

## Done when

- **Go:** `go vet ./...` and `go test ./...` are green. The new tests cover the git-config resolution, the dirty-tree note, the `ref_not_found` mapping, the no-origin not-requested case, and either the forwarder or the exact-host flag with its refusals.
- **UI:** `npm run typecheck` and `npm test` are green, if anything in `reportui` changed.
- **`scripts/smoke.sh --real`** is unchanged and green; **`--real --nuguard-fake`** is green.
- **Command lines:** the rendering test shows them unchanged without `--nuguard`.
- **The real trial (step 6)** ran, or the summary says exactly why it didn't.
- **The summary lists:**
  - the reachability result and the Docker Desktop version;
  - which option from ground rule 2 was chosen and why;
  - files changed;
  - every deviation from this prompt;
  - what wasn't verified.
- Don't commit unless asked. Work on a new branch, `feature/real-mode-nuguard`, from `feature/nuguard-ui-controls`.
