# Claude Code prompt: make NuGuard work in real mode on this Mac, for real

> Open Claude Code in `~/Desktop/wanAware`, the folder that contains both `vulnerabilityAI/` and `nuguard/nuguard/`, so it can work in both repositories. Docker Desktop must be running. Paste everything below the line.

---

## Goal

`./run.sh --real --nuguard ~/clones` must work as a repeatable, everyday setup on this Mac, against **my real-mode database and my clones**, not a throwaway. When it's done, I can open the interface and use every NuGuard feature already built:

- the "AI scanning (NuGuard)" page;
- per-repository settings;
- "Scan now" with NuGuard options;
- "Found by: NuGuard";
- the AI components panel;
- the AI-SBOM download.

Every result must be reproducible from a commit.

The code for this exists. What's left is committing, environment hygiene, two small fixes, and a real end-to-end bring-up. Don't build new features.

## Hard safety rules (these override everything below)

1. **Only stop processes and containers you started in this session,** by PID or by container name you created. Never kill by port, by pattern (`pkill -f`), or "everything listening on X". A previous session killed Docker Desktop's backend that way.
2. **Leave these alone:**
   - the `vf-demo` Compose stack and its volumes;
   - the `vf-pg-test` container;
   - the `nuguard-service` container (broken, not used by real mode; I'll decide about it separately);
   - `~/.local/share/vulnframework/backups/archive/`.
3. **Back up before touching my real-mode database:** `scripts/db.sh backup --target real`. Say where the backup is. If the backup fails, stop.
4. **Never print secrets:** the NuGuard API key, any GitHub token, `deploy/.env` values. No `set -x` near them. Ask me before using a GitHub token; never look for one.
5. **Git:**
   - commit only on the feature branches named below;
   - never push, never merge into `main` or `develop`, never rewrite history, never `git add -A` blindly;
   - review every file you stage.
6. **Ask me before anything that installs software system-wide** (Homebrew packages). Ask me before the first real sweep (step 6) with the list of what it will scan.

## Read first

- **vulnerabilityAI:**
  - `PROGRESS.md` (the entries from 2026-11-03 onwards, especially the real-mode NuGuard entry and its "Not verified" list);
  - `REAL-REPOS.md` (§6 and §6a);
  - `run.sh`, `scripts/real.sh`, `scripts/nuguard-local.sh`, `scripts/launch.sh`, `scripts/test-real-cmdlines.sh`, `scripts/smoke.sh`, `scripts/db.sh`;
  - `DEPLOY.md` ("NuGuard", "NuGuard controls").
- **nuguard** (`nuguard/nuguard`):
  - `CLAUDE.md` and `.github/skills/pydantic-interface/SKILL.md`;
  - `documentation/docs/remote-api.md`;
  - `nuguard/service/` (`results.py`: `NUGUARD_TOOLS_JSON`, `NUGUARD_IMAGE_DIGEST`);
  - `nuguard/sbom/extractor/git_clone.py` (`_INHERITED_ENV`).

## Work, in order. Report after each step: done, or blocked and why.

### Step 1: Fix and commit NuGuard (`nuguard/nuguard`, currently on `develop` with about 59 uncommitted changes)

1. **Create branch** `feature/remote-scan-service` from the current `develop` HEAD, carrying the working tree.
2. **Fix the proxy bug.** `_INHERITED_ENV` in `nuguard/sbom/extractor/git_clone.py` drops the proxy and CA variables, so clones fail behind a proxy.
   - Add `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy`, `NO_PROXY`, `no_proxy`, `ALL_PROXY`, `all_proxy`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `GIT_SSL_CAINFO` and `CURL_CA_BUNDLE`.
   - Add a test that `git_env()` keeps them under a host policy and still drops `GH_TOKEN`, `GITHUB_TOKEN` and every `NUGUARD_*`.
   - Check the GitHub tree-API calls in `github_clone.py` honour the proxy too.
3. **Review the uncommitted tree before staging.** Delete my stray archive `.ng-src.tgz` at the repo root. Don't commit `.DS_Store` files or anything under `tests/apps/**/node_modules`. Decide, and tell me, whether `CONTEXT.md` and `GATEWAY-DESIGN.md` belong in the commit; they're design notes.
4. **Run, per its `CLAUDE.md`:**
   - `uv run ruff check nuguard/ tests/`
   - `uv run mypy nuguard/`
   - `uv run pytest tests/contracts tests/service tests/analysis tests/sbom -q`
   - then the full suite. Report failures that already existed separately from new ones.
5. **Commit in reviewable pieces.** Suggested split, with messages that name the spec section (`documentation/developer-specs/remote-scan-api.md`):
   - P1 no-false-clean tool status;
   - P2 Semgrep rule fixes;
   - P3/P4 token and clone safety, including the proxy fix;
   - P5 finding identity;
   - P6 packaging;
   - the service;
   - docs and CI.

   If clean splitting would take hunk surgery that risks mistakes, use fewer commits and say so.

### Step 2: Commit vulnerabilityAI (`feature/real-mode-nuguard`, about 22 modified files plus new ones, based on `b707be8`)

1. **Review and stage** the real-mode NuGuard work and the `launch.sh` credential scrub.
2. **Don't commit:**
   - `.claude/`;
   - `Project Phase Plan GitHub-Wide Code and AI Vulnerability Scanner.pdf`;
   - my archives in `nuguard-integration/`: `.vf-src.tgz`, `.b707be8.tgz`, `.rmn.tgz`. Delete those three files.
   - The prompt `.md` files and `sample-scan-result.json` in `nuguard-integration/` can stay untracked; ask me whether to commit them.
3. **Before committing:**
   - `go vet ./...` and `go test ./...` (memory backend, and Postgres if `VULNFRAMEWORK_TEST_DSN` can point at a container you start yourself);
   - `npm run typecheck` and `npm test` in `reportui`;
   - `scripts/test-real-cmdlines.sh`.

### Step 3: A reproducible NuGuard environment

1. **`uv`:** check `uv --version`. If it's missing, ask me to approve `brew install uv`.
2. **Lockfile:** make `scripts/nuguard-local.sh` build NuGuard's venv (under `~/.local/share/vulnframework/nuguard/`, as now) **from NuGuard's lockfile** when `uv` is present. For example, `UV_PROJECT_ENVIRONMENT=<that venv> uv sync --frozen --extra service --extra secrets`, run in the NuGuard checkout. Keep the pip fallback, but have `status` say "dependencies not from lockfile" when it was used.
3. **Record the source:** set `NUGUARD_IMAGE_DIGEST` for the local service to `git:<nuguard commit>` (plus `-dirty` when the tree is dirty). Every result then records the exact source in `provenance.image_digest`, which vulnframework already stores as `nuguard/image`. Document that, for a native run, this field holds a git commit, not an image digest.
4. **Report Semgrep's version:** today the service reports `semgrep` with a `null` version natively, because `/etc/nuguard/tools.json` only exists in the image. Have `nuguard-local.sh` write a `tools.json` in its data folder with the venv's actual Semgrep version, and start the service with `NUGUARD_TOOLS_JSON` pointing at it. Check the file format against `results.py`. Afterwards, `/v1/capabilities` must show a Semgrep version.
5. **Check:** `scripts/nuguard-local.sh start`, then `status`. It should show the version 0.9.15 (matching `vulnframework/config/tools.lock`), the lockfile in use, the clean commit from step 1, Semgrep's version, and loopback-only binding. Then `stop`.

### Step 4: Ctrl-C clean-up in plain real mode

Apply the clean-up fix that `--nuguard` already has to plain `./run.sh --real` too: Ctrl-C must stop the scan worker container, the API server and the dev server.

- Keep the container command lines byte-identical; `scripts/test-real-cmdlines.sh` must still pass.
- Re-run `scripts/smoke.sh --real` and `scripts/smoke.sh --real --nuguard-fake`.

### Step 5: Check my clones before scanning

1. **Back up** the real-mode database (safety rule 3).
2. **Inventory, without changing anything:**
   - list the repositories registered in real mode (`./vfctl.sh repo list` or the equivalent);
   - for each, check that `~/clones/<last part of the name>` exists, its `origin` remote (GitHub or not), whether HEAD is pushed (`git -C … status -sb`, and `git ls-remote origin <HEAD>` where the network allows), and whether the working tree is dirty;
   - also list the clones in `~/clones` that aren't registered.
3. **Show me a table** of repository, GitHub origin, commit pushed?, dirty?, and "NuGuard will: scan / not requested (no GitHub origin) / gap (commit not on GitHub)". Say which ones are private (they'll need a read-only token).
4. **Wait for my go-ahead.** I may register or remove repositories, push commits, or provide a fine-grained read-only token through `VULNFRAMEWORK_GITHUB_TOKEN` in the shell that runs `run.sh`. Don't ask me to paste a token into chat.

### Step 6: The real bring-up (after my go-ahead)

1. **Run** `./run.sh --real --nuguard ~/clones` in the background, capturing its output to a log under the session's scratch folder, and record the PIDs and containers it starts (safety rule 1).
   - Confirm the backup-before-migrate step ran if the schema was older.
   - Confirm the NuGuard status line.
2. **Verify through the API on `127.0.0.1:8080`**, with the same local auth the interface uses:
   - `GET /v1/nuguard`: `configured: true`, reachable, `version_ok: true`, recent `checked_at`.
   - The sweep's run: for each GitHub-origin repository, `nuguard`, `nuguard/nga-rules`, `nuguard/atlas` and `nuguard/semgrep` ran ok (or a gap with an honest cause), `effective_nuguard` is recorded, and `ToolVersions` includes `nuguard/image` = `git:<commit>`.
   - `GET /v1/repos/{repo}` shows `ai_components.measured: true` with counts, and `last_commit_sha`.
   - `GET /v1/findings?found_by=nuguard`: lists NuGuard findings if any exist. Zero findings with all sub-tools ok is a valid result; say so plainly.
   - Non-GitHub repositories show NuGuard as not requested, with the reason.
3. **Use the controls, then undo them:**
   - turn NuGuard off for one repository through `PUT /v1/repos/{repo}/nuguard` (with the CSRF and origin headers the interface sends);
   - "Scan now" that repository through `POST /v1/scans`;
   - confirm its earlier NuGuard findings stayed open and are flagged not re-observed;
   - turn it back on, scan again, and confirm they're re-observed.
   - Restore any setting you changed to what it was, and list the audit entries you created.
4. **Check the interface,** with `npm run probe:layout` or the existing layout probe if it can point at the running dev server: the NuGuard page, a repository page with the AI components panel, and a NuGuard finding page all render without errors. If no probe can do that, say so.
5. **Restart resilience:**
   - stop NuGuard with `scripts/nuguard-local.sh stop` while the worker runs;
   - "Scan now" one repository: it must complete with a NuGuard gap, never a clean result;
   - start NuGuard again: the status card must recover within a minute, and the next scan must run NuGuard.
6. **Stop everything you started,** with Ctrl-C semantics or by PID or container name. Confirm the `vf-demo` stack and `vf-pg-test` are in the state you found them.

### Step 7: Documentation

- **`REAL-REPOS.md`:** a short "Everyday use with NuGuard" checklist at the top of §6a covering:
  - start, stop, status and reset (`scripts/nuguard-local.sh`);
  - what `nuguard/image = git:…` means;
  - how to update NuGuard: pull or commit in the checkout, then `start` rebuilds the venv when the lockfile changes;
  - what to do when `version_ok` is false (`tools.lock` pin vs service version).
- **`PROGRESS.md`:** a dated entry with:
  - both commit lists (nuguard and vulnerabilityAI);
  - the backup path;
  - the step 5 table;
  - the bring-up results per repository;
  - the restart test;
  - what's still not verified.
- **nuguard `documentation/docs/remote-api.md`:** the proxy fix, and running the service natively with `NUGUARD_TOOLS_JSON` and `NUGUARD_IMAGE_DIGEST`.

## Done when

- **nuguard:** `feature/remote-scan-service` holds all its work in reviewed commits. The proxy fix is tested, and lint, types and tests are reported.
- **vulnerabilityAI:** `feature/real-mode-nuguard` holds the real-mode work and the step 3–4 changes in reviewed commits. Go, UI, command-line and both smoke checks pass.
- **`nuguard-local.sh status`** shows: lockfile used, a clean commit recorded as `git:<sha>`, Semgrep's version, version 0.9.15 matching the pin.
- **A real sweep** of my clones with `--nuguard` completed, with the step 6 checks passing or each failure explained.
- **Everything you started is stopped,** and nothing you didn't start was touched.
- **The final summary lists:**
  - the commits;
  - the backup path;
  - the repository table;
  - results per repository;
  - deviations from this prompt and why;
  - what I need to decide next. At least: merging the two feature branches, the D13 amendment, and the broken `nuguard-service` container.
