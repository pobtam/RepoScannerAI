# Scanning your real repositories (read-only, on this machine)

This guide is for running the framework against your own clones on your own
machine: scan them, keep the results in a local PostgreSQL database, score and
route the findings, and browse them in the web interface.

It is **read-only**. Nothing in this path writes to GitHub, opens a pull
request, comments, or creates a ticket. Your clones are mounted into the scan
container read-only.

The demonstration (`./run.sh` with no options) is unaffected and still needs
none of this.

> **Real mode is for quick local trials, not ongoing history.** The history
> you keep lives in the account-mode stack at https://localhost:18443
> (compose project `vf-demo`, section 10). Use real mode to try a change or
> a scanner against your clones; expect its database to be reset or thrown
> away. Its history up to 27 October 2026 is kept as a read-only archive,
> `~/.local/share/vulnframework/backups/archive/real-20261027-151412.dump`.

---

## 1. Prerequisites

| You need | Why | Check |
|---|---|---|
| Go and Node.js, with the interface's dependencies installed | runs the API and the interface | `./setup.sh` |
| Docker Desktop, **running** | PostgreSQL and the scanners run in containers | `docker info` |
| The scanner image `vulnframework-scanner:v1` | holds the eight scanner tools at the versions in `vulnframework/config/tools.lock` | `docker image inspect vulnframework-scanner:v1` |
| About 6 GB of disk | the image (~1.9 GB), the scanner cache (~2 GB), the database | |
| Internet access during a sweep | scanners download vulnerability databases and rules; see section 6 | |

If the image is missing, build it (this takes a while):

```sh
docker build -t vulnframework-scanner:v1 vulnframework/deploy/scanner
```

Before every sweep, `run.sh --real` checks the image against
`config/tools.lock`. If any tool is missing or at another version, it prints
which ones and **stops**. It never rebuilds the image for you, because every
run records the tool versions it used, and a record that disagrees with the
binaries would be wrong. Rebuild with the command above, then run again.

## 2. Clone your repositories

Put every repository you want scanned in one folder. Each folder's name must
be the **last part** of the name you register (`acme/payments-api` is looked
for in `<folder>/payments-api`).

```sh
mkdir -p ~/clones && cd ~/clones
git clone git@github.com:acme/payments-api.git
git clone git@github.com:acme/checkout-web.git
```

The sweep scans whatever is checked out in each clone, as files on disk; it
does not read git history. Run `git pull` yourself before sweeping if you
want the latest code.

**Not supported yet:**

- **Repositories whose `go.mod` is not at the root.** Monorepos and
  multi-module repositories are not handled. The Go scanners run `./...` from
  the repository root, so they fail and the scan is recorded as partial or
  failed. The registry has a field for module layout, but no scanner reads it
  yet.
- **Private Go module dependencies.** The scan container has no credentials,
  so dependencies it cannot download leave the Go scanners unable to load the
  code, and the scan is recorded as partial.
- **Languages other than Go and JavaScript/TypeScript.**

## 3. Register them

The sweep scans only registered repositories. Register each clone once:

```sh
./vfctl.sh repo add acme/payments-api -languages go -tier 1 -test-suite
./vfctl.sh repo add acme/checkout-web -languages javascript -tier 2 -lockfile
./vfctl.sh repo list
```

| Flag | Meaning |
|---|---|
| `-languages` | `go`, `javascript`, or both (`go,javascript`). Required for a new repository: it picks the scanners. |
| `-tier` | 1 (most critical) to 3. Default 3. Affects priority and SLA windows. |
| `-lockfile` | The repository commits `package-lock.json`. Turns on `npm audit`; without it, `npm audit` does not run. |
| `-test-suite` | The repository has a real test suite. Used by policy routing. |

Running `repo add` again on a registered repository changes only the flags you
pass. Use `-lockfile=false` to clear a flag. `./vfctl.sh repo remove NAME`
**archives** a repository: future sweeps skip it and its history is kept.
Adding it again restores it.

`vfctl.sh` starts the database container if it is not running, applies
migrations, and leaves the database running.

## 4. Sweep and browse

```sh
./run.sh --real ~/clones
```

In order, this:

1. starts PostgreSQL (container `vulnframework-pg`, data in volume
   `vulnframework-pgdata`) and applies migrations;
2. checks the scanner image against `tools.lock`, and stops if it differs;
3. scans every registered repository inside the scanner image, with
   `~/clones` mounted read-only. The first sweep is slow because the scanners
   download their databases;
4. for each repository a scanner completed on, looks up exploitation data
   (CISA KEV and FIRST EPSS), computes a priority and an SLA position, and
   routes each finding through policy;
5. starts the API and the interface, with **local auth on** (section 7), at
   http://localhost:5173.

The full record of each sweep is saved in `vulnframework/bin/real-runs/`.
Press Ctrl-C to stop. To browse the last results without scanning again:

```sh
./run.sh --real --no-sweep
```

### Scan now, from the interface

`./run.sh --real` also starts a **scan worker** (container
`vulnframework-scanworker`), which runs scans requested while the app is open.
It scans the clones in `~/clones`, read-only, and needs no GitHub token in
this mode.

- **One repository:** open its page under Repositories and press **Scan
  now**. Pull the latest changes into its clone first if you want them
  scanned.
- **Everything:** on Repositories, press **Scan all included repositories**.
  The whole batch is one run of kind `sweep`, so it is a point on the trend
  chart under Runs and counts towards coverage. A single repository's scan
  is a `manual` run and is left off the trend, because one repository's
  count beside the fleet's would look like the fleet shrinking.
- **From the terminal:**
  ```sh
  ./vfctl.sh scan request owner/name
  ./vfctl.sh scan enqueue -all
  ./vfctl.sh scan list
  ```

**What you see.** Each request shows one of these statuses:

| Status | Meaning |
|---|---|
| queued | waiting for the worker |
| running | being scanned |
| finished | scanned; links to the run and the repository's findings. A partial scan also says what was missed |
| failed | not scanned, with the reason |
| timed out | stopped at the time limit (15 minutes, `VULNFRAMEWORK_SCAN_TIMEOUT`). Recorded as a coverage gap, never as clean |
| interrupted | the worker stopped during the scan. Press **Retry** |
| refused | the repository is excluded, skipped or archived, with the reason |

**How it behaves:**
- Pressing Scan now again while a scan is queued or running doesn't queue a
  second one: the request merges into the existing one.
- Each person can make 10 requests a minute.
- Only the security-owner level may request scans. Local auth (section 7)
  grants it on this machine.
- Every request is recorded with who asked, which repository and when. It's
  in the access log, and kept as a row in the queue, which is never deleted.

**Stopping.** Ctrl-C stops the worker with the app. A scan it was running is
marked interrupted, never finished.

**What the states mean here.** Findings are scored and routed, but nothing
acts on the routing:

- A finding routed to `open_ticket` or `escalate_p0` sits in **NEEDS_HUMAN**.
- One routed to `auto_remediate` stays **TRIAGED**, with the reason recorded.

**Every secret finding is routed to `escalate_p0`.** No configuration can change
this. Secrets are also never closed by disappearing. Section 9 covers known-fake
test credentials, allowlists, and secrets removed from the files.

**AI triage narratives are off by default.** Findings are still scored and
routed. The sweep record and each finding's Triage panel say a narrative is
unavailable and why. To turn narratives on, set both variables (this sends
data to Anthropic; see section 6):

```sh
export VULNFRAMEWORK_TRIAGE_MODEL=<model id>
export ANTHROPIC_API_KEY=<your key>
./run.sh --real ~/clones
```

The key is passed to the scan container by name and never appears on a
command line. Decision D2 in `DECISIONS-NEEDED.md` advises against issuing an
API key to a machine where the sandbox probe has not passed. That advice is
written mainly about the agentic fixer, which is not used here. Whether it
also applies to triage is your call.

## 5. Waves need your own first-party module config

A **wave** sequences a fix through your own shared modules. The repository
that owns a module fixes it first, and the repositories that depend on it are
held back until that fix ships. The framework cannot work out which modules
you own, so you have to tell it. Create `vulnframework/config/firstparty.yaml`:

```yaml
version: 1
# When consumers are released: "tag" (the owner publishes a tag) or
# "merge" (the owner's fix merges).
wave2_trigger: tag
modules:
  # module path: the registered repository that owns it
  github.com/acme/platform-common: acme/platform-common
  github.com/acme/authkit: acme/authkit
```

The owning repository must be registered under exactly that name. When this
file exists, `run.sh --real` gives it to both the sweep and the API:

- Findings reached through one of those modules are classified as
  first-party.
- Consumers' findings are deferred to the owner (BLOCKED_UPSTREAM).
- The **Waves** view works.

Without it, the Waves view shows "no first-party registry" (HTTP 503), and
first-party findings are treated as ordinary third-party ones. This path is
unit-tested but has not yet been run against a real organisation's modules.

## 6. What leaves this machine

| Destination | What is sent | When |
|---|---|---|
| `api.osv.dev` (osv-scanner) | names and versions of your dependencies (Go and npm) | every sweep |
| `registry.npmjs.org` (npm audit) | your npm dependency tree: names and versions | repositories registered with `-lockfile` |
| `vuln.go.dev` (govulncheck) | requests for the Go vulnerability database; which entries are fetched reveals which modules you depend on | Go repositories |
| `proxy.golang.org`, `sum.golang.org` | module paths and versions of your Go dependencies, downloaded so the Go scanners can load the code (and a Go toolchain if `go.mod` asks for a newer one) | Go repositories, when not already cached |
| `semgrep.dev` | requests for the `p/javascript` rule pack. Usage metrics and the version check are **turned off**. | JavaScript repositories |
| `ghcr.io` / `mirror.gcr.io` (trivy) | a download of trivy's vulnerability database and checks; nothing about your code | when trivy's cache is stale |
| `www.cisa.gov`, `epss.empiricalsecurity.com` | one download of each whole catalogue per sweep; nothing about your code | every sweep |
| `api.anthropic.com` (**only if AI triage is on**) | per finding: fingerprint, category, advisory and rule IDs, module, versions, severity, reachability, and **file path**. Per repository: its name, languages, tier, whether it has a test suite. Secret values are never sent: they are redacted at scan time, and every request is checked for credential-shaped content before it leaves. | only with both variables from section 4 set |
| Docker Hub | the `postgres:16-alpine` image | first run |
| Anthropic, through Claude (**only if you use the Claude connector**, `vfmcp`) | whatever Claude reads through it becomes part of your conversation: finding details, descriptions and advisory text, repository names, **file paths**, rule names, run history. Secret values never: vulnframework does not store them. Not sent by vulnframework itself but by the Claude app you asked. | each question you ask Claude that uses it (`USAGE.md`, "Ask Claude about your findings"; decision D15) |
| `github.com`, `api.github.com`, `codeload.github.com` (**only with `--nuguard`**) | NuGuard, running on this Mac, clones each repository whose origin is on github.com, at the commit being scanned; with a token set, private repositories too. Your clone itself is not sent: NuGuard downloads GitHub's copy. | every scan, for clones with a GitHub origin |
| `pypi.org`, `files.pythonhosted.org` (**only with `--nuguard`**) | NuGuard's Python packages and its Semgrep, installed into its own environment | first start, and when NuGuard's dependencies change |

These stay on this machine:

- your source code;
- your git history;
- your secrets (gitleaks runs locally and redacts what it reports);
- the gosec and staticcheck analyses;
- the database.

Without `--nuguard`, no GitHub API is called, and cloning is something you
do yourself. With it, NuGuard clones from GitHub as described in the table.

## 6a. NuGuard in real mode

**Everyday use with NuGuard**

- **Run:** `./run.sh --real --nuguard ~/clones`. Ctrl-C stops the scan
  worker, the API, the dev server and the NuGuard this run started.
- **On its own:** `scripts/nuguard-local.sh start`, `stop` and `status`.
  `status` shows what is running and on which address (it must say
  "loopback only"), the version against the `config/tools.lock` pin,
  whether dependencies came from NuGuard's lockfile, Semgrep's version (as
  installed and as the service reports it), and the recorded source.
- **Reset:** `scripts/nuguard-local.sh stop`, then delete
  `~/.local/share/vulnframework/nuguard`. The next `start` rebuilds the
  environments and makes a new API key.
- **`nuguard/image = git:<commit>`:** on a scan, this records which NuGuard
  produced the result. Natively there is no image, so it is the NuGuard
  checkout's commit, with `-dirty` when it had uncommitted changes to
  tracked files, or new files under `nuguard/`, `pyproject.toml` or
  `uv.lock`, at start. The same value is the AI components panel's
  `image_digest`. A `-dirty` result cannot be reproduced from a commit.
- **Updating NuGuard:** pull or commit in the checkout
  (`../nuguard/nuguard`), then `stop` and `start`. `start` rebuilds the
  environment when `pyproject.toml`, `uv.lock` or the Semgrep pin changed.
  `status` warns when the checkout moved since the running NuGuard started.
- **`version_ok` is false** (NuGuard page, or `start` refusing): the service
  reports a different version from the one `vulnframework/config/tools.lock`
  pins (`tool nuguard …`). Either check out the pinned NuGuard version, or
  change the pin on purpose, in a reviewed commit, after checking the new
  version.

NuGuard is an optional extra scanner for AI-specific problems in code, plus
an inventory of the AI parts of each repository: models, agents, prompts
and tools (DECISIONS-NEEDED.md, D13 amendment). In real mode it runs on this
Mac, from the NuGuard checkout next to this repository, without a NuGuard
image:

```bash
./run.sh --real --nuguard ~/clones
```

Without `--nuguard`, real mode is exactly as before.

**Prerequisites.** These are needed only with `--nuguard`:

- the NuGuard checkout at `../nuguard`, or set `NUGUARD_DIR`. A folder
  holding the checkout one level down, `../nuguard/nuguard`, is found too;
- Python 3.12 or newer (`brew install python@3.12`);
- `uv` (`brew install uv`). Without it, `pip` is used, NuGuard's lockfile
  is not, and `status` says "dependencies not from lockfile".

**What happens.** `scripts/nuguard-local.sh start`:

1. builds NuGuard its own Python environment from its lockfile, and
   Semgrep a separate one at the version NuGuard's CI pins. They have to be
   separate: Semgrep in NuGuard's environment fails on start-up. This
   happens the first time, and again when NuGuard's dependencies, the pin or
   the install method change. It also writes `tools.json` (NuGuard's,
   Semgrep's and git's versions) for the service to report;
2. creates an API key the first time;
3. starts `nuguard serve` on `127.0.0.1:8090` (`NUGUARD_PORT`), which is
   reachable from this Mac only;
4. checks that NuGuard reports the version `config/tools.lock` pins, and
   stops it if not.

`./run.sh --real --nuguard` does this for you. It also:

- passes the key into the scan containers by name only;
- prints what will happen before the sweep;
- on Ctrl-C, stops NuGuard if this run started it.

Inside the scan container a small bridge (`cmd/loopbridge`) carries NuGuard's
port from the container's own `127.0.0.1` to the Mac. This keeps the
scanner's rule that the API key only ever travels over https or to a
loopback address.

**Which repositories NuGuard can scan.** NuGuard downloads the repository
from GitHub; it never reads your clone:

| Your clone | What you see |
|---|---|
| origin on github.com, commit pushed | NuGuard's findings and the AI inventory. The GitHub repository is read from the clone's `origin`, so the registered name need not match it. |
| uncommitted changes, or untracked files | NuGuard scans the commit, not your working tree. Each NuGuard finding says "NuGuard scanned the committed state, not the working tree". |
| origin on github.com, commit not pushed | a coverage gap, owned by the repository: "commit … is not on GitHub". Push it and scan again. |
| no origin, or one elsewhere (GitLab, a path) | NuGuard "not requested: no GitHub origin; NuGuard needs the repository on GitHub". This is not a failure, and the other tools scan as usual. |

**Private repositories.** Set `VULNFRAMEWORK_GITHUB_TOKEN` to a fine-grained,
read-only token (Contents: read, Metadata: read) for those repositories
before starting. It is passed to NuGuard only. Public repositories need no
token.

**The ceiling.** The interface's NuGuard controls work in real mode within
these limits, set from the environment with the same defaults as
`deploy/compose.yaml`:

- `NUGUARD_ALLOW_TOOLS`, `NUGUARD_ALLOW_POSTURE` and `NUGUARD_MAX_TIMEOUT` set
  the ceiling;
- `NUGUARD_TOOLS`, `NUGUARD_INCLUDE_POSTURE` and `NUGUARD_TIMEOUT` set the
  defaults.

**Where its files are.** Everything is in `~/.local/share/vulnframework/nuguard/`,
readable only by you:

- the API key, `api-key`, which is never printed;
- the service settings, which hold only the key's SHA-256;
- NuGuard's environment, database and log.

**Commands.**

- `scripts/nuguard-local.sh status` shows:
  - whether NuGuard is running, and its version;
  - its Semgrep;
  - the NuGuard commit, and whether that checkout has uncommitted changes.
    Results from uncommitted NuGuard work cannot be reproduced later, and
    the status says so.
- `scripts/nuguard-local.sh stop` stops NuGuard.
- To reset, stop it and delete `~/.local/share/vulnframework/nuguard/`. A new
  key is made on the next start.

**Behind a proxy.** Export the proxy and CA variables (`HTTPS_PROXY`,
`NO_PROXY`, `SSL_CERT_FILE` and so on) in the shell that runs `start` or
`run.sh`. `start` passes them to NuGuard's workers, and NuGuard's git clones
and GitHub API calls use them (NuGuard commit `0d00e7d` onwards). An older
NuGuard checkout ignored them for clones. `status` warns when a proxy is set
and the checkout lacks that fix. Not yet tried behind a real proxy.

## 7. Local auth gives full access to anything on this machine

With a database, the API serves only callers whose identity is vouched for by
an authenticating proxy, and refuses everything else. On a laptop there is no
such proxy. So in `--real` mode the interface's development server takes that
role: it sets `VULNFRAMEWORK_LOCAL_AUTH=1` and stamps every request it forwards
with **your username at the `security_owner` level**. That level gives full
access, including the detail of secret findings.

Safeguards:

- It is off unless that variable is set. `run.sh` sets it only for the
  interface process it starts, and only in `--real` mode.
- The development server refuses to start with it on unless it is bound to
  `127.0.0.1` and the API is on this machine. `vite build` and `vite preview`
  refuse it outright.
- Identity headers sent by the browser are discarded.
- Requests made by other websites in your browser get no identity, and the
  API refuses them.
- The API server itself never trusts this. It still refuses anonymous
  requests made to it directly.

What it does **not** protect against: **while it is on, any program running on
this machine that connects to `127.0.0.1:5173` gets security-owner access.** That includes the read-only Claude connector
(`vfmcp`, `USAGE.md` "Ask Claude about your findings"), which reads through
this address by design.
That includes other user accounts on a shared machine, and any local software
you would not hand your findings to. Only run it on a machine you alone use,
and stop it (Ctrl-C) when you are done browsing.

To make sure it is off:

```sh
unset VULNFRAMEWORK_LOCAL_AUTH VULNFRAMEWORK_LOCAL_AUTH_REPOS
env | grep VULNFRAMEWORK_LOCAL_AUTH    # should print nothing
```

Never add it to a shell profile. When it is on, the interface prints a
`WARNING: LOCAL AUTH IS ON` banner as it starts.

## 8. What is deliberately disabled

| Capability | Status here |
|---|---|
| Opening pull requests, automated fixes, the agentic fixer | **off**. The post-sweep pass never calls the remediation step, and no GitHub credential exists in this path. |
| Creating or updating tickets | **off**. The ticket step is never called. |
| Syncing the repository list from GitHub | **off**. You register repositories with `vfctl.sh`. |
| GitHub webhooks | **off**. No secret is configured, so no endpoint is registered. |
| AI triage narratives | **off** unless you opt in (section 4). |
| Issuing and recording immutable per-run reports | **not done** on this path. The interface generates report views on demand. |

## 9. Secrets: known fakes, allowlists, and removed secrets

Secrets always escalate to P0, and no configuration can relax that. Nothing
closes a secret finding automatically: only a human, using the commands below.

### Known-fake secrets: allowlist them, then confirm

A repository whose tests contain fabricated credentials is reported every
sweep. Tell gitleaks about them **in the repository**, with its own
configuration. Commit a `.gitleaks.toml` at the repository root:

```toml
# Fabricated credentials used by tests. Real ones anywhere else are still reported.
[extend]
useDefault = true

[allowlist]
description = "fabricated credentials in two named test fixtures"
paths = [
  '''^internal/auth/testdata/fake_credentials\.json$''',
  '''^config/settings_test\.yaml$''',
]
```

> **Allowlist exact files, never patterns.** Each path above is anchored with
> `^` and `$` and names one file. Do not allowlist a folder (`^testdata/`) or
> a pattern (`_test\.go$`): every file it matches becomes invisible to the
> ordinary scan, including a real key someone pastes into a test next year.
> The sweep would still record it as a proposal, but only a person reading
> proposals would notice. Better still, build fake credentials in test code
> at run time from parts, so no file contains a complete key and nothing
> needs allowlisting at all.

A `.gitleaksignore` file of finding fingerprints and an inline
`gitleaks:allow` comment work too.

**An allowlist is a proposal, not a fix.** Anyone with commit access can write
one, so allowlisting a secret does not close it. Each sweep also looks past
your allowlists and records which secrets are still in the files but hidden.
It never stores the secrets themselves. Each one becomes a **suppression
proposal**, in state FALSE_POSITIVE_CANDIDATE, recording:

- which mechanism hid it (`.gitleaks.toml`, `.gitleaksignore` or inline);
- which file holds that decision, and a hash of that file's content;
- the allowlist's description, if it has one;
- the run that first saw it.

Proposals are counted on the overview (**Secrets awaiting a human**) and in
every report, never only in the finding list. Review them with:

```sh
./vfctl.sh finding pending                              # everything waiting on a human
./vfctl.sh finding confirm-suppression <fingerprint>    # agree: the finding becomes SUPPRESSED
./vfctl.sh finding reject-suppression <fingerprint>     # disagree: it stays open
```

Each decision is recorded against your login, or against `-as NAME`. The
finding's timeline shows every step with its cause: proposed, escalated,
decided, withdrawn.

What happens next:

- **Nobody reviews it in time:** once a proposal is older than the secret
  window (the P0 SLA window for the repository's tier, from
  `config/calibration.yaml`), the next sweep moves it back to NEEDS_HUMAN as
  **overdue**. It can still be confirmed or rejected.
- **The allowlist entry is removed, or stops matching:** the secret comes back
  to NEEDS_HUMAN. That applies to confirmed suppressions too.
- **The same secret appears in a file the allowlist doesn't cover:** that file
  is reported as a new finding.
- **You reject a proposal:** it isn't proposed again while the allowlist
  configuration is unchanged. Changing the configuration makes a new proposal.

This was checked against the scanner image, with all three mechanisms. On this
project's own code, the `.gitleaks.toml` above hid all 145 fixture hits from
the ordinary scan, and a credential planted outside those paths was still
reported. That check used a folder and a pattern to show the mechanism works;
for your own repositories, follow the warning above and name exact files.

### Removed secrets stay open until you confirm rotation

If a complete scan no longer finds a secret and no allowlist explains it, the
finding stays open, marked **removed, rotation unconfirmed**. The sweep scans
only the current files, not git history, so a deleted secret is still in your
history and, until rotated, still valid. Removal is not remediation (VM-F-856).
These are counted on the overview and in reports too. Once the credential has
really been rotated:

```sh
./vfctl.sh finding confirm-rotation <fingerprint>
```

That closes the finding as VERIFIED (`rotation_confirmed`), recorded against
you. If the secret reappears before that, the "removed" mark is cleared.

## 10. One database across sessions, and backups

### Where your history lives

Everything the scanner has recorded, every finding, run and decision, is in
one Docker volume, `vulnframework-pgdata`. The database container
(`vulnframework-pg`) is disposable: `./run.sh --real` creates it when it is
missing and attaches the same volume, so a new session carries on the same
history. Closing Docker Desktop, restarting the Mac, or a container
disappearing loses nothing.

The history is lost only if the **volume** goes, which happens when:

- you run `docker volume rm vulnframework-pgdata` (section 11), or
  `docker volume prune` / `docker system prune --volumes` while the
  database is stopped (prune removes volumes no container is using);
- Docker Desktop's **Troubleshoot → Clean / Purge data** or **Reset to
  factory defaults** is used: both delete every volume;
- Docker Desktop is uninstalled, or the Mac is replaced without moving it.

To keep one continuous history:

- always use the defaults: do not set `VULNFRAMEWORK_PG_VOLUME` or
  `VULNFRAMEWORK_DSN` except deliberately, because a different volume or DSN
  starts an empty database;
- take a backup before anything on the list above, and regularly anyway.

The local deployment stack at https://localhost:18443 (compose project
`vf-demo`) is a **separate** database in its own volume, `vf-demo_pgdata`,
and it is the **main history**: the one to back up and keep. The real-mode
database above is for trials. To look at the archived real-mode history,
restore the archive into the real-mode database with `scripts/db.sh restore`;
the database it replaces is kept, as always.
Its settings live in `~/.config/vulnframework/demo/env`, outside the
repository. Pass them to the deploy scripts with
`VF_ENV_FILE=~/.config/vulnframework/demo/env COMPOSE_PROJECT_NAME=vf-demo`.

Its login (name `admin`) has a random password kept beside the settings in
`~/.config/vulnframework/demo/login-password`, readable only by you; the
settings file holds only its hash. Read or reset it with:

```sh
deploy/login.sh copy     # to the clipboard, never printed
deploy/login.sh show     # printed, only on a terminal
deploy/login.sh reset    # a new one; then recreate the stack:
docker compose --env-file ~/.config/vulnframework/demo/env -p vf-demo -f deploy/compose.yaml up -d
```

Neither the password nor its file belongs in the repository, a chat or a
ticket. Keep a copy in your password manager if you want one.

### Backing up and restoring

`./run.sh --real` takes a backup by itself before a newer version migrates
your database, and says where the backup is.

```sh
scripts/db.sh backup                    # the real-mode database
scripts/db.sh backup --target demo      # the local deployment stack
scripts/db.sh list   [--target demo]
scripts/db.sh restore [--target demo] FILE
```

- **Where backups go:** `~/.local/share/vulnframework/backups/`, readable
  only by you. `VF_BACKUP_DIR` changes the folder. A backup holds your
  findings, including where secrets were found but never their values,
  which are not stored. Copy the folder somewhere off the Mac to survive
  losing it.
- **Checked when made:** a backup is checked by reading it back. A backup
  that can't be read is deleted, and the command fails.
- **Safe to restore:** a restore never overwrites in place.
  - It loads the backup into a new database, checks it, and only then swaps
    the two.
  - The database it replaced is kept, renamed `vulnframework_before_<time>`,
    and the command prints how to undo the restore or free that space.
  - A backup that fails to load changes nothing.
  - It refuses while the scan worker is running; stop the app first.
- **Database running or not:** backup works either way. If it starts the
  database, it stops it again afterwards.

## 11. Cleaning up

| To remove | Command | Notes |
|---|---|---|
| Running services | Ctrl-C in the `run.sh` terminal | stops the interface, the API, and the database if `run.sh` started it |
| The database container, if `vfctl.sh` started it | `docker stop vulnframework-pg` | the data stays in the volume |
| **All stored findings and history** | `docker stop vulnframework-pg; docker volume rm vulnframework-pgdata` | **cannot be undone** without a backup: run `scripts/db.sh backup` first (section 10) |
| The scanner cache (~2 GB) | `docker volume rm vulnframework-scanhome` | the next sweep downloads everything again |
| Saved sweep records and the container build of the orchestrator | `rm -rf vulnframework/bin/real-runs vulnframework/bin/orchestrator-linux-*` | |
| The scanner image | `docker image rm vulnframework-scanner:v1` | rebuilding takes a while |
| Local auth | stop `run.sh`, then the `unset` from section 7 | it lives only in the interface process `run.sh` starts |

## 12. Troubleshooting

| Message | What to do |
|---|---|
| `The scanner image does not match …/tools.lock` | Rebuild the image (section 1). |
| `X is registered but <folder> does not exist` | Clone it into that folder, or archive it with `./vfctl.sh repo remove X`. |
| `No repositories are registered yet` | Register them (section 3). |
| `Docker is installed but not running` | Start Docker Desktop. |
| `requires the dev server to be bound to 127.0.0.1` | Something started the interface without `--host 127.0.0.1`; use `run.sh`. |
| Port already in use | `API_PORT=8090 UI_PORT=5180 ./run.sh --real ~/clones` |
| A repository's scan is `partial` | The sweep record (`vulnframework/bin/real-runs/`) and the Coverage view name the tool that failed and why. The usual causes are in section 2. |

Advanced overrides: `VULNFRAMEWORK_PG_PORT`, `VULNFRAMEWORK_PG_CONTAINER`,
`VULNFRAMEWORK_PG_VOLUME`, `VULNFRAMEWORK_KEV_URL`, `VULNFRAMEWORK_EPSS_URL`.
