# Scanning your real repositories (read-only, on this machine)

This guide is for running the framework against your own clones on your own
machine: scan them, keep the results in a local PostgreSQL database, score and
route the findings, and browse them in the web interface.

It is **read-only**. Nothing in this path writes to GitHub, opens a pull
request, comments, or creates a ticket. Your clones are mounted into the scan
container read-only.

The demonstration (`./run.sh` with no options) is unaffected and still needs
none of this.

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

**What the states mean here.** Findings are scored and routed, but nothing
acts on the routing:

- A finding routed to `open_ticket` or `escalate_p0` sits in **NEEDS_HUMAN**.
- One routed to `auto_remediate` stays **TRIAGED**, with the reason recorded.

**Every secret finding is routed to `escalate_p0`.** No configuration can change
this; see section 9 for known-fake test credentials.

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

These stay on this machine:

- your source code;
- your git history;
- your secrets (gitleaks runs locally and redacts what it reports);
- the gosec and staticcheck analyses;
- the database.

No GitHub API is called. Cloning is something you do yourself.

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
this machine that connects to `127.0.0.1:5173` gets security-owner access.**
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

## 9. Known-fake secrets in test fixtures

Secrets always escalate to P0. Unlike other findings, that cannot be relaxed by
configuration. So a repository whose tests contain fabricated credentials is
reported every sweep. The framework has no "mark as false positive" command
yet, so silence them **in the repository**, with gitleaks' own config. Commit a
`.gitleaks.toml` at the repository root:

```toml
# Fabricated credentials used by tests. Real ones anywhere else are still reported.
[extend]
useDefault = true

[allowlist]
description = "test fixtures"
paths = [
  '''_test\.go$''',
  '''^testdata/''',
]
```

This was checked against the scanner image. On this project's own code it
removed all 145 fixture hits, and a credential planted outside those paths
was still reported. Keep the paths narrow: anything allowlisted is invisible,
including a real key that someone later pastes into a test.

For individual findings rather than whole paths, gitleaks also reads a
`.gitleaksignore` file of finding fingerprints at the repository root.

After the change is in your clone, the next **complete** scan of that
repository no longer observes those findings and moves them to VERIFIED. They
are resolved, not deleted, so their history stays visible.

## 10. Cleaning up

| To remove | Command | Notes |
|---|---|---|
| Running services | Ctrl-C in the `run.sh` terminal | stops the interface, the API, and the database if `run.sh` started it |
| The database container, if `vfctl.sh` started it | `docker stop vulnframework-pg` | the data stays in the volume |
| **All stored findings and history** | `docker stop vulnframework-pg; docker volume rm vulnframework-pgdata` | **cannot be undone** |
| The scanner cache (~2 GB) | `docker volume rm vulnframework-scanhome` | the next sweep downloads everything again |
| Saved sweep records and the container build of the orchestrator | `rm -rf vulnframework/bin/real-runs vulnframework/bin/orchestrator-linux-*` | |
| The scanner image | `docker image rm vulnframework-scanner:v1` | rebuilding takes a while |
| Local auth | stop `run.sh`, then the `unset` from section 7 | it lives only in the interface process `run.sh` starts |

## 11. Troubleshooting

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
