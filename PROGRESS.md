# PROGRESS

Unattended run on `real-repos`, started 2026-10-13. If a session restarts,
read this file first and resume from "Next".

## Current

- **Priority changed by you (2026-10-13):** build only what a bare-minimum
  NON-LOCAL demo needs, before resuming Phase 1. See "Demo track" below.
- **Phase:** demo track, step D3 (GCP as code, DEPLOY.md)
- **Next:** Terraform for the VM, startup script, sweep timer; validate via the terraform image

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
- **Test stacks leave their Docker volumes** (`vf-d2test_*`,
  `vf-stacktest_*`): the rules forbid deleting volumes. Remove them with
  `docker volume rm $(docker volume ls -q | grep -E '^vf-(d2test|stacktest)_')`.
- **The smoke test's throwaway database is deleted after each run.** It is
  created by the script, in a temp folder, never a named Docker volume; the
  "never delete databases" rule is about yours.

## Open problems

(none)

## Only you can do

- Push `real-repos` and `main` (origin is set to
  https://github.com/pobtampal/vulnerabilityAI.git). The fake keys are gone
  from the tree, but OLD commits still contain them, so push protection will
  still block until you allow them via the two unblock URLs from the first
  attempt (or rewrite history yourself). First commit with the pair:
  `d7c213b`; also in `1620f74`, `27016ab`, `de01629`, `9badcb0`.
