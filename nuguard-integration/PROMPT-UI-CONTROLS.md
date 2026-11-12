# Claude Code prompt: let users control NuGuard from the vulnframework interface

> Paste everything below the line into Claude Code, opened at the root of `vulnerabilityAI`.
> It builds on the uncommitted work on branch `feature/nuguard-adapter` (the NuGuard adapter, migration 0018, the "AI components detected" panel). **Commit or stash that work first**, so this change can be reviewed on its own.

---

## Task

NuGuard is currently configured only by the operator, through flags on the scan worker (`-nuguard-url`, `-nuguard-tools`, `-nuguard-include-posture`, `-nuguard-timeout`). Users see its results but can't control it.

Let **security owners** control NuGuard from the report browser (`reportui/`):

- turn it on or off for the fleet, for a repository, and for an individual scan;
- choose its tools and whether posture is counted;
- see whether it's working;
- find what it found.

**Engineers** see the settings and status read-only. **Public** sees none of it.

The operator keeps a ceiling. Users choose *within* what the operator allowed, never beyond it.

Before writing code, read:

1. `PROGRESS.md`: the 2026-11-03 NuGuard entries, including "NuGuard choices".
2. `DECISIONS-NEEDED.md`: D6 (auth in front of the API), D13 and its 2026-11-03 amendment.
3. `vuln-framework-report-browser-ui-spec.md`: the VM-UI-F requirements and the conventions for absent values, role levels and write actions.
4. `vulnframework/internal/api/scans.go`: the five write gates. **Every new write follows them exactly.**
5. `vulnframework/internal/orchestrator/scanworker.go`, `internal/scan/adapters/nuguard.go`, `nuguard_flags.go`, `internal/nuguard/`.
6. `vulnframework/internal/store/store.go`: `Reconcile` and its absence rules (VM-ADR-12, VM-F-160/161).
7. `reportui/src/features/scans/ScanControls.tsx`, `features/repos/Repos.tsx`, `api/client.ts`, `api/schemas.ts`, `scripts/gen-types.mjs`, and `components/primitives`.

Cite requirement IDs in comments and commit messages the way the existing code does. Where a new requirement is needed, add it to the UI spec under a new ID; don't reuse an existing ID.

## Ground rules (non-negotiable; each needs a test)

1. **Turning NuGuard off must never resolve its findings.**
   - Today `Reconcile` verifies "findings absent from a successful scan". With user control, a scan can be complete *without* NuGuard. Then every open NuGuard finding would be absent and wrongly marked VERIFIED.
   - Make reconciliation **tool-aware**: a finding may verify only if every source that observed it ran `ok` in this scan. That includes NuGuard sub-tools: a finding from `nuguard/semgrep` needs `nuguard/semgrep` in `ToolsOK`.
   - A tool not requested in this scan is recorded as **not requested**. That is neither ok nor failed, and the findings it previously reported keep their state and are flagged not re-observed, exactly like a coverage gap (VM-F-160/161).
   - Fix this **first, as its own commit**, with tests on both store backends:
     - NuGuard off;
     - NuGuard on with fewer tools;
     - NuGuard on and the finding gone, which must still verify.
   - Check whether the same flaw already exists for other adapters. A JavaScript-only adapter set never sees Go findings, for example. Report what you find; fix only NuGuard's case unless the fix is the same code.
2. **The operator ceiling.**
   - Flags on the scan worker set what's *allowed*:
     - keep `-nuguard-url` (no URL means NuGuard is unavailable everywhere, and the UI says so);
     - add `-nuguard-allow-tools` (default `nga-rules,atlas,semgrep`);
     - add `-nuguard-allow-posture` (default true);
     - add `-nuguard-max-timeout` (default 10m).
   - The existing `-nuguard-tools`, `-nuguard-include-posture` and `-nuguard-timeout` become the **defaults** for a fleet that has never been configured in the UI. Keep them for backward compatibility, and refuse to start if a default exceeds its ceiling.
   - The worker re-checks every stored setting against the ceiling **at scan time**. If a stored value exceeds the ceiling, it's clipped, and the scan records that it was clipped and why. It is never silently honoured.
3. **Only AI tools are user-selectable.** Users may choose from `nga-rules`, `atlas` and `semgrep`. Don't offer `osv`, `grype`, `trivy`, `checkov` or `supply-chain`: the adapter maps only `kind=code` and treats unrequested kinds as `normalise_failed`, and this project's own adapters cover those areas. A change to that is a separate decision; list it in `NOW-VS-LATER.md`.
4. **Writes use the five gates in `scans.go`:** role (security_owner), same-origin, CSRF token, per-caller rate limit, strict input. Strict input means a closed JSON schema with unknown fields rejected and every value validated server-side. The client's validation is a convenience, never the check.
5. **Everything is audited.** Every settings change is a row with who, when, before, after and an optional reason, kept forever and shown in the UI. Every scan request records the NuGuard options it asked for.
6. **The API process still holds no credentials.** It never talks to NuGuard and never sees the NuGuard key or the GitHub token. Status and AI-SBOMs reach the UI only through rows the scan worker writes (see steps 3 and 6).
7. **The effective options are provenance.** Every repository scan records the NuGuard options actually used (after inheritance and clipping) next to `ToolVersions` (VM-F-202). The UI shows them wherever NuGuard results appear. A finding or inventory without its options is uninterpretable.
8. **Nothing changes when NuGuard isn't configured.** With no `-nuguard-url`, the existing `testdata/worker/no-nuguard.golden.json` still matches, API responses differ only by the new fields, and the UI shows one line, "NuGuard is not configured on this deployment", with no controls.

## Settings model

Three levels. Each resolves to the next one up when unset:

| Level | Stored in | Fields | Who changes it |
|---|---|---|---|
| Fleet | `nuguard_settings` (one current row plus history) | `enabled`, `tools[]`, `include_posture`, `timeout_s` | security owner |
| Repository | `nuguard_repo_overrides` (repo PK) | `mode` ∈ inherit, on, off; optional `tools[]`, `include_posture` | security owner |
| Scan request | new nullable columns on `scan_requests` | `nuguard` ∈ default, on, off; optional `tools[]`, `include_posture` | security owner, when requesting |

- **Resolution order:** scan request → repository → fleet → worker flag defaults. Then clip to the ceiling.
- Put resolution in **one pure Go function**, `resolveNuGuardOptions(ceiling, fleet, repo, request) (Effective, []ClipNote)`, with table tests. The API's "what would happen" preview and the worker both call it, so the two can never disagree.
- **Migration 0019 for both backends** (the next number; check `internal/store/migrations` first):
  - the settings tables, the history/audit table, and the `scan_requests` columns;
  - an `effective_nuguard` JSON column on the repository scan result;
  - a `nuguard_status` table (step 3);
  - an `ai_sbom` table (step 6).
  - Add store conformance tests for all of it.

## Work, in order

### Step 1: Tool-aware reconciliation

Ground rule 1. Its own commit. Don't continue until both backends pass.

### Step 2: Scan worker honours stored settings

- **Per repository:** resolve the effective options when the worker claims requests. Pass them on the `Job` (they contain no secret), and have the NuGuard adapter take its options from `RunOpts`, not from its constructor.
  - The adapter's `Supports` stays as it is.
  - When the effective setting is off, the adapter is **not run**, and the scan records `nuguard` as *not requested*, with the reason "off for this repository", "off for this scan" and so on.
- **Batches** ("Scan all", the daily timer): each repository resolves its own options. A batch request may carry one scan-level override that applies to every repository in it.
- **Scans not started from a request** (the daily timer, vfctl) use fleet and repository settings with no scan-level override.
- Record `effective_nuguard` (the options plus clip notes) on each repository scan result. Add a "not requested" vocabulary to `ToolsOK`/`ToolsFailed` or a third list, `ToolsNotRequested`. Pick whichever keeps the existing coverage views correct, and say which in the summary.

### Step 3: NuGuard status, published by the worker

- While NuGuard is configured, the worker checks `readyz` and `capabilities` at start-up and every 5 minutes. It writes one `nuguard_status` row with:
  - `configured`, `reachable`, `checked_at`;
  - `service_version`, `pinned_version`, `version_ok`;
  - `tools_allowed_by_service`, `ceiling`;
  - `last_error` (sanitized, the same rules as gap detail).
- No URL means one row saying `configured=false`.
- If the row is older than 15 minutes, the UI shows "status unknown: the scan worker has not reported since …", never the stale values as current.

### Step 4: API (`internal/api`)

New endpoints, registered in `openapi.go` so `npm run gen` picks them up:

| Method & path | Who | Purpose |
|---|---|---|
| `GET /v1/nuguard` | engineer+ | Status (step 3), ceiling, fleet settings, a count of repository overrides, the last 20 audit entries |
| `PUT /v1/nuguard/settings` | security owner, 5 gates | Replace fleet settings. Body: `{enabled, tools, include_posture, timeout_s, reason?}`. Reject values above the ceiling with `422` naming the field and the ceiling. |
| `GET /v1/nuguard/audit?cursor=` | engineer+ | Full settings history |
| `GET /v1/repos/{repo}/nuguard` | engineer+ | The repository override, the **effective** options now (via `resolveNuGuardOptions`), and the last 10 scans' effective options |
| `PUT /v1/repos/{repo}/nuguard` | security owner, 5 gates | Set or clear the override |
| `GET /v1/nuguard/preview?repo=&nuguard=&tools=&include_posture=` | engineer+ | What a scan would use, with clip notes. The UI calls this before submitting. |
| `POST /v1/scans`, `POST /v1/scans/all` | unchanged gates | Accept an **optional** `nuguard: {mode, tools?, include_posture?}`. Absent means today's behaviour exactly. Existing clients keep working; `{repo}` alone stays valid. |
| `GET /v1/findings?…&found_by=` | existing | Add a `found_by` filter: `nuguard`, or any adapter name |
| `GET /v1/repos/{repo}/ai-sbom/{run_id}?format=json\|cyclonedx` | engineer+ | The stored AI-SBOM (step 6), or `404` with a reason |

- Keep the existing strict-input rule. Extend the request-body decoders with the new fields only, keeping `DisallowUnknownFields`.
- Add API tests for:
  - each role;
  - each gate;
  - each `422`;
  - backward compatibility of `{repo}`-only scan requests;
  - the preview matching what the worker then does. This is an integration test through the fake NuGuard.

### Step 5: Report browser (`reportui/`)

Follow the existing design system, primitives and colour tokens. Don't add a component library. Every value that wasn't measured uses `Absent` with a reason, never zero or blank. Run `npm run gen` after the API changes; don't hand-edit `generated/schema.ts`.

1. **New page: "AI scanning (NuGuard)",** in the navigation, visible to engineer+.
   - **Status card:** configured/reachable/version (pinned vs service) / last checked. Show "status unknown" when stale (step 3).
   - **Fleet settings form** (security owners; read-only for engineers):
     - an on/off switch;
     - tool checkboxes. Options outside the ceiling are disabled, with the reason: "not allowed by the operator" or "not offered by the service".
     - a posture toggle, with the explanation "counted into the inventory, never findings";
     - a timeout, capped;
     - an optional reason field.
     - **Save** opens a confirmation summarising the change and how many repositories it affects (from the overrides count).
   - **Repository overrides table:** repository, mode, tools, posture, last changed by and when. Links to each repository page.
   - **Settings history table** from the audit endpoint.
   - A plain-language note: NuGuard adds AI code rules and an AI component inventory; dependency, IaC and container scanning stay with this project's own tools; turning it off does not close its findings.
2. **Repository page:**
   - A **NuGuard section** next to the "AI components detected" panel: the effective setting and where it comes from ("inherited from fleet", "on for this repository"), an override control for security owners, and the last 10 scans' effective options.
   - **Show the scanned commit** (`last_commit_sha`, already in the schema), short form, with the full SHA on hover and copy.
   - The AI components panel gets a **"Download AI-SBOM"** action when one is stored for that run (step 6).
3. **Scan controls** (`ScanControls.tsx`):
   - "Scan now" and "Scan all" get a small **options disclosure**, collapsed by default: NuGuard default / on / off; tools and posture when on.
   - Before submitting, call the preview endpoint and show the effective options and any clip notes.
   - The default path, one click with no options, behaves exactly as today.
   - The scan request list shows the NuGuard options each request asked for.
4. **Findings:**
   - Add a **"Found by"** filter to the findings explorer, with NuGuard as an option.
   - On a NuGuard finding's page, add a structured **NuGuard section** instead of raw annotations: rule, NuGuard sub-tool, OWASP LLM / ASI reference, MITRE ATLAS technique, enclosing function, and the effective options of the scan that last observed it.
5. **Coverage and run pages:**
   - "Not requested" NuGuard tools appear distinctly from failed ones, with the reason.
   - Clip notes appear on the run overview.
6. **Tests:**
   - vitest for each new view and control, by role;
   - the confirmation dialog;
   - disabled options with reasons;
   - stale status;
   - the not-configured single line;
   - the one-click scan path unchanged.
   - Update `scripts/capture-fixtures.mjs` and the fixtures. Run `npm run typecheck`, `npm test`, and `npm run probe:layout` if it runs headless here.

### Step 6: Stored AI-SBOM (optional within this task; do it if steps 1–5 are green)

- Add a per-scan option "Keep the AI-SBOM", default off. When it's on, the worker asks NuGuard for `include_sbom: true` and stores the SBOM JSON in `ai_sbom` (run, repo, commit, NuGuard version, size, sha256), with a size cap from a worker flag.
  - If it's over the cap, store nothing and record why.
- The API serves the stored copy. It never fetches from NuGuard, because NuGuard deletes results after its own retention period and the API holds no key.
- CycloneDX output needs a conversion. If there's no existing Go converter, serve JSON only and list CycloneDX in `NOW-VS-LATER.md`.

### Step 7: Documentation

- **`USAGE.md`:** the new page, overrides, scan options, the "Found by" filter, and how to read "not requested" versus "failed".
- **`DEPLOY.md`:** the ceiling flags and what each one lets users do.
- **`PROGRESS.md`:** a dated entry with what was and wasn't verified.
- **`FINAL-STATUS.md`:** what's real and what isn't.
- **`DECISIONS-NEEDED.md`:** add a dated note under the D13 amendment that NuGuard is now user-controllable within an operator ceiling. The amendment itself is still the owner's to accept, so don't mark it decided.
- **The UI spec:** the new VM-UI-F requirements.

## Done when

- **Go:** `go vet ./...`, `go test ./...`, and `go test -race` on `internal/store/...`, `internal/api/...`, `internal/orchestrator/...` and `internal/scan/...` are all green on both backends.
- **UI:** `npm run typecheck` and `npm test` are green.
- **`deploy/test-stack.sh`,** with the fake NuGuard, additionally asserts that:
  - a security owner turns NuGuard off for one repository, scans it, and its open NuGuard finding stays open and is flagged not re-observed;
  - an engineer can't change settings (`403`) and sees the page read-only;
  - a scan with NuGuard on and fewer tools records the clip or narrowing on the run.
- With no `-nuguard-url`, the no-NuGuard golden still matches and the UI shows only the not-configured line.
- The summary lists:
  - files changed;
  - new endpoints, tables and requirement IDs;
  - what the reconciliation audit found for non-NuGuard adapters;
  - every deviation from this prompt and why;
  - what wasn't verified (Docker, the real NuGuard image, a live GitHub run).
- Don't commit unless asked. Work on a new branch, `feature/nuguard-ui-controls`, based on `feature/nuguard-adapter`.
