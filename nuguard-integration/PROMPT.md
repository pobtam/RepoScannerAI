# Claude Code prompt: integrate the NuGuard Remote Scan API into vulnframework

> Paste everything below the line into Claude Code, opened at the root of `vulnerabilityAI`.
> A real NuGuard result is next to this file, at `nuguard-integration/sample-scan-result.json`. It's a scan of `openai/openai-quickstart-python@ec8890d` (tools nga-rules, atlas, osv; osv failed, so the job is `partial`). Use it as the first fixture.

---

## Task

Add NuGuard as a **remote scanner adapter** in `vulnframework`. The adapter calls the NuGuard Remote Scan API, which is now built in the sibling repo `../nuguard`. It turns the API's results into this project's findings and coverage gaps, without weakening any existing guarantee.

Before you write code, read these:

1. `README.md`, `FINAL-STATUS.md`, `PROGRESS.md`
2. **`DECISIONS-NEEDED.md` §D13**, and the "Phase 3 evaluation: NuGuard as the AI scanner" section of `PROGRESS.md`
3. `vuln-framework-architecture-design.md` §5 (fingerprints), §8 (scan worker, adapters, tool matrix); `vuln-framework-functional-requirements.md` VM-F-1xx and VM-F-2xx
4. The NuGuard contract:
   - `../nuguard/documentation/developer-specs/remote-scan-api.md` (the spec)
   - `../nuguard/documentation/docs/remote-api.md` (the user guide)
   - **`../nuguard/nuguard/service/openapi.json`, which is the source of truth for every field name and enum.** Where the spec and `openapi.json` disagree, follow `openapi.json` and note the difference.

Cite requirement IDs (VM-F-…, VM-AD §…) in code comments and commit messages the way the existing code does.

## Ground rules (non-negotiable; each needs a test)

These restate this project's own rules as they apply to a remote tool:

1. **A scanner that didn't run is a coverage gap, never a clean result** (VM-F-204/205/211). A NuGuard job that is `partial`, `failed`, `cancelled` or `expired`, any NuGuard `tool_runs[]` entry that isn't `ok`/`not_applicable`/`disabled`, a transport error, a timeout, or a version mismatch must each produce a `CoverageGap` with the correct `Owner` (VM-F-214). None of them may yield an empty finding list that looks clean.
2. **`Normalize` stays a pure function of bytes** (VM-AD §8.4). `Run` does all the HTTP. `Normalize` parses the stored `ScanResult` JSON and nothing else. Fixture tests go under `testdata/fixtures/nuguard/` and use the existing golden/shape/meta conventions in `internal/scan/adapters/fixtures_test.go`.
3. **Fingerprints are this project's own.** Compute them from `RawFinding` through the existing `internal/fingerprint` package. Never use NuGuard's `fingerprint` as identity; keep it only as a non-determining annotation (`Annotations["nuguard.fingerprint"]`). Line numbers are never part of identity (VM-F-102, VM-ADR-04).
4. **Pinned and recorded** (VM-F-202). Add `tool nuguard <version>` to `config/tools.lock`. If the result's `provenance.nuguard_version` differs from the pin, that's a coverage gap (`cause: version_mismatch`, owner platform), not silently accepted output. Record `nuguard_version`, `rulepack_sha256` and `image_digest` in `Result.ToolVersions`, for example under the keys `nuguard`, `nuguard/rulepack` and `nuguard/image`.
5. **Credentials.**
   - The GitHub token reaches NuGuard only in the `github_token` body field, over HTTPS (or loopback).
   - It must never appear in `RunOpts`, `Job`, `RawOutput`, `Raw`, logs, error text, gaps, the store or reports.
   - The NuGuard API key gets the same treatment, and is sent only as `Authorization: Bearer`.
   - Take both through a `func() (string, error)`, the pattern `gh.TokenClient.Token` already uses, so neither is a struct field that `%+v` could print.
   - Reuse the existing redaction helpers (`redactArgs` and similar) for error text.
   - Use the same read-only fine-grained token the worker already holds (VM-F-206: no write credential).
6. **Same commit.** NuGuard must scan exactly the commit the other adapters scanned (see step 3). If `job.commit_sha` in the result differs from the expected SHA, raise a gap with `cause: commit_mismatch` and drop the findings.
7. **Respect D13.** NuGuard enters as an *AI code-rule and inventory* signal, not as a replacement for this project's own Phase 3 rules, and it is **off unless configured**. Don't change D13's text; add a dated amendment (step 8) for the owner to accept.

## What the NuGuard API gives you (summary; verify against `openapi.json`)

- `POST /v1/scans` with `{repo_url, ref, github_token, options, client_reference, callback_url?}` returns `202 ScanJob`.
  - Supports the `Idempotency-Key` header and `Prefer: wait=N` (N ≤ 120).
  - `options`: `tools`, `min_severity`, `include_sbom`, `include_posture`, `network`, `use_llm`, `subpath`.
- `GET /v1/scans/{id}` returns `ScanJob`: `status` ∈ queued, running, succeeded, partial, failed, cancelled, expired; `phase`; `commit_sha`; `error: ProblemDetail{code,…}`.
- `GET /v1/scans/{id}/result` returns `ScanResult`, or `409` until it's terminal, or `410` once expired. The `ScanResult` contains:
  - `provenance{nuguard_version, rulepack_sha256, image_digest, tools[], options_effective, llm_used}`;
  - `coverage{tool_runs[{tool, version, status, findings, reason}], gaps[]}`;
  - `findings[{fingerprint, rule_id, source_tool, kind, severity, title, description, locations[{path, start_line, end_line, symbol}], owasp_llm_ref, owasp_asi_ref, mitre_atlas_technique, references, remediation, raw}]`;
  - `inventory{node_counts, edge_count, frameworks, model_providers}`;
  - `result_sha256`.
- `kind` ∈ code, posture, dependency, iac, container, supply_chain.
- `POST /v1/scans/{id}/cancel`, `GET /v1/readyz`, `GET /v1/capabilities`.
- Job error codes:
  - `repo_not_found_or_no_access`, `auth_failed`, `ref_not_found`
  - `repo_too_large`, `clone_timeout`, `clone_failed`
  - `subpath_not_found`, `sbom_failed`, `analysis_crashed`
  - `job_timeout`, `worker_lost`, `credential_unavailable`
- `credential_unavailable` and `worker_lost` release the idempotency key, so a retry with the same key is allowed.

## Work, in order

### Step 1: API client package `internal/nuguard/`

- **Go types** mirroring the `openapi.json` schemas this project uses: `ScanCreateRequest`, `ScanOptions`, `ScanJob`, `ScanResult`, `ScanFinding`, `FindingLocation`, `Coverage`, `ToolRun`, `Provenance`, `InventorySummary` and `ProblemDetail`, with enum constants for the statuses and kinds.
  - Decode strictly: unknown **enum values** are errors. New **fields** are tolerated by the client but caught by the fixture shape test.
  - Add a test that loads `../nuguard/nuguard/service/openapi.json`, when present, and checks that every enum value the Go code knows about still exists. Skip the test if the file is absent.
- **`Client`** with:
  - `BaseURL`
  - `APIKey func() (string, error)`
  - `HTTP *http.Client`, with bounded timeouts. Refuse plain `http://` unless the host is loopback.
  - `Submit`, `Get`, `Result`, `Cancel`, `Ready` and `Capabilities` methods.
- **Polling:** use `Prefer: wait=…` on submit, then poll `Get` with capped exponential backoff and jitter, bounded by `ctx`. On `ctx` cancellation, call `Cancel` best-effort with a fresh short-timeout context, then return `ctx.Err()`.
- **Idempotency key:** `vf-<runID>-<sha256(repo+"@"+commit)[:16]>`. Set `client_reference` to the run ID.
- **Retries:** on `429` and `503`, honour `Retry-After`. On a terminal `credential_unavailable` or `worker_lost`, resubmit once with the same key.
- **Fake server** `internal/nuguard/nuguardfake` (`httptest`), modelled on `internal/gh/ghfake`. It serves canned `ScanResult` fixtures and can be scripted for each failure mode.

### Step 2: The adapter `internal/scan/adapters/nuguard.go`

Implement `scan.Adapter`:

- `Name() = "nuguard"`. `Version()` is the tools.lock pin.
- `Supports`: true for `go` and `javascript` (the current language set). See step 6 for Python.
- **`Run(ctx, dir, opts)`:**
  - Needs the repository and commit, which `RunOpts` doesn't carry today. Add **non-secret** fields `Repo string` and `CommitSHA string` to `scan.RunOpts`, set by `Worker.Scan` / the dispatchers (step 3). Never add a credential to `RunOpts`.
  - Build the request:
    - `repo_url = https://github.com/<repo>`, or the configured GitHub host;
    - `ref = opts.CommitSHA`; if it's empty, return an error, which becomes an execution gap;
    - `options`:

      ```
      tools:           [nga-rules, atlas, semgrep]   # configurable
      network:         false
      include_posture: false                          # configurable
      include_sbom:    false
      min_severity:    low
      use_llm:         false
      ```

  - **Why these defaults:** this project's own adapters already cover dependencies, IaC and containers, so NuGuard's OSV/Grype/Trivy/Checkov would only duplicate findings, need network and add alias churn. Posture findings were found in PROGRESS.md not to tell safe code from vulnerable code. Both are config switches, not hard-coded.
  - Return `RawOutput{Tool: "nuguard", ToolVersion: pin, Stdout: <ScanResult JSON as received>, ExitCode: 0 for succeeded, 1 for partial}`.
  - A job that ends `failed`/`cancelled`/`expired` returns a typed error carrying the job error `code`. Never put the token or URL userinfo in it.
- **Sub-tool gaps:** `Worker.Scan` currently knows only "the adapter ran or didn't". Add an **optional** interface in `internal/scan`, so nothing downstream changes for other adapters (VM-NF-502):

  ```go
  // GapReporter is implemented by adapters that wrap several tools and can
  // lose some of them while still producing valid output (VM-F-211).
  type GapReporter interface {
      Gaps(out RawOutput) ([]CoverageGap, error)   // pure, like Normalize
  }
  ```

  `Worker.Scan` calls it after a successful `Normalize`, appends the gaps, and reclassifies the outcome:
  - Any sub-tool gap makes the scan `partial`.
  - Name sub-tools `nuguard/<tool>` in `ToolsOK`/`ToolsFailed`/`CoverageGap.Tool`, so the report shows which of NuGuard's tools was lost.
  - Add worker tests for these cases.
- **Error code → gap cause and owner** (from `ProblemDetail.code` or the typed error):

  | NuGuard condition | Gap `Cause` | `Owner` |
  |---|---|---|
  | transport error, `5xx`, `not_ready`, `job_timeout`, `worker_lost`, `analysis_crashed`, `sbom_failed` | `execution_failed` | platform |
  | `auth_failed`, `repo_not_found_or_no_access`, `credential_unavailable` | `credential_failed` | platform |
  | `ref_not_found`, `clone_failed`, `clone_timeout` | `fetch_failed` | platform |
  | `repo_too_large` | `repo_too_large` | repo |
  | `tool_runs[].status` = failed / timeout / skipped | `tool_failed` / `tool_timeout` / `tool_skipped` | platform |
  | `provenance.nuguard_version` ≠ pin | `version_mismatch` | platform |
  | `job.commit_sha` ≠ expected | `commit_mismatch` | platform |
  | result JSON unparseable / unknown enum | `normalise_failed` (existing) | platform |

  Reuse an existing cause string where one already means the same thing; check `internal/store/coverage.go` and the report templates for the existing vocabulary before inventing new causes.
- **`Normalize(out)`** maps each `ScanFinding` to `model.RawFinding`, but only for `kind == code`:

  | RawFinding field | Value |
  |---|---|
  | `Category` | `model.CategoryCode` |
  | `Tool` | `"nuguard"` |
  | `RuleID` | `rule_id`, prefixed `nuguard.` only if needed to avoid a collision with the local semgrep adapter's rule IDs (decide and document) |
  | `File` | `locations[0].path` via `relPath` (must already be repo-relative; reject absolute paths as `normalise_failed`) |
  | `Function` | `locations[0].symbol`, when present |
  | `Line` | `locations[0].start_line`, display only |
  | `Classification.Severity` | `severity`, mapped with `severityFromBand` |
  | `Reachable` | same convention as the existing semgrep adapter |
  | `DepClass` | `model.DepNotApplicable` |
  | `Description` | through `model.SafeDescription` |
  | `AdvisoryURL` | first of `references` |
  | `Annotations` | `nuguard.fingerprint`, `nuguard.source_tool`, `owasp_llm_ref`, `owasp_asi_ref`, `mitre_atlas_technique` |
  | `Raw` | the `ScanFinding` with its `raw` field dropped, to keep the store small; the full result stays in `RawOutput` |

  Other kinds:
  - `posture` findings, if included, are **not** findings. Count them into the inventory (step 4).
  - Any other `kind`: skip it and count it. If the adapter receives kinds it didn't request, that's a `normalise_failed` gap, because the request/response contract was broken.
  - Then run `dedupe` and `sortFindings`, like the other adapters.
- Update the `ResidualWarning(CategoryCode)` text, or add a NuGuard-specific variant: it currently says no pinned scanner reports the enclosing symbol, which stops being true for NuGuard findings that carry `symbol`. Don't change fingerprints of existing findings.
- Register the adapter in `adapters.All` **only when configured** (step 5). The registry stays deterministic and sorted.

### Step 3: Make every adapter scan the same commit

- Today `DownloadDispatcher.fetch` downloads the tarball with `ref ""` (the default branch) and no SHA is recorded.
- Resolve the default branch's HEAD SHA through the read-only GitHub client *before* downloading. Add a method on `gh.TokenClient`, using the existing read-only transport. Then download the tarball **at that SHA** and set `job.Opts.CommitSHA` and `job.Opts.Repo`.
- Do the same for `LocalDispatcher` and `cmd/scanworker`:
  - add a `-commit` flag;
  - if it's missing, read HEAD from `.git` in `dir`;
  - if neither exists, the nuguard adapter alone records an execution gap.
- Record the scanned commit on `scan.Result` (`CommitSHA string \`json:"commit_sha"\``) so reports can quote it. This is useful beyond NuGuard.
- Extend `internal/gh/ghfake` to serve the commit lookup. Update the dispatcher tests and the `worker_e2e_test.go` path.

### Step 4: AI inventory

- Add `AIInventory *AIInventory \`json:"ai_inventory,omitempty"\`` to `scan.Result`, containing:
  - `node_counts`, `edge_count`, `frameworks`, `model_providers`;
  - `posture_observations` (the count by `rule_id`, when posture was included);
  - `source: "nuguard <version>"`.
- Fill it from a pure function over the stored result bytes, like `Normalize`.
- Follow `Result` to where it's persisted and reported (`internal/store`, `internal/report`):
  - If run documents are stored as JSON, the field rides along. Show it in the report as **"AI components detected"**, labelled as an inventory signal, not a finding.
  - If persisting needs a schema change, add a migration for **both** the Postgres and memory backends, with conformance tests.
- If NuGuard didn't run or its inventory is missing, the report says **"not measured"**, never zero (the same tri-state discipline as EPSS/KEV, OQ-AUDIT-01).

### Step 5: Configuration, wiring, deployment

- Add flags to `cmd/orchestrator` and `cmd/scanworker`: `-nuguard-url`, `-nuguard-tools`, `-nuguard-include-posture` and `-nuguard-timeout`.
  - Read the API key from env `VULNFRAMEWORK_NUGUARD_API_KEY`.
  - With no URL, the adapter isn't registered, and the run's tool matrix says so.
- **Start-up check:** with a URL configured, call `GET /v1/readyz` and `GET /v1/capabilities`.
  - Refuse to start if the service's `nuguard_version` ≠ the pin, or the configured tools aren't in `tools_allowed`.
  - If it's simply unreachable, log a warning and start; scans then get gaps. That matches how other tool failures behave.
- `deploy/compose.yaml`: add a `nuguard` service in the `worker` profile, on the internal network only (no published port), with egress to `github.com`, `api.github.com` and `codeload.github.com`.
  - Its `nuguard.yaml` `service:` section binds non-loopback, so it needs TLS or `trust_proxy: true`; pick and justify one.
  - Add the key to `deploy/env.example`, and wire the scanworker's flags.
  - Load the key the way `deploy/scanworker.sh` loads the GitHub token, and document `docker inspect` exposure the same way.
- Update `deploy/test-stack.sh` so the local stack runs the fake NuGuard alongside the fake GitHub, and asserts these three cases:
  - a scan with a NuGuard code finding;
  - a NuGuard `partial` recorded as a gap;
  - NuGuard down → gap, scan otherwise complete.

### Step 6 (optional; do it only if steps 1–5 are green and you have time)

- Add `LangPython` detection to `rootLanguages` (`pyproject.toml`, `requirements*.txt`, `setup.py`), and let only the nuguard adapter `Support` it.
- A Python-only repository, previously "no adapter applies", would then be scanned by NuGuard alone. The result **must** carry a gap saying that no dependency, secret or config scanner covers Python in the pinned tool set. Don't present it as a full scan.
- Put this behind `-nuguard-python` (default off), and list it in `NOW-VS-LATER.md`.

### Step 7: Tests

Each ground rule needs at least one test. Minimum set:

- **Fixtures** `testdata/fixtures/nuguard/`:
  - `quickstart-partial.json`, from `nuguard-integration/sample-scan-result.json`, with `.meta.json` (`captured_from`: NuGuard 0.9.15 service, `openai/openai-quickstart-python@ec8890d101bdc17d66512d94a76b5e7131d188a1`, 2026-11-03), `.golden.json` and `.shape.txt`;
  - a hand-made `ai-code.json` with `kind=code` findings, symbols and multiple locations;
  - `empty-succeeded.json`.
  - All of them go through the existing golden/shape tests.
- **Adapter:** each row of the error→gap table; version mismatch; commit mismatch; unrequested kind; absolute path rejected; posture excluded from findings but counted in the inventory; token absent from every output.
  - For the token check, fuzz the error paths with a recognisable token and search all of `RawOutput`, the gaps, the logs and the stored result.
- **Client:** idempotent resubmit; `Retry-After`; cancel on `ctx` done; `Prefer: wait`; strict enums; refusal of plain http to a non-loopback host.
- **Worker:** `GapReporter` makes the outcome `partial`; other adapters are unaffected (run the existing worker tests unchanged).
- **Dispatcher:** the tarball is fetched at the resolved SHA; `CommitSHA` is propagated.
- **Fingerprint stability:** the same fixture with shifted line numbers gives the same fingerprints.
- **E2E (opt-in):** under env `VF_NUGUARD_E2E=1` with `VF_NUGUARD_URL` and `VF_NUGUARD_API_KEY`, scan the pinned public repo twice and assert identical fingerprints and identical `result_sha256`.

Run `go vet ./...`, `go test ./...` and `go test -race ./internal/scan/... ./internal/nuguard/... ./internal/orchestrator/...`, plus `deploy/test-stack.sh` if Docker is available. If it isn't, say so in the summary.

### Step 8: Documentation

- `DECISIONS-NEEDED.md`: append **"D13 amendment (proposed 2026-11-03, awaiting owner)"**. It should say:
  - NuGuard's Remote Scan API (with the upstream fixes P1–P6) is added as an opt-in adapter for AI code rules and inventory only;
  - the defaults;
  - what was re-evaluated: the six repaired Semgrep rules and the false-clean fix;
  - what stays unchanged: this project's own Phase 3 rules remain planned.
  - Don't edit the original D13 text.
- `PROGRESS.md`: a dated entry with commits and what was and wasn't verified.
- `DEPLOY.md`: a NuGuard section covering deployment, key generation (`nuguard serve keygen`), the egress list, and the fact that the NuGuard image must be built and `readyz`-checked before enabling.
- `FINAL-STATUS.md`: add NuGuard to "what is real / what is not".
- `vuln-framework-architecture-design.md` §8.2 tool matrix: add the row, marked opt-in.
- `NOW-VS-LATER.md`: step 6 if not done; webhooks instead of polling; `github_token_ref` once NuGuard supports it.

## Known upstream issues to account for (in `../nuguard`, not this repo)

- **Proxy bug:** `nuguard/sbom/extractor/git_clone.py` `_INHERITED_ENV` drops `HTTPS_PROXY`/CA variables, so the service can't clone behind an egress proxy. If it's not fixed upstream yet, document it in `DEPLOY.md` as a blocker for proxied deployments. Don't work around it in Go.
- **Untested image:** the NuGuard Docker image has never been built or tested. Don't claim the compose stack works until `deploy/test-stack.sh` passes with the real image.
- **`options_effective.tools`:** the service returned `null` here even though the server limited the tools. Use `coverage.tool_runs` as the authority for which tools ran, not `options_effective`.

## Done when

- `go test ./...` is green, with the new tests above.
- No existing golden fixture changed. If one had to change, explain why.
- With no `-nuguard-url`, a run's output is byte-for-byte what it was before, apart from the new `commit_sha` field. Prove this with a test.
- The summary lists:
  - files changed;
  - new causes added to the gap vocabulary;
  - any deviation from this prompt and why;
  - what was not verified (Docker, the real NuGuard image, a live GitHub run).
- Don't commit unless asked. Leave the work on a new branch `feature/nuguard-adapter`.
