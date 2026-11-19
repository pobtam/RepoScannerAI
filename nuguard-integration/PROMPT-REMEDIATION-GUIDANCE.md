# Claude Code prompt: remediation guidance for NuGuard findings (NuGuard's advice and our own playbook)

> Paste everything below the line into Claude Code, opened at the root of `vulnerabilityAI`.
> It builds on the NuGuard work on `feature/nuguard-adapter` and `feature/nuguard-ui-controls`. **Commit or stash the current branch's uncommitted changes first**, so this change can be reviewed on its own.

---

## Task

NuGuard findings currently reach users with no advice on how to fix them. Add two sources of remediation guidance, each clearly labelled for what it is:

1. **NuGuard's own guidance.**
   - Every NuGuard `ScanFinding` carries a `remediation` string. It's generic, per-rule advice, for example "Add authentication middleware … to 'Chat'". The adapter currently drops it.
   - Keep it, store it, and show it labelled **"NuGuard guidance: generic, not validated"**.
   - It's untrusted tool output.
2. **Our own remediation playbook.**
   - A versioned, human-reviewed file with one fix recipe per NuGuard rule, owned by this team.
   - It contains: what the rule detects, why it matters, concrete steps, a language-specific before/after example, how to verify the fix, and references.
   - Every example must be **proven**: the "before" triggers the NuGuard rule, and the "after" doesn't.
   - Entries you write start as **draft** and are shown as such until a person on the team marks them reviewed.

Out of scope: automatic fixes, pull requests, feeding guidance to the fixing agent, and changing policy routing. Those belong to Phase 8a (`REMEDIATION-DESIGN.md`). List them in `NOW-VS-LATER.md` (step 7).

Before writing code, read:

1. `REMEDIATION-DESIGN.md`, especially §4.2, the "deterministic first" principle and the VM-F-309 untrusted-input rule.
2. `PROGRESS.md`: the NuGuard entries from 2026-11-03 on.
3. `vulnframework/internal/scan/adapters/nuguard.go`: `Normalize`, `annotate` (annotation keys are version-tagged, `nuguard/<version>/<key>`), and how `RuleID` is formed.
4. `vulnframework/internal/model/finding.go`: `Finding`, `RawFinding.Annotations` ("nothing here may reach Classification"), and `Triage.Remediation`, which is the existing **model-written** remediation text.
5. `vulnframework/internal/model/describe.go` (`SafeDescription`), `internal/tracker/spec.go` (ticket body), `internal/api/findings.go` and `dto.go`, `reportui/src/features/detail/FindingDetail.tsx`.
6. NuGuard's rule sources in the sibling repo: `../nuguard/nuguard/analysis/plugins/semgrep_rules/ai-security.yaml`, `generic-security.yaml` and `java-ai-security.yaml`, and the NGA/ATLAS rule tables in `../nuguard/nuguard/analysis/plugins/nga_rules.py` and `atlas_annotator.py`.
   - Also read `_projection()` in `../nuguard/nuguard/analysis/static_analyzer.py` to see which rules can come back as `kind=code`. Only `kind=code` findings become findings here.

Cite requirement IDs the way the existing code does. Add new requirements to the functional-requirements document under new IDs; don't reuse an existing ID.

## Ground rules (each needs a test)

1. **Three sources, never blended.**
   - A finding can show up to three kinds of remediation text:
     - **our playbook** (team-owned; draft or reviewed);
     - **NuGuard guidance** (tool output; generic);
     - **triage** (model-written; the existing `Triage.Remediation`).
   - Each is stored separately, labelled with its source and version wherever it appears (UI, API, tracker ticket), and never merged into one string.
   - Nothing may overwrite another source's text.
2. **NuGuard's text is untrusted data** (VM-F-309).
   - Pass it through `model.SafeDescription` and cap it at 2,000 characters, with truncation marked.
   - The UI renders it as plain text, never markdown or HTML.
   - In tracker tickets it goes inside a clearly delimited quote block, after escaping.
   - Test it with hostile input: HTML, markdown links, a fake "ignore previous instructions", control characters, and 10 KB.
3. **Guidance never changes identity, classification or priority.** Fingerprints, severity, score and routing are byte-identical with and without guidance. Prove this with a golden test.
4. **The playbook is change-controlled.**
   - It lives in the repository as `config/remediation-playbook.yaml` and is changed by code review. The UI has no edit screen.
   - Its SHA-256 and `version` are recorded wherever its content is shown, like `tools.lock`.
5. **Draft is visible as draft.**
   - An entry with `status: draft` is shown with a "Draft: not yet reviewed by your team" badge.
   - Only `status: reviewed` entries may carry `reviewed_by` and `reviewed_at`, and the loader rejects a reviewed entry without them.
   - **Mark every entry you write as `draft`. Never mark anything reviewed yourself.**
6. **Examples are proven against the actual rule.** For every playbook example, a test runs NuGuard's Semgrep rule on the before and after files. Before must match and after must not. See step 4.
7. **Nothing changes for non-NuGuard findings** or with NuGuard not configured. The existing goldens still match.

## Work, in order

### Step 1: Keep NuGuard's guidance (adapter)

- In `Normalize`, when `ScanFinding.remediation` is non-empty, store it as the annotation `nuguard/<version>/remediation`, after `SafeDescription` and the 2,000-character cap. That's an observation, matching how the other NuGuard fields are recorded, and needs no migration.
  - If the annotation storage has a size limit, find it and respect it.
  - If annotations are the wrong place for text this long, say so and add a dedicated column on the observation instead, with a migration for both backends. Explain the choice in the summary.
- The fixture goldens under `testdata/fixtures/nuguard/` will change, because the annotation is new. That's an expected value change: update them with `-update` and explain it in the summary. The **shape** tests must not need `-update-shapes`, because `remediation` is already a known field. If they do, stop and report it.
- Add tests: guidance present, absent, hostile, over-long; and identity unchanged (ground rule 3).

### Step 2: The playbook format and loader (`internal/playbook/`)

`config/remediation-playbook.yaml`:

```yaml
version: 1                     # bump on every content change
entries:
  - tool: nuguard              # matches RawFinding.Tool
    rule_id: nuguard-eval-on-llm-output   # exactly as stored in RawFinding.RuleID (check the adapter's prefixing)
    status: draft              # draft | reviewed
    reviewed_by: ""            # required when reviewed
    reviewed_at: ""            # RFC 3339 date, required when reviewed
    title: Model output is executed as code
    detects: >                 # what the rule actually matches, from its pattern
      ...
    why: >                     # the risk, in plain language; OWASP LLM reference
      ...
    fix_kind: code_change      # code_change | config_change | architectural
    steps:
      - ...
    examples:                  # one per language the rule covers
      - language: python
        before: testdata/playbook/nuguard-eval-on-llm-output/before.py
        after:  testdata/playbook/nuguard-eval-on-llm-output/after.py
    verify:
      - Re-scan: the finding no longer appears on the next scan of the fixed commit.
      - Add a test that ...
    references:
      - https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/
    effort: small              # small | medium | large
  - tool: nuguard
    rule_id: nuguard-langchain-verbose-true
    status: no_playbook        # an explicit, reasoned gap
    reason: >
      ...
```

- **Loader:** a strict decode with unknown fields rejected and a closed set of enums.
  - It verifies that the `(tool, rule_id)` pairs are unique and that every example file exists.
  - It reads the example files into memory at load time; the API never reads files per request.
  - It computes the SHA-256 over the YAML and all example files.
  - A `Lookup(tool, ruleID)` returns the entry, or a typed "none" with the reason (`no_playbook` reason, or "rule not in playbook").
- **Example choice:** choose the example whose `language` matches the finding's file extension. If there's no match, return them all and say none matches the file.
- **Wiring:** load it in `cmd/apiserver` and `cmd/orchestrator` (for tracker tickets) from a `-playbook` flag, defaulting to `config/remediation-playbook.yaml`.
  - A malformed playbook is a **start-up error**.
  - A missing file is allowed: the UI says "no remediation playbook configured".
  - Copy it into the images the same way `policy.yaml` is: check `deploy/build.sh` and the Dockerfiles.
- **Tests:** the loader's validation matrix, lookup, extension matching, and that the hash changes when an example file changes.

### Step 3: Write the playbook content (all entries as `draft`)

- **Cover every NuGuard rule that can produce a `kind=code` finding.** At the time of writing, that's NuGuard's Semgrep rules:
  - **`ai-security.yaml`** (17):
    - `nuguard-llm-prompt-injection-fstring`, `nuguard-llm-direct-user-input`, `nuguard-hardcoded-api-key`, `nuguard-openai-key-in-code`
    - `nuguard-eval-on-llm-output`, `nuguard-sql-injection-via-llm`, `nuguard-llm-ssrf-requests`, `nuguard-no-output-length-limit`
    - `nuguard-langchain-verbose-true`, `nuguard-pickle-model-load`
    - `nuguard-go-llm-prompt-injection-sprintf`, `nuguard-go-hardcoded-api-key`, `nuguard-go-llm-missing-context-timeout`, `nuguard-go-llm-insecure-tls`
    - `nuguard-csharp-llm-prompt-injection-interpolation`, `nuguard-csharp-llm-unsanitized-input`, `nuguard-csharp-llm-unvalidated-output`
  - **`generic-security.yaml`** (10):
    - `nuguard-js-sql-injection`, `nuguard-js-command-injection`, `nuguard-js-path-traversal`
    - `nuguard-js-xss-dangerously-set-inner-html`, `nuguard-js-xss-unescaped-response`
    - `nuguard-js-insecure-eval`, `nuguard-js-insecure-deserialization`, `nuguard-js-weak-hash-for-password`
    - `nuguard-js-hardcoded-secret`, `nuguard-js-open-redirect`
  - **`java-ai-security.yaml`** (4): `java-ai-prompt-injection`, `java-ai-llm-response-deserialization`, `java-ai-jackson-default-typing`, `java-ai-unvalidated-controller-response`
  - **Any NGA/ATLAS rule** that `_projection()` can turn into `kind=code`.
  - Re-derive this list from `../nuguard` rather than trusting it. Add a test that fails when NuGuard's rule files contain a code rule with no playbook entry and no `no_playbook` reason. Skip the test, with a message, when `../nuguard` isn't present.
- **Hardcoded secrets:** for the hardcoded-key and hardcoded-secret rules, follow this project's secret handling. The fix is **rotation first**, then removal and moving the value to a secret store. Use the same rotation checklist wording the project already uses for secret findings (VM-F-407). The example must show a placeholder, never anything key-shaped.
- **Write each entry from the rule itself:** read its `pattern`, `pattern-not`, `languages` and `message`. The steps must fix what the rule actually detects, not a generic version of the problem.
  - Prefer the smallest correct change: parameterised queries, `ast.literal_eval`/a parser or an allowlist instead of `eval`, separating user content into its own message instead of interpolating it into the system prompt, an explicit `max_tokens`, a context with a timeout, verified TLS, `safetensors` instead of pickle.
  - Use `architectural` only where no local code change fixes it, and say what the architectural change is.
- **Examples:** for each language the rule's `languages` covers, write a minimal, self-contained `before` and `after` under `vulnframework/testdata/playbook/<rule_id>/`. Use realistic but invented code, with no real keys, URLs or company names.
- **Plain language** in `title`, `why` and `steps`, for an engineer who has never heard of NuGuard.

### Step 4: Prove the examples

- **The proof test** `internal/playbook/rules_test.go`:
  - For each entry, it runs Semgrep with **that rule's NuGuard rule file** on each `before` and `after`.
  - It asserts that `before` produces a match for that `rule_id` and `after` produces none for it.
- **Version:** use the Semgrep version pinned in `config/tools.lock`. If Semgrep isn't installed, or the version differs, skip the test with a clear message naming the expected version.
- **Rule files:** read them from `../nuguard`. Record the rule-file SHA-256 used in a `testdata/playbook/RULES.lock`. Fail if the rules changed without the playbook being re-checked, so a NuGuard rule update forces a playbook review.
- **Run it** in this session if Semgrep is available, and report the result per rule.
  - If a `before` doesn't match, the rule is narrower than its name suggests. Rewrite the example to match what the rule detects, and note the narrowness in the entry's `detects`.
  - If an `after` still matches, the fix is wrong or the rule over-matches. Fix the example. If the rule itself is at fault, record it in the summary as an upstream NuGuard issue, and don't bend the example.

### Step 5: API

- **`GET /v1/findings/{fingerprint}`** gains a `remediation_guidance` object:

  ```json
  {
    "playbook": { "status": "draft|reviewed|no_playbook|none", "entry": {...}, "example_match": "python",
                  "playbook_version": 1, "playbook_sha256": "...", "reason": "..." },
    "nuguard":  { "text": "...", "nuguard_version": "0.9.15", "truncated": false } | null,
    "triage":   { "text": "...", "model": "..." } | null
  }
  ```

  The existing `remediation` field stays exactly as it is, for compatibility.
- **`GET /v1/remediation/playbook`** (engineer+): every entry, the version, the hash, and **coverage**: which NuGuard rule IDs have actually been observed in the store with no reviewed entry, ordered by open finding count. This is the team's review queue.
- Register both in `openapi.go`, run `npm run gen`, and add API tests for each role, each status, the three-source separation, and hostile NuGuard text.

### Step 6: Report browser and tracker

- **`FindingDetail.tsx`:** add a **"How to fix"** panel with up to three sections, in this order:
  1. **"Our playbook"**: the status badge (Draft / Reviewed by X on date), title, why, steps, the matched example as a before/after pair (plain `<pre>` blocks, no syntax-highlighting library), verification, references, effort, and the playbook version and short hash.
     - For `no_playbook`, show the reason. For `none`, show `Absent` with "no playbook entry for this rule yet".
  2. **"NuGuard guidance: generic, not validated"**: the plain text, the NuGuard version, and a note if truncated.
  3. **"Model-written suggestion"**: the existing triage remediation, relabelled. Same content, now attributed.
- **A new page, "Remediation playbook"** (engineer+, read-only): entries with status, and the coverage review queue from the API. It links to the file path so people know where to change it.
- **Tracker tickets** (`internal/tracker/spec.go`):
  - include the playbook steps only when the entry is **reviewed**, with version and hash;
  - include NuGuard guidance as a delimited, escaped quote with its source line;
  - keep the existing "Suggested remediation" line, relabelled as model-written;
  - draft entries are left out of tickets.
  - Test the body against a golden.
- **Tests:** vitest for each panel state, the hostile-text render (it must appear literally), and the playbook page. Run `npm run typecheck` and `npm test`.

### Step 7: Documentation

- **`USAGE.md`:** reading the "How to fix" panel, what each source means, and how to review a draft entry (edit the YAML, set `status: reviewed`, `reviewed_by`, `reviewed_at`, bump `version`, run the proof test).
- **`REMEDIATION-DESIGN.md`:** a short section saying the playbook is the deterministic-first knowledge base Phase 8a's agent candidates can later use as **trusted** context, unlike NuGuard text, which stays untrusted.
- **`NOW-VS-LATER.md`:**
  - feeding reviewed playbook entries to the fixing agent (8a);
  - routing `fix_kind: architectural` to tickets in `policy.yaml`;
  - NuGuard's structured `remediation_plan` (needs an upstream API change);
  - playbook entries for this project's own adapters (gosec, semgrep, staticcheck), using the same format.
- **`PROGRESS.md`:** a dated entry with the per-rule proof results and what wasn't verified.

## Done when

- **Go:** `go vet ./...` and `go test ./...` pass on both backends. The playbook proof test has run, if Semgrep is available, with per-rule results listed.
- **UI:** `npm run typecheck` and `npm test` are green.
- **Goldens:** the non-NuGuard goldens are unchanged; the NuGuard goldens changed only by the new annotation.
- **Every NuGuard code rule** has a draft entry with proven examples, or a `no_playbook` reason.
- **The summary lists:**
  - files changed;
  - entries written;
  - rules whose behaviour surprised you (narrower or broader than their names);
  - suspected upstream NuGuard rule bugs;
  - every deviation from this prompt and why.
- Don't commit unless asked. Work on a new branch, `feature/nuguard-remediation-guidance`, based on the current NuGuard branch.
