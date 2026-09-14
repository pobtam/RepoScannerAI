# Vulnerability Report Browser
## Frontend Requirements & Design Specification

| Field | Value |
|---|---|
| Document ID | VM-UI |
| Version | 0.3 |
| Status | Draft — for review |
| Date | 2026-09-02 |
| Owner | Platform Engineering |
| Companions | `vuln-framework-functional-requirements.md` (VM-FR), `vuln-framework-architecture-design.md` (VM-AD) |
| Implementation | React + TypeScript |

### Revision history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-09-02 | Initial draft |
| 0.3 | 2026-09-02 | Report generation view (§4.11). Scope of the application widens from read-only browsing to browsing plus report issuance; ADR-04 amended. |
| 0.2 | 2026-09-02 | Corpus scope control (§4.4). Run span and not-re-observed marker (§4.4). Age and SLA on finding tables (§4.6). Waves reframed as blast radius (§4.7). Coverage gaps promoted to a specified view (§4.8). Derived from prototype review; drives VM-FR v0.2 §5.3, §5.4, §5.11 and VM-AD v0.2 ADR-12/13/14. |

> **Feedback into VM-AD.** This specification requires orchestrator API endpoints and one storage behaviour that VM-AD v0.1 does not provide. See §6. Those changes must land in VM-AD before frontend Phase 1.

---

## 1. Purpose and scope

### 1.1 Purpose

A read-only browser over the vulnerability framework's findings and reports. It answers three questions: what is the state of the fleet right now, how did it get here, and where is a specific thing.

### 1.2 In scope

- Current run: fleet posture, new findings, regressions, per-repository rollup
- Historical: run history, trends, run-to-run comparison
- Search and filter across findings, scoped to a run or across all history
- Finding detail with full lifecycle timeline
- Repository detail
- First-party module wave status
- Links out to the permanent report archive, pull requests, tickets, and advisories
- Generating, issuing, and delivering reports from any template against any past run

### 1.3 Out of scope for v1.0

- Any write operation against **findings, tickets, or pull requests**. Resetting a `DECLINED` finding, approving a suppression, and rejecting a false-positive nomination are all Phase 2 (VM-UI-OQ-02). Report generation is in scope and is not an exception to this: it creates a new artifact and mutates no finding state.
- Policy editing
- Triggering runs
- Authoring or editing reports
- Native mobile applications

---

## 2. Users and their jobs

| User | Primary job | Frequency |
|---|---|---|
| Platform engineer | Check the sweep landed; investigate coverage gaps; check cost | Weekly, post-sweep |
| Repository CODEOWNER | See what is open on my repositories and what the bot opened | Ad hoc, arrives from a ticket link |
| Security owner | Fleet posture; escalations; SLA breaches; regressions | Weekly and during incidents |
| Incident responder | "Which repositories are affected by this advisory" — under time pressure | Rare, urgent |

The incident responder is the demanding case. That query must be one filter and must return in under two seconds, because the alternative is a fleet rescan measured in tens of minutes. Design for it explicitly.

---

## 3. Information architecture

```
/                             → redirect to /runs/latest
/runs/latest                  Current run overview
/runs/S-001247                Historical run overview (snapshot), addressed by run id
/runs                         Run history + trends
/runs/compare?a=&b=           Run comparison
/findings                     Finding explorer (search + filter)
/findings/:fingerprint        Finding detail
/repos                        Repository index
/repos/:repo                  Repository detail
/waves                        First-party module wave status
/gaps                         Coverage gaps, with failure history
/reports                      Issued reports; generate new
/reports/R-000042             Issued report: metadata, query, hash, formats
```

Every route carries its full state in the URL. See VM-UI-F-401.

---

## 4. Functional requirements

### 4.1 Data and correctness (VM-UI-F-1xx)

| ID | Norm | Requirement |
|---|---|---|
| VM-UI-F-101 | MUST | All data shall be read from the orchestrator API. The application shall not parse the report git repository. |
| VM-UI-F-102 | MUST | A historical run view shall display the state as recorded at that run, not the current state of its findings. |
| VM-UI-F-103 | MUST | The current run view shall display live state, reflecting changes since the run completed. |
| VM-UI-F-104 | MUST | Where a view mixes snapshot and live data, it shall label which is which. |
| VM-UI-F-105 | MUST | The application shall never display a secret value. It shall assert on receipt that secret findings carry no value field and shall fail loudly if one is present. |
| VM-UI-F-106 | MUST | API responses shall be validated against a schema at runtime; a response failing validation shall surface as an error, not render partially. |
| VM-UI-F-107 | MUST | TypeScript types shall be generated from the framework's Go schema definitions, not hand-written. |
| VM-UI-F-108 | MUST | Every displayed count shall be traceable to a query the user can reproduce by clicking through to the filtered finding list. |

VM-UI-F-102 is the one that is easy to get wrong. A finding detected in the run of 12 August and fixed on 20 August must appear as open when viewing the August 12 run. Rendering a historical run from the live findings table would show it as verified, silently rewriting history and making every trend chart wrong.

### 4.2 Current run view (VM-UI-F-2xx)

| ID | Norm | Requirement |
|---|---|---|
| VM-UI-F-201 | MUST | Display headline counts: found, fixed, not fixed, each with the delta against the previous run. |
| VM-UI-F-202 | MUST | Display new findings and regressions as two separate, prominent sections. |
| VM-UI-F-203 | MUST | Regressions shall be visually distinguished from new findings; they represent a different failure. |
| VM-UI-F-204 | MUST | Display the not-fixed breakdown by reason code, each linking to the corresponding filtered list. |
| VM-UI-F-205 | MUST | Display the per-repository rollup: repository, tier, language, found, fixed, open by severity, pull requests opened. |
| VM-UI-F-206 | MUST | Display coverage gaps prominently. A repository that was not scanned is more urgent than a repository with findings, and must not be buried below the rollup. |
| VM-UI-F-207 | MUST | Display run metadata: identifier, trigger, duration, scanner image digest, tool versions. |
| VM-UI-F-207a | MUST | The run identifier and its start timestamp shall always be displayed together. The identifier is not self-dating and the timestamp is not unique; neither alone identifies a run. |
| VM-UI-F-207b | MUST | Run identifiers shall be routable — `/runs/S-001247` shall resolve — and copyable in one action for pasting into a ticket. |
| VM-UI-F-208 | MUST | Display token and cost accounting, including cost per finding fixed and cost per abandoned attempt. |
| VM-UI-F-209 | MUST | Where tool versions differ from the previous run, indicate it — a change in finding counts is uninterpretable without knowing whether the scanner changed. |
| VM-UI-F-210 | MUST | Link to the permanent report archive entry for the run. |
| VM-UI-F-211 | SHOULD | Indicate SLA breaches: findings past their remediation window for their severity and tier. |

### 4.3 Historical views (VM-UI-F-3xx)

| ID | Norm | Requirement |
|---|---|---|
| VM-UI-F-301 | MUST | List all runs with date, trigger, duration, repositories scanned, repositories failed, and headline counts. |
| VM-UI-F-302 | MUST | Support opening any run's overview as a snapshot. |
| VM-UI-F-303 | MUST | Display trends over a selectable window: open findings by severity, new versus fixed per run, mean time to remediation, token cost per run. |
| VM-UI-F-304 | MUST | Trend charts shall be interactive to the extent of identifying a run and navigating to it. |
| VM-UI-F-305 | MUST | Support comparing two runs, showing findings appearing, disappearing, and changing state between them. |
| VM-UI-F-306 | MUST | Indicate on trend charts where the scanner image changed, so a step change in counts is attributable. |
| VM-UI-F-307 | MUST | Where a run failed or was partial, mark it as such in every history and trend view rather than showing an artificially low count. |
| VM-UI-F-308 | SHOULD | Support exporting a run comparison as CSV. |
| VM-UI-F-309 | MUST | Deltas shall be computed against the previous run of the same kind. A sweep compared against a single-repository manual run produces a figure that looks like a collapse. |
| VM-UI-F-310 | MUST | Trend series shall be drawn from one run kind at a time, and the kind shall be labelled. |
| VM-UI-F-311 | MUST | Run kind shall be visible wherever runs are listed. |

VM-UI-F-306 and VM-UI-F-307 exist because trend charts invite causal inference. A drop in findings caused by half the fleet failing to scan looks identical to a drop caused by remediation working, and someone will present the wrong one at a review.

### 4.4 Search and filter (VM-UI-F-4xx)

| ID | Norm | Requirement |
|---|---|---|
| VM-UI-F-401 | MUST | All filter, sort, and pagination state shall be encoded in the URL. A filtered view shall be shareable by copying the address. |
| VM-UI-F-402 | MUST | Filtering and sorting shall be performed server-side. The client shall not fetch the full finding set. |
| VM-UI-F-403 | MUST | Results shall be paginated by cursor, not offset. |
| VM-UI-F-404 | MUST | Free-text search shall match: vulnerability identifier and its aliases, module path, package path, file path, and repository name. |
| VM-UI-F-405 | MUST | Searching by any alias of a vulnerability shall return the finding regardless of which identifier is primary. |
| VM-UI-F-406 | MUST | The following filter dimensions shall be supported, combinable: repository, tier, language, category, state, reason code, priority, severity, reachability, dependency class, transitive, first-party blocked, has pull request, has ticket, first-seen range, last-seen range, run. |
| VM-UI-F-407 | MUST | Filters shall be multi-select within a dimension and conjunctive across dimensions. |
| VM-UI-F-408 | MUST | Each filter option shall display its result count, and options yielding zero results shall be visibly disabled rather than hidden. |
| VM-UI-F-409 | MUST | Active filters shall be displayed as removable elements with a single action to clear all. |
| VM-UI-F-410 | MUST | The result count shall be displayed and shall update with the filter. |
| VM-UI-F-411 | MUST | Default scope shall be findings open across all history, not findings in the latest run — the latter hides everything the most recent sweep did not re-observe. |
| VM-UI-F-412 | MUST | Results shall be sortable by priority, severity, first seen, last seen, and repository. |
| VM-UI-F-413 | MUST | The result table shall be virtualised and shall remain responsive at 10,000 rows. |
| VM-UI-F-414 | SHOULD | Saved filters shall be supported, stored per user. |
| VM-UI-F-415 | SHOULD | Results shall be exportable as CSV, respecting the active filter. |
| VM-UI-F-416 | MUST | The corpus in view shall be selectable between: unresolved across all runs, observed in one named run, and everything ever recorded. |
| VM-UI-F-417 | MUST | The active corpus shall be stated in words on screen, not implied by a default. A count is meaningless without stating which findings it counts. |
| VM-UI-F-418 | MUST | The interface shall state what the active corpus excludes and how many records that is. |
| VM-UI-F-419 | MUST | The result count shall distinguish records matching the filter from records in the corpus from the total, so filter and scope are separately legible. |
| VM-UI-F-420 | MUST | Corpus scope shall be encoded in the URL alongside the filters. |
| VM-UI-F-421 | MUST | A finding's first-seen and last-seen runs shall both be displayed. Neither alone conveys whether it is current. |
| VM-UI-F-422 | MUST | A finding not re-observed in the most recent applicable run while unresolved shall be visibly marked, and the marker shall be explained on screen. |
| VM-UI-F-423 | MUST | The explanation shall state that non-observation is ambiguous between remediation and a coverage gap, and shall direct the reader to coverage gaps before concluding the former. |
| VM-UI-F-424 | MUST | Where a run-scoped view shows live state rather than state as of that run, it shall say so. |

VM-UI-F-408 is not cosmetic. Counts on filter options are what let the incident responder narrow from four thousand findings to the affected set without a sequence of empty result screens.

### 4.5 Finding detail (VM-UI-F-5xx)

| ID | Norm | Requirement |
|---|---|---|
| VM-UI-F-501 | MUST | Display the complete finding record: identity and aliases, location, versions, classification, triage output, state, and reason code. |
| VM-UI-F-502 | MUST | Display the lifecycle timeline from state transitions: every state change with timestamp, actor, and cause. |
| VM-UI-F-503 | MUST | Display observation history: every run in which the finding was seen, and gaps where it was not. |
| VM-UI-F-504 | MUST | Display reachability explicitly as one of reachable, not reachable, or unknown. Unknown shall be visually distinct from not reachable. |
| VM-UI-F-505 | MUST | Link to the pull request, ticket, and advisory where present. |
| VM-UI-F-506 | MUST | Where the finding is blocked upstream, link to the upstream finding and identify the owning repository. |
| VM-UI-F-507 | MUST | Where the finding is an upstream first-party finding, list the blocked consumers. |
| VM-UI-F-508 | MUST | Display remediation attempt history including outcome, reason code, and verification evidence. |
| VM-UI-F-509 | MUST | Verification evidence shall be displayed verbatim in a monospaced, scrollable region. |
| VM-UI-F-510 | MUST | Display the priority score decomposition — which factors produced the score. |
| VM-UI-F-511 | MUST | Display the tools that reported the finding and their versions. |
| VM-UI-F-512 | MUST | Display the fingerprint, copyable in one action. |

VM-UI-F-510 is what makes the scoring model trustworthy. "P1" is an assertion; "base 7.5, in known-exploited catalogue, reachable, production dependency, tier 1" is an argument someone can disagree with.

### 4.6 Repository view (VM-UI-F-6xx)

| ID | Norm | Requirement |
|---|---|---|
| VM-UI-F-601 | MUST | Display repository profile: tier, languages, module topology, test suite presence, code owners, last scanned. |
| VM-UI-F-602 | MUST | Display open findings by severity and category. |
| VM-UI-F-603 | MUST | Display finding trend for the repository over time. |
| VM-UI-F-604 | MUST | Display the dependency inventory, searchable. |
| VM-UI-F-605 | MUST | Display open remediation pull requests. |
| VM-UI-F-606 | MUST | Where the repository owns a first-party module, list its consumers. |
| VM-UI-F-607 | MUST | Where a repository has no test suite, display it prominently — it constrains what the framework may do there. |
| VM-UI-F-608 | MUST | The repository finding table shall display, per finding: priority, identifier, component, first-seen and last-seen run, age, SLA status, and state. |
| VM-UI-F-609 | MUST | Age shall never be displayed without its SLA status. The same elapsed time is unremarkable at one priority and a breach at another; age alone invites sorting by the wrong column. |
| VM-UI-F-610 | MUST | SLA status shall be displayed as one of: within window, approaching, breached with overrun, paused, or stopped with the closing duration. |
| VM-UI-F-611 | MUST | A finding whose clock is paused shall never render as breached. |
| VM-UI-F-612 | MUST | The SLA windows in force shall be stated on the view, not left implicit. |
| VM-UI-F-613 | MUST | Findings shall be ordered by priority then by age descending, so the oldest urgent item is first. |
| VM-UI-F-614 | MUST | The count of findings past SLA shall be visible without reading rows. |

### 4.7 First-party wave view (VM-UI-F-7xx)

| ID | Norm | Requirement |
|---|---|---|
| VM-UI-F-701 | MUST | List active waves: the upstream finding, owning repository, Wave 1 pull request status, and consumer count. |
| VM-UI-F-702 | MUST | For each wave, list consumers with their blocked or upgraded state. |
| VM-UI-F-703 | MUST | Display the age of a Wave 1 pull request. A stalled upstream fix blocking twelve consumers is a distinct escalation from twelve independent findings. |
| VM-UI-F-704 | MUST | List consumers excluded from a wave due to a replace directive, with the reason. |
| VM-UI-F-705 | MUST | Display the configured Wave 2 trigger, since it determines whether a merge is sufficient or a tag is required. |
| VM-UI-F-706 | MUST | The relationship between the vulnerability, the shared module, and its consumers shall be shown as a dependency graph. A list of repository names does not convey that they share one root cause and one unblocking action. |
| VM-UI-F-707 | MUST | Consumers that reach the vulnerable code shall be visually distinguished from consumers that merely depend on the module and from consumers whose reachability is unknown. |
| VM-UI-F-708 | MUST | Depend-count and reach-count shall both be displayed as separate figures, adjacent, so neither can be quoted alone. |
| VM-UI-F-709 | MUST | The steps that clear the wave shall be enumerated in order, with the publication step called out where the trigger is tag rather than merge. |
| VM-UI-F-710 | MUST | Excluded consumers shall be shown within the graph, not omitted, with the exclusion reason. |
| VM-UI-F-711 | MUST | Module fan-out shall be available independently of any active finding, so exposure can be assessed before an advisory arrives. |
| VM-UI-F-712 | MUST | Version spread across consumers shall be displayed, since divergent versions may prevent a single-target wave. |

### 4.8 Coverage gaps view (VM-UI-F-75x)

| ID | Norm | Requirement |
|---|---|---|
| VM-UI-F-751 | MUST | Each gap shall display the run identifier and start timestamp in which it occurred. |
| VM-UI-F-752 | MUST | Each gap shall display consecutive-failure count, elapsed time without data, and the last run that scanned the repository successfully. A single-run view cannot distinguish a transient failure from a standing blind spot. |
| VM-UI-F-753 | MUST | Each gap shall be classified as total or partial, and a partial gap shall state which signals were lost and which remain current. |
| VM-UI-F-754 | MUST | Each gap shall name its owner, since infrastructure causes and repository causes route to different people. |
| VM-UI-F-755 | MUST | Each gap shall state the count of findings not re-observed as a result, linking to them. |
| VM-UI-F-756 | MUST | Per-repository scan outcome across recent runs shall be displayed as a compact history, so coverage decay is visible without reading individual gaps. |
| VM-UI-F-757 | MUST | The view shall state that a failed scan and a clean scan are indistinguishable in every aggregate, and that gaps invalidate the figures on the run overview. |
| VM-UI-F-758 | SHOULD | Coverage percentage shall be trended alongside finding counts. |

### 4.9 Access and visibility (VM-UI-F-8xx)

| ID | Norm | Requirement |
|---|---|---|
| VM-UI-F-801 | MUST | Access shall require authentication against the organisation identity provider. |
| VM-UI-F-802 | MUST | Authorisation shall be enforced server-side. The client shall not be the access control point. |
| VM-UI-F-803 | MUST | Secret findings shall be visible only to the security owner group and the owning repository's code owners. |
| VM-UI-F-804 | MUST | Where a finding is hidden from a user, counts shall remain consistent — an aggregate shall not silently exclude records the user cannot open. Display the count with an indication that detail is restricted. |
| VM-UI-F-805 | SHOULD | Access shall be logged. |

VM-UI-F-804 resolves an otherwise confusing failure: a rollup showing four findings while the list shows three, with no explanation.

### 4.10 Presentation, states, and performance (VM-UI-F-9xx)

| ID | Norm | Requirement |
|---|---|---|
| VM-UI-F-901 | MUST | Severity and state shall be encoded by more than colour alone. |
| VM-UI-F-902 | MUST | Every view shall define a loading, empty, error, and partial-data state. |
| VM-UI-F-903 | MUST | Error states shall state what failed and what the user can do. |
| VM-UI-F-904 | MUST | Empty states shall distinguish "no results for this filter" from "no data yet". |
| VM-UI-F-905 | MUST | Views shall render progressively; a slow panel shall not block the page. |
| VM-UI-F-906 | MUST | Interface language shall use terms from the framework's own vocabulary, consistently, matching the reports and tickets. |
| VM-UI-F-907 | MUST | Keyboard navigation shall reach every interactive element with visible focus. |
| VM-UI-F-908 | MUST | Contrast shall meet WCAG AA. |
| VM-UI-F-909 | MUST | Reduced-motion preferences shall be respected. |
| VM-UI-F-910 | SHOULD | The layout shall be usable at tablet width. Phone width is not a target. |

---

### 4.11 Report generation (VM-UI-F-11xx)

| ID | Norm | Requirement |
|---|---|---|
| VM-UI-F-1101 | MUST | The user shall be able to generate a report by selecting a template, a run anchor, and an output format. |
| VM-UI-F-1102 | MUST | Each template shall display its intended audience and what it contains, before generation. |
| VM-UI-F-1103 | MUST | The anchor shall be an explicit choice of run. The interface shall state that reports cannot be anchored to live state, rather than silently anchoring to the latest run. |
| VM-UI-F-1104 | MUST | Filters active in the finding explorer shall be carriable into a report request, and the resulting filter shall be displayed for confirmation before generation. |
| VM-UI-F-1105 | MUST | The estimated size of the report shall be shown before generation, and an over-limit request shall be refused with the limit stated. |
| VM-UI-F-1106 | MUST | Issued reports shall be listed with identifier, template, anchor, requester, timestamp, and content hash. |
| VM-UI-F-1107 | MUST | An issued report shall be re-downloadable in any of its generated formats without regeneration. |
| VM-UI-F-1108 | MUST | Where a report supersedes another, both shall be visible and the relationship stated. Superseded reports shall not be deleted. |
| VM-UI-F-1109 | MUST | Where a report was redacted, the interface shall show the withheld count. |
| VM-UI-F-1110 | MUST | The content hash shall be copyable in one action, for verifying a circulated copy. |
| VM-UI-F-1111 | MUST | The interface shall not present a "current" or "live" report option, since no such report is reproducible. |
| VM-UI-F-1112 | SHOULD | Delivery to a ticket or the report repository shall be available from the issued report. |

## 5. Non-functional requirements

| ID | Norm | Requirement |
|---|---|---|
| VM-UI-NF-101 | MUST | Filtered finding query returns within 2 seconds at the 95th percentile against the full history. |
| VM-UI-NF-102 | MUST | Run overview renders within 1 second at the 95th percentile. |
| VM-UI-NF-103 | MUST | Initial JavaScript payload under 300 KB compressed. |
| VM-UI-NF-201 | MUST | Adding a filter dimension requires a change in one place in the client and one in the API. |
| VM-UI-NF-202 | MUST | A change to the finding schema surfaces as a TypeScript compile error, not a runtime failure. |
| VM-UI-NF-301 | MUST | Supported browsers: current and previous major versions of Chrome, Firefox, and Safari. |

---

## 6. Required changes to VM-AD

The frontend cannot be built against VM-AD v0.1 as written. Three changes are required.

### 6.1 Run snapshot persistence

VM-AD stores `fleet.json` only as a git commit. Serving VM-UI-F-102 by parsing git at request time is unacceptable for latency and unavailable for filtering.

**Change:** the orchestrator persists each run's `fleet.json` in a `run_snapshots` table (`run_id`, `snapshot JSONB`, `created_at`) at the same time it commits to the report repository. The git commit remains the permanent, externally-citable archive; the table is the query surface. Both are written from the same generated object, so they cannot diverge.

### 6.2 Additional API endpoints

```
GET  /v1/runs?limit=&cursor=              run list with headline counts
GET  /v1/runs/latest                      current run overview
GET  /v1/runs/{id}/snapshot               persisted fleet.json ({id} = 'S-001247')
GET  /v1/runs/compare?a=&b=               appearing / disappearing / changed
GET  /v1/findings?<filters>&cursor=       filtered, sorted, cursor-paginated
GET  /v1/findings/facets?<filters>        per-option counts for the current filter
GET  /v1/findings/{fp}                    full record
GET  /v1/findings/{fp}/timeline           state transitions + observations
GET  /v1/findings/{fp}/attempts           remediation attempt history
GET  /v1/repos                            repository index
GET  /v1/repos/{repo}                     profile, rollup, deps, open PRs
GET  /v1/repos/{repo}/trend?window=       finding counts over time
GET  /v1/waves                            active first-party waves
GET  /v1/metrics/trends?window=&metric=   fleet trend series
GET  /v1/schema/openapi.json              schema for type generation
```

`GET /v1/findings/facets` is the endpoint VM-UI-F-408 depends on and is easy to omit at design time. It returns counts per filter option under the currently applied filters, which requires a separate aggregate query, not a post-hoc count of the returned page.

### 6.3 Alias search index

VM-UI-F-405 requires searching by any alias. VM-AD stores aliases inside the `data` JSONB column. Add a generated column or a dedicated `finding_aliases` table with an index; a JSONB containment scan across full history will not meet VM-UI-NF-101.

---

## 7. Technical design

### 7.1 Stack

| Concern | Choice | Rationale |
|---|---|---|
| Framework | React 18 + TypeScript, strict | Stated requirement |
| Build | Vite | |
| Routing | TanStack Router | Typed search parameters — VM-UI-F-401 is a routing requirement, and a typed router makes filter state a compile-time contract rather than string parsing |
| Server state | TanStack Query | Caching, background refresh, request deduplication |
| Table | TanStack Table + TanStack Virtual | Virtualisation is required at 10,000 rows (VM-UI-F-413) |
| Charts | Recharts | |
| Validation | Zod | Runtime validation per VM-UI-F-106 |
| Types | `openapi-typescript` from `/v1/schema/openapi.json` | VM-UI-F-107 |
| Styling | Tailwind | |

**No global state library.** The URL holds view state and TanStack Query holds server state. Adding a third store creates a synchronisation problem where none exists.

### 7.2 Project layout

```
reportui/
  src/
    api/          generated/schema.ts    ← generated, never edited
                  client.ts, queries.ts
    routes/       runs.latest.tsx, runs.$runId.tsx, runs.index.tsx,
                  runs.compare.tsx, findings.index.tsx,
                  findings.$fingerprint.tsx, repos.index.tsx,
                  repos.$repo.tsx, waves.tsx, gaps.tsx
    features/
      run-overview/   headline, deltas, rollup, gaps, cost
      finding-table/  table, columns, virtualisation
      filters/        filter-bar, facet-list, url-sync
      finding-detail/ record, timeline, attempts, score-breakdown
      trends/         charts, annotations
      waves/
    components/   primitives: table, chip, badge, panel, empty, error
    lib/          severity, state, dates, csv, format
  scripts/
    gen-types.sh
```

### 7.3 Filter state as URL

```ts
const findingSearchSchema = z.object({
  repo:      z.array(z.string()).optional(),
  tier:      z.array(z.number()).optional(),
  category:  z.array(z.enum(['dependency','code','secret','config'])).optional(),
  state:     z.array(findingState).optional(),
  reason:    z.array(reasonCode).optional(),
  priority:  z.array(z.enum(['P0','P1','P2','P3'])).optional(),
  reachable: z.array(z.enum(['true','false','unknown'])).optional(),
  depClass:  z.array(z.enum(['production','development'])).optional(),
  blocked:   z.boolean().optional(),
  hasPR:     z.boolean().optional(),
  hasTicket: z.boolean().optional(),
  q:         z.string().optional(),
  firstSeenFrom: z.string().datetime().optional(),
  firstSeenTo:   z.string().datetime().optional(),
  run:       z.string().optional(),
  sort:      z.enum(['priority','severity','firstSeen','lastSeen','repo']).default('priority'),
  dir:       z.enum(['asc','desc']).default('desc'),
  cursor:    z.string().optional(),
});
```

The schema is the single definition of filter state: it types the route, validates the URL, and serialises to the API query. One place to change when a dimension is added (VM-UI-NF-201).

### 7.4 Snapshot versus live

```ts
// Historical: read the persisted snapshot. Never recompute from live findings.
useQuery({ queryKey: ['run', runId, 'snapshot'], queryFn: () => api.runSnapshot(runId) });

// Current: live query, refetched in background.
useQuery({ queryKey: ['run', 'latest'], queryFn: api.latestRun, refetchInterval: 60_000 });
```

Two different hooks, deliberately not unified. Unifying them is how VM-UI-F-102 gets violated six months later by someone simplifying the data layer.

### 7.5 Deployment

Static bundle served from the same origin as the orchestrator API, behind the existing ingress. Same origin avoids CORS and cross-site cookie handling. Authentication via the organisation identity provider with an HTTP-only session cookie; the client holds no token.

---

## 8. Design direction

### 8.1 What this is

A triage console for security and platform engineers. Its closest relatives are log viewers, monitoring consoles, and package managers — not marketing dashboards. Density is a feature. A user arriving from a ticket wants the record on screen without scrolling; a user hunting an advisory wants a hundred rows visible at once.

The data grid is the hero, not a headline. There is no marketing surface here and nothing needs selling.

### 8.2 Tokens

**Colour.** Cool, low-saturation ground so severity encoding is the only strong colour on screen.

```
--ground     #FAFBFC   page
--surface    #FFFFFF   panels, table
--rule       #E3E7EB   borders, dividers
--ink        #1A2027   primary text
--ink-quiet  #5A6672   secondary text
--accent     #2E5A8C   links, selection, focus
```

Severity, used only for severity — never for decoration:

```
--sev-p0     #8C2E3C
--sev-p1     #B5642A
--sev-p2     #7A6A2E
--sev-p3     #5A6672
```

State encoding is separate from severity and uses shape and label rather than hue: open states are outlined, resolved states are filled and muted, blocked states carry a distinct border treatment. Severity and state must be distinguishable in a greyscale screenshot, since these get pasted into tickets (VM-UI-F-901).

**Type.** Two families with clearly separated jobs.

- Interface: IBM Plex Sans. Chosen for its wide numeral set and legibility at small sizes; the interface is majority numbers and identifiers.
- Data: IBM Plex Mono, for identifiers, module paths, file paths, fingerprints, versions, and verification output. Monospace here is functional — `CVE-2025-22869` against `CVE-2025-22689` is a comparison the user makes constantly, and proportional digits make it harder.

Scale: 12 / 13 / 15 / 18 / 24 px. Table body sits at 13. No size above 24; there is no display type in this product.

**Layout.** Fixed left navigation, fluid content, no maximum content width — a wide monitor should show more columns, not more margin. Density is a user preference toggle, comfortable and compact, persisted.

**Principles.**
1. The table is the product. Everything else supports getting to a row or explaining one.
2. Colour means severity. Nothing else is coloured.
3. Every number links to the query that produced it.
4. Snapshot and live data are always labelled.
5. Motion only confirms an action — expanding a row, applying a filter. No entrance animation.

### 8.3 Design plan review

Checked against the generic defaults: no cream-and-terracotta palette, no card-kit fragmentation (the table is one continuous surface, not rows of cards), no all-caps eyebrows, no gradient washes, and no big-number hero. The one place risking genericism was the run overview, which naturally attracts a row of stat cards. Revised: headline counts render as a single horizontal band with deltas inline, above the fold and above the table, rather than four bordered cards — because the counts belong together as one reading and the delta is the actual information.

### 8.4 Wireframes

**Current run overview**

```
┌────────────┬──────────────────────────────────────────────────────────────┐
│            │ S-001247 · Sweep · 2 Sep 2026 03:00 UTC · 41 repos · 12m30s  │
│  Current   │ scanner sha256:9c1a… · tool versions unchanged               │
│  Runs      ├──────────────────────────────────────────────────────────────┤
│  Findings  │  Found 312  +14    Fixed 187  +23    Not fixed 125  −9       │
│  Repos     ├──────────────────────────────────────────────────────────────┤
│  Waves     │ ⚠ 2 repos not scanned — payments-web, ops-tools    [view]    │
│  Gaps      ├────────────────────────────────┬─────────────────────────────┤
│            │ New this run              14   │ Regressed              3    │
│            │ ───────────────────────────    │ ──────────────────────────  │
│            │ P0 GO-2025-3106  wanaware-api  │ P1 CVE-2025-1109  common    │
│            │ P1 CVE-2025-2210 wanaware-api  │ P2 gosec G401     ldu-sync  │
│            │ … 12 more                      │ … 1 more                    │
│            ├────────────────────────────────┴─────────────────────────────┤
│            │ Not fixed by reason                                          │
│            │ Blocked upstream        41  ▓▓▓▓▓▓▓▓▓▓▓▓                     │
│            │ No upstream fix         33  ▓▓▓▓▓▓▓▓▓                        │
│            │ Major bump — policy     22  ▓▓▓▓▓▓                           │
│            │ Build failed            14  ▓▓▓▓                             │
│            │ Needs human — secret     2  ▓                                │
│            ├──────────────────────────────────────────────────────────────┤
│            │ Repository                Tier  Found  Fixed  Open  PRs      │
│            │ wanaware-api                 1     47     31    16    4      │
│            │ wanaware-common              1     22     18     4    2      │
│            │ …                                                            │
│            ├──────────────────────────────────────────────────────────────┤
│            │ 1.42M in · 89K out · 4.1M cached · $18.40                    │
│            │ $0.80 per finding fixed · $2.10 per abandoned attempt        │
└────────────┴──────────────────────────────────────────────────────────────┘
```

**Finding explorer**

```
┌────────────┬──────────────────────────────────────────────────────────────┐
│            │ ⌕ CVE-2025-22869                          312 findings        │
│  Current   │ [Repo ▾] [State ▾] [Priority ▾] [Reachable ▾] [Category ▾]   │
│  Runs      │ tier:1 ×   state:PR_OPEN ×   reachable:true ×    clear all   │
│  Findings ●├──────────────────────────────────────────────────────────────┤
│  Repos     │ Pri Identifier       Repo            Component       State   │
│  Waves     │ ─────────────────────────────────────────────────────────────│
│  Gaps      │ P0  GO-2025-3106     wanaware-api    x/crypto@v0     PR open │
│            │ P1  CVE-2025-2210    wanaware-api    x/net@v0        Blocked │
│            │ P1  gosec G402       ldu-sync        tls/config.go   Triaged │
│            │ P2  GHSA-hcg3-q754   payments-web    lodash@v4       Triaged │
│            │ …                                                            │
│            │                                    ← prev   next →           │
└────────────┴──────────────────────────────────────────────────────────────┘
```

**Finding detail**

```
GO-2025-3106                                                     [P0] [PR open]
also CVE-2025-22869 · GHSA-hcg3-q754-cr77                    fp a3f9c21e8b7d ⧉

golang.org/x/crypto  v0.35.0 → v0.36.0    production · transitive · reachable

  Score 9.2   base 7.5 · known exploited +3.0 · epss 0.004 · reachable ×1.0
              production ×1.0 · tier 1 ×1.2

  Impact      Remote attacker can exhaust server memory during SSH key
              exchange, causing denial of service on the ingress path.

  Pulled in via  wanaware-common → golang.org/x/crypto

  Timeline
    17 Aug 03:12  Detected            scanworker
    17 Aug 03:41  Triaged             triage
    17 Aug 04:02  Auto remediating    orchestrator · policy rule 6
    17 Aug 04:19  PR open             fixworker · PR #1180

  Observed in 3 runs · 17 Aug, 24 Aug, 2 Sep

  Attempts
    17 Aug  agentic  PR #1180  build ✓  tests ✓  scan clean ✓   [evidence ▾]

  → Pull request #1180   → Ticket #412   → Advisory
```

---

## 9. Architecture decision records

### UI-ADR-01 — The API is the data source, not the report repository

**Decision:** all reads go through the orchestrator API.
**Rationale:** the report repository is optimised for permanence and citation, not query. Filtering across full history by parsing git is unworkable at the latency the incident-response case requires. The repository remains the link target for permanent citation.

### UI-ADR-02 — Historical views read persisted snapshots

**Decision:** each run's `fleet.json` is persisted and served; historical views never recompute from live findings.
**Rationale:** live findings carry current state. Rendering a past run from them rewrites history — a finding since fixed would appear fixed in the run that detected it, and every trend derived from it would be wrong.
**Consequences:** requires the VM-AD change in §6.1; storage grows per run.

### UI-ADR-03 — URL is the view state

**Decision:** filter, sort, and pagination live in typed search parameters.
**Rationale:** the primary sharing mechanism between engineers is a pasted link. State held in a client store is unshareable, breaks the back button, and cannot be cited from a ticket.

### UI-ADR-04 — Read-only against findings; report issuance permitted (amended v0.3)

**Decision:** no write operations against findings, tickets, or pull requests. Report generation is permitted.
**Rationale:** the requested scope is browsing. Write actions — resetting a declined finding, approving a suppression — carry authorisation and audit requirements that would dominate v1.0 and are better designed once the read surface is in use.
**Consequences:** those actions remain in the tracker and the API until Phase 2. Report generation is
admitted because it mutates no finding state — it creates a new, immutable, separately-identified artifact,
and the audit surface it needs (who generated what, delivered where) is far smaller than that of state
mutation.

### UI-ADR-05 — Types are generated, never hand-written

**Decision:** TypeScript types generate from the framework's OpenAPI schema.
**Rationale:** a hand-maintained mirror of the finding schema will drift, and the drift surfaces as a blank field in front of a stakeholder rather than a build failure.

### UI-ADR-06 — Server-side filtering and cursor pagination

**Decision:** the client never holds the full finding set.
**Rationale:** the set grows without bound across history; client-side filtering has a hard ceiling and fails exactly when the fleet is largest. Cursor pagination also stays correct while findings change state underneath a paging session, which offset pagination does not.

---

## 10. Build sequence

| Phase | Deliverable | Gate |
|---|---|---|
| **U0** | Scaffold, generated types, API client, Zod validation, primitives, error boundary | Type generation runs in CI; a schema change breaks the build. |
| **U1** | Finding explorer: table, virtualisation, server-side filter, URL state, facet counts | Filter state round-trips through the URL. Table responsive at 10,000 rows. Alias search returns the finding. |
| **U2** | Finding detail: record, timeline, observations, attempts, score breakdown | Every field in `findings.v1` is either rendered or deliberately excluded with a note. |
| **U3** | Current run overview | Counts match the API. Every count links to its filtered list. Coverage gaps above the rollup. |
| **U4** | Run history, snapshots, trends | Historical run shows state as of that run, verified against a finding fixed after the run in question. Scanner-change annotation present. |
| **U5** | Run comparison | Appearing, disappearing, and changed sets correct across two known runs. |
| **U6** | Repository views | |
| **U7** | Wave view | Stalled Wave 1 with blocked consumers renders correctly. |
| **U8** | Auth, restricted visibility, access logging | A user without security-owner membership sees the secret finding count but not its detail, and no secret value appears in any network response. |
| **U9** | Report generation view: templates, anchor selection, issued list, hashes | An audit pack is generated from a past run and re-downloaded without regeneration. A live anchor is not offered. A redacted report shows its withheld count. |
| **U10** | Accessibility, keyboard, density toggle, reduced motion, CSV export | Keyboard-only traversal of the explorer and detail views. Contrast audit passes. |

U1 before U3 is deliberate. The explorer is the load-bearing view and the hardest; building the overview first produces an appealing page that links to nothing.

---

## 11. Open questions

| ID | Question | Blocks |
|---|---|---|
| VM-UI-OQ-01 | Identity provider and group source for the security-owner group in VM-UI-F-803. | U8 |
| VM-UI-OQ-02 | Are write actions wanted in Phase 2, and which ones? Reset from declined, approve suppression, and re-trigger a repository scan are the candidates. | Post-v1.0 |
| VM-UI-OQ-03 | Should rendered per-repository report Markdown be displayed in-app, or only linked to the archive? In-app avoids a context switch but creates a second rendering path for the same data. | U3 |
| VM-UI-OQ-04 | Report and observation retention (VM-OQ-07) bounds how far back history and trends can go. The UI must state the boundary rather than showing a truncated series as complete. | U4 |
| VM-UI-OQ-05 | Are saved filters per user or shared across the team? Shared filters need a store and a naming convention. | U1 |
| VM-UI-OQ-06 | Should the explorer default scope be all open findings or the latest run? VM-UI-F-411 specifies all open; confirm this matches how the team thinks about the fleet. | U1 |
| VM-UI-OQ-07 | Is tablet width a real requirement, or is this desktop-only? It affects the table strategy materially. | U0 |
| VM-UI-OQ-08 | Does run-scoped filtering read from the persisted snapshot, or does it select findings by run membership while showing live state? The first is correct and costlier; the second is cheaper and must be labelled. | U1 |
| VM-UI-OQ-09 | Is `MERGED` shown as resolved, unresolved, or its own bucket? Mirrors VM-OQ-09; the interface must not answer it differently from the reports. | U1 |
| VM-UI-OQ-10 | Should `DECLINED` findings remain in the default open corpus? They are real unaddressed risk, but they never move, and a permanent unmovable row trains people to ignore the list. | U1 |
| VM-UI-OQ-12 | Should report generation be available to all authenticated users, or restricted? Generation is cheap to abuse and every report is a durable artifact. | U9 |
| VM-UI-OQ-13 | Does the fixed-layout format need to render server-side, or is browser print acceptable for the audit pack? Server-side is reproducible; browser print is not. | U9 |
| VM-UI-OQ-11 | Should time-in-current-state be a column alongside age? It separates a triage backlog from a stalled review, but two duration columns adjacent are easily confused. | U2 |
