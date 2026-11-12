/**
 * Runtime validation of every API response (VM-UI-F-106).
 *
 * Why both these schemas AND the generated types exist, when that looks like
 * two definitions of one shape:
 *
 *   the GENERATED types (src/api/generated/schema.ts) are the compile-time
 *   contract, produced from the server's own reflection over its response
 *   structs. They cannot drift from the server, and a field that disappears
 *   becomes a type error rather than an `undefined` at runtime (VM-UI-NF-202).
 *
 *   these Zod schemas are the RUNTIME check. A type says what the response
 *   should be; it does not look at what arrived. A server serving an older
 *   build, a proxy rewriting a body, a field that changed meaning — all of
 *   those pass the compiler and would otherwise render as a blank panel or,
 *   worse, as a zero.
 *
 * The two are held together by a COMPILE-TIME PROOF: each schema is asserted
 * assignable to its generated counterpart at the bottom of this file. A Zod
 * schema that drifts from the generated type fails `tsc`, so the second
 * definition cannot quietly become a different definition.
 */
import { z } from 'zod';
import type { components } from './generated/schema';

type Schemas = components['schemas'];

/** A tri-state, never a boolean (VM-F-243). */
export const reachable = z.enum(['true', 'false', 'unknown']);

export const identity = z.object({
  primary_id: z.string().optional(),
  aliases: z.array(z.string()).optional(),
  rule_id: z.string().optional(),
});

export const location = z.object({
  module: z.string().optional(),
  module_major: z.string().optional(),
  package: z.string().optional(),
  function: z.string().optional(),
  file: z.string().optional(),
  line: z.number().optional(),
});

export const versions = z.object({
  current: z.string().optional(),
  fixed: z.string().optional(),
  introduced: z.string().optional(),
});

/**
 * Classification, with the absences intact.
 *
 * `epss` and `kev` are OPTIONAL, and the interface must render their absence
 * as "nothing answered" rather than as a measurement. A default of 0 here —
 * the obvious convenience — would convert a feed outage into good news, which
 * is the exact defect the availability flags exist to prevent.
 */
export const classification = z.object({
  severity: z.string(),
  cvss: z.number().optional(),
  epss: z.number().optional(),
  epss_as_of: z.string().optional(),
  kev: z.boolean().optional(),
  kev_as_of: z.string().optional(),
  exploit_intel_unavailable: z.array(z.string()).optional(),
  reachable: z.string(),
  dep_class: z.string().optional(),
  transitive: z.boolean(),
  first_party_path: z.string().optional(),
});

export const scoreInputs = z.object({
  available: z.number(),
  declared: z.number(),
  unavailable: z.array(z.string()).optional(),
  stale: z.array(z.string()).optional(),
});

export const scoreBreakdown = z.object({
  score: z.number(),
  priority: z.string(),
  base: z.number(),
  kev_boost: z.number(),
  epss_boost: z.number(),
  reach_multiplier: z.number(),
  dep_multiplier: z.number(),
  tier_multiplier: z.number(),
  fanout_multiplier: z.number(),
  explain: z.array(z.string()).optional(),
  inputs: scoreInputs,
  caveat: z.string().optional(),
  thresholds_calibrated: z.boolean(),
  recomputed: z.boolean(),
  disagrees_with_stored: z.boolean().optional(),
  stored_priority: z.string().optional(),
});

export const sla = z.object({
  computed: z.boolean(),
  status: z.string().optional(),
  window_days: z.number().optional(),
  breach_days: z.number().optional(),
  age_days: z.number(),
  windows_provisional: z.boolean(),
  caveat: z.string().optional(),
});

export const observation = z.object({
  first_seen_run: z.string().optional(),
  last_seen_run: z.string().optional(),
  first_seen_at: z.string(),
  last_seen_at: z.string(),
  resolved_at: z.string().optional(),
  not_reobserved: z.boolean(),
  not_reobserved_note: z.string().optional(),
  gap_repo_scan: z.string().optional(),
  residual_possible: z.boolean().optional(),
  residual_detail: z.string().optional(),
});

export const refs = z.object({
  ticket: z.string().optional(),
  pull_request: z.string().optional(),
  advisory_url: z.string().optional(),
  upstream_finding: z.string().optional(),
});

export const provenance = z.object({
  tools: z.array(z.string()).optional(),
  tool_versions: z.record(z.string(), z.string()).optional(),
});

export const triage = z.object({
  description: z.string().optional(),
  impact: z.string().optional(),
  remediation: z.string().optional(),
  false_positive_candidate: z.boolean(),
  fp_reasoning: z.string().optional(),
  triaged_at: z.string().optional(),
  model: z.string().optional(),
});

/* --- NuGuard (VM-UI-F-1201..1212) ------------------------------------- */

/** A tool a scan did not ask for, and why: neither ok nor failed. */
export const notRequested = z.object({ tool: z.string(), reason: z.string() });

/** A value the operator's ceiling did not allow, and what was used. */
export const clipNote = z.object({ field: z.string(), asked: z.string(), used: z.string(), why: z.string() });

/**
 * What one repository's scan uses (or used), after inheritance and the
 * ceiling: provenance a NuGuard finding or inventory is read against.
 */
export const effectiveNuGuard = z.object({
  enabled: z.boolean(),
  tools: z.array(z.string()),
  include_posture: z.boolean(),
  timeout_s: z.number(),
  keep_sbom: z.boolean(),
  from: z.string(),
  reason: z.string().optional(),
  clips: z.array(clipNote).optional(),
  not_requested: z.array(notRequested).optional(),
});

/** A NuGuard finding's own detail, on the detail view only. */
export const nuguardDetail = z.object({
  version: z.string(),
  rule: z.string(),
  sub_tool: z.string().optional(),
  owasp_llm_ref: z.string().optional(),
  owasp_asi_ref: z.string().optional(),
  mitre_atlas_technique: z.string().optional(),
  function: z.string().optional(),
  scanned: z.string().optional(),
  last_run: z.string().optional(),
  effective: effectiveNuGuard.optional(),
  note: z.string().optional(),
});

export const finding = z.object({
  fingerprint: z.string(),
  repo: z.string(),
  category: z.string(),
  identity: identity,
  location: location,
  versions: versions.optional(),
  classification: classification,
  state: z.string(),
  partition: z.string(),
  priority: z.string().optional(),
  reason_code: z.string().optional(),
  verified_reason: z.string().optional(),
  credential_type: z.string().optional(),
  description: z.string().optional(),
  description_source: z.string().optional(),
  sla: sla,
  observation: observation,
  refs: refs,
  provenance: provenance,
  triage: triage.optional(),
  annotations: z.record(z.string(), z.string()).optional(),
  score: scoreBreakdown.optional(),
  restricted: z.boolean().optional(),
  nuguard: nuguardDetail.optional(),
});

export const corpus = z.object({
  scope: z.string(),
  description: z.string(),
  excludes: z.string().optional(),
  excluded_count: z.number(),
  run_id: z.string().optional(),
});

export const findingPage = z.object({
  findings: z.array(finding),
  matched: z.number(),
  in_corpus: z.number(),
  total: z.number(),
  corpus: corpus,
  next_cursor: z.string().optional(),
  sort: z.string(),
  dir: z.string(),
  restricted_count: z.number(),
});

export const facetOption = z.object({
  value: z.string(),
  count: z.number(),
  disabled: z.boolean(),
});

export const facets = z.object({
  repos: z.array(facetOption),
  tiers: z.array(facetOption),
  languages: z.array(facetOption),
  categories: z.array(facetOption),
  states: z.array(facetOption),
  reasons: z.array(facetOption),
  priorities: z.array(facetOption),
  severities: z.array(facetOption),
  reachable: z.array(facetOption),
  dep_classes: z.array(facetOption),
});

export const transition = z.object({
  from: z.string().optional(),
  to: z.string(),
  actor: z.string(),
  cause: z.string().optional(),
  at: z.string(),
  scan_outcome: z.string().optional(),
});

export const runObservation = z.object({
  run_id: z.string(),
  kind: z.string(),
  at: z.string(),
  observed: z.boolean(),
  outcome: z.string().optional(),
  tools: z.array(z.string()).optional(),
  note: z.string().optional(),
});

export const timeline = z.object({
  fingerprint: z.string(),
  transitions: z.array(transition),
  observations: z.array(runObservation),
});

export const attempt = z.object({
  branch: z.string(),
  fix_group_id: z.string().optional(),
  repo: z.string(),
  number: z.number().optional(),
  url: z.string().optional(),
  state: z.string(),
  merged: z.boolean(),
  opened_at: z.string(),
  closed_at: z.string().optional(),
  findings: z.array(z.string()).optional(),
  ticket_url: z.string().optional(),
  confirmed_at: z.string().optional(),
});

export const runSummary = z.object({
  id: z.string(),
  kind: z.string(),
  started_at: z.string(),
  finished_at: z.string().optional(),
  trigger: z.string().optional(),
  scanner_image: z.string().optional(),
  repos_planned: z.number(),
  repos_scanned: z.number(),
  repos_failed: z.number(),
  partial: z.boolean(),
  partial_note: z.string().optional(),
});

export const runPage = z.object({
  runs: z.array(runSummary),
  next_cursor: z.string().optional(),
  total: z.number(),
});

/**
 * The report package's structures, validated loosely on purpose.
 *
 * Counts, deltas, coverage and provenance are the REPORT's shapes, carried
 * through the API rather than restated (so the interface cannot disagree with
 * a report about the same run). Their maps are open-ended — a new reason code
 * or state appears as a new key — so validating them field by field would make
 * the interface reject a run it can render perfectly well. The fields the
 * interface actually reads are named; the rest passes through.
 */
const openMap = z.record(z.string(), z.number());

export const counts = z
  .object({
    total: z.number(),
    unresolved: z.number(),
    pending_verification: z.number(),
    resolved: z.number(),
    by_priority: openMap,
    by_state: openMap,
    by_category: openMap,
    not_reobserved: z.number(),
    sla_breached: z.number(),
    sla_paused: z.number(),
    not_fixed_by_reason: openMap.optional(),
    not_fixed_unexplained: z.number(),
    sla_not_computed: z.number(),
    suppression_proposals_pending: z.number(),
    suppression_proposals_overdue: z.number(),
    secrets_removed_rotation_unconfirmed: z.number(),
  })
  .passthrough();

export const delta = z
  .object({
    previous_run: z.string().optional(),
    comparable: z.boolean(),
    total_change: z.number(),
    unresolved_change: z.number(),
    new: z.number(),
    no_longer_observed: z.number(),
    verified: z.number(),
    regressed: z.number(),
  })
  .passthrough();

export const staleness = z
  .object({
    in_scope: z.number(),
    never_scanned: z.number(),
    max_age: z.number(),
    p95_age: z.number(),
    median_age: z.number(),
    stalest_repo: z.string().optional(),
  })
  .passthrough();

export const escalation = z
  .object({
    repo: z.string(),
    sweeps_since_qualifying: z.number(),
    cause: z.string().optional(),
    last_qualifying_run: z.string().optional(),
    last_qualifying_at: z.string().optional(),
  })
  .passthrough();

export const coverage = z
  .object({
    in_scope: z.number(),
    complete: z.number(),
    partial: z.number(),
    failed: z.number(),
    not_dispatched: z.number(),
    no_result: z.number(),
    by_cause: openMap.optional(),
    percent: z.number(),
    staleness: staleness,
    escalations: z.array(escalation).optional(),
    unscanned_repos: z.array(z.string()).optional(),
  })
  .passthrough();

export const reportProvenance = z
  .object({
    scanner_image: z.string().optional(),
    tool_versions: z.record(z.string(), z.string()).optional(),
    thresholds_calibrated: z.boolean(),
    sla_windows_calibrated: z.boolean(),
    scoring_inputs_available: z.number(),
    scoring_inputs_declared: z.number(),
    caveats: z.array(z.string()).optional(),
  })
  .passthrough();

export const overview = z.object({
  run: runSummary,
  live: z.boolean(),
  live_note: z.string().optional(),
  snapshot_id: z.string().optional(),
  content_hash: z.string().optional(),
  counts: counts,
  delta: delta,
  coverage: coverage,
  provenance: reportProvenance,
  caveats: z.array(z.string()).optional(),
  nuguard: z
    .array(z.object({ repo: z.string(), effective: effectiveNuGuard, not_requested: z.array(notRequested).optional() }))
    .optional(),
});

export const coverageGap = z.object({
  repo: z.string(),
  run_id: z.string(),
  run_at: z.string(),
  outcome: z.string(),
  classification: z.string(),
  cause: z.string().optional(),
  detail: z.string().optional(),
  owner: z.string().optional(),
  tools_ok: z.array(z.string()).optional(),
  tools_failed: z.array(z.string()).optional(),
  tools_not_requested: z.array(notRequested).optional(),
  consecutive_runs: z.number(),
  consecutive_deferrals: z.number(),
  last_qualifying_run: z.string().optional(),
  last_qualifying_at: z.string().optional(),
  hours_without_data: z.number().optional(),
  never_scanned: z.boolean(),
  not_reobserved: z.number(),
  findings_query: z.string().optional(),
});

export const repoCoverageHistory = z.object({
  repo: z.string(),
  outcomes: z.array(z.string()),
  runs: z.array(z.string()),
});

export const coverageView = z.object({
  run_id: z.string().optional(),
  gaps: z.array(coverageGap),
  in_scope: z.number(),
  complete: z.number(),
  percent: z.number(),
  staleness: staleness,
  escalations: z.array(escalation).optional(),
  warning: z.string(),
  history: z.array(repoCoverageHistory),
  not_requested: z.array(z.object({ repo: z.string(), run_id: z.string(), tools: z.array(notRequested) })),
});

export const repoSummary = z.object({
  name: z.string(),
  tier: z.number(),
  languages: z.array(z.string()),
  has_test_suite: z.boolean(),
  module_topology: z.string().optional(),
  codeowners: z.array(z.string()).optional(),
  archived: z.boolean().optional(),
  open_findings: z.number(),
  by_severity: openMap.optional(),
  by_category: openMap.optional(),
  sla_breached: z.number(),
  not_reobserved: z.number(),
  last_scanned_run: z.string().optional(),
  last_scanned_at: z.string().optional(),
  last_outcome: z.string().optional(),
  last_commit_sha: z.string().optional(),
  no_test_suite_note: z.string().optional(),
});

export const dependency = z.object({
  module: z.string(),
  version: z.string(),
  direct: z.boolean(),
  replaced: z.boolean(),
});

export const consumer = z.object({
  repo: z.string(),
  version: z.string(),
  tier: z.number(),
  reachable: z.string(),
  replaced: z.boolean().optional(),
  excluded: z.boolean().optional(),
  reason: z.string().optional(),
});

/**
 * What the latest scan found of a repository's AI use: an inventory signal,
 * never findings. "Not measured" is its own state, said in words, never
 * rendered as zero.
 */
export const aiComponents = z.object({
  measured: z.boolean(),
  note: z.string(),
  run_id: z.string().optional(),
  source: z.string().optional(),
  rulepack_sha256: z.string().optional(),
  image_digest: z.string().optional(),
  node_counts: openMap.optional(),
  edge_count: z.number().optional(),
  frameworks: z.array(z.string()).optional(),
  model_providers: z.array(z.string()).optional(),
  posture_observations: openMap.optional(),
  ai_sbom: z
    .object({ stored: z.boolean(), size_bytes: z.number(), sha256: z.string(), withheld: z.string().optional() })
    .optional(),
});

export const repoDetail = z.object({
  repo: repoSummary,
  sla_windows: z.record(z.string(), z.record(z.string(), z.string())),
  sla_windows_provisional: z.boolean(),
  dependencies: z.array(dependency).optional(),
  open_prs: z.array(attempt).optional(),
  consumers: z.array(consumer).optional(),
  coverage: z.array(repoCoverageHistory),
  ai_components: aiComponents,
});

export const wave = z.object({
  module: z.string(),
  owner_repo: z.string(),
  upstream_finding: z.string().optional(),
  upstream_state: z.string().optional(),
  wave1_pr: z.string().optional(),
  wave1_pr_at: z.string().optional(),
  wave1_age_hours: z.number().optional(),
  trigger: z.string(),
  depend_count: z.number(),
  reach_count: z.number(),
  unknown_count: z.number(),
  consumers: z.array(consumer),
  version_spread: openMap.optional(),
  steps: z.array(z.string()),
});

export const trendPoint = z.object({
  run_id: z.string(),
  at: z.string(),
  value: z.number(),
  partial: z.boolean(),
  scanner_changed: z.boolean(),
  live: z.boolean(),
  scanner_image: z.string().optional(),
});

export const trendSeries = z.object({
  metric: z.string(),
  kind: z.string(),
  points: z.array(trendPoint),
  note: z.string().optional(),
});

export const reportSummary = z.object({
  id: z.string(),
  kind: z.string(),
  repo: z.string().optional(),
  template: z.string(),
  anchor_run_id: z.string(),
  issued_at: z.string(),
  issued_by: z.string().optional(),
  content_hash: z.string(),
  supersedes: z.string().optional(),
  superseded_by: z.string().optional(),
  redacted: z.boolean().optional(),
  withheld_count: z.number(),
});

export const stateChange = z.object({
  finding: finding,
  from: z.string(),
  to: z.string(),
});

export const comparison = z.object({
  a: runSummary,
  b: runSummary,
  comparable: z.boolean(),
  note: z.string().optional(),
  appearing: z.array(finding),
  disappearing: z.array(finding),
  changed: z.array(stateChange),
});

export const health = z.object({
  ok: z.boolean(),
  backend: z.string(),
  degraded: z.array(z.string()).optional(),
  demo: z.boolean(),
  scan_requests: z.boolean(),
});

export const scanRequest = z.object({
  id: z.string(),
  repo: z.string(),
  batch_id: z.string().optional(),
  source: z.string(),
  requested_by: z.string(),
  requested_at: z.string(),
  status: z.enum(['queued', 'running', 'finished', 'failed', 'timed_out', 'interrupted', 'refused']),
  reason: z.string().optional(),
  run_id: z.string().optional(),
  started_at: z.string().optional(),
  finished_at: z.string().optional(),
  retry_of: z.string().optional(),
  nuguard: z
    .object({
      mode: z.enum(['default', 'on', 'off']),
      tools: z.array(z.string()).optional(),
      include_posture: z.boolean().optional(),
      keep_sbom: z.boolean().optional(),
    })
    .optional(),
});

export const scanRequestResult = z.object({ request: scanRequest, merged: z.boolean() });

export const scanBatchResult = z.object({
  batch_id: z.string(),
  requests: z.array(scanRequest),
  queued: z.number(),
  merged: z.number(),
});

export const csrfToken = z.object({ token: z.string(), expires_at: z.string() });

export const githubAccount = z.object({
  account: z.string(),
  kind: z.string(),
  scopes: z.array(z.string()),
  expires_at: z.string().optional(),
  expires_in_days: z.number().optional(),
  read_only: z.string(),
  checked_at: z.string(),
  checked_by: z.string(),
});

export const discoveredRepo = z.object({
  name: z.string(),
  account: z.string(),
  affiliation: z.string(),
  private: z.boolean(),
  archived: z.boolean(),
  fork: z.boolean(),
  size_kb: z.number(),
  default_branch: z.string(),
  language: z.string().optional(),
  included: z.boolean(),
  reason: z.string().optional(),
  detail: z.string().optional(),
  discovered_at: z.string(),
});

export const excludedRepo = z.object({
  name: z.string(),
  reason: z.string(),
  excluded_by: z.string(),
  excluded_at: z.string(),
});

export const githubView = z.object({
  connections: z.array(githubAccount),
  discovered: z.array(discoveredRepo),
  exclusions: z.array(excludedRepo),
  summary: z.object({
    seen: z.number(),
    included: z.number(),
    skipped: openMap,
    last_discovered_at: z.string().optional(),
  }),
});

export const nuguardStatus = z.object({
  reported: z.boolean(),
  stale: z.boolean(),
  stale_note: z.string().optional(),
  checked_at: z.string().optional(),
  reachable: z.boolean().optional(),
  service_version: z.string().optional(),
  pinned_version: z.string().optional(),
  version_ok: z.boolean().optional(),
  tools_allowed_by_service: z.array(z.string()).optional(),
  last_error: z.string().optional(),
});

export const nuguardFleet = z.object({
  enabled: z.boolean(),
  tools: z.array(z.string()),
  include_posture: z.boolean(),
  timeout_s: z.number(),
});

export const nuguardCeiling = z.object({
  configured: z.boolean(),
  allow_tools: z.array(z.string()),
  allow_posture: z.boolean(),
  max_timeout_s: z.number(),
  service_tools: z.array(z.string()).optional(),
  defaults: nuguardFleet,
});

export const nuguardOverride = z.object({
  repo: z.string(),
  mode: z.string(),
  tools: z.array(z.string()).optional(),
  include_posture: z.boolean().optional(),
  changed_by: z.string(),
  changed_at: z.string(),
});

export const nuguardAudit = z.object({
  id: z.number(),
  scope: z.string(),
  repo: z.string().optional(),
  before: z.record(z.string(), z.unknown()).optional(),
  after: z.record(z.string(), z.unknown()).optional(),
  changed_by: z.string(),
  changed_at: z.string(),
  reason: z.string().optional(),
});

export const nuguardView = z.object({
  configured: z.boolean(),
  note: z.string().optional(),
  status: nuguardStatus,
  ceiling: nuguardCeiling.optional(),
  selectable: z.array(z.string()),
  fleet: z.object({
    set: z.boolean(),
    settings: nuguardFleet,
    changed_by: z.string().optional(),
    changed_at: z.string().optional(),
  }),
  override_count: z.number(),
  overrides: z.array(nuguardOverride),
  audit: z.array(nuguardAudit),
  can_edit: z.boolean(),
});

export const nuguardAuditPage = z.object({ entries: z.array(nuguardAudit), next: z.string().optional() });

export const nuguardScanOptions = z.object({
  run_id: z.string(),
  run_at: z.string().optional(),
  effective: effectiveNuGuard.optional(),
  not_requested: z.array(notRequested).optional(),
  note: z.string().optional(),
});

export const repoNuGuard = z.object({
  repo: z.string(),
  configured: z.boolean(),
  note: z.string().optional(),
  override: nuguardOverride.optional(),
  effective: effectiveNuGuard,
  recent: z.array(nuguardScanOptions),
  can_edit: z.boolean(),
});

export const nuguardPreview = z.object({
  repo: z.string(),
  configured: z.boolean(),
  effective: effectiveNuGuard,
  clips: z.array(clipNote),
  note: z.string().optional(),
});

export const apiError = z.object({
  error: z.string(),
  detail: z.string().optional(),
  remedy: z.string().optional(),
});

export type Finding = z.infer<typeof finding>;
export type FindingPage = z.infer<typeof findingPage>;
export type Facets = z.infer<typeof facets>;
export type FacetOption = z.infer<typeof facetOption>;
export type Timeline = z.infer<typeof timeline>;
export type Attempt = z.infer<typeof attempt>;
export type RunSummary = z.infer<typeof runSummary>;
export type RunPage = z.infer<typeof runPage>;
export type Overview = z.infer<typeof overview>;
export type CoverageView = z.infer<typeof coverageView>;
export type CoverageGap = z.infer<typeof coverageGap>;
export type RepoSummary = z.infer<typeof repoSummary>;
export type RepoDetail = z.infer<typeof repoDetail>;
export type Wave = z.infer<typeof wave>;
export type Consumer = z.infer<typeof consumer>;
export type TrendSeries = z.infer<typeof trendSeries>;
export type ReportSummary = z.infer<typeof reportSummary>;
export type Comparison = z.infer<typeof comparison>;
export type StateChange = z.infer<typeof stateChange>;
export type Health = z.infer<typeof health>;
export type GitHubView = z.infer<typeof githubView>;
export type ScanRequest = z.infer<typeof scanRequest>;
export type DiscoveredRepo = z.infer<typeof discoveredRepo>;
export type ApiError = z.infer<typeof apiError>;
export type EffectiveNuGuard = z.infer<typeof effectiveNuGuard>;
export type NotRequested = z.infer<typeof notRequested>;
export type NuGuardView = z.infer<typeof nuguardView>;
export type NuGuardAuditEntry = z.infer<typeof nuguardAudit>;
export type NuGuardAuditPage = z.infer<typeof nuguardAuditPage>;
export type RepoNuGuard = z.infer<typeof repoNuGuard>;
export type NuGuardPreview = z.infer<typeof nuguardPreview>;
export type NuGuardDetail = z.infer<typeof nuguardDetail>;
export type ScanNuGuardOptions = NonNullable<ScanRequest['nuguard']>;

/* ---------------------------------------------------------------------------
 * The compile-time proof.
 *
 * Each line asserts that what the runtime validator produces MATCHES what the
 * GENERATED type describes. A field renamed on the server changes the
 * generated type, the assertion fails, and `npm run typecheck` fails — which
 * is VM-UI-NF-202: a schema change surfaces as a compile error rather than as
 * a runtime failure.
 *
 * Two things are checked, because each catches a different lie:
 *
 *   ASSIGNABILITY — the validator's output must be usable where the generated
 *   type is expected. This catches a field whose TYPE drifted (a boolean that
 *   became a number).
 *
 *   NO EXTRA KEYS — the validator must not claim a field the server does not
 *   have. TypeScript's structural assignability permits extra properties, so
 *   without this an invented `credential_value` field would type-check
 *   perfectly and the interface would render a column the API can never fill —
 *   which for THAT field name would also be the disclosure this build spent
 *   three layers preventing.
 *
 * The first version of this proof was decorative: it resolved to `never` on
 * failure, and `never extends true` is true, so nothing could ever fail it.
 * Both mutations below now fail the build, which is the only reason to believe
 * the third one would.
 *
 * Every NESTED shape is proved separately. A nested extra key is invisible to
 * a top-level key check, and the nested shapes are where the honesty fields
 * live: the absent EPSS, the not-re-observed note, the SLA caveat.
 * ------------------------------------------------------------------------ */
type Matches<Actual, Expected> = [Actual] extends [Expected]
  ? [Exclude<keyof Actual, keyof Expected>] extends [never]
    ? true
    : { error: 'the validator claims keys the server does not have'; keys: Exclude<keyof Actual, keyof Expected> }
  : { error: 'the validator does not match the generated type'; actual: Actual; expected: Expected };

type Proof<T extends true> = T;

export type _proofs = [
  Proof<Matches<Finding, Schemas['Finding']>>,
  Proof<Matches<FindingPage, Schemas['FindingPage']>>,
  Proof<Matches<Facets, Schemas['Facets']>>,
  Proof<Matches<Timeline, Schemas['Timeline']>>,
  Proof<Matches<Attempt, Schemas['Attempt']>>,
  Proof<Matches<RunSummary, Schemas['RunSummary']>>,
  Proof<Matches<RunPage, Schemas['RunPage']>>,
  Proof<Matches<CoverageGap, Schemas['CoverageGap']>>,
  Proof<Matches<RepoSummary, Schemas['RepoSummary']>>,
  Proof<Matches<Wave, Schemas['Wave']>>,
  Proof<Matches<Consumer, Schemas['Consumer']>>,
  Proof<Matches<TrendSeries, Schemas['TrendSeries']>>,
  Proof<Matches<ReportSummary, Schemas['ReportSummary']>>,
  Proof<Matches<Comparison, Schemas['Comparison']>>,
  Proof<Matches<StateChange, Schemas['StateChange']>>,
  Proof<Matches<Health, Schemas['Health']>>,
  Proof<Matches<ApiError, Schemas['Error']>>,
  Proof<Matches<NuGuardView, Schemas['NuGuardView']>>,
  Proof<Matches<NuGuardAuditPage, Schemas['NuGuardAuditPage']>>,
  Proof<Matches<RepoNuGuard, Schemas['RepoNuGuardView']>>,
  Proof<Matches<NuGuardPreview, Schemas['NuGuardPreview']>>,
  Proof<Matches<z.infer<typeof overview>, Schemas['Overview']>>,
  Proof<Matches<z.infer<typeof coverageView>, Schemas['CoverageView']>>,
  Proof<Matches<ScanRequest, Schemas['ScanRequestView']>>,
  Proof<Matches<z.infer<typeof aiComponents>, Schemas['AIComponents']>>,

  // The nested shapes, where the honesty fields live.
  Proof<Matches<z.infer<typeof identity>, Schemas['Identity']>>,
  Proof<Matches<z.infer<typeof location>, Schemas['Location']>>,
  Proof<Matches<z.infer<typeof versions>, Schemas['Versions']>>,
  Proof<Matches<z.infer<typeof classification>, Schemas['Classification']>>,
  Proof<Matches<z.infer<typeof sla>, Schemas['SLA']>>,
  Proof<Matches<z.infer<typeof observation>, Schemas['Observation']>>,
  Proof<Matches<z.infer<typeof refs>, Schemas['Refs']>>,
  Proof<Matches<z.infer<typeof provenance>, Schemas['Provenance']>>,
  Proof<Matches<z.infer<typeof triage>, Schemas['Triage']>>,
  Proof<Matches<z.infer<typeof scoreBreakdown>, Schemas['ScoreBreakdown']>>,
  Proof<Matches<z.infer<typeof scoreInputs>, Schemas['ScoreInputs']>>,
  Proof<Matches<z.infer<typeof corpus>, Schemas['Corpus']>>,
  Proof<Matches<z.infer<typeof facetOption>, Schemas['FacetOption']>>,
  Proof<Matches<z.infer<typeof transition>, Schemas['Transition']>>,
  Proof<Matches<z.infer<typeof runObservation>, Schemas['RunObservation']>>,
  Proof<Matches<z.infer<typeof repoCoverageHistory>, Schemas['RepoCoverageHistory']>>,
  Proof<Matches<z.infer<typeof dependency>, Schemas['Dependency']>>,
  Proof<Matches<z.infer<typeof trendPoint>, Schemas['TrendPoint']>>,
  Proof<Matches<NuGuardDetail, Schemas['NuGuardDetail']>>,
  Proof<Matches<z.infer<typeof nuguardStatus>, Schemas['NuGuardStatusView']>>,
  Proof<Matches<z.infer<typeof nuguardOverride>, Schemas['NuGuardOverrideView']>>,
  Proof<Matches<z.infer<typeof nuguardAudit>, Schemas['NuGuardAuditView']>>,
  Proof<Matches<z.infer<typeof nuguardScanOptions>, Schemas['NuGuardScanOptions']>>,
  Proof<Matches<z.infer<typeof effectiveNuGuard>, NonNullable<Schemas['NuGuardDetail']['effective']>>>,
];
