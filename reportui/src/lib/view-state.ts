/**
 * The URL holds the view state (VM-UI-F-401, VM-UI-F-420, UI-ADR-03).
 *
 * Every filter, the sort, the corpus scope and the page cursor live in the
 * address bar, so a filtered view is shareable by copying the address and a
 * reload shows the same list. Nothing about the current view lives only in a
 * component's state: two sources of view state disagree the moment someone
 * uses the back button.
 *
 * The schema below is the SINGLE definition of that state. It types the view,
 * validates what arrives in the URL, and serialises to the API's query
 * parameters — so adding a filter dimension is one change here and one in the
 * API (VM-UI-NF-201).
 *
 * An unparseable parameter is DROPPED and reported, never guessed at: showing
 * someone a list they did not ask for, with no indication, is worse than
 * showing them the unfiltered one.
 */
import { z } from 'zod';

export const scopeSchema = z.enum(['open', 'all', 'run']);
export const sortSchema = z.enum(['priority', 'severity', 'first_seen', 'last_seen', 'repo']);
export const dirSchema = z.enum(['asc', 'desc']);

const list = z
  .string()
  .transform((v) => v.split(',').map((s) => s.trim()).filter(Boolean))
  .pipe(z.array(z.string()));

const tri = z.enum(['true', 'false']);

/** The finding explorer's view state. */
export const explorerState = z.object({
  scope: scopeSchema.default('open'),
  run: z.string().optional(),
  repo: list.optional(),
  tier: list.optional(),
  language: list.optional(),
  category: list.optional(),
  state: list.optional(),
  reason: list.optional(),
  priority: list.optional(),
  severity: list.optional(),
  reachable: list.optional(),
  depClass: list.optional(),
  // The tools that reported a finding (VM-UI-F-1207).
  found_by: list.optional(),
  transitive: tri.optional(),
  firstParty: tri.optional(),
  blocked: tri.optional(),
  hasPR: tri.optional(),
  hasTicket: tri.optional(),
  notReobserved: tri.optional(),
  slaBreached: tri.optional(),
  q: z.string().optional(),
  sort: sortSchema.default('priority'),
  dir: dirSchema.default('desc'),
  cursor: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(500).default(50),
});

export type ExplorerState = z.infer<typeof explorerState>;

/** The dimensions that are multi-select, for the filter panel. */
export const MULTI_DIMENSIONS = [
  'repo',
  'tier',
  'language',
  'category',
  'state',
  'reason',
  'priority',
  'severity',
  'reachable',
  'depClass',
  'found_by',
] as const;
export type MultiDimension = (typeof MULTI_DIMENSIONS)[number];

/** The boolean dimensions, which are tri-state in the URL: absent, true, false. */
export const FLAG_DIMENSIONS = [
  'transitive',
  'firstParty',
  'blocked',
  'hasPR',
  'hasTicket',
  'notReobserved',
  'slaBreached',
] as const;
export type FlagDimension = (typeof FLAG_DIMENSIONS)[number];

export interface ParseResult {
  state: ExplorerState;
  /** Dropped names any parameter that could not be understood. */
  dropped: string[];
}

/**
 * parseExplorerState reads the view state from a query string.
 *
 * A parameter that fails validation is dropped and NAMED, so the interface can
 * say "this part of the link was not understood" rather than silently
 * rendering a different query from the one in the address bar.
 */
export function parseExplorerState(search: string): ParseResult {
  const params = new URLSearchParams(search);
  const raw: Record<string, string> = {};
  for (const [k, v] of params.entries()) {
    if (v !== '') raw[k] = v;
  }

  const first = explorerState.safeParse(raw);
  if (first.success) return { state: first.data, dropped: [] };

  const dropped: string[] = [];
  const cleaned = { ...raw };
  for (const issue of first.error.issues) {
    const key = String(issue.path[0] ?? '');
    if (key && key in cleaned) {
      delete cleaned[key];
      dropped.push(key);
    }
  }
  const second = explorerState.safeParse(cleaned);
  return {
    state: second.success ? second.data : explorerState.parse({}),
    dropped,
  };
}

/** serialiseExplorerState renders the state back into a query string. */
export function serialiseExplorerState(state: ExplorerState): string {
  const defaults = explorerState.parse({});
  const params = new URLSearchParams();
  const put = (key: string, value: string | undefined) => {
    if (value === undefined || value === '') return;
    params.set(key, value);
  };

  if (state.scope !== defaults.scope) put('scope', state.scope);
  put('run', state.run);
  for (const dim of MULTI_DIMENSIONS) {
    const values = state[dim];
    if (values && values.length > 0) put(dim, values.join(','));
  }
  for (const flag of FLAG_DIMENSIONS) put(flag, state[flag]);
  put('q', state.q);
  if (state.sort !== defaults.sort) put('sort', state.sort);
  if (state.dir !== defaults.dir) put('dir', state.dir);
  put('cursor', state.cursor);
  if (state.limit !== defaults.limit) put('limit', String(state.limit));

  const rendered = params.toString();
  return rendered ? `?${rendered}` : '';
}

/**
 * apiQuery renders the state as the API's query string.
 *
 * Scope is ALWAYS sent, even at its default, because the API refuses a query
 * with no corpus — and it refuses on purpose: a count is meaningless without
 * saying which findings it counts, and a default applied on the server would
 * be a default nobody chose.
 */
export function apiQuery(state: ExplorerState, extra?: { withoutCursor?: boolean }): string {
  const params = new URLSearchParams();
  params.set('scope', state.scope);
  if (state.run) params.set('run', state.run);
  for (const dim of MULTI_DIMENSIONS) {
    const values = state[dim];
    if (values) for (const v of values) params.append(dim, v);
  }
  for (const flag of FLAG_DIMENSIONS) {
    const value = state[flag];
    if (value) params.set(flag, value);
  }
  if (state.q) params.set('q', state.q);
  params.set('sort', state.sort);
  params.set('dir', state.dir);
  params.set('limit', String(state.limit));
  if (state.cursor && !extra?.withoutCursor) params.set('cursor', state.cursor);
  return `?${params.toString()}`;
}

/** toggle adds or removes one value from a multi-select dimension. */
export function toggle(state: ExplorerState, dim: MultiDimension, value: string): ExplorerState {
  const current = state[dim] ?? [];
  const next = current.includes(value)
    ? current.filter((v) => v !== value)
    : [...current, value];
  return {
    ...state,
    [dim]: next.length > 0 ? next : undefined,
    // Any filter change invalidates the cursor: it names a position in a
    // DIFFERENT result set, and resuming from it would show a page from the
    // middle of a list the reader is no longer looking at.
    cursor: undefined,
  };
}

/** setFlag sets or clears a tri-state flag. */
export function setFlag(
  state: ExplorerState,
  flag: FlagDimension,
  value: 'true' | 'false' | undefined,
): ExplorerState {
  return { ...state, [flag]: value, cursor: undefined };
}

/** activeFilters lists the filters in force, for the removable chips. */
export function activeFilters(
  state: ExplorerState,
): { dimension: string; value: string; label: string }[] {
  const out: { dimension: string; value: string; label: string }[] = [];
  for (const dim of MULTI_DIMENSIONS) {
    for (const value of state[dim] ?? []) {
      out.push({ dimension: dim, value, label: `${dim}: ${value}` });
    }
  }
  for (const flag of FLAG_DIMENSIONS) {
    const value = state[flag];
    if (value) out.push({ dimension: flag, value, label: `${flag} is ${value}` });
  }
  if (state.q) out.push({ dimension: 'q', value: state.q, label: `text: ${state.q}` });
  return out;
}

/** clearAll resets the filters, keeping the corpus and the ordering. */
export function clearAll(state: ExplorerState): ExplorerState {
  const cleared = explorerState.parse({});
  return { ...cleared, scope: state.scope, run: state.run, sort: state.sort, dir: state.dir };
}
