/**
 * The filter panel (VM-UI-F-406 … VM-UI-F-410).
 *
 * Every option shows its result count, and an option that would return nothing
 * is DISABLED AND VISIBLE rather than hidden (VM-UI-F-408). Hiding it teaches
 * the reader that the dimension does not exist; showing it at zero tells them
 * the truth, which is that nothing in the current corpus has that value.
 *
 * The counts come from the API's facet endpoint, computed with each
 * dimension's own filter cleared, so a count answers "what would I get if I
 * selected this" rather than "what have I already selected".
 */
import type { Facets, FacetOption } from '../../api/schemas';
import { Chip } from '../../components/primitives';
import {
  activeFilters,
  clearAll,
  setFlag,
  toggle,
  type ExplorerState,
  type FlagDimension,
  type MultiDimension,
} from '../../lib/view-state';

const DIMENSION_LABELS: Record<MultiDimension, string> = {
  repo: 'Repository',
  tier: 'Tier',
  language: 'Language',
  category: 'Category',
  state: 'State',
  reason: 'Reason code',
  priority: 'Priority',
  severity: 'Severity',
  reachable: 'Reachability',
  depClass: 'Dependency class',
};

const FLAG_LABELS: Record<FlagDimension, { label: string; hint: string }> = {
  transitive: { label: 'Transitive', hint: 'the dependency is not declared directly' },
  firstParty: { label: 'First-party module', hint: 'the finding is inside a module this organisation owns' },
  blocked: { label: 'Blocked upstream', hint: 'waiting on a first-party fix somewhere else' },
  hasPR: { label: 'Has a pull request', hint: 'a remediation attempt is open' },
  hasTicket: { label: 'Has a ticket', hint: 'tracked in the issue tracker' },
  notReobserved: {
    label: 'Not re-observed',
    hint:
      'the most recent applicable run did not see it while it remains unresolved. ' +
      'AMBIGUOUS between a fix and a coverage gap',
  },
  slaBreached: { label: 'Past SLA', hint: 'beyond its remediation window for its priority and tier' },
};

const FACET_KEYS: Record<MultiDimension, keyof Facets> = {
  repo: 'repos',
  tier: 'tiers',
  language: 'languages',
  category: 'categories',
  state: 'states',
  reason: 'reasons',
  priority: 'priorities',
  severity: 'severities',
  reachable: 'reachable',
  depClass: 'dep_classes',
};

export function FilterPanel({
  state,
  facets,
  facetsError,
  onChange,
}: {
  state: ExplorerState;
  facets?: Facets;
  facetsError?: Error | null;
  onChange: (next: ExplorerState) => void;
}) {
  const active = activeFilters(state);

  return (
    <aside className="filters" aria-label="Filters">
      <div className="filters-head">
        <h2>Filters</h2>
        {active.length > 0 && (
          <button type="button" className="link-button" onClick={() => onChange(clearAll(state))}>
            Clear all
          </button>
        )}
      </div>

      {active.length > 0 && (
        <div className="active-filters" aria-label="Active filters">
          {active.map((f) => (
            <Chip
              key={`${f.dimension}:${f.value}`}
              label={f.label}
              onRemove={() => {
                if (f.dimension === 'q') return onChange({ ...state, q: undefined, cursor: undefined });
                if ((FLAG_LABELS as Record<string, unknown>)[f.dimension]) {
                  return onChange(setFlag(state, f.dimension as FlagDimension, undefined));
                }
                onChange(toggle(state, f.dimension as MultiDimension, f.value));
              }}
            />
          ))}
        </div>
      )}

      {facetsError != null && (
        <p className="state state-error" role="alert">
          The option counts could not be loaded, so the numbers beside each option are missing.
          The filters themselves still work.
        </p>
      )}

      {(Object.keys(DIMENSION_LABELS) as MultiDimension[]).map((dim) => {
        const options = facets ? (facets[FACET_KEYS[dim]] as FacetOption[]) : [];
        if (options.length === 0 && !facets) return null;
        return (
          <fieldset key={dim} className="filter-group">
            <legend>{DIMENSION_LABELS[dim]}</legend>
            {options.length === 0 ? (
              <p className="muted small">no options in this corpus</p>
            ) : (
              <ul>
                {options.map((opt) => {
                  const checked = (state[dim] ?? []).includes(opt.value);
                  return (
                    <li key={opt.value}>
                      <label className={opt.disabled && !checked ? 'disabled' : undefined}>
                        <input
                          type="checkbox"
                          checked={checked}
                          // Disabled, not hidden: an option that disappears
                          // looks like a dimension that does not exist.
                          disabled={opt.disabled && !checked}
                          onChange={() => onChange(toggle(state, dim, opt.value))}
                        />
                        <span className="filter-value">{labelFor(dim, opt.value)}</span>
                        <span className="filter-count" aria-label={`${opt.count} results`}>
                          {opt.count}
                        </span>
                      </label>
                    </li>
                  );
                })}
              </ul>
            )}
          </fieldset>
        );
      })}

      <fieldset className="filter-group">
        <legend>Flags</legend>
        <ul>
          {(Object.keys(FLAG_LABELS) as FlagDimension[]).map((flag) => (
            <li key={flag}>
              <label title={FLAG_LABELS[flag].hint}>
                <select
                  value={state[flag] ?? ''}
                  onChange={(e) =>
                    onChange(
                      setFlag(
                        state,
                        flag,
                        e.target.value === '' ? undefined : (e.target.value as 'true' | 'false'),
                      ),
                    )
                  }
                >
                  {/* Three options, because the flag is a tri-state in the
                      URL: unset is not the same query as false. */}
                  <option value="">any</option>
                  <option value="true">yes</option>
                  <option value="false">no</option>
                </select>
                <span className="filter-value">{FLAG_LABELS[flag].label}</span>
              </label>
            </li>
          ))}
        </ul>
      </fieldset>
    </aside>
  );
}

function labelFor(dim: MultiDimension, value: string): string {
  if (dim === 'reachable') {
    // The tri-state's middle value is spelled out, because "unknown" read
    // quickly next to "false" invites treating them as the same thing.
    if (value === 'unknown') return 'unknown (not a determination)';
  }
  if (dim === 'tier') return `tier ${value}`;
  return value;
}
