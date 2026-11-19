/**
 * The finding explorer (U1).
 *
 * The load-bearing view, and the one the build order puts first: an overview
 * built before it is an appealing page that links to nothing.
 *
 * Three properties are load-bearing rather than decorative:
 *
 *   THE CORPUS IS STATED IN WORDS (VM-UI-F-417/418/419). A count is
 *   meaningless without saying which findings it counts, so the corpus, what
 *   it excludes, and the three separate figures — matching, in corpus, total —
 *   are all on screen. The default is "unresolved across ALL runs", not
 *   "findings in the latest run", because the latter hides everything the most
 *   recent sweep did not re-observe (VM-UI-F-411).
 *
 *   FILTERING AND SORTING ARE THE SERVER'S (VM-UI-F-402). The client never
 *   fetches the whole set. The address bar holds the query; the server answers
 *   it.
 *
 *   PAGINATION IS BY CURSOR (VM-UI-F-403). Findings change state while
 *   somebody is reading, and offset pagination silently skips and repeats rows
 *   when they do.
 */
import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import { Empty, ErrorState, Loading, Panel } from '../../components/primitives';
import { Link, useRouter } from '../../lib/router';
import { toCSV } from '../../lib/format';
import {
  apiQuery,
  parseExplorerState,
  serialiseExplorerState,
  type ExplorerState,
} from '../../lib/view-state';
import { FilterPanel } from './FilterPanel';
import { FindingTable } from './FindingTable';

export function Explorer() {
  const { search, navigate } = useRouter();
  const { state, dropped } = useMemo(() => parseExplorerState(search), [search]);
  const [text, setText] = useState(state.q ?? '');

  useEffect(() => setText(state.q ?? ''), [state.q]);

  // Hiding the filter panel gives the table its width back. A per-viewer
  // convenience, like row density: localStorage, never the URL, and the
  // active filters stay in force (and listed as chips) while it is hidden.
  const [filtersHidden, setFiltersHidden] = useState(() => {
    try {
      return window.localStorage.getItem('explorer.filters') === 'hidden';
    } catch {
      return false;
    }
  });
  useEffect(() => {
    try {
      window.localStorage.setItem('explorer.filters', filtersHidden ? 'hidden' : 'shown');
    } catch {
      // Blocked site data: the choice lasts for this page only.
    }
  }, [filtersHidden]);

  const update = (next: ExplorerState) => {
    navigate(`/findings${serialiseExplorerState(next)}`);
  };

  const query = apiQuery(state);
  const page = useQuery({
    queryKey: ['findings', query],
    queryFn: () => api.findings(query),
  });
  // The facets are a separate request on purpose: they are an aggregate over
  // the whole matching set, not a summary of the page, and a slow facet query
  // must not block the rows (VM-UI-F-905).
  const facetQuery = apiQuery({ ...state, cursor: undefined }, { withoutCursor: true });
  const facets = useQuery({
    queryKey: ['facets', facetQuery],
    queryFn: () => api.facets(facetQuery),
  });

  return (
    <div className={`explorer${filtersHidden ? ' filters-hidden' : ''}`}>
      {!filtersHidden && (
        <FilterPanel
          state={state}
          facets={facets.data}
          facetsError={facets.error as Error | null}
          onChange={update}
        />
      )}

      <div className="explorer-main">
        <Panel
          title="Findings"
          subtitle={
            page.data ? (
              <CorpusStatement
                matched={page.data.matched}
                inCorpus={page.data.in_corpus}
                total={page.data.total}
                description={page.data.corpus.description}
                excludes={page.data.corpus.excludes}
                excludedCount={page.data.corpus.excluded_count}
                restricted={page.data.restricted_count}
              />
            ) : null
          }
          actions={
            <>
              <button
                type="button"
                onClick={() => setFiltersHidden((h) => !h)}
                aria-pressed={!filtersHidden}
              >
                {filtersHidden ? 'Show filters' : 'Hide filters'}
              </button>
              <select
                value={state.scope}
                onChange={(e) =>
                  update({
                    ...state,
                    scope: e.target.value as ExplorerState['scope'],
                    cursor: undefined,
                  })
                }
                aria-label="Corpus"
              >
                <option value="open">unresolved across all runs</option>
                <option value="all">everything ever recorded</option>
                <option value="run">observed in one run</option>
              </select>
              {state.scope === 'run' && (
                <input
                  type="text"
                  value={state.run ?? ''}
                  placeholder="run identifier"
                  aria-label="Run identifier"
                  onChange={(e) => update({ ...state, run: e.target.value, cursor: undefined })}
                />
              )}
              {page.data && page.data.findings.length > 0 && (
                <button type="button" className="link-button" onClick={() => exportCSV(page.data)}>
                  Export this page (CSV)
                </button>
              )}
            </>
          }
        >
          <form
            className="search"
            onSubmit={(e) => {
              e.preventDefault();
              update({ ...state, q: text || undefined, cursor: undefined });
            }}
          >
            <label htmlFor="q">
              Search identifier, <strong>any alias</strong>, module, package, file or repository
            </label>
            <input
              id="q"
              type="search"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="CVE-…, GHSA-…, example.com/module, internal/handler/auth.go"
            />
            <button type="submit">Search</button>
          </form>

          {dropped.length > 0 && (
            <p className="state state-warning" role="alert">
              Part of this link was not understood and has been ignored: {dropped.join(', ')}. The
              list below is the query in the address bar, not the one you pasted.
            </p>
          )}

          {page.isLoading && <Loading what="findings" />}
          {page.error != null && <ErrorState error={page.error} what="findings" />}
          {page.data && page.data.findings.length === 0 && (
            <Empty
              filtered={page.data.in_corpus > 0}
              what="findings"
              hint={
                page.data.in_corpus > 0 ? (
                  <p className="muted">
                    {page.data.in_corpus} findings are in this corpus and none match the filter.
                  </p>
                ) : undefined
              }
            />
          )}
          {page.data && page.data.findings.length > 0 && (
            <>
              <FindingTable
                findings={page.data.findings}
                state={state}
                onSort={(field) =>
                  update({
                    ...state,
                    sort: field,
                    dir: state.sort === field && state.dir === 'desc' ? 'asc' : 'desc',
                    // A new ordering invalidates the cursor: it names a
                    // position in a differently-ordered set, and the API
                    // refuses it rather than resuming in the wrong place.
                    cursor: undefined,
                  })
                }
              />
              <nav className="pager" aria-label="Pagination">
                {state.cursor && (
                  <button type="button" onClick={() => update({ ...state, cursor: undefined })}>
                    ⏮ First page
                  </button>
                )}
                <span className="muted small">
                  showing {page.data.findings.length} of {page.data.matched} matching
                </span>
                {page.data.next_cursor ? (
                  <button
                    type="button"
                    onClick={() => update({ ...state, cursor: page.data.next_cursor })}
                  >
                    Next page ⏭
                  </button>
                ) : (
                  <span className="muted small">end of results</span>
                )}
              </nav>
            </>
          )}
        </Panel>
      </div>
    </div>
  );
}

/**
 * CorpusStatement is the sentence VM-UI-F-417 requires.
 *
 * Three figures, kept apart: how many MATCH the filter, how many are IN the
 * corpus, and how many exist in total. One number cannot express that, and a
 * reader given only "42" cannot tell whether the fleet has 42 problems or 42
 * of 4,000 that this filter happens to select.
 */
function CorpusStatement({
  matched,
  inCorpus,
  total,
  description,
  excludes,
  excludedCount,
  restricted,
}: {
  matched: number;
  inCorpus: number;
  total: number;
  description: string;
  excludes?: string;
  excludedCount: number;
  restricted: number;
}) {
  return (
    <span className="corpus">
      <strong>{matched}</strong> matching, of <strong>{inCorpus}</strong> in this corpus (
      {description}), of <strong>{total}</strong> ever recorded.
      {excludes && excludedCount > 0 && (
        <>
          {' '}
          This corpus excludes {excludedCount} records: {excludes}.
        </>
      )}
      {restricted > 0 && (
        <>
          {' '}
          <span className="restricted-note">
            {restricted} of the matching findings are counted here but restricted: you may not open
            their detail.
          </span>
        </>
      )}
    </span>
  );
}

function exportCSV(page: { findings: { [k: string]: unknown }[] }) {
  const header = [
    'fingerprint',
    'repo',
    'category',
    'type',
    'primary_id',
    'description',
    'priority',
    'severity',
    'reachable',
    'state',
    'sla_status',
    'sla_computed',
    'not_reobserved',
    'epss',
    'epss_known',
    'kev',
    'kev_known',
    'first_seen_run',
    'last_seen_run',
  ];
  const rows = page.findings.map((raw) => {
    const f = raw as unknown as import('../../api/schemas').Finding;
    return [
      f.fingerprint,
      f.repo,
      f.category,
      f.domain,
      f.identity.primary_id ?? '',
      f.description ?? '',
      f.priority ?? '',
      f.classification.severity,
      f.classification.reachable,
      f.state,
      f.sla.status ?? '',
      // The export carries the DISTINCTIONS, not just the values: a CSV that
      // wrote 0 for an uncomputed SLA or an absent EPSS would launder exactly
      // the ambiguity the interface works to preserve.
      String(f.sla.computed),
      String(f.observation.not_reobserved),
      f.classification.epss === undefined ? '' : String(f.classification.epss),
      String(f.classification.epss !== undefined),
      f.classification.kev === undefined ? '' : String(f.classification.kev),
      String(f.classification.kev !== undefined),
      f.observation.first_seen_run ?? '',
      f.observation.last_seen_run ?? '',
    ];
  });
  const blob = new Blob([toCSV(header, rows)], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'findings.csv';
  a.click();
  URL.revokeObjectURL(url);
}

export { CorpusStatement };
export const ExplorerLink = ({ query, children }: { query: string; children: React.ReactNode }) => (
  <Link to={`/findings${query}`}>{children}</Link>
);
