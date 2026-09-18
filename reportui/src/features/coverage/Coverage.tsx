/**
 * The coverage view (U3's companion, VM-UI-F-75x).
 *
 * This view exists to say one thing that no other view can: a failed scan and
 * a clean scan are INDISTINGUISHABLE in every aggregate. Findings absent from
 * a repository with a gap are not absent because they were fixed — nobody
 * looked. The sentence is rendered at the top, not in a footnote, because a
 * reader who does not see it will read the run overview as reassurance.
 */
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import { Absent, Empty, ErrorState, Loading, Panel } from '../../components/primitives';
import { Link } from '../../lib/router';
import { formatDate, formatHours, formatNanoseconds, pct } from '../../lib/format';

export function Coverage() {
  const q = useQuery({ queryKey: ['coverage'], queryFn: () => api.coverage() });
  if (q.isLoading) return <Loading what="coverage" />;
  if (q.error != null) return <ErrorState error={q.error} what="coverage" />;
  const v = q.data!;

  return (
    <div className="coverage">
      <Panel tone="urgent" title="What a gap means for every other number">
        <p>{v.warning}</p>
      </Panel>

      <Panel title="Coverage">
        <div className="figures">
          <div className="figure">
            <span className="figure-value">{pct(v.percent)}</span>
            <span className="figure-label">of the fleet has a qualifying scan</span>
          </div>
          <div className="figure">
            <span className="figure-value">
              {v.complete}/{v.in_scope}
            </span>
            <span className="figure-label">repositories complete</span>
          </div>
          <div className="figure" title="repositories with no qualifying scan EVER: they have no age, and substituting zero would read as freshly scanned">
            <span className="figure-value">{v.staleness.never_scanned}</span>
            <span className="figure-label">never scanned</span>
          </div>
          <div className="figure">
            <span className="figure-value">{formatNanoseconds(v.staleness.max_age)}</span>
            <span className="figure-label">
              oldest coverage{v.staleness.stalest_repo ? ` (${v.staleness.stalest_repo})` : ''}
            </span>
          </div>
          <div className="figure">
            <span className="figure-value">{formatNanoseconds(v.staleness.median_age)}</span>
            <span className="figure-label">median coverage age</span>
          </div>
        </div>
        <p className="muted small">
          A flat gap COUNT with a growing maximum AGE is starvation that a percentage cannot show,
          which is why both are here (OQ-P4-01).
        </p>
      </Panel>

      <Panel title="Gaps" subtitle={`${v.gaps.length} repositories with no qualifying scan`}>
        {v.gaps.length === 0 ? (
          <Empty filtered={false} what="coverage gaps" />
        ) : (
          <table className="gaps">
            <thead>
              <tr>
                <th scope="col">Repository</th>
                <th scope="col">Run</th>
                <th scope="col">Outcome</th>
                <th scope="col">Total or partial</th>
                <th scope="col">Cause</th>
                <th scope="col">Owner</th>
                <th scope="col">Signals kept / lost</th>
                <th scope="col">Consecutive</th>
                <th scope="col">Without data</th>
                <th scope="col">Findings affected</th>
              </tr>
            </thead>
            <tbody>
              {v.gaps.map((g) => (
                <tr key={`${g.repo}-${g.run_id}`}>
                  <td>
                    <Link to={`/repos/${g.repo}`}>{g.repo}</Link>
                  </td>
                  <td className="mono small">
                    {g.run_id ? (
                      <>
                        <Link to={`/runs/${g.run_id}`}>{g.run_id}</Link>
                        <span className="muted"> {formatDate(g.run_at)}</span>
                      </>
                    ) : (
                      <Absent why="no scan result was recorded for this repository in this run" />
                    )}
                  </td>
                  <td>{g.outcome || <Absent why="no outcome recorded" />}</td>
                  <td>
                    <strong>{g.classification || 'total'}</strong>
                  </td>
                  <td className="small" title={g.detail}>
                    {g.cause || <Absent why="no cause was recorded: the worker produced nothing to attribute" />}
                  </td>
                  <td>
                    {/* Platform and repository causes route to different
                        people; a gap with no owner routes to nobody
                        (VM-F-214). */}
                    {g.owner || <Absent why="unattributed — this gap cannot be routed to anyone" />}
                  </td>
                  <td className="small">
                    {g.tools_ok && g.tools_ok.length > 0 ? (
                      <span title="these signals remain current">{g.tools_ok.join(', ')}</span>
                    ) : (
                      <span className="warn-text">nothing current</span>
                    )}
                    {' / '}
                    {g.tools_failed && g.tools_failed.length > 0 ? (
                      <span className="warn-text" title="these signals were lost">
                        {g.tools_failed.join(', ')}
                      </span>
                    ) : (
                      <Absent why="no individual tool was recorded as failed" />
                    )}
                  </td>
                  <td>{g.consecutive_runs}</td>
                  <td>
                    {g.never_scanned ? (
                      <span className="warn-text" title="this repository has NEVER had a qualifying scan, so no age exists. Rendering zero would read as freshly scanned">
                        never scanned
                      </span>
                    ) : (
                      <>
                        {formatHours(g.hours_without_data)}
                        {g.last_qualifying_run && (
                          <span className="muted small"> since {g.last_qualifying_run}</span>
                        )}
                      </>
                    )}
                  </td>
                  <td>
                    {g.not_reobserved > 0 ? (
                      <Link to={`/findings?${g.findings_query ?? ''}`}>
                        {g.not_reobserved} not re-observed
                      </Link>
                    ) : (
                      <span className="muted">none outstanding</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel
        title="Recent outcomes per repository"
        subtitle="newest first — coverage decay is visible here without reading individual gaps (VM-UI-F-756)"
      >
        <table className="coverage-history">
          <tbody>
            {(v.history ?? []).map((h) => (
              <tr key={h.repo}>
                <th scope="row">
                  <Link to={`/repos/${h.repo}`}>{h.repo}</Link>
                </th>
                <td>
                  <span className="strip">
                    {h.outcomes.map((o, i) => (
                      <span
                        key={`${h.runs[i]}-${i}`}
                        className={`cell cell-${o}`}
                        title={`${h.runs[i]}: ${o}`}
                      >
                        {mark(o)}
                      </span>
                    ))}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted small">
          ▮ complete · ▪ partial · ✕ failed · ⊘ never dispatched · ? dispatched and silent
        </p>
      </Panel>
    </div>
  );
}

function mark(outcome: string): string {
  switch (outcome) {
    case 'complete':
      return '▮';
    case 'partial':
      return '▪';
    case 'failed':
      return '✕';
    case 'not_dispatched':
      return '⊘';
    case 'no_result':
      return '?';
    default:
      return '·';
  }
}
