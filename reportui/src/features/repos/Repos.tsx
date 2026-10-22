/**
 * Repository views (U6, VM-UI-F-6xx).
 *
 * Two rules from the specification are load-bearing here:
 *
 *   AGE IS NEVER SHOWN WITHOUT ITS SLA STATUS (VM-UI-F-609). The same elapsed
 *   time is unremarkable at one priority and a breach at another, and age
 *   alone invites sorting by the wrong column.
 *
 *   A REPOSITORY WITH NO TEST SUITE IS SHOWN PROMINENTLY (VM-UI-F-607),
 *   because it constrains what the framework may do there: with no suite there
 *   is no verification gate, so no fix can be proven and none is attempted.
 */
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import { Absent, Empty, ErrorState, Loading, Panel } from '../../components/primitives';
import { Link } from '../../lib/router';
import { formatDate, pct } from '../../lib/format';
import { ScanNow, ScanQueue, ScanRow, useLatestScans } from '../scans/ScanControls';

export function RepoIndex() {
  const q = useQuery({ queryKey: ['repos'], queryFn: api.repos });
  // null where no scan worker exists: the column is not shown at all.
  const latestScans = useLatestScans();
  if (q.isLoading) return <Loading what="repositories" />;
  if (q.error != null) return <ErrorState error={q.error} what="repositories" />;
  const repos = q.data!;

  return (
    <>
    <ScanQueue />
    <Panel title="Repositories" subtitle={`${repos.length} in the registry`}>
      {repos.length === 0 ? (
        <Empty filtered={false} what="repositories" />
      ) : (
        <table className="repos">
          <thead>
            <tr>
              <th scope="col">Repository</th>
              <th scope="col">Tier</th>
              <th scope="col">Languages</th>
              <th scope="col">Open findings</th>
              <th scope="col">Past SLA</th>
              <th scope="col">Not re-observed</th>
              <th scope="col">Last scan</th>
              <th scope="col">Test suite</th>
              {latestScans && <th scope="col">Scan</th>}
            </tr>
          </thead>
          <tbody>
            {repos.map((r) => (
              <tr key={r.name}>
                <td>
                  <Link to={`/repos/${r.name}`}>{r.name}</Link>
                </td>
                <td>{r.tier}</td>
                <td className="small">{r.languages.join(', ') || <Absent why="no language recorded" />}</td>
                <td>
                  <Link to={`/findings?scope=open&repo=${encodeURIComponent(r.name)}`}>
                    {r.open_findings}
                  </Link>
                </td>
                <td className={r.sla_breached > 0 ? 'warn-text' : undefined}>{r.sla_breached}</td>
                <td className={r.not_reobserved > 0 ? 'warn-text' : undefined}>{r.not_reobserved}</td>
                <td className="small">
                  {r.last_scanned_run ? (
                    <>
                      <Link to={`/runs/${r.last_scanned_run}`}>{r.last_scanned_run}</Link>
                      <span className="muted"> {r.last_outcome}</span>
                    </>
                  ) : (
                    <span className="warn-text" title="this repository has never produced a scan result: it is not clean, it is unknown">
                      never scanned
                    </span>
                  )}
                </td>
                <td>
                  {r.has_test_suite ? (
                    'yes'
                  ) : (
                    <span className="warn-text" title={r.no_test_suite_note ?? ''}>
                      none
                    </span>
                  )}
                </td>
                {latestScans && (
                  <td>
                    <ScanRow repo={r.name} last={latestScans.get(r.name)} />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
    </>
  );
}

export function RepoDetail({ repo }: { repo: string }) {
  const q = useQuery({ queryKey: ['repo', repo], queryFn: () => api.repo(repo) });
  const trend = useQuery({ queryKey: ['repo-trend', repo], queryFn: () => api.repoTrend(repo) });
  if (q.isLoading) return <Loading what={repo} />;
  if (q.error != null) return <ErrorState error={q.error} what={repo} />;
  const d = q.data!;
  const r = d.repo;

  return (
    <div className="repo">
      <header className="detail-head">
        <h1>{r.name}</h1>
        <p className="muted">
          tier {r.tier} · {r.languages.join(', ')} · {r.module_topology ?? 'topology unrecorded'} ·
          owners: {r.codeowners?.join(', ') || 'none recorded'}
        </p>
        <ScanNow repo={r.name} />
      </header>

      {!r.has_test_suite && (
        <Panel tone="urgent" title="No test suite">
          <p>{r.no_test_suite_note}</p>
        </Panel>
      )}

      <Panel title="Open findings">
        <div className="figures">
          <div className="figure">
            <Link to={`/findings?scope=open&repo=${encodeURIComponent(r.name)}`}>
              <span className="figure-value">{r.open_findings}</span>
              <span className="figure-label">open</span>
            </Link>
          </div>
          <div className="figure">
            <Link to={`/findings?scope=open&repo=${encodeURIComponent(r.name)}&slaBreached=true`}>
              <span className="figure-value">{r.sla_breached}</span>
              <span className="figure-label">past SLA</span>
            </Link>
          </div>
          <div className="figure">
            <Link to={`/findings?scope=open&repo=${encodeURIComponent(r.name)}&notReobserved=true`}>
              <span className="figure-value">{r.not_reobserved}</span>
              <span className="figure-label">not re-observed</span>
            </Link>
          </div>
        </div>
        <div className="split">
          <Counts title="By severity" counts={r.by_severity ?? {}} repo={r.name} param="severity" />
          <Counts title="By category" counts={r.by_category ?? {}} repo={r.name} param="category" />
        </div>
      </Panel>

      <Panel
        title="Remediation windows in force"
        subtitle="stated rather than implied, because an age means nothing without them (VM-UI-F-612)"
      >
        <table className="sla-windows">
          <thead>
            <tr>
              <th scope="col">Tier</th>
              <th scope="col">P0</th>
              <th scope="col">P1</th>
              <th scope="col">P2</th>
              <th scope="col">P3</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(d.sla_windows).map(([tier, windows]) => (
              <tr key={tier} className={String(r.tier) === tier ? 'current' : undefined}>
                <th scope="row">tier {tier}</th>
                {['P0', 'P1', 'P2', 'P3'].map((p) => (
                  <td key={p}>{windows[p] ?? '—'}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {d.sla_windows_provisional && (
          <p className="state state-warning">
            These windows are provisional: nobody has reviewed them (VM-OQ-02). Every breach count
            computed against them carries the same qualification.
          </p>
        )}
      </Panel>

      {d.open_prs && d.open_prs.length > 0 && (
        <Panel title="Open remediation pull requests">
          <ul className="links">
            {d.open_prs.map((pr) => (
              <li key={pr.branch}>
                <a href={pr.url} target="_blank" rel="noreferrer">
                  #{pr.number}
                </a>{' '}
                <span className="mono small">{pr.branch}</span>
                <span className="muted small">
                  {' '}
                  opened {formatDate(pr.opened_at)} · {pr.findings?.length ?? 0} findings
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {d.consumers && d.consumers.length > 0 && (
        <Panel
          title="Consumers of this repository's shared module"
          subtitle="a fix here unblocks them; a delay here blocks all of them"
        >
          <ul className="links">
            {d.consumers.map((c) => (
              <li key={c.repo}>
                <Link to={`/repos/${c.repo}`}>{c.repo}</Link>
                <span className="muted small">
                  {' '}
                  {c.version} · tier {c.tier} · reachability {c.reachable}
                </span>
                {c.excluded && <span className="warn-text"> excluded: {c.reason}</span>}
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <Panel title="Dependency inventory" subtitle={`${d.dependencies?.length ?? 0} modules read from the manifest`}>
        {!d.dependencies || d.dependencies.length === 0 ? (
          <p className="muted">
            No manifest was read for this repository. The reverse-dependency index — and therefore
            every blast-radius figure that mentions it — is blind here.
          </p>
        ) : (
          <table className="deps">
            <thead>
              <tr>
                <th scope="col">Module</th>
                <th scope="col">Version</th>
                <th scope="col">Direct</th>
                <th scope="col">Replaced</th>
              </tr>
            </thead>
            <tbody>
              {d.dependencies.map((dep) => (
                <tr key={dep.module}>
                  <td className="mono small">{dep.module}</td>
                  <td className="mono small">{dep.version}</td>
                  <td>{dep.direct ? 'yes' : 'no'}</td>
                  <td>
                    {dep.replaced ? (
                      <span className="warn-text" title="a replace directive means a version bump would not change what this repository builds (VM-F-608)">
                        replaced
                      </span>
                    ) : (
                      'no'
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Findings observed per run" subtitle={trend.data?.note}>
        {trend.isLoading && <Loading what="the trend" />}
        {trend.data && (
          <table className="mini-trend">
            <tbody>
              <tr>
                {trend.data.points.map((p) => (
                  <td key={p.run_id} className={p.partial ? 'partial' : undefined} title={`${p.run_id}${p.partial ? ' — partial run' : ''}`}>
                    <div className="bar" style={{ height: `${Math.min(100, p.value * 8)}px` }} />
                    <span className="small">{p.value}</span>
                  </td>
                ))}
              </tr>
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Recent scan outcomes" subtitle="newest first">
        {(d.coverage ?? []).map((h) => (
          <p key={h.repo} className="strip-row">
            <span className="strip">
              {h.outcomes.map((o, i) => (
                <span key={`${h.runs[i]}-${i}`} className={`cell cell-${o}`} title={`${h.runs[i]}: ${o}`}>
                  {o === 'complete' ? '▮' : o === 'partial' ? '▪' : o === 'failed' ? '✕' : o === 'not_dispatched' ? '⊘' : '?'}
                </span>
              ))}
            </span>
          </p>
        ))}
      </Panel>
    </div>
  );
}

function Counts({
  title,
  counts,
  repo,
  param,
}: {
  title: string;
  counts: Record<string, number>;
  repo: string;
  param: string;
}) {
  const entries = Object.entries(counts).filter(([, n]) => n > 0);
  entries.sort((a, b) => b[1] - a[1]);
  return (
    <div className="breakdown">
      <h3>{title}</h3>
      <ul>
        {entries.map(([key, n]) => (
          <li key={key}>
            <Link
              to={`/findings?scope=open&repo=${encodeURIComponent(repo)}&${param}=${encodeURIComponent(key)}`}
            >
              <span>{key}</span>
              <span className="count">{n}</span>
            </Link>
          </li>
        ))}
        {entries.length === 0 && <li className="muted">none</li>}
      </ul>
    </div>
  );
}

export { pct };
