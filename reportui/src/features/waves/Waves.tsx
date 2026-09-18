/**
 * The first-party wave view (U7, VM-UI-F-7xx).
 *
 * A wave is one root cause and one unblocking action across several
 * repositories, and the view's whole job is to make that legible rather than
 * showing twelve independent findings.
 *
 * Two figures are kept side by side and never merged: DEPEND and REACH
 * (VM-UI-F-708). Reporting one number for both overstates the incident and
 * burns the credibility the next real incident needs — a two-repository
 * problem presented as twenty is believed once.
 *
 * Excluded consumers are shown WITHIN the wave, not omitted (VM-UI-F-710),
 * with the reason: a consumer a wave cannot advance is waiting for a fix that
 * has already shipped, and dropping it from the list is how it waits for ever.
 */
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { Consumer, Wave } from '../../api/schemas';
import { Absent, Badge, Empty, ErrorState, Loading, Panel } from '../../components/primitives';
import { Link } from '../../lib/router';
import { formatDate, formatHours } from '../../lib/format';

export function Waves() {
  const q = useQuery({ queryKey: ['waves'], queryFn: api.waves });
  if (q.isLoading) return <Loading what="waves" />;
  if (q.error != null) return <ErrorState error={q.error} what="waves" />;
  const waves = q.data!;

  if (waves.length === 0) {
    return (
      <Empty
        filtered={false}
        what="first-party waves"
        hint={
          <p className="muted">
            A wave appears when a finding in a module this organisation owns blocks consumers of
            that module. None is in flight.
          </p>
        }
      />
    );
  }

  return (
    <div className="waves">
      {waves.map((w) => (
        <WavePanel key={w.module} wave={w} />
      ))}
    </div>
  );
}

function WavePanel({ wave: w }: { wave: Wave }) {
  const stalled = (w.wave1_age_hours ?? 0) > 72;
  return (
    <Panel
      title={
        <>
          {w.module} <span className="muted">owned by</span>{' '}
          <Link to={`/repos/${w.owner_repo}`}>{w.owner_repo}</Link>
        </>
      }
      subtitle={`wave 2 trigger: ${w.trigger}`}
      tone={stalled ? 'urgent' : undefined}
    >
      <div className="figures">
        {/* Adjacent, so neither can be quoted alone. */}
        <div className="figure" title="repositories that have the dependency">
          <span className="figure-value">{w.depend_count}</span>
          <span className="figure-label">depend on it</span>
        </div>
        <div className="figure" title="repositories that execute the vulnerable path — this is the exposure figure">
          <span className="figure-value">{w.reach_count}</span>
          <span className="figure-label">reach the vulnerable code</span>
        </div>
        <div
          className="figure"
          title="reachability has not been determined for these. NOT reachable and NOT safe: folding them into either side would overstate or understate"
        >
          <span className="figure-value">{w.unknown_count}</span>
          <span className="figure-label">undetermined</span>
        </div>
      </div>

      <p className="muted">
        {w.depend_count} repositories depend on {w.module}; {w.reach_count} reach the vulnerable
        code
        {w.unknown_count > 0 && (
          <>
            ; {w.unknown_count} have not been determined and are <strong>unknown</strong> — not
            reachable and not safe
          </>
        )}
        .
      </p>

      <div className="split">
        <div>
          <h3>Upstream fix</h3>
          <dl className="record">
            <dt>Upstream finding</dt>
            <dd>
              {w.upstream_finding ? (
                <Link to={`/findings/${w.upstream_finding}`} className="mono small">
                  {w.upstream_finding}
                </Link>
              ) : (
                <Absent why="no consumer records which upstream finding it is waiting on" />
              )}
            </dd>
            <dt>Upstream state</dt>
            <dd>{w.upstream_state ? <Badge>{w.upstream_state}</Badge> : <Absent why="unknown" />}</dd>
            <dt>Wave 1 pull request</dt>
            <dd>
              {w.wave1_pr ? (
                <a href={w.wave1_pr} target="_blank" rel="noreferrer">
                  {w.wave1_pr}
                </a>
              ) : (
                <Absent why="no remediation pull request is open on the owning repository, so nothing is propagating yet" />
              )}
            </dd>
            <dt>Age</dt>
            <dd>
              {w.wave1_pr_at ? (
                <>
                  {formatHours(w.wave1_age_hours)} <span className="muted small">since {formatDate(w.wave1_pr_at)}</span>
                  {stalled && (
                    <span className="warn-text">
                      {' '}
                      — a stalled upstream fix blocking {w.depend_count} consumers is a different
                      escalation from {w.depend_count} independent findings (VM-UI-F-703)
                    </span>
                  )}
                </>
              ) : (
                <Absent why="no pull request to age" />
              )}
            </dd>
          </dl>
        </div>

        <div>
          <h3>What clears this wave</h3>
          <ol className="steps">
            {w.steps.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
        </div>
      </div>

      <h3>Consumers</h3>
      <ConsumerGraph wave={w} />
      <table className="consumers">
        <thead>
          <tr>
            <th scope="col">Repository</th>
            <th scope="col">Version</th>
            <th scope="col">Tier</th>
            <th scope="col">Reaches the vulnerable code</th>
            <th scope="col">In this wave</th>
          </tr>
        </thead>
        <tbody>
          {w.consumers.map((c) => (
            <tr key={c.repo} className={c.excluded ? 'excluded' : undefined}>
              <td>
                <Link to={`/repos/${c.repo}`}>{c.repo}</Link>
              </td>
              <td className="mono small">{c.version}</td>
              <td>{c.tier}</td>
              <td>
                <span className={`reach reach-${c.reachable}`}>{reachWord(c)}</span>
              </td>
              <td className="small">
                {c.excluded ? <span className="warn-text">excluded — {c.reason}</span> : 'yes'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {w.version_spread && Object.keys(w.version_spread).length > 1 && (
        <p className="state state-warning">
          Consumers are on {Object.keys(w.version_spread).length} different versions (
          {Object.entries(w.version_spread)
            .map(([v, n]) => `${v}×${n}`)
            .join(', ')}
          ). A single-target bump may not build for the laggards, which is what VM-UI-F-712 asks
          this view to show before anyone dispatches one.
        </p>
      )}
    </Panel>
  );
}

function reachWord(c: Consumer): string {
  switch (c.reachable) {
    case 'true':
      return 'reaches it';
    case 'false':
      return 'does not reach it';
    default:
      return 'undetermined';
  }
}

/**
 * ConsumerGraph draws the relationship (VM-UI-F-706).
 *
 * A list of repository names does not convey that they share one root cause
 * and one unblocking action; an explicit graph does. Rendered as SVG with text
 * labels rather than a canvas so it is readable by a screen reader and
 * survives a zoom.
 */
function ConsumerGraph({ wave: w }: { wave: Wave }) {
  const rows = w.consumers.length;
  const height = Math.max(120, rows * 34 + 40);
  const midY = height / 2;

  return (
    <svg
      className="wave-graph"
      viewBox={`0 0 640 ${height}`}
      role="img"
      aria-label={`${w.module} is owned by ${w.owner_repo} and consumed by ${w.consumers
        .map((c) => `${c.repo} (${reachWord(c)}${c.excluded ? ', excluded' : ''})`)
        .join(', ')}`}
    >
      <rect x="8" y={midY - 26} width="190" height="52" rx="6" className="node node-owner" />
      <text x="103" y={midY - 6} textAnchor="middle" className="node-label">
        {w.owner_repo}
      </text>
      <text x="103" y={midY + 12} textAnchor="middle" className="node-sub">
        owns the module
      </text>

      {w.consumers.map((c, i) => {
        const y = 30 + i * 34;
        return (
          <g key={c.repo}>
            <path
              d={`M198 ${midY} C 300 ${midY}, 340 ${y}, 430 ${y}`}
              className={`edge edge-${c.excluded ? 'excluded' : c.reachable}`}
              fill="none"
            />
            <rect x="432" y={y - 13} width="200" height="26" rx="4" className={`node node-${c.reachable}${c.excluded ? ' node-excluded' : ''}`} />
            <text x="440" y={y + 4} className="node-label small">
              {c.repo}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
