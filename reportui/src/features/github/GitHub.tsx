/**
 * The GitHub account view (read-only).
 *
 * Which account a token connected, when it expires, and every repository
 * discovery saw with whether it is scanned and, if not, why. A repository
 * that is silently left out is outside the coverage denominator, so the
 * skipped ones are listed as prominently as the scanned ones.
 *
 * Nothing here can change anything: connecting, discovering and excluding
 * are vfctl commands until the interface has a real login.
 */
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { api } from '../../api/client';
import type { DiscoveredRepo, GitHubView } from '../../api/schemas';
import { Badge, ErrorState, Loading, Panel } from '../../components/primitives';
import { Link } from '../../lib/router';

const REASON_LABEL: Record<string, string> = {
  excluded: 'excluded by a person',
  archived: 'archived',
  collaborator: 'collaborator only',
  fork: 'fork',
  empty: 'empty',
  too_large: 'too large',
};

export function GitHubPage() {
  const q = useQuery({ queryKey: ['github'], queryFn: api.github });
  if (q.isLoading) return <Loading what="the GitHub account" />;
  if (q.error) return <ErrorState error={q.error} what="the GitHub account" />;
  const v = q.data!;

  return (
    <>
      <header className="page-head">
        <h1>GitHub</h1>
        <p>
          The account a read-only token connects, and every repository it reaches. Skipped
          repositories are listed with their reason, because one left out silently would never show
          up as a coverage gap.
        </p>
      </header>
      {v.connections.length === 0 ? <NotConnected /> : <Connected view={v} />}
    </>
  );
}

function NotConnected() {
  return (
    <Panel title="No account connected">
      <div className="state state-empty">
        <p>
          <strong>Nothing has been discovered yet.</strong>
        </p>
        <p className="muted">
          Create a fine-grained personal access token with only <em>Contents: read-only</em> and{' '}
          <em>Metadata: read-only</em>, then run:
        </p>
        <pre className="error-detail">
          {'export VULNFRAMEWORK_GITHUB_TOKEN=…   # or omit it and be prompted\n' +
            './vfctl.sh github connect\n' +
            './vfctl.sh github discover'}
        </pre>
      </div>
    </Panel>
  );
}

function Connected({ view }: { view: GitHubView }) {
  const [show, setShow] = useState<'all' | 'scanned' | 'skipped'>('all');
  const rows = view.discovered.filter((r) =>
    show === 'all' ? true : show === 'scanned' ? r.included : !r.included,
  );
  const skippedTotal = view.summary.seen - view.summary.included;

  return (
    <>
      {view.connections.map((c) => (
        <Panel
          key={c.account}
          title={
            <>
              {c.account} <span className="pill pill-accent">{c.kind.replace('_', '-')} token</span>
            </>
          }
          subtitle={`checked ${formatWhen(c.checked_at)} by ${c.checked_by}`}
          tone={c.expires_in_days !== undefined && c.expires_in_days < 14 ? 'warning' : undefined}
        >
          <dl className="record">
            <dt>Expires</dt>
            <dd>
              <Expiry days={c.expires_in_days} at={c.expires_at} />
            </dd>
            <dt>Read-only</dt>
            <dd>{c.read_only}</dd>
            {c.scopes.length > 0 && (
              <>
                <dt>Scopes</dt>
                <dd className="mono">{c.scopes.join(', ')}</dd>
              </>
            )}
          </dl>
        </Panel>
      ))}

      <Panel
        title="Discovered repositories"
        subtitle={
          view.summary.last_discovered_at
            ? `last discovery ${formatWhen(view.summary.last_discovered_at)}`
            : 'discovery has not run: ./vfctl.sh github discover'
        }
        actions={
          <div role="group" aria-label="Show" className="sidebar-tools">
            {(['all', 'scanned', 'skipped'] as const).map((k) => (
              <button
                key={k}
                type="button"
                className="tool-button"
                aria-pressed={show === k}
                onClick={() => setShow(k)}
              >
                {k}
              </button>
            ))}
          </div>
        }
      >
        <div className="figures">
          <Figure value={view.summary.seen} label="reachable with this token" />
          <Figure value={view.summary.included} label="scanned by each sweep" to="/repos" />
          <Figure value={skippedTotal} label="skipped, each with a reason" warn={skippedTotal > 0} />
        </div>
        {Object.keys(view.summary.skipped).length > 0 && (
          <p className="muted small">
            Skipped:{' '}
            {Object.entries(view.summary.skipped)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([reason, n]) => `${n} ${REASON_LABEL[reason] ?? reason}`)
              .join(' · ')}
          </p>
        )}
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th scope="col">Repository</th>
                <th scope="col">Decision</th>
                <th scope="col">Why</th>
                <th scope="col">Relation</th>
                <th scope="col">Visibility</th>
                <th scope="col">Size</th>
                <th scope="col">Language</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <Row key={r.name} r={r} />
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      {view.exclusions.length > 0 && (
        <Panel title="Exclusions" subtitle="repositories a person chose to leave out, with who and why">
          <table>
            <thead>
              <tr>
                <th scope="col">Repository</th>
                <th scope="col">Reason</th>
                <th scope="col">By</th>
                <th scope="col">When</th>
              </tr>
            </thead>
            <tbody>
              {view.exclusions.map((e) => (
                <tr key={e.name}>
                  <td className="mono">{e.name}</td>
                  <td>{e.reason}</td>
                  <td>{e.excluded_by}</td>
                  <td>{formatWhen(e.excluded_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted small" style={{ marginTop: 8 }}>
            Lift one with <code>./vfctl.sh repo include NAME</code>.
          </p>
        </Panel>
      )}
    </>
  );
}

function Row({ r }: { r: DiscoveredRepo }) {
  return (
    <tr>
      <td className="mono">
        {r.included ? <Link to={`/repos/${r.name}`}>{r.name}</Link> : r.name}
      </td>
      <td>
        {r.included ? (
          <Badge mark="✓" tone="state-resolved">
            scanned
          </Badge>
        ) : (
          <Badge mark="–" tone="state-unresolved">
            skipped
          </Badge>
        )}
      </td>
      <td className={r.included ? 'muted' : undefined}>{r.included ? '—' : r.detail}</td>
      <td>{r.affiliation}</td>
      <td>{r.private ? 'private' : 'public'}</td>
      <td>{formatSize(r.size_kb)}</td>
      <td>{r.language || <span className="absent">—</span>}</td>
    </tr>
  );
}

function Figure({ value, label, to, warn }: { value: number; label: string; to?: string; warn?: boolean }) {
  const body = (
    <>
      <span className="figure-value">{value}</span>
      <span className="figure-label">{label}</span>
    </>
  );
  return <div className={`figure${warn ? ' figure-warn' : ''}`}>{to ? <Link to={to}>{body}</Link> : body}</div>;
}

function Expiry({ days, at }: { days?: number; at?: string }) {
  if (at === undefined || days === undefined) {
    return <span className="sla-approaching">no expiry reported — a standing credential; prefer one that expires</span>;
  }
  const date = at.slice(0, 10);
  if (days < 0) return <span className="sla-breached">{date} — expired; sweeps will fail until it is replaced</span>;
  if (days < 14) return <span className="sla-approaching">{date} — in {days} days; rotate it soon</span>;
  return <span className="sla-within">{date} (in {days} days)</span>;
}

function formatSize(kb: number): string {
  if (kb === 0) return 'empty';
  if (kb < 1024) return `${kb} KB`;
  return `${(kb / 1024).toFixed(kb < 10240 ? 1 : 0)} MB`;
}

function formatWhen(iso: string): string {
  return iso.replace('T', ' ').slice(0, 16) + 'Z';
}
