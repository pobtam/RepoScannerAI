/**
 * Run history, trends and comparison (U4, U5).
 *
 * Trend charts invite causal inference, so three things are marked on every
 * series: the run KIND it is drawn from (VM-UI-F-310), which points come from
 * a run that did not cover the fleet (VM-UI-F-307), and where the scanner
 * image changed (VM-UI-F-306). A drop caused by half the fleet failing to scan
 * looks identical to a drop caused by remediation working, and someone will
 * present the wrong one at a review.
 */
import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceDot,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { api } from '../../api/client';
import { Badge, Empty, ErrorState, Loading, Panel } from '../../components/primitives';
import { Link, useRouter } from '../../lib/router';
import { formatDate, formatDateTime, toCSV } from '../../lib/format';

const METRICS: { key: string; label: string }[] = [
  { key: 'open', label: 'Unresolved findings' },
  { key: 'new', label: 'New findings' },
  { key: 'verified', label: 'Verified' },
  { key: 'regressed', label: 'Regressed' },
  { key: 'not_observed', label: 'Not re-observed (ambiguous)' },
  { key: 'coverage', label: 'Coverage %' },
  { key: 'sla_breached', label: 'Past SLA' },
];

export function RunHistory() {
  const runs = useQuery({ queryKey: ['runs'], queryFn: () => api.runs('?limit=50') });
  const [metric, setMetric] = useState('open');
  const trend = useQuery({
    queryKey: ['trend', metric],
    queryFn: () => api.trends(metric, 25),
  });
  const { navigate } = useRouter();
  const [a, setA] = useState('');
  const [b, setB] = useState('');

  return (
    <div className="history">
      <Panel
        title="Trend"
        subtitle={trend.data?.note}
        actions={
          <select value={metric} onChange={(e) => setMetric(e.target.value)} aria-label="Metric">
            {METRICS.map((m) => (
              <option key={m.key} value={m.key}>
                {m.label}
              </option>
            ))}
          </select>
        }
      >
        {trend.isLoading && <Loading what="the trend" />}
        {trend.error != null && <ErrorState error={trend.error} what="the trend" />}
        {trend.data && <TrendChart data={trend.data} onPick={(id) => navigate(`/runs/${id}`)} />}
      </Panel>

      <Panel
        title="Runs"
        subtitle="every run, with its kind — a sweep and a single-repository rescan are not comparable (VM-UI-F-311)"
        actions={
          runs.data && (
            <button type="button" className="link-button" onClick={() => exportRuns(runs.data.runs)}>
              Export (CSV)
            </button>
          )
        }
      >
        {runs.isLoading && <Loading what="the run history" />}
        {runs.error != null && <ErrorState error={runs.error} what="the run history" />}
        {runs.data && runs.data.runs.length === 0 && <Empty filtered={false} what="runs" />}
        {runs.data && runs.data.runs.length > 0 && (
          <table className="runs">
            <thead>
              <tr>
                <th scope="col">Run</th>
                <th scope="col">Kind</th>
                <th scope="col">Started</th>
                <th scope="col">Trigger</th>
                <th scope="col">Scanned</th>
                <th scope="col">Failed</th>
                <th scope="col">Coverage</th>
                <th scope="col">Compare</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.runs.map((r) => (
                <tr key={r.id} className={r.partial ? 'partial' : undefined}>
                  <td className="mono">
                    <Link to={`/runs/${r.id}`}>{r.id}</Link>
                  </td>
                  <td>
                    <Badge tone={`kind-${r.kind}`}>{r.kind}</Badge>
                  </td>
                  <td className="mono small">{formatDateTime(r.started_at)}</td>
                  <td className="small">{r.trigger}</td>
                  <td>
                    {r.repos_scanned}/{r.repos_planned}
                  </td>
                  <td>{r.repos_failed}</td>
                  <td>
                    {r.partial ? (
                      <span className="warn-text" title={r.partial_note ?? ''}>
                        partial
                      </span>
                    ) : (
                      'complete'
                    )}
                  </td>
                  <td className="small">
                    <button type="button" className="link-button" onClick={() => setA(r.id)}>
                      A
                    </button>{' '}
                    <button type="button" className="link-button" onClick={() => setB(r.id)}>
                      B
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Compare two runs" subtitle="findings appearing, disappearing and changing">
        <form
          className="compare-form"
          onSubmit={(e) => {
            e.preventDefault();
            navigate(`/runs/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
          }}
        >
          <label>
            A <input value={a} onChange={(e) => setA(e.target.value)} placeholder="S-000001" />
          </label>
          <label>
            B <input value={b} onChange={(e) => setB(e.target.value)} placeholder="S-000002" />
          </label>
          <button type="submit" disabled={!a || !b}>
            Compare
          </button>
        </form>
      </Panel>
    </div>
  );
}

function TrendChart({
  data,
  onPick,
}: {
  data: import('../../api/schemas').TrendSeries;
  onPick: (runID: string) => void;
}) {
  const points = useMemo(
    () => data.points.map((p) => ({ ...p, label: formatDate(p.at) })),
    [data.points],
  );
  if (points.length === 0) return <Empty filtered={false} what="runs of this kind" />;

  return (
    <>
      <div className="chart" style={{ height: 260 }}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={points} onClick={(e) => {
            const p = e?.activePayload?.[0]?.payload as { run_id?: string } | undefined;
            if (p?.run_id) onPick(p.run_id);
          }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="label" />
            <YAxis allowDecimals={false} />
            <Tooltip
              formatter={(value: number) => [value, data.metric]}
              labelFormatter={(label: string) => {
                const p = points.find((x) => x.label === label);
                if (!p) return label;
                const notes = [p.run_id];
                if (p.partial) notes.push('PARTIAL RUN — this dip may be a coverage gap, not a fix');
                if (p.scanner_changed) notes.push('scanner image changed at this run');
                if (p.live) notes.push('computed live, not from an immutable snapshot');
                return notes.join(' · ');
              }}
            />
            <Line type="monotone" dataKey="value" stroke="#2b6cb0" strokeWidth={2} dot />
            {/* The annotations that stop a reader attributing a step change to
                the wrong cause. */}
            {points
              .filter((p) => p.scanner_changed)
              .map((p) => (
                <ReferenceDot
                  key={`scanner-${p.run_id}`}
                  x={p.label}
                  y={p.value}
                  r={7}
                  fill="#b7791f"
                  stroke="#744210"
                />
              ))}
            {points
              .filter((p) => p.partial)
              .map((p) => (
                <ReferenceDot
                  key={`partial-${p.run_id}`}
                  x={p.label}
                  y={p.value}
                  r={4}
                  fill="#c53030"
                  stroke="#742a2a"
                />
              ))}
          </LineChart>
        </ResponsiveContainer>
      </div>
      <ul className="legend">
        <li>
          <span className="swatch swatch-scanner" /> the scanner image changed at this run: a step
          change in counts may be the scanner, not the fleet (VM-UI-F-306)
        </li>
        <li>
          <span className="swatch swatch-partial" /> this run did not cover the fleet: its figure is
          lower than the fleet's position rather than better (VM-UI-F-307)
        </li>
        <li>
          drawn from runs of kind <strong>{data.kind}</strong> only (VM-UI-F-310)
        </li>
      </ul>
    </>
  );
}

export function RunComparison() {
  const { search } = useRouter();
  const params = new URLSearchParams(search);
  const a = params.get('a') ?? '';
  const b = params.get('b') ?? '';
  const q = useQuery({
    queryKey: ['compare', a, b],
    queryFn: () => api.compare(a, b),
    enabled: Boolean(a && b),
  });

  if (!a || !b) return <Empty filtered={false} what="runs to compare" />;
  if (q.isLoading) return <Loading what="the comparison" />;
  if (q.error != null) return <ErrorState error={q.error} what="the comparison" />;
  const c = q.data!;

  return (
    <div className="comparison">
      <h1>
        {c.a.id} → {c.b.id}
      </h1>
      {!c.comparable && (
        <Panel tone="warning" title="These runs are not comparable">
          <p>{c.note}</p>
        </Panel>
      )}
      <div className="split">
        <Panel title={`Appearing in ${c.b.id}`} subtitle={`${c.appearing.length} findings`}>
          <FindingList findings={c.appearing} />
        </Panel>
        <Panel
          title={`Not observed in ${c.b.id}`}
          subtitle={`${c.disappearing.length} findings — observed in ${c.a.id} and not in ${c.b.id}`}
        >
          <p className="muted small">
            Deliberately not called "fixed": a finding not observed may have been fixed, or may
            simply not have been looked for. Check the coverage of {c.b.id} first (VM-ADR-12).
          </p>
          <FindingList findings={c.disappearing} />
        </Panel>
      </div>
      <Panel title="Changed state" subtitle={`${c.changed.length} findings`}>
        {c.changed.length === 0 ? (
          <p className="muted">
            State differences between two runs are not computed in this build: a finding's state AS
            OF a past run has to be reconstructed from its audit trail, which is recorded as
            OQ-API-02 rather than approximated here. Appearing and disappearing above are exact.
          </p>
        ) : (
          <FindingList findings={c.changed.map((ch) => ch.finding)} />
        )}
      </Panel>
    </div>
  );
}

function FindingList({ findings }: { findings: import('../../api/schemas').Finding[] }) {
  if (findings.length === 0) return <p className="muted">none</p>;
  return (
    <ul className="finding-list">
      {findings.map((f) => (
        <li key={f.fingerprint}>
          <Link to={`/findings/${f.fingerprint}`} className="mono">
            {f.identity.primary_id || f.fingerprint}
          </Link>{' '}
          <span className="muted small">
            {f.repo} · {f.classification.severity} · {f.state}
          </span>
        </li>
      ))}
    </ul>
  );
}

function exportRuns(runs: import('../../api/schemas').RunSummary[]) {
  const csv = toCSV(
    ['run', 'kind', 'started_at', 'trigger', 'planned', 'scanned', 'failed', 'partial'],
    runs.map((r) => [
      r.id,
      r.kind,
      r.started_at,
      r.trigger ?? '',
      String(r.repos_planned),
      String(r.repos_scanned),
      String(r.repos_failed),
      String(r.partial),
    ]),
  );
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'runs.csv';
  link.click();
  URL.revokeObjectURL(url);
}
