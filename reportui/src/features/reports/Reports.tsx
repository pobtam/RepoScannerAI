/**
 * Issued reports (U9, VM-UI-F-11xx).
 *
 * The interface lists what has been ISSUED and offers no "current" or "live"
 * report, because no such report is reproducible: a report anchors to a
 * completed run, is immutable, and is identified by the hash of its content
 * (VM-UI-F-1111, VM-ADR-15). Offering one would invite a citation that cannot
 * be checked.
 *
 * Generation is not offered either — this build has no write path for it
 * (OQ-API-03), and a button that does nothing is worse than no button.
 */
import { useQuery } from '@tanstack/react-query';
import { api, API_BASE } from '../../api/client';
import { Absent, CopyButton, Empty, ErrorState, Loading, Panel } from '../../components/primitives';
import { Link } from '../../lib/router';
import { formatDateTime } from '../../lib/format';

export function Reports() {
  const q = useQuery({ queryKey: ['reports'], queryFn: api.reports });
  if (q.isLoading) return <Loading what="issued reports" />;
  if (q.error != null) return <ErrorState error={q.error} what="issued reports" />;
  const reports = q.data!;

  return (
    <Panel
      title="Issued reports"
      subtitle="each anchored to a completed run, immutable, and identified by the hash of its content"
    >
      <p className="muted small">
        There is no "current" or "live" report here. A report cannot be anchored to now: it would
        not be reproducible, and a citation to it could not be checked (VM-UI-F-1111).
      </p>

      {reports.length === 0 ? (
        <Empty
          filtered={false}
          what="issued reports"
          hint={<p className="muted">A report is issued by the orchestrator at the end of a run.</p>}
        />
      ) : (
        <table className="reports">
          <thead>
            <tr>
              <th scope="col">Report</th>
              <th scope="col">Template</th>
              <th scope="col">Anchor run</th>
              <th scope="col">Issued</th>
              <th scope="col">By</th>
              <th scope="col">Content hash</th>
              <th scope="col">Redaction</th>
              <th scope="col">Download</th>
            </tr>
          </thead>
          <tbody>
            {reports.map((r) => (
              <tr key={r.id}>
                <td className="mono small">{r.id}</td>
                <td>{r.template}</td>
                <td className="mono small">
                  <Link to={`/runs/${r.anchor_run_id}`}>{r.anchor_run_id}</Link>
                </td>
                <td className="mono small">{formatDateTime(r.issued_at)}</td>
                <td className="small">{r.issued_by || <Absent why="not recorded" />}</td>
                <td className="mono small">
                  {r.content_hash.slice(0, 16)}…
                  <CopyButton value={r.content_hash} label="the content hash" />
                </td>
                <td className="small">
                  {r.redacted ? (
                    <span className="warn-text">
                      redacted · {r.withheld_count} withheld
                    </span>
                  ) : (
                    'none'
                  )}
                </td>
                <td className="small">
                  {/* Re-downloadable without regeneration (VM-UI-F-1107): the
                      stored document is served as issued, byte for byte. */}
                  <a href={`${API_BASE}/reports/${encodeURIComponent(r.id)}`} target="_blank" rel="noreferrer">
                    JSON
                  </a>{' '}
                  ·{' '}
                  <a
                    href={`${API_BASE}/reports/${encodeURIComponent(r.id)}?format=markdown`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Markdown
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="muted small">
        Generating a new report is not available in this build: the API has no write path for it
        (OQ-API-03), and an interface that offered a button doing nothing would be worse than one
        that does not offer it.
      </p>
    </Panel>
  );
}
