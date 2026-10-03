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
import type { ReportSummary } from '../../api/schemas';

/**
 * The supersession relationship, stated on BOTH reports (VM-UI-F-1108).
 *
 * Both directions, and the backwards one is the one that matters. A reader
 * who arrives at the superseded report is the reader most likely to be about
 * to quote a figure that has since been corrected — they followed an
 * identifier from a ticket or an email, and nothing else on the row would
 * tell them.
 *
 * Rendered as a warning on the superseded report and as a plain note on the
 * replacement, because only one of the two changes what the reader should do.
 */
function Lineage({ report }: { report: ReportSummary }) {
  if (report.superseded_by == null && report.supersedes == null) {
    // The class is what the test asserts on. Matching the word in the page's
    // text would also match the paragraph above that says there is no
    // "current" report, and an assertion satisfied by unrelated prose is one
    // that cannot fail.
    return <span className="muted lineage-current">current</span>;
  }
  return (
    <>
      {report.superseded_by != null && (
        <div className="warn-text">
          superseded by <span className="mono">{report.superseded_by}</span>
          <div className="muted small">
            A later report corrects this one. Figures quoted from here may have been superseded.
          </div>
        </div>
      )}
      {report.supersedes != null && (
        <div className="muted small">
          replaces <span className="mono">{report.supersedes}</span>
        </div>
      )}
    </>
  );
}

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
              <th scope="col">Lineage</th>
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
                  <Lineage report={r} />
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
        A superseded report stays in this list and stays downloadable (VM-UI-F-1108). A corrected
        figure only means something beside the figure it corrected, and somebody quoting the older
        one has its identifier in their hand, not the replacement's.
      </p>
      <p className="muted small">
        Generating a new report is not available in this build: the API has no write path for it
        (OQ-API-03), and an interface that offered a button doing nothing would be worse than one
        that does not offer it.
      </p>
    </Panel>
  );
}
