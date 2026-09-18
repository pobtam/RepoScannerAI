/**
 * The finding table (VM-UI-F-412, VM-UI-F-413, VM-UI-F-421 … VM-UI-F-423).
 *
 * Virtualised, because the requirement is to stay responsive at ten thousand
 * rows and a page is at most five hundred — the virtualiser is what makes the
 * page size a server decision rather than a rendering limit.
 *
 * Two columns exist purely to stop a reader drawing the wrong conclusion:
 *
 *   FIRST / LAST SEEN, together. Neither alone says whether a finding is
 *   current (VM-UI-F-421), and a list showing only "last seen" reads as a
 *   list of fresh findings.
 *
 *   The NOT RE-OBSERVED marker, with its explanation attached rather than in a
 *   legend (VM-UI-F-422, VM-UI-F-423). A marker whose meaning lives elsewhere
 *   gets read as "probably fixed".
 */
import { useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import type { Finding } from '../../api/schemas';
import { Absent, Badge, Caveat } from '../../components/primitives';
import { Link } from '../../lib/router';
import {
  epssLabel,
  formatDate,
  kevLabel,
  reachableLabel,
  severityMark,
  slaLabel,
  stateMark,
} from '../../lib/format';
import type { ExplorerState } from '../../lib/view-state';

/**
 * The columns, each with the share of the table it occupies.
 *
 * The width lives here rather than in the stylesheet because the <colgroup>
 * and the header are generated from this one list: a column added to the
 * header without a width would otherwise silently unpin the table.
 *
 * Widths are needed at all because the body is virtualised. Under automatic
 * table layout the column widths are computed from whichever rows happen to
 * be rendered, so they would shift as the reader scrolled.
 */
const COLUMNS: {
  key: ExplorerState['sort'] | null;
  label: string;
  width: string;
  hint?: string;
}[] = [
  // Priority is wider than its content needs because the CAVEAT sits with the
  // number rather than in a header, and a column that breaks "uncalibrated"
  // across two lines makes the qualification harder to read than the figure
  // it qualifies. State is wider than its longest label for the same reason:
  // BLOCKED_UPSTREAM must not be clipped to BLOCKED_UPSTREA.
  { key: 'priority', label: 'Priority', width: '9%' },
  { key: 'severity', label: 'Severity', width: '8%' },
  { key: null, label: 'Finding', width: '11%' },
  { key: 'repo', label: 'Repository', width: '10%' },
  { key: null, label: 'Component', width: '12%' },
  { key: null, label: 'Reachable', width: '7%', hint: 'a tri-state: unknown is not "not reachable"' },
  { key: null, label: 'Exploitation', width: '9%', hint: 'KEV and EPSS; "not looked up" is not zero' },
  { key: null, label: 'State', width: '12%' },
  { key: null, label: 'SLA', width: '9%', hint: 'age is never shown without its SLA status' },
  { key: 'first_seen', label: 'First seen', width: '6.5%' },
  { key: 'last_seen', label: 'Last seen', width: '6.5%' },
];

export function FindingTable({
  findings,
  state,
  onSort,
}: {
  findings: Finding[];
  state: ExplorerState;
  onSort: (field: ExplorerState['sort']) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const rows = useVirtualizer({
    count: findings.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 44,
    overscan: 12,
  });

  // Virtualisation is an optimisation, and a container that has not been
  // measured yet must not mean ZERO ROWS. A table that renders nothing
  // because the layout has not settled looks exactly like a fleet with no
  // findings, which is the one thing this interface must never imply.
  const windowed = rows.getVirtualItems();
  const items =
    windowed.length === 0 && findings.length > 0
      ? findings.map((_, index) => ({
          index,
          key: index,
          start: index * 44,
          end: (index + 1) * 44,
          size: 44,
        }))
      : windowed;
  const virtualised = windowed.length > 0;

  // The window is placed with SPACER ROWS rather than by positioning each row
  // absolutely.
  //
  // An absolutely positioned row is out of the table's flow, so the table
  // cannot size its columns from it and cannot stop two rows overlapping —
  // which is exactly what happened: the offsets came from the 44px estimate
  // while the rows measured 190px. Two empty rows of the right height put the
  // window in the right place and leave every other decision to the table.
  const first = items[0];
  const last = items[items.length - 1];
  const padTop = virtualised && first ? first.start : 0;
  const padBottom = virtualised && last ? Math.max(0, rows.getTotalSize() - last.end) : 0;

  return (
    <div className="table-scroll" ref={parentRef}>
      <table className="findings">
        {/* The columns are pinned here, from the same list the header is
            built from, so a virtual window cannot change their widths. */}
        <colgroup>
          {COLUMNS.map((col) => (
            <col key={col.label} style={{ width: col.width }} />
          ))}
        </colgroup>
        <thead>
          <tr>
            {COLUMNS.map((col) => (
              <th key={col.label} title={col.hint} scope="col">
                {col.key ? (
                  <button
                    type="button"
                    className={`sort${state.sort === col.key ? ` sort-${state.dir}` : ''}`}
                    onClick={() => onSort(col.key!)}
                    aria-label={`Sort by ${col.label}`}
                  >
                    {col.label}
                    {state.sort === col.key && <span aria-hidden="true">{state.dir === 'desc' ? ' ▼' : ' ▲'}</span>}
                  </button>
                ) : (
                  col.label
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {padTop > 0 && <Spacer height={padTop} columns={COLUMNS.length} />}
          {items.map((item) => {
            const f = findings[item.index]!;
            return (
              <Row
                key={f.fingerprint}
                finding={f}
                index={item.index}
                measure={rows.measureElement}
              />
            );
          })}
          {padBottom > 0 && <Spacer height={padBottom} columns={COLUMNS.length} />}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Spacer stands in for the rows outside the window.
 *
 * aria-hidden because it carries no data: a screen reader counting rows
 * should not find two empty ones, and every assertion about the table
 * excludes them for the same reason.
 */
function Spacer({ height, columns }: { height: number; columns: number }) {
  return (
    <tr aria-hidden="true" className="spacer" style={{ height }}>
      <td colSpan={columns} />
    </tr>
  );
}

function Row({
  finding: f,
  index,
  measure,
}: {
  finding: Finding;
  index: number;
  measure: (el: HTMLElement | null) => void;
}) {
  const reach = reachableLabel(f.classification.reachable);
  const epss = epssLabel(f.classification.epss);
  const kev = kevLabel(f.classification.kev);
  const sla = slaLabel(f.sla);

  return (
    <tr
      // data-index is what the virtualiser's measurer reads to attribute a
      // measured height to the right row.
      ref={measure}
      data-index={index}
      className={f.restricted ? 'row restricted' : 'row'}
    >
      <td>
        {f.priority ? (
          <>
            <Badge tone={`prio-${f.priority}`}>{f.priority}</Badge>
            {/* The caveat travels with the number, not in a page header. */}
            {f.score?.caveat && <Caveat text={f.score.caveat} short="partial inputs" />}
            {f.score?.thresholds_calibrated === false && (
              <Caveat
                text="the priority bands behind this figure have not been calibrated against a shadow run (VM-OQ-06)"
                short="uncalibrated"
              />
            )}
          </>
        ) : (
          <Absent why="nothing has scored this finding yet, so it has no priority — which is not the same as a low one" />
        )}
      </td>
      <td>
        <Badge mark={severityMark(f.classification.severity)} tone={`sev-${f.classification.severity}`}>
          {f.classification.severity}
        </Badge>
      </td>
      <td>
        {f.restricted ? (
          <span className="muted" title="a secret finding's detail is restricted to the security owner group and the owning repository's code owners">
            restricted — counted, not shown
          </span>
        ) : (
          <Link to={`/findings/${f.fingerprint}`} className="mono">
            {f.identity.primary_id || f.fingerprint}
          </Link>
        )}
      </td>
      <td>
        <Link to={`/repos/${f.repo}`}>{f.repo}</Link>
      </td>
      <td className="mono small">
        {f.location.module || f.location.file || <Absent why="this category of finding has no component path" />}
      </td>
      <td>
        <span className={`reach reach-${f.classification.reachable}`} title={reach.hint}>
          {reach.text}
        </span>
      </td>
      <td className="small">
        <span className={kev.known ? '' : 'absent'} title={kev.known ? undefined : 'the catalogue was not consulted for this finding: the absence is not a determination that it is unexploited'}>
          {kev.text}
        </span>
        {' · '}
        <span className={epss.known ? '' : 'absent'} title={epss.known ? `as of ${formatDate(f.classification.epss_as_of)}` : 'nothing answered for this finding’s identifiers: the absence is not a score of zero'}>
          {epss.text}
        </span>
      </td>
      <td>
        <Badge mark={stateMark(f.state)} tone={`state-${f.partition}`} title={`partition: ${f.partition}`}>
          {f.state}
        </Badge>
        {f.observation.not_reobserved && (
          <span className="not-reobserved" title={f.observation.not_reobserved_note ?? ''}>
            not re-observed
          </span>
        )}
      </td>
      <td>
        <span className={`sla sla-${sla.tone}`}>{sla.text}</span>
        {f.sla.windows_provisional && f.sla.computed && (
          <Caveat text={f.sla.caveat ?? ''} short="provisional windows" />
        )}
        {/* Age is never rendered without the SLA status (VM-UI-F-609). */}
        <span className="muted small"> · {f.sla.age_days}d old</span>
      </td>
      <td className="mono small">
        {f.observation.first_seen_run || formatDate(f.observation.first_seen_at)}
      </td>
      <td className="mono small">
        {f.observation.last_seen_run || formatDate(f.observation.last_seen_at)}
      </td>
    </tr>
  );
}
