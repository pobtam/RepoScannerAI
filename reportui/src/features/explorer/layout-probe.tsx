/**
 * The layout probe: the real findings table, rendered in a real browser,
 * measuring itself.
 *
 * It exists because the type checker, the unit tests and the Zod validators
 * cannot see a layout. Every one of them passed while every body row was
 * collapsed into the first column — the data was correct, the DOM was
 * correct, and the page was unusable.
 *
 * jsdom has no layout engine, so every rectangle it reports is zero. This
 * page is loaded by headless Chrome (see layout.test.ts), which does have one.
 * It renders the ACTUAL component with the ACTUAL stylesheet and the captured
 * API fixture, measures where the cells landed, and writes the measurements
 * into the DOM where the test can read them.
 */
import { flushSync } from 'react-dom';
import { createRoot } from 'react-dom/client';
import { FindingTable } from './FindingTable';
import { RouterProvider } from '../../lib/router';
import { explorerState } from '../../lib/view-state';
import type { Finding } from '../../api/schemas';
import findingsPage from '../../test-fixtures/findings-page.json';
import '../../styles.css';

const findings = (findingsPage as unknown as { findings: Finding[] }).findings;

function Probe() {
  return (
    <RouterProvider>
      <div className="explorer-main" style={{ width: 1240 }}>
        <FindingTable findings={findings} state={explorerState.parse({})} onSort={() => {}} />
      </div>
    </RouterProvider>
  );
}

const host = document.getElementById('root')!;
const root = createRoot(host);
// flushSync, so the first commit has happened before anything measures. The
// probe must not depend on a frame arriving: under a virtual clock it may
// not, and a measurement that sometimes does not happen is worse than one
// that never does — it reads as a pass.
flushSync(() => root.render(<Probe />));

/** measure reads where the browser actually put things. */
function measure() {
  const table = document.querySelector('.findings') as HTMLTableElement | null;
  const out = document.getElementById('layout-result')!;
  if (!table) {
    out.textContent = JSON.stringify({ error: 'the table did not render' });
    return;
  }

  const left = (el: Element) => Math.round(el.getBoundingClientRect().left);
  const headerCells = [...table.querySelectorAll('thead th')];
  // Spacer rows are structural padding for the virtualiser and carry no data;
  // they are marked aria-hidden and excluded from every assertion.
  const bodyRows = [...table.querySelectorAll('tbody tr')].filter(
    (r) => r.getAttribute('aria-hidden') !== 'true',
  );

  const headerXs = headerCells.map(left);
  const rows = bodyRows.map((row) => {
    const r = row.getBoundingClientRect();
    return {
      cellCount: row.children.length,
      cellXs: [...row.children].map(left),
      top: Math.round(r.top),
      bottom: Math.round(r.bottom),
      width: Math.round(r.width),
    };
  });

  // The drift that matters: how far each body cell sits from the header cell
  // it belongs under. A table whose body is outside the column model shows a
  // drift that grows across the row; a correct one shows zero.
  let maxDrift = 0;
  for (const row of rows) {
    row.cellXs.forEach((x, i) => {
      const h = headerXs[i];
      if (h !== undefined) maxDrift = Math.max(maxDrift, Math.abs(x - h));
    });
  }

  let overlaps = 0;
  for (let i = 1; i < rows.length; i++) {
    if (rows[i]!.top < rows[i - 1]!.bottom - 1) overlaps++;
  }

  document.getElementById('layout-result')!.textContent = JSON.stringify({
    tableWidth: Math.round(table.getBoundingClientRect().width),
    tbodyDisplay: getComputedStyle(table.querySelector('tbody')!).display,
    rowPosition: bodyRows[0] ? getComputedStyle(bodyRows[0]).position : 'none',
    headerCellCount: headerCells.length,
    headerXs,
    rowCount: rows.length,
    rows: rows.slice(0, 6),
    maxColumnDrift: maxDrift,
    overlappingRowPairs: overlaps,
    distinctHeaderXs: new Set(headerXs).size,
    minColumnGap: Math.min(
      ...headerXs.slice(1).map((x, i) => x - headerXs[i]!),
    ),
  });
}

/**
 * Measure repeatedly until the numbers stop moving.
 *
 * The virtualiser needs a commit to see its scroll container, and another to
 * place the window it decides on. Rather than guessing how many frames that
 * takes, the probe writes a measurement after every attempt and stops once
 * two agree: the last write is what the DOM dump carries, and a `settled`
 * flag says whether it is one the probe believes.
 */
let previous = '';
let attempts = 0;

function attempt() {
  measure();
  const current = document.getElementById('layout-result')!.textContent ?? '';
  attempts++;
  const settled = current === previous && current !== '';
  if (settled || attempts > 40) {
    const parsed = JSON.parse(current) as Record<string, unknown>;
    parsed.settled = settled;
    parsed.attempts = attempts;
    document.getElementById('layout-result')!.textContent = JSON.stringify(parsed);
    return;
  }
  previous = current;
  setTimeout(attempt, 25);
}

attempt();
