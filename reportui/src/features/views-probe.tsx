/**
 * The layout probe for the views OQ-UI-04 names.
 *
 * The findings table has a geometry guard because it broke. The run
 * overview's figure grid, the coverage strip and the wave graph have DOM
 * assertions only — and the findings-table defect is the proof that a DOM
 * assertion cannot see a layout. The same class of defect could be sitting in
 * any of them, and nothing in this repository would know.
 *
 * This renders each of them with the captured API fixtures in a real browser
 * and measures where everything landed. It is the same mechanism as
 * explorer/layout-probe.tsx, pointed at three more views, which is what that
 * file's own open question asked for.
 */
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { flushSync } from 'react-dom';
import { createRoot } from 'react-dom/client';

import { RouterProvider } from '../lib/router';
import { measurePanel, type PanelMeasurement } from '../lib/layout-measure';
import { LatestOverview } from './runs/Overview';
import { Coverage } from './coverage/Coverage';
import { Waves } from './waves/Waves';

import overviewLatest from '../test-fixtures/overview-latest.json';
import coverage from '../test-fixtures/coverage.json';
import waves from '../test-fixtures/waves.json';
import runs from '../test-fixtures/runs.json';
import trend from '../test-fixtures/trend.json';
import '../styles.css';

/**
 * The fixture table, tried IN ORDER.
 *
 * In order rather than by longest match, for the reason test-utils records:
 * `/runs` is a prefix of `/runs/latest`, and a length rule silently answers
 * one with the other.
 */
const ROUTES: [string, unknown][] = [
  ['/runs/latest', overviewLatest],
  ['/metrics/trends', trend],
  ['/coverage', coverage],
  ['/waves', waves],
  ['/runs', runs],
];

// A request nothing answers FAILS rather than returning an empty object. A
// view rendered against nothing lays out perfectly and proves nothing.
window.fetch = (async (input: RequestInfo | URL) => {
  const url = String(input);
  const hit = ROUTES.find(([fragment]) => url.includes(fragment));
  if (!hit) throw new Error(`layout probe: no fixture for ${url}`);
  return new Response(JSON.stringify(hit[1]), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}) as typeof fetch;

/** The regions measured, and what each one is. */
const PANELS: { view: 'overview' | 'coverage' | 'waves'; name: string; selector: string }[] = [
  { view: 'overview', name: 'the run overview figure grid', selector: '.figures' },
  { view: 'coverage', name: 'the coverage history strip', selector: '.coverage-history' },
  { view: 'waves', name: 'the wave graph', selector: '.wave-graph' },
];

function viewFor(which: string) {
  switch (which) {
    case 'overview':
      return <LatestOverview />;
    case 'coverage':
      return <Coverage />;
    default:
      return <Waves />;
  }
}

const host = document.getElementById('root')!;
const out = document.getElementById('layout-result')!;

const results: Record<string, PanelMeasurement> = {};
let index = 0;

/**
 * Render one view, let it settle, measure it, move on.
 *
 * Sequentially rather than all at once: these are page-level views and
 * rendering three of them into one document would have them influence each
 * other's widths, which is a layout the application never produces.
 */
function next() {
  if (index >= PANELS.length) {
    out.textContent = JSON.stringify({ panels: results, settled: true });
    return;
  }
  const panel = PANELS[index]!;

  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const root = createRoot(host);
  // flushSync so a first commit has happened before anything measures; the
  // probe must not depend on a frame arriving under a virtual clock.
  flushSync(() =>
    root.render(
      <QueryClientProvider client={client}>
        <RouterProvider>
          <div className="app-main" style={{ width: 1240 }}>{viewFor(panel.view)}</div>
        </RouterProvider>
      </QueryClientProvider>,
    ),
  );

  // The data arrives asynchronously, so measure repeatedly until two
  // consecutive readings agree. `settled` travels with the result: a
  // measurement the probe does not believe must not read as a pass.
  let previous = '';
  let attempts = 0;

  const attempt = () => {
    const m = measurePanel(panel.selector);
    const current = JSON.stringify(m);
    attempts++;

    if ((current === previous && m.found) || attempts > 60) {
      results[panel.view] = { ...m, selector: `${panel.selector} (${panel.name})` };
      root.unmount();
      host.innerHTML = '';
      index++;
      setTimeout(next, 10);
      return;
    }
    previous = current;
    setTimeout(attempt, 25);
  };
  attempt();
}

next();
