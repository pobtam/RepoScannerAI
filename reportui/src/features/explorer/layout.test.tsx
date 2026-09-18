/**
 * The layout regression guard.
 *
 * Every other gate in this project passed while the findings table was
 * unusable: the types checked, the Zod validators accepted every response,
 * the unit tests found 17 correct rows with the right states, and the columns
 * test found data in every column. All of that was true. Every body row was
 * also collapsed into the first column, 115px wide inside a 1,223px table,
 * with all sixteen row pairs overlapping each other.
 *
 * The lesson is narrow and worth writing down: a DOM assertion is not a
 * layout assertion. jsdom reports every rectangle as zero, so no test that
 * runs in it can see where anything landed.
 *
 * This guard therefore has two halves.
 *
 *   STRUCTURE (always runs, in jsdom). The conditions that CAUSE the collapse:
 *   whether the body is inside the table's column model at all, whether rows
 *   are in the flow, whether the column count matches, whether the columns are
 *   pinned. These are checkable without a layout engine because they are
 *   inputs to the layout, not outputs of it.
 *
 *   GEOMETRY (runs where a browser exists). The real thing: the actual
 *   component with the actual stylesheet in headless Chrome, measuring where
 *   the cells landed. Skipped LOUDLY where no browser is found — a geometry
 *   check that quietly did not run reads as a pass, which is the failure mode
 *   this whole project is built to avoid.
 */
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { waitFor } from '@testing-library/react';
import { renderApp, stubApi } from '../../test-utils';
import { Explorer } from './Explorer';
import findingsPage from '../../test-fixtures/findings-page.json';
import facets from '../../test-fixtures/facets.json';
import { findBrowser, probeLayout } from '../../../scripts/layout-probe.mjs';

afterEach(() => vi.unstubAllGlobals());

/** dataRows are the rows carrying findings; spacers are structural. */
function dataRows(): HTMLTableRowElement[] {
  return [...document.querySelectorAll<HTMLTableRowElement>('.findings tbody tr')].filter(
    (r) => r.getAttribute('aria-hidden') !== 'true',
  );
}

async function renderTable() {
  // The real stylesheet, so getComputedStyle resolves what the browser would
  // cascade. jsdom will not lay the table out, but it does apply the rules —
  // and the rule that broke this was a `display` declaration.
  const style = document.createElement('style');
  style.textContent = readFileSync('src/styles.css', 'utf8');
  document.head.append(style);

  stubApi([
    ['/findings/facets', facets],
    ['/findings', findingsPage],
  ]);
  renderApp(<Explorer />, '/findings?scope=open');
  await waitFor(() => expect(dataRows().length).toBeGreaterThan(3));
}

describe('the findings table stays inside the table layout model', () => {
  it('gives every body row the same number of cells as the header', async () => {
    await renderTable();
    const headerCells = document.querySelectorAll('.findings thead th').length;
    expect(headerCells).toBeGreaterThan(5);

    for (const row of dataRows()) {
      expect(
        row.children.length,
        `a body row has ${row.children.length} cells and the header has ${headerCells}`,
      ).toBe(headerCells);
    }
  });

  it('keeps the body in the table box, so its cells share the header columns', async () => {
    await renderTable();
    const tbody = document.querySelector('.findings tbody')!;
    const row = dataRows()[0]!;

    // This is the assertion that would have caught the bug. A `display: block`
    // box inside a <table> is wrapped by CSS table fixup in an anonymous
    // table-cell, which lands in COLUMN ONE — so the whole body becomes one
    // cell the width of the first column and every row is crushed into it.
    // The header is unaffected, which is exactly what was seen: a correct
    // header above a column of overlapping text.
    expect(
      getComputedStyle(tbody).display,
      'the table body is not a table-row-group, so its rows are outside the ' +
        'column model the header defines',
    ).toBe('table-row-group');
    expect(
      getComputedStyle(row).display,
      'a body row is not a table-row, so its cells do not join the table columns',
    ).toBe('table-row');
  });

  it('keeps body rows in the flow rather than positioning them absolutely', async () => {
    await renderTable();
    for (const row of dataRows()) {
      // Absolute rows were how the virtualiser placed them, and it is why the
      // rows overlapped: the offsets came from a 44px estimate while the
      // squeezed rows were 190px tall. Virtualisation must be done with
      // spacer rows, which the table lays out itself.
      expect(
        row.style.position,
        'a body row is positioned absolutely, so nothing corrects its height ' +
          'against its neighbours',
      ).not.toBe('absolute');
      expect(getComputedStyle(row).position).not.toBe('absolute');
    }
  });

  it('pins the columns, so they cannot shift as the virtual window changes', async () => {
    await renderTable();
    const table = document.querySelector('.findings') as HTMLTableElement;
    const cols = table.querySelectorAll('colgroup col');
    const headerCells = table.querySelectorAll('thead th').length;

    // With a virtualised body, the rows in the DOM change as the reader
    // scrolls. Under automatic table layout the column widths are computed
    // from whichever rows happen to be rendered, so the columns would shift
    // under the reader's cursor. A colgroup plus fixed layout makes the widths
    // a property of the table rather than of the window.
    expect(cols.length, 'the table declares no <colgroup>').toBe(headerCells);
    expect(getComputedStyle(table).tableLayout).toBe('fixed');
    for (const col of cols) {
      expect((col as HTMLTableColElement).style.width, 'a column has no width').not.toBe('');
    }
  });
});

/**
 * The geometry half. This is the only assertion in the project that can see
 * where something was drawn.
 */
describe('the findings table lays out where it says it does', () => {
  const browser = findBrowser();

  it.skipIf(browser === null)('puts each body cell under its header column', () => {
    const m = probeLayout() as {
      settled: boolean;
      attempts: number;
      maxColumnDrift: number;
      overlappingRowPairs: number;
      rowCount: number;
      tableWidth: number;
      headerCellCount: number;
      minColumnGap: number;
      rowPosition: string;
      tbodyDisplay: string;
      rows: { width: number; cellCount: number; cellXs: number[] }[];
    };

    // A measurement the probe does not believe is not evidence. Without this
    // a page that failed to settle would report drift 0 from an empty table
    // and read as the strongest pass in the suite.
    expect(
      m.settled,
      `the probe never settled after ${m.attempts} attempts, so its numbers are not trustworthy`,
    ).toBe(true);
    expect(m.rowCount, 'the probe measured no rows').toBeGreaterThan(3);

    // Measured in Chrome against the real component and the real stylesheet.
    // The broken layout measured a drift of 1,002px on a 1,223px table.
    expect(
      m.maxColumnDrift,
      `a body cell sits ${m.maxColumnDrift}px from the header column it belongs ` +
        `under. The header and the body are not sharing a column model`,
    ).toBeLessThanOrEqual(2);

    // And the rows do not sit on top of each other. Every pair overlapped
    // before the fix.
    expect(
      m.overlappingRowPairs,
      `${m.overlappingRowPairs} of ${m.rowCount - 1} row pairs overlap vertically`,
    ).toBe(0);

    // A row spans the table rather than one column. This is the same fact as
    // the drift, stated where it is easiest to read in a failure.
    for (const row of m.rows) {
      expect(
        row.width,
        `a body row is ${row.width}px wide inside a ${m.tableWidth}px table`,
      ).toBeGreaterThan(m.tableWidth * 0.9);
    }

    // The columns are genuinely spread, not merely distinct. The broken
    // layout had eleven DISTINCT cell positions ten pixels apart, so
    // "distinct" alone would have passed on it.
    expect(m.minColumnGap, 'two columns are closer than a word').toBeGreaterThan(20);
    expect(m.rows[0]!.cellCount).toBe(m.headerCellCount);

    // These two are what jsdom cannot see: Chrome runs the real virtualised
    // path, where the rows used to be lifted out of the table.
    expect(m.tbodyDisplay, 'the body is outside the table box in the browser').toBe(
      'table-row-group',
    );
    expect(m.rowPosition, 'a body row is positioned absolutely in the browser').not.toBe(
      'absolute',
    );
  });

  it('reports loudly when no browser is available to measure with', () => {
    if (browser === null) {
      // Not a pass. The structural half above still ran; the geometry did not,
      // and this line is here so that shows up in the output rather than
      // being read as a green tick.
      console.warn(
        '\n  ⚠ LAYOUT GEOMETRY NOT CHECKED: no Chrome or Chromium was found.\n' +
          '    The structural guard ran; nothing measured where the cells landed.\n' +
          '    Set CHROME_PATH to a browser binary to enable it.\n',
      );
    }
    expect(true).toBe(true);
  });
});
