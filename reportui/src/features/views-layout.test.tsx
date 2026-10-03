/**
 * Layout guards for the views OQ-UI-04 names.
 *
 * The findings table has a geometry guard because it broke, and the open
 * question that defect left behind was this: the run overview's figure grid,
 * the coverage strip and the wave graph are covered only by DOM assertions,
 * which the same defect has just proved are blind.
 *
 * That defect passed 73 tests, a type checker and a Zod validator while every
 * row was collapsed into a 115px column with all sixteen row pairs
 * overlapping. jsdom has no layout engine; every rectangle it reports is zero.
 * So these run in a real browser.
 *
 * Four properties, each of which was false of the broken table:
 *
 *   CONTAINMENT — nothing extends past the box it is inside.
 *   NO OVERLAP — no two siblings occupy the same space.
 *   NON-DEGENERATE — nothing carrying text has zero width or height.
 *   NOT CLIPPED — nothing is narrower than its own content.
 *
 * Where no browser is found the check skips LOUDLY. A geometry check that
 * quietly did not run reads as a pass, which is the failure this whole
 * project is built to avoid.
 */
import { describe, expect, it } from 'vitest';
import { findBrowser, probeLayout } from '../../scripts/layout-probe.mjs';
import { summarise, type PanelMeasurement } from '../lib/layout-measure';

interface ProbeResult {
  panels?: Record<string, PanelMeasurement>;
  settled?: boolean;
  skipped?: string;
}

const PANELS = ['overview', 'coverage', 'waves'] as const;

describe('the other views lay out where they say they do (OQ-UI-04)', () => {
  const browser = findBrowser();

  if (!browser) {
    it('SKIPPED: no browser, so no view below has been measured', () => {
      console.warn(
        '\n' +
          '  ============================================================\n' +
          '  LAYOUT GEOMETRY NOT MEASURED — no Chrome or Chromium found.\n' +
          '  The run overview, the coverage strip and the wave graph have\n' +
          '  NOT been checked. Nothing below is evidence about their\n' +
          '  layout. Set CHROME_PATH, or install Chromium, and re-run.\n' +
          '  ============================================================\n',
      );
      expect(browser).toBeNull();
    });
    return;
  }

  // One browser run for all three panels: each render is a page-level view
  // and bundling plus launching Chrome per panel would triple the cost for
  // the same answer.
  const result = probeLayout('src/features/views-probe.tsx') as ProbeResult;

  // The table column model, checked wherever a table is in scope. The generic
  // properties cannot see the defect that started all of this: when a table
  // body is lifted out of the column model the rows get NARROWER, nothing
  // overflows, nothing overlaps, nothing clips, and the page is unusable.
  const tablesOf = (name: string) => result.panels?.[name]?.tables ?? [];

  it('measured every panel, and believes its own numbers', () => {
    expect(result.skipped, 'the probe reported a skip after a browser was found').toBeUndefined();
    expect(result.settled, 'the probe never settled: two consecutive measurements never agreed, ' +
      'so the numbers below are of a page still moving').toBe(true);
    expect(Object.keys(result.panels ?? {}).sort()).toEqual([...PANELS].sort());
  });

  for (const name of PANELS) {
    describe(name, () => {
      const panel = () => {
        const m = result.panels?.[name];
        if (!m) throw new Error(`the probe produced no measurement for ${name}`);
        return m;
      };

      it('rendered, with content in it', () => {
        const m = panel();
        expect(m.found, `${m.selector} is not in the page at all`).toBe(true);
        // A region that rendered nothing lays out perfectly, which is the
        // way this test is most likely to pass for no reason.
        expect(m.descendantCount, `${m.selector} is empty, so every assertion below is vacuous`)
          .toBeGreaterThan(3);
        expect(m.rect!.width).toBeGreaterThan(100);
        expect(m.rect!.height).toBeGreaterThan(10);
      });

      it('keeps its content inside its own box', () => {
        const m = panel();
        expect(m.overflows, summarise(m)).toEqual([]);
      });

      it('does not stack two things in one place', () => {
        const m = panel();
        expect(m.overlaps, summarise(m)).toEqual([]);
      });

      it('renders nothing at zero size', () => {
        const m = panel();
        expect(m.degenerate, summarise(m)).toEqual([]);
      });

      it('keeps every table cell under the column it belongs to', () => {
        const m = panel();
        for (const table of tablesOf(name)) {
          expect(table.bodyRows, `${table.what} has no rows, so this proves nothing`)
            .toBeGreaterThan(0);
          expect(table.maxColumnDrift, summarise(m)).toBeLessThanOrEqual(2);
          expect(table.cellCountMismatches, summarise(m)).toBe(0);
          expect(table.overlappingRowPairs, summarise(m)).toBe(0);
          // Distinct by ten pixels satisfied the first version of the
          // findings-table guard, and the broken rows DID have eleven
          // distinct positions — 328, 339, 349. Columns have to be more than
          // a word apart.
          expect(table.minColumnGap, summarise(m)).toBeGreaterThan(20);
          // The absolute check, and the only one that catches a UNIFORM
          // collapse: a table with no thead is measured against its own
          // first row, so if every row falls into column one together they
          // still agree and the drift is zero. A `<tr>` spans its table.
          expect(table.narrowestRowRatio, summarise(m)).toBeGreaterThan(0.9);
        }
      });

      it('clips none of its own text', () => {
        const m = panel();
        // The specific defect this catches: a figure rendered beside the
        // caveat that qualifies it, in a column too narrow for both. That is
        // how "uncalibrated" came to be breaking mid-word next to the number
        // it applies to — and a caveat that is unreadable is a caveat that
        // does not travel with its number.
        expect(m.clipped, summarise(m)).toEqual([]);
      });
    });
  }
});
