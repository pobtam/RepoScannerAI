/**
 * Generic layout measurements, for the views OQ-UI-04 names.
 *
 * The findings table taught this project one narrow lesson: a DOM assertion is
 * not a layout assertion. jsdom reports every rectangle as zero, so 73 passing
 * tests, a type checker and a schema validator all agreed the table was
 * correct while every row was collapsed into a 115px first column with all
 * sixteen row pairs overlapping.
 *
 * The guard written for that defect is specific to a table: header columns,
 * body cells, column drift. OQ-UI-04 recorded that the other views — the run
 * overview's figure grid, the coverage strip, the wave graph — are still
 * covered only by DOM assertions, which have just been shown to be blind.
 *
 * This module is what they are measured with instead. It asserts the four
 * things that are true of ANY laid-out region and were each false of the
 * broken table:
 *
 *   CONTAINMENT — nothing extends beyond the box it is inside. The collapsed
 *   rows resolved their width against a 115px cell and their content spilled.
 *
 *   NO OVERLAP — no two siblings occupy the same space. The rows were
 *   positioned from a 44px estimate while measuring 190px tall.
 *
 *   NON-DEGENERATE — nothing with content has zero width or height. An
 *   element collapsed to nothing is invisible and reads, to every test that
 *   can only see the DOM, exactly like an element that is fine.
 *
 *   NOT CLIPPED — no element's content is wider than the element. This is the
 *   one that catches a number rendered beside a caveat that no longer fits,
 *   which is how "uncalibrated" came to be breaking mid-word beside the figure
 *   it qualifies.
 */

/** Rect is a measured rectangle, rounded to whole pixels. */
export interface Rect {
  left: number;
  top: number;
  right: number;
  bottom: number;
  width: number;
  height: number;
}

/** Overflow is one element escaping its container. */
export interface Overflow {
  what: string;
  by: number;
  edge: 'right' | 'bottom' | 'left' | 'top';
}

/** Overlap is two siblings occupying the same space. */
export interface Overlap {
  a: string;
  b: string;
  by: number;
}

/** Degenerate is an element with content and no size. */
export interface Degenerate {
  what: string;
  width: number;
  height: number;
  text: string;
}

/** Clipped is an element narrower than its own content. */
export interface Clipped {
  what: string;
  by: number;
  text: string;
}

/**
 * TableMeasurement is the column model of one table.
 *
 * Its own measurement because the generic checks cannot see the defect that
 * started all of this. When a table body is lifted out of the column model —
 * a `display: block` inside a `<table>` is wrapped in an anonymous cell, and
 * that cell lands in column one — the rows get NARROWER, not wider. Nothing
 * overflows, no two siblings overlap, every element has a size, and nothing
 * clips. The page is unusable and all four generic properties hold.
 *
 * So the specific question has to be asked: does each body cell sit under the
 * header cell it belongs to?
 */
export interface TableMeasurement {
  what: string;
  headerCells: number;
  /**
   * referenceIsHeader says whether the columns were measured against a
   * thead or against the first body row.
   *
   * Reported, not hidden: a table measured against its own first row cannot
   * detect a collapse that moved every row identically, and a reader of
   * these numbers should know which question was asked.
   */
  referenceIsHeader: boolean;
  bodyRows: number;
  /** maxColumnDrift is the furthest any body cell sits from its header column. */
  maxColumnDrift: number;
  /** cellCountMismatches counts rows with a different cell count from the header. */
  cellCountMismatches: number;
  /** overlappingRowPairs counts rows that occupy each other's vertical space. */
  overlappingRowPairs: number;
  /** minColumnGap is the narrowest distance between two header columns. */
  minColumnGap: number;
  /**
   * narrowestRowRatio is the narrowest body row's width as a fraction of the
   * table's.
   *
   * The absolute check, and the only one that catches a UNIFORM collapse. A
   * table with no thead is measured against its own first row, so if every
   * row falls into column one together they still agree with each other and
   * the drift is zero. What does not hold is this: a `<tr>` spans its table.
   * A row occupying a fraction of the table width is a row that has left the
   * column model, whatever the other rows did.
   */
  narrowestRowRatio: number;
}

/** PanelMeasurement is everything measured about one region. */
export interface PanelMeasurement {
  found: boolean;
  selector: string;
  rect: Rect | null;
  childCount: number;
  /**
   * descendantCount is every visible element inside the region.
   *
   * Reported separately from childCount because the wave graph is an SVG:
   * its direct children are excluded from the overlap check, so childCount is
   * zero there and would make an empty panel indistinguishable from a drawn
   * one. A region that rendered nothing lays out perfectly.
   */
  descendantCount: number;
  overflows: Overflow[];
  overlaps: Overlap[];
  degenerate: Degenerate[];
  clipped: Clipped[];
  /** tables is the column model of every table in the region. */
  tables: TableMeasurement[];
}

/**
 * tolerance absorbs sub-pixel rounding and the one-pixel borders a table
 * draws.
 *
 * Deliberately small. The defect this exists for showed a thousand pixels of
 * drift and 190px-tall rows overlapping a 44px stride; a tolerance generous
 * enough to hide a real break would make the whole check decorative.
 */
const TOLERANCE = 2;

function rectOf(el: Element): Rect {
  const r = el.getBoundingClientRect();
  return {
    left: Math.round(r.left),
    top: Math.round(r.top),
    right: Math.round(r.right),
    bottom: Math.round(r.bottom),
    width: Math.round(r.width),
    height: Math.round(r.height),
  };
}

/** describe names an element well enough to find it again. */
function describe(el: Element): string {
  const tag = el.tagName.toLowerCase();
  const cls = (el.getAttribute('class') ?? '').trim().split(/\s+/).filter(Boolean).slice(0, 2);
  const text = (el.textContent ?? '').trim().slice(0, 28);
  return `${tag}${cls.map((c) => '.' + c).join('')}${text ? ` "${text}"` : ''}`;
}

function isHidden(el: Element): boolean {
  if (el.getAttribute('aria-hidden') === 'true') return true;
  const style = getComputedStyle(el);
  return style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0';
}

/**
 * isScreenReaderOnly reports the visually-hidden pattern.
 *
 * Excluded from the clipping check because clipping is how it WORKS: a
 * one-pixel box with hidden overflow, carrying a sentence for a screen
 * reader. Flagging it would report every accessible description in the
 * interface as a layout defect, and a check that fires on correct code is one
 * people learn to ignore — which is the only way this check actually fails.
 *
 * Narrow on purpose. It matches the class the stylesheet uses and the
 * one-pixel geometry that defines the pattern, not "anything small".
 */
function isScreenReaderOnly(el: Element): boolean {
  if (el.classList.contains('sr-only') || el.classList.contains('visually-hidden')) return true;
  const r = el.getBoundingClientRect();
  return r.width <= 1 && r.height <= 1;
}

/**
 * insideSVG reports whether an element lives in an SVG coordinate system.
 *
 * Excluded from the OVERLAP check, and only that one. An SVG is not a flow
 * layout: a label sits on the node it labels, a marker sits on a bar, and
 * overlap is the intended result rather than a symptom. Containment and
 * degeneracy still apply, because a graph drawn outside its own viewport or
 * collapsed to nothing is broken in either kind of layout.
 */
function insideSVG(el: Element): boolean {
  let node: Element | null = el;
  while (node) {
    if (node.tagName.toLowerCase() === 'svg') return true;
    node = node.parentElement;
  }
  return false;
}

/**
 * scrollableAncestor reports whether anything between el and the container
 * scrolls.
 *
 * An element inside a scroller is legitimately allowed to extend past its
 * container: that is what a scroller is for. Without this, every virtualised
 * list and every horizontally-scrolling table would report as broken, the
 * check would be ignored, and being ignored is the only way it actually
 * fails.
 */
function insideScroller(el: Element, container: Element): boolean {
  let node: Element | null = el.parentElement;
  while (node && node !== container) {
    const style = getComputedStyle(node);
    const overflow = style.overflow + style.overflowX + style.overflowY;
    if (/(auto|scroll)/.test(overflow)) return true;
    node = node.parentElement;
  }
  const style = getComputedStyle(container);
  return /(auto|scroll)/.test(style.overflow + style.overflowX + style.overflowY);
}

/** measurePanel measures one region of the page. */
export function measurePanel(selector: string): PanelMeasurement {
  const container = document.querySelector(selector);
  if (!container) {
    return {
      found: false, selector, rect: null, childCount: 0, descendantCount: 0,
      overflows: [], overlaps: [], degenerate: [], clipped: [], tables: [],
    };
  }

  const box = rectOf(container);
  const scroller = insideScroller(container, container);

  const overflows: Overflow[] = [];
  const degenerate: Degenerate[] = [];
  const clipped: Clipped[] = [];

  for (const el of Array.from(container.querySelectorAll('*'))) {
    if (isHidden(el)) continue;
    const r = rectOf(el);

    // Containment.
    if (!scroller && !insideScroller(el, container)) {
      if (r.right > box.right + TOLERANCE) {
        overflows.push({ what: describe(el), by: r.right - box.right, edge: 'right' });
      }
      if (r.left < box.left - TOLERANCE) {
        overflows.push({ what: describe(el), by: box.left - r.left, edge: 'left' });
      }
    }

    // Non-degenerate: an element carrying its OWN text, with no size.
    const own = Array.from(el.childNodes)
      .filter((n) => n.nodeType === 3)
      .map((n) => (n.textContent ?? '').trim())
      .join('');
    if (own !== '' && (r.width === 0 || r.height === 0) && !isScreenReaderOnly(el)) {
      degenerate.push({ what: describe(el), width: r.width, height: r.height, text: own.slice(0, 40) });
    }

    // Not clipped: the element is narrower than its own content. scrollWidth
    // exceeding clientWidth is the browser's own statement that something did
    // not fit.
    const over = (el as HTMLElement).scrollWidth - (el as HTMLElement).clientWidth;
    const style = getComputedStyle(el);
    if (over > TOLERANCE && style.overflowX === 'hidden' && !isScreenReaderOnly(el)) {
      clipped.push({ what: describe(el), by: over, text: (el.textContent ?? '').trim().slice(0, 40) });
    }
  }

  // No overlap, among DIRECT children only.
  //
  // Direct children, because descendants legitimately overlap: a badge sits on
  // a card, an absolutely-positioned marker sits on a bar. Siblings laid out
  // in a row or a grid do not.
  const children = Array.from(container.children).filter(
    (el) => !isHidden(el) && !insideSVG(el),
  );
  const overlaps: Overlap[] = [];
  for (let i = 0; i < children.length; i++) {
    for (let j = i + 1; j < children.length; j++) {
      const a = rectOf(children[i]!);
      const b = rectOf(children[j]!);
      if (a.width === 0 || a.height === 0 || b.width === 0 || b.height === 0) continue;
      const style = getComputedStyle(children[j]!);
      if (style.position === 'absolute' || style.position === 'fixed') continue;

      const horizontal = Math.min(a.right, b.right) - Math.max(a.left, b.left);
      const vertical = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
      if (horizontal > TOLERANCE && vertical > TOLERANCE) {
        overlaps.push({
          a: describe(children[i]!),
          b: describe(children[j]!),
          by: Math.min(horizontal, vertical),
        });
      }
    }
  }

  return {
    found: true, selector, rect: box,
    childCount: children.length,
    descendantCount: Array.from(container.querySelectorAll('*')).filter((el) => !isHidden(el)).length,
    overflows, overlaps, degenerate, clipped,
    tables: measureTables(container),
  };
}

/** measureTables measures every table in a region, including the region itself. */
function measureTables(container: Element): TableMeasurement[] {
  const tables: HTMLTableElement[] = [];
  if (container.tagName.toLowerCase() === 'table') tables.push(container as HTMLTableElement);
  tables.push(...Array.from(container.querySelectorAll('table')));

  return tables.filter((t) => !isHidden(t)).map((table) => {
    const headerCells = Array.from(table.querySelectorAll('thead th')).filter((el) => !isHidden(el));
    // Spacer rows are structural padding for a virtualiser and carry no data.
    const bodyRows = Array.from(table.querySelectorAll('tbody tr')).filter(
      (r) => r.getAttribute('aria-hidden') !== 'true' && !isHidden(r),
    );

    // The reference columns: the header's, or — for a table with row headers
    // and no thead, which the coverage history is — the first body row's.
    //
    // Without the fallback such a table is unmeasured: maxColumnDrift stays
    // zero because there is nothing to compare against, and a table whose
    // rows disagreed about where the columns are would report perfectly.
    let headerXs = headerCells.map((el) => rectOf(el).left);
    let referenceIsHeader = headerXs.length > 0;
    if (!referenceIsHeader && bodyRows.length > 0) {
      headerXs = Array.from(bodyRows[0]!.children)
        .filter((el) => !isHidden(el))
        .map((el) => rectOf(el).left);
    }

    let maxColumnDrift = 0;
    let cellCountMismatches = 0;
    for (const row of bodyRows) {
      const cells = Array.from(row.children).filter((el) => !isHidden(el));
      // A row spanning the table with one cell is a legitimate "no rows"
      // message rather than a collapse, and colSpan is how it says so.
      const spans = cells.length === 1 && Number((cells[0] as HTMLTableCellElement).colSpan) > 1;
      if (headerXs.length > 0 && cells.length !== headerXs.length && !spans) {
        cellCountMismatches++;
      }
      if (spans) continue;
      cells.forEach((cell, i) => {
        const h = headerXs[i];
        if (h !== undefined) maxColumnDrift = Math.max(maxColumnDrift, Math.abs(rectOf(cell).left - h));
      });
    }

    let overlappingRowPairs = 0;
    for (let i = 1; i < bodyRows.length; i++) {
      const previous = rectOf(bodyRows[i - 1]!);
      const current = rectOf(bodyRows[i]!);
      if (current.top < previous.bottom - 1) overlappingRowPairs++;
    }

    const tableWidth = rectOf(table).width;
    let narrowestRowRatio = 1;
    for (const row of bodyRows) {
      const width = rectOf(row).width;
      if (tableWidth > 0) narrowestRowRatio = Math.min(narrowestRowRatio, width / tableWidth);
    }

    const gaps = headerXs.slice(1).map((x, i) => x - headerXs[i]!);
    return {
      what: describe(table),
      headerCells: headerCells.length,
      referenceIsHeader,
      bodyRows: bodyRows.length,
      maxColumnDrift,
      cellCountMismatches,
      overlappingRowPairs,
      minColumnGap: gaps.length > 0 ? Math.min(...gaps) : 0,
      narrowestRowRatio: Math.round(narrowestRowRatio * 1000) / 1000,
    };
  });
}

/**
 * summarise renders a measurement as the sentence a failing test should print.
 *
 * Here rather than in the test, because the test runs in jsdom and the
 * measurement was taken in a browser: whatever explains the failure has to
 * survive being serialised through a DOM dump.
 */
export function summarise(m: PanelMeasurement): string {
  if (!m.found) return `${m.selector} did not render at all`;
  const parts: string[] = [];
  for (const o of m.overflows) parts.push(`${o.what} extends ${o.by}px past the ${o.edge} edge`);
  for (const o of m.overlaps) parts.push(`${o.a} overlaps ${o.b} by ${o.by}px`);
  for (const d of m.degenerate) parts.push(`${d.what} has no size but carries "${d.text}"`);
  for (const c of m.clipped) parts.push(`${c.what} clips ${c.by}px of "${c.text}"`);
  for (const t of m.tables) {
    if (t.maxColumnDrift > TOLERANCE) {
      parts.push(`${t.what}: a body cell sits ${t.maxColumnDrift}px from its header column`);
    }
    if (t.cellCountMismatches > 0) {
      parts.push(`${t.what}: ${t.cellCountMismatches} row(s) have a different cell count from the header`);
    }
    if (t.overlappingRowPairs > 0) {
      parts.push(`${t.what}: ${t.overlappingRowPairs} overlapping row pair(s)`);
    }
    if (t.narrowestRowRatio < 0.9) {
      parts.push(
        `${t.what}: a body row spans only ${Math.round(t.narrowestRowRatio * 100)}% of the ` +
          `table, so it has left the column model`,
      );
    }
  }
  return parts.length === 0 ? `${m.selector}: laid out correctly` : `${m.selector}: ${parts.join('; ')}`;
}
