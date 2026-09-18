/**
 * No always-empty column.
 *
 * The user's rule, and the right one: an always-empty column is a
 * producer-coverage failure, not a styling gap. The API proves every field it
 * sends has a real producer; this proves every COLUMN the interface renders
 * has a value in it for at least one row of a realistic corpus.
 *
 * A column that is empty for every row of the demonstration data is either
 * reading a field nothing writes or reading it wrongly, and both look exactly
 * like a feature nobody has used yet.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { waitFor } from '@testing-library/react';
import { Explorer } from './Explorer';
import { renderApp, stubApi } from '../../test-utils';
import findingsPage from '../../test-fixtures/findings-page.json';
import facets from '../../test-fixtures/facets.json';

afterEach(() => vi.unstubAllGlobals());

describe('every column carries data for a realistic corpus', () => {
  it('has a non-empty cell in every column', async () => {
    stubApi([['/findings/facets', facets], ['/findings', findingsPage]]);
    renderApp(<Explorer />, '/findings?scope=open');

    await waitFor(() => expect(document.querySelectorAll('.row').length).toBeGreaterThan(3));

    const headers = [...document.querySelectorAll('.findings thead th')].map((th) =>
      (th.textContent ?? '').trim(),
    );
    const rows = [...document.querySelectorAll('.findings tbody tr')];
    expect(rows.length).toBeGreaterThan(3);

    const empty: string[] = [];
    headers.forEach((header, column) => {
      const hasValue = rows.some((row) => {
        const cell = row.children[column];
        if (!cell) return false;
        const text = (cell.textContent ?? '').replace(/[\s—]/g, '');
        return text.length > 0;
      });
      if (!hasValue) empty.push(header || `column ${column}`);
    });

    expect(
      empty,
      `these columns are empty for every one of ${rows.length} findings: ${empty.join(', ')}. ` +
        'An always-empty column is a producer-coverage failure — the interface is reading a ' +
        'field nothing writes, or reading it wrongly — not a styling gap.',
    ).toEqual([]);
  });

  it('renders as many rows as the API returned', async () => {
    stubApi([['/findings/facets', facets], ['/findings', findingsPage]]);
    renderApp(<Explorer />, '/findings?scope=open');
    await waitFor(() =>
      expect(document.querySelectorAll('.findings tbody tr').length).toBe(
        findingsPage.findings.length,
      ),
    );
  });
});
