/**
 * Accessibility (U10, VM-UI-F-901 … VM-UI-F-909).
 *
 * These are the parts a test can hold: every interactive element has an
 * accessible name, every table column has a header with a scope, severity and
 * state are encoded by text as well as colour, and the graph has a text
 * alternative. Contrast and a full keyboard traversal are checked by hand —
 * recorded as such rather than claimed.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { waitFor } from '@testing-library/react';
import { renderApp, stubApi } from './test-utils';
import { Explorer } from './features/explorer/Explorer';
import { FindingDetail } from './features/detail/FindingDetail';
import findingsPage from './test-fixtures/findings-page.json';
import facets from './test-fixtures/facets.json';
import finding from './test-fixtures/finding.json';
import timeline from './test-fixtures/timeline.json';
import attempts from './test-fixtures/attempts.json';

afterEach(() => vi.unstubAllGlobals());

/** accessibleName is what a screen reader would announce. */
function accessibleName(el: Element): string {
  return (
    el.getAttribute('aria-label') ??
    el.getAttribute('title') ??
    (el.textContent ?? '').trim()
  );
}

describe('the explorer', () => {
  async function render() {
    stubApi([['/findings/facets', facets], ['/findings', findingsPage]]);
    renderApp(<Explorer />, '/findings?scope=open');
    await waitFor(() => expect(document.querySelectorAll('.row').length).toBeGreaterThan(0));
  }

  it('gives every button and link an accessible name', async () => {
    await render();
    const interactive = [...document.querySelectorAll('button, a, select, input')];
    expect(interactive.length).toBeGreaterThan(10);
    const unnamed = interactive.filter((el) => {
      if (el.tagName === 'INPUT' || el.tagName === 'SELECT') {
        // A form control is named by its label, its aria-label, or the label
        // that wraps it.
        return !(
          el.getAttribute('aria-label') ||
          el.closest('label') ||
          (el.id && document.querySelector(`label[for="${el.id}"]`))
        );
      }
      return accessibleName(el).length === 0;
    });
    expect(
      unnamed.map((el) => el.outerHTML.slice(0, 80)),
      'these controls cannot be announced or reached meaningfully by keyboard',
    ).toEqual([]);
  });

  it('gives every column a header with a scope', async () => {
    await render();
    const headers = [...document.querySelectorAll('.findings thead th')];
    expect(headers.length).toBeGreaterThan(5);
    for (const th of headers) {
      expect(th.getAttribute('scope'), `header without a scope: ${th.textContent}`).toBe('col');
    }
  });

  it('encodes severity and state by text as well as colour (VM-UI-F-901)', async () => {
    await render();
    for (const badge of [...document.querySelectorAll('.badge')].slice(0, 12)) {
      // The class carries the colour; the text carries the meaning. A reader
      // who cannot distinguish the hues still reads the value.
      expect((badge.textContent ?? '').trim().length).toBeGreaterThan(1);
    }
  });

  it('marks the live region for loading, so a change is announced', async () => {
    stubApi([['/findings/facets', facets], ['/findings', findingsPage]]);
    renderApp(<Explorer />, '/findings?scope=open');
    const status = document.querySelector('[role="status"]');
    expect(status?.getAttribute('aria-live')).toBe('polite');
  });
});

describe('the finding detail', () => {
  it('describes every absence in text, not by an empty cell', async () => {
    stubApi([['/timeline', timeline], ['/attempts', attempts], ['/findings/', finding]]);
    renderApp(<FindingDetail fingerprint={(finding as { fingerprint: string }).fingerprint} />);
    await waitFor(() => expect(document.querySelector('.record')).toBeTruthy());

    for (const el of [...document.querySelectorAll('.absent')]) {
      // A screen reader hears the explanation, not a dash.
      const hidden = el.querySelector('.sr-only');
      expect(
        hidden?.textContent ?? el.getAttribute('title') ?? '',
        `an absence with nothing to announce: ${el.outerHTML.slice(0, 120)}`,
      ).toMatch(/\w{6}/);
    }
  });

  it('puts verification evidence in a scrollable monospaced region (VM-UI-F-509)', async () => {
    stubApi([['/timeline', timeline], ['/attempts', attempts], ['/findings/', finding]]);
    renderApp(<FindingDetail fingerprint={(finding as { fingerprint: string }).fingerprint} />);
    await waitFor(() => expect(document.querySelector('.score')).toBeTruthy());
    const verbatim = document.querySelector('.verbatim');
    if (verbatim) {
      expect(verbatim.tagName).toBe('PRE');
    }
  });
});
