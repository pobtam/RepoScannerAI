/**
 * App or AI vulnerability: every finding says which it is, and the finding
 * explorer filters and counts on it. The API decides (model.DomainOf); these
 * tests hold the interface to what the captured API responses say.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, within } from '@testing-library/dom';
import { cleanup, waitFor } from '@testing-library/react';
import { Explorer } from './Explorer';
import { FilterPanel } from './FilterPanel';
import { FindingDetail } from '../detail/FindingDetail';
import { renderApp, stubApi } from '../../test-utils';
import { activeFilters, apiQuery, parseExplorerState } from '../../lib/view-state';
import findingsPage from '../../test-fixtures/findings-page.json';
import findingsNuGuard from '../../test-fixtures/findings-nuguard.json';
import facets from '../../test-fixtures/facets.json';
import finding from '../../test-fixtures/finding.json';
import findingNuGuard from '../../test-fixtures/finding-nuguard.json';
import timeline from '../../test-fixtures/timeline.json';
import attempts from '../../test-fixtures/attempts.json';
import type { Facets } from '../../api/schemas';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

async function rowsOf(page: unknown) {
  stubApi([['/findings/facets', facets], ['/findings', page]]);
  renderApp(<Explorer />, '/findings?scope=open');
  await waitFor(() => expect(document.querySelectorAll('.row').length).toBeGreaterThan(0));
  return Array.from(document.querySelectorAll<HTMLElement>('.row'));
}

describe('app or AI vulnerability', () => {
  it('marks every row with exactly one type, as the API classified it', async () => {
    for (const page of [findingsPage, findingsNuGuard]) {
      const rows = await rowsOf(page);
      const want = page.findings.map((f) => (f.domain === 'ai' ? 'AI' : 'App'));
      const got = rows.map((r) => {
        const badges = r.querySelectorAll('.badge-domain-app, .badge-domain-ai');
        expect(badges).toHaveLength(1);
        return badges[0]!.textContent;
      });
      expect(got).toEqual(want.slice(0, got.length));
      cleanup();
    }
    // The captured pages hold both kinds, so both renderings were checked.
    expect(findingsPage.findings.some((f) => f.domain === 'app')).toBe(true);
    expect(findingsNuGuard.findings.some((f) => f.domain === 'ai')).toBe(true);
  });

  it('offers Type as a counted filter, with an empty option shown and disabled, not hidden', () => {
    const onChange = vi.fn();
    const { state } = parseExplorerState('scope=open');
    renderApp(<FilterPanel state={state} facets={facets as unknown as Facets} onChange={onChange} />);
    const group = screen.getByText('Type').closest('fieldset')!;
    for (const opt of facets.domains) {
      const label = within(group)
        .getByText(opt.value === 'ai' ? 'AI vulnerability' : 'App vulnerability')
        .closest('label')!;
      expect(label.textContent).toContain(String(opt.count));
      expect(label.querySelector('input')!.disabled).toBe(opt.disabled);
    }
    const app = within(group).getByText('App vulnerability').closest('label')!.querySelector('input')!;
    fireEvent.click(app);
    const next = onChange.mock.calls[0]![0];
    expect(next.domain).toEqual(['app']);
    expect(apiQuery(next)).toContain('domain=app');
  });

  it('round-trips the filter through the URL and names it in words on its chip', () => {
    const { state, dropped } = parseExplorerState('scope=open&domain=ai,app');
    expect(dropped).toEqual([]);
    expect(state.domain).toEqual(['ai', 'app']);
    // Sent as repeated parameters; the API reads repeated and comma forms.
    expect(apiQuery(state)).toContain('domain=ai&domain=app');
    const chips = activeFilters(state).map((f) => f.label);
    expect(chips).toContain('type: AI vulnerability');
    expect(chips).toContain('type: App vulnerability');
  });

  it('says the type on the finding page', async () => {
    for (const [f, label] of [
      [finding, 'App vulnerability'],
      [findingNuGuard, 'AI vulnerability'],
    ] as const) {
      stubApi([['/timeline', timeline], ['/attempts', attempts], ['/findings/', f]]);
      renderApp(<FindingDetail fingerprint={f.fingerprint} />);
      const h1 = await screen.findByRole('heading', { level: 1 });
      await waitFor(() => expect(h1.textContent).toContain(label));
      cleanup();
      vi.unstubAllGlobals();
    }
  });
});
