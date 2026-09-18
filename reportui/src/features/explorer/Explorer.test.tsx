/**
 * The explorer's honesty (U1).
 *
 * Every test here corresponds to a way the interface could mislead while
 * looking perfectly normal. The rendering is checked against the captured API
 * payloads, so a test passes only if the interface renders what the server
 * actually sends.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/dom';
import { waitFor } from '@testing-library/react';
import { Explorer } from './Explorer';
import { renderApp, stubApi } from '../../test-utils';
import findingsPage from '../../test-fixtures/findings-page.json';
import facets from '../../test-fixtures/facets.json';
import type { FindingPage } from '../../api/schemas';

// The fixture, typed as the schema rather than as its own literal shape, so a
// test can vary one field without TypeScript inferring a narrower type from
// the JSON than the API actually sends.
const page = findingsPage as unknown as FindingPage;

afterEach(() => vi.unstubAllGlobals());

function renderExplorer(page: unknown = findingsPage, path = '/findings?scope=open') {
  stubApi([['/findings/facets', facets], ['/findings', page]]);
  return renderApp(<Explorer />, path);
}

describe('the corpus statement (VM-UI-F-417/418/419)', () => {
  it('states the corpus in words and keeps the three figures apart', async () => {
    renderExplorer();
    await waitFor(() => expect(document.querySelector('.corpus')).toBeTruthy());

    const corpus = document.querySelector('.corpus')!;
    const text = corpus.textContent ?? '';
    // Matching, in corpus, and total: one number cannot express which
    // findings a count counts.
    expect(text).toMatch(new RegExp(`${findingsPage.matched}\\s*matching`));
    expect(text).toContain(String(findingsPage.in_corpus));
    expect(text).toContain(String(findingsPage.total));
    expect(text).toContain(findingsPage.corpus.description);
  });

  it('says what the corpus excludes, and how many records that is', async () => {
    renderExplorer();
    await waitFor(() => expect(document.querySelector('.corpus')).toBeTruthy());
    const text = document.querySelector('.corpus')!.textContent ?? '';
    if (findingsPage.corpus.excluded_count > 0) {
      expect(text).toContain(String(findingsPage.corpus.excluded_count));
      expect(text.toLowerCase()).toContain('exclude');
    }
  });
});

describe('absences render as absences', () => {
  it('shows an unavailable exploitation input as "not looked up", never as zero', async () => {
    renderExplorer();
    await waitFor(() => expect(document.querySelectorAll('.row').length).toBeGreaterThan(0));

    const withoutEpss = findingsPage.findings.filter((f) => f.classification.epss === undefined);
    expect(withoutEpss.length).toBeGreaterThan(0);

    // The table must say nothing answered. A "0.00" here would turn a feed
    // outage into reassurance (OQ-AUDIT-01).
    expect(screen.getAllByText('not looked up').length).toBeGreaterThan(0);
    expect(screen.queryByText('0.00')).toBeNull();
  });

  it('shows a finding with no priority as absent, not as a low one', async () => {
    const varied = structuredClone(page);
    varied.findings = [{ ...varied.findings[0]!, priority: undefined }];
    renderExplorer(varied);
    await waitFor(() => expect(document.querySelectorAll('.row').length).toBe(1));

    const cell = document.querySelector('.row td')!;
    expect(cell.querySelector('.absent')).toBeTruthy();
    expect(cell.textContent).not.toContain('P3');
  });
});

describe('the not-re-observed marker (VM-UI-F-422/423)', () => {
  it('renders with its explanation attached, not in a legend', async () => {
    const varied = structuredClone(page);
    const marked = {
      ...varied.findings[0]!,
      observation: {
        ...varied.findings[0]!.observation,
        not_reobserved: true,
        not_reobserved_note:
          'the most recent applicable run did not observe this finding while it remains ' +
          'unresolved. That is AMBIGUOUS between remediation and a coverage gap',
      },
    };
    varied.findings = [marked];
    renderExplorer(varied);

    await waitFor(() => expect(screen.getByText('not re-observed')).toBeTruthy());
    const el = screen.getByText('not re-observed');
    // The words travel WITH the marker: a marker whose meaning lives
    // elsewhere is read as "probably fixed".
    expect(el.getAttribute('title')).toContain('AMBIGUOUS');
    expect(el.getAttribute('title')).toContain('coverage gap');
  });
});

describe('restricted findings (VM-UI-F-804)', () => {
  it('are shown as counted-but-not-openable rather than omitted', async () => {
    const varied = structuredClone(page);
    varied.findings = [{ ...varied.findings[0]!, restricted: true, identity: {} }];
    varied.restricted_count = 1;
    renderExplorer(varied);

    await waitFor(() => expect(screen.getByText(/restricted — counted, not shown/)).toBeTruthy());
    // And the count says so, so the reader knows why they see less detail.
    expect(document.querySelector('.restricted-note')!.textContent).toContain('1');
  });
});

describe('the filter panel (VM-UI-F-408)', () => {
  it('shows every option with its count, including zero, and disables the empty ones', async () => {
    renderExplorer();
    await waitFor(() => expect(document.querySelectorAll('.filter-group').length).toBeGreaterThan(3));

    const zeroOptions = [...facets.states, ...facets.severities].filter((o) => o.count === 0);
    expect(zeroOptions.length).toBeGreaterThan(0);

    for (const option of zeroOptions.slice(0, 3)) {
      // Present and disabled, never hidden: a hidden option looks like a
      // dimension that does not exist.
      const label = screen.getAllByText(option.value)[0];
      expect(label).toBeTruthy();
      const input = label!.closest('label')!.querySelector('input');
      expect(input?.hasAttribute('disabled')).toBe(true);
    }
  });

  it('spells out that "unknown" reachability is not a determination', async () => {
    renderExplorer();
    await waitFor(() => expect(screen.getByText(/unknown \(not a determination\)/)).toBeTruthy());
  });
});

describe('the tri-state reachability column (VM-UI-F-504)', () => {
  it('renders unknown differently from "not reachable"', async () => {
    renderExplorer();
    await waitFor(() => expect(document.querySelectorAll('.row').length).toBeGreaterThan(0));

    const unknown = document.querySelector('.reach-unknown');
    expect(unknown).toBeTruthy();
    expect(unknown!.textContent).toBe('unknown');
    expect(unknown!.getAttribute('title')).toContain('NOT');
  });
});

describe('the empty states (VM-UI-F-904)', () => {
  it('distinguishes an empty filter from an empty system', async () => {
    const filtered = { ...structuredClone(page), findings: [], matched: 0, in_corpus: 12 };
    renderExplorer(filtered);
    await waitFor(() => expect(screen.getByText(/No findings match this filter/)).toBeTruthy());

    vi.unstubAllGlobals();
    const empty = { ...structuredClone(page), findings: [], matched: 0, in_corpus: 0, total: 0 };
    renderExplorer(empty);
    await waitFor(() => expect(screen.getByText(/No findings recorded yet/)).toBeTruthy());
  });
});

describe('errors (VM-UI-F-903)', () => {
  it('says what failed and what to do, rather than showing a blank panel', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ error: 'scope required', remedy: 'pass scope=open' }), {
          status: 400,
        }),
      ),
    );
    renderApp(<Explorer />, '/findings');
    await waitFor(() => expect(screen.getAllByRole('alert').length).toBeGreaterThan(0));
    const alerts = screen.getAllByRole('alert');
    const reported = alerts.find((a) => a.textContent?.includes('scope required'));
    expect(reported, `no alert named the failure: ${alerts.map((a) => a.textContent).join(' | ')}`)
      .toBeTruthy();
    expect(within(reported!).getByText(/scope required/)).toBeTruthy();
    expect(reported!.textContent).toContain('pass scope=open');
  });
});

describe('pagination (VM-UI-F-403)', () => {
  it('offers the next page only when the server said there is one', async () => {
    const withCursor = { ...structuredClone(page), next_cursor: 'abc' };
    renderExplorer(withCursor);
    await waitFor(() => expect(screen.getByText(/Next page/)).toBeTruthy());

    vi.unstubAllGlobals();
    const lastPage = { ...structuredClone(page), next_cursor: undefined };
    renderExplorer(lastPage);
    await waitFor(() => expect(screen.getByText(/end of results/)).toBeTruthy());
  });
});
