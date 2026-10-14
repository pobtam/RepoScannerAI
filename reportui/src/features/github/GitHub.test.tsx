import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { renderApp, stubApi } from '../../test-utils';
import { GitHubPage } from './GitHub';
import github from '../../test-fixtures/github.json';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('the GitHub page', () => {
  it('shows the connected account, its expiry, and how read-only is assured', async () => {
    stubApi([['/github', github]]);
    renderApp(<GitHubPage />, '/github');
    const account = github.connections[0]!;
    await waitFor(() => expect(screen.getByRole('heading', { name: new RegExp(account.account) })).toBeTruthy());
    expect(screen.getByText('fine-grained token')).toBeTruthy();
    expect(screen.getByText(/limited to GET by the client/)).toBeTruthy();
    expect(screen.getByText(new RegExp(`in ${account.expires_in_days} days`))).toBeTruthy();
  });

  it('lists every repository, and gives every skipped one its reason', async () => {
    stubApi([['/github', github]]);
    const { container } = renderApp(<GitHubPage />, '/github');
    await waitFor(() => expect(container.querySelectorAll('tbody tr').length).toBeGreaterThan(0));

    const rows = container.querySelectorAll('.table-scroll tbody tr');
    expect(rows).toHaveLength(github.discovered.length);
    for (const r of github.discovered.filter((d) => !d.included)) {
      expect(screen.getByText(r.detail!)).toBeTruthy();
    }
    // Scanned repositories link to their repository page; skipped ones are
    // not in the registry, so they do not.
    const scanned = github.discovered.find((d) => d.included)!;
    expect(screen.getByRole('link', { name: scanned.name }).getAttribute('href')).toBe(`/repos/${scanned.name}`);
    const skipped = github.discovered.find((d) => !d.included)!;
    expect(screen.queryByRole('link', { name: skipped.name })).toBeNull();
  });

  it('filters to scanned or skipped without losing count of the other', async () => {
    stubApi([['/github', github]]);
    const { container } = renderApp(<GitHubPage />, '/github');
    await waitFor(() => expect(container.querySelectorAll('tbody tr').length).toBeGreaterThan(0));

    fireEvent.click(screen.getByRole('button', { name: 'skipped' }));
    const skippedCount = github.summary.seen - github.summary.included;
    expect(container.querySelectorAll('.table-scroll tbody tr')).toHaveLength(skippedCount);
    // The figures are the whole discovery, whatever the table shows.
    const figures = [...container.querySelectorAll('.figure-value')].map((e) => e.textContent);
    expect(figures).toEqual([String(github.summary.seen), String(github.summary.included), String(skippedCount)]);

    fireEvent.click(screen.getByRole('button', { name: 'scanned' }));
    expect(container.querySelectorAll('.table-scroll tbody tr')).toHaveLength(github.summary.included);
  });

  it('says how to connect when no account is connected', async () => {
    // The shape the API sends before any connection: empty arrays, never
    // missing ones (internal/api TestGitHubViewShowsTheAccountAndEveryDecision).
    stubApi([['/github', { connections: [], discovered: [], exclusions: [], summary: { seen: 0, included: 0, skipped: {} } }]]);
    renderApp(<GitHubPage />, '/github');
    await waitFor(() => expect(screen.getByText('No account connected')).toBeTruthy());
    expect(screen.getByText(/github connect/)).toBeTruthy();
  });
});
