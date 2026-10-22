/**
 * "Scan now", "Scan all included repositories" and the status of each
 * request, against responses captured from the real API (the end-to-end test
 * in cmd/orchestrator writes them with UPDATE_UI_FIXTURES=1).
 */
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { renderApp } from '../../test-utils';
import { ScanNow, ScanQueue, ScanRow } from './ScanControls';
import { RepoIndex } from '../repos/Repos';
import repos from '../../test-fixtures/repos.json';
import healthOff from '../../test-fixtures/health.json';
import healthOn from '../../test-fixtures/health-scans.json';
import scans from '../../test-fixtures/scans.json';
import queued from '../../test-fixtures/scan-request.json';
import forbidden from '../../test-fixtures/scan-forbidden.json';

type Call = { method: string; url: string; headers: Record<string, string>; body?: string };

/** A fetch stub that answers by method and path, and records every call. */
function stub(routes: { method?: string; path: string; status?: number; body: unknown }[]): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      calls.push({ method, url, headers: (init?.headers ?? {}) as Record<string, string>, body: init?.body as string });
      const hit = routes.find((r) => (r.method ?? 'GET') === method && url.includes(r.path));
      if (!hit) throw new Error(`no route for ${method} ${url}`);
      return new Response(JSON.stringify(hit.body), {
        status: hit.status ?? 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }),
  );
  return calls;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('Scan now', () => {
  it('is not offered where no scan worker exists', async () => {
    stub([{ path: '/health', body: healthOff }]);
    const { container } = renderApp(<ScanNow repo="octo/api" />);
    await waitFor(() => expect(container.textContent).toBe(''));
    expect(screen.queryByRole('button', { name: /Scan now/ })).toBeNull();
  });

  it('queues a scan with the CSRF token and a body of the repository only', async () => {
    const calls = stub([
      { path: '/health', body: healthOn },
      { path: '/csrf', body: { token: 'tok-1', expires_at: '2026-10-22T21:00:00Z' } },
      { method: 'POST', path: '/scans', status: 201, body: queued },
      { path: '/scans', body: [] },
    ]);
    renderApp(<ScanNow repo="octo/api" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Scan now' }));

    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    const post = calls.find((c) => c.method === 'POST')!;
    expect(post.url).toMatch(/\/v1\/scans$/);
    expect(post.headers['X-CSRF-Token']).toBe('tok-1');
    expect(JSON.parse(post.body!)).toEqual({ repo: 'octo/api' });
  });

  it('says why when the caller may not request scans', async () => {
    stub([
      { path: '/health', body: healthOn },
      { path: '/csrf', body: { token: 'tok-1', expires_at: '2026-10-22T21:00:00Z' } },
      { method: 'POST', path: '/scans', status: 403, body: forbidden },
      { path: '/scans', body: [] },
    ]);
    renderApp(<ScanNow repo="octo/api" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Scan now' }));
    expect(await screen.findByText(/not permitted: requesting a scan needs the security-owner level/)).toBeTruthy();
  });

  it('shows a queued scan as queued and does not offer a second', async () => {
    stub([
      { path: '/health', body: healthOn },
      { path: '/scans', body: [queued.request] },
    ]);
    renderApp(<ScanNow repo="octo/api" />);
    const button = await screen.findByRole('button', { name: 'Scan queued' });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText('queued')).toBeTruthy();
  });
});

describe('the scan queue', () => {
  it('shows every outcome as itself, with its reason and links', async () => {
    stub([
      { path: '/health', body: healthOn },
      { path: '/scans', body: scans },
    ]);
    renderApp(<ScanQueue />);
    await screen.findByRole('button', { name: 'Scan all included repositories' });

    const finished = scans.find((r) => r.status === 'finished')!;
    expect(await screen.findByRole('link', { name: `run ${finished.run_id}` })).toBeTruthy();

    const timedOut = scans.find((r) => r.status === 'timed_out')!;
    expect(screen.getByText(timedOut.reason!)).toBeTruthy();
    expect(screen.getByText('timed out')).toBeTruthy();
    // A timeout is a gap, and says so; it is never shown as finished.
    expect(screen.getAllByRole('link', { name: 'recorded as a coverage gap' }).length).toBeGreaterThan(0);

    const refused = scans.find((r) => r.status === 'refused')!;
    expect(screen.getByText(refused.reason!)).toBeTruthy();

    const interrupted = scans.find((r) => r.status === 'interrupted')!;
    expect(screen.getByText(interrupted.reason!)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeTruthy();
  });

  it('queues every included repository as one batch', async () => {
    const calls = stub([
      { path: '/health', body: healthOn },
      // The client keeps its token for the session, so the server issues the
      // same one here as in the tests above.
      { path: '/csrf', body: { token: 'tok-1', expires_at: '2026-10-22T21:00:00Z' } },
      { method: 'POST', path: '/scans/all', status: 201, body: { batch_id: 'batch_x', requests: [], queued: 3, merged: 1 } },
      { path: '/scans', body: [] },
    ]);
    renderApp(<ScanQueue />);
    fireEvent.click(await screen.findByRole('button', { name: 'Scan all included repositories' }));
    expect(await screen.findByText('3 queued, 1 already queued or running.')).toBeTruthy();
    const post = calls.find((c) => c.method === 'POST')!;
    expect(post.url).toMatch(/\/v1\/scans\/all$/);
    expect(post.body).toBeUndefined();
    expect(post.headers['X-CSRF-Token']).toBe('tok-1');
  });
});

describe('Scan now on every row of the repositories table', () => {
  it('has no scan column where no scan worker exists', async () => {
    stub([
      { path: '/health', body: healthOff },
      { path: '/repos', body: repos },
    ]);
    renderApp(<RepoIndex />);
    await screen.findByRole('link', { name: repos[0]!.name });
    expect(screen.queryByRole('columnheader', { name: 'Scan' })).toBeNull();
    expect(screen.queryAllByRole('button', { name: /Scan .* now/ })).toHaveLength(0);
  });

  it('offers every repository, and queues the one clicked with the CSRF token', async () => {
    const calls = stub([
      { path: '/health', body: healthOn },
      { path: '/repos', body: repos },
      { path: '/csrf', body: { token: 'tok-1', expires_at: '2026-10-22T21:00:00Z' } },
      { method: 'POST', path: '/scans', status: 201, body: queued },
      { path: '/scans', body: [] },
    ]);
    renderApp(<RepoIndex />);
    await screen.findByRole('columnheader', { name: 'Scan' });
    for (const r of repos) {
      expect(screen.getByRole('button', { name: `Scan ${r.name} now` })).toBeTruthy();
    }
    // The index asks for the queue once, not once per row.
    const lists = calls.filter((c) => c.method === 'GET' && /\/v1\/scans\?/.test(c.url) && !c.url.includes('repo='));
    expect(lists.length).toBeLessThanOrEqual(2); // the row lookup and the queue panel

    const target = repos[1]!.name;
    fireEvent.click(screen.getByRole('button', { name: `Scan ${target} now` }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    const post = calls.find((c) => c.method === 'POST')!;
    expect(post.url).toMatch(/\/v1\/scans$/);
    expect(post.headers['X-CSRF-Token']).toBe('tok-1');
    expect(JSON.parse(post.body!)).toEqual({ repo: target });
  });

  it('shows a queued request as queued and does not offer a second', () => {
    stub([]);
    renderApp(<ScanRow repo="octo/api" last={queued.request as never} />);
    const button = screen.getByRole('button', { name: 'Scan of octo/api queued' });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText('queued')).toBeTruthy();
  });

  it('shows the latest outcome as itself, with its reason on hover, and offers a new scan', () => {
    stub([]);
    const timedOut = scans.find((r) => r.status === 'timed_out')!;
    renderApp(<ScanRow repo={timedOut.repo} last={timedOut as never} />);
    expect((screen.getByRole('button', { name: `Scan ${timedOut.repo} now` }) as HTMLButtonElement).disabled).toBe(false);
    const badge = screen.getByText('timed out');
    expect(badge.closest('[title]')?.getAttribute('title')).toBe(timedOut.reason);
  });

  it('says why when the caller may not request scans', async () => {
    stub([
      { path: '/csrf', body: { token: 'tok-1', expires_at: '2026-10-22T21:00:00Z' } },
      { method: 'POST', path: '/scans', status: 403, body: forbidden },
    ]);
    renderApp(<ScanRow repo="octo/api" />);
    fireEvent.click(screen.getByRole('button', { name: 'Scan octo/api now' }));
    expect(await screen.findByText(/not permitted: requesting a scan needs the security-owner level/)).toBeTruthy();
  });
});
