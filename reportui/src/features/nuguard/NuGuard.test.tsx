/**
 * The NuGuard controls (VM-UI-F-1201..1212), against responses captured from
 * the real API with the real scan worker scanning through the fake NuGuard
 * (UPDATE_UI_FIXTURES=1 go test ./internal/api -run TestNuGuardViewsFromTheRealServer).
 */
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { renderApp } from '../../test-utils';
import { NuGuardPage, RepoNuGuardSection, NuGuardFindingSection, AISBOMDownload, CommitSHA } from './NuGuard';
import { ScanNow, ScanQueue } from '../scans/ScanControls';
import { Coverage } from '../coverage/Coverage';
import { RunPage } from '../runs/Overview';
import { FilterPanel } from '../explorer/FilterPanel';
import { apiQuery, parseExplorerState } from '../../lib/view-state';
import * as s from '../../api/schemas';
import page from '../../test-fixtures/nuguard-page.json';
import pageEngineer from '../../test-fixtures/nuguard-page-engineer.json';
import pageStale from '../../test-fixtures/nuguard-page-stale.json';
import notConfigured from '../../test-fixtures/nuguard-not-configured.json';
import nuguardDemo from '../../test-fixtures/nuguard-demo.json';
import refused422 from '../../test-fixtures/nuguard-422.json';
import preview from '../../test-fixtures/nuguard-preview.json';
import repoNuGuard from '../../test-fixtures/repo-nuguard.json';
import repoNuGuardOff from '../../test-fixtures/repo-nuguard-off.json';
import repoDetail from '../../test-fixtures/repo-detail-nuguard.json';
import scansNuGuard from '../../test-fixtures/scans-nuguard.json';
import coverage from '../../test-fixtures/coverage-nuguard.json';
import overview from '../../test-fixtures/overview-nuguard.json';
import finding from '../../test-fixtures/finding-nuguard.json';
import repos from '../../test-fixtures/repos.json';
import healthOn from '../../test-fixtures/health-scans.json';
import queued from '../../test-fixtures/scan-request.json';
import forbidden from '../../test-fixtures/scan-forbidden.json';

type Call = { method: string; url: string; headers: Record<string, string>; body?: string };

/** A fetch stub that answers by method and path, in order, and records every call. */
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

const csrf = { path: '/csrf', body: { token: 'tok-1', expires_at: '2026-10-22T21:00:00Z' } };

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('the fixtures are what the validators accept', () => {
  it('parses every captured NuGuard response', () => {
    for (const v of [page, pageEngineer, pageStale, notConfigured, nuguardDemo]) s.nuguardView.parse(v);
    s.repoNuGuard.parse(repoNuGuard);
    s.repoNuGuard.parse(repoNuGuardOff);
    s.nuguardPreview.parse(preview);
    s.repoDetail.parse(repoDetail);
    s.coverageView.parse(coverage);
    s.overview.parse(overview);
    s.finding.parse(finding);
    s.apiError.parse(refused422);
  });
});

describe('the AI scanning page', () => {
  it('shows only the one line where NuGuard is not configured', async () => {
    stub([{ path: '/nuguard', body: nuguardDemo }]);
    renderApp(<NuGuardPage />);
    expect((await screen.findByTestId('nuguard-not-configured')).textContent).toContain(
      'NuGuard is not configured on this deployment',
    );
    expect(screen.queryByText('Fleet settings')).toBeNull();
    expect(screen.queryByText('Status')).toBeNull();
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('lets a security owner edit, with options outside the ceiling disabled and saying why', async () => {
    stub([{ path: '/nuguard', body: page }]);
    renderApp(<NuGuardPage />);
    await screen.findByText('Fleet settings');
    expect(screen.getByRole('button', { name: 'Save' })).toBeTruthy();
    const semgrep = screen.getByText('semgrep').closest('label')!;
    expect((within(semgrep).getByRole('checkbox') as HTMLInputElement).disabled).toBe(true);
    expect(semgrep.textContent).toContain('not offered by the service');
    expect(screen.getByText(/counted into the inventory, never findings/)).toBeTruthy();
    expect(document.body.textContent).toContain('Turning NuGuard off does not close its findings');
  });

  it('says "not allowed by the operator" for a tool the operator left out', async () => {
    stub([{ path: '/nuguard', body: { ...page, ceiling: { ...page.ceiling, allow_tools: ['nga-rules'] } } }]);
    renderApp(<NuGuardPage />);
    await screen.findByText('Fleet settings');
    expect(screen.getByText('atlas').closest('label')!.textContent).toContain('not allowed by the operator');
  });

  it('is read-only for an engineer', async () => {
    stub([{ path: '/nuguard', body: pageEngineer }]);
    renderApp(<NuGuardPage />);
    await screen.findByText(/Read-only: changing NuGuard's settings needs the security-owner level/);
    expect(screen.queryByRole('button', { name: 'Save' })).toBeNull();
    for (const box of screen.getAllByRole('checkbox')) expect((box as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByText('Repository overrides')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'octo/web' })).toBeTruthy();
  });

  it('never shows a stale status as current', async () => {
    stub([{ path: '/nuguard', body: pageStale }]);
    renderApp(<NuGuardPage />);
    expect(await screen.findByText(/status unknown: the scan worker has not reported since/)).toBeTruthy();
    expect(screen.queryByText('Reachable')).toBeNull();
    expect(screen.queryByText(/matches/)).toBeNull();
  });

  it('shows the settings history with who, what and why', async () => {
    stub([{ path: '/nuguard', body: page }]);
    renderApp(<NuGuardPage />);
    const history = (await screen.findByText('Settings history')).closest('section')!;
    expect(history.textContent).toContain('vendored SDK, no AI code');
    expect(history.textContent).toContain('AI rules on for the fleet');
    expect(history.textContent).toContain('pat');
  });

  it('confirms a change with what it affects before saving, then saves with the CSRF token', async () => {
    const calls = stub([
      { path: '/nuguard', body: page },
      { path: '/repos', body: repos },
      csrf,
      { method: 'PUT', path: '/nuguard/settings', body: page },
    ]);
    renderApp(<NuGuardPage />);
    await screen.findByText('Fleet settings');
    fireEvent.click(screen.getByRole('switch'));
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    const dialog = await screen.findByRole('alertdialog');
    expect(dialog.textContent).toContain('on → off');
    const total = s.repoSummary.array().parse(repos).filter((r) => !r.archived).length;
    await waitFor(() => expect(dialog.textContent).toContain(`Affects the ${total - 1} of ${total} included repositories`));
    expect(dialog.textContent).toContain('1 have their own on/off override');
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);

    fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    const put = calls.find((c) => c.method === 'PUT')!;
    expect(put.headers['X-CSRF-Token']).toBe('tok-1');
    expect(JSON.parse(put.body!)).toEqual({ enabled: false, tools: ['nga-rules', 'atlas'], include_posture: true, timeout_s: 300 });
  });

  it('cancelling the confirmation saves nothing', async () => {
    const calls = stub([{ path: '/nuguard', body: page }, { path: '/repos', body: repos }]);
    renderApp(<NuGuardPage />);
    await screen.findByText('Fleet settings');
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('alertdialog')).toBeNull();
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
  });

  it('shows a refusal above the ceiling with the field and the ceiling', async () => {
    stub([
      { path: '/nuguard', body: page },
      { path: '/repos', body: repos },
      csrf,
      { method: 'PUT', path: '/nuguard/settings', status: 422, body: refused422 },
    ]);
    renderApp(<NuGuardPage />);
    await screen.findByText('Fleet settings');
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Confirm' }));
    const alert = await screen.findByText(/timeout_s: above the ceiling of 600 seconds/);
    expect(alert.textContent).toContain("the operator's ceiling is");
  });
});

describe('NuGuard on the repository page', () => {
  it('says where the effective setting comes from, and lists the last scans with their clips', async () => {
    stub([
      { path: '/repos/octo/api/nuguard', body: repoNuGuard },
      { path: '/nuguard', body: page },
    ]);
    renderApp(<RepoNuGuardSection repo="octo/api" />);
    const panel = (await screen.findByText('A scan now would use')).closest('section')!;
    expect(panel.textContent).toContain('inherited from the fleet setting');
    expect(panel.textContent).toContain('semgrep → left out (not offered by the service)');
    expect(within(panel).getByRole('link', { name: 'M-000001' })).toBeTruthy();
    expect(within(panel).getByRole('form', { name: 'NuGuard override for this repository' })).toBeTruthy();
  });

  it('shows an override that turns it off, read-only for an engineer', async () => {
    stub([
      { path: '/repos/octo/web/nuguard', body: repoNuGuardOff },
      { path: '/nuguard', body: pageEngineer },
    ]);
    renderApp(<RepoNuGuardSection repo="octo/web" />);
    const panel = (await screen.findByText('A scan now would use')).closest('section')!;
    expect(panel.textContent).toContain('off for this repository');
    expect(within(panel).queryByRole('form')).toBeNull();
    expect(panel.textContent).toContain('not requested');
  });

  it('shows nothing to the public', async () => {
    stub([{ path: '/repos/octo/api/nuguard', status: 403, body: forbidden }]);
    const { container } = renderApp(<RepoNuGuardSection repo="octo/api" />);
    await waitFor(() => expect(container.textContent).toBe(''));
  });

  it('shows the scanned commit short, with the full SHA on hover', () => {
    const sha = repoDetail.repo.last_commit_sha!;
    renderApp(<CommitSHA sha={sha} />);
    const el = screen.getByTitle(sha);
    expect(el.textContent).toContain(sha.slice(0, 7));
    expect(screen.getByRole('button', { name: 'Copy the full commit SHA' })).toBeTruthy();
  });

  it('offers the kept AI-SBOM for download', () => {
    const ai = repoDetail.ai_components;
    renderApp(<AISBOMDownload repo="octo/api" runID={ai.run_id} sbom={ai.ai_sbom} />);
    const link = screen.getByRole('link', { name: 'Download AI-SBOM' });
    expect(link.getAttribute('href')).toBe(`/v1/repos/octo/api/ai-sbom/${ai.run_id}?format=json`);
  });
});

describe('scan options', () => {
  it('leaves the one-click scan exactly as it was: no options, a body of the repository only', async () => {
    const calls = stub([
      { path: '/health', body: healthOn },
      { path: '/nuguard', body: page },
      csrf,
      { method: 'POST', path: '/scans', status: 201, body: queued },
      { path: '/scans', body: [] },
    ]);
    renderApp(<ScanNow repo="octo/api" />);
    await screen.findByText('NuGuard options');
    fireEvent.click(screen.getByRole('button', { name: 'Scan now' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    expect(JSON.parse(calls.find((c) => c.method === 'POST')!.body!)).toEqual({ repo: 'octo/api' });
    expect(calls.some((c) => c.url.includes('/nuguard/preview'))).toBe(false);
  });

  it('previews what a scan would use before it is submitted, and sends the options', async () => {
    const calls = stub([
      { path: '/health', body: healthOn },
      { path: '/nuguard/preview', body: preview },
      { path: '/nuguard', body: page },
      csrf,
      { method: 'POST', path: '/scans', status: 201, body: queued },
      { path: '/scans', body: [] },
    ]);
    renderApp(<ScanNow repo="octo/api" />);
    fireEvent.click(await screen.findByText('NuGuard options'));
    fireEvent.click(screen.getByLabelText('on'));
    fireEvent.click(screen.getByLabelText('Keep the AI-SBOM'));

    const status = await screen.findByText(/A scan of octo\/api would use/);
    expect(status.closest('[role=status]')!.textContent).toContain('semgrep → left out (not offered by the service)');
    expect(calls.some((c) => c.url.includes('/nuguard/preview') && c.url.includes('nuguard=on') && c.url.includes('keep_sbom=true'))).toBe(true);

    fireEvent.click(screen.getByRole('button', { name: 'Scan now' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    expect(JSON.parse(calls.find((c) => c.method === 'POST')!.body!)).toEqual({
      repo: 'octo/api',
      nuguard: { mode: 'on', keep_sbom: true },
    });
  });

  it('is not offered where NuGuard is not configured', async () => {
    stub([
      { path: '/health', body: healthOn },
      { path: '/nuguard', body: nuguardDemo },
      { path: '/scans', body: [] },
    ]);
    renderApp(<ScanNow repo="octo/api" />);
    await screen.findByRole('button', { name: 'Scan now' });
    await waitFor(() => expect(screen.queryByText('NuGuard options')).toBeNull());
  });

  it('shows the NuGuard options each request asked for', async () => {
    stub([
      { path: '/health', body: healthOn },
      { path: '/nuguard', body: page },
      { path: '/scans', body: scansNuGuard },
    ]);
    renderApp(<ScanQueue />);
    expect(await screen.findByText(/NuGuard on · nga-rules, atlas, semgrep · keep AI-SBOM/)).toBeTruthy();
  });
});

describe('NuGuard on the finding, coverage and run pages', () => {
  it("gives a NuGuard finding its own section, with the options of the scan that last saw it", () => {
    renderApp(<NuGuardFindingSection d={finding.nuguard!} />);
    const panel = screen.getByText('NuGuard tool').closest('section')!;
    expect(panel.textContent).toContain(finding.nuguard!.rule);
    expect(panel.textContent).toContain(finding.nuguard!.sub_tool!);
    expect(panel.textContent).toContain('LLM01');
    expect(panel.textContent).toContain('AML.T0051');
    expect(panel.textContent).toContain('set for this scan');
    // A reference NuGuard did not give is absent, with the reason, not blank.
    expect(panel.querySelector('.absent')).toBeTruthy();
  });

  it('says when NuGuard scanned the commit rather than the working tree, and only then', () => {
    const { unmount } = renderApp(<NuGuardFindingSection d={finding.nuguard!} />);
    expect(screen.queryByText('What NuGuard scanned')).toBeNull();
    unmount();
    const scanned = 'NuGuard scanned the committed state, not the working tree';
    renderApp(<NuGuardFindingSection d={{ ...finding.nuguard!, scanned }} />);
    expect(screen.getByText('What NuGuard scanned').nextElementSibling!.textContent).toBe(scanned);
  });

  it('lists tools not requested apart from failed ones, with the reason', async () => {
    stub([{ path: '/coverage', body: coverage }]);
    renderApp(<Coverage />);
    const panel = (await screen.findByText('Tools not requested')).closest('section')!;
    expect(panel.textContent).toContain('octo/web');
    expect(panel.textContent).toContain('off for this repository');
    expect(panel.textContent).toContain('nuguard/semgrep');
    expect(panel.textContent).toContain('not offered by the service');
  });

  it("shows each repository's NuGuard options and clip notes on the run page", async () => {
    stub([{ path: '/runs/', body: overview }]);
    renderApp(<RunPage runID={overview.run.id} />);
    const panel = (await screen.findByText('NuGuard in this run')).closest('section')!;
    expect(panel.textContent).toContain('semgrep → left out (not offered by the service)');
    expect(panel.textContent).toContain('AI-SBOM kept');
  });
});

describe('the "found by" filter', () => {
  it('filters on the tool that found a finding, and says it carries no counts', () => {
    const onChange = vi.fn();
    const { state } = parseExplorerState('scope=open');
    renderApp(<FilterPanel state={state} onChange={onChange} />);
    const group = screen.getByText('Found by').closest('fieldset')!;
    expect(group.textContent).toContain('listed, not counted');
    fireEvent.click(within(group).getByLabelText('NuGuard'));
    const next = onChange.mock.calls[0]![0];
    expect(next.found_by).toEqual(['nuguard']);
    expect(apiQuery(next)).toContain('found_by=nuguard');
  });
});
