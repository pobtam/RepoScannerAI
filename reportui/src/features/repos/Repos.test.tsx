import { describe, expect, it, afterEach, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { renderApp, stubApi } from '../../test-utils';
import { RepoDetail } from './Repos';
import repoDetail from '../../test-fixtures/repo-detail.json';
import repoTrend from '../../test-fixtures/repo-trend.json';
import health from '../../test-fixtures/health.json';

afterEach(() => vi.unstubAllGlobals());

const repo = 'demo-org/checkout-web';

function render(detail: unknown) {
  // The trend first: its path contains the repository's.
  stubApi([
    [`/repos/${repo}/trend`, repoTrend],
    [`/repos/${repo}`, detail],
    ['/health', health],
  ]);
  renderApp(<RepoDetail repo={repo} />);
}

async function aiPanel() {
  await waitFor(() => expect(screen.getByText('AI components detected')).toBeTruthy());
  return screen.getByText('AI components detected').closest('section')!;
}

describe('AI components on the repository page', () => {
  // The fixture is the demonstration's own answer: NuGuard is not configured.
  it('says "not measured" in words, and shows no count', async () => {
    render(repoDetail);
    const panel = await aiPanel();
    expect(panel.textContent).toContain('not measured');
    expect(panel.textContent).toContain('Not measured is not none');
    expect(within(panel).queryByText('Components')).toBeNull();
  });

  it('shows a measured inventory as a signal, with its source', async () => {
    render({
      ...repoDetail,
      ai_components: {
        measured: true,
        note: "an inventory signal, not findings: what nuguard 0.9.15 found of this repository's AI use",
        run_id: 'S-000006',
        source: 'nuguard 0.9.15',
        rulepack_sha256: '397fd47bbc1b3313c3c8ac22e482c72edf3eda16046a3fc3b1e2d009ed97161b',
        node_counts: { MODEL: 2, AGENT: 1, API_ENDPOINT: 9 },
        edge_count: 16,
        frameworks: ['LangChain.js'],
        model_providers: ['openai'],
        posture_observations: { 'NGA-001': 11, 'ATLAS-NC-001': 1 },
      },
    });
    const panel = await aiPanel();
    expect(panel.textContent).toContain('1 agent · 9 api endpoint · 2 model');
    expect(panel.textContent).toContain('openai');
    expect(panel.textContent).toContain('12 across 2 rules, counted and not reported as findings');
    expect(panel.textContent).toContain('not findings');
    expect(panel.textContent).toContain('rule pack 397fd47bbc1b');
    expect(within(panel).getByRole('link', { name: 'run S-000006' })).toBeTruthy();
  });

  it('says posture was not requested rather than showing zero', async () => {
    render({
      ...repoDetail,
      ai_components: {
        measured: true, note: 'an inventory signal, not findings', source: 'nuguard 0.9.15',
        node_counts: {}, edge_count: 0, frameworks: [], model_providers: [],
      },
    });
    const panel = await aiPanel();
    expect(panel.textContent).toContain('none found');
    expect(panel.querySelector('.absent')!.getAttribute('title')).toContain('posture was not requested');
  });
});
