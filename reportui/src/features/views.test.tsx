/**
 * The remaining views, tested against the captured API payloads.
 *
 * Each assertion is a way the interface could mislead while looking correct:
 * a historical run rendered from live state, a partial run shown as a dip, a
 * never-scanned repository shown as fresh, a wave whose depend and reach
 * counts have been merged into one reassuring number.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/dom';
import { waitFor } from '@testing-library/react';
import { renderApp, stubApi } from '../test-utils';
import { FindingDetail } from './detail/FindingDetail';
import { LatestOverview, RunPage } from './runs/Overview';
import { Coverage } from './coverage/Coverage';
import { RepoIndex } from './repos/Repos';
import { Waves } from './waves/Waves';
import { Reports } from './reports/Reports';
import { RunHistory } from './runs/History';
import finding from '../test-fixtures/finding.json';
import blockedFinding from '../test-fixtures/blocked-finding.json';
import timeline from '../test-fixtures/timeline.json';
import timelineGap from '../test-fixtures/timeline-gap.json';
import findingGap from '../test-fixtures/finding-gap.json';
import attempts from '../test-fixtures/attempts.json';
import overviewLatest from '../test-fixtures/overview-latest.json';
import overviewSnapshot from '../test-fixtures/overview-snapshot.json';
import coverage from '../test-fixtures/coverage.json';
import repos from '../test-fixtures/repos.json';
import waves from '../test-fixtures/waves.json';
import runs from '../test-fixtures/runs.json';
import trend from '../test-fixtures/trend.json';
import reports from '../test-fixtures/reports.json';
import type {
  CoverageView,
  Finding,
  Overview as OverviewData,
  RepoSummary,
  RunPage as RunPageData,
  Wave,
} from '../api/schemas';

// The fixtures, typed as the schemas rather than as their own literal shapes.
// A JSON import's inferred type is narrower than the API's contract — an
// absent optional field becomes `never` — and a test written against the
// narrow type would fail to compile the moment it varied one.
const fixtures = {
  finding: finding as unknown as Finding,
  blocked: blockedFinding as unknown as Finding,
  gap: findingGap as unknown as Finding,
  latest: overviewLatest as unknown as OverviewData,
  snapshot: overviewSnapshot as unknown as OverviewData,
  coverage: coverage as unknown as CoverageView,
  repos: repos as unknown as RepoSummary[],
  waves: waves as unknown as Wave[],
  runs: runs as unknown as RunPageData,
};

afterEach(() => vi.unstubAllGlobals());

describe('the finding detail (U2)', () => {
  function renderDetail(f: Finding = fixtures.finding) {
    stubApi([['/timeline', timeline], ['/attempts', attempts], ['/findings/', f]]);
    return renderApp(<FindingDetail fingerprint={f.fingerprint} />);
  }

  it('says what the problem is, and whose words those are', async () => {
    renderDetail();
    const section = await screen.findByRole('region', { name: 'Description' });
    expect(section.textContent).toContain(fixtures.finding.description!);
    // The demonstration pipeline records no scanner text, so the server built
    // this one, and the page says so rather than passing it off as a tool's.
    expect(fixtures.finding.description_source).toBe('derived');
    expect(section.textContent).toContain('no scanner supplied a description');
  });

  it("credits a scanner's description to the scanner", async () => {
    renderDetail({ ...fixtures.finding, description: 'Potential file inclusion via variable', description_source: 'gosec' });
    const section = await screen.findByRole('region', { name: 'Description' });
    expect(section.textContent).toContain('Potential file inclusion via variable');
    expect(section.textContent).toContain('In the words of gosec.');
  });

  it('explains every absent field rather than leaving a blank', async () => {
    renderDetail();
    await waitFor(() => expect(document.querySelectorAll('.record').length).toBeGreaterThan(1));

    const absents = [...document.querySelectorAll('.absent')];
    expect(absents.length).toBeGreaterThan(0);
    for (const el of absents) {
      // Every absence carries WHY it is absent. A blank cell is
      // indistinguishable from a value nobody has produced.
      const why = el.getAttribute('title') ?? el.textContent ?? '';
      expect(why.length, `an absent value with no explanation: ${el.outerHTML}`).toBeGreaterThan(3);
    }
  });

  it('records that no pinned tool reports the enclosing symbol', async () => {
    renderDetail();
    await waitFor(() => expect(screen.getByText('Package / function')).toBeTruthy());
    const dd = screen.getByText('Package / function').nextElementSibling!;
    expect(dd.textContent).toContain('—');
    expect(dd.querySelector('.absent')!.getAttribute('title')).toContain('OQ-AUDIT-02');
  });

  it('shows the score as an argument, not just a band (VM-UI-F-510)', async () => {
    renderDetail();
    await waitFor(() => expect(document.querySelector('.score-table')).toBeTruthy());
    const table = document.querySelector('.score-table')!;
    for (const row of ['base', 'reachability', 'dependency class', 'repository tier']) {
      expect(table.textContent).toContain(row);
    }
    expect(document.querySelector('.score')!.textContent).toMatch(/of 5 declared inputs/);
  });

  it('shows the observation history INCLUDING runs that did not see it', async () => {
    // A finding the most recent run did not observe. A fixture where every
    // run saw the finding cannot show a gap, and the gap is the interesting
    // half (VM-UI-F-503).
    stubApi([['/timeline', timelineGap], ['/attempts', attempts], ['/findings/', findingGap]]);
    renderApp(<FindingDetail fingerprint={fixtures.gap.fingerprint} />);

    await waitFor(() => expect(document.querySelector('.observations')).toBeTruthy());
    const rows = [...document.querySelectorAll('.observations tbody tr')];
    expect(rows.length).toBeGreaterThan(1);

    const missed = rows.filter((r) => r.classList.contains('not-observed'));
    expect(missed.length, 'no run is shown as having missed this finding').toBeGreaterThan(0);
    // And the row says what the miss MEANS: a scan that did not qualify says
    // nothing about the finding (VM-ADR-12).
    expect(missed[0]!.textContent).toMatch(/did not qualify|complete scan did not observe/);
  });

  it('links a blocked consumer to the upstream finding it waits on', async () => {
    renderDetail(fixtures.blocked);
    await waitFor(() => expect(document.querySelector('.links')).toBeTruthy());
    const item = [...document.querySelectorAll('.links li')].find((li) =>
      li.textContent?.startsWith('Upstream finding'),
    );
    expect(item, 'the detail does not mention the upstream finding at all').toBeTruthy();
    if (fixtures.blocked.refs.upstream_finding) {
      expect(item!.querySelector('a')).toBeTruthy();
    } else {
      expect(item!.querySelector('.absent')).toBeTruthy();
    }
  });
});

describe('the run overview (U3)', () => {
  it('says when its figures are LIVE rather than a snapshot (VM-UI-F-424)', async () => {
    stubApi([['/runs/latest', overviewLatest]]);
    renderApp(<LatestOverview />);
    await waitFor(() => expect(document.querySelector('.overview')).toBeTruthy());

    if (fixtures.latest.live) {
      expect(screen.getByText(/These figures are live, not a snapshot/)).toBeTruthy();
      expect(document.body.textContent).toContain(fixtures.latest.live_note!.slice(0, 40));
    }
  });

  it('says when its figures come from an immutable snapshot, with the hash', async () => {
    stubApi([['/runs/', overviewSnapshot]]);
    renderApp(<RunPage runID={overviewSnapshot.run.id} />);
    await waitFor(() => expect(document.querySelector('.overview')).toBeTruthy());

    expect(fixtures.snapshot.live).toBe(false);
    const note = document.querySelector('.snapshot-note')!;
    expect(note.textContent).toContain('immutable report');
    expect(note.textContent).toContain(fixtures.snapshot.content_hash!.slice(0, 16));
  });

  it('puts coverage above the findings and warns when it is short (VM-UI-F-206)', async () => {
    stubApi([['/runs/latest', overviewLatest]]);
    renderApp(<LatestOverview />);
    await waitFor(() => expect(document.querySelectorAll('.panel h2').length).toBeGreaterThan(2));

    const panels = [...document.querySelectorAll('.panel h2')].map((h) => h.textContent);
    const coverageAt = panels.indexOf('Coverage');
    const findingsAt = panels.indexOf('Findings');
    expect(coverageAt).toBeGreaterThan(-1);
    expect(findingsAt).toBeGreaterThan(-1);
    // A repository nobody scanned is more urgent than a repository with
    // findings, and burying it below the counts is how a fleet convinces
    // itself it is clean.
    expect(coverageAt).toBeLessThan(findingsAt);
  });

  it('marks a run that did not cover the fleet', async () => {
    const partial = structuredClone(fixtures.latest);
    partial.run.partial = true;
    partial.run.partial_note = '2 of 6 repositories produced no qualifying scan';
    stubApi([['/runs/latest', partial]]);
    renderApp(<LatestOverview />);
    await waitFor(() => expect(screen.getByText(/This run did not cover the fleet/)).toBeTruthy());
    expect(document.body.textContent).toContain('lower than the fleet');
  });

  it('never presents "no longer observed" as fixed', async () => {
    stubApi([['/runs/latest', overviewLatest]]);
    renderApp(<LatestOverview />);
    await waitFor(() => expect(document.querySelector('.overview')).toBeTruthy());
    const body = document.body.textContent ?? '';
    expect(body).toContain('No longer observed');
    // The word "fixed" must not be used for a finding that merely stopped
    // being observed (VM-ADR-12).
    expect(body).not.toMatch(/\bFixed\b/);
  });
});

describe('the coverage view', () => {
  it('states that a failed scan and a clean scan are indistinguishable', async () => {
    stubApi([['/coverage', coverage]]);
    renderApp(<Coverage />);
    await waitFor(() => expect(screen.getByText(/indistinguishable/)).toBeTruthy());
  });

  it('renders a never-scanned repository as never scanned, not as zero hours', async () => {
    const view = structuredClone(fixtures.coverage);
    view.gaps[0]!.never_scanned = true;
    view.gaps[0]!.hours_without_data = 0;
    stubApi([['/coverage', view]]);
    renderApp(<Coverage />);
    await waitFor(() => expect(document.querySelector('.gaps')).toBeTruthy());
    const marker = [...document.querySelectorAll('.gaps .warn-text')].find(
      (el) => el.textContent === 'never scanned',
    );
    expect(marker, 'a never-scanned repository is not marked as such in the gaps table').toBeTruthy();
    expect(marker!.getAttribute('title')).toContain('NEVER');
    // And no zero-hour figure stands in for an age that does not exist.
    expect(marker!.closest('td')!.textContent).not.toContain('0h');
  });

  it('names the owner of each gap, because platform and repository causes route differently', async () => {
    stubApi([['/coverage', coverage]]);
    renderApp(<Coverage />);
    await waitFor(() => expect(document.querySelector('.gaps')).toBeTruthy());
    const rows = [...document.querySelectorAll('.gaps tbody tr')];
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      const owner = row.children[5]!;
      expect(owner.textContent!.length).toBeGreaterThan(0);
    }
  });

  it('says which signals survived a partial gap', async () => {
    stubApi([['/coverage', coverage]]);
    renderApp(<Coverage />);
    await waitFor(() => expect(document.querySelector('.gaps')).toBeTruthy());
    const partial = fixtures.coverage.gaps.find((g) => g.classification === 'partial');
    if (partial) {
      expect(document.body.textContent).toContain(partial.tools_ok![0]!);
      expect(document.body.textContent).toContain(partial.tools_failed![0]!);
    }
  });
});

describe('the repository index', () => {
  it('shows a repository with no test suite prominently (VM-UI-F-607)', async () => {
    stubApi([['/repos', repos]]);
    renderApp(<RepoIndex />);
    await waitFor(() => expect(document.querySelector('.repos')).toBeTruthy());
    const without = fixtures.repos.filter((r) => !r.has_test_suite);
    expect(without.length).toBeGreaterThan(0);
    const cells = screen.getAllByText('none');
    expect(cells.length).toBeGreaterThan(0);
    expect(cells[0]!.getAttribute('title')).toContain('verified');
  });
});

describe('the wave view (U7)', () => {
  it('keeps depend and reach as separate adjacent figures (VM-UI-F-708)', async () => {
    stubApi([['/waves', waves]]);
    renderApp(<Waves />);
    await waitFor(() => expect(screen.getByText('depend on it')).toBeTruthy());
    expect(screen.getByText('reach the vulnerable code')).toBeTruthy();
    const labels = [...document.querySelectorAll('.figures .figure-label')].map((el) => el.textContent);
    expect(labels).toContain('depend on it');
    expect(labels).toContain('reach the vulnerable code');
    expect(labels).toContain('undetermined');
  });

  it('shows an excluded consumer within the wave, with its reason', async () => {
    stubApi([['/waves', waves]]);
    renderApp(<Waves />);
    await waitFor(() => expect(document.querySelector('.consumers')).toBeTruthy());
    const excluded = fixtures.waves[0]!.consumers.filter((c) => c.excluded);
    if (excluded.length > 0) {
      expect(document.querySelectorAll('tr.excluded').length).toBe(excluded.length);
      expect(document.body.textContent).toContain('excluded —');
    }
  });

  it('calls out the publication step when the trigger is a tag (VM-UI-F-705)', async () => {
    stubApi([['/waves', waves]]);
    renderApp(<Waves />);
    await waitFor(() => expect(document.querySelector('.steps')).toBeTruthy());
    if (fixtures.waves[0]!.trigger === 'tag') {
      expect(document.querySelector('.steps')!.textContent).toContain('TAG');
    }
  });

  it('draws the relationship as a graph with a text alternative (VM-UI-F-706)', async () => {
    stubApi([['/waves', waves]]);
    renderApp(<Waves />);
    await waitFor(() => expect(document.querySelector('.wave-graph')).toBeTruthy());
    const svg = document.querySelector('.wave-graph')!;
    expect(svg.getAttribute('role')).toBe('img');
    expect(svg.getAttribute('aria-label')).toContain(fixtures.waves[0]!.owner_repo);
  });
});

describe('the run history and trends (U4)', () => {
  it('labels the run kind and marks partial runs and scanner changes', async () => {
    stubApi([['/metrics/trends', trend], ['/runs', runs]]);
    renderApp(<RunHistory />);
    await waitFor(() => expect(document.querySelector('.legend')).toBeTruthy());
    const legend = document.querySelector('.legend')!.textContent ?? '';
    expect(legend).toContain('scanner image changed');
    expect(legend).toContain('did not cover the fleet');
    expect(legend).toContain(trend.kind);
  });

  it('marks a partial run in the run list', async () => {
    stubApi([['/metrics/trends', trend], ['/runs', runs]]);
    renderApp(<RunHistory />);
    await waitFor(() => expect(document.querySelector('.runs')).toBeTruthy());
    const partials = fixtures.runs.runs.filter((r) => r.partial);
    if (partials.length > 0) {
      expect(document.querySelectorAll('tr.partial').length).toBe(partials.length);
    }
  });
});

describe('issued reports (U9)', () => {
  it('offers no live report and shows every hash', async () => {
    stubApi([['/reports', reports]]);
    renderApp(<Reports />);
    await waitFor(() => expect(document.querySelector('.reports')).toBeTruthy());
    expect(document.body.textContent).toContain('There is no "current" or "live" report here');
    for (const r of reports) {
      expect(document.body.textContent).toContain(r.content_hash.slice(0, 16));
      expect(document.body.textContent).toContain(r.anchor_run_id);
    }
  });

  // VM-UI-F-1108. Both reports visible, the relationship stated on BOTH, and
  // the superseded one not deleted.
  it('states the supersession on both reports and keeps the superseded one', async () => {
    stubApi([['/reports', reports]]);
    renderApp(<Reports />);
    await waitFor(() => expect(document.querySelector('.reports')).toBeTruthy());

    const replacement = reports.find((r) => r.supersedes != null)!;
    const superseded = reports.find((r) => r.superseded_by != null)!;
    const text = document.body.textContent ?? '';

    // The superseded report is still listed. VM-UI-F-1108 is explicit that it
    // is never deleted: a corrected figure only means something beside the
    // figure it corrected.
    expect(text).toContain(superseded.id);
    expect(text).toContain(superseded.content_hash.slice(0, 16));

    // Stated in both directions. The backwards one matters most: somebody
    // who arrives from a quoted identifier is holding the OLD one, and
    // nothing else on the row would tell them the figure had moved.
    expect(text).toContain('superseded by');
    expect(text).toContain(replacement.id);
    expect(text).toContain('replaces');
    expect(text).toContain(superseded.id);
  });

  // Assert-the-negative: a report in no lineage must not claim one. A column
  // that always says something is one a reader stops looking at.
  it('says nothing about lineage for a report in none', async () => {
    const plain = reports.filter((r) => r.supersedes == null && r.superseded_by == null);
    expect(plain.length).toBeGreaterThan(0);

    stubApi([['/reports', plain]]);
    renderApp(<Reports />);
    await waitFor(() => expect(document.querySelector('.reports')).toBeTruthy());

    const text = document.body.textContent ?? '';
    expect(text).not.toContain('superseded by');
    expect(text).not.toContain('replaces ');

    // And it says so positively, once per row. An empty cell would read as
    // "we did not look", which is the distinction this whole interface is
    // built on: a report in no lineage is a FACT, not a missing value.
    //
    // Asserted on the cell rather than on the page's text, because the
    // paragraph above the table also contains the word "current" and would
    // satisfy a text match whether or not anything was rendered.
    expect(document.querySelectorAll('.lineage-current')).toHaveLength(plain.length);
  });
});
