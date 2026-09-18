/**
 * The URL is the view state (VM-UI-F-401, UI-ADR-03).
 *
 * The round-trip property is what makes a filtered view shareable: a link
 * someone pastes has to produce the same list it produced for the person who
 * copied it. The cursor rules are what stop a shared link from resuming in the
 * middle of a different result set.
 */
import { describe, expect, it } from 'vitest';
import {
  activeFilters,
  apiQuery,
  clearAll,
  parseExplorerState,
  serialiseExplorerState,
  setFlag,
  toggle,
} from './view-state';

describe('round-tripping through the URL', () => {
  it('survives a parse and a serialise unchanged', () => {
    const search =
      '?scope=all&repo=demo-org%2Fpayments-api%2Cdemo-org%2Fedge-proxy&category=dependency' +
      '&severity=CRITICAL%2CHIGH&reachable=unknown&notReobserved=true&q=CVE-DEMO&sort=severity&dir=asc&limit=25';
    const { state, dropped } = parseExplorerState(search);
    expect(dropped).toEqual([]);

    const rendered = serialiseExplorerState(state);
    const second = parseExplorerState(rendered);
    expect(second.state).toEqual(state);
  });

  it('leaves defaults out of the URL, so a shared link is readable', () => {
    const { state } = parseExplorerState('');
    expect(serialiseExplorerState(state)).toBe('');
    expect(state.scope).toBe('open');
    expect(state.sort).toBe('priority');
    expect(state.dir).toBe('desc');
  });

  it('defaults the corpus to unresolved across ALL runs, not the latest run', () => {
    // VM-UI-F-411: the latter hides everything the most recent sweep did not
    // re-observe, which is the failure mode the whole interface exists to
    // prevent.
    const { state } = parseExplorerState('');
    expect(state.scope).toBe('open');
    expect(state.run).toBeUndefined();
  });

  it('drops a parameter it cannot understand AND names it', () => {
    const { state, dropped } = parseExplorerState('?scope=all&sort=whenever&severity=HIGH');
    expect(dropped).toContain('sort');
    expect(state.sort).toBe('priority');
    // The rest of the link survives: dropping everything because one
    // parameter was wrong would lose the reader's whole query.
    expect(state.severity).toEqual(['HIGH']);
    expect(state.scope).toBe('all');
  });

  it('always sends the corpus to the API, even at its default', () => {
    const { state } = parseExplorerState('');
    expect(apiQuery(state)).toContain('scope=open');
  });

  it('repeats multi-select values as separate parameters for the API', () => {
    const { state } = parseExplorerState('?repo=a,b&category=code,secret');
    const query = apiQuery(state);
    expect(query).toContain('repo=a&repo=b');
    expect(query).toContain('category=code&category=secret');
  });
});

describe('the cursor', () => {
  it('is dropped when a filter changes', () => {
    const { state } = parseExplorerState('?scope=open&cursor=abc123');
    expect(state.cursor).toBe('abc123');
    // A cursor names a position in a PARTICULAR result set. Keeping it across
    // a filter change resumes in the middle of a list the reader is no longer
    // looking at, and the page looks ordinary.
    expect(toggle(state, 'severity', 'HIGH').cursor).toBeUndefined();
    expect(setFlag(state, 'hasPR', 'true').cursor).toBeUndefined();
  });

  it('survives when nothing else changes', () => {
    const { state } = parseExplorerState('?scope=open&cursor=abc123');
    expect(serialiseExplorerState(state)).toContain('cursor=abc123');
  });
});

describe('filter manipulation', () => {
  it('toggles a value in and out of a dimension', () => {
    const { state } = parseExplorerState('?severity=HIGH');
    const added = toggle(state, 'severity', 'CRITICAL');
    expect(added.severity).toEqual(['HIGH', 'CRITICAL']);
    const removed = toggle(added, 'severity', 'HIGH');
    expect(removed.severity).toEqual(['CRITICAL']);
    const emptied = toggle(removed, 'severity', 'CRITICAL');
    expect(emptied.severity).toBeUndefined();
  });

  it('lists the active filters for removal, including the flags and the text', () => {
    const { state } = parseExplorerState('?severity=HIGH&hasPR=true&q=crypto');
    const active = activeFilters(state);
    expect(active.map((a) => a.label)).toEqual([
      'severity: HIGH',
      'hasPR is true',
      'text: crypto',
    ]);
  });

  it('clearing all keeps the corpus and the ordering', () => {
    const { state } = parseExplorerState('?scope=all&severity=HIGH&sort=repo&dir=asc');
    const cleared = clearAll(state);
    expect(cleared.severity).toBeUndefined();
    expect(cleared.scope).toBe('all');
    expect(cleared.sort).toBe('repo');
    expect(cleared.dir).toBe('asc');
  });
});

describe('the tri-state flags', () => {
  it('distinguishes unset from false', () => {
    const { state } = parseExplorerState('');
    expect(state.hasPR).toBeUndefined();
    expect(apiQuery(state)).not.toContain('hasPR');

    const no = setFlag(state, 'hasPR', 'false');
    expect(apiQuery(no)).toContain('hasPR=false');

    const cleared = setFlag(no, 'hasPR', undefined);
    expect(apiQuery(cleared)).not.toContain('hasPR');
  });
});
