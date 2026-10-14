/**
 * The shell: the sidebar marks where you are, says what this deployment is
 * reading and what it cannot do, and the per-viewer switches take effect.
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { Explorer } from './features/explorer/Explorer';
import { renderApp, stubApi } from './test-utils';
import health from './test-fixtures/health.json';
import repos from './test-fixtures/repos.json';
import facets from './test-fixtures/facets.json';
import page from './test-fixtures/findings-page.json';

// Node 25 defines a global localStorage of its own that shadows jsdom's and
// lacks most of the Storage interface. The shell keeps its preferences there,
// so these tests supply a working in-memory Storage explicitly.
function memoryStorage(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k) => m.get(k) ?? null,
    key: (i) => [...m.keys()][i] ?? null,
    removeItem: (k) => void m.delete(k),
    setItem: (k, v) => void m.set(k, String(v)),
  };
}

beforeEach(() => {
  vi.stubGlobal('localStorage', memoryStorage());
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  delete document.documentElement.dataset.theme;
});

function renderShellAt(path: string) {
  stubApi([
    ['/health', health],
    ['/repos', repos],
  ]);
  window.history.replaceState(null, '', path);
  return render(<App />);
}

describe('the sidebar', () => {
  it('marks the page being shown, and only that page', async () => {
    renderShellAt('/repos');
    const nav = screen.getByRole('navigation', { name: 'Main' });
    const current = nav.querySelectorAll('[aria-current="page"]');
    expect(current).toHaveLength(1);
    expect(current[0]?.textContent).toContain('Repositories');
    expect(screen.getByRole('link', { name: /Findings/ }).getAttribute('aria-current')).toBeNull();
  });

  it('says which backend it reads and how many inputs are provisional', async () => {
    renderShellAt('/repos');
    await waitFor(() => expect(screen.getByText('memory')).toBeTruthy());
    expect(screen.getByText('Provisional inputs')).toBeTruthy();
    for (const d of health.degraded) {
      expect(screen.getByText(d)).toBeTruthy();
    }
  });

  it('puts demonstration data in a notice across the page, not only in the sidebar', async () => {
    renderShellAt('/repos');
    await waitFor(() => expect(screen.getByText(/Demonstration data\./)).toBeTruthy());
    expect(screen.getByText(/Demonstration data\./).closest('.notice')).toBeTruthy();
  });

  it('cycles the colour scheme through system, light and dark, and remembers it', async () => {
    renderShellAt('/repos');
    const toggle = screen.getByRole('button', { name: /Colour scheme/ });
    expect(document.documentElement.dataset.theme).toBeUndefined();
    fireEvent.click(toggle);
    expect(document.documentElement.dataset.theme).toBe('light');
    fireEvent.click(toggle);
    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(localStorage.getItem('theme')).toBe('dark');
    fireEvent.click(toggle);
    expect(document.documentElement.dataset.theme).toBeUndefined();
  });

  it('opens and closes the drawer on narrow screens from the menu button', async () => {
    const { container } = renderShellAt('/repos');
    const app = container.querySelector('.app')!;
    const menu = screen.getByRole('button', { name: 'Open navigation' });
    expect(app.getAttribute('data-nav')).toBe('closed');
    fireEvent.click(menu);
    expect(app.getAttribute('data-nav')).toBe('open');
    expect(menu.getAttribute('aria-expanded')).toBe('true');
  });
});

describe('the explorer filter panel', () => {
  it('can be hidden to give the table its width, and keeps the filters in force', async () => {
    stubApi([
      ['/findings/facets', facets],
      ['/findings', page],
    ]);
    renderApp(<Explorer />, '/findings?scope=open&severity=HIGH');
    await waitFor(() => expect(document.querySelectorAll('.row').length).toBeGreaterThan(0));
    expect(screen.getByRole('complementary', { name: 'Filters' })).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Hide filters' }));
    expect(screen.queryByRole('complementary', { name: 'Filters' })).toBeNull();
    // Hiding the panel is a view preference, not a change of query.
    expect(window.location.search).toContain('severity=HIGH');
    expect(localStorage.getItem('explorer.filters')).toBe('hidden');

    fireEvent.click(screen.getByRole('button', { name: 'Show filters' }));
    expect(screen.getByRole('complementary', { name: 'Filters' })).toBeTruthy();
  });
});
