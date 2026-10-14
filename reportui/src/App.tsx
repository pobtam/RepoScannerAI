/**
 * The application shell.
 *
 * The banner at the top is not decoration. It states which backend is being
 * read and what is DEGRADED in this deployment — an uncalibrated threshold, a
 * missing exploitation feed, seeded demonstration data. A reader who does not
 * know they are looking at demonstration data, or at priorities computed from
 * three of five inputs, will quote a number that does not mean what they think
 * it means.
 */
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { Component, useEffect, useState, type ReactNode } from 'react';
import { api } from './api/client';
import { describeError } from './components/primitives';
import { Explorer } from './features/explorer/Explorer';
import { FindingDetail } from './features/detail/FindingDetail';
import { LatestOverview, RunPage } from './features/runs/Overview';
import { RunComparison, RunHistory } from './features/runs/History';
import { Coverage } from './features/coverage/Coverage';
import { RepoDetail, RepoIndex } from './features/repos/Repos';
import { Waves } from './features/waves/Waves';
import { Reports } from './features/reports/Reports';
import { GitHubPage } from './features/github/GitHub';
import { Link, RouterProvider, match, useRouter } from './lib/router';
import { icons } from './components/icons';

const client = new QueryClient({
  defaultOptions: {
    queries: {
      // A failed query is shown, not retried into silence: the error states
      // say what failed and what to do about it, and three invisible retries
      // just delay that.
      retry: false,
      refetchOnWindowFocus: false,
      staleTime: 15_000,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={client}>
      <RouterProvider>
        <Shell />
      </RouterProvider>
    </QueryClientProvider>
  );
}

/** The navigation, in the order a reader works: what happened, what is
 *  open, whether it was all looked at; then the records behind it. */
const NAV: { heading: string; items: { to: string; label: string; icon: ReactNode; active: (p: string) => boolean }[] }[] = [
  {
    heading: 'Monitor',
    items: [
      { to: '/', label: 'Overview', icon: icons.overview, active: (p) => p === '/' || p === '' },
      { to: '/findings?scope=open', label: 'Findings', icon: icons.findings, active: (p) => p.startsWith('/findings') },
      { to: '/coverage', label: 'Coverage', icon: icons.coverage, active: (p) => p === '/coverage' },
    ],
  },
  {
    heading: 'Explore',
    items: [
      { to: '/repos', label: 'Repositories', icon: icons.repos, active: (p) => p.startsWith('/repos') },
      { to: '/waves', label: 'Waves', icon: icons.waves, active: (p) => p === '/waves' },
    ],
  },
  {
    heading: 'Records',
    items: [
      { to: '/runs', label: 'Run history', icon: icons.history, active: (p) => p.startsWith('/runs') },
      { to: '/reports', label: 'Reports', icon: icons.reports, active: (p) => p === '/reports' },
    ],
  },
  {
    heading: 'Sources',
    items: [{ to: '/github', label: 'GitHub', icon: icons.github, active: (p) => p === '/github' }],
  },
];

function Shell() {
  const { path } = useRouter();
  const [navOpen, setNavOpen] = useState(false);

  // A drawer left open over the page you just chose is in the way.
  useEffect(() => setNavOpen(false), [path]);

  return (
    <div className="app" data-nav={navOpen ? 'open' : 'closed'}>
      <aside className="sidebar" id="sidebar">
        <Link to="/" className="brand">
          <span className="brand-mark">{icons.shield}</span>
          <span>
            Vulnerability
            <span className="brand-sub">report browser</span>
          </span>
        </Link>

        <nav aria-label="Main">
          {NAV.map((section) => (
            <div className="nav-section" key={section.heading}>
              <p className="nav-heading">{section.heading}</p>
              {section.items.map((item) => (
                <Link key={item.to} to={item.to} className="nav-link" current={item.active(path)}>
                  {item.icon}
                  {item.label}
                </Link>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-foot">
          <DeploymentStatus />
          <div className="sidebar-tools">
            <DensityToggle />
            <ThemeToggle />
          </div>
        </div>
      </aside>
      <div className="scrim" onClick={() => setNavOpen(false)} aria-hidden="true" />

      <div className="page">
        <header className="topbar">
          <button
            type="button"
            className="menu-button"
            aria-label="Open navigation"
            aria-controls="sidebar"
            aria-expanded={navOpen}
            onClick={() => setNavOpen((o) => !o)}
          >
            {icons.menu}
          </button>
          <Link to="/" className="brand">
            <span className="brand-mark">{icons.shield}</span>
            <span>Vulnerability</span>
          </Link>
        </header>
        <DemoNotice />
        <main>
          <ErrorBoundary>
            <Routes />
          </ErrorBoundary>
        </main>
        <footer className="footer">
          <p className="small">
            Counts, priorities and coverage figures on these pages are the framework's own — the
            interface computes none of them, so it cannot disagree with a report about the same run.
            Where a figure rests on incomplete inputs the qualification is beside the number, not in
            this footer.
          </p>
        </footer>
      </div>
    </div>
  );
}

function Routes() {
  const { path } = useRouter();

  const fp = match(path, '/findings/:fp');
  if (fp) return <FindingDetail fingerprint={fp} />;
  if (path === '/findings') return <Explorer />;

  if (path === '/runs') return <RunHistory />;
  if (path === '/runs/compare') return <RunComparison />;
  const runID = match(path, '/runs/:id');
  if (runID) return <RunPage runID={runID} />;

  if (path === '/coverage') return <Coverage />;
  if (path === '/waves') return <Waves />;
  if (path === '/reports') return <Reports />;
  if (path === '/github') return <GitHubPage />;

  if (path === '/repos') return <RepoIndex />;
  const repo = match(path, '/repos/:repo*');
  if (repo) return <RepoDetail repo={repo} />;

  if (path === '/' || path === '') return <LatestOverview />;

  return (
    <div className="state state-empty">
      <p>
        <strong>No such view: {path}</strong>
      </p>
      <p className="muted">
        <Link to="/">Start at the latest run</Link>, or{' '}
        <Link to="/findings?scope=open">open the finding explorer</Link>.
      </p>
    </div>
  );
}

/**
 * DensityToggle switches between comfortable and compact rows (VM-UI-F-910's
 * companion in U10).
 *
 * A per-viewer convenience, so it lives in localStorage rather than in the URL:
 * the URL holds what a shared link must reproduce, and someone else's row
 * height is not part of the query. Reading it is wrapped, because a browser
 * with site data blocked throws rather than returning null.
 */
function DensityToggle() {
  const [dense, setDense] = useState(() => {
    try {
      return window.localStorage.getItem('density') === 'dense';
    } catch {
      return false;
    }
  });

  useEffect(() => {
    document.documentElement.dataset.density = dense ? 'dense' : 'comfortable';
    try {
      window.localStorage.setItem('density', dense ? 'dense' : 'comfortable');
    } catch {
      // A viewer with site data blocked keeps the choice for this page only.
    }
  }, [dense]);

  return (
    <button
      type="button"
      className="tool-button"
      onClick={() => setDense((d) => !d)}
      aria-pressed={dense}
      title={dense ? 'Switch to comfortable rows' : 'Switch to compact rows'}
    >
      {icons.rows}
      Compact
    </button>
  );
}

/**
 * ThemeToggle cycles the colour scheme: following the system, light, dark.
 * Like density it is a per-viewer convenience, so it lives in localStorage.
 */
function ThemeToggle() {
  const order = ['system', 'light', 'dark'] as const;
  type Theme = (typeof order)[number];
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const t = window.localStorage.getItem('theme');
      return t === 'light' || t === 'dark' ? t : 'system';
    } catch {
      return 'system';
    }
  });

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'system') delete root.dataset.theme;
    else root.dataset.theme = theme;
    try {
      window.localStorage.setItem('theme', theme);
    } catch {
      // Blocked site data: the choice lasts for this page only.
    }
  }, [theme]);

  const label = theme === 'system' ? 'Auto' : theme === 'light' ? 'Light' : 'Dark';
  return (
    <button
      type="button"
      className="tool-button"
      onClick={() => setTheme((t) => order[(order.indexOf(t) + 1) % order.length] ?? 'system')}
      title={`Colour scheme: ${label}. Click to change.`}
      aria-label={`Colour scheme: ${label}`}
    >
      {icons.theme}
      {label}
    </button>
  );
}

/**
 * DemoNotice and DeploymentStatus say what this deployment cannot do.
 *
 * Demonstration data and an uncalibrated threshold are both facts that change
 * what a number means, and neither is visible in the number itself. Demo data
 * changes EVERY number, so it is a notice across the top of every page; the
 * backend and the degraded inputs sit in the sidebar, always in view, with
 * each qualification also repeated beside the figures it affects.
 */
function useHealth() {
  return useQuery({ queryKey: ['health'], queryFn: api.health, staleTime: 60_000 });
}

function DemoNotice() {
  const q = useHealth();
  if (!q.data?.demo) return null;
  return (
    <div className="notice" role="note">
      <span aria-hidden="true">⚠</span>
      <span>
        <strong>Demonstration data.</strong> Every repository, advisory and credential below is
        fabricated. None of it came from a scanner.
      </span>
    </div>
  );
}

function DeploymentStatus() {
  const q = useHealth();
  if (!q.data) return null;
  const h = q.data;
  const degraded = h.degraded ?? [];
  return (
    <div className="status-card" role="note">
      <div className="status-row">
        <span>Backend</span>
        <span className="pill">
          <span className="pill-dot" aria-hidden="true" />
          {h.backend}
        </span>
      </div>
      {degraded.length > 0 && (
        <details>
          <summary>
            <span className="status-row" style={{ marginTop: 8 }}>
              <span>Provisional inputs</span>
              <span className="pill pill-warn">{degraded.length}</span>
            </span>
          </summary>
          <ul>
            {degraded.map((d) => (
              <li key={d}>{d}</li>
            ))}
          </ul>
          <p className="small" style={{ margin: '6px 0 0' }}>
            Figures that rest on these carry the qualification beside them.
          </p>
        </details>
      )}
    </div>
  );
}

/**
 * ErrorBoundary catches a render failure and says what happened.
 *
 * Specifically it catches the two errors the client THROWS on purpose — a
 * credential in a response, and a response that did not match the schema — so
 * those surface as an explanation rather than as a blank page.
 */
class ErrorBoundary extends Component<{ children: ReactNode }, { error: unknown }> {
  override state = { error: null as unknown };

  static getDerivedStateFromError(error: unknown) {
    return { error };
  }

  override render() {
    if (this.state.error == null) return this.props.children;
    const { title, detail, remedy } = describeError(this.state.error);
    return (
      <div className="state state-error" role="alert">
        <h2>{title}</h2>
        {detail && <pre className="error-detail">{detail}</pre>}
        <p>{remedy}</p>
        <button type="button" onClick={() => this.setState({ error: null })}>
          Try again
        </button>
      </div>
    );
  }
}
