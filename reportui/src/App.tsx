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
import { Link, RouterProvider, match, useRouter } from './lib/router';

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

function Shell() {
  return (
    <>
      <DeploymentBanner />
      <header className="masthead">
        <h1>
          <Link to="/">Vulnerability report browser</Link>
        </h1>
        <DensityToggle />
        <nav aria-label="Main">
          <Link to="/">Latest run</Link>
          <Link to="/findings?scope=open">Findings</Link>
          <Link to="/coverage">Coverage</Link>
          <Link to="/runs">History</Link>
          <Link to="/repos">Repositories</Link>
          <Link to="/waves">Waves</Link>
          <Link to="/reports">Reports</Link>
        </nav>
      </header>
      <main>
        <ErrorBoundary>
          <Routes />
        </ErrorBoundary>
      </main>
      <footer className="footer">
        <p className="muted small">
          Counts, priorities and coverage figures on these pages are the framework's own — the
          interface computes none of them, so it cannot disagree with a report about the same run.
          Where a figure rests on incomplete inputs the qualification is beside the number, not in
          this footer.
        </p>
      </footer>
    </>
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
      className="link-button density"
      onClick={() => setDense((d) => !d)}
      aria-pressed={dense}
    >
      {dense ? 'Comfortable rows' : 'Compact rows'}
    </button>
  );
}

/**
 * DeploymentBanner says what this deployment cannot do.
 *
 * Demonstration data and an uncalibrated threshold are both facts that change
 * what a number means, and neither is visible in the number itself.
 */
function DeploymentBanner() {
  const q = useQuery({ queryKey: ['health'], queryFn: api.health, staleTime: 60_000 });
  if (!q.data) return null;
  const h = q.data;
  return (
    <div className={`banner${h.demo ? ' banner-demo' : ''}`} role="note">
      {h.demo && (
        <strong>
          DEMONSTRATION DATA — every repository, advisory and credential below is fabricated. None
          of it came from a scanner.{' '}
        </strong>
      )}
      <span>
        Reading the <strong>{h.backend}</strong> backend.
      </span>
      {h.degraded && h.degraded.length > 0 && (
        <span>
          {' '}
          Degraded in this deployment: {h.degraded.join('; ')}. Figures that rest on those inputs
          carry the qualification beside them.
        </span>
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
