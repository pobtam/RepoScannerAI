/**
 * A small router.
 *
 * The interface's view state lives in the URL (UI-ADR-03), so what a router
 * has to provide here is narrow: the current path and search, a way to change
 * them without a reload, and links that respect the back button. The UI
 * specification names TanStack Router for its typed search parameters; the
 * typing is provided here by the Zod schema in view-state.ts, which is also
 * what validates a pasted link — so the benefit is kept without a second
 * source of route truth or a generated route tree.
 *
 * Recorded as a deviation in BUILD-LOG.md rather than made silently.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

export interface Location {
  path: string;
  search: string;
}

interface RouterValue extends Location {
  navigate: (to: string, opts?: { replace?: boolean }) => void;
}

const RouterContext = createContext<RouterValue | null>(null);

function current(): Location {
  return { path: window.location.pathname || '/', search: window.location.search };
}

export function RouterProvider({ children }: { children: ReactNode }) {
  const [loc, setLoc] = useState<Location>(current);

  useEffect(() => {
    const onPop = () => setLoc(current());
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const navigate = useCallback((to: string, opts?: { replace?: boolean }) => {
    const url = new URL(to, window.location.origin);
    if (opts?.replace) {
      window.history.replaceState(null, '', url);
    } else {
      window.history.pushState(null, '', url);
    }
    setLoc({ path: url.pathname, search: url.search });
  }, []);

  const value = useMemo<RouterValue>(() => ({ ...loc, navigate }), [loc, navigate]);
  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
}

export function useRouter(): RouterValue {
  const value = useContext(RouterContext);
  if (!value) throw new Error('useRouter outside a RouterProvider');
  return value;
}

/** Link navigates without a reload, and is a real anchor so it can be opened
 *  in a new tab, copied, and reached by keyboard (VM-UI-F-907). */
export function Link({
  to,
  children,
  className,
  title,
  current,
}: {
  to: string;
  children: ReactNode;
  className?: string;
  title?: string;
  /** Marks the link as the page being shown, for assistive technology as
   *  well as for the eye (WCAG 2.4.8). */
  current?: boolean;
}) {
  const { navigate } = useRouter();
  return (
    <a
      href={to}
      className={className}
      title={title}
      aria-current={current ? 'page' : undefined}
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
        e.preventDefault();
        navigate(to);
      }}
    >
      {children}
    </a>
  );
}

/** match returns the path parameter for a single-segment pattern like
 *  `/findings/:fp`, or null. */
export function match(path: string, pattern: string): string | null {
  const p = pattern.split('/').filter(Boolean);
  const a = path.split('/').filter(Boolean);
  if (p.length === 0) return null;
  // A repository name contains a slash, so a trailing parameter captures the
  // remainder rather than one segment.
  const isRest = p[p.length - 1]?.startsWith(':') && p[p.length - 1]?.endsWith('*');
  if (!isRest && a.length !== p.length) return null;
  if (isRest && a.length < p.length) return null;

  let captured: string | null = null;
  for (let i = 0; i < p.length; i++) {
    const seg = p[i]!;
    if (seg.startsWith(':')) {
      captured = seg.endsWith('*') ? a.slice(i).join('/') : (a[i] ?? null);
      continue;
    }
    if (seg !== a[i]) return null;
  }
  return captured;
}
