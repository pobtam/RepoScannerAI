/**
 * Test helpers.
 *
 * Every view is rendered against the CAPTURED API fixtures (src/test-fixtures),
 * which came from the real server over the demonstration pipeline. Nothing here
 * constructs a payload: a hand-built one can contain a field the API never
 * sends and omit one it always does, and a test over it proves the fixture.
 */
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, type RenderResult } from '@testing-library/react';
import type { ReactElement } from 'react';
import { vi } from 'vitest';
import { RouterProvider } from './lib/router';

/**
 * routes pairs a URL fragment with the fixture that request should answer
 * with, tried IN ORDER.
 *
 * In order rather than by longest match, because `/findings/` is a prefix of
 * `/findings/{fp}/timeline` and a length rule silently answers a timeline
 * request with a finding — which then fails schema validation and leaves the
 * test looking at an error state it did not intend.
 */
export type Routes = [string, unknown][];

/**
 * stubApi answers fetch from a table of fixtures.
 *
 * A request no route matches FAILS the test rather than returning an empty
 * object: a silent empty answer is how a view comes to be tested against
 * nothing at all.
 */
export function stubApi(routes: Routes) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const hit = routes.find(([fragment]) => url.includes(fragment));
      if (!hit) {
        throw new Error(
          `no fixture for ${url}. Add one to the routes table rather than letting the view ` +
            `render against nothing.`,
        );
      }
      return new Response(JSON.stringify(hit[1]), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }),
  );
}

export function renderApp(ui: ReactElement, path = '/'): RenderResult {
  window.history.replaceState(null, '', path);
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={client}>
      <RouterProvider>{ui}</RouterProvider>
    </QueryClientProvider>,
  );
}
