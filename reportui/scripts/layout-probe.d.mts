/**
 * Types for the probe harness.
 *
 * Hand-written because the harness is a .mjs script: it runs esbuild and
 * drives Chrome, which are Node concerns rather than application ones, and
 * putting it through the application's build to obtain types would mean
 * bundling a bundler.
 */
export declare function findBrowser(): string | null;

/**
 * probeLayout bundles a probe entry and measures it in headless Chrome.
 *
 * The return is `unknown` on purpose: it crosses a process boundary as a DOM
 * dump, so the caller has to narrow it rather than trust a shape this
 * signature claims.
 */
export declare function probeLayout(entry?: string): unknown;
