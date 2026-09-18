/** Types for the layout probe, which is plain JavaScript so it can be run
 *  directly with node as well as from the test. */
export declare function findBrowser(): string | null;
export declare function probeLayout(): Record<string, unknown> & { skipped?: string };
