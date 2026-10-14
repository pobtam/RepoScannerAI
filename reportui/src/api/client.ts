/**
 * The API client.
 *
 * Three things happen to every response before any component sees it, and each
 * one exists because of a failure that is otherwise silent:
 *
 *   1. THE DISCLOSURE ASSERTION (VM-UI-F-105). The raw body is scanned for
 *      anything shaped like a live credential, and a response containing one
 *      is REJECTED — not rendered, not logged and displayed anyway. The server
 *      already refuses to send such a response; this is the client refusing to
 *      accept one, because a server that regressed must not be able to make
 *      the interface the thing that leaks.
 *
 *   2. RUNTIME VALIDATION (VM-UI-F-106). The body is parsed against a Zod
 *      schema. A type says what a response should be; it does not look at what
 *      arrived. A server on an older build, a proxy rewriting a body, a field
 *      that changed meaning — all pass the compiler, and without this they
 *      render as a blank panel or, worse, as a zero.
 *
 *   3. LOUD FAILURE. A shape mismatch throws. It does not fall back to a
 *      partial render: a view that quietly drops the field it could not parse
 *      is a view that shows fewer findings than exist, which is the defect
 *      class this whole framework is built to prevent.
 */
import { z } from 'zod';
import * as s from './schemas';

/** Where the API lives. Same origin, proxied in development (VM-UI §7.5). */
export const API_BASE = '/v1';

/**
 * CREDENTIAL_PATTERNS is the client's copy of "looks like a live credential".
 *
 * The AUTHORITATIVE list is the server's (internal/model/secret.go), which is
 * shared by the report, the ticket and the durable queue so those boundaries
 * cannot disagree. This is a deliberate duplicate for one purpose: to catch a
 * server that regressed. It is a subset, and it is not a filter — nothing here
 * removes anything. A match rejects the whole response, because a response
 * that needs scrubbing has a defect at the producer and scrubbing it here
 * would hide that.
 */
const CREDENTIAL_PATTERNS: readonly RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bASIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
  /\bglpat-[A-Za-z0-9_-]{20,}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
  /\bsk-[A-Za-z0-9]{32,}\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
];

/** Thrown when a response carries credential material. */
export class CredentialDisclosureError extends Error {
  constructor(
    readonly path: string,
    readonly pattern: string,
  ) {
    super(
      `The response from ${path} contained something shaped like a live credential ` +
        `(${pattern}) and was REJECTED without being rendered.\n\n` +
        'No secret value may cross this boundary (VM-UI-F-105). The finding record has ' +
        'nowhere to hold one, so this is a defect at the producer — a narrative or a log ' +
        'line that quoted a matched value. It must be fixed there, not filtered here.',
    );
    this.name = 'CredentialDisclosureError';
  }
}

/** Thrown when a response does not match the schema. */
export class ShapeDriftError extends Error {
  constructor(
    readonly path: string,
    readonly issues: z.ZodIssue[],
  ) {
    const detail = issues
      .slice(0, 8)
      .map((i) => `  ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    super(
      `The response from ${path} did not match the shape this interface was built ` +
        `against:\n\n${detail}\n\n` +
        'This is a version mismatch between the interface and the API, not a data problem. ' +
        'Regenerate the types (npm run gen) and rebuild; the interface refuses to render a ' +
        'response it cannot fully understand rather than showing you part of it.',
    );
    this.name = 'ShapeDriftError';
  }
}

/** Thrown for an error the API reported. */
export class ApiRequestError extends Error {
  constructor(
    readonly path: string,
    readonly status: number,
    readonly body: s.ApiError,
  ) {
    super(body.error);
    this.name = 'ApiRequestError';
  }
  /** What the reader can do about it (VM-UI-F-903). */
  get remedy(): string {
    return this.body.remedy ?? '';
  }
  get detail(): string {
    return this.body.detail ?? '';
  }
}

/** assertNoCredential rejects a body carrying credential material. */
export function assertNoCredential(path: string, raw: string): void {
  for (const pattern of CREDENTIAL_PATTERNS) {
    if (pattern.test(raw)) {
      throw new CredentialDisclosureError(path, pattern.source);
    }
  }
}

async function request<T>(path: string, schema: z.ZodType<T>): Promise<T> {
  const res = await fetch(API_BASE + path, {
    headers: { Accept: 'application/json' },
    credentials: 'same-origin',
  });
  const raw = await res.text();

  // The disclosure assertion runs on the RAW BODY, before parsing, and on
  // error bodies too: an error message that quoted a value would leak it just
  // as effectively as a finding.
  assertNoCredential(path, raw);

  let json: unknown;
  try {
    json = raw === '' ? null : JSON.parse(raw);
  } catch {
    throw new ShapeDriftError(path, [
      { code: 'custom', path: [], message: `the response was not JSON (${res.status})` } as z.ZodIssue,
    ]);
  }

  if (!res.ok) {
    const parsed = s.apiError.safeParse(json);
    throw new ApiRequestError(
      path,
      res.status,
      parsed.success ? parsed.data : { error: `request failed with status ${res.status}` },
    );
  }

  const parsed = schema.safeParse(json);
  if (!parsed.success) {
    throw new ShapeDriftError(path, parsed.error.issues);
  }
  return parsed.data;
}

/** Query parameters, rendered so an empty value is omitted rather than sent blank. */
export function qs(params: Record<string, string | number | boolean | undefined | string[]>): string {
  const out = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === '' || value === false) continue;
    if (Array.isArray(value)) {
      for (const v of value) if (v !== '') out.append(key, v);
      continue;
    }
    out.set(key, String(value));
  }
  const rendered = out.toString();
  return rendered ? `?${rendered}` : '';
}

export const api = {
  health: () => request('/health', s.health),
  findings: (query: string) => request(`/findings${query}`, s.findingPage),
  facets: (query: string) => request(`/findings/facets${query}`, s.facets),
  finding: (fp: string) => request(`/findings/${encodeURIComponent(fp)}`, s.finding),
  timeline: (fp: string) => request(`/findings/${encodeURIComponent(fp)}/timeline`, s.timeline),
  attempts: (fp: string) => request(`/findings/${encodeURIComponent(fp)}/attempts`, z.array(s.attempt)),
  runs: (query = '') => request(`/runs${query}`, s.runPage),
  latestRun: () => request('/runs/latest', s.overview),
  run: (id: string) => request(`/runs/${encodeURIComponent(id)}`, s.overview),
  compare: (a: string, b: string) =>
    request(`/runs/compare${qs({ a, b })}`, s.comparison),
  repos: () => request('/repos', z.array(s.repoSummary)),
  repo: (name: string) => request(`/repos/${name}`, s.repoDetail),
  repoTrend: (name: string, window = 20) => request(`/repos/${name}/trend${qs({ window })}`, s.trendSeries),
  coverage: (runID?: string) => request(`/coverage${qs({ run: runID })}`, s.coverageView),
  waves: () => request('/waves', z.array(s.wave)),
  trends: (metric: string, window = 20, kind = 'sweep') =>
    request(`/metrics/trends${qs({ metric, window, kind })}`, s.trendSeries),
  reports: () => request('/reports', z.array(s.reportSummary)),
  github: () => request('/github', s.githubView),
};
