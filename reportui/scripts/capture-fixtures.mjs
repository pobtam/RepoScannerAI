/**
 * Capture the demonstration API's responses as test fixtures.
 *
 * The interface's tests need realistic payloads, and constructing them by hand
 * is the mistake this whole build has been avoiding: a hand-built payload can
 * contain a field the API never sends and omit one it always does, so a test
 * over it proves the fixture rather than the interface.
 *
 * These come from the REAL API over the demonstration pipeline. They are
 * validated against the Zod schemas on every test run, so a schema change
 * invalidates them loudly rather than letting the tests pass against a shape
 * the server no longer produces.
 *
 *   go run ./cmd/apiserver -demo &
 *   node scripts/capture-fixtures.mjs
 */
import { writeFileSync, mkdirSync } from 'node:fs';

const base = process.env.API_URL ?? 'http://127.0.0.1:8080';
const out = 'src/test-fixtures';

async function get(path) {
  const res = await fetch(base + path);
  if (!res.ok) throw new Error(`${path} returned ${res.status}`);
  return res.json();
}

async function main() {
  mkdirSync(out, { recursive: true });

  const page = await get('/v1/findings?scope=open&limit=50');
  const withPR = page.findings.find((f) => f.refs.pull_request) ?? page.findings[0];
  const blocked = page.findings.find((f) => f.state === 'BLOCKED_UPSTREAM') ?? page.findings[0];
  const gapPage = await get('/v1/findings?scope=open&notReobserved=true&limit=1');
  const gapFinding = gapPage.findings[0];
  const runs = await get('/v1/runs');
  const oldest = runs.runs[runs.runs.length - 1];

  const fixtures = {
    'health.json': await get('/v1/health'),
    'findings-page.json': page,
    'facets.json': await get('/v1/findings/facets?scope=open'),
    'finding.json': await get(`/v1/findings/${withPR.fingerprint}`),
    'timeline.json': await get(`/v1/findings/${withPR.fingerprint}/timeline`),
    'attempts.json': await get(`/v1/findings/${withPR.fingerprint}/attempts`),
    'blocked-finding.json': await get(`/v1/findings/${blocked.fingerprint}`),
    // A finding the most recent run did NOT observe, and its timeline. The
    // observation history's whole point is the runs that did not see it, and a
    // fixture where every run observed the finding cannot show that.
    ...(gapFinding
      ? {
          'finding-gap.json': await get(`/v1/findings/${gapFinding.fingerprint}`),
          'timeline-gap.json': await get(`/v1/findings/${gapFinding.fingerprint}/timeline`),
        }
      : {}),
    'runs.json': runs,
    'overview-latest.json': await get('/v1/runs/latest'),
    'overview-snapshot.json': await get(`/v1/runs/${oldest.id}`),
    'coverage.json': await get('/v1/coverage'),
    'repos.json': await get('/v1/repos'),
    'repo-detail.json': await get('/v1/repos/demo-org/checkout-web'),
    'repo-trend.json': await get('/v1/repos/demo-org/checkout-web/trend'),
    'waves.json': await get('/v1/waves'),
    'trend.json': await get('/v1/metrics/trends?metric=open'),
    'reports.json': await get('/v1/reports'),
    'github.json': await get('/v1/github'),
    // NuGuard on a deployment without it: the one line, and nothing else
    // (VM-UI-F-1211). The configured views come from the Go test that drives
    // the real worker against the fake NuGuard:
    //   UPDATE_UI_FIXTURES=1 go test ./internal/api -run TestNuGuardViewsFromTheRealServer
    'nuguard-demo.json': await get('/v1/nuguard'),
    'repo-nuguard-demo.json': await get('/v1/repos/demo-org/checkout-web/nuguard'),
  };

  // ONLY=name.json,other.json captures just those, leaving the rest as they
  // were captured: the demonstration's dates move with the clock, and a full
  // recapture rewrites fixtures whose content other tests rely on.
  const only = process.env.ONLY?.split(',');

  for (const [name, body] of Object.entries(fixtures)) {
    if (only && !only.includes(name)) continue;
    writeFileSync(`${out}/${name}`, JSON.stringify(body, null, 2) + '\n');
    console.log(`wrote ${out}/${name}`);
  }
}

main().catch((err) => {
  console.error(`capture-fixtures: ${err.message}`);
  console.error('The demonstration API must be running: go run ./cmd/apiserver -demo');
  process.exit(1);
});
