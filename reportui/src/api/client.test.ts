/**
 * The client's three guarantees.
 *
 * Each test exists because the failure it describes is silent: a credential
 * rendered, a response partially understood, an error shown as a blank page.
 */
import { describe, expect, it, vi, afterEach } from 'vitest';
import { z } from 'zod';
import {
  ApiRequestError,
  CredentialDisclosureError,
  ShapeDriftError,
  api,
  assertNoCredential,
  qs,
} from './client';
import * as schemas from './schemas';
import findingsPage from '../test-fixtures/findings-page.json';
import finding from '../test-fixtures/finding.json';

function respondWith(body: unknown, status = 200) {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(text, { status, headers: { 'Content-Type': 'application/json' } })),
  );
}

afterEach(() => vi.unstubAllGlobals());

// AWS's documented example key ID, joined at run time so no key-like string is
// committed (secret scanners and push protection read files, not programs).
const exampleKeyId = ['AK', 'IA', 'IOSFODNN', '7EXAMPLE'].join('');

describe('the disclosure assertion (VM-UI-F-105)', () => {
  it('rejects a response carrying credential material instead of rendering it', async () => {
    const poisoned = structuredClone(finding) as Record<string, unknown>;
    (poisoned.triage as Record<string, unknown>).description =
      `the key ${exampleKeyId} is in the file`;
    respondWith(poisoned);

    await expect(api.finding('abc')).rejects.toBeInstanceOf(CredentialDisclosureError);
  });

  it('rejects credential material in an ERROR body too', async () => {
    respondWith({ error: 'boom', detail: 'token ghp_' + 'a'.repeat(40) }, 500);
    await expect(api.finding('abc')).rejects.toBeInstanceOf(CredentialDisclosureError);
  });

  it('names what matched, so the defect can be fixed at the producer', () => {
    try {
      assertNoCredential('/findings', `x ${exampleKeyId} y`);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(CredentialDisclosureError);
      expect((err as CredentialDisclosureError).message).toContain('at the producer');
      expect((err as CredentialDisclosureError).message).toContain('VM-UI-F-105');
    }
  });

  it('does not reject an ordinary response', async () => {
    respondWith(findingsPage);
    await expect(api.findings('?scope=open')).resolves.toBeDefined();
  });
});

describe('runtime validation (VM-UI-F-106)', () => {
  it('throws on shape drift rather than rendering a partial view', async () => {
    const drifted = structuredClone(findingsPage) as Record<string, unknown>;
    delete drifted.matched;
    respondWith(drifted);

    await expect(api.findings('?scope=open')).rejects.toBeInstanceOf(ShapeDriftError);
  });

  it('throws when a field changes type, even to a plausible one', async () => {
    const drifted = structuredClone(findingsPage) as { matched: unknown };
    drifted.matched = '17';
    respondWith(drifted);
    await expect(api.findings('?scope=open')).rejects.toBeInstanceOf(ShapeDriftError);
  });

  it('says what to do about it', async () => {
    respondWith({ nonsense: true });
    await expect(api.findings('?scope=open')).rejects.toThrow(/Regenerate the types/);
  });

  it('rejects a non-JSON body', async () => {
    respondWith('<html>a proxy error page</html>');
    await expect(api.findings('?scope=open')).rejects.toBeInstanceOf(ShapeDriftError);
  });
});

describe('API errors', () => {
  it('carries the remedy the server supplied (VM-UI-F-903)', async () => {
    respondWith(
      { error: 'scope required', detail: 'the corpus is never defaulted', remedy: 'pass scope=open' },
      400,
    );
    try {
      await api.findings('');
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(ApiRequestError);
      const e = err as ApiRequestError;
      expect(e.status).toBe(400);
      expect(e.remedy).toBe('pass scope=open');
      expect(e.detail).toContain('never defaulted');
    }
  });
});

describe('the captured fixtures', () => {
  // The fixtures come from the real API. Validating them on every run is what
  // stops a schema change leaving the interface's tests passing against a
  // shape the server no longer produces.
  const cases: [string, z.ZodType<unknown>, unknown][] = [
    ['findings page', schemas.findingPage, findingsPage],
    ['finding', schemas.finding, finding],
  ];
  for (const [name, schema, fixture] of cases) {
    it(`${name} still matches the schema`, () => {
      const parsed = schema.safeParse(fixture);
      if (!parsed.success) {
        throw new Error(
          `the captured ${name} fixture no longer matches the schema:\n` +
            JSON.stringify(parsed.error.issues.slice(0, 5), null, 2) +
            '\n\nRe-capture it against the demonstration API (node scripts/capture-fixtures.mjs). ' +
            'A stale fixture makes every test over it a test of the fixture.',
        );
      }
    });
  }
});

describe('query rendering', () => {
  it('omits empty values rather than sending blanks', () => {
    expect(qs({ a: '', b: undefined, c: false, d: 'x', e: 2 })).toBe('?d=x&e=2');
  });
  it('repeats an array parameter', () => {
    expect(qs({ repo: ['a', 'b'] })).toBe('?repo=a&repo=b');
  });
});
