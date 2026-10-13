import { describe, expect, it } from 'vitest';
import {
  identityHeaders,
  localAuthFromEnv,
  requestMayCarryIdentity,
  warningBanner,
  type DevServerShape,
} from './local-auth';

const dev: DevServerShape = {
  command: 'serve',
  isPreview: false,
  host: '127.0.0.1',
  target: 'http://127.0.0.1:8080',
};
const on = { VULNFRAMEWORK_LOCAL_AUTH: '1', USER: 'pat' };

describe('localAuthFromEnv', () => {
  it('is off by default', () => {
    expect(localAuthFromEnv({}, dev)).toBeNull();
    expect(localAuthFromEnv({ VULNFRAMEWORK_LOCAL_AUTH: '' }, dev)).toBeNull();
    expect(localAuthFromEnv({ VULNFRAMEWORK_LOCAL_AUTH: '0' }, dev)).toBeNull();
  });

  it('grants a security-owner identity when explicitly enabled on 127.0.0.1', () => {
    const auth = localAuthFromEnv({ ...on, VULNFRAMEWORK_LOCAL_AUTH_REPOS: 'org/api, org/web,,' }, dev);
    expect(auth).toEqual({ user: 'local:pat', level: 'security_owner', repos: ['org/api', 'org/web'] });
  });

  it('refuses an ambiguous value rather than guessing', () => {
    expect(() => localAuthFromEnv({ VULNFRAMEWORK_LOCAL_AUTH: 'true' }, dev)).toThrow(/set it to 1/);
  });

  it.each([
    ['0.0.0.0', '0.0.0.0'],
    ['every interface (--host)', true],
    ['the default host', undefined],
    ['localhost, which may resolve beyond loopback', 'localhost'],
    ['a LAN address', '192.168.1.20'],
  ])('refuses to start bound to %s', (_name, host) => {
    expect(() => localAuthFromEnv(on, { ...dev, host })).toThrow(/127\.0\.0\.1/);
  });

  it('refuses vite build and vite preview', () => {
    expect(() => localAuthFromEnv(on, { ...dev, command: 'build' })).toThrow(/development server only/);
    expect(() => localAuthFromEnv(on, { ...dev, isPreview: true })).toThrow(/development server only/);
  });

  it('refuses to send the identity to an API that is not on this machine', () => {
    expect(() => localAuthFromEnv(on, { ...dev, target: 'https://vulns.example.com' })).toThrow(/not loopback/);
    expect(() => localAuthFromEnv(on, { ...dev, target: 'not a url' })).toThrow(/does not parse/);
    expect(localAuthFromEnv(on, { ...dev, target: 'http://localhost:8080' })).not.toBeNull();
  });
});

describe('requestMayCarryIdentity', () => {
  const port = 5173;

  it('allows the interface talking to its own dev server', () => {
    expect(requestMayCarryIdentity({ host: '127.0.0.1:5173' }, port)).toBe(true);
    expect(requestMayCarryIdentity({ host: 'localhost:5173', origin: 'http://localhost:5173' }, port)).toBe(true);
    expect(requestMayCarryIdentity({ host: '127.0.0.1:5173', 'sec-fetch-site': 'same-origin' }, port)).toBe(true);
    expect(requestMayCarryIdentity({ host: '127.0.0.1:5173', 'sec-fetch-site': 'none' }, port)).toBe(true);
  });

  it('refuses a request addressed by another name (DNS rebinding)', () => {
    expect(requestMayCarryIdentity({ host: 'attacker.example:5173' }, port)).toBe(false);
    expect(requestMayCarryIdentity({}, port)).toBe(false);
    expect(requestMayCarryIdentity({ host: '127.0.0.1:9999' }, port)).toBe(false);
  });

  it('refuses a request another website made', () => {
    expect(requestMayCarryIdentity({ host: '127.0.0.1:5173', origin: 'https://attacker.example' }, port)).toBe(false);
    expect(requestMayCarryIdentity({ host: '127.0.0.1:5173', 'sec-fetch-site': 'cross-site' }, port)).toBe(false);
    expect(requestMayCarryIdentity({ host: '127.0.0.1:5173', 'sec-fetch-site': 'same-site' }, port)).toBe(false);
  });
});

describe('identityHeaders and the warning', () => {
  const auth = { user: 'local:pat', level: 'security_owner' as const, repos: ['org/api', 'org/web'] };

  it('sets exactly the three headers the API reads', () => {
    expect(identityHeaders(auth)).toEqual({
      'x-auth-user': 'local:pat',
      'x-auth-level': 'security_owner',
      'x-auth-repos': 'org/api,org/web',
    });
  });

  it('says plainly what is on', () => {
    const banner = warningBanner(auth, 5173);
    expect(banner).toMatch(/WARNING: LOCAL AUTH IS ON/);
    expect(banner).toMatch(/security_owner/);
    expect(banner).toMatch(/127\.0\.0\.1:5173/);
  });
});
