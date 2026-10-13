/**
 * Local-only identity for browsing a real store from this machine.
 *
 * The API server in -dsn mode trusts identity headers set by an authenticating
 * proxy, and refuses an anonymous request (VM-UI-F-802). On a laptop there is
 * no such proxy, so a real store cannot be browsed at all. This module lets the
 * Vite DEV server stand in for one — injecting a fixed security-owner identity
 * on every proxied /v1 request — under conditions that keep it a single-user,
 * single-machine convenience:
 *
 *   - off unless VULNFRAMEWORK_LOCAL_AUTH=1 is set explicitly;
 *   - the dev server only: `vite build` and `vite preview` refuse it, so it
 *     can never ship in a bundle or a preview deployment;
 *   - the dev server must be bound to 127.0.0.1, and the API it proxies to
 *     must be on loopback — a fixed identity on a reachable port is an open
 *     door, and on a remote API it is impersonation;
 *   - a request whose Host or Origin is not this machine's dev server gets no
 *     identity, which is what stops another website open in the same browser
 *     (by DNS rebinding or a cross-site request) from borrowing it.
 *
 * The API server itself never gains this ability. It stays fail-closed; only
 * the development proxy in front of it changes.
 */

export const LOCAL_AUTH_ENV = 'VULNFRAMEWORK_LOCAL_AUTH';
export const LOCAL_AUTH_REPOS_ENV = 'VULNFRAMEWORK_LOCAL_AUTH_REPOS';

/** The header names the API server reads by default (-user-header etc.). */
export const AUTH_HEADERS = {
  user: 'x-auth-user',
  level: 'x-auth-level',
  repos: 'x-auth-repos',
} as const;

export interface LocalAuth {
  user: string;
  level: 'security_owner';
  repos: string[];
}

export interface DevServerShape {
  /** 'serve' for `vite` and `vite preview`, 'build' for `vite build`. */
  command: 'serve' | 'build';
  isPreview: boolean;
  /** The resolved server.host — what --host set. */
  host: string | boolean | undefined;
  /** The API the /v1 proxy forwards to. */
  target: string;
}

type Env = Record<string, string | undefined>;

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

/**
 * Decides whether local auth is on, and refuses every unsafe combination.
 * Returns null when it is off. Throws — so the dev server does not start —
 * when it was asked for and cannot be granted safely.
 */
export function localAuthFromEnv(env: Env, shape: DevServerShape): LocalAuth | null {
  const raw = env[LOCAL_AUTH_ENV];
  if (raw === undefined || raw === '' || raw === '0') {
    return null;
  }
  if (raw !== '1') {
    throw new Error(`${LOCAL_AUTH_ENV}=${JSON.stringify(raw)}: set it to 1 to enable local auth, or unset it.`);
  }
  if (shape.command !== 'serve' || shape.isPreview) {
    throw new Error(
      `${LOCAL_AUTH_ENV} is for the development server only; refusing to apply it to ` +
        `${shape.isPreview ? 'vite preview' : 'vite build'}. Unset it.`,
    );
  }
  if (shape.host !== '127.0.0.1') {
    throw new Error(
      `${LOCAL_AUTH_ENV} requires the dev server to be bound to 127.0.0.1 (got ${JSON.stringify(shape.host ?? 'the default')}). ` +
        `Start it with --host 127.0.0.1. Any other address would grant a security-owner identity to whoever can reach the port.`,
    );
  }
  let targetHost: string;
  try {
    targetHost = new URL(shape.target).hostname;
  } catch {
    throw new Error(`${LOCAL_AUTH_ENV}: the API URL ${JSON.stringify(shape.target)} does not parse.`);
  }
  if (!LOOPBACK.has(targetHost)) {
    throw new Error(
      `${LOCAL_AUTH_ENV} only injects identity into an API on this machine; ${shape.target} is not loopback.`,
    );
  }

  const repos = (env[LOCAL_AUTH_REPOS_ENV] ?? '')
    .split(',')
    .map((r) => r.trim())
    .filter((r) => r !== '');
  return { user: `local:${env.USER || 'user'}`, level: 'security_owner', repos };
}

/**
 * Whether a proxied request may receive the identity: it must be addressed to
 * this dev server by a loopback name, and if the browser says where it came
 * from, it must have come from this dev server too.
 *
 * Origin alone is not enough: a browser sends none on a cross-site GET made by
 * an <img> or a no-cors fetch. Sec-Fetch-Site is sent on those, so it is
 * checked as well; 'none' is a URL typed into the address bar.
 */
export function requestMayCarryIdentity(
  headers: {
    host?: string | undefined;
    origin?: string | undefined;
    'sec-fetch-site'?: string | undefined;
  },
  port: number,
): boolean {
  const own = [`127.0.0.1:${port}`, `localhost:${port}`];
  if (!headers.host || !own.includes(headers.host.toLowerCase())) {
    return false;
  }
  if (headers.origin !== undefined && !own.map((h) => `http://${h}`).includes(headers.origin.toLowerCase())) {
    return false;
  }
  const site = headers['sec-fetch-site'];
  if (site !== undefined && site !== 'same-origin' && site !== 'none') {
    return false;
  }
  return true;
}

/** The headers to set, replacing anything the client sent under those names. */
export function identityHeaders(auth: LocalAuth): Record<string, string> {
  return {
    [AUTH_HEADERS.user]: auth.user,
    [AUTH_HEADERS.level]: auth.level,
    [AUTH_HEADERS.repos]: auth.repos.join(','),
  };
}

export function warningBanner(auth: LocalAuth, port: number): string {
  const line = '='.repeat(78);
  return [
    line,
    'WARNING: LOCAL AUTH IS ON (VULNFRAMEWORK_LOCAL_AUTH=1)',
    `Every /v1 request through http://127.0.0.1:${port} is sent to the API as`,
    `"${auth.user}" with level ${auth.level} — full access, secret findings included.`,
    'This is for browsing your own data on your own machine. Never expose this port,',
    'never run it on a shared host, and unset the variable when you are done.',
    line,
  ].join('\n');
}
