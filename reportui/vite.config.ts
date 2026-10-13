import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import {
  AUTH_HEADERS,
  identityHeaders,
  localAuthFromEnv,
  requestMayCarryIdentity,
  warningBanner,
  type LocalAuth,
} from './scripts/local-auth';

const target = process.env.API_URL ?? 'http://127.0.0.1:8080';
const port = Number(process.env.PORT ?? 5173);

// Set once the configuration is resolved — only then is --host known — and
// read by the proxy on every request. Null means local auth is off.
let localAuth: LocalAuth | null = null;

// Decides local auth (scripts/local-auth.ts). Throwing here stops the server
// from starting, which is the point: asked-for-but-unsafe never runs.
function localAuthPlugin(command: 'serve' | 'build', isPreview: boolean): Plugin {
  return {
    name: 'vulnframework-local-auth',
    configResolved(config) {
      // Tests load this file too, and must never run with an identity.
      if (process.env.VITEST) {
        return;
      }
      localAuth = localAuthFromEnv(process.env, {
        command,
        isPreview,
        host: isPreview ? config.preview.host : config.server.host,
        target,
      });
      if (localAuth) {
        config.logger.warn(warningBanner(localAuth, port));
      }
    },
  };
}

// The interface is served from the same origin as the API in a real
// deployment (VM-UI §7.5), so development proxies /v1 rather than enabling
// CORS. Enabling CORS in development and relying on same-origin in production
// means the two environments disagree about the thing hardest to debug.
export default defineConfig(({ command, isPreview }) => ({
  plugins: [react(), localAuthPlugin(command, isPreview === true)],
  server: {
    port,
    strictPort: true,
    proxy: {
      '/v1': {
        target,
        changeOrigin: false,
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq, req) => {
            if (!localAuth) {
              return;
            }
            // Whatever the client sent under these names is discarded: the
            // identity is the proxy's to assert, never the browser's.
            for (const name of Object.values(AUTH_HEADERS)) {
              proxyReq.removeHeader(name);
            }
            const h = req.headers;
            const fetchSite = h['sec-fetch-site'];
            if (
              !requestMayCarryIdentity(
                {
                  host: h.host,
                  origin: h.origin,
                  'sec-fetch-site': Array.isArray(fetchSite) ? fetchSite[0] : fetchSite,
                },
                port,
              )
            ) {
              // Forwarded anonymous, so the API refuses it (fail closed).
              return;
            }
            for (const [name, value] of Object.entries(identityHeaders(localAuth))) {
              proxyReq.setHeader(name, value);
            }
          });
        },
      },
    },
  },
  build: { outDir: 'dist', sourcemap: true },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
  },
}));
