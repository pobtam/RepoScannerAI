import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The interface is served from the same origin as the API in a real
// deployment (VM-UI §7.5), so development proxies /v1 rather than enabling
// CORS. Enabling CORS in development and relying on same-origin in production
// means the two environments disagree about the thing hardest to debug.
export default defineConfig({
  plugins: [react()],
  server: {
    port: Number(process.env.PORT ?? 5173),
    strictPort: true,
    proxy: {
      '/v1': {
        target: process.env.API_URL ?? 'http://127.0.0.1:8080',
        changeOrigin: false,
      },
    },
  },
  build: { outDir: 'dist', sourcemap: true },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
  },
});
