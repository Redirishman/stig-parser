import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // Assets are served from the SPA bucket through the API Gateway S3 proxy,
  // which sits under a stage path (e.g. /v1). Relative asset URLs survive that;
  // absolute ones (/assets/...) would 404.
  base: './',
  build: { outDir: 'dist', sourcemap: false },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    // Playwright specs live in tests/e2e and are run by `npm run e2e`.
    exclude: ['tests/e2e/**', 'node_modules/**'],
  },
});
