import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// outDir is the bundle root copied into the sbc-frontend nginx image
// (see ./Dockerfile: COPY --from=build /app/dist/sbc-dashboard/browser).
// The bundle is no longer embedded into the SBC daemon — the dashboard runs
// in its own pod so UI releases don't restart SIP.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist/sbc-dashboard/browser',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 4200,
    proxy: {
      // Forward API calls in dev to a locally-running sbc-daemon.
      '/api': 'http://localhost:8080',
    },
  },
});
