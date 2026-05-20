import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// outDir matches the path baked into the SBC daemon's include_dir! macro:
//   crates/sbc/sbc-daemon/src/api_server.rs:
//     include_dir!("$CARGO_MANIFEST_DIR/../sbc-dashboard/dist/sbc-dashboard/browser")
//
// Keeping this path means the Rust embed mechanism works unchanged across
// the Angular -> React migration.
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
