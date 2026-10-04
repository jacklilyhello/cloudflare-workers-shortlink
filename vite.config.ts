import { defineConfig } from 'vite';
export default defineConfig({
  root: 'ui',
  build: { outDir: '../dist', emptyOutDir: true, sourcemap: false },
});
