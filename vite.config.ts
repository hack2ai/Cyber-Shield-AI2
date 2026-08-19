import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  base: './',
  plugins: [tailwindcss()],
  build: {
    outDir: 'docs',
    emptyOutDir: true,
    // The upgraded Vite/esbuild toolchain should preserve modern syntax in
    // dependencies (Lucide, Motion, Firebase) instead of targeting legacy
    // browser matrices that cannot be transformed reliably by current esbuild.
    target: 'es2022'
  },
  server: {
    port: 3000,
    proxy: {
      '/api': 'http://localhost:3000'
    }
  }
});
