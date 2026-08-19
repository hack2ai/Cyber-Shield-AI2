import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  base: './',
  plugins: [tailwindcss()],
  build: {
    outDir: 'docs',
    emptyOutDir: true
  },
  server: {
    port: 3000,
    proxy: {
      '/api': 'http://localhost:3000'
    }
  }
});
