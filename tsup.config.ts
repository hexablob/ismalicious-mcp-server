import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts', 'src/server.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  minify: false,
  treeshake: true,
  splitting: false,
  target: 'es2022',
  // The CLI entry is executable; ship the shebang.
  banner: { js: '#!/usr/bin/env node' },
})
