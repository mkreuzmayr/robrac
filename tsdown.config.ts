import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/index.ts', 'src/client.ts', 'src/core.ts', 'src/testing.ts'],
  format: 'esm',
  // `dist/` only ever holds the published build, so the test files the root
  // tsconfig covers must stay out of declaration emit.
  dts: { tsconfig: 'tsconfig.build.json' },
  clean: true,
  // No sourcemaps in the tarball: they are ~152 kB of the published package and a
  // consumer debugging robrac reads `src/` from GitHub, not a map in node_modules.
  sourcemap: false,
  // Dependencies and peers (zod, better-auth) are externalised by default.
});
