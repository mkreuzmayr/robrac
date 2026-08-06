import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/index.ts', 'src/client.ts', 'src/testing.ts'],
  format: 'esm',
  // `dist/` only ever holds the published build, so the test files the root
  // tsconfig covers must stay out of declaration emit.
  dts: { tsconfig: 'tsconfig.build.json' },
  clean: true,
  sourcemap: true,
  // Dependencies and peers (zod, better-auth) are externalised by default.
});
