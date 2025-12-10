import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'adapters/express/index': 'src/adapters/express/index.ts',
    'mcp/index': 'src/mcp/index.ts',
    'bin/generate-jwks': 'src/bin/generate-jwks.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  external: [
    'express',
    'express-session',
    'keyv',
    'openid-client',
  ],
});
