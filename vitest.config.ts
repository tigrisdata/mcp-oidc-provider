import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts'],
    // Setup file for global test configuration (inspired by AWS MCP patterns)
    setupFiles: ['./src/test/setup.ts'],
    // Sequence tests to avoid race conditions
    sequence: {
      shuffle: false,
    },
    // Test pool configuration
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true,
      },
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      reportsDirectory: './coverage',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/**/*.d.ts', 'src/types.ts', 'src/core/types.ts', 'src/bin/**/*.ts', 'src/test/**/*.ts'],
      thresholds: {
        statements: 95,
        branches: 85,
        functions: 90,
        lines: 95,
      },
    },
    // Type-check tests (similar to pyright in AWS MCP)
    typecheck: {
      enabled: false, // Enable when ready for stricter type checking in tests
    },
  },
});
