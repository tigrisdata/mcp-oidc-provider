/**
 * Test setup file - configures global test environment.
 *
 * Inspired by AWS MCP's testing patterns which apply fixtures like
 * `patch_log_tool_call` to all tests for consistent behavior.
 */

import { vi, beforeAll, afterAll, afterEach } from 'vitest';

/**
 * Suppress console output during tests to reduce noise.
 * Tests can still assert on logged values via mocks.
 *
 * Similar to AWS MCP's approach of patching logging side effects.
 */
const originalConsole = {
  log: console.log,
  info: console.info,
  warn: console.warn,
  error: console.error,
  debug: console.debug,
};

beforeAll(() => {
  // Only suppress in CI or when SUPPRESS_LOGS is set
  if (process.env.CI || process.env.SUPPRESS_LOGS) {
    console.log = vi.fn();
    console.info = vi.fn();
    console.warn = vi.fn();
    console.error = vi.fn();
    console.debug = vi.fn();
  }
});

afterAll(() => {
  // Restore console after all tests
  console.log = originalConsole.log;
  console.info = originalConsole.info;
  console.warn = originalConsole.warn;
  console.error = originalConsole.error;
  console.debug = originalConsole.debug;
});

afterEach(() => {
  // Clear all mocks after each test for isolation
  vi.clearAllMocks();
});

/**
 * Global test utilities available in all tests.
 */
declare global {
  /**
   * Skip test in CI environment.
   * Use for tests that require live services.
   */
  const skipInCI: () => boolean;
}

// @ts-expect-error - Adding to global for test convenience
globalThis.skipInCI = () => Boolean(process.env.CI);
