import { describe, it, expect } from 'vitest';
import { createConsoleLogger, noopLogger, generateJwks, generateDevJwks } from './index.js';

describe('utils/index exports', () => {
  it('should export createConsoleLogger', () => {
    expect(createConsoleLogger).toBeDefined();
    expect(typeof createConsoleLogger).toBe('function');
  });

  it('should export noopLogger', () => {
    expect(noopLogger).toBeDefined();
    expect(noopLogger.debug).toBeDefined();
    expect(noopLogger.info).toBeDefined();
    expect(noopLogger.warn).toBeDefined();
    expect(noopLogger.error).toBeDefined();
  });

  it('should export generateJwks', () => {
    expect(generateJwks).toBeDefined();
    expect(typeof generateJwks).toBe('function');
  });

  it('should export generateDevJwks', () => {
    expect(generateDevJwks).toBeDefined();
    expect(typeof generateDevJwks).toBe('function');
  });
});
