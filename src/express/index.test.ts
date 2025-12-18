import { describe, it, expect } from 'vitest';
import {
  createExpressAdapter,
  isOidcProviderRoute,
  createExpressAuthMiddleware,
  KeyvSessionStore,
  createMcpCorsMiddleware,
} from './index.js';

describe('express/index exports', () => {
  it('should export createExpressAdapter', () => {
    expect(createExpressAdapter).toBeDefined();
    expect(typeof createExpressAdapter).toBe('function');
  });

  it('should export isOidcProviderRoute', () => {
    expect(isOidcProviderRoute).toBeDefined();
    expect(typeof isOidcProviderRoute).toBe('function');
  });

  it('should export createExpressAuthMiddleware', () => {
    expect(createExpressAuthMiddleware).toBeDefined();
    expect(typeof createExpressAuthMiddleware).toBe('function');
  });

  it('should export KeyvSessionStore', () => {
    expect(KeyvSessionStore).toBeDefined();
    expect(typeof KeyvSessionStore).toBe('function');
  });

  it('should export createMcpCorsMiddleware', () => {
    expect(createMcpCorsMiddleware).toBeDefined();
    expect(typeof createMcpCorsMiddleware).toBe('function');
  });
});
