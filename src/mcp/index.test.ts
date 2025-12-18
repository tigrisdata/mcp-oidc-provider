import { describe, it, expect } from 'vitest';
import {
  setupMcpExpress,
  createMcpAuthProvider,
  getIdpTokens,
  InvalidTokenError,
} from './index.js';

describe('mcp/index exports', () => {
  it('should export setupMcpExpress', () => {
    expect(setupMcpExpress).toBeDefined();
    expect(typeof setupMcpExpress).toBe('function');
  });

  it('should export createMcpAuthProvider', () => {
    expect(createMcpAuthProvider).toBeDefined();
    expect(typeof createMcpAuthProvider).toBe('function');
  });

  it('should export getIdpTokens', () => {
    expect(getIdpTokens).toBeDefined();
    expect(typeof getIdpTokens).toBe('function');
  });

  it('should export InvalidTokenError', () => {
    expect(InvalidTokenError).toBeDefined();
    expect(typeof InvalidTokenError).toBe('function');
  });
});
