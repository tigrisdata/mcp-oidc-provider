import { describe, it, expect } from 'vitest';
import { createMcpAuthProvider, getIdpTokens } from './index.js';

describe('mcp/index exports', () => {
  it('should export createMcpAuthProvider', () => {
    expect(createMcpAuthProvider).toBeDefined();
    expect(typeof createMcpAuthProvider).toBe('function');
  });

  it('should export getIdpTokens', () => {
    expect(getIdpTokens).toBeDefined();
    expect(typeof getIdpTokens).toBe('function');
  });
});
