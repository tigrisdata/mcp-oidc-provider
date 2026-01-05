import { describe, it, expect } from 'vitest';
import { OidcClient, createOidcServer } from './index.js';

describe('oidc/index exports', () => {
  it('should export OidcClient', () => {
    expect(OidcClient).toBeDefined();
    expect(typeof OidcClient).toBe('function');
  });

  it('should export createOidcServer', () => {
    expect(createOidcServer).toBeDefined();
    expect(typeof createOidcServer).toBe('function');
  });
});
