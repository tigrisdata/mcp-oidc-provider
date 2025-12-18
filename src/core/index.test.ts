import { describe, it, expect } from 'vitest';
import {
  createOidcProvider,
  createSessionStore,
  createExtendedSessionStore,
  createOidcAdapterFactory,
  DEFAULT_ACCESS_TOKEN_TTL,
  DEFAULT_AUTHORIZATION_CODE_TTL,
  DEFAULT_ID_TOKEN_TTL,
  DEFAULT_REFRESH_TOKEN_TTL,
  DEFAULT_INTERACTION_SESSION_TTL_MS,
  DEFAULT_USER_SESSION_TTL_MS,
  DEFAULT_SCOPES,
  DEFAULT_CLAIMS,
  DEFAULT_ROUTES,
  DEFAULT_ALLOWED_CLIENT_PROTOCOLS,
} from './index.js';

describe('core/index exports', () => {
  it('should export createOidcProvider', () => {
    expect(createOidcProvider).toBeDefined();
    expect(typeof createOidcProvider).toBe('function');
  });

  it('should export createSessionStore', () => {
    expect(createSessionStore).toBeDefined();
    expect(typeof createSessionStore).toBe('function');
  });

  it('should export createExtendedSessionStore', () => {
    expect(createExtendedSessionStore).toBeDefined();
    expect(typeof createExtendedSessionStore).toBe('function');
  });

  it('should export createOidcAdapterFactory', () => {
    expect(createOidcAdapterFactory).toBeDefined();
    expect(typeof createOidcAdapterFactory).toBe('function');
  });

  it('should export config constants', () => {
    expect(DEFAULT_ACCESS_TOKEN_TTL).toBeDefined();
    expect(DEFAULT_AUTHORIZATION_CODE_TTL).toBeDefined();
    expect(DEFAULT_ID_TOKEN_TTL).toBeDefined();
    expect(DEFAULT_REFRESH_TOKEN_TTL).toBeDefined();
    expect(DEFAULT_INTERACTION_SESSION_TTL_MS).toBeDefined();
    expect(DEFAULT_USER_SESSION_TTL_MS).toBeDefined();
    expect(DEFAULT_SCOPES).toBeDefined();
    expect(DEFAULT_CLAIMS).toBeDefined();
    expect(DEFAULT_ROUTES).toBeDefined();
    expect(DEFAULT_ALLOWED_CLIENT_PROTOCOLS).toBeDefined();
  });
});
