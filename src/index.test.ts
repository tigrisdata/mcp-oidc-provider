import { describe, it, expect } from 'vitest';
import {
  createOidcProvider,
  OidcClient,
  createSessionStore,
  createExtendedSessionStore,
  createOidcAdapterFactory,
  createConsoleLogger,
  noopLogger,
  generateJwks,
  DEFAULT_ACCESS_TOKEN_TTL,
  DEFAULT_AUTHORIZATION_CODE_TTL,
  DEFAULT_ID_TOKEN_TTL,
  DEFAULT_REFRESH_TOKEN_TTL,
  DEFAULT_INTERACTION_SESSION_TTL_MS,
  DEFAULT_USER_SESSION_TTL_MS,
  DEFAULT_INTERACTION_TTL,
  DEFAULT_GRANT_TTL,
  DEFAULT_SESSION_TTL,
  DEFAULT_SCOPES,
  DEFAULT_CLAIMS,
  DEFAULT_ROUTES,
  DEFAULT_ALLOWED_CLIENT_PROTOCOLS,
  DEFAULT_JWKS_CACHE_OPTIONS,
  STORAGE_NAMESPACES,
} from './index.js';

describe('index exports', () => {
  describe('core exports', () => {
    it('should export createOidcProvider', () => {
      expect(createOidcProvider).toBeDefined();
      expect(typeof createOidcProvider).toBe('function');
    });

    it('should export OidcClient', () => {
      expect(OidcClient).toBeDefined();
      expect(typeof OidcClient).toBe('function');
    });

    it('should export session store functions', () => {
      expect(createSessionStore).toBeDefined();
      expect(createExtendedSessionStore).toBeDefined();
    });

    it('should export createOidcAdapterFactory', () => {
      expect(createOidcAdapterFactory).toBeDefined();
    });
  });

  describe('logger exports', () => {
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
  });

  describe('JWKS exports', () => {
    it('should export generateJwks', () => {
      expect(generateJwks).toBeDefined();
      expect(typeof generateJwks).toBe('function');
    });
  });

  describe('config constants', () => {
    it('should export TTL constants', () => {
      expect(DEFAULT_ACCESS_TOKEN_TTL).toBeDefined();
      expect(DEFAULT_AUTHORIZATION_CODE_TTL).toBeDefined();
      expect(DEFAULT_ID_TOKEN_TTL).toBeDefined();
      expect(DEFAULT_REFRESH_TOKEN_TTL).toBeDefined();
      expect(DEFAULT_INTERACTION_SESSION_TTL_MS).toBeDefined();
      expect(DEFAULT_USER_SESSION_TTL_MS).toBeDefined();
      expect(DEFAULT_INTERACTION_TTL).toBeDefined();
      expect(DEFAULT_GRANT_TTL).toBeDefined();
      expect(DEFAULT_SESSION_TTL).toBeDefined();
    });

    it('should export DEFAULT_SCOPES', () => {
      expect(DEFAULT_SCOPES).toBeDefined();
    });

    it('should export DEFAULT_CLAIMS', () => {
      expect(DEFAULT_CLAIMS).toBeDefined();
    });

    it('should export DEFAULT_ROUTES', () => {
      expect(DEFAULT_ROUTES).toBeDefined();
    });

    it('should export DEFAULT_ALLOWED_CLIENT_PROTOCOLS', () => {
      expect(DEFAULT_ALLOWED_CLIENT_PROTOCOLS).toBeDefined();
    });

    it('should export DEFAULT_JWKS_CACHE_OPTIONS', () => {
      expect(DEFAULT_JWKS_CACHE_OPTIONS).toBeDefined();
    });

    it('should export STORAGE_NAMESPACES', () => {
      expect(STORAGE_NAMESPACES).toBeDefined();
    });
  });
});
