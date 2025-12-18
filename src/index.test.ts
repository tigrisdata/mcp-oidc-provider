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
      expect(DEFAULT_ACCESS_TOKEN_TTL).toBe(900);
      expect(DEFAULT_AUTHORIZATION_CODE_TTL).toBe(600);
      expect(DEFAULT_ID_TOKEN_TTL).toBe(900);
      expect(DEFAULT_REFRESH_TOKEN_TTL).toBe(86400 * 30);
      expect(DEFAULT_INTERACTION_SESSION_TTL_MS).toBe(30 * 60 * 1000);
      expect(DEFAULT_USER_SESSION_TTL_MS).toBe(30 * 24 * 60 * 60 * 1000);
      expect(DEFAULT_INTERACTION_TTL).toBe(600);
      expect(DEFAULT_GRANT_TTL).toBe(86400 * 14);
      expect(DEFAULT_SESSION_TTL).toBe(86400 * 30);
    });

    it('should export DEFAULT_SCOPES', () => {
      expect(DEFAULT_SCOPES).toEqual(['openid', 'email', 'profile', 'offline_access']);
    });

    it('should export DEFAULT_CLAIMS', () => {
      expect(DEFAULT_CLAIMS).toBeDefined();
      expect(DEFAULT_CLAIMS.openid).toContain('sub');
      expect(DEFAULT_CLAIMS.email).toContain('email');
      expect(DEFAULT_CLAIMS.profile).toContain('name');
    });

    it('should export DEFAULT_ROUTES', () => {
      expect(DEFAULT_ROUTES.authorization).toBe('/authorize');
      expect(DEFAULT_ROUTES.token).toBe('/token');
      expect(DEFAULT_ROUTES.jwks).toBe('/jwks');
    });

    it('should export DEFAULT_ALLOWED_CLIENT_PROTOCOLS', () => {
      expect(DEFAULT_ALLOWED_CLIENT_PROTOCOLS).toContain('cursor://');
      expect(DEFAULT_ALLOWED_CLIENT_PROTOCOLS).toContain('vscode://');
    });

    it('should export DEFAULT_JWKS_CACHE_OPTIONS', () => {
      expect(DEFAULT_JWKS_CACHE_OPTIONS.cooldownDuration).toBe(30_000);
      expect(DEFAULT_JWKS_CACHE_OPTIONS.cacheMaxAge).toBe(600_000);
    });

    it('should export STORAGE_NAMESPACES', () => {
      expect(STORAGE_NAMESPACES.USER_SESSIONS).toBe('user-sessions');
      expect(STORAGE_NAMESPACES.INTERACTION_SESSIONS).toBe('interaction-sessions');
      expect(STORAGE_NAMESPACES.EXPRESS_SESSIONS).toBe('express-sessions');
    });
  });
});
