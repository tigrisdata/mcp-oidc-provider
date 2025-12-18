import { describe, it, expect } from 'vitest';
import {
  DEFAULT_AUTHORIZATION_CODE_TTL,
  DEFAULT_ACCESS_TOKEN_TTL,
  DEFAULT_ID_TOKEN_TTL,
  DEFAULT_REFRESH_TOKEN_TTL,
  DEFAULT_INTERACTION_SESSION_TTL_MS,
  DEFAULT_USER_SESSION_TTL_MS,
  DEFAULT_INTERACTION_TTL,
  DEFAULT_GRANT_TTL,
  DEFAULT_SESSION_TTL,
  DEFAULT_SCOPES,
  DEFAULT_CLAIMS,
  DEFAULT_ALLOWED_CLIENT_PROTOCOLS,
  DEFAULT_ROUTES,
  STORAGE_NAMESPACES,
  DEFAULT_JWKS_CACHE_OPTIONS,
} from './config.js';

describe('config', () => {
  describe('token TTLs', () => {
    it('should have authorization code TTL of 10 minutes', () => {
      expect(DEFAULT_AUTHORIZATION_CODE_TTL).toBe(600);
    });

    it('should have access token TTL of 15 minutes', () => {
      expect(DEFAULT_ACCESS_TOKEN_TTL).toBe(900);
    });

    it('should have id token TTL equal to access token TTL', () => {
      expect(DEFAULT_ID_TOKEN_TTL).toBe(DEFAULT_ACCESS_TOKEN_TTL);
    });

    it('should have refresh token TTL of 30 days', () => {
      expect(DEFAULT_REFRESH_TOKEN_TTL).toBe(86400 * 30);
    });

    it('should have interaction session TTL of 30 minutes in ms', () => {
      expect(DEFAULT_INTERACTION_SESSION_TTL_MS).toBe(30 * 60 * 1000);
    });

    it('should have user session TTL of 30 days in ms', () => {
      expect(DEFAULT_USER_SESSION_TTL_MS).toBe(30 * 24 * 60 * 60 * 1000);
    });

    it('should have interaction TTL of 10 minutes', () => {
      expect(DEFAULT_INTERACTION_TTL).toBe(600);
    });

    it('should have grant TTL of 14 days', () => {
      expect(DEFAULT_GRANT_TTL).toBe(86400 * 14);
    });

    it('should have session TTL of 30 days', () => {
      expect(DEFAULT_SESSION_TTL).toBe(86400 * 30);
    });
  });

  describe('scopes and claims', () => {
    it('should have required default scopes', () => {
      expect(DEFAULT_SCOPES).toContain('openid');
      expect(DEFAULT_SCOPES).toContain('email');
      expect(DEFAULT_SCOPES).toContain('profile');
      expect(DEFAULT_SCOPES).toContain('offline_access');
    });

    it('should have openid claim with sub', () => {
      expect(DEFAULT_CLAIMS.openid).toContain('sub');
    });

    it('should have email claims', () => {
      expect(DEFAULT_CLAIMS.email).toContain('email');
      expect(DEFAULT_CLAIMS.email).toContain('email_verified');
    });

    it('should have profile claims', () => {
      expect(DEFAULT_CLAIMS.profile).toContain('name');
      expect(DEFAULT_CLAIMS.profile).toContain('nickname');
      expect(DEFAULT_CLAIMS.profile).toContain('picture');
    });
  });

  describe('allowed client protocols', () => {
    it('should allow standard MCP client protocols', () => {
      expect(DEFAULT_ALLOWED_CLIENT_PROTOCOLS).toContain('cursor://');
      expect(DEFAULT_ALLOWED_CLIENT_PROTOCOLS).toContain('vscode://');
      expect(DEFAULT_ALLOWED_CLIENT_PROTOCOLS).toContain('windsurf://');
    });
  });

  describe('default routes', () => {
    it('should have standard OIDC routes', () => {
      expect(DEFAULT_ROUTES.authorization).toBe('/authorize');
      expect(DEFAULT_ROUTES.registration).toBe('/register');
      expect(DEFAULT_ROUTES.token).toBe('/token');
      expect(DEFAULT_ROUTES.jwks).toBe('/jwks');
      expect(DEFAULT_ROUTES.userinfo).toBe('/me');
    });
  });

  describe('storage namespaces', () => {
    it('should have all required namespaces', () => {
      expect(STORAGE_NAMESPACES.USER_SESSIONS).toBe('user-sessions');
      expect(STORAGE_NAMESPACES.INTERACTION_SESSIONS).toBe('interaction-sessions');
      expect(STORAGE_NAMESPACES.EXPRESS_SESSIONS).toBe('express-sessions');
      expect(STORAGE_NAMESPACES.OIDC_SERVER_SESSIONS).toBe('oidc-server-sessions');
      expect(STORAGE_NAMESPACES.OIDC_CLIENT).toBe('oidc:Client');
    });
  });

  describe('JWKS cache options', () => {
    it('should have cooldown duration of 30 seconds', () => {
      expect(DEFAULT_JWKS_CACHE_OPTIONS.cooldownDuration).toBe(30_000);
    });

    it('should have cache max age of 10 minutes', () => {
      expect(DEFAULT_JWKS_CACHE_OPTIONS.cacheMaxAge).toBe(600_000);
    });
  });
});
