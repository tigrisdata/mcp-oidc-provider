import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import { createMcpAuthProvider, getIdpTokens, InvalidTokenError } from './auth-provider.js';
import type { KeyvLike, AuthenticatedUser } from '../types.js';
import type { AuthInfo } from './auth-provider.js';

// Mock jose
vi.mock('jose', () => ({
  createRemoteJWKSet: vi.fn(() => vi.fn()),
  jwtVerify: vi.fn(),
}));

describe('auth-provider', () => {
  let mockStore: KeyvLike;
  let storedData: Map<string, unknown>;

  beforeEach(() => {
    storedData = new Map();
    const mockUnderlyingStore = {
      get: vi.fn((key: string) => Promise.resolve(storedData.get(key))),
      set: vi.fn((key: string, value: unknown) => {
        storedData.set(key, value);
        return Promise.resolve(true);
      }),
      delete: vi.fn((key: string) => Promise.resolve(storedData.delete(key))),
      clear: vi.fn(() => Promise.resolve()),
    };

    mockStore = {
      get: vi.fn((key: string) => Promise.resolve(storedData.get(key))),
      set: vi.fn((key: string, value: unknown) => {
        storedData.set(key, value);
        return Promise.resolve(true);
      }),
      delete: vi.fn((key: string) => Promise.resolve(storedData.delete(key))),
      clear: vi.fn(() => Promise.resolve()),
      opts: {
        store: mockUnderlyingStore,
      },
    };

    vi.clearAllMocks();
  });

  describe('createMcpAuthProvider', () => {
    it('should create an auth provider with all required components', () => {
      const result = createMcpAuthProvider({
        oidcBaseUrl: 'http://localhost:4001',
        store: mockStore,
        mcpServerBaseUrl: 'http://localhost:3001',
      });

      expect(result.proxyOAuthServerProviderConfig).toBeDefined();
      expect(result.mcpRoutes).toBeDefined();
      expect(result.resourceMetadataUrl).toBeDefined();
    });

    it('should configure correct OAuth endpoints', () => {
      const result = createMcpAuthProvider({
        oidcBaseUrl: 'http://localhost:4001',
        store: mockStore,
        mcpServerBaseUrl: 'http://localhost:3001',
      });

      const { endpoints } = result.proxyOAuthServerProviderConfig;
      expect(endpoints.authorizationUrl).toBe('http://localhost:4001/authorize');
      expect(endpoints.tokenUrl).toBe('http://localhost:4001/token');
      expect(endpoints.revocationUrl).toBe('http://localhost:4001/token/revocation');
      expect(endpoints.registrationUrl).toBe('http://localhost:4001/register');
    });

    it('should return correct resource metadata URL', () => {
      const result = createMcpAuthProvider({
        oidcBaseUrl: 'http://localhost:4001',
        store: mockStore,
        mcpServerBaseUrl: 'http://localhost:3001',
      });

      expect(result.resourceMetadataUrl).toBe(
        'http://localhost:3001/.well-known/oauth-protected-resource'
      );
    });

    it('should use custom scopes if provided', () => {
      const customScopes = ['openid', 'custom:scope'];
      const result = createMcpAuthProvider({
        oidcBaseUrl: 'http://localhost:4001',
        store: mockStore,
        mcpServerBaseUrl: 'http://localhost:3001',
        scopesSupported: customScopes,
      });

      expect(result.proxyOAuthServerProviderConfig).toBeDefined();
      // The scopes are used internally in the routes
    });

    it('should use custom MCP endpoint path', () => {
      const result = createMcpAuthProvider({
        oidcBaseUrl: 'http://localhost:4001',
        store: mockStore,
        mcpServerBaseUrl: 'http://localhost:3001',
        mcpEndpointPath: '/custom-mcp',
      });

      // The path is used in the protected resource metadata
      expect(result.resourceMetadataUrl).toBe(
        'http://localhost:3001/.well-known/oauth-protected-resource'
      );
    });

    describe('verifyAccessToken', () => {
      it('should verify a valid token', async () => {
        const { jwtVerify } = await import('jose');
        vi.mocked(jwtVerify).mockResolvedValue({
          payload: {
            sub: 'user-123',
            client_id: 'client-123',
            scope: 'openid email',
            exp: Math.floor(Date.now() / 1000) + 3600,
          },
          protectedHeader: { alg: 'RS256' },
          key: {} as CryptoKey,
        });

        const result = createMcpAuthProvider({
          oidcBaseUrl: 'http://localhost:4001',
          store: mockStore,
          mcpServerBaseUrl: 'http://localhost:3001',
        });

        const authInfo =
          await result.proxyOAuthServerProviderConfig.verifyAccessToken('valid-token');

        expect(authInfo.token).toBe('valid-token');
        expect(authInfo.clientId).toBe('client-123');
        expect(authInfo.scopes).toEqual(['openid', 'email']);
      });

      it('should throw InvalidTokenError for invalid token', async () => {
        const { jwtVerify } = await import('jose');
        vi.mocked(jwtVerify).mockRejectedValue(new Error('Invalid token'));

        const result = createMcpAuthProvider({
          oidcBaseUrl: 'http://localhost:4001',
          store: mockStore,
          mcpServerBaseUrl: 'http://localhost:3001',
        });

        await expect(
          result.proxyOAuthServerProviderConfig.verifyAccessToken('invalid-token')
        ).rejects.toThrow(InvalidTokenError);
      });

      it('should call onVerifyError callback when token verification fails', async () => {
        const { jwtVerify } = await import('jose');
        const originalError = new Error('JWT verification failed');
        vi.mocked(jwtVerify).mockRejectedValue(originalError);

        const onVerifyError = vi.fn();
        const result = createMcpAuthProvider({
          oidcBaseUrl: 'http://localhost:4001',
          store: mockStore,
          mcpServerBaseUrl: 'http://localhost:3001',
          onVerifyError,
        });

        await expect(
          result.proxyOAuthServerProviderConfig.verifyAccessToken('invalid-token')
        ).rejects.toThrow(InvalidTokenError);

        expect(onVerifyError).toHaveBeenCalledWith(originalError);
      });

      it('should include session data in extra', async () => {
        const { jwtVerify } = await import('jose');
        vi.mocked(jwtVerify).mockResolvedValue({
          payload: {
            sub: 'user-123',
            client_id: 'client-123',
            scope: 'openid',
          },
          protectedHeader: { alg: 'RS256' },
          key: {} as CryptoKey,
        });

        // Store a session
        storedData.set('user-sessions:user-123', {
          userId: 'user-123',
          claims: { email: 'test@example.com' },
          tokenSet: { accessToken: 'idp-access-token' },
          customData: { org: 'test-org' },
        });

        const result = createMcpAuthProvider({
          oidcBaseUrl: 'http://localhost:4001',
          store: mockStore,
          mcpServerBaseUrl: 'http://localhost:3001',
        });

        const authInfo =
          await result.proxyOAuthServerProviderConfig.verifyAccessToken('valid-token');

        expect(authInfo.extra?.sub).toBe('user-123');
      });
    });

    describe('getClient', () => {
      it('should return undefined for non-existent client', async () => {
        const result = createMcpAuthProvider({
          oidcBaseUrl: 'http://localhost:4001',
          store: mockStore,
          mcpServerBaseUrl: 'http://localhost:3001',
        });

        const client = await result.proxyOAuthServerProviderConfig.getClient('non-existent');

        expect(client).toBeUndefined();
      });

      it('should have a getClient function', () => {
        const result = createMcpAuthProvider({
          oidcBaseUrl: 'http://localhost:4001',
          store: mockStore,
          mcpServerBaseUrl: 'http://localhost:3001',
        });

        expect(result.proxyOAuthServerProviderConfig.getClient).toBeDefined();
        expect(typeof result.proxyOAuthServerProviderConfig.getClient).toBe('function');
      });
    });
  });

  describe('getIdpTokens', () => {
    it('should return undefined for null input', () => {
      expect(getIdpTokens(null)).toBeUndefined();
    });

    it('should return undefined for undefined input', () => {
      expect(getIdpTokens(undefined)).toBeUndefined();
    });

    it('should extract tokens from AuthenticatedUser (req.user)', () => {
      const user: AuthenticatedUser = {
        accountId: 'account-123',
        userId: 'user-123',
        claims: { sub: 'user-123' },
        tokenSet: {
          accessToken: 'access-token',
          idToken: 'id-token',
          refreshToken: 'refresh-token',
        },
      };

      const tokens = getIdpTokens(user);

      expect(tokens).toEqual({
        accessToken: 'access-token',
        idToken: 'id-token',
        refreshToken: 'refresh-token',
      });
    });

    it('should extract tokens from AuthInfo (req.auth)', () => {
      const authInfo: AuthInfo = {
        token: 'jwt-token',
        clientId: 'client-123',
        scopes: ['openid'],
        extra: {
          idpTokens: {
            accessToken: 'idp-access',
            idToken: 'idp-id',
            refreshToken: 'idp-refresh',
          },
        },
      };

      const tokens = getIdpTokens(authInfo);

      expect(tokens).toEqual({
        accessToken: 'idp-access',
        idToken: 'idp-id',
        refreshToken: 'idp-refresh',
      });
    });

    it('should return undefined if AuthInfo has no idpTokens in extra', () => {
      const authInfo: AuthInfo = {
        token: 'jwt-token',
        clientId: 'client-123',
        scopes: ['openid'],
        extra: {
          sub: 'user-123',
        },
      };

      const tokens = getIdpTokens(authInfo);

      expect(tokens).toBeUndefined();
    });

    it('should return undefined if AuthInfo has no extra', () => {
      const authInfo: AuthInfo = {
        token: 'jwt-token',
        clientId: 'client-123',
        scopes: ['openid'],
      };

      const tokens = getIdpTokens(authInfo);

      expect(tokens).toBeUndefined();
    });
  });

  describe('InvalidTokenError', () => {
    it('should create an error with correct name', () => {
      const error = new InvalidTokenError('Token expired');

      expect(error.name).toBe('InvalidTokenError');
      expect(error.message).toBe('Token expired');
      expect(error).toBeInstanceOf(Error);
    });
  });

  describe('mcpRoutes', () => {
    it('should return health status from /health endpoint', async () => {
      const result = createMcpAuthProvider({
        oidcBaseUrl: 'http://localhost:4001',
        store: mockStore,
        mcpServerBaseUrl: 'http://localhost:3001',
      });

      const app = express();
      app.use(result.mcpRoutes);

      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('ok');
      expect(response.body.timestamp).toBeDefined();
    });

    it('should return protected resource metadata from /.well-known/oauth-protected-resource', async () => {
      const result = createMcpAuthProvider({
        oidcBaseUrl: 'http://localhost:4001',
        store: mockStore,
        mcpServerBaseUrl: 'http://localhost:3001',
      });

      const app = express();
      app.use(result.mcpRoutes);

      const response = await request(app).get('/.well-known/oauth-protected-resource');

      expect(response.status).toBe(200);
      expect(response.body.resource).toBe('http://localhost:3001/mcp');
      expect(response.body.authorization_servers).toEqual(['http://localhost:4001']);
      expect(response.body.scopes_supported).toEqual([
        'openid',
        'email',
        'profile',
        'offline_access',
      ]);
      expect(response.body.bearer_methods_supported).toEqual(['header']);
    });

    it('should use custom MCP endpoint path in protected resource metadata', async () => {
      const result = createMcpAuthProvider({
        oidcBaseUrl: 'http://localhost:4001',
        store: mockStore,
        mcpServerBaseUrl: 'http://localhost:3001',
        mcpEndpointPath: '/custom-mcp',
        scopesSupported: ['openid', 'custom'],
      });

      const app = express();
      app.use(result.mcpRoutes);

      const response = await request(app).get('/.well-known/oauth-protected-resource');

      expect(response.status).toBe(200);
      expect(response.body.resource).toBe('http://localhost:3001/custom-mcp');
      expect(response.body.scopes_supported).toEqual(['openid', 'custom']);
    });

    it('should set CORS headers for allowed origins', async () => {
      const result = createMcpAuthProvider({
        oidcBaseUrl: 'http://localhost:4001',
        store: mockStore,
        mcpServerBaseUrl: 'http://localhost:3001',
      });

      const app = express();
      app.use(result.mcpRoutes);

      // MCP Inspector origin should be allowed by default
      const response = await request(app).get('/health').set('Origin', 'http://localhost:6274');

      expect(response.headers['access-control-allow-origin']).toBe('http://localhost:6274');
      expect(response.headers['access-control-allow-credentials']).toBe('true');
    });

    it('should respond to OPTIONS preflight requests', async () => {
      const result = createMcpAuthProvider({
        oidcBaseUrl: 'http://localhost:4001',
        store: mockStore,
        mcpServerBaseUrl: 'http://localhost:3001',
      });

      const app = express();
      app.use(result.mcpRoutes);

      const response = await request(app).options('/health').set('Origin', 'http://localhost:6274');

      expect(response.status).toBe(204);
      expect(response.headers['access-control-allow-methods']).toContain('GET');
    });
  });
});
