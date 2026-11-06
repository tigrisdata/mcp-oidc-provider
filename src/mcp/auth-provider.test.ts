import { describe, it, expect, vi, beforeEach } from 'vitest';
import express, { type Router } from 'express';
import { OAuthError, type AuthInfo } from '@modelcontextprotocol/server';
import {
  createMcpAuthProvider,
  fetchAuthorizationServerMetadata,
  getIdpTokens,
  resourceFromAudience,
} from './auth-provider.js';
import { createMockStore, listen, storeUserSession } from '../test/helpers/index.js';
import type { KeyvLike } from '../types.js';

// Mock jose
vi.mock('jose', () => ({
  createRemoteJWKSet: vi.fn(() => vi.fn()),
  jwtVerify: vi.fn(),
}));

const MCP_BASE_URL = 'http://localhost:3001';

/**
 * Stand-in for the OIDC server: serves authorization server metadata whose
 * issuer is its own base URL (unless overridden) and counts the requests.
 */
const startOidcServer = async (options: { status?: number; issuer?: string } = {}) => {
  let hits = 0;
  const metadata: Record<string, unknown> = {};
  const app = express();
  app.get('/.well-known/oauth-authorization-server', (_req, res) => {
    hits += 1;
    res.status(options.status ?? 200).json(metadata);
  });
  const oidcBaseUrl = await listen(app);
  Object.assign(metadata, {
    issuer: options.issuer ?? oidcBaseUrl,
    authorization_endpoint: `${oidcBaseUrl}/authorize`,
    token_endpoint: `${oidcBaseUrl}/token`,
    response_types_supported: ['code'],
  });
  return { oidcBaseUrl, metadata, hits: () => hits };
};

describe('auth-provider', () => {
  let mockStore: KeyvLike;
  let storedData: Map<string, unknown>;
  let oidc: Awaited<ReturnType<typeof startOidcServer>>;

  beforeEach(async () => {
    ({ store: mockStore, storedData } = createMockStore());
    vi.clearAllMocks();
    oidc = await startOidcServer();
  });

  const createProvider = (overrides: Partial<Parameters<typeof createMcpAuthProvider>[0]> = {}) =>
    createMcpAuthProvider({
      oidcBaseUrl: oidc.oidcBaseUrl,
      store: mockStore,
      mcpServerBaseUrl: MCP_BASE_URL,
      ...overrides,
    });

  const serve = async (routes: Router): Promise<string> => {
    const app = express();
    app.use(routes);
    app.post('/mcp', (_req, res) => {
      res.json({ ok: true });
    });
    return listen(app);
  };

  const mockVerifiedPayload = async (payload: Record<string, unknown>) => {
    const { jwtVerify } = await import('jose');
    vi.mocked(jwtVerify).mockResolvedValue({
      payload,
      protectedHeader: { alg: 'RS256' },
      key: {} as CryptoKey,
    });
  };

  describe('createMcpAuthProvider', () => {
    it('should return a verifier, the metadata routes and the path-based resource metadata URL', async () => {
      const result = await createProvider();

      expect(typeof result.verifier.verifyAccessToken).toBe('function');
      expect(result.mcpRoutes).toBeDefined();
      expect(result.resourceMetadataUrl).toBe(
        'http://localhost:3001/.well-known/oauth-protected-resource/mcp'
      );
    });

    it('should fetch the authorization server metadata once, at creation', async () => {
      const baseUrl = await serve((await createProvider()).mcpRoutes);

      await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
      await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);

      expect(oidc.hits()).toBe(1);
    });

    it('should reject when the OIDC server does not serve its metadata', async () => {
      const { oidcBaseUrl } = await startOidcServer({ status: 500 });

      await expect(createProvider({ oidcBaseUrl })).rejects.toThrow(
        `Failed to fetch authorization server metadata from ${oidcBaseUrl}/.well-known/oauth-authorization-server: HTTP 500`
      );
    });

    it('should reject when the metadata issuer does not match oidcBaseUrl', async () => {
      const { oidcBaseUrl } = await startOidcServer({ issuer: 'https://other.example.com' });

      await expect(createProvider({ oidcBaseUrl })).rejects.toThrow(
        `Authorization server metadata issuer "https://other.example.com" does not match oidcBaseUrl "${oidcBaseUrl}"`
      );
    });
  });

  describe('fetchAuthorizationServerMetadata', () => {
    it('should return the metadata document', async () => {
      await expect(fetchAuthorizationServerMetadata(oidc.oidcBaseUrl)).resolves.toEqual(
        oidc.metadata
      );
    });
  });

  describe('verifyAccessToken', () => {
    it('should verify a valid token', async () => {
      await mockVerifiedPayload({
        sub: 'user-123',
        client_id: 'client-123',
        scope: 'openid email',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });

      const { verifier } = await createProvider();
      const authInfo = await verifier.verifyAccessToken('valid-token');

      expect(authInfo.token).toBe('valid-token');
      expect(authInfo.clientId).toBe('client-123');
      expect(authInfo.scopes).toEqual(['openid', 'email']);
    });

    it('should default clientId and scopes when the claims are missing', async () => {
      await mockVerifiedPayload({ sub: 'user-123' });

      const { verifier } = await createProvider();
      const authInfo = await verifier.verifyAccessToken('valid-token');

      expect(authInfo.clientId).toBe('');
      expect(authInfo.scopes).toEqual([]);
      expect(authInfo.resource).toBeUndefined();
    });

    it('should reject with the SDK OAuthError (invalid_token) for an invalid token', async () => {
      const { jwtVerify } = await import('jose');
      vi.mocked(jwtVerify).mockRejectedValue(new Error('Invalid token'));

      const { verifier } = await createProvider();
      const error: unknown = await verifier
        .verifyAccessToken('invalid-token')
        .catch((e: unknown) => e);

      expect(error).toBeInstanceOf(OAuthError);
      expect((error as OAuthError).code).toBe('invalid_token');
      expect((error as OAuthError).message).toBe('Invalid or expired token');
    });

    it('should expose expiry, resource and resource metadata URL from the token', async () => {
      const exp = Math.floor(Date.now() / 1000) + 3600;
      await mockVerifiedPayload({
        sub: 'user-123',
        client_id: 'client-123',
        scope: 'openid',
        exp,
        aud: ['not-a-url', 'http://localhost:3001/mcp'],
      });

      const { verifier } = await createProvider();
      const authInfo = await verifier.verifyAccessToken('valid-token');

      expect(authInfo.expiresAt).toBe(exp);
      expect(authInfo.resource?.href).toBe('http://localhost:3001/mcp');
      expect(authInfo.resourceMetadataUrl).toBe(
        'http://localhost:3001/.well-known/oauth-protected-resource/mcp'
      );
    });

    it('should call onVerifyError callback when token verification fails', async () => {
      const { jwtVerify } = await import('jose');
      const originalError = new Error('JWT verification failed');
      vi.mocked(jwtVerify).mockRejectedValue(originalError);

      const onVerifyError = vi.fn();
      const { verifier } = await createProvider({ onVerifyError });

      await expect(verifier.verifyAccessToken('invalid-token')).rejects.toThrow(
        'Invalid or expired token'
      );

      expect(onVerifyError).toHaveBeenCalledWith(originalError);
    });

    it('should include the user session in extra', async () => {
      await mockVerifiedPayload({ sub: 'user-123', client_id: 'client-123', scope: 'openid' });

      // Stored under the user-sessions namespace by the OIDC server
      const session = {
        userId: 'user-123',
        claims: { email: 'test@example.com' },
        tokenSet: { accessToken: 'idp-access-token' },
        customData: { org: 'test-org' },
      };
      storeUserSession(storedData, 'user-123', session);

      const { verifier } = await createProvider();
      const authInfo = await verifier.verifyAccessToken('valid-token');

      expect(authInfo.extra).toEqual({
        sub: 'user-123',
        claims: { email: 'test@example.com' },
        idpTokens: { accessToken: 'idp-access-token' },
        customData: { org: 'test-org' },
      });
    });

    it('should leave session fields undefined when no session is stored', async () => {
      await mockVerifiedPayload({ sub: 'user-404', client_id: 'client-123', scope: 'openid' });

      const { verifier } = await createProvider();
      const authInfo = await verifier.verifyAccessToken('valid-token');

      expect(authInfo.extra).toEqual({
        sub: 'user-404',
        claims: undefined,
        idpTokens: undefined,
        customData: undefined,
      });
    });
  });

  describe('getIdpTokens', () => {
    const baseAuthInfo: AuthInfo = {
      token: 'jwt-token',
      clientId: 'client-123',
      scopes: ['openid'],
    };

    it('should return undefined for null or undefined input', () => {
      expect(getIdpTokens(null)).toBeUndefined();
      expect(getIdpTokens(undefined)).toBeUndefined();
    });

    it('should extract the IdP token set from AuthInfo.extra', () => {
      const idpTokens = {
        accessToken: 'idp-access',
        idToken: 'idp-id',
        refreshToken: 'idp-refresh',
      };

      expect(getIdpTokens({ ...baseAuthInfo, extra: { idpTokens } })).toEqual(idpTokens);
    });

    it('should return undefined when extra has no idpTokens', () => {
      expect(getIdpTokens({ ...baseAuthInfo, extra: { sub: 'user-123' } })).toBeUndefined();
    });

    it('should return undefined when AuthInfo has no extra', () => {
      expect(getIdpTokens(baseAuthInfo)).toBeUndefined();
    });
  });

  describe('resourceFromAudience', () => {
    it('should return undefined when there is no audience', () => {
      expect(resourceFromAudience(undefined)).toBeUndefined();
      expect(resourceFromAudience(42)).toBeUndefined();
    });

    it('should return undefined when no audience is a URL', () => {
      expect(resourceFromAudience('api')).toBeUndefined();
      expect(resourceFromAudience(['api', 7])).toBeUndefined();
    });

    it('should pick the first URL audience', () => {
      expect(resourceFromAudience('https://mcp.example.com/mcp')?.href).toBe(
        'https://mcp.example.com/mcp'
      );
      expect(resourceFromAudience(['api', 'https://mcp.example.com/mcp'])?.href).toBe(
        'https://mcp.example.com/mcp'
      );
    });
  });

  describe('mcpRoutes', () => {
    it('should serve the protected resource metadata at the path-based well-known URL', async () => {
      const baseUrl = await serve((await createProvider()).mcpRoutes);

      const response = await fetch(`${baseUrl}/.well-known/oauth-protected-resource/mcp`);

      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({
        resource: 'http://localhost:3001/mcp',
        authorization_servers: [oidc.oidcBaseUrl],
        scopes_supported: ['openid', 'email', 'profile', 'offline_access'],
      });
    });

    it('should not serve a root protected resource document for a non-root MCP endpoint', async () => {
      const baseUrl = await serve((await createProvider()).mcpRoutes);

      const response = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`);

      expect(response.status).toBe(404);
    });

    it('should use the custom MCP endpoint path and scopes in the metadata', async () => {
      const provider = await createProvider({
        mcpEndpointPath: '/custom-mcp',
        scopesSupported: ['openid', 'custom'],
      });
      const baseUrl = await serve(provider.mcpRoutes);

      const response = await fetch(`${baseUrl}/.well-known/oauth-protected-resource/custom-mcp`);

      expect(provider.resourceMetadataUrl).toBe(
        'http://localhost:3001/.well-known/oauth-protected-resource/custom-mcp'
      );
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        resource: 'http://localhost:3001/custom-mcp',
        scopes_supported: ['openid', 'custom'],
      });
    });

    it('should serve the root protected resource document for a root MCP endpoint', async () => {
      const provider = await createProvider({ mcpEndpointPath: '/' });
      const baseUrl = await serve(provider.mcpRoutes);

      const response = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`);

      expect(provider.resourceMetadataUrl).toBe(
        'http://localhost:3001/.well-known/oauth-protected-resource'
      );
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ resource: 'http://localhost:3001/' });
    });

    it('should serve the authorization server metadata fetched from the OIDC server', async () => {
      const baseUrl = await serve((await createProvider()).mcpRoutes);

      const response = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);

      expect(response.status).toBe(200);
      expect(await response.json()).toEqual(oidc.metadata);
    });

    it('should allow any origin to read the metadata documents', async () => {
      const baseUrl = await serve((await createProvider()).mcpRoutes);

      const response = await fetch(`${baseUrl}/.well-known/oauth-protected-resource/mcp`, {
        headers: { Origin: 'https://client.example.com' },
      });
      const preflight = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`, {
        method: 'OPTIONS',
        headers: { Origin: 'https://client.example.com' },
      });

      expect(response.headers.get('access-control-allow-origin')).toBe('*');
      expect(preflight.status).toBe(204);
    });

    it('should set MCP CORS headers on the MCP endpoint for allowed origins', async () => {
      const baseUrl = await serve((await createProvider()).mcpRoutes);

      // MCP Inspector origin should be allowed by default
      const response = await fetch(`${baseUrl}/mcp`, {
        method: 'POST',
        headers: { Origin: 'http://localhost:6274' },
      });

      expect(response.status).toBe(200);
      expect(response.headers.get('access-control-allow-origin')).toBe('http://localhost:6274');
      expect(response.headers.get('access-control-allow-credentials')).toBe('true');
      expect(response.headers.get('access-control-expose-headers')).toContain('Mcp-Session-Id');
    });

    it('should respond to OPTIONS preflight requests on the MCP endpoint', async () => {
      const baseUrl = await serve((await createProvider()).mcpRoutes);

      const response = await fetch(`${baseUrl}/mcp`, {
        method: 'OPTIONS',
        headers: { Origin: 'http://localhost:6274' },
      });

      expect(response.status).toBe(204);
      expect(response.headers.get('access-control-allow-methods')).toContain('POST');
    });
  });
});
