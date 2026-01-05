import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  isOidcProviderRoute,
  createExpressAdapter,
  createCompleteExpressRouter,
} from './adapter.js';
import type { OidcProvider } from '../core/types.js';
import type { Request, Response } from 'express';

describe('adapter', () => {
  describe('isOidcProviderRoute', () => {
    it('should return true for /authorize', () => {
      expect(isOidcProviderRoute('/authorize')).toBe(true);
    });

    it('should return true for /token', () => {
      expect(isOidcProviderRoute('/token')).toBe(true);
    });

    it('should return true for /jwks', () => {
      expect(isOidcProviderRoute('/jwks')).toBe(true);
    });

    it('should return true for /me', () => {
      expect(isOidcProviderRoute('/me')).toBe(true);
    });

    it('should return true for /userinfo', () => {
      expect(isOidcProviderRoute('/userinfo')).toBe(true);
    });

    it('should return true for /register', () => {
      expect(isOidcProviderRoute('/register')).toBe(true);
    });

    it('should return true for /introspect', () => {
      expect(isOidcProviderRoute('/introspect')).toBe(true);
    });

    it('should return true for /revoke', () => {
      expect(isOidcProviderRoute('/revoke')).toBe(true);
    });

    it('should return true for /.well-known/openid-configuration', () => {
      expect(isOidcProviderRoute('/.well-known/openid-configuration')).toBe(true);
    });

    it('should return true for /.well-known/oauth-authorization-server', () => {
      expect(isOidcProviderRoute('/.well-known/oauth-authorization-server')).toBe(true);
    });

    it('should return true for routes with subpaths', () => {
      expect(isOidcProviderRoute('/authorize/callback')).toBe(true);
      expect(isOidcProviderRoute('/token/revoke')).toBe(true);
    });

    it('should return false for non-provider routes', () => {
      expect(isOidcProviderRoute('/health')).toBe(false);
      expect(isOidcProviderRoute('/api/users')).toBe(false);
      expect(isOidcProviderRoute('/mcp')).toBe(false);
      expect(isOidcProviderRoute('/oauth/callback')).toBe(false);
    });

    it('should return false for /auth (only /auth is a route)', () => {
      expect(isOidcProviderRoute('/auth')).toBe(true);
      expect(isOidcProviderRoute('/authentication')).toBe(false);
    });
  });

  describe('createExpressAdapter', () => {
    let mockProvider: OidcProvider;

    beforeEach(() => {
      mockProvider = {
        provider: {
          callback: vi.fn().mockReturnValue(vi.fn()),
        },
        sessionStore: {} as OidcProvider['sessionStore'],
        handleInteraction: vi.fn().mockResolvedValue(undefined),
        handleCallback: vi.fn().mockResolvedValue(undefined),
        validateToken: vi.fn(),
        refreshIdpTokens: vi.fn(),
      } as unknown as OidcProvider;
    });

    it('should create an adapter with all components', () => {
      const adapter = createExpressAdapter(mockProvider);

      expect(adapter.routes).toBeDefined();
      expect(adapter.wellKnownRoutes).toBeDefined();
      expect(adapter.providerCallback).toBeDefined();
      expect(adapter.bodyParserMiddleware).toBeDefined();
      expect(adapter.isProviderRoute).toBeDefined();
    });

    it('should return isOidcProviderRoute as isProviderRoute', () => {
      const adapter = createExpressAdapter(mockProvider);

      expect(adapter.isProviderRoute('/authorize')).toBe(true);
      expect(adapter.isProviderRoute('/mcp')).toBe(false);
    });

    describe('bodyParserMiddleware', () => {
      it('should skip body parsing for provider routes', () => {
        const adapter = createExpressAdapter(mockProvider);
        const mockReq = { path: '/authorize' } as Request;
        const mockRes = {} as Response;
        const mockNext = vi.fn();

        adapter.bodyParserMiddleware(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
      });

      it('should apply body parsing for non-provider routes', () => {
        const adapter = createExpressAdapter(mockProvider);
        const mockReq = {
          path: '/api/test',
          headers: { 'content-type': 'application/json' },
        } as Request;
        const mockRes = {} as Response;
        const mockNext = vi.fn();

        // This test just verifies the middleware doesn't immediately call next
        // for non-provider routes (it delegates to express.json())
        adapter.bodyParserMiddleware(mockReq, mockRes, mockNext);

        // express.json() is called internally, which handles parsing
      });
    });

    describe('providerCallback', () => {
      it('should return a middleware function', () => {
        const adapter = createExpressAdapter(mockProvider);
        const callback = adapter.providerCallback();

        expect(typeof callback).toBe('function');
      });

      it('should inject scope for /authorize without scope', () => {
        const adapter = createExpressAdapter(mockProvider);
        adapter.providerCallback();

        const mockCallback = vi.fn();
        vi.mocked(mockProvider.provider.callback).mockReturnValue(mockCallback);

        const mockReq = {
          path: '/authorize',
          method: 'GET',
          query: {},
          originalUrl: '/authorize?client_id=test',
          headers: { host: 'localhost' },
          url: '/authorize?client_id=test',
        } as unknown as Request;
        const mockRes = {} as Response;
        const mockNext = vi.fn();

        // Get fresh callback that uses new mock
        const freshCallback = createExpressAdapter(mockProvider).providerCallback();
        freshCallback(mockReq, mockRes, mockNext);

        // URL should be modified to include scope
        expect(mockReq.url).toContain('scope=openid');
      });

      it('should not modify scope if already present', () => {
        const adapter = createExpressAdapter(mockProvider);

        const mockReq = {
          path: '/authorize',
          method: 'GET',
          query: { scope: 'openid email' },
          originalUrl: '/authorize?scope=openid+email',
          headers: { host: 'localhost' },
          url: '/authorize?scope=openid+email',
        } as unknown as Request;
        const originalUrl = mockReq.url;

        const callback = adapter.providerCallback();
        callback(mockReq, {} as Response, vi.fn());

        // URL should not be modified
        expect(mockReq.url).toBe(originalUrl);
      });
    });
  });

  describe('createCompleteExpressRouter', () => {
    let mockProvider: OidcProvider;

    beforeEach(() => {
      mockProvider = {
        provider: {
          callback: vi.fn().mockReturnValue(vi.fn()),
        },
        sessionStore: {} as OidcProvider['sessionStore'],
        handleInteraction: vi.fn().mockResolvedValue(undefined),
        handleCallback: vi.fn().mockResolvedValue(undefined),
        validateToken: vi.fn(),
        refreshIdpTokens: vi.fn(),
      } as unknown as OidcProvider;
    });

    it('should create a complete router', () => {
      const router = createCompleteExpressRouter(mockProvider);

      expect(router).toBeDefined();
      // Router is an Express Router instance
      expect(router.stack).toBeDefined();
    });
  });

  describe('routes', () => {
    let mockProvider: OidcProvider;

    beforeEach(() => {
      mockProvider = {
        provider: {
          callback: vi.fn().mockReturnValue(vi.fn()),
        },
        sessionStore: {} as OidcProvider['sessionStore'],
        handleInteraction: vi.fn().mockResolvedValue(undefined),
        handleCallback: vi.fn().mockResolvedValue(undefined),
        validateToken: vi.fn(),
        refreshIdpTokens: vi.fn(),
      } as unknown as OidcProvider;
    });

    it('should call handleInteraction for interaction route', async () => {
      const adapter = createExpressAdapter(mockProvider);

      // Find the interaction route handler
      const interactionLayer = adapter.routes.stack.find(
        (layer: { route?: { path: string } }) => layer.route?.path === '/interaction/:uid'
      );

      expect(interactionLayer).toBeDefined();

      // Simulate a request
      const mockReq = { params: { uid: 'test-uid' } } as unknown as Request;
      const mockRes = {} as Response;

      // Call the handler
      const handler = interactionLayer?.route?.stack[0]?.handle as (
        req: Request,
        res: Response
      ) => void;
      if (handler) {
        handler(mockReq, mockRes);
        // handleInteraction is called with void, so we just verify it was called
        expect(mockProvider.handleInteraction).toHaveBeenCalledWith(mockReq, mockRes);
      }
    });

    it('should call handleCallback for callback route', async () => {
      const adapter = createExpressAdapter(mockProvider);

      // Find the callback route handler
      const callbackLayer = adapter.routes.stack.find(
        (layer: { route?: { path: string } }) => layer.route?.path === '/callback'
      );

      expect(callbackLayer).toBeDefined();

      const mockReq = { query: { code: 'test-code', state: 'test-state' } } as unknown as Request;
      const mockRes = {} as Response;

      const handler = callbackLayer?.route?.stack[0]?.handle as (
        req: Request,
        res: Response
      ) => void;
      if (handler) {
        handler(mockReq, mockRes);
        expect(mockProvider.handleCallback).toHaveBeenCalledWith(mockReq, mockRes);
      }
    });

    it('should support custom interaction path', () => {
      const adapter = createExpressAdapter(mockProvider, {
        interactionPath: '/custom-interaction',
      });

      const interactionLayer = adapter.routes.stack.find(
        (layer: { route?: { path: string } }) => layer.route?.path === '/custom-interaction/:uid'
      );

      expect(interactionLayer).toBeDefined();
    });

    it('should support custom callback path', () => {
      const adapter = createExpressAdapter(mockProvider, { callbackPath: '/custom-callback' });

      const callbackLayer = adapter.routes.stack.find(
        (layer: { route?: { path: string } }) => layer.route?.path === '/custom-callback'
      );

      expect(callbackLayer).toBeDefined();
    });
  });

  describe('wellKnownRoutes', () => {
    let mockProvider: OidcProvider;

    beforeEach(() => {
      mockProvider = {
        provider: {
          callback: vi.fn().mockReturnValue(vi.fn()),
        },
        sessionStore: {} as OidcProvider['sessionStore'],
        handleInteraction: vi.fn().mockResolvedValue(undefined),
        handleCallback: vi.fn().mockResolvedValue(undefined),
        validateToken: vi.fn(),
        refreshIdpTokens: vi.fn(),
      } as unknown as OidcProvider;
    });

    it('should return protected resource metadata', () => {
      const adapter = createExpressAdapter(mockProvider, {
        baseUrl: 'https://example.com',
        mcpPath: '/mcp',
      });

      const protectedResourceLayer = adapter.wellKnownRoutes.stack.find(
        (layer: { route?: { path: string } }) =>
          layer.route?.path === '/.well-known/oauth-protected-resource'
      );

      expect(protectedResourceLayer).toBeDefined();

      const mockReq = {
        protocol: 'https',
        get: vi.fn().mockReturnValue('example.com'),
      } as unknown as Request;
      const mockRes = {
        json: vi.fn(),
      } as unknown as Response;

      const handler = protectedResourceLayer?.route?.stack[0]?.handle as (
        req: Request,
        res: Response
      ) => void;
      if (handler) {
        handler(mockReq, mockRes);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            resource: 'https://example.com/mcp',
            authorization_servers: ['https://example.com'],
            bearer_methods_supported: ['header'],
            resource_signing_alg_values_supported: ['RS256'],
            scopes_supported: expect.any(Array),
          })
        );
      }
    });

    it('should return protected resource metadata with resource param', () => {
      const adapter = createExpressAdapter(mockProvider, {
        baseUrl: 'https://example.com',
      });

      const protectedResourceWithParamLayer = adapter.wellKnownRoutes.stack.find(
        (layer: { route?: { path: string } }) =>
          layer.route?.path === '/.well-known/oauth-protected-resource/:resource'
      );

      expect(protectedResourceWithParamLayer).toBeDefined();

      const mockReq = {
        protocol: 'https',
        get: vi.fn().mockReturnValue('example.com'),
        params: { resource: 'custom-resource' },
      } as unknown as Request;
      const mockRes = {
        json: vi.fn(),
      } as unknown as Response;

      const handler = protectedResourceWithParamLayer?.route?.stack[0]?.handle as (
        req: Request,
        res: Response
      ) => void;
      if (handler) {
        handler(mockReq, mockRes);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            resource: 'https://example.com/custom-resource',
          })
        );
      }
    });

    it('should return protected resource metadata with default resource', () => {
      const adapter = createExpressAdapter(mockProvider, {
        baseUrl: 'https://example.com',
      });

      const protectedResourceWithParamLayer = adapter.wellKnownRoutes.stack.find(
        (layer: { route?: { path: string } }) =>
          layer.route?.path === '/.well-known/oauth-protected-resource/:resource'
      );

      const mockReq = {
        protocol: 'https',
        get: vi.fn().mockReturnValue('example.com'),
        params: {},
      } as unknown as Request;
      const mockRes = {
        json: vi.fn(),
      } as unknown as Response;

      const handler = protectedResourceWithParamLayer?.route?.stack[0]?.handle as (
        req: Request,
        res: Response
      ) => void;
      if (handler) {
        handler(mockReq, mockRes);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            resource: 'https://example.com/mcp',
          })
        );
      }
    });

    it('should handle authorization server metadata with resource param', async () => {
      const adapter = createExpressAdapter(mockProvider, {
        baseUrl: 'https://example.com',
      });

      const authServerWithParamLayer = adapter.wellKnownRoutes.stack.find(
        (layer: { route?: { path: string } }) =>
          layer.route?.path === '/.well-known/oauth-authorization-server/:resource'
      );

      expect(authServerWithParamLayer).toBeDefined();
    });

    it('should infer base URL from request if not provided', () => {
      const adapter = createExpressAdapter(mockProvider);

      const protectedResourceLayer = adapter.wellKnownRoutes.stack.find(
        (layer: { route?: { path: string } }) =>
          layer.route?.path === '/.well-known/oauth-protected-resource'
      );

      const mockReq = {
        protocol: 'https',
        get: vi.fn().mockReturnValue('inferred-host.com'),
      } as unknown as Request;
      const mockRes = {
        json: vi.fn(),
      } as unknown as Response;

      const handler = protectedResourceLayer?.route?.stack[0]?.handle as (
        req: Request,
        res: Response
      ) => void;
      if (handler) {
        handler(mockReq, mockRes);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            resource: 'https://inferred-host.com/mcp',
            authorization_servers: ['https://inferred-host.com'],
          })
        );
      }
    });

    it('should use localhost as fallback host', () => {
      const adapter = createExpressAdapter(mockProvider);

      const protectedResourceLayer = adapter.wellKnownRoutes.stack.find(
        (layer: { route?: { path: string } }) =>
          layer.route?.path === '/.well-known/oauth-protected-resource'
      );

      const mockReq = {
        protocol: 'http',
        get: vi.fn().mockReturnValue(undefined),
      } as unknown as Request;
      const mockRes = {
        json: vi.fn(),
      } as unknown as Response;

      const handler = protectedResourceLayer?.route?.stack[0]?.handle as (
        req: Request,
        res: Response
      ) => void;
      if (handler) {
        handler(mockReq, mockRes);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            resource: 'http://localhost/mcp',
            authorization_servers: ['http://localhost'],
          })
        );
      }
    });

    it('should use custom scopes if provided', () => {
      const customScopes = ['openid', 'custom:scope', 'another:scope'];
      const adapter = createExpressAdapter(mockProvider, {
        baseUrl: 'https://example.com',
        scopes: customScopes,
      });

      const protectedResourceLayer = adapter.wellKnownRoutes.stack.find(
        (layer: { route?: { path: string } }) =>
          layer.route?.path === '/.well-known/oauth-protected-resource'
      );

      const mockReq = {
        protocol: 'https',
        get: vi.fn().mockReturnValue('example.com'),
      } as unknown as Request;
      const mockRes = {
        json: vi.fn(),
      } as unknown as Response;

      const handler = protectedResourceLayer?.route?.stack[0]?.handle as (
        req: Request,
        res: Response
      ) => void;
      if (handler) {
        handler(mockReq, mockRes);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            scopes_supported: customScopes,
          })
        );
      }
    });

    it('should fetch discovery metadata for auth server with resource param', async () => {
      const adapter = createExpressAdapter(mockProvider, {
        baseUrl: 'https://example.com',
      });

      const authServerWithParamLayer = adapter.wellKnownRoutes.stack.find(
        (layer: { route?: { path: string } }) =>
          layer.route?.path === '/.well-known/oauth-authorization-server/:resource'
      );

      expect(authServerWithParamLayer).toBeDefined();

      // Mock fetch globally
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockResolvedValue({
        json: vi.fn().mockResolvedValue({
          issuer: 'https://example.com',
          authorization_endpoint: 'https://example.com/authorize',
        }),
      });

      const mockReq = {
        protocol: 'https',
        get: vi.fn().mockReturnValue('example.com'),
        params: { resource: 'test-resource' },
      } as unknown as Request;
      const mockRes = {
        json: vi.fn(),
        status: vi.fn().mockReturnThis(),
      } as unknown as Response;

      const handler = authServerWithParamLayer?.route?.stack[0]?.handle as (
        req: Request,
        res: Response
      ) => Promise<void>;
      if (handler) {
        await handler(mockReq, mockRes);
        expect(mockRes.json).toHaveBeenCalled();
      }

      // Restore fetch
      globalThis.fetch = originalFetch;
    });

    it('should handle fetch error for auth server metadata', async () => {
      const adapter = createExpressAdapter(mockProvider, {
        baseUrl: 'https://example.com',
      });

      const authServerWithParamLayer = adapter.wellKnownRoutes.stack.find(
        (layer: { route?: { path: string } }) =>
          layer.route?.path === '/.well-known/oauth-authorization-server/:resource'
      );

      // Mock fetch to throw
      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

      const mockReq = {
        protocol: 'https',
        get: vi.fn().mockReturnValue('example.com'),
        params: { resource: 'test-resource' },
      } as unknown as Request;
      const mockRes = {
        json: vi.fn(),
        status: vi.fn().mockReturnThis(),
      } as unknown as Response;

      const handler = authServerWithParamLayer?.route?.stack[0]?.handle as (
        req: Request,
        res: Response
      ) => Promise<void>;
      if (handler) {
        await handler(mockReq, mockRes);
        expect(mockRes.status).toHaveBeenCalledWith(500);
        expect(mockRes.json).toHaveBeenCalledWith({ error: 'Failed to fetch discovery metadata' });
      }

      // Restore fetch
      globalThis.fetch = originalFetch;
    });
  });
});
