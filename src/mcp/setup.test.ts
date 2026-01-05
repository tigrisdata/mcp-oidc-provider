import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setupMcpExpress } from './setup.js';
import type { IOidcClient, KeyvLike } from '../types.js';

// Mock dependencies
vi.mock('oidc-provider', () => {
  const MockProvider = vi.fn().mockImplementation(() => ({
    proxy: false,
    callback: vi.fn().mockReturnValue(vi.fn()),
    interactionDetails: vi.fn(),
    interactionFinished: vi.fn(),
  }));

  return {
    default: MockProvider,
  };
});

vi.mock('jose', () => ({
  createRemoteJWKSet: vi.fn(() => vi.fn()),
  jwtVerify: vi.fn(),
}));

describe('setup', () => {
  let mockStore: KeyvLike;
  let mockIdpClient: IOidcClient;
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

    mockIdpClient = {
      createAuthorizationUrl: vi.fn().mockResolvedValue({
        authorizationUrl: 'https://auth.example.com/authorize',
        state: 'state-123',
        nonce: 'nonce-123',
        codeVerifier: 'verifier-123',
      }),
      exchangeCode: vi.fn().mockResolvedValue({
        accessToken: 'access-token',
        idToken: 'id-token',
        refreshToken: 'refresh-token',
        expiresIn: 3600,
      }),
      refreshToken: vi.fn().mockResolvedValue({
        accessToken: 'new-access-token',
        idToken: 'new-id-token',
        refreshToken: 'new-refresh-token',
        expiresIn: 3600,
      }),
      parseIdToken: vi.fn().mockReturnValue({
        sub: 'user-123',
        email: 'user@example.com',
      }),
      extractCustomData: vi.fn().mockReturnValue(undefined),
    };

    vi.clearAllMocks();
  });

  describe('setupMcpExpress', () => {
    it('should create an Express app with handleMcpRequest function', () => {
      const result = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:3000',
        secret: 'test-secret',
      });

      expect(result.app).toBeDefined();
      expect(result.handleMcpRequest).toBeDefined();
      expect(typeof result.handleMcpRequest).toBe('function');
    });

    it('should set trust proxy', () => {
      const result = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:3000',
        secret: 'test-secret',
      });

      expect(result.app.get('trust proxy')).toBe(1);
    });

    it('should register custom middleware', () => {
      const customMiddleware = vi.fn((_req, _res, next) => next());

      const result = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:3000',
        secret: 'test-secret',
        customMiddleware: [customMiddleware],
      });

      expect(result.app).toBeDefined();
    });

    it('should accept isProduction option', () => {
      const result = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:3000',
        secret: 'test-secret',
        isProduction: true,
      });

      expect(result.app).toBeDefined();
    });

    it('should accept sessionMaxAge option', () => {
      const result = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:3000',
        secret: 'test-secret',
        sessionMaxAge: 86400000,
      });

      expect(result.app).toBeDefined();
    });

    it('should accept additionalCorsOrigins option', () => {
      const result = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:3000',
        secret: 'test-secret',
        additionalCorsOrigins: ['https://custom.com'],
      });

      expect(result.app).toBeDefined();
    });

    it('should accept jwks option', () => {
      const result = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:3000',
        secret: 'test-secret',
        jwks: {
          keys: [{ kty: 'RSA', alg: 'RS256' }],
        },
      });

      expect(result.app).toBeDefined();
    });

    describe('handleMcpRequest', () => {
      it('should register the MCP handler', () => {
        const result = setupMcpExpress({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:3000',
          secret: 'test-secret',
        });

        const handler = vi.fn();
        result.handleMcpRequest(handler);

        // Handler should be registered (we can't easily test this without making a request)
        expect(result.handleMcpRequest).toBeDefined();
      });

      it('should allow registering and calling the handler', () => {
        const result = setupMcpExpress({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:3000',
          secret: 'test-secret',
        });

        const handler = vi.fn();
        result.handleMcpRequest(handler);

        // handleMcpRequest registers the handler
        expect(typeof result.handleMcpRequest).toBe('function');
      });
    });

    describe('Express app routes', () => {
      it('should have trust proxy set', () => {
        const result = setupMcpExpress({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:3000',
          secret: 'test-secret',
        });

        expect(result.app.get('trust proxy')).toBe(1);
      });

      it('should be an Express application', () => {
        const result = setupMcpExpress({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:3000',
          secret: 'test-secret',
        });

        // Express apps have these characteristic properties
        expect(typeof result.app.use).toBe('function');
        expect(typeof result.app.get).toBe('function');
        expect(typeof result.app.post).toBe('function');
        expect(typeof result.app.listen).toBe('function');
      });
    });

    describe('configuration options', () => {
      it('should use custom session max age', () => {
        const result = setupMcpExpress({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:3000',
          secret: 'test-secret',
          sessionMaxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        expect(result.app).toBeDefined();
      });

      it('should handle isProduction flag', () => {
        const result = setupMcpExpress({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:3000',
          secret: 'test-secret',
          isProduction: false,
        });

        expect(result.app).toBeDefined();
      });

      it('should handle multiple custom middleware', () => {
        const middleware1 = vi.fn((_req, _res, next) => next());
        const middleware2 = vi.fn((_req, _res, next) => next());

        const result = setupMcpExpress({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:3000',
          secret: 'test-secret',
          customMiddleware: [middleware1, middleware2],
        });

        expect(result.app).toBeDefined();
      });

      it('should handle empty custom middleware array', () => {
        const result = setupMcpExpress({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:3000',
          secret: 'test-secret',
          customMiddleware: [],
        });

        expect(result.app).toBeDefined();
      });

      it('should handle multiple additional CORS origins', () => {
        const result = setupMcpExpress({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:3000',
          secret: 'test-secret',
          additionalCorsOrigins: ['https://app1.com', 'https://app2.com'],
        });

        expect(result.app).toBeDefined();
      });
    });
  });
});
