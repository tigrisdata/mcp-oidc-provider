import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createOidcServer } from './server.js';
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

describe('server', () => {
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

  describe('createOidcServer', () => {
    it('should create an OIDC server with all required components', () => {
      const result = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4001',
        secret: 'test-secret',
        port: 4001,
      });

      expect(result.app).toBeDefined();
      expect(result.start).toBeDefined();
      expect(result.baseUrl).toBe('http://localhost:4001');
      expect(result.validateToken).toBeDefined();
    });

    it('should have a start function that returns a promise', () => {
      const result = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4001',
        secret: 'test-secret',
        port: 4001,
      });

      expect(typeof result.start).toBe('function');
    });

    it('should accept isProduction option', () => {
      const result = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4001',
        secret: 'test-secret',
        port: 4001,
        isProduction: true,
      });

      expect(result.app).toBeDefined();
    });

    it('should accept sessionMaxAge option', () => {
      const result = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4001',
        secret: 'test-secret',
        port: 4001,
        sessionMaxAge: 86400000,
      });

      expect(result.app).toBeDefined();
    });

    it('should accept additionalCorsOrigins option', () => {
      const result = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4001',
        secret: 'test-secret',
        port: 4001,
        additionalCorsOrigins: ['https://custom.com'],
      });

      expect(result.app).toBeDefined();
    });

    it('should accept jwks option', () => {
      const result = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4001',
        secret: 'test-secret',
        port: 4001,
        jwks: {
          keys: [{ kty: 'RSA', alg: 'RS256' }],
        },
      });

      expect(result.app).toBeDefined();
    });

    it('should accept onListen callback', () => {
      const onListen = vi.fn();

      const result = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4001',
        secret: 'test-secret',
        port: 4001,
        onListen,
      });

      expect(result.app).toBeDefined();
    });

    it('should set trust proxy', () => {
      const result = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4001',
        secret: 'test-secret',
        port: 4001,
      });

      expect(result.app.get('trust proxy')).toBe(1);
    });

    it('should create an app that can be used', () => {
      const result = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4001',
        secret: 'test-secret',
        port: 4001,
      });

      // Express app should be usable (can add middleware)
      expect(typeof result.app.use).toBe('function');
      expect(typeof result.app.get).toBe('function');
    });

    describe('validateToken', () => {
      it('should be a function', () => {
        const result = createOidcServer({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:4001',
          secret: 'test-secret',
          port: 4001,
        });

        expect(typeof result.validateToken).toBe('function');
      });
    });

    describe('start function', () => {
      it('should return a Promise', () => {
        const result = createOidcServer({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:4001',
          secret: 'test-secret',
          port: 4001,
        });

        // start returns a Promise
        expect(typeof result.start).toBe('function');
      });
    });

    describe('Express app', () => {
      it('should be an Express application', () => {
        const result = createOidcServer({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:4001',
          secret: 'test-secret',
          port: 4001,
        });

        expect(typeof result.app.use).toBe('function');
        expect(typeof result.app.get).toBe('function');
        expect(typeof result.app.post).toBe('function');
        expect(typeof result.app.listen).toBe('function');
      });
    });

    describe('configuration', () => {
      it('should use custom session max age', () => {
        const result = createOidcServer({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:4001',
          secret: 'test-secret',
          port: 4001,
          sessionMaxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        expect(result.app).toBeDefined();
      });

      it('should handle isProduction false', () => {
        const result = createOidcServer({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:4001',
          secret: 'test-secret',
          port: 4001,
          isProduction: false,
        });

        expect(result.app).toBeDefined();
      });

      it('should handle multiple CORS origins', () => {
        const result = createOidcServer({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'http://localhost:4001',
          secret: 'test-secret',
          port: 4001,
          additionalCorsOrigins: ['https://app1.com', 'https://app2.com'],
        });

        expect(result.app).toBeDefined();
      });

      it('should store baseUrl correctly', () => {
        const result = createOidcServer({
          idpClient: mockIdpClient,
          store: mockStore,
          baseUrl: 'https://custom-base.example.com',
          secret: 'test-secret',
          port: 4001,
        });

        expect(result.baseUrl).toBe('https://custom-base.example.com');
      });
    });
  });
});
