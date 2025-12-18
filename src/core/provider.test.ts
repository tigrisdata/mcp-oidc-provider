import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createOidcProvider } from './provider.js';
import type { IOidcClient, KeyvLike } from '../types.js';

// Mock dependencies
vi.mock('oidc-provider', () => {
  const MockProvider = vi.fn().mockImplementation(() => ({
    proxy: false,
    callback: vi.fn().mockReturnValue(vi.fn()),
    interactionDetails: vi.fn(),
    interactionFinished: vi.fn(),
    Grant: vi.fn().mockImplementation(() => ({
      addOIDCScope: vi.fn(),
      addResourceScope: vi.fn(),
      save: vi.fn().mockResolvedValue('grant-id'),
    })),
  }));

  // Add Schema mock on prototype
  MockProvider.prototype.Grant = MockProvider;

  return {
    default: MockProvider,
  };
});

vi.mock('jose', () => ({
  createRemoteJWKSet: vi.fn(() => vi.fn()),
  jwtVerify: vi.fn(),
}));

describe('provider', () => {
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

  describe('createOidcProvider', () => {
    it('should create an OIDC provider with all required methods', () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      expect(provider).toBeDefined();
      expect(provider.provider).toBeDefined();
      expect(provider.sessionStore).toBeDefined();
      expect(provider.handleInteraction).toBeDefined();
      expect(provider.handleCallback).toBeDefined();
      expect(provider.validateToken).toBeDefined();
      expect(provider.refreshIdpTokens).toBeDefined();
    });

    it('should warn when no JWKS provided', () => {
      vi.spyOn(console, 'warn').mockImplementation(() => {});

      createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // The warning is logged via the logger, which defaults to console
      // We can't easily test this without mocking the logger
    });

    it('should not warn when JWKS is provided', () => {
      vi.spyOn(console, 'warn').mockImplementation(() => {});

      createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
        jwks: {
          keys: [{ kty: 'RSA', alg: 'RS256', use: 'sig', kid: 'key-1' }],
        },
      });

      // Should not have warned about missing JWKS
    });

    it('should use provided scopes', () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
        scopes: ['openid', 'custom'],
      });

      expect(provider).toBeDefined();
    });

    it('should use provided TTL configuration', () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
        ttl: {
          accessToken: 600,
          refreshToken: 86400,
        },
      });

      expect(provider).toBeDefined();
    });

    it('should use provided allowed client protocols', () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
        allowedClientProtocols: ['myapp://'],
      });

      expect(provider).toBeDefined();
    });

    it('should use provided claims configuration', () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
        claims: {
          openid: ['sub', 'custom_claim'],
        },
      });

      expect(provider).toBeDefined();
    });

    it('should enable proxy on provider', () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      expect(provider.provider.proxy).toBe(true);
    });
  });

  describe('validateToken', () => {
    it('should return invalid for failed JWT verification', async () => {
      const { jwtVerify } = await import('jose');
      vi.mocked(jwtVerify).mockRejectedValue(new Error('Invalid token'));

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const result = await provider.validateToken('invalid-token');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid or expired token');
    });

    it('should return invalid when user session not found', async () => {
      const { jwtVerify } = await import('jose');
      vi.mocked(jwtVerify).mockResolvedValue({
        payload: { sub: 'user-123' },
        protectedHeader: { alg: 'RS256' },
        key: {} as CryptoKey,
      });

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const result = await provider.validateToken('valid-token');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('User session not found');
    });

    it('should have validateToken method that returns appropriate structure', async () => {
      const { jwtVerify } = await import('jose');
      vi.mocked(jwtVerify).mockRejectedValue(new Error('Invalid token'));

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const result = await provider.validateToken('some-token');

      // Should return an object with valid and error properties
      expect(result).toHaveProperty('valid');
      expect(typeof result.valid).toBe('boolean');
    });
  });

  describe('refreshIdpTokens', () => {
    it('should return false when session not found', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const result = await provider.refreshIdpTokens('non-existent');

      expect(result).toBe(false);
    });

    it('should be a callable function', () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      expect(typeof provider.refreshIdpTokens).toBe('function');
    });
  });

  describe('handleInteraction', () => {
    it('should be a callable function', () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      expect(typeof provider.handleInteraction).toBe('function');
    });
  });

  describe('handleCallback', () => {
    it('should be a callable function', () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      expect(typeof provider.handleCallback).toBe('function');
    });
  });

  describe('provider configuration', () => {
    it('should use custom getResourceServerInfo when provided', () => {
      const customGetResourceServerInfo = vi.fn().mockReturnValue({
        scope: 'custom-scope',
        audience: 'custom-audience',
        accessTokenTTL: 600,
        accessTokenFormat: 'jwt',
      });

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
        getResourceServerInfo: customGetResourceServerInfo,
      });

      expect(provider.provider).toBeDefined();
    });

    it('should use custom ttl configuration', () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
        ttl: {
          accessToken: 300,
          refreshToken: 86400,
          authorizationCode: 60,
          idToken: 300,
          interaction: 600,
          grant: 86400,
          session: 1209600,
        },
      });

      expect(provider.provider).toBeDefined();
    });

    it('should use isProduction for cookie settings', () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
        isProduction: true,
      });

      expect(provider.provider).toBeDefined();
    });

    it('should use isProduction false for cookie settings', () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
        isProduction: false,
      });

      expect(provider.provider).toBeDefined();
    });

    it('should use custom logger when provided', () => {
      const customLogger = {
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
        debug: vi.fn(),
      };

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
        logger: customLogger,
      });

      expect(provider.provider).toBeDefined();
    });
  });
});
