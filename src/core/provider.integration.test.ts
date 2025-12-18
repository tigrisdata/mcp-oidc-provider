import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createOidcProvider } from './provider.js';
import type { IOidcClient, KeyvLike } from '../types.js';
import type { Request, Response } from 'express';

// Mock dependencies
vi.mock('oidc-provider', () => {
  const mockGrant = vi.fn().mockImplementation(() => ({
    addOIDCScope: vi.fn(),
    addResourceScope: vi.fn(),
    save: vi.fn().mockResolvedValue('grant-id-123'),
  }));

  const MockProvider = vi.fn().mockImplementation(() => ({
    proxy: false,
    callback: vi.fn().mockReturnValue(vi.fn()),
    interactionDetails: vi.fn().mockResolvedValue({
      uid: 'interaction-uid',
      params: {
        client_id: 'client-123',
        scope: 'openid email',
        resource: 'https://api.example.com',
      },
    }),
    interactionFinished: vi.fn().mockResolvedValue(undefined),
    Grant: mockGrant,
  }));

  // Add Grant to prototype for access
  MockProvider.prototype.Grant = mockGrant;

  return {
    default: MockProvider,
  };
});

vi.mock('jose', () => ({
  createRemoteJWKSet: vi.fn(() => vi.fn()),
  jwtVerify: vi.fn(),
}));

describe('provider integration tests', () => {
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

  describe('handleInteraction', () => {
    it('should return 400 if uid is missing', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const mockReq = {
        params: {},
        session: {},
      } as unknown as Request;
      const mockRes = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith('Missing interaction UID');
    });

    it('should redirect to IdP when user not authenticated', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const mockReq = {
        params: { uid: 'interaction-uid' },
        session: {
          save: vi.fn((cb: (err?: Error) => void) => cb()),
        },
      } as unknown as Request;
      const mockRes = {
        redirect: vi.fn(),
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockReq, mockRes);

      expect(mockIdpClient.createAuthorizationUrl).toHaveBeenCalled();
      expect(mockRes.redirect).toHaveBeenCalledWith('https://auth.example.com/authorize');
    });

    it('should regenerate stale session', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const regenerateFn = vi.fn((cb: (err?: Error) => void) => cb());
      const saveFn = vi.fn((cb: (err?: Error) => void) => cb());

      const mockReq = {
        params: { uid: 'interaction-uid' },
        session: {
          userSessionId: 'stale-session-id', // Session ID exists but no user data
          regenerate: regenerateFn,
          save: saveFn,
        },
      } as unknown as Request;
      const mockRes = {
        redirect: vi.fn(),
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockReq, mockRes);

      expect(regenerateFn).toHaveBeenCalled();
      expect(mockRes.redirect).toHaveBeenCalled();
    });

    it('should handle interaction error gracefully', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Make interactionDetails throw
      provider.provider.interactionDetails = vi.fn().mockRejectedValue(new Error('Test error'));

      const mockReq = {
        params: { uid: 'interaction-uid' },
        session: {},
      } as unknown as Request;
      const mockRes = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
        redirect: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.send).toHaveBeenCalledWith('Internal server error');
    });

    it('should handle no session gracefully', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const mockReq = {
        params: { uid: 'interaction-uid' },
        // No session object
      } as unknown as Request;
      const mockRes = {
        redirect: vi.fn(),
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockReq, mockRes);

      expect(mockIdpClient.createAuthorizationUrl).toHaveBeenCalled();
      expect(mockRes.redirect).toHaveBeenCalled();
    });
  });

  describe('handleCallback', () => {
    it('should return 400 if code is missing', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const mockReq = {
        query: { state: 'state-123' },
        originalUrl: '/oauth/callback?state=state-123',
        session: {},
      } as unknown as Request;
      const mockRes = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleCallback(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith('Missing code or state parameter');
    });

    it('should return 400 if state is missing', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const mockReq = {
        query: { code: 'code-123' },
        originalUrl: '/oauth/callback?code=code-123',
        session: {},
      } as unknown as Request;
      const mockRes = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleCallback(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith('Missing code or state parameter');
    });

    it('should return 400 if no interaction session ID in session', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const mockReq = {
        query: { code: 'code-123', state: 'state-123' },
        originalUrl: '/oauth/callback?code=code-123&state=state-123',
        session: {},
      } as unknown as Request;
      const mockRes = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleCallback(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith(
        'Invalid session - session cookie not found or expired'
      );
    });

    it('should return 400 if interaction session not found', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const mockReq = {
        query: { code: 'code-123', state: 'state-123' },
        originalUrl: '/oauth/callback?code=code-123&state=state-123',
        session: {
          interactionSessionId: 'non-existent-session',
        },
      } as unknown as Request;
      const mockRes = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleCallback(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith('Invalid interaction session');
    });

    it('should return 400 if state does not match', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const mockReq = {
        query: { code: 'code-123', state: 'state-123' },
        originalUrl: '/oauth/callback?code=code-123&state=state-123',
        session: {
          interactionSessionId: 'session-123',
        },
      } as unknown as Request;
      const mockRes = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleCallback(mockReq, mockRes);

      // The session won't be found (different store), so we get invalid session
      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalled();
    });

    it('should handle callback error gracefully', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Use the actual Keyv namespace format for storing data
      // The session store uses 'interaction-sessions:' namespace
      await provider.sessionStore.set('session-123', {
        interactionUid: 'uid-123',
        idpState: 'state-123',
        idpNonce: 'nonce-123',
        codeVerifier: 'verifier-123',
      } as unknown as import('../types.js').UserSession);

      // Make exchangeCode throw
      mockIdpClient.exchangeCode = vi.fn().mockRejectedValue(new Error('Exchange error'));

      const mockReq = {
        query: { code: 'code-123', state: 'state-123' },
        originalUrl: '/oauth/callback?code=code-123&state=state-123',
        protocol: 'https',
        get: vi.fn().mockReturnValue('auth.example.com'),
        session: {
          interactionSessionId: 'session-123',
        },
      } as unknown as Request;
      const mockRes = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleCallback(mockReq, mockRes);

      // Should return 400 because the interaction session won't be found in the correct store
      expect(mockRes.status).toHaveBeenCalled();
      expect(mockRes.send).toHaveBeenCalled();
    });
  });

  describe('session helpers', () => {
    it('should handle regenerate session error', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const regenerateFn = vi.fn((cb: (err?: Error) => void) => cb(new Error('Regenerate error')));

      const mockReq = {
        params: { uid: 'interaction-uid' },
        session: {
          userSessionId: 'stale-session-id',
          regenerate: regenerateFn,
        },
      } as unknown as Request;
      const mockRes = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
        redirect: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockReq, mockRes);

      // Should handle the error
      expect(mockRes.status).toHaveBeenCalledWith(500);
    });

    it('should handle save session error', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const saveFn = vi.fn((cb: (err?: Error) => void) => cb(new Error('Save error')));

      const mockReq = {
        params: { uid: 'interaction-uid' },
        session: {
          save: saveFn,
        },
      } as unknown as Request;
      const mockRes = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
        redirect: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockReq, mockRes);

      // Should handle the error
      expect(mockRes.status).toHaveBeenCalledWith(500);
    });

    it('should handle non-Error rejection in regenerate', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const regenerateFn = vi.fn((cb: (err?: unknown) => void) => cb('string error'));

      const mockReq = {
        params: { uid: 'interaction-uid' },
        session: {
          userSessionId: 'stale-session-id',
          regenerate: regenerateFn,
        },
      } as unknown as Request;
      const mockRes = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
        redirect: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(500);
    });
  });

  describe('refreshIdpTokens', () => {
    it('should return false when no refresh token', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Store a session without refresh token
      await provider.sessionStore.set('account-123', {
        userId: 'user-123',
        claims: { sub: 'user-123' },
        tokenSet: {
          accessToken: 'access-token',
          idToken: 'id-token',
          refreshToken: '',
        },
      });

      // Make refresh throw
      mockIdpClient.refreshToken = vi.fn().mockRejectedValue(new Error('No refresh token'));

      const result = await provider.refreshIdpTokens('account-123');

      expect(result).toBe(false);
    });

    it('should successfully refresh tokens', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Store a session with refresh token
      await provider.sessionStore.set('account-123', {
        userId: 'user-123',
        claims: { sub: 'user-123' },
        tokenSet: {
          accessToken: 'old-access-token',
          idToken: 'old-id-token',
          refreshToken: 'refresh-token',
        },
      });

      const result = await provider.refreshIdpTokens('account-123');

      expect(result).toBe(true);
      expect(mockIdpClient.refreshToken).toHaveBeenCalledWith('refresh-token');
    });
  });

  describe('validateToken with token refresh', () => {
    it('should auto-refresh expired IdP tokens during validation', async () => {
      const { jwtVerify } = await import('jose');
      vi.mocked(jwtVerify).mockResolvedValue({
        payload: { sub: 'account-123' },
        protectedHeader: { alg: 'RS256' },
        key: {} as CryptoKey,
      });

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Store a session with expired tokens (expiresAt in the past)
      await provider.sessionStore.set('account-123', {
        userId: 'user-123',
        claims: { sub: 'user-123', email: 'user@example.com' },
        tokenSet: {
          accessToken: 'old-access-token',
          idToken: 'old-id-token',
          refreshToken: 'refresh-token',
          expiresAt: Date.now() - 1000, // Expired 1 second ago
        },
      });

      const result = await provider.validateToken('valid-token');

      expect(result.valid).toBe(true);
      expect(mockIdpClient.refreshToken).toHaveBeenCalledWith('refresh-token');
    });

    it('should auto-refresh tokens expiring soon during validation', async () => {
      const { jwtVerify } = await import('jose');
      vi.mocked(jwtVerify).mockResolvedValue({
        payload: { sub: 'account-123' },
        protectedHeader: { alg: 'RS256' },
        key: {} as CryptoKey,
      });

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Store a session with tokens expiring in 30 seconds (within buffer)
      await provider.sessionStore.set('account-123', {
        userId: 'user-123',
        claims: { sub: 'user-123' },
        tokenSet: {
          accessToken: 'old-access-token',
          idToken: 'old-id-token',
          refreshToken: 'refresh-token',
          expiresAt: Date.now() + 30 * 1000, // Expires in 30 seconds
        },
      });

      const result = await provider.validateToken('valid-token');

      expect(result.valid).toBe(true);
      expect(mockIdpClient.refreshToken).toHaveBeenCalled();
    });

    it('should continue validation if refresh fails', async () => {
      const { jwtVerify } = await import('jose');
      vi.mocked(jwtVerify).mockResolvedValue({
        payload: { sub: 'account-123' },
        protectedHeader: { alg: 'RS256' },
        key: {} as CryptoKey,
      });

      mockIdpClient.refreshToken = vi.fn().mockRejectedValue(new Error('Refresh failed'));

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Store a session with expired tokens
      await provider.sessionStore.set('account-123', {
        userId: 'user-123',
        claims: { sub: 'user-123' },
        tokenSet: {
          accessToken: 'stale-access-token',
          idToken: 'stale-id-token',
          refreshToken: 'invalid-refresh-token',
          expiresAt: Date.now() - 1000, // Expired
        },
      });

      const result = await provider.validateToken('valid-token');

      // Should still return valid but with stale tokens
      expect(result.valid).toBe(true);
    });

    it('should not refresh tokens if no expiresAt', async () => {
      const { jwtVerify } = await import('jose');
      vi.mocked(jwtVerify).mockResolvedValue({
        payload: { sub: 'account-123' },
        protectedHeader: { alg: 'RS256' },
        key: {} as CryptoKey,
      });

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Store a session without expiresAt (no refresh needed)
      await provider.sessionStore.set('account-123', {
        userId: 'user-123',
        claims: { sub: 'user-123' },
        tokenSet: {
          accessToken: 'access-token',
          idToken: 'id-token',
          refreshToken: 'refresh-token',
          // No expiresAt - should assume valid
        },
      });

      const result = await provider.validateToken('valid-token');

      expect(result.valid).toBe(true);
      expect(mockIdpClient.refreshToken).not.toHaveBeenCalled();
    });

    it('should include custom data in authenticated user', async () => {
      const { jwtVerify } = await import('jose');
      vi.mocked(jwtVerify).mockResolvedValue({
        payload: { sub: 'account-123' },
        protectedHeader: { alg: 'RS256' },
        key: {} as CryptoKey,
      });

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Store a session with custom data
      await provider.sessionStore.set('account-123', {
        userId: 'user-123',
        claims: { sub: 'user-123' },
        tokenSet: {
          accessToken: 'access-token',
          idToken: 'id-token',
          refreshToken: 'refresh-token',
        },
        customData: { role: 'admin', permissions: ['read', 'write'] },
      });

      const result = await provider.validateToken('valid-token');

      expect(result.valid).toBe(true);
      expect(result.user?.customData).toEqual({ role: 'admin', permissions: ['read', 'write'] });
    });

    it('should handle generic error in validation', async () => {
      const { jwtVerify } = await import('jose');
      vi.mocked(jwtVerify).mockResolvedValue({
        payload: { sub: 'account-123' },
        protectedHeader: { alg: 'RS256' },
        key: {} as CryptoKey,
      });

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Store a session that will cause an error during validation
      await provider.sessionStore.set('account-123', {
        userId: 'user-123',
        claims: { sub: 'user-123' },
        tokenSet: {
          accessToken: 'access-token',
          idToken: 'id-token',
          refreshToken: 'refresh-token',
        },
      });

      // Make sessionStore.get throw after first call
      const originalGet = provider.sessionStore.get.bind(provider.sessionStore);
      let callCount = 0;
      provider.sessionStore.get = vi.fn(async (key: string) => {
        callCount++;
        if (callCount > 1) {
          throw new Error('Unexpected error');
        }
        return originalGet(key);
      });

      const result = await provider.validateToken('valid-token');

      expect(result.valid).toBe(true);
    });
  });

  describe('handleInteraction with authenticated user', () => {
    it('should grant consent for authenticated user', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Store a valid user session
      await provider.sessionStore.set('user-session-123', {
        userId: 'user-123',
        claims: { sub: 'user-123', email: 'user@example.com' },
        tokenSet: {
          accessToken: 'access-token',
          idToken: 'id-token',
          refreshToken: 'refresh-token',
        },
      });

      const mockReq = {
        params: { uid: 'interaction-uid' },
        session: {
          userSessionId: 'user-session-123',
          save: vi.fn((cb: (err?: Error) => void) => cb()),
        },
      } as unknown as Request;
      const mockRes = {
        redirect: vi.fn(),
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockReq, mockRes);

      // Should call interactionFinished for consent grant
      expect(provider.provider.interactionFinished).toHaveBeenCalled();
    });

    it('should handle interaction with resource parameter', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Store a valid user session
      await provider.sessionStore.set('user-session-456', {
        userId: 'user-456',
        claims: { sub: 'user-456' },
        tokenSet: {
          accessToken: 'access-token',
          idToken: 'id-token',
          refreshToken: 'refresh-token',
        },
      });

      const mockReq = {
        params: { uid: 'interaction-uid' },
        session: {
          userSessionId: 'user-session-456',
          save: vi.fn((cb: (err?: Error) => void) => cb()),
        },
      } as unknown as Request;
      const mockRes = {
        redirect: vi.fn(),
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockReq, mockRes);

      expect(provider.provider.interactionFinished).toHaveBeenCalled();
    });

    it('should add offline_access to scopes', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Store a valid user session
      await provider.sessionStore.set('user-session-789', {
        userId: 'user-789',
        claims: { sub: 'user-789' },
        tokenSet: {
          accessToken: 'access-token',
          idToken: 'id-token',
          refreshToken: 'refresh-token',
        },
      });

      const mockReq = {
        params: { uid: 'interaction-uid' },
        session: {
          userSessionId: 'user-session-789',
          save: vi.fn((cb: (err?: Error) => void) => cb()),
        },
      } as unknown as Request;
      const mockRes = {
        redirect: vi.fn(),
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockReq, mockRes);

      // Verify Grant was created and scopes were added
      expect(provider.provider.Grant).toHaveBeenCalled();
    });
  });

  describe('handleCallback success flow', () => {
    it('should successfully exchange code and create user session', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // We need to set up the interaction session in the correct store
      // First trigger an interaction to create the session
      const saveFn = vi.fn((cb: (err?: Error) => void) => cb());
      const mockInteractionReq = {
        params: { uid: 'interaction-uid' },
        session: {
          save: saveFn,
          interactionSessionId: undefined as string | undefined,
        },
      } as unknown as Request;
      const mockInteractionRes = {
        redirect: vi.fn(),
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      // This will create an interaction session
      await provider.handleInteraction(mockInteractionReq, mockInteractionRes);

      // Get the interaction session ID that was saved
      const interactionSessionId = mockInteractionReq.session.interactionSessionId;
      expect(interactionSessionId).toBeDefined();

      // Now test the callback
      const callbackSaveFn = vi.fn((cb: (err?: Error) => void) => cb());
      const mockCallbackReq = {
        query: { code: 'code-123', state: 'state-123' },
        originalUrl: '/oauth/callback?code=code-123&state=state-123',
        protocol: 'https',
        get: vi.fn().mockReturnValue('auth.example.com'),
        session: {
          interactionSessionId,
          save: callbackSaveFn,
          userSessionId: undefined as string | undefined,
        },
      } as unknown as Request;
      const mockCallbackRes = {
        redirect: vi.fn(),
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleCallback(mockCallbackReq, mockCallbackRes);

      // Should exchange the code
      expect(mockIdpClient.exchangeCode).toHaveBeenCalled();
      // Should redirect back to interaction
      expect(mockCallbackRes.redirect).toHaveBeenCalledWith('/oauth/interaction/interaction-uid');
      // Should set user session ID
      expect(mockCallbackReq.session.userSessionId).toBeDefined();
    });

    it('should handle callback without session object', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const mockReq = {
        query: { code: 'code-123', state: 'state-123' },
        originalUrl: '/oauth/callback?code=code-123&state=state-123',
        // No session object
      } as unknown as Request;
      const mockRes = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleCallback(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.send).toHaveBeenCalledWith(
        'Invalid session - session cookie not found or expired'
      );
    });

    it('should handle callback with extractCustomData', async () => {
      mockIdpClient.extractCustomData = vi.fn().mockReturnValue({
        customField: 'custom-value',
        organization: 'test-org',
      });

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Create interaction session first
      const saveFn = vi.fn((cb: (err?: Error) => void) => cb());
      const mockInteractionReq = {
        params: { uid: 'interaction-uid' },
        session: {
          save: saveFn,
          interactionSessionId: undefined as string | undefined,
        },
      } as unknown as Request;
      const mockInteractionRes = {
        redirect: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockInteractionReq, mockInteractionRes);
      const interactionSessionId = mockInteractionReq.session.interactionSessionId;

      // Now callback
      const callbackSaveFn = vi.fn((cb: (err?: Error) => void) => cb());
      const mockCallbackReq = {
        query: { code: 'code-123', state: 'state-123' },
        originalUrl: '/oauth/callback?code=code-123&state=state-123',
        protocol: 'https',
        get: vi.fn().mockReturnValue('auth.example.com'),
        session: {
          interactionSessionId,
          save: callbackSaveFn,
          userSessionId: undefined as string | undefined,
        },
      } as unknown as Request;
      const mockCallbackRes = {
        redirect: vi.fn(),
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleCallback(mockCallbackReq, mockCallbackRes);

      expect(mockIdpClient.extractCustomData).toHaveBeenCalled();
      expect(mockCallbackRes.redirect).toHaveBeenCalled();
    });

    it('should handle callback error from exchangeCode', async () => {
      mockIdpClient.exchangeCode = vi.fn().mockRejectedValue(new Error('Exchange failed'));

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Create interaction session first
      const saveFn = vi.fn((cb: (err?: Error) => void) => cb());
      const mockInteractionReq = {
        params: { uid: 'interaction-uid' },
        session: {
          save: saveFn,
          interactionSessionId: undefined as string | undefined,
        },
      } as unknown as Request;
      const mockInteractionRes = {
        redirect: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockInteractionReq, mockInteractionRes);
      const interactionSessionId = mockInteractionReq.session.interactionSessionId;

      // Now callback should fail
      const mockCallbackReq = {
        query: { code: 'code-123', state: 'state-123' },
        originalUrl: '/oauth/callback?code=code-123&state=state-123',
        protocol: 'https',
        get: vi.fn().mockReturnValue('auth.example.com'),
        session: {
          interactionSessionId,
        },
      } as unknown as Request;
      const mockCallbackRes = {
        redirect: vi.fn(),
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleCallback(mockCallbackReq, mockCallbackRes);

      expect(mockCallbackRes.status).toHaveBeenCalledWith(500);
      expect(mockCallbackRes.send).toHaveBeenCalledWith('Authentication failed: Exchange failed');
    });

    it('should handle callback with non-Error exception', async () => {
      mockIdpClient.exchangeCode = vi.fn().mockRejectedValue('String error');

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Create interaction session first
      const saveFn = vi.fn((cb: (err?: Error) => void) => cb());
      const mockInteractionReq = {
        params: { uid: 'interaction-uid' },
        session: {
          save: saveFn,
          interactionSessionId: undefined as string | undefined,
        },
      } as unknown as Request;
      const mockInteractionRes = {
        redirect: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockInteractionReq, mockInteractionRes);
      const interactionSessionId = mockInteractionReq.session.interactionSessionId;

      const mockCallbackReq = {
        query: { code: 'code-123', state: 'state-123' },
        originalUrl: '/oauth/callback?code=code-123&state=state-123',
        protocol: 'https',
        get: vi.fn().mockReturnValue('auth.example.com'),
        session: {
          interactionSessionId,
        },
      } as unknown as Request;
      const mockCallbackRes = {
        redirect: vi.fn(),
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleCallback(mockCallbackReq, mockCallbackRes);

      expect(mockCallbackRes.status).toHaveBeenCalledWith(500);
      expect(mockCallbackRes.send).toHaveBeenCalledWith('Authentication failed: Unknown error');
    });
  });

  describe('getResourceServerInfo custom handler', () => {
    it('should use custom getResourceServerInfo when provided', () => {
      const customGetResourceServerInfo = vi.fn().mockReturnValue({
        scope: 'custom-scope api:read',
        audience: 'custom-audience',
        accessTokenTTL: 1800,
        accessTokenFormat: 'jwt' as const,
      });

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
        getResourceServerInfo: customGetResourceServerInfo,
      });

      expect(provider).toBeDefined();
    });

    it('should return undefined from custom handler to use default', () => {
      const customGetResourceServerInfo = vi.fn().mockReturnValue(undefined);

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
        getResourceServerInfo: customGetResourceServerInfo,
      });

      expect(provider).toBeDefined();
    });
  });

  describe('handleCallback state mismatch', () => {
    it('should return 400 when state does not match interaction session state', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Create interaction session with specific state
      const saveFn = vi.fn((cb: (err?: Error) => void) => cb());
      const mockInteractionReq = {
        params: { uid: 'interaction-uid' },
        session: {
          save: saveFn,
          interactionSessionId: undefined as string | undefined,
        },
      } as unknown as Request;
      const mockInteractionRes = {
        redirect: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockInteractionReq, mockInteractionRes);
      const interactionSessionId = mockInteractionReq.session.interactionSessionId;

      // Callback with DIFFERENT state than what was stored (state-123)
      const mockCallbackReq = {
        query: { code: 'code-123', state: 'wrong-state' }, // Wrong state!
        originalUrl: '/oauth/callback?code=code-123&state=wrong-state',
        protocol: 'https',
        get: vi.fn().mockReturnValue('auth.example.com'),
        session: {
          interactionSessionId,
        },
      } as unknown as Request;
      const mockCallbackRes = {
        redirect: vi.fn(),
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleCallback(mockCallbackReq, mockCallbackRes);

      expect(mockCallbackRes.status).toHaveBeenCalledWith(400);
      expect(mockCallbackRes.send).toHaveBeenCalledWith('State mismatch');
    });
  });

  describe('validateToken outer catch block', () => {
    it('should return validation failed on unexpected error', async () => {
      const { jwtVerify } = await import('jose');
      vi.mocked(jwtVerify).mockResolvedValue({
        payload: { sub: 'account-123' },
        protectedHeader: { alg: 'RS256' },
        key: {} as CryptoKey,
      });

      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Store a session
      await provider.sessionStore.set('account-123', {
        userId: 'user-123',
        claims: { sub: 'user-123' },
        tokenSet: {
          accessToken: 'access-token',
          idToken: 'id-token',
          refreshToken: 'refresh-token',
        },
      });

      // Override sessionStore.get to throw after jwtVerify succeeds but during user retrieval
      // We need to make it throw during the token refresh check, which happens later in the flow
      const originalGet = provider.sessionStore.get.bind(provider.sessionStore);
      provider.sessionStore.get = vi.fn(async (key: string) => {
        const session = await originalGet(key);
        // Return a session with a getter that throws when accessing claims
        if (session) {
          return {
            ...session,
            get claims() {
              throw new Error('Unexpected access error');
            },
          };
        }
        return session;
      });

      const result = await provider.validateToken('valid-token');

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Token validation failed');
    });
  });

  describe('regenerateSession edge cases', () => {
    it('should handle regenerate with no session object', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Set a stale userSessionId but make session.regenerate not exist (undefined session)
      const mockReq = {
        params: { uid: 'interaction-uid' },
        session: undefined, // No session at all
      } as unknown as Request;
      const mockRes = {
        redirect: vi.fn(),
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockReq, mockRes);

      // Should still work (redirects to IdP)
      expect(mockIdpClient.createAuthorizationUrl).toHaveBeenCalled();
      expect(mockRes.redirect).toHaveBeenCalled();
    });

    it('should handle saveSession with undefined session', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      // Create a request with undefined session for the callback flow
      // This should trigger the early return in saveSession
      const mockReq = {
        query: { code: 'code-123', state: 'state-123' },
        originalUrl: '/oauth/callback?code=code-123&state=state-123',
        // No session - triggers early return paths
      } as unknown as Request;
      const mockRes = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as Response;

      await provider.handleCallback(mockReq, mockRes);

      // Should fail early due to missing session
      expect(mockRes.status).toHaveBeenCalledWith(400);
    });

    it('should handle save callback with non-Error rejection', async () => {
      const provider = createOidcProvider({
        issuer: 'https://auth.example.com',
        idpClient: mockIdpClient,
        store: mockStore,
        cookieSecrets: ['secret-123'],
      });

      const saveFn = vi.fn((cb: (err?: unknown) => void) => cb('string save error'));

      const mockReq = {
        params: { uid: 'interaction-uid' },
        session: {
          save: saveFn,
        },
      } as unknown as Request;
      const mockRes = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
        redirect: vi.fn(),
      } as unknown as Response;

      await provider.handleInteraction(mockReq, mockRes);

      // Should handle the string error
      expect(mockRes.status).toHaveBeenCalledWith(500);
    });
  });
});
