import { describe, it, expect, vi, beforeEach } from 'vitest';
import { OidcClient } from './client.js';

// Mock the openid-client module
vi.mock('openid-client', () => ({
  discovery: vi.fn(),
  buildAuthorizationUrl: vi.fn(),
  randomPKCECodeVerifier: vi.fn(),
  calculatePKCECodeChallenge: vi.fn(),
  authorizationCodeGrant: vi.fn(),
  refreshTokenGrant: vi.fn(),
}));

// Mock jose for decodeJwt
vi.mock('jose', () => ({
  decodeJwt: vi.fn(),
}));

describe('OidcClient', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('constructor', () => {
    it('should create an instance with required config', () => {
      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
      });

      expect(client).toBeInstanceOf(OidcClient);
    });

    it('should accept optional config', () => {
      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
        scopes: 'openid email profile offline_access',
        additionalAuthParams: { audience: 'https://api.example.com' },
        extractCustomData: (claims) => ({ org: claims['org_id'] }),
      });

      expect(client).toBeInstanceOf(OidcClient);
    });
  });

  describe('createAuthorizationUrl', () => {
    it('should create an authorization URL with PKCE', async () => {
      const openidClient = await import('openid-client');
      vi.mocked(openidClient.discovery).mockResolvedValue(
        {} as ReturnType<typeof openidClient.discovery>
      );
      vi.mocked(openidClient.randomPKCECodeVerifier).mockReturnValue('code-verifier');
      vi.mocked(openidClient.calculatePKCECodeChallenge).mockResolvedValue('code-challenge');
      vi.mocked(openidClient.buildAuthorizationUrl).mockReturnValue(
        new URL('https://auth.example.com/authorize?client_id=client-123')
      );

      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
      });

      const result = await client.createAuthorizationUrl();

      expect(result.authorizationUrl).toContain('https://auth.example.com/authorize');
      expect(result.state).toBeDefined();
      expect(result.nonce).toBeDefined();
      expect(result.codeVerifier).toBe('code-verifier');
    });

    it('should use default scopes if not provided', async () => {
      const openidClient = await import('openid-client');
      vi.mocked(openidClient.discovery).mockResolvedValue(
        {} as ReturnType<typeof openidClient.discovery>
      );
      vi.mocked(openidClient.randomPKCECodeVerifier).mockReturnValue('code-verifier');
      vi.mocked(openidClient.calculatePKCECodeChallenge).mockResolvedValue('code-challenge');
      vi.mocked(openidClient.buildAuthorizationUrl).mockReturnValue(
        new URL('https://auth.example.com/authorize')
      );

      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
      });

      await client.createAuthorizationUrl();

      expect(openidClient.buildAuthorizationUrl).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          scope: 'openid email profile',
        })
      );
    });

    it('should use custom scopes if provided', async () => {
      const openidClient = await import('openid-client');
      vi.mocked(openidClient.discovery).mockResolvedValue(
        {} as ReturnType<typeof openidClient.discovery>
      );
      vi.mocked(openidClient.randomPKCECodeVerifier).mockReturnValue('code-verifier');
      vi.mocked(openidClient.calculatePKCECodeChallenge).mockResolvedValue('code-challenge');
      vi.mocked(openidClient.buildAuthorizationUrl).mockReturnValue(
        new URL('https://auth.example.com/authorize')
      );

      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
        scopes: 'openid offline_access',
      });

      await client.createAuthorizationUrl();

      expect(openidClient.buildAuthorizationUrl).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          scope: 'openid offline_access',
        })
      );
    });

    it('should include additional auth params', async () => {
      const openidClient = await import('openid-client');
      vi.mocked(openidClient.discovery).mockResolvedValue(
        {} as ReturnType<typeof openidClient.discovery>
      );
      vi.mocked(openidClient.randomPKCECodeVerifier).mockReturnValue('code-verifier');
      vi.mocked(openidClient.calculatePKCECodeChallenge).mockResolvedValue('code-challenge');
      vi.mocked(openidClient.buildAuthorizationUrl).mockReturnValue(
        new URL('https://auth.example.com/authorize')
      );

      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
        additionalAuthParams: {
          audience: 'https://api.example.com',
          prompt: 'consent',
        },
      });

      await client.createAuthorizationUrl();

      expect(openidClient.buildAuthorizationUrl).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          audience: 'https://api.example.com',
          prompt: 'consent',
        })
      );
    });

    it('should cache OIDC configuration after first call', async () => {
      const openidClient = await import('openid-client');
      vi.mocked(openidClient.discovery).mockResolvedValue(
        {} as ReturnType<typeof openidClient.discovery>
      );
      vi.mocked(openidClient.randomPKCECodeVerifier).mockReturnValue('code-verifier');
      vi.mocked(openidClient.calculatePKCECodeChallenge).mockResolvedValue('code-challenge');
      vi.mocked(openidClient.buildAuthorizationUrl).mockReturnValue(
        new URL('https://auth.example.com/authorize')
      );

      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
      });

      await client.createAuthorizationUrl();
      await client.createAuthorizationUrl();

      expect(openidClient.discovery).toHaveBeenCalledTimes(1);
    });

    it('should add https:// prefix if not present', async () => {
      const openidClient = await import('openid-client');
      vi.mocked(openidClient.discovery).mockResolvedValue(
        {} as ReturnType<typeof openidClient.discovery>
      );
      vi.mocked(openidClient.randomPKCECodeVerifier).mockReturnValue('code-verifier');
      vi.mocked(openidClient.calculatePKCECodeChallenge).mockResolvedValue('code-challenge');
      vi.mocked(openidClient.buildAuthorizationUrl).mockReturnValue(
        new URL('https://auth.example.com/authorize')
      );

      const client = new OidcClient({
        issuer: 'auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
      });

      await client.createAuthorizationUrl();

      expect(openidClient.discovery).toHaveBeenCalledWith(
        expect.objectContaining({ href: 'https://auth.example.com/' }),
        expect.any(String),
        expect.any(String)
      );
    });
  });

  describe('exchangeCode', () => {
    it('should exchange code for tokens', async () => {
      const openidClient = await import('openid-client');
      vi.mocked(openidClient.discovery).mockResolvedValue(
        {} as ReturnType<typeof openidClient.discovery>
      );
      vi.mocked(openidClient.authorizationCodeGrant).mockResolvedValue({
        access_token: 'access-token',
        id_token: 'id-token',
        refresh_token: 'refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      });

      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
      });

      const result = await client.exchangeCode(
        'https://app.example.com/callback?code=auth-code&state=state-123',
        'code-verifier',
        'state-123',
        'nonce-123'
      );

      expect(result.accessToken).toBe('access-token');
      expect(result.idToken).toBe('id-token');
      expect(result.refreshToken).toBe('refresh-token');
      expect(result.expiresIn).toBe(3600);
      expect(result.tokenType).toBe('Bearer');
    });

    it('should handle missing optional tokens', async () => {
      const openidClient = await import('openid-client');
      vi.mocked(openidClient.discovery).mockResolvedValue(
        {} as ReturnType<typeof openidClient.discovery>
      );
      vi.mocked(openidClient.authorizationCodeGrant).mockResolvedValue({
        access_token: 'access-token',
      });

      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
      });

      const result = await client.exchangeCode(
        'https://app.example.com/callback?code=auth-code',
        'code-verifier',
        'state-123'
      );

      expect(result.accessToken).toBe('access-token');
      expect(result.idToken).toBeUndefined();
      expect(result.refreshToken).toBeUndefined();
    });
  });

  describe('refreshToken', () => {
    it('should refresh tokens', async () => {
      const openidClient = await import('openid-client');
      vi.mocked(openidClient.discovery).mockResolvedValue(
        {} as ReturnType<typeof openidClient.discovery>
      );
      vi.mocked(openidClient.refreshTokenGrant).mockResolvedValue({
        access_token: 'new-access-token',
        id_token: 'new-id-token',
        refresh_token: 'new-refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      });

      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
      });

      const result = await client.refreshToken('old-refresh-token');

      expect(result.accessToken).toBe('new-access-token');
      expect(result.refreshToken).toBe('new-refresh-token');
    });
  });

  describe('parseIdToken', () => {
    it('should parse standard claims from ID token', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
        sub: 'user-123',
        email: 'user@example.com',
        email_verified: true,
        name: 'Test User',
        nickname: 'testuser',
        picture: 'https://example.com/avatar.jpg',
        updated_at: 1234567890,
      });

      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
      });

      const claims = client.parseIdToken('id-token');

      expect(claims.sub).toBe('user-123');
      expect(claims.email).toBe('user@example.com');
      expect(claims.emailVerified).toBe(true);
      expect(claims.name).toBe('Test User');
      expect(claims.nickname).toBe('testuser');
      expect(claims.picture).toBe('https://example.com/avatar.jpg');
      expect(claims.updatedAt).toBe(1234567890);
    });

    it('should handle missing claims', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
        sub: 'user-123',
      });

      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
      });

      const claims = client.parseIdToken('id-token');

      expect(claims.sub).toBe('user-123');
      expect(claims.email).toBeUndefined();
    });

    it('should include additional provider-specific claims', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
        sub: 'user-123',
        org_id: 'org-456',
        roles: ['admin', 'user'],
      });

      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
      });

      const claims = client.parseIdToken('id-token');

      expect(claims['org_id']).toBe('org-456');
      expect(claims['roles']).toEqual(['admin', 'user']);
    });

    it('should use empty string for missing sub', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({});

      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
      });

      const claims = client.parseIdToken('id-token');

      expect(claims.sub).toBe('');
    });
  });

  describe('extractCustomData', () => {
    it('should return undefined if no extractCustomData function provided', () => {
      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
      });

      const result = client.extractCustomData({ sub: 'user-123' });

      expect(result).toBeUndefined();
    });

    it('should call extractCustomData function if provided', () => {
      const extractFn = vi.fn().mockReturnValue({ org: 'org-123' });

      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
        extractCustomData: extractFn,
      });

      const claims = { sub: 'user-123', org_id: 'org-123' };
      const result = client.extractCustomData(claims);

      expect(extractFn).toHaveBeenCalledWith(claims);
      expect(result).toEqual({ org: 'org-123' });
    });

    it('should handle extractCustomData returning undefined', () => {
      const extractFn = vi.fn().mockReturnValue(undefined);

      const client = new OidcClient({
        issuer: 'https://auth.example.com',
        clientId: 'client-123',
        clientSecret: 'secret-123',
        redirectUri: 'https://app.example.com/callback',
        extractCustomData: extractFn,
      });

      const result = client.extractCustomData({ sub: 'user-123' });

      expect(result).toBeUndefined();
    });
  });
});
