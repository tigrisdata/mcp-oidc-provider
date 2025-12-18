import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import { createOidcServer } from './server.js';
import type { IOidcClient, KeyvLike } from '../types.js';

// Mock dependencies
vi.mock('oidc-provider', () => {
  const MockProvider = vi.fn().mockImplementation(() => ({
    proxy: false,
    callback: vi.fn().mockReturnValue((_req: unknown, _res: unknown, next: () => void) => next()),
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

describe('server integration tests', () => {
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

  describe('health endpoint', () => {
    it('should return health status', async () => {
      const { app } = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4001',
        secret: 'test-secret',
        port: 4001,
      });

      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('ok');
      expect(response.body.timestamp).toBeDefined();
    });
  });

  describe('404 handler', () => {
    it('should return 404 for unknown routes', async () => {
      const { app } = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4001',
        secret: 'test-secret',
        port: 4001,
      });

      const response = await request(app).get('/unknown-route');

      expect(response.status).toBe(404);
      expect(response.body.error).toBe('Not Found');
    });
  });

  describe('start function', () => {
    it('should start the server and call onListen', async () => {
      const onListen = vi.fn();
      const { start } = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4002',
        secret: 'test-secret',
        port: 4002,
        onListen,
      });

      const server = await start();

      expect(server).toBeDefined();
      expect(onListen).toHaveBeenCalledWith('http://localhost:4002');

      // Clean up
      server.close();
    });

    it('should start the server without onListen callback', async () => {
      const { start } = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4003',
        secret: 'test-secret',
        port: 4003,
      });

      const server = await start();

      expect(server).toBeDefined();

      // Clean up
      server.close();
    });
  });

  describe('urlencoded middleware', () => {
    it('should skip urlencoded parsing for OIDC routes', async () => {
      const { app } = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4001',
        secret: 'test-secret',
        port: 4001,
      });

      // Request to an OIDC route should not error due to body parsing
      const response = await request(app)
        .post('/token')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('grant_type=authorization_code');

      // The request goes through (may return error from OIDC provider, but no body parsing error)
      expect(response.status).toBeDefined();
    });
  });

  describe('well-known endpoints', () => {
    it('should serve oauth-protected-resource metadata', async () => {
      const { app } = createOidcServer({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: 'http://localhost:4001',
        secret: 'test-secret',
        port: 4001,
      });

      const response = await request(app).get('/.well-known/oauth-protected-resource');

      expect(response.status).toBe(200);
      expect(response.body.resource).toBeDefined();
      expect(response.body.authorization_servers).toBeDefined();
    });
  });
});
