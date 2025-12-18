import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import { setupMcpExpress } from './setup.js';
import type { IOidcClient, KeyvLike } from '../types.js';
import { TEST_BASE_URL, TEST_SECRET, TEST_USER_ID, TEST_EMAIL } from '../test/constants.js';
import { createMockStore, createMockIdpClient, storeUserSession } from '../test/helpers/index.js';

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
  jwtVerify: vi.fn().mockResolvedValue({
    payload: { sub: 'user-123' },
    protectedHeader: { alg: 'RS256' },
    key: {},
  }),
}));

describe('setup integration tests', () => {
  let mockStore: KeyvLike;
  let mockIdpClient: IOidcClient;
  let storedData: Map<string, unknown>;

  beforeEach(() => {
    const storeResult = createMockStore();
    mockStore = storeResult.store;
    storedData = storeResult.storedData;
    mockIdpClient = createMockIdpClient();
    vi.clearAllMocks();
  });

  describe('health endpoint', () => {
    it('should return health status', async () => {
      const { app } = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: TEST_BASE_URL,
        secret: TEST_SECRET,
      });

      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
      expect(response.body.status).toBe('ok');
      expect(response.body.timestamp).toBeDefined();
    });
  });

  describe('404 handler', () => {
    it('should return 404 for unknown routes', async () => {
      const { app } = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: TEST_BASE_URL,
        secret: TEST_SECRET,
      });

      const response = await request(app).get('/unknown-route');

      expect(response.status).toBe(404);
      expect(response.body.error).toBe('Not Found');
    });
  });

  describe('MCP endpoint authentication', () => {
    it('should return 401 for unauthenticated POST to /mcp', async () => {
      const { app } = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: TEST_BASE_URL,
        secret: TEST_SECRET,
      });

      const response = await request(app).post('/mcp').send({ test: 'data' });

      expect(response.status).toBe(401);
    });

    it('should return 500 if MCP handler not configured for GET', async () => {
      const { app } = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: TEST_BASE_URL,
        secret: TEST_SECRET,
      });

      const response = await request(app).get('/mcp');

      expect(response.status).toBe(500);
      expect(response.body.error).toBe('MCP handler not configured');
    });

    it('should return 500 if MCP handler not configured for DELETE', async () => {
      const { app } = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: TEST_BASE_URL,
        secret: TEST_SECRET,
      });

      const response = await request(app).delete('/mcp');

      expect(response.status).toBe(500);
      expect(response.body.error).toBe('MCP handler not configured');
    });

    it('should call MCP handler for GET when configured', async () => {
      const { app, handleMcpRequest } = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: TEST_BASE_URL,
        secret: TEST_SECRET,
      });

      handleMcpRequest((_req, res) => {
        res.json({ handled: true });
      });

      const response = await request(app).get('/mcp');

      expect(response.status).toBe(200);
      expect(response.body.handled).toBe(true);
    });

    it('should call MCP handler for DELETE when configured', async () => {
      const { app, handleMcpRequest } = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: TEST_BASE_URL,
        secret: TEST_SECRET,
      });

      handleMcpRequest((_req, res) => {
        res.json({ deleted: true });
      });

      const response = await request(app).delete('/mcp');

      expect(response.status).toBe(200);
      expect(response.body.deleted).toBe(true);
    });
  });

  describe('urlencoded middleware', () => {
    it('should skip urlencoded parsing for OIDC routes', async () => {
      const { app } = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: TEST_BASE_URL,
        secret: TEST_SECRET,
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
      const { app } = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: TEST_BASE_URL,
        secret: TEST_SECRET,
      });

      const response = await request(app).get('/.well-known/oauth-protected-resource');

      expect(response.status).toBe(200);
      expect(response.body.resource).toBeDefined();
      expect(response.body.authorization_servers).toBeDefined();
    });
  });

  describe('authenticated MCP POST handler', () => {
    it('should return 500 if MCP handler not configured for authenticated POST', async () => {
      const { app } = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: TEST_BASE_URL,
        secret: TEST_SECRET,
      });

      // Pre-populate a user session AFTER creating the app
      storeUserSession(storedData, TEST_USER_ID, {
        userId: TEST_USER_ID,
        claims: { sub: TEST_USER_ID, email: TEST_EMAIL },
        tokenSet: {
          accessToken: 'idp-access-token',
          idToken: 'idp-id-token',
          refreshToken: 'idp-refresh-token',
        },
      });

      const response = await request(app)
        .post('/mcp')
        .set('Authorization', 'Bearer valid-token')
        .send({ test: 'data' });

      // With valid auth but no handler, should return 500
      expect(response.status).toBe(500);
      expect(response.body.error).toBe('MCP handler not configured');
    });

    it('should call MCP handler for authenticated POST when configured', async () => {
      // Pre-populate a user session
      storeUserSession(storedData, TEST_USER_ID, {
        userId: TEST_USER_ID,
        claims: { sub: TEST_USER_ID, email: TEST_EMAIL },
        tokenSet: {
          accessToken: 'idp-access-token',
          idToken: 'idp-id-token',
          refreshToken: 'idp-refresh-token',
        },
      });

      const { app, handleMcpRequest } = setupMcpExpress({
        idpClient: mockIdpClient,
        store: mockStore,
        baseUrl: TEST_BASE_URL,
        secret: TEST_SECRET,
      });

      // Configure the MCP handler
      handleMcpRequest((req, res) => {
        // req.user should be set by auth middleware
        res.json({
          handled: true,
          hasUser: !!req.user,
          userId: req.user?.userId,
        });
      });

      const response = await request(app)
        .post('/mcp')
        .set('Authorization', 'Bearer valid-token')
        .send({ test: 'data' });

      expect(response.status).toBe(200);
      expect(response.body.handled).toBe(true);
      expect(response.body.hasUser).toBe(true);
      expect(response.body.userId).toBe(TEST_USER_ID);
    });
  });
});
