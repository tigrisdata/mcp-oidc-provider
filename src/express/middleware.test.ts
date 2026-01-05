import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createExpressAuthMiddleware } from './middleware.js';
import type { OidcProvider } from '../core/types.js';
import type { Request, Response, NextFunction } from 'express';
import {
  createMockRequest,
  createMockResponse,
  createMockNext,
  createMockUser,
  createExpiringJwt,
} from '../test/helpers/index.js';

describe('middleware', () => {
  let mockProvider: OidcProvider;
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let headers: Record<string, string>;

  beforeEach(() => {
    mockProvider = {
      validateToken: vi.fn(),
      refreshIdpTokens: vi.fn(),
    } as unknown as OidcProvider;

    mockReq = createMockRequest();
    const responseResult = createMockResponse();
    mockRes = responseResult.res;
    headers = responseResult.headers;
    mockNext = createMockNext();
  });

  describe('createExpressAuthMiddleware', () => {
    it('should create a middleware function', () => {
      const middleware = createExpressAuthMiddleware(mockProvider);

      expect(typeof middleware).toBe('function');
    });

    it('should return 401 if no Authorization header', async () => {
      const middleware = createExpressAuthMiddleware(mockProvider);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'unauthorized',
        message: expect.stringContaining('Missing or invalid Authorization header'),
      });
      expect(headers['WWW-Authenticate']).toBeDefined();
    });

    it('should return 401 if Authorization header does not start with Bearer', async () => {
      const middleware = createExpressAuthMiddleware(mockProvider);
      mockReq.headers = { authorization: 'Basic abc123' };

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
    });

    it('should return 401 if token validation fails', async () => {
      const middleware = createExpressAuthMiddleware(mockProvider);
      mockReq.headers = { authorization: 'Bearer invalid-token' };
      vi.mocked(mockProvider.validateToken).mockResolvedValue({
        valid: false,
        error: 'Invalid token',
      });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'invalid_token',
        message: 'Invalid token',
      });
    });

    it('should attach user to request and call next on success', async () => {
      const middleware = createExpressAuthMiddleware(mockProvider);
      const mockUser = createMockUser();
      mockReq.headers = { authorization: 'Bearer valid-token' };
      vi.mocked(mockProvider.validateToken).mockResolvedValue({
        valid: true,
        user: mockUser,
      });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect((mockReq as Request & { user: typeof mockUser }).user).toEqual(mockUser);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should set WWW-Authenticate header with resource metadata URL', async () => {
      const middleware = createExpressAuthMiddleware(mockProvider);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(headers['WWW-Authenticate']).toContain('resource_metadata=');
      expect(headers['WWW-Authenticate']).toContain('.well-known/oauth-protected-resource');
    });

    it('should use configured baseUrl for WWW-Authenticate header', async () => {
      const middleware = createExpressAuthMiddleware(mockProvider, {
        baseUrl: 'https://custom.com',
      });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(headers['WWW-Authenticate']).toContain('https://custom.com');
    });

    it('should auto-refresh tokens when they are expiring soon', async () => {
      const middleware = createExpressAuthMiddleware(mockProvider, {
        autoRefresh: true,
        refreshBufferSeconds: 300,
      });

      // Create a token that expires in 60 seconds (within 300 second buffer)
      const expiringToken = createExpiringJwt(60);
      const mockUser = createMockUser();
      mockUser.tokenSet.accessToken = expiringToken;

      mockReq.headers = { authorization: `Bearer ${expiringToken}` };
      vi.mocked(mockProvider.validateToken).mockResolvedValue({
        valid: true,
        user: mockUser,
      });
      vi.mocked(mockProvider.refreshIdpTokens).mockResolvedValue(true);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockProvider.refreshIdpTokens).toHaveBeenCalledWith(mockUser.accountId);
    });

    it('should not refresh tokens when autoRefresh is disabled', async () => {
      const middleware = createExpressAuthMiddleware(mockProvider, {
        autoRefresh: false,
      });

      const expiringToken = createExpiringJwt(60);
      const mockUser = createMockUser();
      mockUser.tokenSet.accessToken = expiringToken;

      mockReq.headers = { authorization: `Bearer ${expiringToken}` };
      vi.mocked(mockProvider.validateToken).mockResolvedValue({
        valid: true,
        user: mockUser,
      });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockProvider.refreshIdpTokens).not.toHaveBeenCalled();
    });

    it('should continue even if refresh fails', async () => {
      const middleware = createExpressAuthMiddleware(mockProvider, {
        autoRefresh: true,
        refreshBufferSeconds: 300,
      });

      const expiringToken = createExpiringJwt(60);
      const mockUser = createMockUser();
      mockUser.tokenSet.accessToken = expiringToken;

      mockReq.headers = { authorization: `Bearer ${expiringToken}` };
      vi.mocked(mockProvider.validateToken).mockResolvedValue({
        valid: true,
        user: mockUser,
      });
      vi.mocked(mockProvider.refreshIdpTokens).mockResolvedValue(false);

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle errors gracefully', async () => {
      const middleware = createExpressAuthMiddleware(mockProvider);
      mockReq.headers = { authorization: 'Bearer valid-token' };
      vi.mocked(mockProvider.validateToken).mockRejectedValue(new Error('Unexpected error'));

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'internal_server_error',
        message: 'Authentication failed',
      });
    });

    it('should not refresh if token has no expiration', async () => {
      const middleware = createExpressAuthMiddleware(mockProvider, {
        autoRefresh: true,
      });

      // Token without exp claim
      const tokenWithoutExp = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.signature';
      const mockUser = createMockUser();
      mockUser.tokenSet.accessToken = tokenWithoutExp;

      mockReq.headers = { authorization: `Bearer ${tokenWithoutExp}` };
      vi.mocked(mockProvider.validateToken).mockResolvedValue({
        valid: true,
        user: mockUser,
      });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockProvider.refreshIdpTokens).not.toHaveBeenCalled();
    });

    it('should handle invalid JWT format gracefully', async () => {
      const middleware = createExpressAuthMiddleware(mockProvider, {
        autoRefresh: true,
      });

      const invalidToken = 'not-a-jwt';
      const mockUser = createMockUser();
      mockUser.tokenSet.accessToken = invalidToken;

      mockReq.headers = { authorization: `Bearer ${invalidToken}` };
      vi.mocked(mockProvider.validateToken).mockResolvedValue({
        valid: true,
        user: mockUser,
      });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      // Should not throw, should just not try to refresh
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle malformed JWT payload gracefully', async () => {
      const middleware = createExpressAuthMiddleware(mockProvider, {
        autoRefresh: true,
        refreshBufferSeconds: 300,
      });

      // Token with 3 parts but invalid JSON in payload
      const malformedToken = 'eyJhbGciOiJIUzI1NiJ9.not-valid-base64-json.signature';
      const mockUser = createMockUser();
      mockUser.tokenSet.accessToken = malformedToken;

      mockReq.headers = { authorization: `Bearer ${malformedToken}` };
      vi.mocked(mockProvider.validateToken).mockResolvedValue({
        valid: true,
        user: mockUser,
      });

      await middleware(mockReq as Request, mockRes as Response, mockNext);

      // Should not throw, should just not try to refresh (catch returns false)
      expect(mockNext).toHaveBeenCalled();
      expect(mockProvider.refreshIdpTokens).not.toHaveBeenCalled();
    });
  });
});
