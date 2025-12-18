import { describe, it, expect, beforeEach } from 'vitest';
import { createMcpCorsMiddleware } from './cors.js';
import type { Request, Response, NextFunction } from 'express';
import { createMockRequest, createMockResponse, createMockNext } from '../test/helpers/index.js';

describe('cors', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let headers: Record<string, string>;

  beforeEach(() => {
    mockReq = createMockRequest();
    const responseResult = createMockResponse();
    mockRes = responseResult.res;
    headers = responseResult.headers;
    mockNext = createMockNext();
  });

  describe('createMcpCorsMiddleware', () => {
    it('should create a middleware function', () => {
      const middleware = createMcpCorsMiddleware();

      expect(typeof middleware).toBe('function');
    });

    it('should always set credentials header', () => {
      const middleware = createMcpCorsMiddleware();

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(headers['Access-Control-Allow-Credentials']).toBe('true');
    });

    it('should set allowed headers', () => {
      const middleware = createMcpCorsMiddleware();

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(headers['Access-Control-Allow-Headers']).toContain('Content-Type');
      expect(headers['Access-Control-Allow-Headers']).toContain('Authorization');
      expect(headers['Access-Control-Allow-Headers']).toContain('mcp-session-id');
    });

    it('should set exposed headers', () => {
      const middleware = createMcpCorsMiddleware();

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(headers['Access-Control-Expose-Headers']).toContain('Mcp-Session-Id');
      expect(headers['Access-Control-Expose-Headers']).toContain('Location');
    });

    it('should set allowed methods', () => {
      const middleware = createMcpCorsMiddleware();

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(headers['Access-Control-Allow-Methods']).toContain('GET');
      expect(headers['Access-Control-Allow-Methods']).toContain('POST');
      expect(headers['Access-Control-Allow-Methods']).toContain('DELETE');
    });

    it('should set max age header', () => {
      const middleware = createMcpCorsMiddleware();

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(headers['Access-Control-Max-Age']).toBe('86400');
    });

    it('should allow MCP Inspector origin by default', () => {
      const middleware = createMcpCorsMiddleware();
      mockReq.headers = { origin: 'http://localhost:6274' };

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(headers['Access-Control-Allow-Origin']).toBe('http://localhost:6274');
    });

    it('should allow configured baseUrl', () => {
      const middleware = createMcpCorsMiddleware({ baseUrl: 'https://example.com' });
      mockReq.headers = { origin: 'https://example.com' };

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(headers['Access-Control-Allow-Origin']).toBe('https://example.com');
    });

    it('should allow additional origins', () => {
      const middleware = createMcpCorsMiddleware({
        additionalOrigins: ['https://custom.com', 'https://another.com'],
      });
      mockReq.headers = { origin: 'https://custom.com' };

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(headers['Access-Control-Allow-Origin']).toBe('https://custom.com');
    });

    it('should not set origin header for disallowed origin', () => {
      const middleware = createMcpCorsMiddleware({ baseUrl: 'https://example.com' });
      mockReq.headers = { origin: 'https://malicious.com' };

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(headers['Access-Control-Allow-Origin']).toBeUndefined();
    });

    it('should not set origin header when no origin provided', () => {
      const middleware = createMcpCorsMiddleware();
      mockReq.headers = {};

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(headers['Access-Control-Allow-Origin']).toBeUndefined();
    });

    it('should call next() for non-OPTIONS requests', () => {
      const middleware = createMcpCorsMiddleware();
      mockReq.method = 'GET';

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should respond with 204 for OPTIONS requests', () => {
      const middleware = createMcpCorsMiddleware();
      mockReq.method = 'OPTIONS';

      middleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(204);
      expect(mockRes.end).toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should combine baseUrl and additional origins', () => {
      const middleware = createMcpCorsMiddleware({
        baseUrl: 'https://example.com',
        additionalOrigins: ['https://custom.com'],
      });

      // Test baseUrl
      mockReq.headers = { origin: 'https://example.com' };
      middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(headers['Access-Control-Allow-Origin']).toBe('https://example.com');

      // Reset headers for next test
      const responseResult2 = createMockResponse();
      mockRes = responseResult2.res;
      headers = responseResult2.headers;

      // Test additional origin
      mockReq.headers = { origin: 'https://custom.com' };
      middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(headers['Access-Control-Allow-Origin']).toBe('https://custom.com');

      // Reset headers for next test
      const responseResult3 = createMockResponse();
      mockRes = responseResult3.res;
      headers = responseResult3.headers;

      // Test MCP Inspector (always included)
      mockReq.headers = { origin: 'http://localhost:6274' };
      middleware(mockReq as Request, mockRes as Response, mockNext);
      expect(headers['Access-Control-Allow-Origin']).toBe('http://localhost:6274');
    });
  });
});
