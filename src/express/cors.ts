/**
 * Internal CORS middleware for MCP servers.
 * @internal
 */

import type { RequestHandler } from 'express';

/**
 * MCP Inspector origin - always included by default.
 */
const MCP_INSPECTOR_ORIGIN = 'http://localhost:6274';

/**
 * Default headers required for MCP protocol.
 */
const DEFAULT_MCP_ALLOWED_HEADERS = [
  'Content-Type',
  'mcp-session-id',
  'mcp-protocol-version',
  'Authorization',
];

/**
 * Default headers exposed by MCP servers.
 */
const DEFAULT_MCP_EXPOSED_HEADERS = ['Mcp-Session-Id', 'Location'];

/**
 * CORS configuration options for MCP servers.
 * @internal
 */
export interface McpCorsOptions {
  /**
   * Your server's base URL. This will be added to allowed origins
   * along with the MCP Inspector (http://localhost:6274).
   */
  baseUrl?: string;

  /**
   * Additional origins to allow beyond baseUrl and MCP Inspector.
   */
  additionalOrigins?: string[];
}

/**
 * Create CORS middleware configured for MCP servers.
 *
 * This middleware handles the specific CORS requirements for MCP clients
 * like Cursor, VS Code, and the MCP Inspector.
 *
 * MCP Inspector (http://localhost:6274) is always included by default.
 *
 * @param options - CORS configuration options
 * @returns Express middleware function
 * @internal
 */
export function createMcpCorsMiddleware(options?: McpCorsOptions): RequestHandler {
  // Build origins list: MCP Inspector + baseUrl + additionalOrigins
  const allowedOrigins = [MCP_INSPECTOR_ORIGIN];
  if (options?.baseUrl) {
    allowedOrigins.push(options.baseUrl);
  }
  if (options?.additionalOrigins) {
    allowedOrigins.push(...options.additionalOrigins);
  }

  const allowedHeaders = DEFAULT_MCP_ALLOWED_HEADERS.join(', ');
  const exposedHeaders = DEFAULT_MCP_EXPOSED_HEADERS.join(', ');

  return (req, res, next) => {
    const origin = req.headers.origin;

    // Check if origin is allowed
    const isAllowed = origin ? allowedOrigins.includes(origin) : false;

    if (isAllowed && origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }

    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', allowedHeaders);
    res.setHeader('Access-Control-Expose-Headers', exposedHeaders);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Max-Age', '86400');

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }

    next();
  };
}
