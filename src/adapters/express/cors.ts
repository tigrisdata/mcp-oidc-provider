import type { RequestHandler } from 'express';

/**
 * MCP Inspector origin - always included by default.
 */
export const MCP_INSPECTOR_ORIGIN = 'http://localhost:6274';

/**
 * CORS configuration options for MCP servers.
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

  /**
   * Custom origin handler. If provided, overrides baseUrl and additionalOrigins.
   * MCP Inspector is still included unless you explicitly exclude it.
   */
  origin?: string | string[] | ((origin: string | undefined) => boolean);

  /**
   * Additional allowed headers beyond the MCP defaults.
   * Default MCP headers: Content-Type, mcp-session-id, mcp-protocol-version, Authorization
   */
  additionalAllowedHeaders?: string[];

  /**
   * Additional exposed headers beyond the MCP defaults.
   * Default MCP headers: Mcp-Session-Id, Location
   */
  additionalExposedHeaders?: string[];

  /**
   * Whether to allow credentials (cookies, authorization headers).
   * Default: true
   */
  credentials?: boolean;

  /**
   * Max age for preflight cache in seconds.
   * Default: 86400 (24 hours)
   */
  maxAge?: number;
}

/**
 * Default MCP session ID header name.
 */
export const MCP_SESSION_ID_HEADER = 'mcp-session-id';

/**
 * Default headers required for MCP protocol.
 */
export const DEFAULT_MCP_ALLOWED_HEADERS = [
  'Content-Type',
  MCP_SESSION_ID_HEADER,
  'mcp-protocol-version',
  'Authorization',
];

/**
 * Default headers exposed by MCP servers.
 */
export const DEFAULT_MCP_EXPOSED_HEADERS = ['Mcp-Session-Id', 'Location'];

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
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { createMcpCorsMiddleware } from 'mcp-oidc-provider/express';
 *
 * const app = express();
 *
 * // Basic usage - includes MCP Inspector automatically
 * app.use(createMcpCorsMiddleware());
 *
 * // With your server's base URL
 * app.use(createMcpCorsMiddleware({
 *   baseUrl: 'https://your-app.com',
 * }));
 *
 * // With additional origins
 * app.use(createMcpCorsMiddleware({
 *   baseUrl: 'https://your-app.com',
 *   additionalOrigins: ['https://other-domain.com'],
 * }));
 * ```
 */
export function createMcpCorsMiddleware(options?: McpCorsOptions): RequestHandler {
  // Build allowed origins list
  let allowedOrigins: string | string[] | ((origin: string | undefined) => boolean);

  if (options?.origin) {
    // Custom origin handler provided
    allowedOrigins = options.origin;
  } else {
    // Build origins list: MCP Inspector + baseUrl + additionalOrigins
    const origins = [MCP_INSPECTOR_ORIGIN];
    if (options?.baseUrl) {
      origins.push(options.baseUrl);
    }
    if (options?.additionalOrigins) {
      origins.push(...options.additionalOrigins);
    }
    allowedOrigins = origins;
  }

  const credentials = options?.credentials ?? true;
  const maxAge = options?.maxAge ?? 86400;

  const allowedHeaders = [
    ...DEFAULT_MCP_ALLOWED_HEADERS,
    ...(options?.additionalAllowedHeaders ?? []),
  ].join(', ');

  const exposedHeaders = [
    ...DEFAULT_MCP_EXPOSED_HEADERS,
    ...(options?.additionalExposedHeaders ?? []),
  ].join(', ');

  return (req, res, next) => {
    const origin = req.headers.origin;

    // Check if origin is allowed
    let isAllowed = false;

    if (typeof allowedOrigins === 'function') {
      isAllowed = allowedOrigins(origin);
    } else if (typeof allowedOrigins === 'string') {
      isAllowed = origin === allowedOrigins || allowedOrigins === '*';
    } else if (Array.isArray(allowedOrigins)) {
      isAllowed = origin ? allowedOrigins.includes(origin) : false;
    }

    if (isAllowed && origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    } else if (allowedOrigins === '*') {
      res.setHeader('Access-Control-Allow-Origin', '*');
    }

    if (credentials) {
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }

    res.setHeader('Access-Control-Allow-Headers', allowedHeaders);
    res.setHeader('Access-Control-Expose-Headers', exposedHeaders);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Max-Age', maxAge.toString());

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }

    next();
  };
}

/**
 * Get the default CORS options for MCP servers.
 * Useful if you want to use a different CORS library but need the MCP defaults.
 *
 * @param baseUrl - Your server's base URL to include in allowed origins
 * @returns CORS options object compatible with the 'cors' npm package
 *
 * @example
 * ```typescript
 * import cors from 'cors';
 * import { getMcpCorsOptions } from 'mcp-oidc-provider/express';
 *
 * const app = express();
 * app.use(cors(getMcpCorsOptions('https://your-app.com')));
 * ```
 */
export function getMcpCorsOptions(baseUrl?: string): {
  origin: string[];
  allowedHeaders: string[];
  exposedHeaders: string[];
  credentials: boolean;
  maxAge: number;
} {
  const origins = ['http://localhost:6274'];
  if (baseUrl) {
    origins.push(baseUrl);
  }

  return {
    origin: origins,
    allowedHeaders: DEFAULT_MCP_ALLOWED_HEADERS,
    exposedHeaders: DEFAULT_MCP_EXPOSED_HEADERS,
    credentials: true,
    maxAge: 86400,
  };
}
