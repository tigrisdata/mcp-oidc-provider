/**
 * Integrated MCP server setup with built-in OIDC authentication.
 *
 * This module provides a complete Express MCP server setup that includes:
 * - OIDC provider for OAuth authentication
 * - MCP endpoint with token validation
 * - Session management
 * - CORS and health check middleware
 *
 * @example
 * ```typescript
 * import { Keyv } from 'keyv';
 * import { setupMcpExpress } from 'mcp-oidc-provider/mcp';
 * import { OidcClient } from 'mcp-oidc-provider/oidc';
 *
 * const { app, handleMcpRequest } = setupMcpExpress({
 *   idpClient: new OidcClient({
 *     issuer: 'https://your-tenant.auth0.com',
 *     clientId: process.env.AUTH0_CLIENT_ID,
 *     clientSecret: process.env.AUTH0_CLIENT_SECRET,
 *     redirectUri: `${BASE_URL}/oauth/callback`,
 *   }),
 *   store: new Keyv(),
 *   baseUrl: 'https://your-server.com',
 *   secret: process.env.SESSION_SECRET,
 * });
 *
 * handleMcpRequest(async (req, res) => {
 *   // req.user contains the authenticated user
 *   const transport = new StreamableHTTPServerTransport({ ... });
 *   const server = createMcpServer(req.user);
 *   await server.connect(transport);
 *   await transport.handleRequest(req, res, req.body);
 * });
 *
 * app.listen(3000);
 * ```
 *
 * @packageDocumentation
 */

import express, {
  type Application,
  type Request,
  type Response,
  type RequestHandler,
} from 'express';
import session from 'express-session';
import { Keyv } from 'keyv';
import type { BaseOidcOptions } from '../types.js';
import { createOidcProvider } from '../core/provider.js';
import { STORAGE_NAMESPACES } from '../core/config.js';
import { createExpressAdapter, isOidcProviderRoute } from '../express/adapter.js';
import { createMcpCorsMiddleware } from '../express/cors.js';
import { KeyvSessionStore } from '../express/session-store.js';
import { createExpressAuthMiddleware } from '../express/middleware.js';

/**
 * Options for setting up an Express MCP server.
 * Extends BaseOidcOptions with MCP-specific options.
 */
export interface McpExpressSetupOptions extends BaseOidcOptions {
  /**
   * Custom middleware to run after CORS but before other middleware.
   * Useful for request logging, etc.
   */
  customMiddleware?: RequestHandler[];
}

/**
 * MCP request handler function.
 * Called for POST requests to /mcp (authenticated) and GET/DELETE (stateless).
 *
 * For POST: `req.user` contains the authenticated user
 * For GET/DELETE: `req.user` is undefined (stateless session handling)
 *
 * @example
 * ```typescript
 * handleMcpRequest(async (req, res) => {
 *   if (req.user) {
 *     // Authenticated POST request
 *     console.log('User:', req.user.userId);
 *     console.log('Claims:', req.user.claims);
 *     console.log('IdP Access Token:', req.user.tokenSet.accessToken);
 *   } else {
 *     // Stateless GET/DELETE for session management
 *   }
 * });
 * ```
 */
export type McpRequestHandler = (req: Request, res: Response) => void | Promise<void>;

/**
 * Result of setting up the Express MCP server.
 */
export interface McpExpressSetupResult {
  /**
   * The configured Express app, ready to use.
   * Just add your MCP handler and call listen().
   *
   * @example
   * ```typescript
   * const { app, handleMcpRequest } = setupMcpExpress({ ... });
   *
   * handleMcpRequest(async (req, res) => {
   *   if (req.user) {
   *     // POST: authenticated user available
   *     console.log('User:', req.user.userId);
   *   }
   *   // GET/DELETE: stateless session handling
   * });
   *
   * app.listen(3000);
   * ```
   */
  app: Application;

  /**
   * Register your MCP request handler.
   * This handler is called for:
   * - POST requests (authenticated, `req.user` is defined)
   * - GET/DELETE requests (stateless, `req.user` is undefined)
   */
  handleMcpRequest: (handler: McpRequestHandler) => void;
}

/**
 * Set up a complete Express MCP server with OAuth authentication.
 *
 * This function creates and configures everything:
 * - Express app with trust proxy
 * - CORS (with MCP Inspector support)
 * - Session management
 * - Body parsing (that skips OIDC routes)
 * - Health check endpoint at /health
 * - OAuth routes and well-known endpoints
 * - OIDC provider with Cursor compatibility
 * - Authenticated /mcp endpoint
 *
 * @param options - Setup options
 * @returns Configured Express app and MCP handler registration
 *
 * @example
 * ```typescript
 * import { Keyv } from 'keyv';
 * import { setupMcpExpress } from 'mcp-oidc-provider/mcp';
 * import { OidcClient } from 'mcp-oidc-provider/oidc';
 *
 * const { app, handleMcpRequest } = setupMcpExpress({
 *   idpClient: new OidcClient({
 *     issuer: 'https://your-tenant.auth0.com',
 *     clientId: process.env.AUTH0_CLIENT_ID,
 *     clientSecret: process.env.AUTH0_CLIENT_SECRET,
 *     redirectUri: `${BASE_URL}/oauth/callback`,
 *   }),
 *   store: new Keyv(),  // In-memory for dev, use Tigris/Redis for production
 *   baseUrl: 'https://your-server.com',
 *   secret: process.env.SESSION_SECRET,
 * });
 *
 * handleMcpRequest(async (req, res) => {
 *   const transport = new StreamableHTTPServerTransport({ ... });
 *   const server = createMcpServer(req.user); // Access user via req.user
 *   await server.connect(transport);
 *   await transport.handleRequest(req, res, req.body);
 * });
 *
 * app.listen(3000);
 * ```
 */
export function setupMcpExpress(options: McpExpressSetupOptions): McpExpressSetupResult {
  const {
    idpClient,
    store,
    baseUrl,
    secret,
    jwks,
    isProduction = process.env['NODE_ENV'] === 'production',
    sessionMaxAge = 30 * 24 * 60 * 60 * 1000, // 30 days
    additionalCorsOrigins,
    customMiddleware = [],
  } = options;

  // Create Express app
  const app = express();
  app.set('trust proxy', 1);

  // Create OIDC provider
  const provider = createOidcProvider({
    issuer: baseUrl,
    idpClient,
    store,
    cookieSecrets: [secret],
    isProduction,
    jwks,
  });

  // Get the underlying store for namespaced session storage
  const underlyingStore = store.opts?.store;

  // Create session store
  const expressSessionStore = new Keyv({
    store: underlyingStore,
    namespace: STORAGE_NAMESPACES.EXPRESS_SESSIONS,
    ttl: sessionMaxAge,
  });

  // Create CORS middleware
  const corsMiddleware = createMcpCorsMiddleware({
    baseUrl,
    additionalOrigins: additionalCorsOrigins,
  });

  // Create Express adapter
  const adapter = createExpressAdapter(provider, { baseUrl, mcpPath: '/mcp' });

  // Create session middleware
  const sessionMiddleware = session({
    secret,
    resave: false,
    saveUninitialized: false,
    store: new KeyvSessionStore(expressSessionStore),
    cookie: {
      secure: isProduction,
      httpOnly: true,
      sameSite: isProduction ? 'none' : 'lax',
      maxAge: sessionMaxAge,
    },
  });

  // Body parser that skips OIDC routes
  const bodyParserMiddleware = adapter.bodyParserMiddleware;

  const urlencodedMiddleware = (req: Request, res: Response, next: () => void) => {
    if (isOidcProviderRoute(req.path)) {
      next();
      return;
    }
    express.urlencoded({ extended: true })(req, res, next);
  };

  // Health check (before other middleware for fast response)
  app.get('/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // Apply middleware in order
  app.use(corsMiddleware);
  app.use(sessionMiddleware);
  app.use(bodyParserMiddleware);
  app.use(urlencodedMiddleware);

  // Apply custom middleware (e.g., request logging)
  for (const middleware of customMiddleware) {
    app.use(middleware);
  }

  // OAuth routes
  app.use('/oauth', adapter.routes);

  // Well-known endpoints
  app.use('/', adapter.wellKnownRoutes);

  // Create auth middleware
  const authMiddleware = createExpressAuthMiddleware(provider);

  // Store for the MCP handler
  let mcpHandler: McpRequestHandler | undefined;

  // MCP endpoint with authentication (POST)
  // req.user is set by authMiddleware
  const mcpPostHandler = async (req: Request, res: Response): Promise<void> => {
    /* c8 ignore start - defensive check, auth middleware always sets req.user or returns 401 */
    if (!req.user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    /* c8 ignore stop */

    if (!mcpHandler) {
      res.status(500).json({ error: 'MCP handler not configured' });
      return;
    }

    await mcpHandler(req, res);
  };

  // Session handler for GET and DELETE (stateless, no auth)
  // req.user will be undefined for these requests
  const mcpSessionHandler = async (req: Request, res: Response): Promise<void> => {
    if (!mcpHandler) {
      res.status(500).json({ error: 'MCP handler not configured' });
      return;
    }

    await mcpHandler(req, res);
  };

  app.post('/mcp', authMiddleware, mcpPostHandler);
  app.get('/mcp', mcpSessionHandler);
  app.delete('/mcp', mcpSessionHandler);

  // OIDC provider (must be after custom routes)
  app.use('/', adapter.providerCallback());

  // 404 handler
  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: 'Not Found' });
  });

  const handleMcpRequest = (handler: McpRequestHandler): void => {
    mcpHandler = handler;
  };

  return {
    app,
    handleMcpRequest,
  };
}
