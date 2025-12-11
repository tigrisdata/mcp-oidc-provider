/**
 * Standalone OIDC server for MCP authentication.
 *
 * This module provides a standalone Express OIDC server that can be used with
 * the MCP SDK's ProxyOAuthServerProvider. It handles:
 * - Dynamic Client Registration
 * - OAuth 2.0 Authorization Code Flow with PKCE
 * - Token issuance and validation
 * - Session management
 *
 * @example
 * ```typescript
 * import { Keyv } from 'keyv';
 * import { createOidcServer, OidcClient } from 'mcp-oidc-provider/oidc';
 *
 * const server = createOidcServer({
 *   idpClient: new OidcClient({
 *     issuer: 'https://your-tenant.auth0.com',
 *     clientId: process.env.AUTH0_CLIENT_ID,
 *     clientSecret: process.env.AUTH0_CLIENT_SECRET,
 *     redirectUri: 'http://localhost:4001/oauth/callback',
 *   }),
 *   store: new Keyv(),
 *   secret: process.env.SESSION_SECRET,
 *   port: 4001,
 *   baseUrl: 'http://localhost:4001',
 * });
 *
 * await server.start();
 * ```
 *
 * @packageDocumentation
 */

import express, { type Application, type Request, type Response } from 'express';
import session from 'express-session';
import { Keyv } from 'keyv';
import type { Server } from 'node:http';
import type { TokenValidationResult, BaseOidcOptions } from '../types.js';
import { createOidcProvider } from '../core/provider.js';
import { STORAGE_NAMESPACES } from '../core/config.js';
import { createExpressAdapter, isOidcProviderRoute } from '../express/adapter.js';
import { createMcpCorsMiddleware } from '../express/cors.js';
import { KeyvSessionStore } from '../express/session-store.js';

/**
 * Options for creating a standalone OIDC server.
 * Extends BaseOidcOptions with server-specific options.
 */
export interface OidcServerOptions extends BaseOidcOptions {
  /**
   * Port number for the server to listen on.
   */
  port: number;

  /**
   * Callback when server starts listening.
   */
  onListen?: (baseUrl: string) => void;
}

/**
 * Result of creating an OIDC server.
 */
export interface OidcServerResult {
  /**
   * The Express app instance.
   */
  app: Application;

  /**
   * Start the server.
   * @returns Promise that resolves when server is listening
   */
  start: () => Promise<Server>;

  /**
   * The base URL of the OIDC server.
   */
  baseUrl: string;

  /**
   * Validate an access token and get the user session including IdP tokens.
   * @param token - The access token to validate
   * @returns Validation result with user info and IdP tokens if valid
   */
  validateToken: (token: string) => Promise<TokenValidationResult>;
}

/**
 * Create a standalone OIDC server.
 *
 * This creates an Express server that acts as an OIDC provider with Dynamic Client
 * Registration support. It can be used with the MCP SDK's `ProxyOAuthServerProvider`
 * to handle OAuth for MCP servers.
 *
 * @param options - Server options
 * @returns Server instance that can be started
 *
 * @example
 * ```typescript
 * import { Keyv } from 'keyv';
 * import { createOidcServer, OidcClient } from 'mcp-oidc-provider/oidc';
 *
 * const server = createOidcServer({
 *   idpClient: new OidcClient({
 *     issuer: 'https://your-tenant.auth0.com',
 *     clientId: process.env.AUTH0_CLIENT_ID,
 *     clientSecret: process.env.AUTH0_CLIENT_SECRET,
 *     redirectUri: 'http://localhost:4001/oauth/callback',
 *   }),
 *   store: new Keyv(),
 *   secret: process.env.SESSION_SECRET,
 *   port: 4001,
 *   baseUrl: 'http://localhost:4001',
 * });
 *
 * await server.start();
 * console.log(`OIDC server running at ${server.baseUrl}`);
 *
 * // Then in your MCP server, use SDK's ProxyOAuthServerProvider:
 * import { mcpAuthRouter, ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server';
 *
 * const authProvider = new ProxyOAuthServerProvider({
 *   endpoints: {
 *     authorizationUrl: `${server.baseUrl}/authorize`,
 *     tokenUrl: `${server.baseUrl}/token`,
 *     registrationUrl: `${server.baseUrl}/register`,
 *   },
 *   verifyAccessToken: async (token) => {
 *     // Verify token with the OIDC server
 *   },
 * });
 *
 * app.use(mcpAuthRouter({ provider: authProvider }));
 * ```
 */
export function createOidcServer(options: OidcServerOptions): OidcServerResult {
  const {
    idpClient,
    store,
    secret,
    port,
    baseUrl,
    jwks,
    isProduction = process.env['NODE_ENV'] === 'production',
    sessionMaxAge = 30 * 24 * 60 * 60 * 1000, // 30 days
    additionalCorsOrigins,
    onListen,
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
    namespace: STORAGE_NAMESPACES.OIDC_SERVER_SESSIONS,
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

  // OAuth routes
  app.use('/oauth', adapter.routes);

  // Well-known endpoints
  app.use('/', adapter.wellKnownRoutes);

  // OIDC provider (must be after custom routes)
  app.use('/', adapter.providerCallback());

  // 404 handler
  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: 'Not Found' });
  });

  const start = (): Promise<Server> => {
    return new Promise((resolve) => {
      const server = app.listen(port, () => {
        if (onListen) {
          onListen(baseUrl);
        }
        resolve(server);
      });
    });
  };

  return {
    app,
    start,
    baseUrl,
    validateToken: provider.validateToken,
  };
}
