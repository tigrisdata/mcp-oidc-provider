import express, { type Application, type Request, type Response } from 'express';
import session from 'express-session';
import { Keyv } from 'keyv';
import type { Server } from 'node:http';
import type { IdentityProviderClient } from '../../types/idp.js';
import type { TokenValidationResult } from '../../types/provider.js';
import type { JWKS } from '../../utils/jwks.js';
import { createOidcProvider } from '../../core/provider.js';
import { createExpressAdapter, isOidcProviderRoute } from './adapter.js';
import { createMcpCorsMiddleware } from './cors.js';
import { KeyvSessionStore } from './session-store.js';

/**
 * Options for creating a standalone OIDC server.
 */
export interface OidcServerOptions {
  /**
   * Identity provider client (e.g., Auth0Client).
   */
  idpClient: IdentityProviderClient;

  /**
   * Keyv instance for storage.
   */
  store: Keyv;

  /**
   * Secret for signing cookies and sessions.
   */
  secret: string;

  /**
   * Port to listen on.
   * Default: 4000
   */
  port?: number;

  /**
   * Base URL of this OIDC server.
   * If not provided, defaults to http://localhost:{port}
   */
  baseUrl?: string;

  /**
   * Optional JWKS for signing tokens.
   * If not provided, development keys are generated (with a warning).
   */
  jwks?: JWKS;

  /**
   * Whether running in production mode.
   * Default: process.env.NODE_ENV === 'production'
   */
  isProduction?: boolean;

  /**
   * Session max age in milliseconds.
   * Default: 30 days
   */
  sessionMaxAge?: number;

  /**
   * Additional origins to allow for CORS.
   */
  additionalCorsOrigins?: string[];

  /**
   * Callback when server starts listening.
   */
  onListen?: (port: number, baseUrl: string) => void;
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
   * The port the server will listen on.
   */
  port: number;

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
 * import { createOidcServer } from 'mcp-oidc-provider/express';
 * import { Auth0Client } from 'mcp-oidc-provider/auth0';
 *
 * const server = createOidcServer({
 *   idpClient: new Auth0Client({
 *     domain: process.env.AUTH0_DOMAIN,
 *     clientId: process.env.AUTH0_CLIENT_ID,
 *     clientSecret: process.env.AUTH0_CLIENT_SECRET,
 *     redirectUri: 'http://localhost:4000/oauth/callback',
 *   }),
 *   store: new Keyv(),
 *   secret: process.env.SESSION_SECRET,
 *   port: 4000,
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
 *     authorizationUrl: `${server.baseUrl}/auth`,
 *     tokenUrl: `${server.baseUrl}/token`,
 *     registrationUrl: `${server.baseUrl}/reg`,
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
    port = 4000,
    baseUrl: providedBaseUrl,
    jwks,
    isProduction = process.env['NODE_ENV'] === 'production',
    sessionMaxAge = 30 * 24 * 60 * 60 * 1000, // 30 days
    additionalCorsOrigins,
    onListen,
  } = options;

  const baseUrl = providedBaseUrl ?? `http://localhost:${port}`;

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
    namespace: 'oidc-server-sessions',
    ttl: sessionMaxAge,
  });

  // Create CORS middleware - allow all origins for standalone server
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

  // Health check
  app.get('/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // Apply middleware
  app.use(corsMiddleware);
  app.use(sessionMiddleware);
  app.use(bodyParserMiddleware);
  app.use(urlencodedMiddleware);

  // OAuth routes
  app.use('/oauth', adapter.routes);

  // Well-known endpoints
  app.use('/', adapter.wellKnownRoutes);

  // OIDC provider (must be last)
  app.use('/', adapter.providerCallback());

  // 404 handler
  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: 'Not Found' });
  });

  const start = (): Promise<Server> => {
    return new Promise((resolve) => {
      const server = app.listen(port, () => {
        if (onListen) {
          onListen(port, baseUrl);
        }
        resolve(server);
      });
    });
  };

  return {
    app,
    start,
    baseUrl,
    port,
    validateToken: provider.validateToken,
  };
}
