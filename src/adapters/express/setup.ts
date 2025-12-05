import express, {
  type Application,
  type Request,
  type Response,
  type RequestHandler,
} from 'express';
import session from 'express-session';
import { Keyv } from 'keyv';
import type { IdentityProviderClient } from '../../types/idp.js';
import type { AuthenticatedUser } from '../../types/provider.js';
import type { KeyvLike } from '../../types/store.js';
import type { JWKS } from '../../utils/jwks.js';
import { createOidcProvider } from '../../core/provider.js';
import { createExpressAdapter, isOidcProviderRoute } from './adapter.js';
import { createExpressAuthMiddleware } from './middleware.js';
import { createMcpCorsMiddleware } from './cors.js';
import { KeyvSessionStore } from './session-store.js';

/**
 * Options for setting up an Express MCP server.
 */
export interface McpExpressSetupOptions {
  /**
   * Identity provider client (e.g., Auth0Client).
   */
  idpClient: IdentityProviderClient;

  /**
   * Keyv instance for storage.
   * Used for sessions, tokens, grants, and other OIDC data.
   * Any Keyv instance will work regardless of version.
   *
   * @example
   * ```typescript
   * // In-memory (development only)
   * import { Keyv } from 'keyv';
   * const store = new Keyv();
   *
   * // Redis (production)
   * import KeyvRedis from '@keyv/redis';
   * const store = new Keyv({ store: new KeyvRedis('redis://localhost:6379') });
   * ```
   */
  store: KeyvLike;

  /**
   * Base URL of the server.
   * Used for issuer, CORS, OAuth metadata, and session cookies.
   */
  baseUrl: string;

  /**
   * Secret for signing cookies and sessions.
   * Use a strong, random value in production.
   */
  secret: string;

  /**
   * Optional JWKS for signing tokens.
   * If not provided, development keys are generated (with a warning).
   * In production, generate once using: generateJwks()
   */
  jwks?: JWKS;

  /**
   * Whether running in production mode.
   * Affects cookie security settings (secure, sameSite).
   * Default: process.env.NODE_ENV === 'production'
   */
  isProduction?: boolean;

  /**
   * Session max age in milliseconds.
   * Default: 30 days
   */
  sessionMaxAge?: number;

  /**
   * Additional origins to allow for CORS (beyond MCP Inspector and baseUrl).
   */
  additionalCorsOrigins?: string[];

  /**
   * Custom middleware to run after CORS but before other middleware.
   * Useful for request logging, etc.
   */
  customMiddleware?: RequestHandler[];

  /**
   * Scopes to request from the upstream identity provider.
   * Some IdPs (like Clerk) don't support all scopes.
   * Default: 'openid email profile offline_access'
   *
   * @example
   * ```typescript
   * // For Clerk (doesn't support offline_access)
   * idpScopes: 'openid email profile'
   * ```
   */
  idpScopes?: string;
}

/**
 * MCP request handler function.
 * Called for POST requests to /mcp (authenticated) and GET/DELETE (stateless).
 *
 * For POST: user is the authenticated user
 * For GET/DELETE: user is undefined (stateless session handling)
 */
export type McpRequestHandler = (
  req: Request,
  res: Response,
  user: AuthenticatedUser | undefined
) => void | Promise<void>;

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
   * handleMcpRequest(async (req, res, user) => {
   *   // user is defined for POST (authenticated)
   *   // user is undefined for GET/DELETE (stateless session handling)
   * });
   *
   * app.listen(3000);
   * ```
   */
  app: Application;

  /**
   * Register your MCP request handler.
   * This handler is called for:
   * - POST requests (authenticated, user is defined)
   * - GET/DELETE requests (stateless, user is undefined)
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
 * import { setupMcpExpress } from 'mcp-oidc-provider/express';
 * import { Auth0Client } from 'mcp-oidc-provider/auth0';
 *
 * const { app, handleMcpRequest } = setupMcpExpress({
 *   idpClient: new Auth0Client({
 *     domain: process.env.AUTH0_DOMAIN,
 *     clientId: process.env.AUTH0_CLIENT_ID,
 *     clientSecret: process.env.AUTH0_CLIENT_SECRET,
 *     redirectUri: `${BASE_URL}/oauth/callback`,
 *   }),
 *   store: new Keyv(),  // In-memory for dev, use Redis/etc for production
 *   baseUrl: 'https://your-server.com',
 *   secret: process.env.SESSION_SECRET,
 * });
 *
 * handleMcpRequest(async (req, res, user) => {
 *   const transport = new StreamableHTTPServerTransport({ ... });
 *   const server = createMcpServer(user);
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
    idpScopes,
  } = options;

  // Create Express app
  const app = express();
  app.set('trust proxy', 1);

  // Create OIDC provider - it handles namespacing internally
  const provider = createOidcProvider({
    issuer: baseUrl,
    idpClient,
    store,
    cookieSecrets: [secret],
    isProduction,
    jwks,
    idpScopes,
  });

  // Create CORS middleware
  const corsMiddleware = createMcpCorsMiddleware({
    baseUrl,
    additionalOrigins: additionalCorsOrigins,
  });

  // Create Express adapter
  const adapter = createExpressAdapter(provider, { baseUrl, mcpPath: '/mcp' });

  // Create auth middleware
  const authMiddleware = createExpressAuthMiddleware(provider);

  // Create session store from Keyv
  const expressSessionStore = new Keyv({
    store: store.opts?.store,
    namespace: 'express-sessions',
    ttl: sessionMaxAge,
  });

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

  // Create body parser middleware that skips OIDC routes
  const bodyParserMiddleware = adapter.bodyParserMiddleware;

  const urlencodedMiddleware: RequestHandler = (req, res, next) => {
    if (isOidcProviderRoute(req.path)) {
      next();
      return;
    }
    express.urlencoded({ extended: true })(req, res, next);
  };

  // Apply middleware in order
  // 1. Health check (before other middleware for fast response)
  app.get('/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // 2. CORS - must be first for preflight requests
  app.use(corsMiddleware);

  // 3. Session management
  app.use(sessionMiddleware);

  // 4. Body parsing
  app.use(bodyParserMiddleware);
  app.use(urlencodedMiddleware);

  // 5. Custom middleware (e.g., request logging)
  for (const middleware of customMiddleware) {
    app.use(middleware);
  }

  // 6. OAuth routes at /oauth
  app.use('/oauth', adapter.routes);

  // 7. Well-known endpoints at root
  app.use('/', adapter.wellKnownRoutes);

  // Store for the MCP handler
  let mcpHandler: McpRequestHandler | undefined;

  // 8. MCP endpoint with authentication (POST)
  const mcpPostHandler = async (req: Request, res: Response): Promise<void> => {
    if (!req.user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    if (!mcpHandler) {
      res.status(500).json({ error: 'MCP handler not configured' });
      return;
    }

    await mcpHandler(req, res, req.user);
  };

  // 9. Session handler for GET and DELETE (stateless, no auth)
  const mcpSessionHandler = async (req: Request, res: Response): Promise<void> => {
    if (!mcpHandler) {
      res.status(500).json({ error: 'MCP handler not configured' });
      return;
    }

    await mcpHandler(req, res, undefined);
  };

  app.post('/mcp', authMiddleware, mcpPostHandler);
  app.get('/mcp', mcpSessionHandler);
  app.delete('/mcp', mcpSessionHandler);

  // 9. OIDC provider at root (must be after custom routes)
  app.use('/', adapter.providerCallback());

  // 10. 404 handler
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
