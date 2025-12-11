import express, { Router, type RequestHandler, type Request, type Response } from 'express';
import type { OidcProvider } from '../core/types.js';
import { DEFAULT_SCOPES } from '../core/config.js';

/**
 * Options for the Express adapter.
 */
export interface ExpressAdapterOptions {
  /**
   * Base path for the interaction route.
   * Default: '/interaction'
   */
  interactionPath?: string;
  /**
   * Path for the IdP callback route.
   * Default: '/callback'
   */
  callbackPath?: string;
  /**
   * Base URL of the server (used for well-known endpoints).
   * If not provided, will be inferred from the request.
   */
  baseUrl?: string;
  /**
   * Scopes supported by the MCP resource server.
   * Default: ['openid', 'email', 'profile', 'offline_access']
   */
  scopes?: string[];
  /**
   * MCP resource path (used in protected resource metadata).
   * Default: '/mcp'
   */
  mcpPath?: string;
}

/**
 * Result of creating an Express adapter.
 */
export interface ExpressAdapterResult {
  /**
   * Express router containing the OAuth custom routes (interaction, callback).
   * Mount this at your OAuth base path (e.g., '/oauth').
   */
  routes: Router;

  /**
   * Express router containing well-known endpoints.
   * Mount this at your root path.
   */
  wellKnownRoutes: Router;

  /**
   * The oidc-provider callback handler with scope injection for Cursor compatibility.
   * Mount this at your root path to handle OIDC endpoints.
   *
   * @example
   * ```typescript
   * app.use('/oauth', routes);
   * app.use('/', wellKnownRoutes);
   * app.use('/', providerCallback());
   * ```
   */
  providerCallback: () => RequestHandler;

  /**
   * Body parser middleware that automatically skips OIDC provider routes.
   * Use this instead of express.json() to avoid body parsing conflicts.
   *
   * @example
   * ```typescript
   * app.use(bodyParserMiddleware);
   * ```
   */
  bodyParserMiddleware: RequestHandler;

  /**
   * Check if a path is handled by the OIDC provider.
   * Useful for excluding provider routes from other middleware.
   */
  isProviderRoute: (path: string) => boolean;
}

/**
 * OIDC provider route paths (endpoints handled by oidc-provider).
 * These routes should NOT have their bodies parsed by upstream middleware
 * as oidc-provider handles body parsing itself.
 */
const PROVIDER_ROUTES = [
  '/authorize',
  '/auth',
  '/token',
  '/jwks',
  '/certs',
  '/me',
  '/userinfo',
  '/register',
  '/reg',
  '/introspect',
  '/revoke',
  '/session',
  '/end_session',
  '/device',
  '/pushed_authorization_request',
  '/.well-known/openid-configuration',
  '/.well-known/oauth-authorization-server',
];

/**
 * Check if a path is an OIDC provider route.
 * Useful for excluding these routes from body parsing middleware.
 *
 * @param path - The request path to check
 * @returns true if the path is handled by oidc-provider
 *
 * @internal This is an internal utility used by setupMcpExpress and createOidcServer.
 *
 * @example
 * ```typescript
 * import express from 'express';
 *
 * // Skip body parsing for oidc-provider routes
 * app.use((req, res, next) => {
 *   if (isOidcProviderRoute(req.path)) {
 *     return next();
 *   }
 *   express.json()(req, res, next);
 * });
 * ```
 */
export function isOidcProviderRoute(path: string): boolean {
  return PROVIDER_ROUTES.some((route) => path === route || path.startsWith(`${route}/`));
}

/**
 * Create an Express adapter for the OIDC provider.
 *
 * This adapter provides:
 * - Custom routes for interaction (login/consent) and IdP callback
 * - Well-known endpoints for OAuth/OIDC discovery
 * - Body parser middleware that skips OIDC routes
 * - Scope injection for Cursor compatibility
 * - A helper to check if a path is handled by the provider
 *
 * @param provider - The OIDC provider instance
 * @param options - Adapter options
 * @returns Express adapter result
 *
 * @internal This is an internal utility used by setupMcpExpress and createOidcServer.
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { createOidcProvider } from 'mcp-oidc-provider';
 *
 * const app = express();
 * const oidcProvider = createOidcProvider({ ... });
 * const { routes, wellKnownRoutes, providerCallback, bodyParserMiddleware } =
 *   createExpressAdapter(oidcProvider, { baseUrl: 'https://your-server.com' });
 *
 * // Use body parser that skips OIDC routes
 * app.use(bodyParserMiddleware);
 *
 * // Mount custom routes at /oauth
 * app.use('/oauth', routes);
 *
 * // Mount well-known endpoints
 * app.use('/', wellKnownRoutes);
 *
 * // Mount provider callback at root to handle /authorize, /token, etc.
 * app.use('/', providerCallback());
 * ```
 */
export function createExpressAdapter(
  provider: OidcProvider,
  options?: ExpressAdapterOptions
): ExpressAdapterResult {
  const interactionPath = options?.interactionPath ?? '/interaction';
  const callbackPath = options?.callbackPath ?? '/callback';
  const scopes = options?.scopes ?? DEFAULT_SCOPES;
  const mcpPath = options?.mcpPath ?? '/mcp';

  // Helper to get base URL from request or options
  const getBaseUrl = (req: Request): string => {
    if (options?.baseUrl) {
      return options.baseUrl;
    }
    const protocol = req.protocol;
    const host = req.get('host') ?? 'localhost';
    return `${protocol}://${host}`;
  };

  // OAuth routes (interaction and callback)
  const routes = Router();

  // Interaction route - handles OAuth authorization flow
  routes.get(`${interactionPath}/:uid`, (req, res) => {
    void provider.handleInteraction(req, res);
  });

  // IdP callback - handles the response from the identity provider
  routes.get(callbackPath, (req, res) => {
    void provider.handleCallback(req, res);
  });

  // Well-known routes
  const wellKnownRoutes = Router();

  // OAuth protected resource metadata
  wellKnownRoutes.get('/.well-known/oauth-protected-resource', (req: Request, res: Response) => {
    const baseUrl = getBaseUrl(req);
    res.json({
      resource: `${baseUrl}${mcpPath}`,
      authorization_servers: [baseUrl],
      bearer_methods_supported: ['header'],
      resource_signing_alg_values_supported: ['RS256'],
      scopes_supported: scopes,
    });
  });

  // OAuth protected resource metadata with resource parameter
  // Some clients (like ChatGPT) may request this with a resource path
  wellKnownRoutes.get(
    '/.well-known/oauth-protected-resource/:resource',
    (req: Request, res: Response) => {
      const baseUrl = getBaseUrl(req);
      const resource = req.params['resource'] ?? 'mcp';
      res.json({
        resource: `${baseUrl}/${resource}`,
        authorization_servers: [baseUrl],
        bearer_methods_supported: ['header'],
        resource_signing_alg_values_supported: ['RS256'],
        scopes_supported: scopes,
      });
    }
  );

  // OAuth authorization server metadata with resource parameter
  // Some clients may request discovery with a resource indicator
  wellKnownRoutes.get(
    '/.well-known/oauth-authorization-server/:resource',
    async (req: Request, res: Response) => {
      const baseUrl = getBaseUrl(req);
      try {
        // Fetch the base discovery document from oidc-provider
        const discoveryUrl = `${baseUrl}/.well-known/oauth-authorization-server`;
        const response = await fetch(discoveryUrl);
        const data = await response.json();
        res.json(data);
      } catch {
        res.status(500).json({ error: 'Failed to fetch discovery metadata' });
      }
    }
  );

  // Body parser middleware that skips OIDC provider routes
  const bodyParserMiddleware: RequestHandler = (req, res, next) => {
    if (isOidcProviderRoute(req.path)) {
      next();
      return;
    }
    express.json()(req, res, next);
  };

  // Provider callback with scope injection for Cursor compatibility
  // Cursor doesn't send scope parameter, so we inject 'openid' as default
  const providerCallbackWithScopeInjection = (): RequestHandler => {
    // oidc-provider callback works with Express despite being Koa-based
    const callback = provider.provider.callback() as unknown as RequestHandler;
    return (req, res, next) => {
      if (req.path === '/authorize' && req.method === 'GET' && !req.query['scope']) {
        const url = new URL(req.originalUrl, `http://${req.headers.host ?? 'localhost'}`);
        url.searchParams.set('scope', 'openid');
        req.url = url.pathname + url.search;
      }
      return callback(req, res, next);
    };
  };

  return {
    routes,
    wellKnownRoutes,
    providerCallback: providerCallbackWithScopeInjection,
    bodyParserMiddleware,
    isProviderRoute: isOidcProviderRoute,
  };
}

/**
 * Create a complete Express router with all OIDC routes.
 * This is a convenience function that combines custom routes with provider routes.
 *
 * @param provider - The OIDC provider instance
 * @param options - Adapter options
 * @returns Express router with all routes
 *
 * @internal This is an internal utility used by setupMcpExpress and createOidcServer.
 *
 * @example
 * ```typescript
 * const oauthRouter = createCompleteExpressRouter(oidcProvider);
 * app.use('/oauth', oauthRouter);
 * ```
 */
export function createCompleteExpressRouter(
  provider: OidcProvider,
  options?: ExpressAdapterOptions
): Router {
  const { routes, wellKnownRoutes, providerCallback } = createExpressAdapter(provider, options);

  const router = Router();

  // Mount custom routes first
  router.use(routes);

  // Mount well-known routes
  router.use(wellKnownRoutes);

  // Mount provider callback to handle standard OIDC endpoints
  router.use(providerCallback());

  return router;
}
