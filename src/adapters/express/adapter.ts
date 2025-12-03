import { Router, type RequestHandler } from 'express';
import type { OidcProvider } from '../../types/provider.js';
import { createExpressHttpContext } from './http-context.js';

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
}

/**
 * Result of creating an Express adapter.
 */
export interface ExpressAdapterResult {
  /**
   * Express router containing the OAuth custom routes.
   * Mount this at your OAuth base path (e.g., '/oauth').
   */
  routes: Router;

  /**
   * The oidc-provider callback handler.
   * Mount this at your root path to handle OIDC endpoints.
   *
   * @example
   * ```typescript
   * app.use('/oauth', routes);
   * app.use('/', providerCallback());
   * ```
   */
  providerCallback: () => RequestHandler;

  /**
   * Check if a path is handled by the OIDC provider.
   * Useful for excluding provider routes from other middleware.
   */
  isProviderRoute: (path: string) => boolean;
}

/**
 * OIDC provider route paths (endpoints handled by oidc-provider).
 */
const PROVIDER_ROUTES = [
  '/authorize',
  '/token',
  '/jwks',
  '/me',
  '/register',
  '/introspect',
  '/revoke',
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
 * @example
 * ```typescript
 * import express from 'express';
 * import { isOidcProviderRoute } from 'mcp-oidc-provider/express';
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
 * - The oidc-provider callback handler for standard OIDC endpoints
 * - A helper to check if a path is handled by the provider
 *
 * @param provider - The OIDC provider instance
 * @param options - Adapter options
 * @returns Express adapter result
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { createOidcProvider } from 'mcp-oidc-provider';
 * import { createExpressAdapter } from 'mcp-oidc-provider/express';
 *
 * const app = express();
 * const oidcProvider = createOidcProvider({ ... });
 * const { routes, providerCallback } = createExpressAdapter(oidcProvider);
 *
 * // Mount custom routes at /oauth
 * app.use('/oauth', routes);
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

  const routes = Router();

  // Interaction route - handles OAuth authorization flow
  routes.get(`${interactionPath}/:uid`, (req, res) => {
    const ctx = createExpressHttpContext(req, res);
    void provider.handleInteraction(ctx);
  });

  // IdP callback - handles the response from the identity provider
  routes.get(callbackPath, (req, res) => {
    const ctx = createExpressHttpContext(req, res);
    void provider.handleCallback(ctx);
  });

  return {
    routes,
    providerCallback: () => provider.provider.callback(),
    isProviderRoute: (path: string) => {
      return PROVIDER_ROUTES.some((route) => path === route || path.startsWith(`${route}/`));
    },
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
 * @example
 * ```typescript
 * import { createCompleteExpressRouter } from 'mcp-oidc-provider/express';
 *
 * const oauthRouter = createCompleteExpressRouter(oidcProvider);
 * app.use('/oauth', oauthRouter);
 * ```
 */
export function createCompleteExpressRouter(
  provider: OidcProvider,
  options?: ExpressAdapterOptions
): Router {
  const { routes, providerCallback } = createExpressAdapter(provider, options);

  const router = Router();

  // Mount custom routes first
  router.use(routes);

  // Mount provider callback to handle standard OIDC endpoints
  router.use(providerCallback());

  return router;
}
