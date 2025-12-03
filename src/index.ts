/**
 * mcp-oidc-provider
 *
 * Framework-agnostic OIDC provider for MCP servers with pluggable identity providers.
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
 *   store: new Keyv(),
 *   baseUrl: 'https://your-server.com',
 *   secret: process.env.SESSION_SECRET,
 * });
 *
 * handleMcpRequest(async (req, res, user) => {
 *   // Your MCP handler
 * });
 *
 * app.listen(3000);
 * ```
 *
 * @packageDocumentation
 */

// Core provider
export { createOidcProvider } from './core/provider.js';

// Session store utilities
export { createSessionStore, createExtendedSessionStore } from './core/session-store.js';
export type { ExtendedSessionStore } from './core/session-store.js';

// OIDC adapter
export { createOidcAdapterFactory } from './core/oidc-adapter.js';
export type { OidcAdapterFactory } from './core/oidc-adapter.js';

// All types
export type {
  // Provider types
  OidcProviderConfig,
  OidcProvider,
  AuthenticatedUser,
  TokenValidationResult,
  // Identity provider types
  IdentityProviderClient,
  IdentityProviderConfig,
  AuthorizationParams,
  TokenSet,
  UserClaims,
  // HTTP abstraction types
  HttpContext,
  HttpRequest,
  HttpResponse,
  SessionData,
  Middleware,
  NextFunction,
  // Session types
  UserSession,
  SessionStore,
  InteractionSession,
} from './types/index.js';

// Logger utilities
export { createConsoleLogger, noopLogger } from './utils/logger.js';
export type { Logger, LogLevel } from './utils/logger.js';

// JWKS utilities
export { generateJwks } from './utils/jwks.js';
export type { JWK, JWKS, GenerateJwksOptions } from './utils/jwks.js';

// Configuration constants
export {
  DEFAULT_ACCESS_TOKEN_TTL,
  DEFAULT_AUTHORIZATION_CODE_TTL,
  DEFAULT_ID_TOKEN_TTL,
  DEFAULT_REFRESH_TOKEN_TTL,
  DEFAULT_INTERACTION_SESSION_TTL_MS,
  DEFAULT_USER_SESSION_TTL_MS,
  DEFAULT_INTERACTION_TTL,
  DEFAULT_GRANT_TTL,
  DEFAULT_SESSION_TTL,
  DEFAULT_SCOPES,
  DEFAULT_CLAIMS,
  DEFAULT_ROUTES,
  DEFAULT_ALLOWED_CLIENT_PROTOCOLS,
} from './core/config.js';
