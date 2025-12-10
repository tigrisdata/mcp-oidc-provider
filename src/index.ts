/**
 * mcp-oidc-provider
 *
 * Framework-agnostic OIDC provider for MCP servers with pluggable identity providers.
 * Works with any OIDC-compliant identity provider (Auth0, Clerk, Okta, Keycloak, Azure AD, Google, etc.)
 *
 * @example Standalone OIDC Server with MCP SDK
 * ```typescript
 * import { Keyv } from 'keyv';
 * import { createOidcServer } from 'mcp-oidc-provider/express';
 * import { createMcpAuthProvider } from 'mcp-oidc-provider/mcp';
 * import { OidcClient } from 'mcp-oidc-provider';
 *
 * const store = new Keyv();
 *
 * // Create OIDC server with any OIDC provider
 * const oidcServer = createOidcServer({
 *   idpClient: new OidcClient({
 *     issuer: 'https://your-tenant.auth0.com', // or any OIDC issuer
 *     clientId: process.env.OIDC_CLIENT_ID!,
 *     clientSecret: process.env.OIDC_CLIENT_SECRET!,
 *     redirectUri: 'http://localhost:4001/oauth/callback',
 *   }),
 *   store,
 *   secret: process.env.SESSION_SECRET!,
 *   port: 4001,
 *   baseUrl: 'http://localhost:4001',
 * });
 *
 * await oidcServer.start();
 *
 * // Create MCP auth provider for SDK integration
 * const { proxyOAuthServerProviderConfig, mcpRoutes } = createMcpAuthProvider({
 *   oidcBaseUrl: 'http://localhost:4001',
 *   store,
 *   mcpServerBaseUrl: 'http://localhost:3001',
 * });
 * ```
 *
 * @packageDocumentation
 */

// Core provider
export { createOidcProvider } from './core/provider.js';

// OIDC client for any OIDC-compliant identity provider
export { OidcClient } from './oidc/client.js';
export type { OidcClientConfig, ExtractCustomDataFn } from './oidc/client.js';

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
  // OIDC client interface
  IOidcClient,
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
  // Store types
  KeyvLike,
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
