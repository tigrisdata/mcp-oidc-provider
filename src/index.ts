/**
 * mcp-oidc-provider
 *
 * An OAuth 2.1 authorization server for MCP clients that relays to the
 * identity provider you already have (Auth0, Okta, Keycloak, Entra ID,
 * Google, ...). MCP clients register with the relay (Dynamic Client
 * Registration or Client ID Metadata Documents), the user approves the
 * client on the relay's consent page, and the relay forwards the
 * authorization code and refresh token grants to the provider using its
 * single confidential client. Tokens are minted by the provider only; the
 * relay stores no tokens and holds no signing key.
 *
 * @example
 * ```typescript
 * import { createMcpExpressApp, requireBearerAuth } from '@modelcontextprotocol/express';
 * import { Keyv } from 'keyv';
 * import { createAuthRelay } from 'mcp-oidc-provider';
 *
 * const relay = createAuthRelay({
 *   baseUrl: 'https://mcp.example.com',
 *   upstream: {
 *     issuer: 'https://your-tenant.auth0.com',
 *     clientId: process.env.OIDC_CLIENT_ID!,
 *     clientSecret: process.env.OIDC_CLIENT_SECRET!,
 *     audience: 'https://api.example.com',
 *   },
 *   store: new Keyv(),
 * });
 *
 * const app = createMcpExpressApp({ host: '0.0.0.0', allowedHosts: ['mcp.example.com'] });
 * app.use(relay.router);
 * app.post(
 *   '/mcp',
 *   requireBearerAuth({
 *     verifier: relay.verifier,
 *     resourceMetadataUrl: relay.resourceMetadataUrl,
 *     expectedResource: relay.resource,
 *   }),
 *   mcpHandler
 * );
 * app.listen(3000);
 * ```
 *
 * @packageDocumentation
 */

export {
  createAuthRelay,
  DEFAULT_CALLBACK_PATH,
  DEFAULT_CONSENT_COOKIE_NAME,
  DEFAULT_CONSENT_TTL,
  DEFAULT_MCP_ENDPOINT_PATH,
  type AuthRelay,
} from './relay/create-auth-relay.js';

export type {
  AuthRelayOptions,
  ClientOptions,
  ConsentOptions,
  CustomDataContext,
  CustomDataFn,
  JwksCacheOptions,
  KeyvLike,
  TokenResponseEvent,
  TokenResponseHook,
  UpstreamMetadata,
  UpstreamOptions,
} from './types.js';

export type { ConsentView } from './relay/html.js';
export { escapeHtml } from './relay/html.js';
export type { OAuthMetadata } from './relay/metadata.js';
export { DEFAULT_UPSTREAM_SCOPES, DEFAULT_JWKS_CACHE_OPTIONS } from './relay/upstream.js';
export { DEFAULT_REGISTRATION_TTL, DEFAULT_CIMD_CACHE_TTL } from './relay/clients.js';
export { STORAGE_NAMESPACES } from './relay/storage.js';

export { createConsoleLogger, noopLogger } from './utils/logger.js';
export type { Logger, LogLevel } from './utils/logger.js';
