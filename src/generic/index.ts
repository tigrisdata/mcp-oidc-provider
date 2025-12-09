/**
 * Generic OIDC client for any OIDC-compliant identity provider.
 *
 * This module provides a universal client that works with any identity provider
 * that implements the OpenID Connect specification. It uses OIDC Discovery
 * to automatically configure endpoints.
 *
 * @example Google
 * ```typescript
 * import { GenericOidcClient } from 'mcp-oidc-provider/generic';
 *
 * const client = new GenericOidcClient({
 *   issuer: 'https://accounts.google.com',
 *   clientId: process.env.GOOGLE_CLIENT_ID!,
 *   clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
 *   redirectUri: 'https://your-app.com/oauth/callback',
 * });
 * ```
 *
 * @example Microsoft Azure AD
 * ```typescript
 * const client = new GenericOidcClient({
 *   issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
 *   clientId: process.env.AZURE_CLIENT_ID!,
 *   clientSecret: process.env.AZURE_CLIENT_SECRET!,
 *   redirectUri: 'https://your-app.com/oauth/callback',
 * });
 * ```
 *
 * @example Okta
 * ```typescript
 * const client = new GenericOidcClient({
 *   issuer: 'https://your-domain.okta.com',
 *   clientId: process.env.OKTA_CLIENT_ID!,
 *   clientSecret: process.env.OKTA_CLIENT_SECRET!,
 *   redirectUri: 'https://your-app.com/oauth/callback',
 * });
 * ```
 *
 * @example Keycloak
 * ```typescript
 * const client = new GenericOidcClient({
 *   issuer: 'https://keycloak.example.com/realms/my-realm',
 *   clientId: process.env.KEYCLOAK_CLIENT_ID!,
 *   clientSecret: process.env.KEYCLOAK_CLIENT_SECRET!,
 *   redirectUri: 'https://your-app.com/oauth/callback',
 * });
 * ```
 *
 * @packageDocumentation
 */

export { GenericOidcClient } from './client.js';
export type { GenericOidcConfig, ExtractCustomDataFn } from './client.js';
