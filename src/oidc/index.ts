/**
 * OIDC client for any OIDC-compliant identity provider.
 *
 * This module provides a universal client that works with any identity provider
 * that implements the OpenID Connect specification. It uses OIDC Discovery
 * to automatically configure endpoints.
 *
 * @example Google
 * ```typescript
 * import { OidcClient } from 'mcp-oidc-provider/oidc';
 *
 * const client = new OidcClient({
 *   issuer: 'https://accounts.google.com',
 *   clientId: process.env.GOOGLE_CLIENT_ID!,
 *   clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
 *   redirectUri: 'https://your-app.com/oauth/callback',
 * });
 * ```
 *
 * @example Auth0
 * ```typescript
 * const client = new OidcClient({
 *   issuer: 'https://your-tenant.auth0.com',
 *   clientId: process.env.AUTH0_CLIENT_ID!,
 *   clientSecret: process.env.AUTH0_CLIENT_SECRET!,
 *   redirectUri: 'https://your-app.com/oauth/callback',
 *   scopes: 'openid email profile offline_access',
 *   additionalAuthParams: { audience: 'https://your-api.com' },
 * });
 * ```
 *
 * @example Clerk
 * ```typescript
 * const client = new OidcClient({
 *   issuer: 'https://your-app.clerk.accounts.dev',
 *   clientId: process.env.CLERK_CLIENT_ID!,
 *   clientSecret: process.env.CLERK_CLIENT_SECRET!,
 *   redirectUri: 'https://your-app.com/oauth/callback',
 * });
 * ```
 *
 * @example Okta
 * ```typescript
 * const client = new OidcClient({
 *   issuer: 'https://your-domain.okta.com',
 *   clientId: process.env.OKTA_CLIENT_ID!,
 *   clientSecret: process.env.OKTA_CLIENT_SECRET!,
 *   redirectUri: 'https://your-app.com/oauth/callback',
 * });
 * ```
 *
 * @example Keycloak
 * ```typescript
 * const client = new OidcClient({
 *   issuer: 'https://keycloak.example.com/realms/my-realm',
 *   clientId: process.env.KEYCLOAK_CLIENT_ID!,
 *   clientSecret: process.env.KEYCLOAK_CLIENT_SECRET!,
 *   redirectUri: 'https://your-app.com/oauth/callback',
 * });
 * ```
 *
 * @example Microsoft Azure AD
 * ```typescript
 * const client = new OidcClient({
 *   issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
 *   clientId: process.env.AZURE_CLIENT_ID!,
 *   clientSecret: process.env.AZURE_CLIENT_SECRET!,
 *   redirectUri: 'https://your-app.com/oauth/callback',
 * });
 * ```
 *
 * @packageDocumentation
 */

export { OidcClient } from './client.js';
export type { OidcClientConfig, ExtractCustomDataFn } from './client.js';
