import * as client from 'openid-client';
import { randomBytes } from 'node:crypto';
import { decodeJwt } from 'jose';
import type { IOidcClient, AuthorizationParams, TokenSet, UserClaims } from '../types.js';

/**
 * Function type for extracting custom data from ID token claims.
 * Use this to extract provider-specific data like organizations, roles, or metadata.
 *
 * @example
 * ```typescript
 * // Extract Okta groups
 * const extractGroups: ExtractCustomDataFn = (claims) => {
 *   if (claims['groups']) {
 *     return { groups: claims['groups'] };
 *   }
 *   return undefined;
 * };
 * ```
 */
export type ExtractCustomDataFn = (claims: UserClaims) => Record<string, unknown> | undefined;

/**
 * Configuration for the OIDC client.
 * Works with any OIDC-compliant identity provider.
 */
export interface OidcClientConfig {
  /**
   * OIDC issuer URL. This is the base URL where the provider's
   * `.well-known/openid-configuration` endpoint is located.
   *
   * @example
   * - Google: 'https://accounts.google.com'
   * - Microsoft: 'https://login.microsoftonline.com/{tenant}/v2.0'
   * - Okta: 'https://{domain}.okta.com'
   * - Keycloak: 'https://{host}/realms/{realm}'
   * - Auth0: 'https://{tenant}.auth0.com'
   * - Clerk: 'https://{app}.clerk.accounts.dev'
   */
  issuer: string;

  /** OAuth client ID from your identity provider */
  clientId: string;

  /** OAuth client secret from your identity provider */
  clientSecret: string;

  /** Redirect URI for OAuth callback (must be registered with your provider) */
  redirectUri: string;

  /**
   * OAuth scopes to request.
   * @default 'openid email profile'
   */
  scopes?: string;

  /**
   * Additional parameters to include in the authorization request.
   * Useful for provider-specific parameters like:
   * - `audience` (Auth0)
   * - `resource` (Azure AD)
   * - `acr_values` (various providers)
   * - `prompt` (force login, consent, etc.)
   *
   * @example
   * ```typescript
   * additionalAuthParams: {
   *   audience: 'https://my-api.example.com',
   *   prompt: 'consent',
   * }
   * ```
   */
  additionalAuthParams?: Record<string, string>;

  /**
   * Custom function to extract provider-specific data from ID token claims.
   * The extracted data will be available in `req.user.customData`.
   *
   * @example
   * ```typescript
   * extractCustomData: (claims) => {
   *   const data: Record<string, unknown> = {};
   *
   *   // Extract organization info (Clerk-style)
   *   if (claims['org_id']) {
   *     data.organization = {
   *       id: claims['org_id'],
   *       role: claims['org_role'],
   *     };
   *   }
   *
   *   // Extract groups (Okta/Azure AD style)
   *   if (claims['groups']) {
   *     data.groups = claims['groups'];
   *   }
   *
   *   return Object.keys(data).length > 0 ? data : undefined;
   * }
   * ```
   */
  extractCustomData?: ExtractCustomDataFn;
}

/**
 * OIDC client that works with any OIDC-compliant identity provider.
 *
 * This client uses OpenID Connect Discovery to automatically configure
 * endpoints from the provider's `.well-known/openid-configuration`.
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
 * @example Microsoft / Azure AD
 * ```typescript
 * const client = new OidcClient({
 *   issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
 *   clientId: process.env.AZURE_CLIENT_ID!,
 *   clientSecret: process.env.AZURE_CLIENT_SECRET!,
 *   redirectUri: 'https://your-app.com/oauth/callback',
 *   scopes: 'openid email profile offline_access',
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
 *   extractCustomData: (claims) => {
 *     if (claims['groups']) {
 *       return { groups: claims['groups'] };
 *     }
 *   },
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
 *   extractCustomData: (claims) => {
 *     const data: Record<string, unknown> = {};
 *     if (claims['realm_access']) {
 *       data.realmRoles = (claims['realm_access'] as { roles?: string[] })?.roles;
 *     }
 *     if (claims['resource_access']) {
 *       data.resourceAccess = claims['resource_access'];
 *     }
 *     return Object.keys(data).length > 0 ? data : undefined;
 *   },
 * });
 * ```
 *
 * @example Auth0 with audience
 * ```typescript
 * const client = new OidcClient({
 *   issuer: 'https://your-tenant.auth0.com',
 *   clientId: process.env.AUTH0_CLIENT_ID!,
 *   clientSecret: process.env.AUTH0_CLIENT_SECRET!,
 *   redirectUri: 'https://your-app.com/oauth/callback',
 *   scopes: 'openid email profile offline_access',
 *   additionalAuthParams: {
 *     audience: 'https://your-api.example.com',
 *   },
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
 *   // Note: Clerk doesn't support offline_access
 *   extractCustomData: (claims) => {
 *     const data: Record<string, unknown> = {};
 *     if (claims['org_id']) {
 *       data.organization = {
 *         id: claims['org_id'],
 *         slug: claims['org_slug'],
 *         role: claims['org_role'],
 *       };
 *     }
 *     return Object.keys(data).length > 0 ? data : undefined;
 *   },
 * });
 * ```
 */
export class OidcClient implements IOidcClient {
  private config: OidcClientConfig;
  private oidcConfig: client.Configuration | null = null;

  constructor(config: OidcClientConfig) {
    this.config = config;
  }

  /**
   * Get or discover the OIDC configuration from the issuer.
   * Results are cached after the first call.
   */
  private async getConfiguration(): Promise<client.Configuration> {
    if (this.oidcConfig) {
      return this.oidcConfig;
    }

    // Normalize issuer URL (ensure it has https:// prefix)
    const issuerUrl = this.config.issuer.startsWith('http')
      ? this.config.issuer
      : `https://${this.config.issuer}`;

    // Discover OIDC configuration from .well-known/openid-configuration
    this.oidcConfig = await client.discovery(
      new URL(issuerUrl),
      this.config.clientId,
      this.config.clientSecret
    );

    return this.oidcConfig;
  }

  /**
   * Generate a random state parameter for CSRF protection.
   */
  private generateState(): string {
    return randomBytes(16).toString('hex');
  }

  /**
   * Generate a random nonce for replay protection.
   */
  private generateNonce(): string {
    return randomBytes(16).toString('hex');
  }

  /**
   * Create an authorization URL for initiating the OAuth flow.
   * Uses PKCE (Proof Key for Code Exchange) for enhanced security.
   */
  async createAuthorizationUrl(): Promise<AuthorizationParams> {
    const configuration = await this.getConfiguration();

    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
    const state = this.generateState();
    const nonce = this.generateNonce();

    const scope = this.config.scopes ?? 'openid email profile';

    const parameters: Record<string, string> = {
      redirect_uri: this.config.redirectUri,
      scope,
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      // Merge any additional auth parameters
      ...this.config.additionalAuthParams,
    };

    const authorizationUrl = client.buildAuthorizationUrl(configuration, parameters);

    return {
      authorizationUrl: authorizationUrl.toString(),
      state,
      nonce,
      codeVerifier,
    };
  }

  /**
   * Exchange an authorization code for tokens.
   */
  async exchangeCode(
    callbackUrl: string,
    codeVerifier: string,
    expectedState: string,
    expectedNonce?: string
  ): Promise<TokenSet> {
    const configuration = await this.getConfiguration();

    const tokens = await client.authorizationCodeGrant(configuration, new URL(callbackUrl), {
      pkceCodeVerifier: codeVerifier,
      expectedState,
      expectedNonce,
    });

    return {
      accessToken: tokens.access_token ?? '',
      idToken: tokens.id_token,
      refreshToken: tokens.refresh_token,
      expiresIn: tokens.expires_in,
      tokenType: tokens.token_type,
    };
  }

  /**
   * Refresh an access token using a refresh token.
   */
  async refreshToken(refreshToken: string): Promise<TokenSet> {
    const configuration = await this.getConfiguration();

    const tokens = await client.refreshTokenGrant(configuration, refreshToken);

    return {
      accessToken: tokens.access_token ?? '',
      idToken: tokens.id_token,
      refreshToken: tokens.refresh_token,
      expiresIn: tokens.expires_in,
      tokenType: tokens.token_type,
    };
  }

  /**
   * Parse and decode user claims from an ID token.
   * Note: This decodes without verification since verification happens during exchange.
   */
  parseIdToken(idToken: string): UserClaims {
    const payload = decodeJwt(idToken);

    return {
      sub: payload.sub ?? '',
      email: payload['email'] as string | undefined,
      emailVerified: payload['email_verified'] as boolean | undefined,
      name: payload['name'] as string | undefined,
      nickname: payload['nickname'] as string | undefined,
      picture: payload['picture'] as string | undefined,
      updatedAt: payload['updated_at'] as number | undefined,
      // Include all other claims for provider-specific data
      ...payload,
    };
  }

  /**
   * Extract custom data from user claims.
   * Uses the extractCustomData function provided in the config, if any.
   */
  extractCustomData(claims: UserClaims): Record<string, unknown> | undefined {
    if (this.config.extractCustomData) {
      return this.config.extractCustomData(claims);
    }
    return undefined;
  }
}
