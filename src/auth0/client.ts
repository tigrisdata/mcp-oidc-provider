import { GenericOidcClient } from '../generic/client.js';
import type {
  IdentityProviderClient,
  AuthorizationParams,
  TokenSet,
  UserClaims,
} from '../types/idp.js';

/**
 * Configuration for Auth0 client.
 */
export interface Auth0Config {
  /** Auth0 domain (e.g., 'your-tenant.auth0.com') */
  domain: string;
  /** OAuth client ID */
  clientId: string;
  /** OAuth client secret */
  clientSecret: string;
  /** Redirect URI for OAuth callback */
  redirectUri: string;
  /** Optional API audience for access tokens */
  audience?: string;
  /**
   * OAuth scopes to request from Auth0.
   * Default: 'openid email profile offline_access'
   */
  scopes?: string;
}

/**
 * Auth0 client implementing the IdentityProviderClient interface.
 *
 * This is a convenience wrapper around GenericOidcClient with Auth0-specific defaults.
 *
 * @example
 * ```typescript
 * import { Auth0Client } from 'mcp-oidc-provider/auth0';
 *
 * const auth0 = new Auth0Client({
 *   domain: 'your-tenant.auth0.com',
 *   clientId: 'your-client-id',
 *   clientSecret: 'your-client-secret',
 *   redirectUri: 'https://your-app.com/oauth/callback',
 *   audience: 'https://your-api.com',
 * });
 * ```
 */
export class Auth0Client implements IdentityProviderClient {
  private client: GenericOidcClient;

  constructor(config: Auth0Config) {
    this.client = new GenericOidcClient({
      issuer: `https://${config.domain}`,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUri: config.redirectUri,
      scopes: config.scopes ?? 'openid email profile offline_access',
      additionalAuthParams: config.audience ? { audience: config.audience } : undefined,
    });
  }

  /**
   * Create an authorization URL for initiating the OAuth flow.
   * Uses the scopes configured in the constructor (default: 'openid email profile offline_access').
   */
  createAuthorizationUrl(): Promise<AuthorizationParams> {
    return this.client.createAuthorizationUrl();
  }

  /**
   * Exchange an authorization code for tokens.
   */
  exchangeCode(
    callbackUrl: string,
    codeVerifier: string,
    expectedState: string,
    expectedNonce?: string
  ): Promise<TokenSet> {
    return this.client.exchangeCode(callbackUrl, codeVerifier, expectedState, expectedNonce);
  }

  /**
   * Refresh an access token using a refresh token.
   */
  refreshToken(refreshToken: string): Promise<TokenSet> {
    return this.client.refreshToken(refreshToken);
  }

  /**
   * Parse and decode user claims from an ID token.
   * Note: This decodes without verification since verification happens during exchange.
   */
  parseIdToken(idToken: string): UserClaims {
    return this.client.parseIdToken(idToken);
  }

  /**
   * Extract custom data from user claims.
   * Override this method in a subclass to extract IdP-specific data
   * (e.g., organizations, roles, permissions).
   *
   * @param claims - The user claims from the ID token
   * @returns Custom data to store in the user session, or undefined
   */
  extractCustomData(claims: UserClaims): Record<string, unknown> | undefined {
    // Default implementation returns undefined.
    // Subclasses should override this method to extract custom data.
    void claims; // Suppress unused parameter warning
    return undefined;
  }
}
