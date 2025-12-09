import { GenericOidcClient } from '../generic/client.js';
import type {
  IdentityProviderClient,
  AuthorizationParams,
  TokenSet,
  UserClaims,
} from '../types/idp.js';

/**
 * Configuration for Clerk client.
 */
export interface ClerkConfig {
  /** Clerk domain (e.g., 'your-app.clerk.accounts.dev' or custom domain) */
  domain: string;
  /** OAuth client ID (from Clerk Dashboard) */
  clientId: string;
  /** OAuth client secret (from Clerk Dashboard) */
  clientSecret: string;
  /** Redirect URI for OAuth callback */
  redirectUri: string;
  /**
   * OAuth scopes to request from Clerk.
   * Note: Clerk doesn't support offline_access scope.
   * Default: 'openid email profile'
   */
  scopes?: string;
}

/**
 * Clerk client implementing the IdentityProviderClient interface.
 *
 * This is a convenience wrapper around GenericOidcClient with Clerk-specific defaults
 * and custom data extraction for organizations and metadata.
 *
 * To use Clerk as your identity provider:
 * 1. Go to Clerk Dashboard > Configure > SSO Connections
 * 2. Create an OAuth application or use the built-in OIDC support
 * 3. Copy the Client ID and Client Secret
 * 4. Set the redirect URI to your callback URL
 *
 * @example
 * ```typescript
 * import { ClerkClient } from 'mcp-oidc-provider/clerk';
 *
 * const clerk = new ClerkClient({
 *   domain: 'your-app.clerk.accounts.dev',
 *   clientId: 'your-client-id',
 *   clientSecret: 'your-client-secret',
 *   redirectUri: 'https://your-app.com/oauth/callback',
 * });
 * ```
 */
export class ClerkClient implements IdentityProviderClient {
  private client: GenericOidcClient;

  constructor(config: ClerkConfig) {
    // Normalize domain - Clerk accepts both with and without https://
    const issuer = config.domain.startsWith('http')
      ? config.domain
      : `https://${config.domain}`;

    this.client = new GenericOidcClient({
      issuer,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUri: config.redirectUri,
      // Clerk doesn't support offline_access, so default to basic scopes
      scopes: config.scopes ?? 'openid email profile',
    });
  }

  /**
   * Create an authorization URL for initiating the OAuth flow.
   * Uses the scopes configured in the constructor (default: 'openid email profile').
   * Note: Clerk doesn't support offline_access scope.
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
   * Extracts Clerk-specific data like organizations and metadata.
   *
   * @param claims - The user claims from the ID token
   * @returns Custom data including organizations and metadata
   */
  extractCustomData(claims: UserClaims): Record<string, unknown> | undefined {
    const customData: Record<string, unknown> = {};

    // Extract organization data if present
    if (claims['org_id']) {
      customData['organization'] = {
        id: claims['org_id'],
        slug: claims['org_slug'],
        role: claims['org_role'],
        permissions: claims['org_permissions'],
      };
    }

    // Extract public metadata
    if (claims['public_metadata']) {
      customData['publicMetadata'] = claims['public_metadata'];
    }

    // Extract user metadata
    if (claims['unsafe_metadata']) {
      customData['unsafeMetadata'] = claims['unsafe_metadata'];
    }

    return Object.keys(customData).length > 0 ? customData : undefined;
  }
}
