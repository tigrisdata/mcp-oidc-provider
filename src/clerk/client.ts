import * as client from 'openid-client';
import { randomBytes } from 'node:crypto';
import { decodeJwt } from 'jose';
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
  private config: ClerkConfig;
  private oidcConfig: client.Configuration | null = null;

  constructor(config: ClerkConfig) {
    this.config = config;
  }

  /**
   * Get or discover the Clerk OIDC configuration.
   */
  private async getConfiguration(): Promise<client.Configuration> {
    if (this.oidcConfig) {
      return this.oidcConfig;
    }

    // Discover Clerk's OIDC configuration
    // Clerk's issuer URL format: https://<domain>
    const issuerUrl = this.config.domain.startsWith('http')
      ? this.config.domain
      : `https://${this.config.domain}`;

    this.oidcConfig = await client.discovery(
      new URL(issuerUrl),
      this.config.clientId,
      this.config.clientSecret
    );

    return this.oidcConfig;
  }

  /**
   * Generate a random state parameter.
   */
  private generateState(): string {
    return randomBytes(16).toString('hex');
  }

  /**
   * Generate a random nonce parameter.
   */
  private generateNonce(): string {
    return randomBytes(16).toString('hex');
  }

  /**
   * Create an authorization URL for initiating the OAuth flow.
   * Uses the scopes configured in the constructor (default: 'openid email profile').
   * Note: Clerk doesn't support offline_access scope.
   */
  async createAuthorizationUrl(): Promise<AuthorizationParams> {
    const configuration = await this.getConfiguration();

    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
    const state = this.generateState();
    const nonce = this.generateNonce();

    // Clerk doesn't support offline_access, so default to basic scopes
    const scope = this.config.scopes ?? 'openid email profile';

    const parameters: Record<string, string> = {
      redirect_uri: this.config.redirectUri,
      scope,
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
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
      // Clerk-specific claims
      firstName: payload['first_name'] as string | undefined,
      lastName: payload['last_name'] as string | undefined,
      username: payload['username'] as string | undefined,
      publicMetadata: payload['public_metadata'] as Record<string, unknown> | undefined,
      // Include all other claims
      ...payload,
    };
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
