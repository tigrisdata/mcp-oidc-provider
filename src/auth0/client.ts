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
  private config: Auth0Config;
  private oidcConfig: client.Configuration | null = null;

  constructor(config: Auth0Config) {
    this.config = config;
  }

  /**
   * Get or discover the Auth0 OIDC configuration.
   */
  private async getConfiguration(): Promise<client.Configuration> {
    if (this.oidcConfig) {
      return this.oidcConfig;
    }

    // Discover Auth0's OIDC configuration
    this.oidcConfig = await client.discovery(
      new URL(`https://${this.config.domain}`),
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
   * Uses the scopes configured in the constructor (default: 'openid email profile offline_access').
   */
  async createAuthorizationUrl(): Promise<AuthorizationParams> {
    const configuration = await this.getConfiguration();

    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
    const state = this.generateState();
    const nonce = this.generateNonce();

    const scope = this.config.scopes ?? 'openid email profile offline_access';

    const parameters: Record<string, string> = {
      redirect_uri: this.config.redirectUri,
      scope,
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    };

    // Add audience if provided
    if (this.config.audience) {
      parameters['audience'] = this.config.audience;
    }

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
      // Include all other claims
      ...payload,
    };
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
