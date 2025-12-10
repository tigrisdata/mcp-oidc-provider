/**
 * Authorization parameters returned when initiating OAuth flow
 */
export interface AuthorizationParams {
  /** The authorization URL to redirect the user to */
  authorizationUrl: string;
  /** State parameter for CSRF protection */
  state: string;
  /** Nonce for replay protection */
  nonce: string;
  /** PKCE code verifier (to be stored securely) */
  codeVerifier: string;
}

/**
 * Token set returned from token exchange
 */
export interface TokenSet {
  /** Access token for API calls */
  accessToken: string;
  /** ID token containing user claims */
  idToken?: string;
  /** Refresh token for obtaining new access tokens */
  refreshToken?: string;
  /** Token expiration time in seconds */
  expiresIn?: number;
  /** Token type (usually "Bearer") */
  tokenType?: string;
}

/**
 * User claims extracted from ID token
 */
export interface UserClaims {
  /** Subject identifier (unique user ID) */
  sub: string;
  /** User's email address */
  email?: string;
  /** Whether the email is verified */
  emailVerified?: boolean;
  /** User's full name */
  name?: string;
  /** User's nickname or username */
  nickname?: string;
  /** URL to user's profile picture */
  picture?: string;
  /** Timestamp when the user info was last updated */
  updatedAt?: number;
  /** Additional claims from the identity provider */
  [key: string]: unknown;
}

/**
 * OIDC client interface.
 *
 * Implement this interface to add support for any OIDC-compliant identity provider.
 * Built-in implementation: OidcClient (from 'mcp-oidc-provider')
 *
 * @example
 * ```typescript
 * class MyOidcClient implements IOidcClient {
 *   async createAuthorizationUrl(): Promise<AuthorizationParams> {
 *     // Generate authorization URL with PKCE using configured scopes
 *   }
 *   // ... implement other methods
 * }
 * ```
 */
export interface IOidcClient {
  /**
   * Create an authorization URL for initiating the OAuth flow.
   * Should generate PKCE code verifier/challenge, state, and nonce.
   * Uses the scopes configured in the client constructor.
   *
   * @returns Authorization parameters including the URL and security tokens
   */
  createAuthorizationUrl(): Promise<AuthorizationParams>;

  /**
   * Exchange an authorization code for tokens.
   *
   * @param callbackUrl - The full callback URL including query parameters
   * @param codeVerifier - The PKCE code verifier from createAuthorizationUrl
   * @param expectedState - The state parameter to verify
   * @param expectedNonce - Optional nonce to verify in the ID token
   * @returns Token set containing access token, ID token, and optionally refresh token
   */
  exchangeCode(
    callbackUrl: string,
    codeVerifier: string,
    expectedState: string,
    expectedNonce?: string
  ): Promise<TokenSet>;

  /**
   * Refresh an access token using a refresh token.
   *
   * @param refreshToken - The refresh token
   * @returns New token set
   */
  refreshToken(refreshToken: string): Promise<TokenSet>;

  /**
   * Parse and decode user claims from an ID token.
   * Note: This should decode without verification (verification happens during exchange).
   *
   * @param idToken - The ID token JWT
   * @returns Decoded user claims
   */
  parseIdToken(idToken: string): UserClaims;

  /**
   * Extract custom data from user claims (e.g., organizations, roles).
   * This is optional and can be used for IdP-specific claim namespaces.
   *
   * @param claims - The user claims from the ID token
   * @returns Custom data extracted from claims, or undefined if none
   */
  extractCustomData?(claims: UserClaims): Record<string, unknown> | undefined;
}
