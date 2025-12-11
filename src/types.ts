/**
 * Foundation types for mcp-oidc-provider.
 *
 * This file contains all shared interfaces with ZERO internal imports.
 * All modules (core, oidc, mcp, express) import from here.
 *
 * @packageDocumentation
 */

import type { JWTPayload } from 'jose';

// ============================================================================
// JWKS Types
// ============================================================================

/**
 * JWK (JSON Web Key) type for signing keys.
 */
export interface JWK {
  kty: string;
  alg?: string;
  use?: string;
  kid?: string;
  [key: string]: unknown;
}

/**
 * JWKS (JSON Web Key Set) type.
 */
export interface JWKS {
  keys: JWK[];
}

// ============================================================================
// Storage Types
// ============================================================================

/**
 * Generic key-value storage interface.
 * Compatible with Keyv API for easy integration.
 */
export interface KeyValueStore<T = unknown> {
  get(key: string): Promise<T | undefined>;
  set(key: string, value: T, ttl?: number): Promise<boolean>;
  delete(key: string): Promise<boolean>;
  clear(): Promise<void>;
  has?(key: string): Promise<boolean>;
}

/**
 * A Keyv-compatible store interface.
 *
 * This interface matches the essential shape of a Keyv instance without
 * requiring the exact Keyv type. This allows users to pass any Keyv instance
 * regardless of the exact version installed.
 */
export interface KeyvLike {
  get<T = unknown>(key: string): Promise<T | undefined>;
  set<T = unknown>(key: string, value: T, ttl?: number): Promise<boolean>;
  delete(key: string): Promise<boolean>;
  clear(): Promise<void>;
  opts?: {
    store?: unknown;
    [key: string]: unknown;
  };
}

// ============================================================================
// IdP Client Types
// ============================================================================

/**
 * Authorization parameters returned when initiating OAuth flow.
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
 * Token set returned from token exchange.
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
 * User claims extracted from ID token.
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
 * Built-in implementation: OidcClient (from 'mcp-oidc-provider/oidc')
 */
export interface IOidcClient {
  /**
   * Create an authorization URL for initiating the OAuth flow.
   * Should generate PKCE code verifier/challenge, state, and nonce.
   */
  createAuthorizationUrl(): Promise<AuthorizationParams>;

  /**
   * Exchange an authorization code for tokens.
   */
  exchangeCode(
    callbackUrl: string,
    codeVerifier: string,
    expectedState: string,
    expectedNonce?: string
  ): Promise<TokenSet>;

  /**
   * Refresh an access token using a refresh token.
   */
  refreshToken(refreshToken: string): Promise<TokenSet>;

  /**
   * Parse and decode user claims from an ID token.
   */
  parseIdToken(idToken: string): UserClaims;

  /**
   * Extract custom data from user claims (e.g., organizations, roles).
   */
  extractCustomData?(claims: UserClaims): Record<string, unknown> | undefined;
}

// ============================================================================
// Session Types
// ============================================================================

/**
 * User session stored after successful authentication.
 * Contains the user's identity and tokens from the upstream IdP.
 */
export interface UserSession {
  /** Unique user identifier from the IdP (sub claim) */
  userId: string;
  /** JWT claims from the ID token */
  claims: JWTPayload;
  /** Token set from the IdP */
  tokenSet: {
    accessToken: string;
    idToken: string;
    refreshToken: string;
    /** Unix timestamp (ms) when the access token expires */
    expiresAt?: number;
  };
  /** Custom data extracted from IdP claims (e.g., organizations, roles) */
  customData?: Record<string, unknown>;
}

/**
 * Session store interface for managing user sessions.
 */
export interface SessionStore {
  set(sessionId: string, session: UserSession, ttl?: number): Promise<void>;
  get(sessionId: string): Promise<UserSession | undefined>;
  delete(sessionId: string): Promise<boolean>;
  clear(): Promise<void>;
}

/**
 * Interaction session for storing OAuth flow state.
 * Used temporarily during the authorization flow.
 */
export interface InteractionSession {
  /** The OIDC provider interaction UID */
  interactionUid: string;
  /** OAuth state parameter for CSRF protection */
  idpState: string;
  /** OAuth nonce for replay protection */
  idpNonce: string;
  /** PKCE code verifier */
  codeVerifier: string;
}

// ============================================================================
// Auth Result Types
// ============================================================================

/**
 * Authenticated user context attached to requests after token validation.
 */
export interface AuthenticatedUser {
  /** Account ID (matches the OIDC provider's sub claim) */
  accountId: string;
  /** User ID from the upstream IdP */
  userId: string;
  /** User claims from the ID token */
  claims: Record<string, unknown>;
  /** Token set from the upstream IdP */
  tokenSet: {
    accessToken: string;
    idToken: string;
    refreshToken: string;
  };
  /** Custom data extracted by the IdP client (e.g., organizations, roles) */
  customData?: Record<string, unknown>;
}

/**
 * Result of token validation.
 */
export interface TokenValidationResult {
  /** Whether the token is valid */
  valid: boolean;
  /** The authenticated user if valid */
  user?: AuthenticatedUser;
  /** Error message if invalid */
  error?: string;
}

// ============================================================================
// Configuration Types
// ============================================================================

/**
 * Base options shared by both standalone OIDC server and MCP Express setup.
 */
export interface BaseOidcOptions {
  /** OIDC client for upstream authentication */
  idpClient: IOidcClient;

  /** Keyv instance for storage */
  store: KeyvLike;

  /** Base URL of the server (e.g., 'http://localhost:4001') */
  baseUrl: string;

  /** Secret for signing cookies and sessions */
  secret: string;

  /**
   * JWKS for signing tokens.
   * For development: leave undefined (auto-generated, tokens invalidated on restart).
   * For production: generate with `npx mcp-oidc-provider --pretty`.
   */
  jwks?: JWKS;

  /** Whether running in production mode. Default: process.env.NODE_ENV === 'production' */
  isProduction?: boolean;

  /** Session max age in milliseconds. Default: 30 days */
  sessionMaxAge?: number;

  /** Additional origins to allow for CORS (beyond MCP Inspector and baseUrl) */
  additionalCorsOrigins?: string[];
}
