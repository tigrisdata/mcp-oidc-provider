/**
 * Default token TTLs (in seconds)
 */

/** Authorization code TTL: 10 minutes */
export const DEFAULT_AUTHORIZATION_CODE_TTL = 600;

/** Access token TTL: 15 minutes */
export const DEFAULT_ACCESS_TOKEN_TTL = 900;

/** ID token TTL: same as access token */
export const DEFAULT_ID_TOKEN_TTL = DEFAULT_ACCESS_TOKEN_TTL;

/** Refresh token TTL: 30 days */
export const DEFAULT_REFRESH_TOKEN_TTL = 86400 * 30;

/** Interaction session TTL: 30 minutes (in milliseconds) */
export const DEFAULT_INTERACTION_SESSION_TTL_MS = 30 * 60 * 1000;

/** User session TTL: 30 days (in milliseconds, matches refresh token) */
export const DEFAULT_USER_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** Interaction TTL: 10 minutes (oidc-provider interaction session) */
export const DEFAULT_INTERACTION_TTL = 600;

/** Grant TTL: 14 days (oidc-provider grant lifetime) */
export const DEFAULT_GRANT_TTL = 86400 * 14;

/** Session TTL: 30 days (oidc-provider session lifetime) */
export const DEFAULT_SESSION_TTL = 86400 * 30;

/**
 * Default supported OAuth scopes
 */
export const DEFAULT_SCOPES = ['openid', 'email', 'profile', 'offline_access'];

/**
 * Default claims configuration for OIDC
 */
export const DEFAULT_CLAIMS = {
  openid: ['sub'],
  email: ['email', 'email_verified'],
  profile: ['name', 'nickname', 'picture', 'updated_at'],
};

/**
 * Default allowed MCP client protocols for redirect URIs
 */
export const DEFAULT_ALLOWED_CLIENT_PROTOCOLS = ['cursor://', 'vscode://', 'windsurf://'];

/**
 * Default OIDC routes
 */
export const DEFAULT_ROUTES = {
  authorization: '/authorize',
  registration: '/register',
  token: '/token',
  jwks: '/jwks',
  userinfo: '/me',
};

/**
 * Storage namespace constants
 * These are used to namespace data in the Keyv store to prevent collisions.
 */
export const STORAGE_NAMESPACES = {
  /** User sessions containing IdP tokens and claims */
  USER_SESSIONS: 'user-sessions',
  /** Temporary interaction sessions during OAuth flow */
  INTERACTION_SESSIONS: 'interaction-sessions',
  /** Express session data */
  EXPRESS_SESSIONS: 'express-sessions',
  /** OIDC server session data (standalone mode) */
  OIDC_SERVER_SESSIONS: 'oidc-server-sessions',
  /** OIDC client registrations */
  OIDC_CLIENT: 'oidc:Client',
} as const;

/**
 * Default JWKS cache options for createRemoteJWKSet
 */
export const DEFAULT_JWKS_CACHE_OPTIONS = {
  /** Minimum time between JWKS fetches (milliseconds). Default: 30 seconds */
  cooldownDuration: 30_000,
  /** Maximum age of cached JWKS (milliseconds). Default: 10 minutes */
  cacheMaxAge: 600_000,
} as const;

/**
 * JWKS cache options type
 */
export interface JwksCacheOptions {
  /** Minimum time between JWKS fetches (milliseconds) */
  cooldownDuration?: number;
  /** Maximum age of cached JWKS (milliseconds) */
  cacheMaxAge?: number;
}
