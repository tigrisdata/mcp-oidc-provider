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
