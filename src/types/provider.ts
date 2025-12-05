import type Provider from 'oidc-provider';
import type { IdentityProviderClient } from './idp.js';
import type { KeyvLike } from './store.js';
import type { SessionStore } from './session.js';
import type { HttpContext } from './http.js';
import type { Logger } from '../utils/logger.js';

/**
 * Configuration for creating an OIDC provider.
 */
export interface OidcProviderConfig {
  /** Issuer URL for the OIDC provider (your server's base URL) */
  issuer: string;

  /** Identity provider client for upstream authentication */
  idpClient: IdentityProviderClient;

  /**
   * Keyv instance for storage.
   * Used for sessions, tokens, grants, and other OIDC data.
   * Namespacing is handled internally.
   *
   * Any Keyv instance will work regardless of version, as the interface
   * is designed to be compatible with all Keyv versions.
   *
   * @example
   * ```typescript
   * // In-memory (development only)
   * import { Keyv } from 'keyv';
   * const store = new Keyv();
   *
   * // Redis (production)
   * import KeyvRedis from '@keyv/redis';
   * const store = new Keyv({ store: new KeyvRedis('redis://localhost:6379') });
   *
   * // Tigris
   * import { KeyvTigris } from 'keyv-tigris';
   * const store = new Keyv({ store: new KeyvTigris() });
   * ```
   */
  store: KeyvLike;

  /** Cookie signing secret(s) - use multiple for key rotation */
  cookieSecrets: string[];

  /** Path for the IdP callback route (default: '/callback') */
  callbackPath?: string;

  /** Token TTL configuration (in seconds) */
  ttl?: {
    accessToken?: number;
    authorizationCode?: number;
    idToken?: number;
    refreshToken?: number;
    /** Interaction session TTL (default: 600 = 10 minutes) */
    interaction?: number;
    /** Grant TTL (default: 1209600 = 14 days) */
    grant?: number;
    /** Session TTL (default: 2592000 = 30 days) */
    session?: number;
  };

  /** Supported OAuth scopes (default: ['openid', 'email', 'profile', 'offline_access']) */
  scopes?: string[];

  /**
   * Scopes to request from the upstream identity provider.
   * Some IdPs (like Clerk) don't support all scopes.
   * Default: 'openid email profile offline_access'
   *
   * @example
   * ```typescript
   * // For Clerk (doesn't support offline_access)
   * idpScopes: 'openid email profile'
   * ```
   */
  idpScopes?: string;

  /** Production mode flag - affects cookie security settings */
  isProduction?: boolean;

  /**
   * Known MCP client protocols to allow for redirect URIs.
   * These bypass the standard web URI validation.
   * Default: ['cursor://', 'vscode://', 'windsurf://']
   */
  allowedClientProtocols?: string[];

  /** Custom claims configuration for ID tokens */
  claims?: Record<string, string[]>;

  /** Logger instance (default: console logger) */
  logger?: Logger;

  /**
   * JSON Web Key Set for signing tokens.
   * If not provided, development-only keys are generated automatically.
   *
   * In production, you should provide your own signing keys.
   *
   * @example
   * ```typescript
   * import { generateJwks } from 'mcp-oidc-provider';
   *
   * // Generate keys once and store them securely
   * const jwks = await generateJwks();
   * console.log(JSON.stringify(jwks));
   *
   * // Then use them in your configuration
   * const provider = createOidcProvider({
   *   issuer: 'https://your-server.com',
   *   jwks,
   *   // ...
   * });
   * ```
   */
  jwks?: {
    keys: Array<{
      kty: string;
      alg?: string;
      use?: string;
      kid?: string;
      [key: string]: unknown;
    }>;
  };

  /**
   * Custom resource indicator handler.
   * Return undefined to reject unknown resource indicators.
   */
  getResourceServerInfo?: (resourceIndicator: string) =>
    | {
        scope: string;
        audience: string;
        accessTokenTTL: number;
        accessTokenFormat: 'jwt' | 'opaque';
      }
    | undefined;
}

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

/**
 * OIDC Provider instance returned by createOidcProvider.
 */
export interface OidcProvider {
  /** The underlying oidc-provider instance */
  provider: Provider;

  /** Session store for user sessions */
  sessionStore: SessionStore;

  /**
   * Handle an interaction request (login/consent flow).
   * This should be called when a user is redirected to the interaction URL.
   */
  handleInteraction(ctx: HttpContext): Promise<void>;

  /**
   * Handle the IdP callback after user authenticates.
   * This exchanges the authorization code for tokens and creates the user session.
   */
  handleCallback(ctx: HttpContext): Promise<void>;

  /**
   * Validate an access token and return the authenticated user.
   * Supports both JWT and opaque tokens.
   *
   * @param token - The access token to validate
   * @returns Validation result with user info if valid
   */
  validateToken(token: string): Promise<TokenValidationResult>;

  /**
   * Refresh the upstream IdP tokens for a user session.
   * Call this when the IdP access token is expired.
   *
   * @param accountId - The account ID (session ID)
   * @returns true if refresh was successful
   */
  refreshIdpTokens(accountId: string): Promise<boolean>;
}
