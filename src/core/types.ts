/**
 * Internal types for the OIDC provider core.
 *
 * These types are implementation-specific and not part of the public API.
 *
 * @internal
 * @packageDocumentation
 */

import type Provider from 'oidc-provider';
import type { Request, Response } from 'express';
import type { IOidcClient, KeyvLike, SessionStore, TokenValidationResult } from '../types.js';
import type { Logger } from '../utils/logger.js';

/**
 * Configuration for creating an OIDC provider.
 * @internal Used by createOidcProvider - users should use BaseOidcOptions instead.
 */
export interface OidcProviderConfig {
  /** Issuer URL for the OIDC provider (your server's base URL) */
  issuer: string;

  /** OIDC client for upstream authentication */
  idpClient: IOidcClient;

  /** Keyv instance for storage */
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
    interaction?: number;
    grant?: number;
    session?: number;
  };

  /** Supported OAuth scopes */
  scopes?: string[];

  /** Production mode flag */
  isProduction?: boolean;

  /** Known MCP client protocols to allow for redirect URIs */
  allowedClientProtocols?: string[];

  /** Custom claims configuration for ID tokens */
  claims?: Record<string, string[]>;

  /** Logger instance */
  logger?: Logger;

  /** JSON Web Key Set for signing tokens */
  jwks?: {
    keys: Array<{
      kty: string;
      alg?: string;
      use?: string;
      kid?: string;
      [key: string]: unknown;
    }>;
  };

  /** Custom resource indicator handler */
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
 * OIDC Provider instance returned by createOidcProvider.
 * @internal
 */
export interface OidcProvider {
  /** The underlying oidc-provider instance */
  provider: Provider;

  /** Session store for user sessions */
  sessionStore: SessionStore;

  /** Handle an interaction request (login/consent flow) */
  handleInteraction(req: Request, res: Response): Promise<void>;

  /** Handle the IdP callback after user authenticates */
  handleCallback(req: Request, res: Response): Promise<void>;

  /** Validate an access token and return the authenticated user */
  validateToken(token: string): Promise<TokenValidationResult>;

  /** Refresh the upstream IdP tokens for a user session */
  refreshIdpTokens(accountId: string): Promise<boolean>;
}
