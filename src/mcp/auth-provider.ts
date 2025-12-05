/**
 * MCP Auth Provider - A helper to create ProxyOAuthServerProvider for MCP servers.
 *
 * This module provides a simplified way to configure the MCP SDK's ProxyOAuthServerProvider
 * to work with an mcp-oidc-provider OIDC server.
 */

import { Router, type Request, type Response } from 'express';
import { Keyv } from 'keyv';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { createMcpCorsMiddleware } from '../adapters/express/cors.js';
import type { KeyvLike } from '../types/store.js';
import type { UserSession } from '../types/session.js';
import type { AuthenticatedUser } from '../types/provider.js';

/**
 * Client information stored by oidc-provider.
 * This matches the OAuthClientInformationFull interface from the MCP SDK.
 */
export interface ClientInfo {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  grant_types?: string[];
  response_types?: string[];
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  token_endpoint_auth_method?: string;
  scope?: string;
}

/**
 * Auth info returned after token verification.
 * This matches the AuthInfo interface from the MCP SDK.
 */
export interface AuthInfo {
  token: string;
  clientId: string;
  scopes: string[];
  expiresAt?: number;
  extra?: Record<string, unknown>;
}

/**
 * Options for creating an MCP auth provider.
 */
export interface McpAuthProviderOptions {
  /**
   * The base URL of the OIDC server (e.g., 'http://localhost:4001').
   * This is used to construct OAuth endpoints and verify tokens.
   */
  oidcBaseUrl: string;

  /**
   * Keyv store instance (same one used by the OIDC server).
   * Any Keyv instance will work regardless of version.
   */
  store: KeyvLike;

  /**
   * The base URL of the MCP server (resource server).
   * Used for constructing the protected resource metadata and CORS.
   */
  mcpServerBaseUrl: string;

  /**
   * The path to the MCP endpoint (e.g., '/mcp').
   * Default: '/mcp'
   */
  mcpEndpointPath?: string;

  /**
   * Scopes supported by the MCP server.
   * Default: ['openid', 'email', 'profile', 'offline_access']
   */
  scopesSupported?: string[];
}

/**
 * Configuration for ProxyOAuthServerProvider.
 * This can be passed directly to new ProxyOAuthServerProvider(config).
 */
export interface ProxyOAuthServerProviderConfig {
  /**
   * OAuth endpoints for ProxyOAuthServerProvider.
   */
  endpoints: {
    authorizationUrl: string;
    tokenUrl: string;
    revocationUrl: string;
    registrationUrl: string;
  };

  /**
   * Verify an access token and return auth info.
   */
  verifyAccessToken: (token: string) => Promise<AuthInfo>;

  /**
   * Get client information by client ID.
   */
  getClient: (clientId: string) => Promise<ClientInfo | undefined>;
}

/**
 * Result of creating an MCP auth provider.
 */
export interface McpAuthProviderResult {
  /**
   * Configuration for ProxyOAuthServerProvider.
   * Pass this directly to: new ProxyOAuthServerProvider(proxyOAuthServerProviderConfig)
   */
  proxyOAuthServerProviderConfig: ProxyOAuthServerProviderConfig;

  /**
   * Express router that serves CORS, health check, and OAuth 2.0 Protected Resource Metadata (RFC 9728).
   * Mount this on your MCP server: app.use(mcpRoutes)
   */
  mcpRoutes: Router;

  /**
   * The URL of the protected resource metadata endpoint.
   * Use this for requireBearerAuth's resourceMetadataUrl option.
   */
  resourceMetadataUrl: string;
}

/**
 * Error thrown when token verification fails.
 */
export class InvalidTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidTokenError';
  }
}

/**
 * Create an MCP auth provider configuration.
 *
 * This creates the configuration needed for the MCP SDK's ProxyOAuthServerProvider
 * to work with an mcp-oidc-provider OIDC server.
 *
 * @param options - Provider options
 * @returns Configuration for ProxyOAuthServerProvider and a router for protected resource metadata
 *
 * @example
 * ```typescript
 * import { createMcpAuthProvider } from 'mcp-oidc-provider/mcp';
 * import { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
 *
 * const { proxyOAuthServerProviderConfig, mcpRoutes, resourceMetadataUrl } = createMcpAuthProvider({
 *   oidcBaseUrl: 'http://localhost:4001',
 *   store,
 *   mcpServerBaseUrl: 'http://localhost:3001',
 * });
 *
 * // Create the auth provider directly with the config
 * const authProvider = new ProxyOAuthServerProvider(proxyOAuthServerProviderConfig);
 *
 * // Mount the routes (includes CORS, /health, /.well-known/oauth-protected-resource)
 * app.use(mcpRoutes);
 *
 * // Use resourceMetadataUrl in requireBearerAuth
 * app.post('/mcp', requireBearerAuth({ verifier: authProvider, resourceMetadataUrl }), ...);
 * ```
 */
export function createMcpAuthProvider(options: McpAuthProviderOptions): McpAuthProviderResult {
  const {
    oidcBaseUrl,
    store,
    mcpServerBaseUrl,
    mcpEndpointPath = '/mcp',
    scopesSupported = ['openid', 'email', 'profile', 'offline_access'],
  } = options;

  // Get the underlying store for client lookups
  const underlyingStore = store.opts?.store;

  // Create a Keyv instance for client lookups (same namespace as oidc-provider uses)
  const clientStore = new Keyv<ClientInfo>({
    store: underlyingStore,
    namespace: 'oidc:Client',
  });

  // Create a Keyv instance for session lookups (same namespace as core provider uses)
  const sessionStore = new Keyv<UserSession>({
    store: underlyingStore,
    namespace: 'user-sessions',
  });

  // Create JWKS for JWT verification
  const JWKS = createRemoteJWKSet(new URL(`${oidcBaseUrl}/jwks`));

  // Create the config for ProxyOAuthServerProvider
  const config: ProxyOAuthServerProviderConfig = {
    endpoints: {
      authorizationUrl: `${oidcBaseUrl}/authorize`,
      tokenUrl: `${oidcBaseUrl}/token`,
      revocationUrl: `${oidcBaseUrl}/token/revocation`,
      registrationUrl: `${oidcBaseUrl}/register`,
    },

    verifyAccessToken: async (token: string): Promise<AuthInfo> => {
      try {
        const { payload } = await jwtVerify(token, JWKS, {
          issuer: oidcBaseUrl,
        });

        const sub = payload.sub;

        // Look up the session to get IdP tokens and user claims
        const session = sub ? await sessionStore.get(sub) : undefined;

        return {
          token,
          clientId: (payload['client_id'] as string) ?? '',
          scopes: typeof payload['scope'] === 'string' ? payload['scope'].split(' ') : [],
          expiresAt: payload.exp,
          extra: {
            sub,
            // Include user claims from the session
            claims: session?.claims,
            // Include IdP token set directly
            idpTokens: session?.tokenSet,
            // Include any custom data from the IdP client
            customData: session?.customData,
          },
        };
      } catch {
        throw new InvalidTokenError('Invalid or expired token');
      }
    },

    getClient: async (clientId: string): Promise<ClientInfo | undefined> => {
      // Look up client in the same store that oidc-provider uses
      const key = `Client:${clientId}`;
      const client = await clientStore.get(key);
      return client ?? undefined;
    },
  };

  // Create router for protected resource metadata (RFC 9728) and middleware
  const router = Router();

  // CORS middleware for MCP clients (includes MCP Inspector origin by default)
  router.use(createMcpCorsMiddleware({ baseUrl: mcpServerBaseUrl }));

  // Health check endpoint
  router.get('/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // OAuth 2.0 Protected Resource Metadata (RFC 9728)
  // This endpoint tells clients how to authenticate with this resource server
  router.get('/.well-known/oauth-protected-resource', (_req: Request, res: Response) => {
    res.json({
      resource: `${mcpServerBaseUrl}${mcpEndpointPath}`,
      authorization_servers: [oidcBaseUrl],
      scopes_supported: scopesSupported,
      bearer_methods_supported: ['header'],
    });
  });

  const resourceMetadataUrl = `${mcpServerBaseUrl}/.well-known/oauth-protected-resource`;

  return {
    proxyOAuthServerProviderConfig: config,
    mcpRoutes: router,
    resourceMetadataUrl,
  };
}

/**
 * IdP token set structure.
 * Contains tokens from the upstream identity provider.
 */
export interface IdpTokenSet {
  /** Access token for calling IdP APIs */
  accessToken: string;
  /** ID token containing user identity claims */
  idToken: string;
  /** Refresh token for obtaining new access tokens */
  refreshToken: string;
  /** Unix timestamp (seconds) when the access token expires */
  expiresAt?: number;
}

/**
 * Get IdP tokens from either req.user (setupMcpExpress) or req.auth (requireBearerAuth).
 *
 * This helper abstracts the different locations where IdP tokens are stored
 * depending on which authentication approach you use.
 *
 * @param userOrAuth - Either req.user (AuthenticatedUser) or req.auth (AuthInfo)
 * @returns The IdP token set, or undefined if not available
 *
 * @example
 * ```typescript
 * import { getIdpTokens } from 'mcp-oidc-provider/mcp';
 *
 * // Works with setupMcpExpress (req.user)
 * handleMcpRequest(async (req, res) => {
 *   const tokens = getIdpTokens(req.user);
 *   if (tokens) {
 *     console.log('IdP access token:', tokens.accessToken);
 *   }
 * });
 *
 * // Works with requireBearerAuth (req.auth)
 * app.post('/mcp', requireBearerAuth({ verifier }), async (req, res) => {
 *   const tokens = getIdpTokens(req.auth);
 *   if (tokens) {
 *     console.log('IdP access token:', tokens.accessToken);
 *   }
 * });
 * ```
 */
export function getIdpTokens(
  userOrAuth: AuthenticatedUser | AuthInfo | undefined | null
): IdpTokenSet | undefined {
  if (!userOrAuth) {
    return undefined;
  }

  // Check for AuthenticatedUser (from setupMcpExpress via req.user)
  // AuthenticatedUser has tokenSet directly on it
  if ('tokenSet' in userOrAuth && userOrAuth.tokenSet) {
    const tokenSet = userOrAuth.tokenSet as IdpTokenSet;
    return tokenSet;
  }

  // Check for AuthInfo (from requireBearerAuth via req.auth)
  // AuthInfo has idpTokens in extra
  if ('extra' in userOrAuth && userOrAuth.extra) {
    const extra = userOrAuth.extra as Record<string, unknown>;
    if (extra['idpTokens']) {
      return extra['idpTokens'] as IdpTokenSet;
    }
  }

  return undefined;
}
