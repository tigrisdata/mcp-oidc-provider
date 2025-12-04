/**
 * MCP Auth Provider - A helper to create ProxyOAuthServerProvider for MCP servers.
 *
 * This module provides a simplified way to configure the MCP SDK's ProxyOAuthServerProvider
 * to work with an mcp-oidc-provider OIDC server.
 */

import { Router, type Request, type Response } from 'express';
import { Keyv } from 'keyv';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { OidcServerResult } from '../adapters/express/server.js';

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
   * The OIDC server instance created by createOidcServer.
   */
  oidcServer: OidcServerResult;

  /**
   * Keyv store instance (same one used by the OIDC server).
   */
  store: Keyv;

  /**
   * The base URL of the MCP server (resource server).
   * Used for constructing the protected resource metadata.
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
   * Pass this directly to: new ProxyOAuthServerProvider(config)
   */
  config: ProxyOAuthServerProviderConfig;

  /**
   * Express router that serves OAuth 2.0 Protected Resource Metadata (RFC 9728).
   * Mount this on your MCP server: app.use(router)
   */
  router: Router;

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
 * import { createOidcServer } from 'mcp-oidc-provider/express';
 * import { createMcpAuthProvider } from 'mcp-oidc-provider/mcp';
 * import { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
 *
 * const oidcServer = createOidcServer({ ... });
 * await oidcServer.start();
 *
 * const { config, router, resourceMetadataUrl } = createMcpAuthProvider({
 *   oidcServer,
 *   store,
 *   mcpServerBaseUrl: 'http://localhost:3001',
 * });
 *
 * // Create the auth provider directly with the config
 * const authProvider = new ProxyOAuthServerProvider(config);
 *
 * // Mount the router for protected resource metadata
 * app.use(router);
 *
 * // Use resourceMetadataUrl in requireBearerAuth
 * app.post('/mcp', requireBearerAuth({ verifier: authProvider, resourceMetadataUrl }), ...);
 * ```
 */
export function createMcpAuthProvider(options: McpAuthProviderOptions): McpAuthProviderResult {
  const {
    oidcServer,
    store,
    mcpServerBaseUrl,
    mcpEndpointPath = '/mcp',
    scopesSupported = ['openid', 'email', 'profile', 'offline_access'],
  } = options;
  const oidcBaseUrl = oidcServer.baseUrl;

  // Get the underlying store for client lookups
  const underlyingStore = store.opts?.store;

  // Create a Keyv instance for client lookups (same namespace as oidc-provider uses)
  const clientStore = new Keyv<ClientInfo>({
    store: underlyingStore,
    namespace: 'oidc:Client',
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

        return {
          token,
          clientId: (payload['client_id'] as string) ?? '',
          scopes: typeof payload['scope'] === 'string' ? payload['scope'].split(' ') : [],
          expiresAt: payload.exp,
          extra: {
            sub: payload.sub,
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

  // Create router for protected resource metadata (RFC 9728)
  const router = Router();

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
    config,
    router,
    resourceMetadataUrl,
  };
}
