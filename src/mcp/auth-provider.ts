/**
 * MCP Auth Provider - connects an mcp-oidc-provider OIDC server to an MCP
 * resource server built on the MCP TypeScript SDK v2.
 *
 * With SDK v2 an MCP server is a pure OAuth resource server: it advertises its
 * authorization server through OAuth 2.0 Protected Resource Metadata (RFC 9728)
 * and verifies bearer tokens with an `OAuthTokenVerifier`. This module provides
 * both halves for a standalone mcp-oidc-provider server:
 *
 * - `verifier` - an `OAuthTokenVerifier` for `requireBearerAuth` from
 *   `@modelcontextprotocol/express`
 * - `mcpRoutes` - the SDK's `mcpAuthMetadataRouter` (protected resource
 *   metadata plus the OIDC server's authorization server metadata, fetched
 *   once at startup) and CORS for the MCP endpoint
 */

import { Router } from 'express';
import { Keyv } from 'keyv';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type AuthMetadataOptions,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthMetadataRouter,
} from '@modelcontextprotocol/express';
import { createMcpCorsMiddleware } from '../express/cors.js';
import {
  DEFAULT_JWKS_CACHE_OPTIONS,
  DEFAULT_SCOPES,
  STORAGE_NAMESPACES,
  type JwksCacheOptions,
} from '../core/config.js';
import type { KeyvLike, UserSession } from '../types.js';

/**
 * Options for creating an MCP auth provider.
 */
export interface McpAuthProviderOptions {
  /**
   * The base URL of the OIDC server (e.g., 'http://localhost:4001').
   * Used as the token issuer, for JWKS fetching, and as the advertised authorization server.
   * Its authorization server metadata is fetched once when the provider is created,
   * so the OIDC server must be reachable at that point.
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
   * Determines the resource identifier and the protected resource metadata URL.
   * Default: '/mcp'
   */
  mcpEndpointPath?: string;

  /**
   * Scopes advertised in the protected resource metadata (`scopes_supported`).
   * Default: ['openid', 'email', 'profile', 'offline_access']
   */
  scopesSupported?: string[];

  /**
   * JWKS cache options for token verification.
   * Controls how long the JWKS is cached before being refetched.
   * Default: { cooldownDuration: 30000, cacheMaxAge: 600000 }
   */
  jwksCacheOptions?: JwksCacheOptions;

  /**
   * Callback for handling errors during token verification.
   * Useful for logging or monitoring token verification failures.
   * The error is passed here before being converted to an OAuth `invalid_token` error.
   */
  onVerifyError?: (error: unknown) => void;
}

/**
 * Result of creating an MCP auth provider.
 */
export interface McpAuthProviderResult {
  /**
   * Token verifier for the MCP SDK.
   * Pass it to `requireBearerAuth({ verifier, resourceMetadataUrl })`.
   *
   * The returned `AuthInfo` carries `expiresAt`, `resource` (from the token's
   * `aud` claim, so `expectedResource` checks work) and, in `extra`, the user's
   * `sub`, `claims`, `idpTokens` and `customData` from the session.
   * Verification failures reject with the SDK's `OAuthError` (`invalid_token`).
   */
  verifier: OAuthTokenVerifier;

  /**
   * Express router that serves the OAuth discovery documents through the MCP
   * SDK's `mcpAuthMetadataRouter` and CORS for the MCP endpoint:
   *
   * - `/.well-known/oauth-protected-resource/<mcp path>` - Protected Resource
   *   Metadata (RFC 9728). RFC 9728 derives this path from the resource
   *   identifier, and `requireBearerAuth` advertises it in every challenge.
   * - `/.well-known/oauth-authorization-server` - the OIDC server's
   *   Authorization Server Metadata (RFC 8414), for clients that probe the
   *   MCP server origin.
   *
   * Mount this on your MCP server: `app.use(mcpRoutes)`
   */
  mcpRoutes: Router;

  /**
   * The URL of the protected resource metadata document
   * (`<mcpServerBaseUrl>/.well-known/oauth-protected-resource<mcpEndpointPath>`).
   * Use this for `requireBearerAuth`'s `resourceMetadataUrl` option.
   */
  resourceMetadataUrl: string;
}

type OAuthMetadata = AuthMetadataOptions['oauthMetadata'];

/**
 * Fetch the OIDC server's Authorization Server Metadata (RFC 8414).
 * @internal
 */
export async function fetchAuthorizationServerMetadata(
  oidcBaseUrl: string
): Promise<OAuthMetadata> {
  const url = `${oidcBaseUrl}/.well-known/oauth-authorization-server`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(
      `Failed to fetch authorization server metadata from ${url}: HTTP ${response.status}`
    );
  }
  const metadata = (await response.json()) as OAuthMetadata;
  if (metadata.issuer !== oidcBaseUrl) {
    throw new Error(
      `Authorization server metadata issuer "${metadata.issuer}" does not match oidcBaseUrl "${oidcBaseUrl}"`
    );
  }
  return metadata;
}

/**
 * Pick the first `aud` value that is an absolute URL.
 * @internal
 */
export function resourceFromAudience(aud: unknown): URL | undefined {
  const audiences = Array.isArray(aud) ? aud : typeof aud === 'string' ? [aud] : [];
  for (const audience of audiences) {
    if (typeof audience !== 'string') continue;
    try {
      return new URL(audience);
    } catch {
      // not a URL, try the next one
    }
  }
  return undefined;
}

/**
 * Create an MCP auth provider for the MCP TypeScript SDK v2.
 *
 * Fetches the OIDC server's authorization server metadata once, so the OIDC
 * server must be running. The MCP SDK rejects a non-HTTPS issuer other than
 * `localhost`/`127.0.0.1` unless `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL=true`
 * is set.
 *
 * @param options - Provider options
 * @returns A token verifier, a router for the metadata endpoints, and the resource metadata URL
 *
 * @example
 * ```typescript
 * import { createMcpExpressApp, requireBearerAuth } from '@modelcontextprotocol/express';
 * import { createMcpAuthProvider } from 'mcp-oidc-provider/mcp';
 *
 * const { verifier, mcpRoutes, resourceMetadataUrl } = await createMcpAuthProvider({
 *   oidcBaseUrl: 'http://localhost:4001',
 *   store,
 *   mcpServerBaseUrl: 'http://localhost:3001',
 * });
 *
 * const app = createMcpExpressApp({ host: '0.0.0.0', allowedHosts: ['localhost'] });
 *
 * // /.well-known/oauth-protected-resource/mcp, /.well-known/oauth-authorization-server, CORS
 * app.use(mcpRoutes);
 *
 * app.post('/mcp', requireBearerAuth({ verifier, resourceMetadataUrl }), async (req, res) => {
 *   // req.auth is the AuthInfo returned by the verifier
 * });
 * ```
 */
export async function createMcpAuthProvider(
  options: McpAuthProviderOptions
): Promise<McpAuthProviderResult> {
  const {
    oidcBaseUrl,
    store,
    mcpServerBaseUrl,
    mcpEndpointPath = '/mcp',
    scopesSupported = DEFAULT_SCOPES,
    jwksCacheOptions,
    onVerifyError,
  } = options;

  // Get the underlying store for session lookups
  const underlyingStore = store.opts?.store;

  // Create a Keyv instance for session lookups (same namespace as core provider uses)
  const sessionStore = new Keyv<UserSession>({
    store: underlyingStore,
    namespace: STORAGE_NAMESPACES.USER_SESSIONS,
  });

  // Create JWKS for JWT verification with configurable cache options
  const JWKS = createRemoteJWKSet(new URL(`${oidcBaseUrl}/jwks`), {
    ...DEFAULT_JWKS_CACHE_OPTIONS,
    ...jwksCacheOptions,
  });

  // RFC 9728: the metadata URL is derived from the resource identifier (MCP endpoint URL)
  const resourceServerUrl = new URL(`${mcpServerBaseUrl}${mcpEndpointPath}`);
  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resourceServerUrl);

  const oauthMetadata = await fetchAuthorizationServerMetadata(oidcBaseUrl);

  const verifier: OAuthTokenVerifier = {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
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
          resource: resourceFromAudience(payload.aud),
          resourceMetadataUrl,
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
      } catch (error) {
        // Call error callback if provided for debugging/logging
        onVerifyError?.(error);
        // The SDK maps OAuthError(invalid_token) to a 401 with a WWW-Authenticate challenge
        throw new OAuthError(OAuthErrorCode.InvalidToken, 'Invalid or expired token');
      }
    },
  };

  const router = Router();

  // OAuth discovery documents from the MCP SDK (each with its own permissive CORS):
  // protected resource metadata at the path-based well-known URL and the OIDC
  // server's authorization server metadata, verbatim.
  router.use(mcpAuthMetadataRouter({ oauthMetadata, resourceServerUrl, scopesSupported }));

  // CORS for the MCP endpoint itself (includes the MCP Inspector origin by default)
  router.use(createMcpCorsMiddleware({ baseUrl: mcpServerBaseUrl }));

  return {
    verifier,
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
 * Get the IdP token set from the `AuthInfo` produced by the verifier
 * (`req.auth` after `requireBearerAuth`).
 *
 * @param authInfo - `req.auth` from `requireBearerAuth`
 * @returns The IdP token set, or undefined if not available
 *
 * @example
 * ```typescript
 * import { getIdpTokens } from 'mcp-oidc-provider/mcp';
 *
 * app.post('/mcp', requireBearerAuth({ verifier, resourceMetadataUrl }), async (req, res) => {
 *   const tokens = getIdpTokens(req.auth);
 *   if (tokens) {
 *     console.log('IdP access token:', tokens.accessToken);
 *   }
 * });
 * ```
 */
export function getIdpTokens(authInfo: AuthInfo | undefined | null): IdpTokenSet | undefined {
  const idpTokens = authInfo?.extra?.['idpTokens'];
  return idpTokens ? (idpTokens as IdpTokenSet) : undefined;
}
