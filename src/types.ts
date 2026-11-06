/**
 * Public types for mcp-oidc-provider.
 *
 * @packageDocumentation
 */

import type { JWTPayload } from 'jose';
import type { ConsentView } from './relay/html.js';
import type { Logger } from './utils/logger.js';

// ============================================================================
// Storage
// ============================================================================

/**
 * A Keyv-compatible store.
 *
 * Matches the essential shape of a Keyv instance without requiring the exact
 * Keyv type, so any Keyv version (and any Keyv storage adapter) works.
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
// Upstream identity provider
// ============================================================================

/**
 * Authorization server metadata of the upstream identity provider
 * (OpenID Connect Discovery 1.0 or RFC 8414).
 */
export interface UpstreamMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  revocation_endpoint?: string;
  [key: string]: unknown;
}

/**
 * The identity provider the relay forwards to. The relay is registered there
 * as a single confidential OAuth client (the only client that provider sees).
 */
export interface UpstreamOptions {
  /**
   * Issuer URL of the identity provider, e.g. `https://your-tenant.auth0.com`.
   * Its metadata is discovered at `/.well-known/openid-configuration`
   * (falling back to RFC 8414 `/.well-known/oauth-authorization-server`)
   * on first use and cached for the lifetime of the process.
   */
  issuer: string;

  /** Client ID the relay uses at the identity provider. */
  clientId: string;

  /** Client secret the relay uses at the identity provider. */
  clientSecret: string;

  /**
   * Audience the identity provider must issue access tokens for.
   *
   * Sent as the `audience` parameter of every upstream authorization request
   * (the parameter Auth0 and others use to issue a JWT access token for an
   * API) and required in the `aud` claim of every access token the verifier
   * accepts. Providers that do not know the parameter ignore it; use
   * `authorizationParams` to send a provider-specific equivalent.
   */
  audience: string;

  /**
   * Scopes requested from the identity provider.
   * Default: `['openid', 'profile', 'email', 'offline_access']`
   */
  scopes?: string[];

  /**
   * Extra parameters added to every upstream authorization request, e.g.
   * `{ prompt: 'consent' }` or `{ resource: 'https://api.example.com' }`.
   */
  authorizationParams?: Record<string, string>;

  /**
   * How the relay authenticates at the upstream token endpoint.
   * Default: `'client_secret_basic'`
   */
  tokenEndpointAuthMethod?: 'client_secret_basic' | 'client_secret_post';

  /**
   * Upstream metadata to use instead of (or merged over) discovery. When all
   * required endpoints are given no discovery request is made.
   */
  metadata?: Partial<UpstreamMetadata>;

  /**
   * Name shown to users on the consent page ("you will sign in with ...").
   * Default: the issuer's hostname
   */
  displayName?: string;
}

// ============================================================================
// Client registration
// ============================================================================

/** Options for how MCP clients identify themselves to the relay. */
export interface ClientOptions {
  /**
   * Accept Dynamic Client Registration (RFC 7591) at `/register`.
   * Default: `true`
   */
  allowDynamicRegistration?: boolean;

  /**
   * How long a dynamic registration is kept, in milliseconds. Clients whose
   * registration expired re-register on their next `invalid_client` error.
   * Default: 30 days
   */
  registrationTtl?: number;

  /**
   * Accept Client ID Metadata Documents: an `https` URL as `client_id` whose
   * JSON document describes the client. Advertised as
   * `client_id_metadata_document_supported`.
   * Default: `true`
   */
  allowClientIdMetadataDocuments?: boolean;

  /**
   * Restrict metadata document URLs to these hostnames. Hosts listed here
   * skip the private-network checks the relay otherwise performs before
   * fetching a document.
   * Default: any public hostname
   */
  cimdAllowedHosts?: string[];

  /**
   * Upper bound for caching a fetched metadata document, in milliseconds.
   * The document's `Cache-Control: max-age` is honoured within that bound.
   * Default: 1 hour
   */
  cimdCacheTtl?: number;

  /**
   * Replace the default redirect URI policy (`https` URLs, `http` on
   * loopback hosts, and private-use schemes such as `cursor://`).
   */
  isAllowedRedirectUri?: (uri: URL) => boolean;
}

// ============================================================================
// Consent
// ============================================================================

/** Options for the relay's consent page. */
export interface ConsentOptions {
  /**
   * Ask the user to approve each client (identified by `client_id` and
   * redirect URI) before forwarding them to the identity provider. This is the
   * MCP specification's confused-deputy mitigation for proxies that use one
   * static upstream client; disable it only if you accept that risk.
   * Default: `true`
   */
  enabled?: boolean;

  /**
   * How long an approval is remembered, in milliseconds.
   * Default: 30 days
   */
  ttl?: number;

  /**
   * Name of the cookie that remembers approvals.
   * Default: `'mcp_relay_consent'`
   */
  cookieName?: string;

  /**
   * Key used to sign the consent cookie. Must be the same on every instance.
   * Default: derived from the upstream client secret
   */
  secret?: string;

  /** Render your own consent page. Must return a complete HTML document. */
  render?: (view: ConsentView) => string;
}

// ============================================================================
// Verifier
// ============================================================================

/** What `customData` receives for each verified access token. */
export interface CustomDataContext {
  /** Verified claims of the access token. */
  claims: JWTPayload;
  /** The raw access token. */
  token: string;
  /**
   * Fetch the identity provider's UserInfo for this token. The result is
   * cached per token until the token expires, so calling it on every request
   * costs one upstream call per token.
   */
  userinfo(): Promise<Record<string, unknown>>;
}

/** Derive application data from a verified token; the result lands in `req.auth.extra.customData`. */
export type CustomDataFn = (
  context: CustomDataContext
) => Promise<Record<string, unknown> | undefined> | Record<string, unknown> | undefined;

/** A successful token response the relay passed on to an MCP client. */
export interface TokenResponseEvent {
  /** The grant that produced the response. */
  grantType: 'authorization_code' | 'refresh_token';
  /** The MCP client the response was issued to. */
  clientId: string;
  /**
   * Verified claims of the ID token in the response, when the provider
   * returned one and it verified against the provider's keys (or, for
   * `HS*` algorithms, the relay's client secret).
   */
  idTokenClaims?: JWTPayload;
  /** Verified claims of the access token, when it is a JWT for `upstream.audience`. */
  accessTokenClaims?: JWTPayload;
  /** When the access token expires (seconds since epoch), if known. */
  expiresAt?: number;
  /** Scopes the provider granted, as returned in `scope`. */
  scope?: string;
}

/**
 * Observe the tokens the relay passes on, without the tokens themselves. Use
 * it to persist application data that only the ID token carries (profile,
 * organizations, roles) keyed by `sub`, so `customData` can look it up on later
 * requests. The hook runs before the response is sent; a rejection is logged
 * and does not fail the token request.
 */
export type TokenResponseHook = (event: TokenResponseEvent) => void | Promise<void>;

/** Cache options for the identity provider's JWKS. */
export interface JwksCacheOptions {
  /** Minimum time between JWKS fetches, in milliseconds. Default: 30 seconds */
  cooldownDuration?: number;
  /** Maximum age of the cached JWKS, in milliseconds. Default: 10 minutes */
  cacheMaxAge?: number;
}

// ============================================================================
// Relay
// ============================================================================

/** Options for `createAuthRelay`. */
export interface AuthRelayOptions {
  /**
   * Public origin of the server the relay's router is mounted on, e.g.
   * `https://mcp.example.com`. It is the relay's issuer, so the router must be
   * mounted at the root of that origin.
   */
  baseUrl: string;

  /** The identity provider to relay to. */
  upstream: UpstreamOptions;

  /**
   * Keyv store. Holds client registrations, cached client metadata documents
   * and in-flight authorization requests (minutes); never tokens.
   */
  store: KeyvLike;

  /**
   * Path of the MCP endpoint on `baseUrl`; together they form the RFC 8707
   * resource identifier advertised in the protected resource metadata.
   * Default: `'/mcp'`
   */
  mcpEndpointPath?: string;

  /**
   * Scopes advertised to MCP clients (`scopes_supported`).
   * Default: the upstream scopes
   */
  scopesSupported?: string[];

  /** Human-readable name of the MCP server, shown on the consent page and in the metadata. */
  resourceName?: string;

  /** Path the identity provider redirects back to. Default: `'/oauth/callback'` */
  callbackPath?: string;

  /** How MCP clients may identify themselves. */
  clients?: ClientOptions;

  /** The consent page. */
  consent?: ConsentOptions;

  /** Derive application data from each verified token (see `CustomDataContext`). */
  customData?: CustomDataFn;

  /** Called with the verified claims of every token response the relay passes on. */
  onTokenResponse?: TokenResponseHook;

  /** JWKS cache options for token verification. */
  jwksCacheOptions?: JwksCacheOptions;

  /** Additional origins allowed to call the MCP endpoint from a browser. */
  additionalCorsOrigins?: string[];

  /**
   * Whether cookies must be `Secure`.
   * Default: `true` when `baseUrl` uses `https`
   */
  secureCookies?: boolean;

  /** Called with the underlying error whenever a token is rejected. */
  onVerifyError?: (error: unknown) => void;

  /** Logger. Default: a console logger at `info` level */
  logger?: Logger;

  /** `fetch` implementation for upstream and metadata document requests. Default: global `fetch` */
  fetch?: typeof fetch;
}
