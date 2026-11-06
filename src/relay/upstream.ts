/**
 * The upstream identity provider: metadata discovery, token endpoint calls,
 * UserInfo and the key set used to verify its tokens.
 * @internal
 */

import {
  createRemoteJWKSet,
  customFetch,
  decodeProtectedHeader,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from 'jose';
import type { JwksCacheOptions, UpstreamMetadata, UpstreamOptions } from '../types.js';
import type { Logger } from '../utils/logger.js';

/** Scopes requested from the identity provider unless configured otherwise. */
export const DEFAULT_UPSTREAM_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

/** Default JWKS cache options for `createRemoteJWKSet`. */
export const DEFAULT_JWKS_CACHE_OPTIONS = {
  /** Minimum time between JWKS fetches (milliseconds). */
  cooldownDuration: 30_000,
  /** Maximum age of the cached JWKS (milliseconds). */
  cacheMaxAge: 600_000,
} as const;

const REQUEST_TIMEOUT_MS = 10_000;

/** A token endpoint response, to be relayed to the MCP client. */
export interface UpstreamTokenResponse {
  status: number;
  body: Record<string, unknown>;
}

export interface UpstreamDeps {
  fetch: typeof fetch;
  logger: Logger;
  jwksCacheOptions?: JwksCacheOptions;
}

/** Remove one trailing slash. */
export function stripTrailingSlash(url: string): string {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const REQUIRED_ENDPOINTS = ['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const;

/** HTTP Basic credentials per RFC 6749 section 2.3.1. */
function basicCredentials(clientId: string, clientSecret: string): string {
  const encoded = `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`;
  return Buffer.from(encoded).toString('base64');
}

export class Upstream {
  /** Configured issuer without a trailing slash. */
  readonly issuer: string;
  /** The relay's client ID at the provider. */
  readonly clientId: string;
  /** Scopes requested from the provider. */
  readonly scopes: string[];
  /** Name shown to users. */
  readonly displayName: string;

  private readonly options: UpstreamOptions;
  private readonly deps: UpstreamDeps;
  private metadataPromise: Promise<UpstreamMetadata> | undefined;
  private keys: JWTVerifyGetKey | undefined;

  constructor(options: UpstreamOptions, deps: UpstreamDeps) {
    this.options = options;
    this.deps = deps;
    this.issuer = stripTrailingSlash(options.issuer);
    this.clientId = options.clientId;
    this.scopes = options.scopes ?? DEFAULT_UPSTREAM_SCOPES;
    this.displayName = options.displayName ?? new URL(this.issuer).hostname;
  }

  /**
   * The provider's metadata, discovered on first use. A failed discovery is
   * retried on the next call.
   */
  metadata(): Promise<UpstreamMetadata> {
    if (!this.metadataPromise) {
      this.metadataPromise = this.discover().catch((error: unknown) => {
        this.metadataPromise = undefined;
        throw error;
      });
    }
    return this.metadataPromise;
  }

  private async discover(): Promise<UpstreamMetadata> {
    const overrides = this.options.metadata ?? {};
    if (REQUIRED_ENDPOINTS.every((key) => typeof overrides[key] === 'string')) {
      return this.validate({ issuer: this.issuer, ...overrides });
    }

    const issuerUrl = new URL(this.issuer);
    const path = issuerUrl.pathname === '/' ? '' : issuerUrl.pathname;
    const candidates = [
      `${this.issuer}/.well-known/openid-configuration`,
      `${issuerUrl.origin}/.well-known/oauth-authorization-server${path}`,
    ];

    let lastError: unknown = new Error('no metadata document found');
    for (const url of candidates) {
      try {
        const response = await this.deps.fetch(url, {
          headers: { accept: 'application/json' },
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });
        if (response.status === 404) {
          lastError = new Error(`HTTP 404 from ${url}`);
          continue;
        }
        if (!response.ok) throw new Error(`HTTP ${response.status} from ${url}`);
        const document: unknown = await response.json();
        if (!isRecord(document)) throw new Error(`${url} is not a JSON object`);
        const metadata = this.validate({ ...document, ...overrides });
        this.deps.logger.info('Discovered upstream identity provider metadata', {
          issuer: metadata.issuer,
        });
        return metadata;
      } catch (error) {
        lastError = error;
        this.deps.logger.warn('Upstream metadata discovery attempt failed', {
          url,
          error: describeError(error),
        });
      }
    }
    throw new Error(`Could not discover metadata for ${this.issuer}: ${describeError(lastError)}`);
  }

  private validate(document: Record<string, unknown>): UpstreamMetadata {
    for (const key of REQUIRED_ENDPOINTS) {
      if (typeof document[key] !== 'string') {
        throw new Error(`Upstream metadata is missing ${key}`);
      }
    }
    const issuer = document['issuer'];
    if (typeof issuer !== 'string' || stripTrailingSlash(issuer) !== this.issuer) {
      throw new Error(
        `Upstream metadata issuer "${String(issuer)}" does not match the configured issuer "${this.issuer}"`
      );
    }
    return document as UpstreamMetadata;
  }

  /** Build an authorization URL at the provider. */
  async authorizationUrl(params: Record<string, string>): Promise<string> {
    const { authorization_endpoint } = await this.metadata();
    const url = new URL(authorization_endpoint);
    url.searchParams.set('client_id', this.options.clientId);
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }
    return url.toString();
  }

  /**
   * Call the token endpoint with the relay's own client credentials.
   * Resolves with the provider's status and JSON body, whatever they are.
   */
  async token(params: Record<string, string>): Promise<UpstreamTokenResponse> {
    const { token_endpoint } = await this.metadata();
    const body = new URLSearchParams(params);
    const headers: Record<string, string> = {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    };
    if (this.options.tokenEndpointAuthMethod === 'client_secret_post') {
      body.set('client_id', this.options.clientId);
      body.set('client_secret', this.options.clientSecret);
    } else {
      headers['authorization'] =
        `Basic ${basicCredentials(this.options.clientId, this.options.clientSecret)}`;
    }

    const response = await this.deps.fetch(token_endpoint, {
      method: 'POST',
      headers,
      body,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const text = await response.text();
    let parsed: unknown;
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      parsed = undefined;
    }
    if (!isRecord(parsed)) {
      throw new Error(
        `Upstream token endpoint returned a non-JSON response (HTTP ${response.status})`
      );
    }
    return { status: response.status, body: parsed };
  }

  /** Fetch UserInfo for an access token. */
  async userinfo(accessToken: string): Promise<Record<string, unknown>> {
    const { userinfo_endpoint } = await this.metadata();
    if (!userinfo_endpoint) {
      throw new Error('The identity provider does not advertise a userinfo_endpoint');
    }
    const response = await this.deps.fetch(userinfo_endpoint, {
      headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) {
      throw new Error(`UserInfo request failed: HTTP ${response.status}`);
    }
    const body: unknown = await response.json();
    if (!isRecord(body)) {
      throw new Error('UserInfo response is not a JSON object');
    }
    return body;
  }

  /**
   * Verify a JWT the provider issued: signature, issuer, audience, expiry.
   * ID tokens signed with an `HS*` algorithm use the relay's client secret
   * when `allowClientSecret` is set.
   */
  async verifyToken(
    token: string,
    options: { audience: string; requiredClaims?: string[]; allowClientSecret?: boolean }
  ): Promise<JWTPayload> {
    const { issuer } = await this.metadata();
    const symmetric =
      options.allowClientSecret && decodeProtectedHeader(token).alg?.startsWith('HS');
    const key = symmetric
      ? new TextEncoder().encode(this.options.clientSecret)
      : await this.keySet();
    const { payload } = await jwtVerify(token, key, {
      issuer,
      audience: options.audience,
      requiredClaims: options.requiredClaims,
    });
    return payload;
  }

  /** The provider's signing keys, for `jwtVerify`. */
  async keySet(): Promise<JWTVerifyGetKey> {
    if (!this.keys) {
      const { jwks_uri } = await this.metadata();
      this.keys = createRemoteJWKSet(new URL(jwks_uri), {
        ...DEFAULT_JWKS_CACHE_OPTIONS,
        ...this.deps.jwksCacheOptions,
        [customFetch]: this.deps.fetch,
      });
    }
    return this.keys;
  }
}
