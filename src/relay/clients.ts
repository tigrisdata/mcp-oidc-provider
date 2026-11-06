/**
 * MCP client identities: Dynamic Client Registration (RFC 7591) and Client ID
 * Metadata Documents, plus redirect URI policy and token endpoint client
 * authentication.
 * @internal
 */

import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import type { Keyv } from 'keyv';
import type { ClientOptions, KeyvLike } from '../types.js';
import type { Logger } from '../utils/logger.js';
import { OAuthRequestError } from './errors.js';
import { GRANT_TYPES, TOKEN_ENDPOINT_AUTH_METHODS } from './metadata.js';
import { STORAGE_NAMESPACES, namespacedStore, randomId, safeEqual, sha256 } from './storage.js';
import { isRecord } from './upstream.js';

/** Client metadata the relay keeps (RFC 7591 field names). */
export interface ClientMetadata {
  redirect_uris: string[];
  token_endpoint_auth_method: string;
  grant_types: string[];
  response_types: string[];
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  scope?: string;
  contacts?: string[];
  tos_uri?: string;
  policy_uri?: string;
  software_id?: string;
  software_version?: string;
}

/** A client the relay knows. */
export interface RegisteredClient extends ClientMetadata {
  client_id: string;
  client_id_issued_at?: number;
  /** SHA-256 of the client secret; only confidential dynamic clients have one. */
  client_secret_hash?: string;
  /** How the client was established. */
  kind: 'dynamic' | 'metadata-document';
}

/** Default lifetime of a dynamic registration: 30 days. */
export const DEFAULT_REGISTRATION_TTL = 30 * 24 * 60 * 60 * 1000;
/** Default upper bound for caching a metadata document: 1 hour. */
export const DEFAULT_CIMD_CACHE_TTL = 60 * 60 * 1000;

const CIMD_MIN_CACHE_TTL = 60 * 1000;
const CIMD_MAX_BYTES = 64 * 1024;
const CIMD_TIMEOUT_MS = 5_000;
const MAX_REDIRECT_URIS = 20;
const MAX_STRING_LENGTH = 512;
const FORBIDDEN_REDIRECT_SCHEMES = new Set([
  'javascript:',
  'data:',
  'file:',
  'blob:',
  'about:',
  'vbscript:',
]);

/** `localhost`, `*.localhost` and the loopback IP literals. */
export function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname === '127.0.0.1' ||
    hostname === '[::1]'
  );
}

/**
 * Default redirect URI policy: `https`, `http` on loopback hosts, and
 * private-use schemes (`cursor://`, `vscode://`, ...) except the dangerous ones.
 */
export function defaultIsAllowedRedirectUri(uri: URL): boolean {
  if (uri.protocol === 'https:') return true;
  if (uri.protocol === 'http:') return isLoopbackHost(uri.hostname);
  return !FORBIDDEN_REDIRECT_SCHEMES.has(uri.protocol);
}

const isLoopbackIp = (uri: URL): boolean =>
  uri.hostname === '127.0.0.1' || uri.hostname === '[::1]';

/**
 * Exact redirect URI match, except that loopback IP literals may use any port
 * (OAuth 2.1 section 8.4.2).
 */
export function redirectUriMatches(registered: string, requested: string): boolean {
  if (registered === requested) return true;
  try {
    const a = new URL(registered);
    const b = new URL(requested);
    if (
      a.protocol === 'http:' &&
      b.protocol === 'http:' &&
      isLoopbackIp(a) &&
      isLoopbackIp(b) &&
      a.hostname === b.hostname
    ) {
      a.port = '';
      b.port = '';
      return a.toString() === b.toString();
    }
  } catch {
    // not URLs
  }
  return false;
}

/** Whether an IP address is loopback, private, link-local or otherwise not public. */
export function isPrivateAddress(address: string): boolean {
  const v4 = address.startsWith('::ffff:') ? address.slice(7) : address;
  if (isIP(v4) === 4) {
    const [a = 0, b = 0] = v4.split('.').map(Number);
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a >= 224
    );
  }
  const lower = address.toLowerCase();
  return (
    lower === '::' ||
    lower === '::1' ||
    lower.startsWith('fc') ||
    lower.startsWith('fd') ||
    lower.startsWith('fe8') ||
    lower.startsWith('fe9') ||
    lower.startsWith('fea') ||
    lower.startsWith('feb')
  );
}

function invalidMetadata(description: string): OAuthRequestError {
  return new OAuthRequestError('invalid_client_metadata', description);
}

function optionalString(body: Record<string, unknown>, key: string): string | undefined {
  const value = body[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string' || value.length > MAX_STRING_LENGTH) {
    throw invalidMetadata(`${key} must be a string of at most ${MAX_STRING_LENGTH} characters`);
  }
  return value;
}

function optionalUrl(body: Record<string, unknown>, key: string): string | undefined {
  const value = optionalString(body, key);
  if (value === undefined) return undefined;
  try {
    new URL(value);
  } catch {
    throw invalidMetadata(`${key} must be a URL`);
  }
  return value;
}

function optionalStringArray(body: Record<string, unknown>, key: string): string[] | undefined {
  const value = body[key];
  if (value === undefined || value === null) return undefined;
  if (
    !Array.isArray(value) ||
    !value.every((item) => typeof item === 'string' && item.length <= MAX_STRING_LENGTH)
  ) {
    throw invalidMetadata(`${key} must be an array of strings`);
  }
  return value as string[];
}

/** Parse a `Cache-Control: max-age` directive, in milliseconds. */
function maxAgeMs(cacheControl: string | null): number | undefined {
  const match = /(?:^|,)\s*max-age=(\d+)/i.exec(cacheControl ?? '');
  return match?.[1] ? Number(match[1]) * 1000 : undefined;
}

export interface ClientRegistryDeps {
  fetch: typeof fetch;
  logger: Logger;
}

export class ClientRegistry {
  readonly allowDynamicRegistration: boolean;
  readonly allowClientIdMetadataDocuments: boolean;

  private readonly clients: Keyv<RegisteredClient>;
  private readonly documents: Keyv<RegisteredClient>;
  private readonly registrationTtl: number;
  private readonly cimdAllowedHosts: Set<string> | undefined;
  private readonly cimdCacheTtl: number;
  private readonly isAllowedRedirectUri: (uri: URL) => boolean;
  private readonly deps: ClientRegistryDeps;

  constructor(store: KeyvLike, options: ClientOptions, deps: ClientRegistryDeps) {
    this.clients = namespacedStore<RegisteredClient>(store, STORAGE_NAMESPACES.CLIENTS);
    this.documents = namespacedStore<RegisteredClient>(store, STORAGE_NAMESPACES.CIMD);
    this.allowDynamicRegistration = options.allowDynamicRegistration ?? true;
    this.allowClientIdMetadataDocuments = options.allowClientIdMetadataDocuments ?? true;
    this.registrationTtl = options.registrationTtl ?? DEFAULT_REGISTRATION_TTL;
    this.cimdAllowedHosts = options.cimdAllowedHosts
      ? new Set(options.cimdAllowedHosts.map((host) => host.toLowerCase()))
      : undefined;
    this.cimdCacheTtl = options.cimdCacheTtl ?? DEFAULT_CIMD_CACHE_TTL;
    this.isAllowedRedirectUri = options.isAllowedRedirectUri ?? defaultIsAllowedRedirectUri;
    this.deps = deps;
  }

  /** Validate a `redirect_uris` value against the redirect URI policy. */
  validateRedirectUris(value: unknown): string[] {
    const invalid = (description: string) =>
      new OAuthRequestError('invalid_redirect_uri', description);
    if (!Array.isArray(value) || value.length === 0) {
      throw invalid('redirect_uris must be a non-empty array');
    }
    if (value.length > MAX_REDIRECT_URIS) {
      throw invalid(`at most ${MAX_REDIRECT_URIS} redirect_uris are allowed`);
    }
    return value.map((item): string => {
      if (typeof item !== 'string' || item.length > 2048) {
        throw invalid('redirect_uris must contain URL strings');
      }
      let uri: URL;
      try {
        uri = new URL(item);
      } catch {
        throw invalid(`"${item}" is not an absolute URI`);
      }
      if (item.includes('#')) {
        throw invalid(`"${item}" must not contain a fragment`);
      }
      if (!this.isAllowedRedirectUri(uri)) {
        throw invalid(`"${item}" is not an allowed redirect URI`);
      }
      return item;
    });
  }

  /** Validate client metadata (RFC 7591 section 2), applying defaults. */
  parseClientMetadata(body: unknown): ClientMetadata {
    if (!isRecord(body)) throw invalidMetadata('client metadata must be a JSON object');

    const redirect_uris = this.validateRedirectUris(body['redirect_uris']);

    const token_endpoint_auth_method = optionalString(body, 'token_endpoint_auth_method') ?? 'none';
    if (!TOKEN_ENDPOINT_AUTH_METHODS.includes(token_endpoint_auth_method)) {
      throw invalidMetadata(
        `token_endpoint_auth_method must be one of ${TOKEN_ENDPOINT_AUTH_METHODS.join(', ')}`
      );
    }

    const grant_types = optionalStringArray(body, 'grant_types') ?? ['authorization_code'];
    if (
      !grant_types.includes('authorization_code') ||
      grant_types.some((g) => !GRANT_TYPES.includes(g))
    ) {
      throw invalidMetadata(`grant_types must be authorization_code optionally with refresh_token`);
    }

    const response_types = optionalStringArray(body, 'response_types') ?? ['code'];
    if (response_types.length === 0 || response_types.some((type) => type !== 'code')) {
      throw invalidMetadata('response_types must be ["code"]');
    }

    const metadata: ClientMetadata = {
      redirect_uris,
      token_endpoint_auth_method,
      grant_types,
      response_types,
    };
    const client_name = optionalString(body, 'client_name');
    if (client_name) metadata.client_name = client_name;
    for (const key of ['client_uri', 'logo_uri', 'tos_uri', 'policy_uri'] as const) {
      const value = optionalUrl(body, key);
      if (value) metadata[key] = value;
    }
    for (const key of ['scope', 'software_id', 'software_version'] as const) {
      const value = optionalString(body, key);
      if (value) metadata[key] = value;
    }
    const contacts = optionalStringArray(body, 'contacts');
    if (contacts) metadata.contacts = contacts;
    return metadata;
  }

  /**
   * Register a client dynamically. Resolves with the RFC 7591 registration
   * response, which is the only time a client secret is returned.
   */
  async register(body: unknown): Promise<Record<string, unknown>> {
    const metadata = this.parseClientMetadata(body);
    const now = Date.now();
    const client_id = randomId(24);
    const client: RegisteredClient = {
      ...metadata,
      client_id,
      client_id_issued_at: Math.floor(now / 1000),
      kind: 'dynamic',
    };
    const response: Record<string, unknown> = {
      ...metadata,
      client_id,
      client_id_issued_at: client.client_id_issued_at,
    };
    if (metadata.token_endpoint_auth_method !== 'none') {
      const secret = randomId(32);
      client.client_secret_hash = sha256(secret);
      response['client_secret'] = secret;
      response['client_secret_expires_at'] = Math.floor((now + this.registrationTtl) / 1000);
    }
    await this.clients.set(client_id, client, this.registrationTtl);
    this.deps.logger.info('Registered client', {
      clientId: client_id,
      clientName: metadata.client_name,
      redirectUris: metadata.redirect_uris,
    });
    return response;
  }

  /** Whether a `client_id` is a Client ID Metadata Document URL. */
  isMetadataDocumentClientId(clientId: string): boolean {
    if (!clientId.startsWith('https://')) return false;
    try {
      const url = new URL(clientId);
      return url.pathname !== '/' && url.pathname !== '';
    } catch {
      return false;
    }
  }

  /**
   * Look up a client by `client_id`: a dynamic registration or, for `https`
   * URLs, its metadata document. Resolves `undefined` for unknown or invalid
   * clients (the reason is logged).
   */
  async resolve(clientId: string): Promise<RegisteredClient | undefined> {
    if (this.isMetadataDocumentClientId(clientId)) {
      if (!this.allowClientIdMetadataDocuments) return undefined;
      const cached = await this.documents.get(clientId);
      if (cached) return cached;
      try {
        return await this.fetchMetadataDocument(clientId);
      } catch (error) {
        this.deps.logger.warn('Rejected client metadata document', {
          clientId,
          error: error instanceof Error ? error.message : String(error),
        });
        return undefined;
      }
    }
    return this.clients.get(clientId);
  }

  /**
   * Authenticate a client at the token endpoint. Public clients need no
   * secret; confidential clients must present the one issued at registration.
   */
  async authenticate(
    clientId: string | undefined,
    clientSecret: string | undefined
  ): Promise<RegisteredClient> {
    const unauthorized = new OAuthRequestError(
      'invalid_client',
      'Client authentication failed',
      401
    );
    if (!clientId) throw unauthorized;
    const client = await this.resolve(clientId);
    if (!client) throw unauthorized;
    if (client.token_endpoint_auth_method === 'none') return client;
    if (
      !clientSecret ||
      !client.client_secret_hash ||
      !safeEqual(sha256(clientSecret), client.client_secret_hash)
    ) {
      throw unauthorized;
    }
    return client;
  }

  private async assertFetchableHost(url: URL): Promise<void> {
    const hostname = url.hostname.toLowerCase();
    if (this.cimdAllowedHosts) {
      if (!this.cimdAllowedHosts.has(hostname)) {
        throw new Error(`host ${hostname} is not in cimdAllowedHosts`);
      }
      return;
    }
    const bare = hostname.replace(/^\[|\]$/g, '');
    if (isIP(bare) || isLoopbackHost(hostname) || !hostname.includes('.')) {
      throw new Error(`host ${hostname} is not a public hostname`);
    }
    const addresses = await lookup(hostname, { all: true });
    if (addresses.length === 0 || addresses.some(({ address }) => isPrivateAddress(address))) {
      throw new Error(`host ${hostname} resolves to a private address`);
    }
  }

  private async fetchMetadataDocument(clientId: string): Promise<RegisteredClient> {
    const url = new URL(clientId);
    if (url.username || url.password || url.hash) {
      throw new Error('client_id URL must not contain credentials or a fragment');
    }
    await this.assertFetchableHost(url);

    const response = await this.deps.fetch(url, {
      headers: { accept: 'application/json' },
      redirect: 'manual',
      signal: AbortSignal.timeout(CIMD_TIMEOUT_MS),
    });
    if (response.status !== 200) {
      throw new Error(`metadata document request returned HTTP ${response.status}`);
    }
    const text = await response.text();
    if (text.length > CIMD_MAX_BYTES) {
      throw new Error('metadata document is too large');
    }
    let document: unknown;
    try {
      document = JSON.parse(text);
    } catch {
      throw new Error('metadata document is not valid JSON');
    }
    if (!isRecord(document)) throw new Error('metadata document is not a JSON object');
    if (document['client_id'] !== clientId) {
      throw new Error('metadata document client_id does not match its URL');
    }
    const method = document['token_endpoint_auth_method'];
    if (method !== undefined && method !== 'none') {
      throw new Error(
        `token_endpoint_auth_method ${String(method)} is not supported for metadata document clients`
      );
    }
    const metadata = this.parseClientMetadata({ ...document, token_endpoint_auth_method: 'none' });
    const client: RegisteredClient = {
      ...metadata,
      client_name: metadata.client_name ?? url.hostname,
      client_id: clientId,
      kind: 'metadata-document',
    };

    const ttl = Math.min(
      Math.max(
        maxAgeMs(response.headers.get('cache-control')) ?? this.cimdCacheTtl,
        CIMD_MIN_CACHE_TTL
      ),
      this.cimdCacheTtl
    );
    await this.documents.set(clientId, client, ttl);
    this.deps.logger.info('Fetched client metadata document', {
      clientId,
      clientName: client.client_name,
    });
    return client;
  }
}
