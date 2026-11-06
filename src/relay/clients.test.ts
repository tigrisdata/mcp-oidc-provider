import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createMockStore } from '../test/helpers/index.js';
import { noopLogger } from '../utils/logger.js';
import {
  ClientRegistry,
  DEFAULT_REGISTRATION_TTL,
  defaultIsAllowedRedirectUri,
  isPrivateAddress,
  redirectUriMatches,
} from './clients.js';
import { OAuthRequestError } from './errors.js';
import { sha256 } from './storage.js';

const { lookup } = vi.hoisted(() => ({ lookup: vi.fn() }));
vi.mock('node:dns/promises', () => ({ lookup }));

const CIMD_ID = 'https://client.example/oauth/metadata.json';
const document = () => ({
  client_id: CIMD_ID,
  client_name: 'Example Client',
  redirect_uris: ['http://localhost:3000/callback', 'https://client.example/callback'],
  grant_types: ['authorization_code', 'refresh_token'],
});

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  });
}

/** Keyv's stored envelope for a key, to inspect TTLs. */
function envelope(storedData: Map<string, unknown>, key: string): { expires?: number } {
  return JSON.parse(storedData.get(key) as string) as { expires?: number };
}

describe('redirect URI policy', () => {
  it.each([
    ['https://app.example.com/cb', true],
    ['http://localhost:3000/cb', true],
    ['http://127.0.0.1:3000/cb', true],
    ['http://[::1]:3000/cb', true],
    ['http://app.localhost/cb', true],
    ['http://app.example.com/cb', false],
    ['cursor://anysphere.cursor-retrieval/oauth/callback', true],
    ['vscode://redhat.vscode-mcp/callback', true],
    ['javascript:alert(1)', false],
    ['data:text/html,hi', false],
    ['file:///etc/passwd', false],
  ])('%s -> %s', (uri, allowed) => {
    expect(defaultIsAllowedRedirectUri(new URL(uri))).toBe(allowed);
  });

  it('matches exactly, except for the port of loopback IP literals', () => {
    expect(redirectUriMatches('https://a/cb', 'https://a/cb')).toBe(true);
    expect(redirectUriMatches('https://a/cb', 'https://a/cb2')).toBe(false);
    expect(redirectUriMatches('http://127.0.0.1:3000/cb', 'http://127.0.0.1:4000/cb')).toBe(true);
    expect(redirectUriMatches('http://[::1]:3000/cb', 'http://[::1]:4000/cb')).toBe(true);
    expect(redirectUriMatches('http://127.0.0.1:3000/cb', 'http://[::1]:3000/cb')).toBe(false);
    expect(redirectUriMatches('http://localhost:3000/cb', 'http://localhost:4000/cb')).toBe(false);
    expect(redirectUriMatches('http://127.0.0.1:3000/cb', 'http://127.0.0.1:4000/other')).toBe(
      false
    );
    expect(redirectUriMatches('not a url', 'not a url either')).toBe(false);
  });
});

describe('isPrivateAddress', () => {
  it.each([
    ['10.0.0.1', true],
    ['127.0.0.1', true],
    ['192.168.1.1', true],
    ['172.16.0.1', true],
    ['172.31.255.255', true],
    ['172.32.0.1', false],
    ['169.254.169.254', true],
    ['100.64.0.1', true],
    ['0.0.0.0', true],
    ['224.0.0.1', true],
    ['8.8.8.8', false],
    ['::1', true],
    ['::', true],
    ['fd00::1', true],
    ['fc00::1', true],
    ['fe80::1', true],
    ['2001:db8::1', false],
    ['::ffff:10.0.0.1', true],
    ['::ffff:93.184.216.34', false],
  ])('%s -> %s', (address, isPrivate) => {
    expect(isPrivateAddress(address)).toBe(isPrivate);
  });
});

describe('ClientRegistry', () => {
  let store: ReturnType<typeof createMockStore>['store'];
  let storedData: Map<string, unknown>;
  let fetchMock: ReturnType<typeof vi.fn>;

  const createRegistry = (options: ConstructorParameters<typeof ClientRegistry>[1] = {}) =>
    new ClientRegistry(store, options, {
      fetch: fetchMock as unknown as typeof fetch,
      logger: noopLogger,
    });

  beforeEach(() => {
    ({ store, storedData } = createMockStore());
    fetchMock = vi.fn();
    lookup.mockReset();
  });

  describe('register', () => {
    it('registers a public client with defaults', async () => {
      const registry = createRegistry();
      const response = await registry.register({ redirect_uris: ['http://localhost:3000/cb'] });

      expect(response).toEqual({
        client_id: expect.stringMatching(/^[A-Za-z0-9_-]{32}$/),
        client_id_issued_at: expect.any(Number),
        redirect_uris: ['http://localhost:3000/cb'],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code'],
        response_types: ['code'],
      });
      expect(response).not.toHaveProperty('client_secret');

      const client = await registry.resolve(response['client_id'] as string);
      expect(client).toMatchObject({ kind: 'dynamic', client_id: response['client_id'] });
      expect(client).not.toHaveProperty('client_secret_hash');
    });

    it('issues a secret to confidential clients and stores only its hash', async () => {
      const registry = createRegistry();
      const response = await registry.register({
        redirect_uris: ['https://app.example.com/cb'],
        token_endpoint_auth_method: 'client_secret_basic',
      });

      const secret = response['client_secret'] as string;
      expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(response['client_secret_expires_at']).toBeGreaterThan(Date.now() / 1000);
      const client = await registry.resolve(response['client_id'] as string);
      expect(client?.client_secret_hash).toBe(sha256(secret));
      expect(JSON.stringify(client)).not.toContain(secret);
    });

    it('keeps the registration for the configured TTL', async () => {
      await createRegistry().register({ redirect_uris: ['https://a/cb'] });
      const [key] = [...storedData.keys()];
      const { expires } = envelope(storedData, key as string);
      expect(expires).toBeGreaterThan(Date.now() + DEFAULT_REGISTRATION_TTL - 5_000);

      storedData.clear();
      await createRegistry({ registrationTtl: 1_000 }).register({
        redirect_uris: ['https://a/cb'],
      });
      const [shortKey] = [...storedData.keys()];
      expect(envelope(storedData, shortKey as string).expires).toBeLessThan(Date.now() + 2_000);
    });

    it('echoes optional metadata', async () => {
      const response = await createRegistry().register({
        redirect_uris: ['https://app.example.com/cb'],
        client_name: 'My App',
        client_uri: 'https://app.example.com',
        logo_uri: 'https://app.example.com/logo.png',
        tos_uri: 'https://app.example.com/tos',
        policy_uri: 'https://app.example.com/privacy',
        scope: 'openid email',
        contacts: ['dev@example.com'],
        software_id: 'my-app',
        software_version: '1.2.3',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        unknown_field: 'dropped',
      });

      expect(response).toMatchObject({
        client_name: 'My App',
        client_uri: 'https://app.example.com',
        logo_uri: 'https://app.example.com/logo.png',
        tos_uri: 'https://app.example.com/tos',
        policy_uri: 'https://app.example.com/privacy',
        scope: 'openid email',
        contacts: ['dev@example.com'],
        software_id: 'my-app',
        software_version: '1.2.3',
        grant_types: ['authorization_code', 'refresh_token'],
      });
      expect(response).not.toHaveProperty('unknown_field');
    });

    it.each([
      ['not an object', 'invalid_client_metadata'],
      [{}, 'invalid_redirect_uri'],
      [{ redirect_uris: [] }, 'invalid_redirect_uri'],
      [{ redirect_uris: 'https://a/cb' }, 'invalid_redirect_uri'],
      [{ redirect_uris: [42] }, 'invalid_redirect_uri'],
      [{ redirect_uris: ['relative/path'] }, 'invalid_redirect_uri'],
      [{ redirect_uris: ['https://a/cb#frag'] }, 'invalid_redirect_uri'],
      [{ redirect_uris: ['http://evil.example/cb'] }, 'invalid_redirect_uri'],
      [
        { redirect_uris: Array.from({ length: 21 }, (_, i) => `https://a/${i}`) },
        'invalid_redirect_uri',
      ],
      [
        { redirect_uris: ['https://a/cb'], token_endpoint_auth_method: 'private_key_jwt' },
        'invalid_client_metadata',
      ],
      [{ redirect_uris: ['https://a/cb'], grant_types: ['implicit'] }, 'invalid_client_metadata'],
      [
        { redirect_uris: ['https://a/cb'], grant_types: ['refresh_token'] },
        'invalid_client_metadata',
      ],
      [
        { redirect_uris: ['https://a/cb'], grant_types: 'authorization_code' },
        'invalid_client_metadata',
      ],
      [{ redirect_uris: ['https://a/cb'], response_types: ['token'] }, 'invalid_client_metadata'],
      [{ redirect_uris: ['https://a/cb'], response_types: [] }, 'invalid_client_metadata'],
      [
        { redirect_uris: ['https://a/cb'], client_name: 'x'.repeat(513) },
        'invalid_client_metadata',
      ],
      [{ redirect_uris: ['https://a/cb'], client_name: 42 }, 'invalid_client_metadata'],
      [{ redirect_uris: ['https://a/cb'], client_uri: 'not a url' }, 'invalid_client_metadata'],
      [{ redirect_uris: ['https://a/cb'], contacts: 'dev@example.com' }, 'invalid_client_metadata'],
    ])('rejects %j with %s', async (body, code) => {
      await expect(createRegistry().register(body)).rejects.toMatchObject({ code, status: 400 });
    });

    it('applies a custom redirect URI policy', async () => {
      const registry = createRegistry({
        isAllowedRedirectUri: (uri) => uri.hostname === 'ok.example',
      });
      await expect(
        registry.register({ redirect_uris: ['https://ok.example/cb'] })
      ).resolves.toBeDefined();
      await expect(
        registry.register({ redirect_uris: ['https://other.example/cb'] })
      ).rejects.toMatchObject({ code: 'invalid_redirect_uri' });
    });
  });

  describe('authenticate', () => {
    it('accepts a public client with or without a secret', async () => {
      const registry = createRegistry();
      const { client_id } = (await registry.register({ redirect_uris: ['https://a/cb'] })) as {
        client_id: string;
      };

      await expect(registry.authenticate(client_id, undefined)).resolves.toMatchObject({
        client_id,
      });
      await expect(registry.authenticate(client_id, 'anything')).resolves.toMatchObject({
        client_id,
      });
    });

    it('requires the issued secret for confidential clients', async () => {
      const registry = createRegistry();
      const { client_id, client_secret } = (await registry.register({
        redirect_uris: ['https://a/cb'],
        token_endpoint_auth_method: 'client_secret_post',
      })) as { client_id: string; client_secret: string };

      await expect(registry.authenticate(client_id, client_secret)).resolves.toMatchObject({
        client_id,
      });
      for (const secret of ['wrong', undefined, '']) {
        await expect(registry.authenticate(client_id, secret)).rejects.toMatchObject({
          code: 'invalid_client',
          status: 401,
        });
      }
    });

    it('rejects unknown and missing client ids', async () => {
      const registry = createRegistry();
      await expect(registry.authenticate(undefined, undefined)).rejects.toBeInstanceOf(
        OAuthRequestError
      );
      await expect(registry.authenticate('nope', undefined)).rejects.toMatchObject({
        code: 'invalid_client',
      });
    });
  });

  describe('client ID metadata documents', () => {
    it('recognises https URLs with a path as metadata document client ids', () => {
      const registry = createRegistry();
      expect(registry.isMetadataDocumentClientId(CIMD_ID)).toBe(true);
      expect(registry.isMetadataDocumentClientId('https://client.example')).toBe(false);
      expect(registry.isMetadataDocumentClientId('https://client.example/')).toBe(false);
      expect(registry.isMetadataDocumentClientId('http://client.example/x')).toBe(false);
      expect(registry.isMetadataDocumentClientId('https://')).toBe(false);
      expect(registry.isMetadataDocumentClientId('abc')).toBe(false);
    });

    it('fetches, validates and caches the document for an allowed host', async () => {
      fetchMock.mockResolvedValue(
        jsonResponse(document(), { headers: { 'cache-control': 'public, max-age=120' } })
      );
      const registry = createRegistry({ cimdAllowedHosts: ['client.example'] });

      const client = await registry.resolve(CIMD_ID);

      expect(client).toMatchObject({
        client_id: CIMD_ID,
        client_name: 'Example Client',
        kind: 'metadata-document',
        token_endpoint_auth_method: 'none',
        redirect_uris: document().redirect_uris,
        grant_types: ['authorization_code', 'refresh_token'],
      });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock.mock.calls[0]?.[0]).toBeInstanceOf(URL);
      expect(String(fetchMock.mock.calls[0]?.[0])).toBe(CIMD_ID);
      expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({ redirect: 'manual' });
      expect(lookup).not.toHaveBeenCalled();

      await registry.resolve(CIMD_ID);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const key = [...storedData.keys()].find((k) => k.includes('cimd'));
      const { expires } = envelope(storedData, key as string);
      expect(expires).toBeGreaterThan(Date.now() + 110_000);
      expect(expires).toBeLessThan(Date.now() + 130_000);
    });

    it('clamps the cache lifetime', async () => {
      const registry = createRegistry({
        cimdAllowedHosts: ['client.example'],
        cimdCacheTtl: 5 * 60_000,
      });

      fetchMock.mockResolvedValueOnce(
        jsonResponse(document(), { headers: { 'cache-control': 'max-age=1' } })
      );
      await registry.resolve(CIMD_ID);
      let key = [...storedData.keys()].find((k) => k.includes('cimd')) as string;
      expect(envelope(storedData, key).expires).toBeGreaterThan(Date.now() + 55_000);

      storedData.clear();
      fetchMock.mockResolvedValueOnce(
        jsonResponse(document(), { headers: { 'cache-control': 'max-age=86400' } })
      );
      await registry.resolve(CIMD_ID);
      key = [...storedData.keys()].find((k) => k.includes('cimd')) as string;
      expect(envelope(storedData, key).expires).toBeLessThan(Date.now() + 5 * 60_000 + 1_000);

      storedData.clear();
      fetchMock.mockResolvedValueOnce(jsonResponse(document()));
      await registry.resolve(CIMD_ID);
      key = [...storedData.keys()].find((k) => k.includes('cimd')) as string;
      expect(envelope(storedData, key).expires).toBeGreaterThan(Date.now() + 5 * 60_000 - 5_000);
    });

    it('uses the hostname when the document has no client_name', async () => {
      const { client_name: _omit, ...withoutName } = document();
      fetchMock.mockResolvedValue(jsonResponse(withoutName));
      const client = await createRegistry({ cimdAllowedHosts: ['client.example'] }).resolve(
        CIMD_ID
      );
      expect(client?.client_name).toBe('client.example');
    });

    it.each([
      [
        'client_id mismatch',
        () => jsonResponse({ ...document(), client_id: 'https://client.example/other.json' }),
      ],
      [
        'redirect status',
        () => new Response(null, { status: 302, headers: { location: 'https://elsewhere' } }),
      ],
      ['server error', () => new Response('nope', { status: 500 })],
      ['not JSON', () => jsonResponse('{not json')],
      ['not an object', () => jsonResponse([1, 2])],
      ['too large', () => jsonResponse(JSON.stringify({ ...document(), pad: 'x'.repeat(70_000) }))],
      [
        'unsupported auth method',
        () => jsonResponse({ ...document(), token_endpoint_auth_method: 'private_key_jwt' }),
      ],
      [
        'bad redirect uri',
        () => jsonResponse({ ...document(), redirect_uris: ['http://evil.example/cb'] }),
      ],
      ['fetch failure', () => Promise.reject(new Error('ECONNREFUSED'))],
    ])('rejects a document with %s', async (_name, respond) => {
      fetchMock.mockImplementation(() => Promise.resolve(respond()));
      const registry = createRegistry({ cimdAllowedHosts: ['client.example'] });
      await expect(registry.resolve(CIMD_ID)).resolves.toBeUndefined();
      expect(storedData.size).toBe(0);
    });

    it('rejects client ids with credentials or a fragment', async () => {
      const registry = createRegistry({ cimdAllowedHosts: ['client.example'] });
      await expect(
        registry.resolve('https://user:pw@client.example/m.json')
      ).resolves.toBeUndefined();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('returns undefined when metadata documents are disabled', async () => {
      const registry = createRegistry({
        allowClientIdMetadataDocuments: false,
        cimdAllowedHosts: ['client.example'],
      });
      await expect(registry.resolve(CIMD_ID)).resolves.toBeUndefined();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('refuses hosts outside the allowlist', async () => {
      const registry = createRegistry({ cimdAllowedHosts: ['other.example'] });
      await expect(registry.resolve(CIMD_ID)).resolves.toBeUndefined();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('refuses non-public hostnames without an allowlist', async () => {
      const registry = createRegistry();
      for (const id of [
        'https://127.0.0.1/metadata.json',
        'https://[::1]/metadata.json',
        'https://localhost/metadata.json',
        'https://intranet/metadata.json',
      ]) {
        await expect(registry.resolve(id)).resolves.toBeUndefined();
      }
      expect(fetchMock).not.toHaveBeenCalled();
      expect(lookup).not.toHaveBeenCalled();
    });

    it('refuses hostnames that resolve to private addresses', async () => {
      lookup.mockResolvedValue([{ address: '10.1.2.3', family: 4 }]);
      await expect(createRegistry().resolve(CIMD_ID)).resolves.toBeUndefined();
      expect(lookup).toHaveBeenCalledWith('client.example', { all: true });
      expect(fetchMock).not.toHaveBeenCalled();

      lookup.mockResolvedValue([]);
      await expect(createRegistry().resolve(CIMD_ID)).resolves.toBeUndefined();

      lookup.mockRejectedValue(new Error('ENOTFOUND'));
      await expect(createRegistry().resolve(CIMD_ID)).resolves.toBeUndefined();
    });

    it('fetches from public hostnames', async () => {
      lookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
      fetchMock.mockResolvedValue(jsonResponse(document()));
      await expect(createRegistry().resolve(CIMD_ID)).resolves.toMatchObject({
        client_id: CIMD_ID,
      });
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });
});
