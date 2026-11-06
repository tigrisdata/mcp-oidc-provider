import { describe, it, expect, vi, beforeEach } from 'vitest';
import { jwtVerify } from 'jose';
import { startFakeUpstream, type FakeUpstream } from '../test/helpers/index.js';
import { noopLogger } from '../utils/logger.js';
import { DEFAULT_UPSTREAM_SCOPES, Upstream, isRecord, stripTrailingSlash } from './upstream.js';

describe('Upstream', () => {
  let fake: FakeUpstream;
  let fetchSpy: ReturnType<typeof vi.fn>;

  const create = (overrides: Partial<ConstructorParameters<typeof Upstream>[0]> = {}) =>
    new Upstream(
      {
        issuer: fake.issuer,
        clientId: fake.clientId,
        clientSecret: fake.clientSecret,
        audience: fake.audience,
        ...overrides,
      },
      { fetch: fetchSpy as unknown as typeof fetch, logger: noopLogger }
    );

  beforeEach(async () => {
    fake = await startFakeUpstream();
    fetchSpy = vi.fn((input: Parameters<typeof fetch>[0], init?: RequestInit) =>
      fetch(input, init)
    );
  });

  it('exposes helpers', () => {
    expect(stripTrailingSlash('https://a/')).toBe('https://a');
    expect(stripTrailingSlash('https://a')).toBe('https://a');
    expect(isRecord({})).toBe(true);
    expect(isRecord([])).toBe(false);
    expect(isRecord(null)).toBe(false);
  });

  it('applies defaults', () => {
    const upstream = create();
    expect(upstream.scopes).toEqual(DEFAULT_UPSTREAM_SCOPES);
    expect(upstream.displayName).toBe('127.0.0.1');
    expect(create({ scopes: ['openid'], displayName: 'Acme SSO' })).toMatchObject({
      scopes: ['openid'],
      displayName: 'Acme SSO',
    });
  });

  describe('metadata', () => {
    it('discovers metadata once', async () => {
      const upstream = create();
      const [a, b] = await Promise.all([upstream.metadata(), upstream.metadata()]);
      await upstream.metadata();

      expect(a).toBe(b);
      expect(a.token_endpoint).toBe(`${fake.issuer}/oauth/token`);
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      expect(String(fetchSpy.mock.calls[0]?.[0])).toBe(
        `${fake.issuer}/.well-known/openid-configuration`
      );
    });

    it('tolerates a trailing slash on the configured issuer', async () => {
      const upstream = create({ issuer: `${fake.issuer}/` });
      expect(upstream.issuer).toBe(fake.issuer);
      await expect(upstream.metadata()).resolves.toMatchObject({ issuer: fake.issuer });
    });

    it('rejects metadata whose issuer differs', async () => {
      fetchSpy.mockImplementation(() =>
        Promise.resolve(
          new Response(JSON.stringify({ ...fake.metadata, issuer: 'https://other.example' }))
        )
      );
      await expect(create().metadata()).rejects.toThrow(
        /issuer "https:\/\/other.example" does not match/
      );
    });

    it('falls back to RFC 8414 discovery with path insertion', async () => {
      const issuer = 'https://auth.example.com/tenant';
      fetchSpy.mockImplementation((input: Parameters<typeof fetch>[0]) => {
        const url = String(input);
        if (url === 'https://auth.example.com/tenant/.well-known/openid-configuration') {
          return Promise.resolve(new Response('not found', { status: 404 }));
        }
        if (url === 'https://auth.example.com/.well-known/oauth-authorization-server/tenant') {
          return Promise.resolve(new Response(JSON.stringify({ ...fake.metadata, issuer })));
        }
        return Promise.resolve(new Response('unexpected', { status: 500 }));
      });

      await expect(create({ issuer }).metadata()).resolves.toMatchObject({ issuer });
      expect(fetchSpy).toHaveBeenCalledTimes(2);
    });

    it('retries discovery after a failure', async () => {
      fetchSpy.mockResolvedValueOnce(new Response('down', { status: 503 }));
      fetchSpy.mockResolvedValueOnce(new Response('down', { status: 503 }));
      const upstream = create();

      await expect(upstream.metadata()).rejects.toThrow(/Could not discover metadata/);
      await expect(upstream.metadata()).resolves.toMatchObject({ issuer: fake.issuer });
    });

    it.each([
      ['not JSON', () => new Response('<html>')],
      ['not an object', () => new Response('[]')],
      ['missing endpoints', () => new Response(JSON.stringify({ issuer: 'x' }))],
    ])('rejects a document that is %s', async (_name, respond) => {
      fetchSpy.mockImplementation(() => Promise.resolve(respond()));
      await expect(create().metadata()).rejects.toThrow();
    });

    it('skips discovery when the endpoints are configured', async () => {
      const upstream = create({
        metadata: {
          authorization_endpoint: 'https://a/authorize',
          token_endpoint: 'https://a/token',
          jwks_uri: 'https://a/jwks',
        },
      });
      await expect(upstream.metadata()).resolves.toEqual({
        issuer: fake.issuer,
        authorization_endpoint: 'https://a/authorize',
        token_endpoint: 'https://a/token',
        jwks_uri: 'https://a/jwks',
      });
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('merges partial metadata over the discovered document', async () => {
      const upstream = create({ metadata: { userinfo_endpoint: 'https://a/me' } });
      await expect(upstream.metadata()).resolves.toMatchObject({
        token_endpoint: `${fake.issuer}/oauth/token`,
        userinfo_endpoint: 'https://a/me',
      });
    });
  });

  it('builds authorization URLs with the relay client id', async () => {
    const url = new URL(await create().authorizationUrl({ state: 'abc', scope: 'openid' }));
    expect(url.origin + url.pathname).toBe(`${fake.issuer}/authorize`);
    expect(url.searchParams.get('client_id')).toBe(fake.clientId);
    expect(url.searchParams.get('state')).toBe('abc');
    expect(url.searchParams.get('scope')).toBe('openid');
  });

  describe('token', () => {
    it('authenticates with HTTP Basic by default and relays the response', async () => {
      const response = await create().token({ grant_type: 'refresh_token', refresh_token: 'rt-1' });

      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({ token_type: 'Bearer' });
      const request = fake.tokenRequests[0];
      expect(request?.authorization).toMatch(/^Basic /);
      expect(request?.params.get('grant_type')).toBe('refresh_token');
      expect(request?.params.has('client_secret')).toBe(false);
    });

    it('can authenticate with client_secret_post', async () => {
      await create({ tokenEndpointAuthMethod: 'client_secret_post' }).token({
        grant_type: 'refresh_token',
        refresh_token: 'rt-1',
      });
      const request = fake.tokenRequests[0];
      expect(request?.authorization).toBeUndefined();
      expect(request?.params.get('client_id')).toBe(fake.clientId);
      expect(request?.params.get('client_secret')).toBe(fake.clientSecret);
    });

    it('returns error responses as they are', async () => {
      const response = await create().token({ grant_type: 'refresh_token', refresh_token: 'bad' });
      expect(response).toEqual({
        status: 400,
        body: { error: 'invalid_grant', error_description: 'unknown refresh token' },
      });
    });

    it('rejects non-JSON responses', async () => {
      fake.nextTokenResponse = { status: 502, body: '<html>bad gateway</html>' };
      await expect(
        create().token({ grant_type: 'refresh_token', refresh_token: 'rt-1' })
      ).rejects.toThrow(/non-JSON response \(HTTP 502\)/);
    });
  });

  describe('userinfo', () => {
    it('fetches UserInfo with the token', async () => {
      await expect(create().userinfo('token-1')).resolves.toMatchObject({ sub: 'user-123' });
      expect(fake.userinfoRequests).toBe(1);
    });

    it('fails without a userinfo endpoint', async () => {
      const bare = await startFakeUpstream({ withoutUserinfo: true });
      const upstream = create({ issuer: bare.issuer });
      await expect(upstream.userinfo('t')).rejects.toThrow(
        /does not advertise a userinfo_endpoint/
      );
    });

    it('fails on error responses', async () => {
      fetchSpy.mockImplementation((input: Parameters<typeof fetch>[0], init?: RequestInit) =>
        String(input).endsWith('/userinfo')
          ? Promise.resolve(new Response('{}', { status: 401 }))
          : fetch(input, init)
      );
      await expect(create().userinfo('t')).rejects.toThrow(/HTTP 401/);
    });

    it('fails on non-object bodies', async () => {
      fetchSpy.mockImplementation((input: Parameters<typeof fetch>[0], init?: RequestInit) =>
        String(input).endsWith('/userinfo')
          ? Promise.resolve(new Response('[]', { headers: { 'content-type': 'application/json' } }))
          : fetch(input, init)
      );
      await expect(create().userinfo('t')).rejects.toThrow(/not a JSON object/);
    });
  });

  describe('verifyToken', () => {
    it('verifies issuer, audience and signature', async () => {
      const upstream = create();
      const token = await fake.signToken({ scope: 'openid' });
      await expect(upstream.verifyToken(token, { audience: fake.audience })).resolves.toMatchObject(
        {
          sub: 'user-123',
          scope: 'openid',
        }
      );
      await expect(upstream.verifyToken(token, { audience: 'https://other' })).rejects.toThrow();
      await expect(
        upstream.verifyToken(token, { audience: fake.audience, requiredClaims: ['nonce'] })
      ).rejects.toThrow();
    });

    it('uses the client secret for HS* tokens only when allowed', async () => {
      const { SignJWT } = await import('jose');
      const hs = await new SignJWT({ sub: 'user-123' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuer(fake.issuer)
        .setAudience(fake.clientId)
        .setExpirationTime('5m')
        .sign(new TextEncoder().encode(fake.clientSecret));
      const upstream = create();
      await expect(
        upstream.verifyToken(hs, { audience: fake.clientId, allowClientSecret: true })
      ).resolves.toMatchObject({ sub: 'user-123' });
      await expect(upstream.verifyToken(hs, { audience: fake.clientId })).rejects.toThrow();
    });
  });

  it('exposes a key set that verifies the provider tokens', async () => {
    const upstream = create();
    const token = await fake.signToken();
    const keys = await upstream.keySet();
    expect(await upstream.keySet()).toBe(keys);
    const { payload } = await jwtVerify(token, keys, { issuer: fake.issuer });
    expect(payload.sub).toBe('user-123');
  });
});
