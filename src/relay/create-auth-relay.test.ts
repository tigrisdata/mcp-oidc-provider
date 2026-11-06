import { describe, it, expect, vi, beforeEach } from 'vitest';
import express, { type Express } from 'express';
import { requireBearerAuth } from '@modelcontextprotocol/express';
import type { AuthRelayOptions } from '../types.js';
import {
  createMockStore,
  createPkce,
  listen,
  startFakeUpstream,
  type FakeUpstream,
} from '../test/helpers/index.js';
import { noopLogger } from '../utils/logger.js';
import { createAuthRelay, type AuthRelay } from './create-auth-relay.js';

const CLIENT_REDIRECT = 'http://127.0.0.1:9999/callback';

interface Harness {
  app: Express;
  baseUrl: string;
  relay: AuthRelay;
  fake: FakeUpstream;
  storedData: Map<string, unknown>;
}

type RelayOverrides = Partial<Omit<AuthRelayOptions, 'upstream'>> & {
  upstream?: Partial<AuthRelayOptions['upstream']>;
};

async function startRelay(overrides: RelayOverrides = {}, fake?: FakeUpstream): Promise<Harness> {
  const upstream = fake ?? (await startFakeUpstream());
  const { store, storedData } = createMockStore();
  const app = express();
  const baseUrl = await listen(app);
  const relay = createAuthRelay({
    baseUrl,
    store,
    logger: noopLogger,
    ...overrides,
    upstream: {
      issuer: upstream.issuer,
      clientId: upstream.clientId,
      clientSecret: upstream.clientSecret,
      audience: upstream.audience,
      ...overrides.upstream,
    },
  });
  app.use(relay.router);
  app.post(
    '/mcp',
    requireBearerAuth({
      verifier: relay.verifier,
      resourceMetadataUrl: relay.resourceMetadataUrl,
      expectedResource: relay.resource,
    }),
    (req, res) => {
      res.json({ sub: req.auth?.extra?.['sub'] });
    }
  );
  return { app, baseUrl, relay, fake: upstream, storedData };
}

const noRedirect = { redirect: 'manual' as const };

async function registerClient(
  baseUrl: string,
  metadata: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const response = await fetch(`${baseUrl}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      redirect_uris: [CLIENT_REDIRECT],
      grant_types: ['authorization_code', 'refresh_token'],
      ...metadata,
    }),
  });
  expect(response.status).toBe(201);
  return (await response.json()) as Record<string, unknown>;
}

function authorizeUrl(
  baseUrl: string,
  params: Record<string, string | string[] | undefined>
): string {
  const url = new URL(`${baseUrl}/authorize`);
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined) continue;
    for (const item of Array.isArray(value) ? value : [value]) url.searchParams.append(key, item);
  }
  return url.toString();
}

const consentFields = (html: string) => ({
  id: /name="id" value="([^"]+)"/.exec(html)?.[1] ?? '',
  csrf: /name="csrf" value="([^"]+)"/.exec(html)?.[1] ?? '',
});

async function postConsent(
  baseUrl: string,
  fields: Record<string, string>,
  headers: Record<string, string> = {}
): Promise<Response> {
  return fetch(`${baseUrl}/authorize/consent`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams(fields),
    ...noRedirect,
  });
}

async function postToken(
  baseUrl: string,
  params: Record<string, string>,
  headers: Record<string, string> = {}
): Promise<{ status: number; body: Record<string, unknown>; headers: Headers }> {
  const response = await fetch(`${baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams(params),
  });
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
    headers: response.headers,
  };
}

/** Walk the browser part of the flow up to the relay's authorization code. */
async function completeAuthorization(
  h: Harness,
  clientId: string,
  options: { cookie?: string; extra?: Record<string, string>; deny?: boolean } = {}
): Promise<{
  code: string;
  state: string | null;
  challenge: string;
  verifier: string;
  cookie: string | undefined;
  clientRedirect: URL;
}> {
  const pkce = createPkce();
  const start = await fetch(
    authorizeUrl(h.baseUrl, {
      client_id: clientId,
      redirect_uri: CLIENT_REDIRECT,
      response_type: 'code',
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
      state: 'client-state',
      scope: 'openid email',
      resource: `${h.baseUrl}/mcp`,
      ...options.extra,
    }),
    { ...noRedirect, headers: options.cookie ? { cookie: options.cookie } : {} }
  );

  let toUpstream: Response;
  let cookie = options.cookie;
  if (start.status === 200) {
    const fields = consentFields(await start.text());
    toUpstream = await postConsent(
      h.baseUrl,
      { ...fields, decision: options.deny ? 'deny' : 'approve' },
      { origin: h.baseUrl }
    );
    cookie = toUpstream.headers.get('set-cookie')?.split(';')[0] ?? cookie;
  } else {
    toUpstream = start;
  }
  expect(toUpstream.status).toBe(302);
  const upstreamLocation = toUpstream.headers.get('location') as string;
  if (options.deny) {
    const clientRedirect = new URL(upstreamLocation);
    return {
      code: '',
      state: clientRedirect.searchParams.get('state'),
      ...pkce,
      cookie,
      clientRedirect,
    };
  }

  const fromUpstream = await fetch(upstreamLocation, noRedirect);
  expect(fromUpstream.status).toBe(302);
  const callback = await fetch(fromUpstream.headers.get('location') as string, noRedirect);
  expect(callback.status).toBe(302);
  const clientRedirect = new URL(callback.headers.get('location') as string);
  return {
    code: clientRedirect.searchParams.get('code') ?? '',
    state: clientRedirect.searchParams.get('state'),
    ...pkce,
    cookie,
    clientRedirect,
  };
}

describe('createAuthRelay', () => {
  let h: Harness;
  let clientId: string;

  beforeEach(async () => {
    h = await startRelay();
    clientId = (await registerClient(h.baseUrl))['client_id'] as string;
  });

  describe('options', () => {
    it('requires baseUrl to be an origin', () => {
      const options = {
        upstream: { issuer: 'https://a', clientId: 'c', clientSecret: 's', audience: 'x' },
        store: createMockStore().store,
        logger: noopLogger,
      };
      expect(() => createAuthRelay({ ...options, baseUrl: 'nope' })).toThrow(/absolute URL/);
      expect(() => createAuthRelay({ ...options, baseUrl: 'https://a/path' })).toThrow(
        /without a path/
      );
      expect(() => createAuthRelay({ ...options, baseUrl: 'https://a/?q=1' })).toThrow(
        /without a path/
      );
      expect(createAuthRelay({ ...options, baseUrl: 'https://a/' }).metadata.issuer).toBe(
        'https://a'
      );
    });

    it('exposes the resource, metadata URL and upstream discovery', async () => {
      expect(h.relay.resource.toString()).toBe(`${h.baseUrl}/mcp`);
      expect(h.relay.resourceMetadataUrl).toBe(
        `${h.baseUrl}/.well-known/oauth-protected-resource/mcp`
      );
      await expect(h.relay.discoverUpstream()).resolves.toMatchObject({ issuer: h.fake.issuer });
    });
  });

  describe('discovery documents', () => {
    it('serves the relay authorization server metadata', async () => {
      const response = await fetch(`${h.baseUrl}/.well-known/oauth-authorization-server`);
      expect(response.status).toBe(200);
      expect(response.headers.get('access-control-allow-origin')).toBe('*');
      expect(await response.json()).toMatchObject({
        issuer: h.baseUrl,
        authorization_endpoint: `${h.baseUrl}/authorize`,
        token_endpoint: `${h.baseUrl}/token`,
        registration_endpoint: `${h.baseUrl}/register`,
        code_challenge_methods_supported: ['S256'],
        client_id_metadata_document_supported: true,
        scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      });
    });

    it('serves the protected resource metadata for the MCP endpoint', async () => {
      const response = await fetch(`${h.baseUrl}/.well-known/oauth-protected-resource/mcp`);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        resource: `${h.baseUrl}/mcp`,
        authorization_servers: [h.baseUrl],
        scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      });
    });

    it('reflects the MCP endpoint path, scopes and resource name', async () => {
      const custom = await startRelay({
        mcpEndpointPath: '/api/mcp',
        scopesSupported: ['openid'],
        resourceName: 'Example MCP',
      });
      const response = await fetch(
        `${custom.baseUrl}/.well-known/oauth-protected-resource/api/mcp`
      );
      expect(await response.json()).toMatchObject({
        resource: `${custom.baseUrl}/api/mcp`,
        scopes_supported: ['openid'],
        resource_name: 'Example MCP',
      });
      expect(custom.relay.metadata.scopes_supported).toEqual(['openid']);
    });

    it('challenges unauthenticated MCP requests with the metadata URL', async () => {
      const response = await fetch(`${h.baseUrl}/mcp`, { method: 'POST' });
      expect(response.status).toBe(401);
      expect(response.headers.get('www-authenticate')).toContain(
        `resource_metadata="${h.relay.resourceMetadataUrl}"`
      );
    });
  });

  describe('registration', () => {
    it('registers clients with permissive CORS', async () => {
      const preflight = await fetch(`${h.baseUrl}/register`, {
        method: 'OPTIONS',
        headers: { origin: 'http://localhost:6274', 'access-control-request-method': 'POST' },
      });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get('access-control-allow-origin')).toBe('*');

      const registration = await registerClient(h.baseUrl, { client_name: 'Test Client' });
      expect(registration).toMatchObject({
        client_name: 'Test Client',
        token_endpoint_auth_method: 'none',
      });
    });

    it('returns OAuth errors for invalid metadata and malformed bodies', async () => {
      const invalid = await fetch(`${h.baseUrl}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ redirect_uris: ['http://evil.example/cb'] }),
      });
      expect(invalid.status).toBe(400);
      expect(await invalid.json()).toMatchObject({ error: 'invalid_redirect_uri' });

      const malformed = await fetch(`${h.baseUrl}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{not json',
      });
      expect(malformed.status).toBe(400);
      expect(await malformed.json()).toMatchObject({ error: 'invalid_request' });
    });

    it('can be disabled', async () => {
      const closed = await startRelay({ clients: { allowDynamicRegistration: false } });
      expect(closed.relay.metadata.registration_endpoint).toBeUndefined();
      const response = await fetch(`${closed.baseUrl}/register`, { method: 'POST', body: '{}' });
      expect(response.status).toBe(404);
    });
  });

  describe('authorization code flow', () => {
    it('relays the whole flow and the tokens work at the MCP endpoint', async () => {
      const result = await completeAuthorization(h, clientId);

      expect(result.state).toBe('client-state');
      expect(result.clientRedirect.origin + result.clientRedirect.pathname).toBe(CLIENT_REDIRECT);
      expect(result.clientRedirect.searchParams.get('iss')).toBe(h.baseUrl);
      expect(result.cookie).toMatch(/^mcp_relay_consent=/);

      // The identity provider saw the relay as the client and the MCP client's PKCE challenge
      const upstreamRequest = h.fake.authorizeRequests[0];
      expect(upstreamRequest?.get('client_id')).toBe(h.fake.clientId);
      expect(upstreamRequest?.get('redirect_uri')).toBe(`${h.baseUrl}/oauth/callback`);
      expect(upstreamRequest?.get('code_challenge')).toBe(result.challenge);
      expect(upstreamRequest?.get('code_challenge_method')).toBe('S256');
      expect(upstreamRequest?.get('audience')).toBe(h.fake.audience);
      expect(upstreamRequest?.get('scope')).toBe('openid profile email offline_access');
      expect(upstreamRequest?.get('state')).not.toBe('client-state');

      const tokens = await postToken(h.baseUrl, {
        grant_type: 'authorization_code',
        code: result.code,
        code_verifier: result.verifier,
        redirect_uri: CLIENT_REDIRECT,
        client_id: clientId,
      });
      expect(tokens.status).toBe(200);
      expect(tokens.headers.get('cache-control')).toBe('no-store');
      expect(tokens.body).toMatchObject({
        token_type: 'Bearer',
        access_token: expect.any(String),
        refresh_token: expect.stringMatching(/^rt-/),
        id_token: expect.any(String),
      });
      const tokenRequest = h.fake.tokenRequests[0];
      expect(tokenRequest?.params.get('code_verifier')).toBe(result.verifier);
      expect(tokenRequest?.params.get('redirect_uri')).toBe(`${h.baseUrl}/oauth/callback`);
      expect(tokenRequest?.authorization).toMatch(/^Basic /);

      const mcp = await fetch(`${h.baseUrl}/mcp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${tokens.body['access_token'] as string}` },
      });
      expect(mcp.status).toBe(200);
      expect(await mcp.json()).toEqual({ sub: 'user-123' });

      const refreshed = await postToken(h.baseUrl, {
        grant_type: 'refresh_token',
        refresh_token: tokens.body['refresh_token'] as string,
        client_id: clientId,
        scope: 'openid',
      });
      expect(refreshed.status).toBe(200);
      expect(refreshed.body['access_token']).toEqual(expect.any(String));
      expect(h.fake.tokenRequests[1]?.params.get('scope')).toBe('openid');

      // Codes are single use
      const replay = await postToken(h.baseUrl, {
        grant_type: 'authorization_code',
        code: result.code,
        code_verifier: result.verifier,
        client_id: clientId,
      });
      expect(replay.status).toBe(400);
      expect(replay.body).toMatchObject({ error: 'invalid_grant' });

      // Nothing but the registration and the consumed interaction keys were ever stored
      const keys = [...h.storedData.keys()];
      expect(keys.filter((key) => key.includes(':clients:'))).toHaveLength(1);
      expect(JSON.stringify([...h.storedData.values()])).not.toContain(tokens.body['access_token']);
    });

    it('remembers consent per client and redirect URI', async () => {
      const first = await completeAuthorization(h, clientId);
      h.fake.authorizeRequests.length = 0;

      const start = await fetch(
        authorizeUrl(h.baseUrl, {
          client_id: clientId,
          redirect_uri: CLIENT_REDIRECT,
          response_type: 'code',
          code_challenge: createPkce().challenge,
          code_challenge_method: 'S256',
        }),
        { ...noRedirect, headers: { cookie: first.cookie as string } }
      );
      expect(start.status).toBe(302);
      expect(start.headers.get('location')).toContain(`${h.fake.issuer}/authorize`);

      // A different client must be approved separately
      const other = (await registerClient(h.baseUrl))['client_id'] as string;
      const otherStart = await fetch(
        authorizeUrl(h.baseUrl, {
          client_id: other,
          redirect_uri: CLIENT_REDIRECT,
          response_type: 'code',
          code_challenge: createPkce().challenge,
          code_challenge_method: 'S256',
        }),
        { ...noRedirect, headers: { cookie: first.cookie as string } }
      );
      expect(otherStart.status).toBe(200);
      expect(await otherStart.text()).toContain('Authorize');
    });

    it('shows the client details on the consent page', async () => {
      const named = (await registerClient(h.baseUrl, { client_name: 'Shiny <Agent>' }))[
        'client_id'
      ] as string;
      const start = await fetch(
        authorizeUrl(h.baseUrl, {
          client_id: named,
          redirect_uri: CLIENT_REDIRECT,
          response_type: 'code',
          code_challenge: createPkce().challenge,
          code_challenge_method: 'S256',
          scope: 'openid',
        }),
        noRedirect
      );
      const html = await start.text();
      expect(start.headers.get('content-type')).toContain('text/html');
      expect(start.headers.get('cache-control')).toBe('no-store');
      expect(html).toContain('Shiny &lt;Agent&gt;');
      expect(html).toContain('127.0.0.1:9999');
      expect(html).toContain('runs on your computer');
      expect(html).toContain('<code>openid</code>');
    });

    it('forwards nonce, prompt and login_hint and extra upstream parameters', async () => {
      const custom = await startRelay({
        upstream: { authorizationParams: { connection: 'github' }, scopes: ['openid'] },
      });
      const customClient = (await registerClient(custom.baseUrl))['client_id'] as string;
      await completeAuthorization(custom, customClient, {
        extra: { nonce: 'n-1', prompt: 'login', login_hint: 'me@example.com' },
      });
      const request = custom.fake.authorizeRequests[0];
      expect(request?.get('nonce')).toBe('n-1');
      expect(request?.get('prompt')).toBe('login');
      expect(request?.get('login_hint')).toBe('me@example.com');
      expect(request?.get('connection')).toBe('github');
      expect(request?.get('scope')).toBe('openid');
    });

    it('returns access_denied when the user cancels', async () => {
      const result = await completeAuthorization(h, clientId, { deny: true });
      expect(result.clientRedirect.origin + result.clientRedirect.pathname).toBe(CLIENT_REDIRECT);
      expect(result.clientRedirect.searchParams.get('error')).toBe('access_denied');
      expect(result.state).toBe('client-state');
      expect(h.fake.authorizeRequests).toHaveLength(0);
    });

    it('relays identity provider errors to the client', async () => {
      h.fake.nextAuthorizeError = { error: 'login_required', error_description: 'Please log in' };
      const pkce = createPkce();
      const start = await fetch(
        authorizeUrl(h.baseUrl, {
          client_id: clientId,
          redirect_uri: CLIENT_REDIRECT,
          response_type: 'code',
          code_challenge: pkce.challenge,
          code_challenge_method: 'S256',
          state: 's',
        }),
        noRedirect
      );
      const fields = consentFields(await start.text());
      const toUpstream = await postConsent(h.baseUrl, { ...fields, decision: 'approve' });
      const fromUpstream = await fetch(toUpstream.headers.get('location') as string, noRedirect);
      const callback = await fetch(fromUpstream.headers.get('location') as string, noRedirect);
      const target = new URL(callback.headers.get('location') as string);

      expect(target.searchParams.get('error')).toBe('login_required');
      expect(target.searchParams.get('error_description')).toBe('Please log in');
      expect(target.searchParams.get('state')).toBe('s');
    });

    it('skips the consent page when disabled', async () => {
      const open = await startRelay({ consent: { enabled: false } });
      const openClient = (await registerClient(open.baseUrl))['client_id'] as string;
      const start = await fetch(
        authorizeUrl(open.baseUrl, {
          client_id: openClient,
          redirect_uri: CLIENT_REDIRECT,
          response_type: 'code',
          code_challenge: createPkce().challenge,
          code_challenge_method: 'S256',
        }),
        noRedirect
      );
      expect(start.status).toBe(302);
      expect(start.headers.get('location')).toContain(`${open.fake.issuer}/authorize`);
      expect(start.headers.get('set-cookie')).toBeNull();
    });

    it('uses a custom consent page and cookie settings', async () => {
      const custom = await startRelay({
        consent: {
          render: (view) =>
            `<html><body>custom ${view.clientName} <input name="id" value="${view.fields['id']}"><input name="csrf" value="${view.fields['csrf']}"></body></html>`,
          cookieName: 'approved',
          secret: 'static-secret',
          ttl: 60_000,
        },
        secureCookies: true,
      });
      const customClient = (await registerClient(custom.baseUrl, { client_name: 'Custom' }))[
        'client_id'
      ] as string;
      const start = await fetch(
        authorizeUrl(custom.baseUrl, {
          client_id: customClient,
          redirect_uri: CLIENT_REDIRECT,
          response_type: 'code',
          code_challenge: createPkce().challenge,
          code_challenge_method: 'S256',
        }),
        noRedirect
      );
      const html = await start.text();
      expect(html).toContain('custom Custom');
      const fields = consentFields(html);
      const approved = await postConsent(custom.baseUrl, { ...fields, decision: 'approve' });
      const cookie = approved.headers.get('set-cookie') as string;
      expect(cookie).toMatch(/^approved=/);
      expect(cookie).toContain('Max-Age=60');
      expect(cookie).toContain('Secure');
    });
  });

  describe('authorization request validation', () => {
    const base = () => ({
      client_id: clientId,
      redirect_uri: CLIENT_REDIRECT,
      response_type: 'code',
      code_challenge: createPkce().challenge,
      code_challenge_method: 'S256',
      state: 'st',
    });

    it.each([
      ['missing client_id', { client_id: undefined }, 'client_id parameter is required'],
      ['repeated client_id', { client_id: ['a', 'b'] }, 'must be a single value'],
      ['unknown client', { client_id: 'nobody' }, 'not registered'],
      [
        'unregistered redirect_uri',
        { redirect_uri: 'http://127.0.0.1:9999/other' },
        'not registered for this application',
      ],
    ])('shows an error page for %s', async (_name, overrides, text) => {
      const response = await fetch(
        authorizeUrl(h.baseUrl, { ...base(), ...overrides }),
        noRedirect
      );
      expect(response.status).toBe(400);
      expect(response.headers.get('content-type')).toContain('text/html');
      expect(await response.text()).toContain(text);
    });

    it('requires redirect_uri when several are registered', async () => {
      const multi = (
        await registerClient(h.baseUrl, {
          redirect_uris: [CLIENT_REDIRECT, 'http://127.0.0.1:9999/other'],
        })
      )['client_id'] as string;
      const response = await fetch(
        authorizeUrl(h.baseUrl, { ...base(), client_id: multi, redirect_uri: undefined }),
        noRedirect
      );
      expect(response.status).toBe(400);
      expect(await response.text()).toContain('not registered for this application');
    });

    it('accepts an omitted redirect_uri when exactly one is registered', async () => {
      // CLIENT_REDIRECT is the only registered URI for the default client
      const response = await fetch(
        authorizeUrl(h.baseUrl, { ...base(), redirect_uri: undefined }),
        noRedirect
      );
      expect(response.status).toBe(200);
    });

    it('allows any port for loopback IP redirect URIs', async () => {
      const response = await fetch(
        authorizeUrl(h.baseUrl, { ...base(), redirect_uri: 'http://127.0.0.1:1234/callback' }),
        noRedirect
      );
      expect(response.status).toBe(200);
    });

    it.each([
      ['response_type token', { response_type: 'token' }, 'unsupported_response_type'],
      ['missing code_challenge', { code_challenge: undefined }, 'invalid_request'],
      ['short code_challenge', { code_challenge: 'abc' }, 'invalid_request'],
      ['plain code_challenge_method', { code_challenge_method: 'plain' }, 'invalid_request'],
      ['missing code_challenge_method', { code_challenge_method: undefined }, 'invalid_request'],
      ['foreign resource', { resource: 'https://other.example/mcp' }, 'invalid_target'],
      ['repeated scope', { scope: ['a', 'b'] }, 'invalid_request'],
    ])('redirects an error for %s', async (_name, overrides, error) => {
      const response = await fetch(
        authorizeUrl(h.baseUrl, { ...base(), ...overrides }),
        noRedirect
      );
      expect(response.status).toBe(302);
      const target = new URL(response.headers.get('location') as string);
      expect(target.origin + target.pathname).toBe(CLIENT_REDIRECT);
      expect(target.searchParams.get('error')).toBe(error);
      expect(target.searchParams.get('state')).toBe('st');
      expect(target.searchParams.get('iss')).toBe(h.baseUrl);
    });

    it('accepts the resource with a trailing slash', async () => {
      const response = await fetch(
        authorizeUrl(h.baseUrl, { ...base(), resource: `${h.baseUrl}/mcp/` }),
        noRedirect
      );
      expect(response.status).toBe(200);
    });
  });

  describe('consent and callback edge cases', () => {
    it('rejects consent decisions with a bad or missing interaction', async () => {
      const start = await fetch(
        authorizeUrl(h.baseUrl, {
          client_id: clientId,
          redirect_uri: CLIENT_REDIRECT,
          response_type: 'code',
          code_challenge: createPkce().challenge,
          code_challenge_method: 'S256',
        }),
        noRedirect
      );
      const fields = consentFields(await start.text());

      const badCsrf = await postConsent(h.baseUrl, {
        id: fields.id,
        csrf: 'nope',
        decision: 'approve',
      });
      expect(badCsrf.status).toBe(400);
      expect(await badCsrf.text()).toContain('expired');

      const unknown = await postConsent(h.baseUrl, {
        id: 'missing',
        csrf: 'x',
        decision: 'approve',
      });
      expect(unknown.status).toBe(400);

      const empty = await postConsent(h.baseUrl, {});
      expect(empty.status).toBe(400);

      const foreign = await postConsent(
        h.baseUrl,
        { ...fields, decision: 'approve' },
        { origin: 'https://evil.example' }
      );
      expect(foreign.status).toBe(403);

      // The interaction is still usable after a rejected attempt, and consumed by a valid one
      const ok = await postConsent(h.baseUrl, { ...fields, decision: 'approve' });
      expect(ok.status).toBe(302);
      const again = await postConsent(h.baseUrl, { ...fields, decision: 'approve' });
      expect(again.status).toBe(400);
    });

    it('rejects callbacks without a known state', async () => {
      const missing = await fetch(`${h.baseUrl}/oauth/callback?code=x`, noRedirect);
      expect(missing.status).toBe(400);
      const unknown = await fetch(`${h.baseUrl}/oauth/callback?code=x&state=nope`, noRedirect);
      expect(unknown.status).toBe(400);
      expect(await unknown.text()).toContain('expired');
      const repeated = await fetch(
        `${h.baseUrl}/oauth/callback?code=x&state=a&state=b`,
        noRedirect
      );
      expect(repeated.status).toBe(400);
    });

    it('reports a callback without code or error as a server error', async () => {
      const start = await fetch(
        authorizeUrl(h.baseUrl, {
          client_id: clientId,
          redirect_uri: CLIENT_REDIRECT,
          response_type: 'code',
          code_challenge: createPkce().challenge,
          code_challenge_method: 'S256',
        }),
        noRedirect
      );
      const toUpstream = await postConsent(h.baseUrl, {
        ...consentFields(await start.text()),
        decision: 'approve',
      });
      const state = new URL(toUpstream.headers.get('location') as string).searchParams.get(
        'state'
      ) as string;

      const callback = await fetch(`${h.baseUrl}/oauth/callback?state=${state}`, noRedirect);
      expect(callback.status).toBe(302);
      expect(new URL(callback.headers.get('location') as string).searchParams.get('error')).toBe(
        'server_error'
      );

      // The state was consumed
      const second = await fetch(`${h.baseUrl}/oauth/callback?state=${state}&code=x`, noRedirect);
      expect(second.status).toBe(400);
    });

    it('uses the configured callback path', async () => {
      const custom = await startRelay({ callbackPath: '/auth/return' });
      const customClient = (await registerClient(custom.baseUrl))['client_id'] as string;
      const result = await completeAuthorization(custom, customClient);
      expect(result.code).not.toBe('');
      expect(custom.fake.authorizeRequests[0]?.get('redirect_uri')).toBe(
        `${custom.baseUrl}/auth/return`
      );
    });
  });

  describe('token endpoint', () => {
    it('answers preflight requests', async () => {
      const preflight = await fetch(`${h.baseUrl}/token`, {
        method: 'OPTIONS',
        headers: { origin: 'http://localhost:6274' },
      });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get('access-control-allow-origin')).toBe('*');
    });

    it('requires client authentication', async () => {
      const missing = await postToken(h.baseUrl, {
        grant_type: 'refresh_token',
        refresh_token: 'rt-1',
      });
      expect(missing.status).toBe(401);
      expect(missing.body).toMatchObject({ error: 'invalid_client' });
      expect(missing.headers.get('www-authenticate')).toBe('Basic realm="token"');

      const unknown = await postToken(h.baseUrl, {
        grant_type: 'refresh_token',
        refresh_token: 'rt-1',
        client_id: 'nobody',
      });
      expect(unknown.status).toBe(401);
    });

    it('authenticates confidential clients with Basic auth or the body', async () => {
      const confidential = await registerClient(h.baseUrl, {
        token_endpoint_auth_method: 'client_secret_basic',
        grant_types: ['authorization_code', 'refresh_token'],
      });
      const id = confidential['client_id'] as string;
      const secret = confidential['client_secret'] as string;
      const basic = `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')}`;

      const viaHeader = await postToken(
        h.baseUrl,
        { grant_type: 'refresh_token', refresh_token: 'rt-1' },
        { authorization: basic }
      );
      expect(viaHeader.status).toBe(200);

      const viaBody = await postToken(h.baseUrl, {
        grant_type: 'refresh_token',
        refresh_token: 'rt-1',
        client_id: id,
        client_secret: secret,
      });
      expect(viaBody.status).toBe(200);

      const wrong = await postToken(h.baseUrl, {
        grant_type: 'refresh_token',
        refresh_token: 'rt-1',
        client_id: id,
        client_secret: 'wrong',
      });
      expect(wrong.status).toBe(401);

      const mismatch = await postToken(
        h.baseUrl,
        { grant_type: 'refresh_token', refresh_token: 'rt-1', client_id: 'other' },
        { authorization: basic }
      );
      expect(mismatch.status).toBe(400);
      expect(mismatch.body).toMatchObject({ error: 'invalid_request' });

      const malformed = await postToken(
        h.baseUrl,
        { grant_type: 'refresh_token', refresh_token: 'rt-1' },
        { authorization: `Basic ${Buffer.from('no-colon').toString('base64')}` }
      );
      expect(malformed.status).toBe(401);
    });

    it('rejects bad authorization code requests', async () => {
      const result = await completeAuthorization(h, clientId);
      const other = (await registerClient(h.baseUrl))['client_id'] as string;

      const missing = await postToken(h.baseUrl, {
        grant_type: 'authorization_code',
        client_id: clientId,
        code: result.code,
      });
      expect(missing.body).toMatchObject({ error: 'invalid_request' });

      const wrongClient = await postToken(h.baseUrl, {
        grant_type: 'authorization_code',
        client_id: other,
        code: result.code,
        code_verifier: result.verifier,
      });
      expect(wrongClient.body).toMatchObject({ error: 'invalid_grant' });

      // The code was consumed by the failed attempt; start over for the redirect check
      const second = await completeAuthorization(h, clientId, { cookie: result.cookie });
      const wrongRedirect = await postToken(h.baseUrl, {
        grant_type: 'authorization_code',
        client_id: clientId,
        code: second.code,
        code_verifier: second.verifier,
        redirect_uri: 'http://127.0.0.1:9999/other',
      });
      expect(wrongRedirect.body).toMatchObject({ error: 'invalid_grant' });

      const third = await completeAuthorization(h, clientId, { cookie: result.cookie });
      const wrongVerifier = await postToken(h.baseUrl, {
        grant_type: 'authorization_code',
        client_id: clientId,
        code: third.code,
        code_verifier: 'not-the-verifier-not-the-verifier-not-the-verifier',
      });
      expect(wrongVerifier.status).toBe(400);
      expect(wrongVerifier.body).toMatchObject({
        error: 'invalid_grant',
        error_description: 'bad code or verifier',
      });
    });

    it('rejects other grant types and refresh tokens the client may not use', async () => {
      const unsupported = await postToken(h.baseUrl, {
        grant_type: 'client_credentials',
        client_id: clientId,
      });
      expect(unsupported.status).toBe(400);
      expect(unsupported.body).toMatchObject({ error: 'unsupported_grant_type' });
      expect(h.fake.tokenRequests).toHaveLength(0);

      const noGrant = await postToken(h.baseUrl, { client_id: clientId });
      expect(noGrant.body).toMatchObject({ error: 'unsupported_grant_type' });

      const missingToken = await postToken(h.baseUrl, {
        grant_type: 'refresh_token',
        client_id: clientId,
      });
      expect(missingToken.body).toMatchObject({ error: 'invalid_request' });

      const limited = (await registerClient(h.baseUrl, { grant_types: ['authorization_code'] }))[
        'client_id'
      ] as string;
      const denied = await postToken(h.baseUrl, {
        grant_type: 'refresh_token',
        refresh_token: 'rt-1',
        client_id: limited,
      });
      expect(denied.body).toMatchObject({ error: 'unauthorized_client' });
    });

    it('maps unexpected identity provider responses to 502', async () => {
      h.fake.nextTokenResponse = { status: 503, body: { error: 'temporarily_unavailable' } };
      const down = await postToken(h.baseUrl, {
        grant_type: 'refresh_token',
        refresh_token: 'rt-1',
        client_id: clientId,
      });
      expect(down.status).toBe(502);
      expect(down.body).toMatchObject({ error: 'temporarily_unavailable' });

      h.fake.nextTokenResponse = { status: 403, body: { error: 'access_denied' } };
      const forbidden = await postToken(h.baseUrl, {
        grant_type: 'refresh_token',
        refresh_token: 'rt-1',
        client_id: clientId,
      });
      expect(forbidden.status).toBe(502);
      expect(forbidden.body).toMatchObject({ error: 'server_error' });

      h.fake.nextTokenResponse = { status: 400, body: 'plain text' };
      const notJson = await postToken(h.baseUrl, {
        grant_type: 'refresh_token',
        refresh_token: 'rt-1',
        client_id: clientId,
      });
      expect(notJson.status).toBe(500);
      expect(notJson.body).toMatchObject({ error: 'server_error' });
    });

    it('rejects malformed bodies', async () => {
      const response = await fetch(`${h.baseUrl}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'x'.repeat(70 * 1024),
      });
      expect(response.status).toBe(413);
      expect(await response.json()).toMatchObject({ error: 'invalid_request' });
    });
  });

  describe('client ID metadata documents', () => {
    it('accepts a metadata document client end to end', async () => {
      const cimdId = 'https://client.example/mcp/metadata.json';
      const fetchImpl: typeof fetch = (input, init) =>
        String(input) === cimdId
          ? Promise.resolve(
              new Response(
                JSON.stringify({
                  client_id: cimdId,
                  client_name: 'Doc Client',
                  redirect_uris: [CLIENT_REDIRECT],
                  grant_types: ['authorization_code', 'refresh_token'],
                }),
                { headers: { 'content-type': 'application/json' } }
              )
            )
          : fetch(input, init);
      const cimd = await startRelay({
        fetch: fetchImpl,
        clients: { cimdAllowedHosts: ['client.example'] },
      });

      const result = await completeAuthorization(cimd, cimdId);
      const tokens = await postToken(cimd.baseUrl, {
        grant_type: 'authorization_code',
        code: result.code,
        code_verifier: result.verifier,
        client_id: cimdId,
      });
      expect(tokens.status).toBe(200);
      expect(tokens.body['access_token']).toEqual(expect.any(String));
    });
  });

  describe('onTokenResponse', () => {
    const exchange = async (harness: Harness, id: string) => {
      const result = await completeAuthorization(harness, id, { extra: { nonce: 'n-42' } });
      return postToken(harness.baseUrl, {
        grant_type: 'authorization_code',
        code: result.code,
        code_verifier: result.verifier,
        client_id: id,
      });
    };

    it('reports verified ID and access token claims for code and refresh grants', async () => {
      const onTokenResponse = vi.fn();
      const custom = await startRelay({ onTokenResponse });
      const id = (await registerClient(custom.baseUrl))['client_id'] as string;

      const tokens = await exchange(custom, id);
      expect(tokens.status).toBe(200);
      expect(onTokenResponse).toHaveBeenCalledTimes(1);
      expect(onTokenResponse.mock.calls[0]?.[0]).toEqual({
        grantType: 'authorization_code',
        clientId: id,
        idTokenClaims: expect.objectContaining({
          sub: 'user-123',
          email: 'user@example.com',
          nonce: 'n-42',
          aud: custom.fake.clientId,
        }),
        accessTokenClaims: expect.objectContaining({
          sub: 'user-123',
          aud: [custom.fake.audience],
        }),
        expiresAt: expect.any(Number),
        scope: 'openid profile email offline_access',
      });

      await postToken(custom.baseUrl, {
        grant_type: 'refresh_token',
        refresh_token: tokens.body['refresh_token'] as string,
        client_id: id,
      });
      expect(onTokenResponse).toHaveBeenCalledTimes(2);
      expect(onTokenResponse.mock.calls[1]?.[0]).toMatchObject({
        grantType: 'refresh_token',
        clientId: id,
        idTokenClaims: expect.objectContaining({ sub: 'user-123' }),
      });
    });

    it('is not called for failed token requests', async () => {
      const onTokenResponse = vi.fn();
      const custom = await startRelay({ onTokenResponse });
      const id = (await registerClient(custom.baseUrl))['client_id'] as string;
      await postToken(custom.baseUrl, {
        grant_type: 'refresh_token',
        refresh_token: 'bad',
        client_id: id,
      });
      expect(onTokenResponse).not.toHaveBeenCalled();
    });

    it('does not fail the token response when the hook rejects', async () => {
      const custom = await startRelay({
        onTokenResponse: () => Promise.reject(new Error('store down')),
      });
      const id = (await registerClient(custom.baseUrl))['client_id'] as string;
      const tokens = await exchange(custom, id);
      expect(tokens.status).toBe(200);
      expect(tokens.body['access_token']).toEqual(expect.any(String));
    });

    it('verifies HS256 ID tokens with the client secret', async () => {
      const onTokenResponse = vi.fn();
      const fake = await startFakeUpstream({
        idTokenAlg: 'HS256',
        idTokenClaims: { 'https://example/orgs': ['o1'] },
      });
      const custom = await startRelay({ onTokenResponse }, fake);
      const id = (await registerClient(custom.baseUrl))['client_id'] as string;
      await exchange(custom, id);
      expect(onTokenResponse.mock.calls[0]?.[0]).toMatchObject({
        idTokenClaims: expect.objectContaining({ 'https://example/orgs': ['o1'] }),
      });
    });

    it('omits claims it cannot verify and derives expiry from expires_in', async () => {
      const onTokenResponse = vi.fn();
      const custom = await startRelay({ onTokenResponse });
      const id = (await registerClient(custom.baseUrl))['client_id'] as string;
      custom.fake.nextTokenResponse = {
        status: 200,
        body: {
          access_token: 'opaque-token',
          id_token: 'not.a.jwt',
          token_type: 'Bearer',
          expires_in: 600,
        },
      };
      const tokens = await postToken(custom.baseUrl, {
        grant_type: 'refresh_token',
        refresh_token: 'rt-1',
        client_id: id,
      });
      expect(tokens.status).toBe(200);
      const event = onTokenResponse.mock.calls[0]?.[0];
      expect(event).toEqual({
        grantType: 'refresh_token',
        clientId: id,
        expiresAt: expect.any(Number),
      });
      expect(event.expiresAt).toBeGreaterThan(Date.now() / 1000 + 590);

      custom.fake.nextTokenResponse = {
        status: 200,
        body: { access_token: 'opaque', token_type: 'Bearer' },
      };
      await postToken(custom.baseUrl, {
        grant_type: 'refresh_token',
        refresh_token: 'rt-1',
        client_id: id,
      });
      expect(onTokenResponse.mock.calls[1]?.[0]).toEqual({
        grantType: 'refresh_token',
        clientId: id,
      });
    });
  });

  describe('verifier', () => {
    it('passes customData through', async () => {
      const custom = await startRelay({
        customData: ({ claims }) => ({ email: claims['email'] }),
      });
      const auth = await custom.relay.verifier.verifyAccessToken(
        await custom.fake.signToken({ email: 'a@example.com' })
      );
      expect(auth.extra?.['customData']).toEqual({ email: 'a@example.com' });
    });

    it('reports verification errors through onVerifyError', async () => {
      const onVerifyError = vi.fn();
      const custom = await startRelay({ onVerifyError });
      await expect(custom.relay.verifier.verifyAccessToken('bad')).rejects.toThrow();
      expect(onVerifyError).toHaveBeenCalledTimes(1);
    });
  });
});
