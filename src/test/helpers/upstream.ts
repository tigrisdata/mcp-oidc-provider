/**
 * A fake OpenID Connect provider for tests: discovery, an authorization
 * endpoint that issues codes without a login page, a PKCE-checking token
 * endpoint, JWKS and UserInfo.
 */

import { createHash, randomBytes } from 'node:crypto';
import express from 'express';
import { SignJWT, exportJWK, generateKeyPair, type JWTPayload } from 'jose';
import {
  TEST_AUDIENCE,
  TEST_EMAIL,
  TEST_UPSTREAM_CLIENT_ID,
  TEST_UPSTREAM_CLIENT_SECRET,
  TEST_USER_ID,
} from '../constants.js';
import { listen } from './server.js';

export interface FakeUpstreamOptions {
  clientId?: string;
  clientSecret?: string;
  audience?: string;
  /** Access token lifetime in seconds. Default: 900 */
  tokenTtl?: number;
  /** Extra claims put into every access token. */
  accessTokenClaims?: Record<string, unknown>;
  /** Extra claims put into every ID token. */
  idTokenClaims?: Record<string, unknown>;
  /** UserInfo response body (merged over `sub` and `email`). */
  userinfo?: Record<string, unknown>;
  /** Leave `userinfo_endpoint` out of the metadata. */
  withoutUserinfo?: boolean;
  /** Sign ID tokens with HS256 and the client secret instead of RS256. */
  idTokenAlg?: 'RS256' | 'HS256';
}

export interface CapturedTokenRequest {
  params: URLSearchParams;
  authorization: string | undefined;
}

export interface FakeUpstream {
  issuer: string;
  clientId: string;
  clientSecret: string;
  audience: string;
  metadata: Record<string, unknown>;
  /** Query parameters of every authorization request received. */
  authorizeRequests: URLSearchParams[];
  /** Body and Authorization header of every token request received. */
  tokenRequests: CapturedTokenRequest[];
  /** Number of UserInfo requests received. */
  userinfoRequests: number;
  /** Respond to the next authorization request with this error instead of a code. */
  nextAuthorizeError: { error: string; error_description?: string } | undefined;
  /** Respond to the next token request with this instead of the normal response. */
  nextTokenResponse: { status: number; body: unknown } | undefined;
  /** Sign a JWT with the provider's key; defaults make it a valid access token. */
  signToken(claims?: JWTPayload, options?: { omitExpiry?: boolean }): Promise<string>;
}

/** PKCE pair for tests. */
export function createPkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

export async function startFakeUpstream(options: FakeUpstreamOptions = {}): Promise<FakeUpstream> {
  const clientId = options.clientId ?? TEST_UPSTREAM_CLIENT_ID;
  const clientSecret = options.clientSecret ?? TEST_UPSTREAM_CLIENT_SECRET;
  const audience = options.audience ?? TEST_AUDIENCE;
  const tokenTtl = options.tokenTtl ?? 900;
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' };
  const codes = new Map<string, { codeChallenge: string; redirectUri: string; nonce?: string }>();

  const app = express();
  const metadata: Record<string, unknown> = {};
  const upstream: FakeUpstream = {
    issuer: '',
    clientId,
    clientSecret,
    audience,
    metadata,
    authorizeRequests: [],
    tokenRequests: [],
    userinfoRequests: 0,
    nextAuthorizeError: undefined,
    nextTokenResponse: undefined,
    signToken: (claims = {}, signOptions = {}) => {
      const jwt = new SignJWT({
        aud: [audience],
        azp: clientId,
        scope: 'openid profile email offline_access',
        ...options.accessTokenClaims,
        ...claims,
      })
        .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
        .setIssuer(upstream.issuer)
        .setSubject(claims.sub ?? TEST_USER_ID)
        .setIssuedAt();
      if (!signOptions.omitExpiry) {
        jwt.setExpirationTime(claims.exp ?? Math.floor(Date.now() / 1000) + tokenTtl);
      }
      return jwt.sign(privateKey);
    },
  };

  const issueTokens = async (nonce?: string): Promise<Record<string, unknown>> => ({
    access_token: await upstream.signToken(),
    id_token: await new SignJWT({
      email: TEST_EMAIL,
      ...options.idTokenClaims,
      ...(nonce ? { nonce } : {}),
    })
      .setProtectedHeader(
        options.idTokenAlg === 'HS256' ? { alg: 'HS256' } : { alg: 'RS256', kid: 'test-key' }
      )
      .setIssuer(upstream.issuer)
      .setAudience(clientId)
      .setSubject(TEST_USER_ID)
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + tokenTtl)
      .sign(options.idTokenAlg === 'HS256' ? new TextEncoder().encode(clientSecret) : privateKey),
    refresh_token: `rt-${randomBytes(8).toString('hex')}`,
    token_type: 'Bearer',
    expires_in: tokenTtl,
    scope: 'openid profile email offline_access',
  });

  app.get('/.well-known/openid-configuration', (_req, res) => {
    res.json(metadata);
  });

  app.get('/.well-known/jwks.json', (_req, res) => {
    res.json({ keys: [jwk] });
  });

  app.get('/authorize', (req, res) => {
    const params = new URLSearchParams(req.query as Record<string, string>);
    upstream.authorizeRequests.push(params);
    const redirectUri = params.get('redirect_uri') ?? '';
    const target = new URL(redirectUri);
    const state = params.get('state');
    if (state) target.searchParams.set('state', state);
    if (upstream.nextAuthorizeError) {
      target.searchParams.set('error', upstream.nextAuthorizeError.error);
      if (upstream.nextAuthorizeError.error_description) {
        target.searchParams.set('error_description', upstream.nextAuthorizeError.error_description);
      }
      upstream.nextAuthorizeError = undefined;
      res.redirect(302, target.toString());
      return;
    }
    if (params.get('client_id') !== clientId) {
      res.status(400).send('unknown client');
      return;
    }
    const code = `code-${randomBytes(8).toString('hex')}`;
    codes.set(code, {
      codeChallenge: params.get('code_challenge') ?? '',
      redirectUri,
      nonce: params.get('nonce') ?? undefined,
    });
    target.searchParams.set('code', code);
    res.redirect(302, target.toString());
  });

  app.post('/oauth/token', express.urlencoded({ extended: false }), async (req, res) => {
    const params = new URLSearchParams(req.body as Record<string, string>);
    const authorization = req.headers.authorization;
    upstream.tokenRequests.push({ params, authorization });

    let authenticated = false;
    if (authorization?.startsWith('Basic ')) {
      const [id, secret] = Buffer.from(authorization.slice(6), 'base64').toString().split(':');
      authenticated =
        decodeURIComponent(id ?? '') === clientId &&
        decodeURIComponent(secret ?? '') === clientSecret;
    } else {
      authenticated =
        params.get('client_id') === clientId && params.get('client_secret') === clientSecret;
    }
    if (!authenticated) {
      res.status(401).json({ error: 'invalid_client' });
      return;
    }
    if (upstream.nextTokenResponse) {
      const { status, body } = upstream.nextTokenResponse;
      upstream.nextTokenResponse = undefined;
      res.status(status).send(body);
      return;
    }

    const grantType = params.get('grant_type');
    if (grantType === 'authorization_code') {
      const code = params.get('code') ?? '';
      const record = codes.get(code);
      codes.delete(code);
      const verifier = params.get('code_verifier') ?? '';
      const challenge = createHash('sha256').update(verifier).digest('base64url');
      if (
        !record ||
        record.redirectUri !== params.get('redirect_uri') ||
        record.codeChallenge !== challenge
      ) {
        res.status(400).json({ error: 'invalid_grant', error_description: 'bad code or verifier' });
        return;
      }
      res.json(await issueTokens(record.nonce));
      return;
    }
    if (grantType === 'refresh_token') {
      if (!params.get('refresh_token')?.startsWith('rt-')) {
        res
          .status(400)
          .json({ error: 'invalid_grant', error_description: 'unknown refresh token' });
        return;
      }
      res.json(await issueTokens());
      return;
    }
    res.status(400).json({ error: 'unsupported_grant_type' });
  });

  app.get('/userinfo', (req, res) => {
    upstream.userinfoRequests += 1;
    if (!req.headers.authorization?.startsWith('Bearer ')) {
      res.status(401).json({ error: 'invalid_token' });
      return;
    }
    res.json({ sub: TEST_USER_ID, email: TEST_EMAIL, ...options.userinfo });
  });

  upstream.issuer = await listen(app);
  Object.assign(metadata, {
    issuer: upstream.issuer,
    authorization_endpoint: `${upstream.issuer}/authorize`,
    token_endpoint: `${upstream.issuer}/oauth/token`,
    jwks_uri: `${upstream.issuer}/.well-known/jwks.json`,
    ...(options.withoutUserinfo ? {} : { userinfo_endpoint: `${upstream.issuer}/userinfo` }),
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
  });
  return upstream;
}
