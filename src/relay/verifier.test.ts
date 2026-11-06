import { describe, it, expect, vi, beforeEach } from 'vitest';
import { OAuthError } from '@modelcontextprotocol/server';
import { startFakeUpstream, type FakeUpstream } from '../test/helpers/index.js';
import { noopLogger } from '../utils/logger.js';
import type { CustomDataFn } from '../types.js';
import { Upstream } from './upstream.js';
import { clientIdFromClaims, createVerifier, scopesFromClaims } from './verifier.js';

const RESOURCE = new URL('http://localhost:3000/mcp');
const RESOURCE_METADATA_URL = 'http://localhost:3000/.well-known/oauth-protected-resource/mcp';

describe('verifier', () => {
  let fake: FakeUpstream;
  let onVerifyError: ReturnType<typeof vi.fn>;

  const createUpstream = (issuer = fake.issuer) =>
    new Upstream(
      { issuer, clientId: fake.clientId, clientSecret: fake.clientSecret, audience: fake.audience },
      { fetch, logger: noopLogger }
    );

  const create = (customData?: CustomDataFn, audience = fake.audience) =>
    createVerifier({
      upstream: createUpstream(),
      audience,
      resource: RESOURCE,
      resourceMetadataUrl: RESOURCE_METADATA_URL,
      customData,
      onVerifyError: onVerifyError as (error: unknown) => void,
      logger: noopLogger,
    });

  const expectRejected = async (promise: Promise<unknown>) => {
    await expect(promise).rejects.toBeInstanceOf(OAuthError);
    await expect(promise).rejects.toThrow('Invalid or expired token');
    expect(onVerifyError).toHaveBeenCalled();
  };

  beforeEach(async () => {
    fake = await startFakeUpstream();
    onVerifyError = vi.fn();
  });

  it('extracts scopes and client ids from claims', () => {
    expect(scopesFromClaims({ scope: 'a b  c' })).toEqual(['a', 'b', 'c']);
    expect(scopesFromClaims({ scp: ['a', 1, 'b'] })).toEqual(['a', 'b']);
    expect(scopesFromClaims({})).toEqual([]);
    expect(clientIdFromClaims({ azp: 'azp-1', client_id: 'c-1' })).toBe('azp-1');
    expect(clientIdFromClaims({ client_id: 'c-1' })).toBe('c-1');
    expect(clientIdFromClaims({})).toBe('');
  });

  it('accepts a valid access token', async () => {
    const token = await fake.signToken({ scope: 'openid email' });

    const auth = await create().verifyAccessToken(token);

    expect(auth).toEqual({
      token,
      clientId: fake.clientId,
      scopes: ['openid', 'email'],
      expiresAt: expect.any(Number),
      resource: RESOURCE,
      resourceMetadataUrl: RESOURCE_METADATA_URL,
      extra: {
        sub: 'user-123',
        claims: expect.objectContaining({
          sub: 'user-123',
          iss: fake.issuer,
          aud: [fake.audience],
        }),
      },
    });
    expect(onVerifyError).not.toHaveBeenCalled();
  });

  it('rejects expired tokens', async () => {
    const token = await fake.signToken({ exp: Math.floor(Date.now() / 1000) - 120 });
    await expectRejected(create().verifyAccessToken(token));
  });

  it('rejects tokens for another audience', async () => {
    const token = await fake.signToken({ aud: ['https://other-api.example'] });
    await expectRejected(create().verifyAccessToken(token));
    await expectRejected(
      create(undefined, 'https://expected.example').verifyAccessToken(await fake.signToken())
    );
  });

  it('rejects tokens from another issuer', async () => {
    const other = await startFakeUpstream();
    const token = await other.signToken();
    await expectRejected(create().verifyAccessToken(token));
  });

  it('rejects tokens without an expiry, tampered or malformed tokens', async () => {
    const verifier = create();
    const valid = await fake.signToken();
    const [header, payload] = valid.split('.');
    await expectRejected(verifier.verifyAccessToken(`${header}.${payload}.AAAA`));
    await expectRejected(verifier.verifyAccessToken('not-a-jwt'));
    await expectRejected(verifier.verifyAccessToken(''));

    const noExp = await fake.signToken({}, { omitExpiry: true });
    await expectRejected(verifier.verifyAccessToken(noExp));
  });

  describe('customData', () => {
    it('receives the claims and token and lands in extra', async () => {
      const token = await fake.signToken({ 'https://example/orgs': ['org-1'] });
      const customData = vi.fn(({ claims }) => ({ orgs: claims['https://example/orgs'] }));

      const auth = await create(customData).verifyAccessToken(token);

      expect(auth.extra?.['customData']).toEqual({ orgs: ['org-1'] });
      expect(customData).toHaveBeenCalledWith(
        expect.objectContaining({ token, claims: expect.objectContaining({ sub: 'user-123' }) })
      );
    });

    it('fetches UserInfo once per token', async () => {
      const verifier = create(async ({ userinfo }) => ({ profile: await userinfo() }));
      const token = await fake.signToken();

      const first = await verifier.verifyAccessToken(token);
      const second = await verifier.verifyAccessToken(token);
      await verifier.verifyAccessToken(await fake.signToken({ sub: 'user-456' }));

      expect(first.extra?.['customData']).toEqual({
        profile: { sub: 'user-123', email: 'user@example.com' },
      });
      expect(second.extra?.['customData']).toEqual(first.extra?.['customData']);
      expect(fake.userinfoRequests).toBe(2);
    });

    it('retries UserInfo after a failure', async () => {
      const upstream = createUpstream();
      const userinfoSpy = vi
        .spyOn(upstream, 'userinfo')
        .mockRejectedValueOnce(new Error('HTTP 429'))
        .mockResolvedValueOnce({ sub: 'user-123' });
      const verifier = createVerifier({
        upstream,
        audience: fake.audience,
        resource: RESOURCE,
        resourceMetadataUrl: RESOURCE_METADATA_URL,
        customData: async ({ userinfo }) => ({ profile: await userinfo() }),
        onVerifyError: onVerifyError as (error: unknown) => void,
        logger: noopLogger,
      });
      const token = await fake.signToken();

      await expectRejected(verifier.verifyAccessToken(token));
      await expect(verifier.verifyAccessToken(token)).resolves.toMatchObject({
        extra: { customData: { profile: { sub: 'user-123' } } },
      });
      expect(userinfoSpy).toHaveBeenCalledTimes(2);
    });

    it('treats a failing customData function as an invalid token', async () => {
      const verifier = create(() => {
        throw new Error('lookup failed');
      });
      await expectRejected(verifier.verifyAccessToken(await fake.signToken()));
      expect(onVerifyError).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'lookup failed' })
      );
    });
  });
});
