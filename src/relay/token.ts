/**
 * The token endpoint: authenticates the MCP client, then relays the grant to
 * the identity provider with the relay's own credentials.
 * @internal
 */

import type { Request, RequestHandler } from 'express';
import type { Keyv } from 'keyv';
import type { TokenResponseEvent, TokenResponseHook } from '../types.js';
import type { Logger } from '../utils/logger.js';
import type { PendingRecord } from './authorize.js';
import { stringParam, wrap } from './authorize.js';
import type { ClientRegistry } from './clients.js';
import { OAuthRequestError, sendOAuthError } from './errors.js';
import type { Upstream } from './upstream.js';

export interface TokenDeps {
  issuer: string;
  callbackPath: string;
  upstream: Upstream;
  clients: ClientRegistry;
  pending: Keyv<PendingRecord>;
  /** Required `aud` of access tokens, for `accessTokenClaims` in hook events. */
  upstreamAudience: string;
  onTokenResponse?: TokenResponseHook;
  logger: Logger;
}

/** Client credentials from HTTP Basic auth (RFC 6749 section 2.3.1) or the form body. */
export function clientCredentials(req: Request): {
  clientId: string | undefined;
  clientSecret: string | undefined;
} {
  const header = req.headers.authorization;
  if (header?.toLowerCase().startsWith('basic ')) {
    const decoded = Buffer.from(header.slice(6).trim(), 'base64').toString();
    const index = decoded.indexOf(':');
    if (index === -1) {
      throw new OAuthRequestError('invalid_client', 'Malformed Authorization header', 401);
    }
    const decode = (value: string): string => {
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    };
    const clientId = decode(decoded.slice(0, index));
    const bodyClientId = stringParam(req.body, 'client_id');
    if (bodyClientId !== undefined && bodyClientId !== clientId) {
      throw new OAuthRequestError(
        'invalid_request',
        'client_id does not match the Authorization header'
      );
    }
    return { clientId, clientSecret: decode(decoded.slice(index + 1)) };
  }
  return {
    clientId: stringParam(req.body, 'client_id'),
    clientSecret: stringParam(req.body, 'client_secret'),
  };
}

export function createTokenHandler(deps: TokenDeps): RequestHandler {
  const { upstream, clients, pending, logger } = deps;
  const callbackUrl = `${deps.issuer}${deps.callbackPath}`;

  /** Verify the tokens in a response and hand their claims to the hook. */
  const notifyTokenResponse = async (
    grantType: TokenResponseEvent['grantType'],
    clientId: string,
    body: Record<string, unknown>
  ): Promise<void> => {
    if (!deps.onTokenResponse) return;
    const idToken = typeof body['id_token'] === 'string' ? body['id_token'] : undefined;
    const accessToken = typeof body['access_token'] === 'string' ? body['access_token'] : undefined;
    const warn = (what: string) => (error: unknown) => {
      logger.warn(`Could not verify the ${what} in the token response`, {
        error: error instanceof Error ? error.message : String(error),
      });
      return undefined;
    };
    const [idTokenClaims, accessTokenClaims] = await Promise.all([
      idToken
        ? upstream
            .verifyToken(idToken, { audience: upstream.clientId, allowClientSecret: true })
            .catch(warn('ID token'))
        : undefined,
      accessToken
        ? upstream
            .verifyToken(accessToken, { audience: deps.upstreamAudience })
            .catch(() => undefined)
        : undefined,
    ]);
    const expiresIn = typeof body['expires_in'] === 'number' ? body['expires_in'] : undefined;
    const event: TokenResponseEvent = { grantType, clientId };
    if (idTokenClaims) event.idTokenClaims = idTokenClaims;
    if (accessTokenClaims) event.accessTokenClaims = accessTokenClaims;
    const expiresAt =
      accessTokenClaims?.exp ??
      (expiresIn !== undefined ? Math.floor(Date.now() / 1000) + expiresIn : undefined);
    if (expiresAt !== undefined) event.expiresAt = expiresAt;
    if (typeof body['scope'] === 'string') event.scope = body['scope'];
    try {
      await deps.onTokenResponse(event);
    } catch (error) {
      logger.error('onTokenResponse hook failed', error);
    }
  };

  return wrap(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    try {
      const { clientId, clientSecret } = clientCredentials(req);
      const client = await clients.authenticate(clientId, clientSecret);
      const grantType = stringParam(req.body, 'grant_type');

      let params: Record<string, string>;
      if (grantType === 'authorization_code') {
        const code = stringParam(req.body, 'code');
        const codeVerifier = stringParam(req.body, 'code_verifier');
        const redirectUri = stringParam(req.body, 'redirect_uri');
        if (!code || !codeVerifier) {
          throw new OAuthRequestError('invalid_request', 'code and code_verifier are required');
        }
        const record = await pending.get(`code:${code}`);
        if (record) await pending.delete(`code:${code}`);
        if (
          !record ||
          !('upstreamCode' in record) ||
          !record.upstreamCode ||
          record.clientId !== client.client_id ||
          (redirectUri !== undefined && redirectUri !== record.redirectUri)
        ) {
          throw new OAuthRequestError(
            'invalid_grant',
            'Invalid, expired or already used authorization code'
          );
        }
        params = {
          grant_type: 'authorization_code',
          code: record.upstreamCode,
          redirect_uri: callbackUrl,
          code_verifier: codeVerifier,
        };
      } else if (grantType === 'refresh_token') {
        const refreshToken = stringParam(req.body, 'refresh_token');
        if (!refreshToken) {
          throw new OAuthRequestError('invalid_request', 'refresh_token is required');
        }
        if (!client.grant_types.includes('refresh_token')) {
          throw new OAuthRequestError(
            'unauthorized_client',
            'This client may not use refresh tokens'
          );
        }
        params = { grant_type: 'refresh_token', refresh_token: refreshToken };
        const scope = stringParam(req.body, 'scope');
        if (scope) params['scope'] = scope;
      } else {
        throw new OAuthRequestError(
          'unsupported_grant_type',
          'grant_type must be authorization_code or refresh_token'
        );
      }

      const response = await upstream.token(params);
      if (response.status >= 200 && response.status < 300) {
        logger.info('Relayed token response', { clientId: client.client_id, grantType });
        await notifyTokenResponse(grantType, client.client_id, response.body);
        res.status(200).json(response.body);
        return;
      }
      if (response.status === 400 && typeof response.body['error'] === 'string') {
        logger.info('Identity provider rejected the token request', {
          clientId: client.client_id,
          grantType,
          error: response.body['error'],
        });
        res.status(400).json(response.body);
        return;
      }
      logger.error('Unexpected response from the identity provider token endpoint', {
        status: response.status,
        error: response.body['error'],
      });
      throw new OAuthRequestError(
        response.status >= 500 ? 'temporarily_unavailable' : 'server_error',
        'The identity provider could not complete the request',
        502
      );
    } catch (error) {
      if (error instanceof OAuthRequestError) {
        sendOAuthError(res, error);
        return;
      }
      throw error;
    }
  });
}
