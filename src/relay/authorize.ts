/**
 * The authorization endpoint, consent decision and identity provider callback.
 * @internal
 */

import type { Request, RequestHandler, Response } from 'express';
import type { Keyv } from 'keyv';
import type { Logger } from '../utils/logger.js';
import type { ClientRegistry, RegisteredClient } from './clients.js';
import { isLoopbackHost, redirectUriMatches } from './clients.js';
import type { ConsentStore } from './consent.js';
import { OAuthRequestError, errorRedirectUrl, toOAuthError } from './errors.js';
import { renderErrorPage, type ConsentView } from './html.js';
import { RELAY_ROUTES } from './metadata.js';
import { randomId, safeEqual } from './storage.js';
import { stripTrailingSlash, type Upstream } from './upstream.js';

/** An authorization request accepted from an MCP client. */
export interface PendingAuthorization {
  clientId: string;
  clientName: string;
  redirectUri: string;
  state?: string;
  scope?: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  resource?: string;
  nonce?: string;
  prompt?: string;
  loginHint?: string;
  createdAt: number;
  /** Set once the identity provider has issued its code. */
  upstreamCode?: string;
}

/** A consent page waiting for the user's decision. */
export interface ConsentInteraction {
  request: PendingAuthorization;
  csrf: string;
}

export type PendingRecord = PendingAuthorization | ConsentInteraction;

/** How long an authorization request may take end to end. */
export const PENDING_AUTHORIZATION_TTL = 10 * 60 * 1000;
/** How long the MCP client has to redeem a relay authorization code. */
export const AUTHORIZATION_CODE_TTL = 5 * 60 * 1000;

const CODE_CHALLENGE_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;

export interface AuthorizeDeps {
  issuer: string;
  callbackPath: string;
  upstream: Upstream;
  clients: ClientRegistry;
  /** `undefined` when consent is disabled. */
  consent: ConsentStore | undefined;
  renderConsent: (view: ConsentView) => string;
  pending: Keyv<PendingRecord>;
  resource: URL;
  resourceName: string | undefined;
  upstreamAudience: string;
  upstreamAuthorizationParams: Record<string, string>;
  logger: Logger;
}

/** Run an async handler, routing rejections to Express error handling (Express 4 and 5). */
export function wrap(
  handler: (req: Request, res: Response) => Promise<void> | void
): RequestHandler {
  return (req, res, next) => {
    Promise.resolve(handler(req, res)).catch(next);
  };
}

/** A query or form value that must be a single string. */
export function stringParam(source: unknown, name: string): string | undefined {
  const value = (source as Record<string, unknown> | undefined)?.[name];
  if (value === undefined) return undefined;
  if (typeof value !== 'string') {
    throw new OAuthRequestError('invalid_request', `${name} must be a single value`);
  }
  return value;
}

function sendErrorPage(res: Response, status: number, title: string, description: string): void {
  res.setHeader('Cache-Control', 'no-store');
  res.status(status).type('html').send(renderErrorPage(title, description));
}

export function createAuthorizeHandlers(deps: AuthorizeDeps): {
  authorize: RequestHandler;
  consent: RequestHandler;
  callback: RequestHandler;
} {
  const { issuer, upstream, clients, pending, logger } = deps;
  const callbackUrl = `${issuer}${deps.callbackPath}`;
  const resourceId = stripTrailingSlash(deps.resource.toString());

  const redirectToClient = (
    res: Response,
    request: Pick<PendingAuthorization, 'redirectUri' | 'state'>,
    error: OAuthRequestError
  ): void => {
    res.setHeader('Cache-Control', 'no-store');
    res.redirect(302, errorRedirectUrl(request.redirectUri, error, request.state, issuer));
  };

  /** Hand the user to the identity provider with the client's PKCE challenge. */
  const startUpstreamAuthorization = async (
    res: Response,
    request: PendingAuthorization
  ): Promise<void> => {
    const state = randomId();
    await pending.set(`state:${state}`, request, PENDING_AUTHORIZATION_TTL);
    const params: Record<string, string> = {
      response_type: 'code',
      redirect_uri: callbackUrl,
      scope: upstream.scopes.join(' '),
      state,
      code_challenge: request.codeChallenge,
      code_challenge_method: request.codeChallengeMethod,
      audience: deps.upstreamAudience,
      ...deps.upstreamAuthorizationParams,
    };
    if (request.nonce) params['nonce'] = request.nonce;
    if (request.prompt) params['prompt'] = request.prompt;
    if (request.loginHint) params['login_hint'] = request.loginHint;
    logger.info('Forwarding authorization request to the identity provider', {
      clientId: request.clientId,
      redirectUri: request.redirectUri,
    });
    res.setHeader('Cache-Control', 'no-store');
    res.redirect(302, await upstream.authorizationUrl(params));
  };

  /** Validate the parameters that are only checked after the client and redirect URI are known. */
  const parseAuthorizationRequest = (
    query: unknown,
    client: RegisteredClient,
    redirectUri: string
  ): PendingAuthorization => {
    if (stringParam(query, 'response_type') !== 'code') {
      throw new OAuthRequestError('unsupported_response_type', 'response_type must be code');
    }
    const codeChallenge = stringParam(query, 'code_challenge');
    if (!codeChallenge || !CODE_CHALLENGE_PATTERN.test(codeChallenge)) {
      throw new OAuthRequestError('invalid_request', 'A valid code_challenge is required (PKCE)');
    }
    if (stringParam(query, 'code_challenge_method') !== 'S256') {
      throw new OAuthRequestError('invalid_request', 'code_challenge_method must be S256');
    }
    const resource = stringParam(query, 'resource');
    if (resource !== undefined && stripTrailingSlash(resource) !== resourceId) {
      throw new OAuthRequestError(
        'invalid_target',
        `This authorization server only issues tokens for ${resourceId}`
      );
    }
    const request: PendingAuthorization = {
      clientId: client.client_id,
      clientName: client.client_name ?? client.client_id,
      redirectUri,
      codeChallenge,
      codeChallengeMethod: 'S256',
      createdAt: Date.now(),
    };
    const state = stringParam(query, 'state');
    if (state !== undefined) request.state = state;
    const scope = stringParam(query, 'scope');
    if (scope) request.scope = scope;
    if (resource) request.resource = resource;
    const nonce = stringParam(query, 'nonce');
    if (nonce) request.nonce = nonce;
    const prompt = stringParam(query, 'prompt');
    if (prompt) request.prompt = prompt;
    const loginHint = stringParam(query, 'login_hint');
    if (loginHint) request.loginHint = loginHint;
    return request;
  };

  const authorize = wrap(async (req, res) => {
    // Errors about the client or redirect URI must not redirect (RFC 6749 section 4.1.2.1)
    let clientId: string | undefined;
    let redirectUri: string | undefined;
    try {
      clientId = stringParam(req.query, 'client_id');
      redirectUri = stringParam(req.query, 'redirect_uri');
    } catch (error) {
      sendErrorPage(res, 400, 'Invalid request', toOAuthError(error).message);
      return;
    }
    if (!clientId) {
      sendErrorPage(res, 400, 'Invalid request', 'The client_id parameter is required.');
      return;
    }
    const client = await clients.resolve(clientId);
    if (!client) {
      sendErrorPage(
        res,
        400,
        'Unknown client',
        'The application is not registered with this server.'
      );
      return;
    }
    if (redirectUri === undefined && client.redirect_uris.length === 1) {
      redirectUri = client.redirect_uris[0];
    }
    if (
      redirectUri === undefined ||
      !client.redirect_uris.some((registered) =>
        redirectUriMatches(registered, redirectUri as string)
      )
    ) {
      sendErrorPage(
        res,
        400,
        'Invalid redirect URI',
        'The redirect_uri is not registered for this application.'
      );
      return;
    }

    let request: PendingAuthorization;
    try {
      request = parseAuthorizationRequest(req.query, client, redirectUri);
    } catch (error) {
      let state: string | undefined;
      try {
        state = stringParam(req.query, 'state');
      } catch {
        state = undefined;
      }
      redirectToClient(res, { redirectUri, state }, toOAuthError(error));
      return;
    }

    if (!deps.consent || deps.consent.has(req, request.clientId, request.redirectUri)) {
      await startUpstreamAuthorization(res, request);
      return;
    }

    const id = randomId();
    const csrf = randomId(16);
    await pending.set(`consent:${id}`, { request, csrf }, PENDING_AUTHORIZATION_TTL);
    const redirect = new URL(request.redirectUri);
    const view: ConsentView = {
      clientName: request.clientName,
      clientId: request.clientId,
      redirectUri: request.redirectUri,
      redirectHost: redirect.host || redirect.protocol.replace(/:$/, '') + ' application',
      redirectIsLocal:
        redirect.protocol !== 'https:' && (!redirect.host || isLoopbackHost(redirect.hostname)),
      scopes: request.scope?.split(' ').filter(Boolean) ?? [],
      upstreamName: upstream.displayName,
      resourceName: deps.resourceName,
      action: `${issuer}${RELAY_ROUTES.consent}`,
      fields: { id, csrf },
    };
    res.setHeader('Cache-Control', 'no-store');
    res.status(200).type('html').send(deps.renderConsent(view));
  });

  const consent = wrap(async (req, res) => {
    const origin = req.headers.origin;
    if (origin && origin !== new URL(issuer).origin) {
      sendErrorPage(
        res,
        403,
        'Invalid request',
        'The consent form was submitted from another site.'
      );
      return;
    }
    const id = stringParam(req.body, 'id');
    const csrf = stringParam(req.body, 'csrf');
    const record = id ? await pending.get(`consent:${id}`) : undefined;
    if (!id || !csrf || !record || !('csrf' in record) || !safeEqual(record.csrf, csrf)) {
      sendErrorPage(
        res,
        400,
        'Request expired',
        'This authorization request has expired or was already answered.'
      );
      return;
    }
    await pending.delete(`consent:${id}`);
    const { request } = record;

    if (stringParam(req.body, 'decision') !== 'approve') {
      logger.info('User denied the authorization request', { clientId: request.clientId });
      redirectToClient(
        res,
        request,
        new OAuthRequestError('access_denied', 'The user denied the request')
      );
      return;
    }
    deps.consent?.remember(req, res, request.clientId, request.redirectUri);
    await startUpstreamAuthorization(res, request);
  });

  const callback = wrap(async (req, res) => {
    let state: string | undefined;
    try {
      state = stringParam(req.query, 'state');
    } catch {
      state = undefined;
    }
    const record = state ? await pending.get(`state:${state}`) : undefined;
    if (!state || !record || !('codeChallenge' in record)) {
      sendErrorPage(
        res,
        400,
        'Request expired',
        'This sign-in attempt has expired or was already completed.'
      );
      return;
    }
    await pending.delete(`state:${state}`);

    const upstreamError = stringParam(req.query, 'error');
    if (upstreamError) {
      const description =
        stringParam(req.query, 'error_description') ?? 'The identity provider rejected the request';
      logger.warn('Identity provider returned an error', {
        clientId: record.clientId,
        error: upstreamError,
      });
      redirectToClient(res, record, new OAuthRequestError(upstreamError, description));
      return;
    }

    const upstreamCode = stringParam(req.query, 'code');
    if (!upstreamCode) {
      redirectToClient(
        res,
        record,
        new OAuthRequestError('server_error', 'The identity provider did not return a code', 500)
      );
      return;
    }

    const code = randomId();
    await pending.set(`code:${code}`, { ...record, upstreamCode }, AUTHORIZATION_CODE_TTL);
    const redirect = new URL(record.redirectUri);
    redirect.searchParams.set('code', code);
    if (record.state !== undefined) redirect.searchParams.set('state', record.state);
    redirect.searchParams.set('iss', issuer);
    logger.info('Issued authorization code', { clientId: record.clientId });
    res.setHeader('Cache-Control', 'no-store');
    res.redirect(302, redirect.toString());
  });

  return { authorize, consent, callback };
}
