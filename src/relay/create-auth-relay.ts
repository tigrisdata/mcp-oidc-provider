/**
 * `createAuthRelay`: an OAuth 2.1 authorization server for MCP clients that
 * relays every grant to an upstream OpenID Connect provider, plus the token
 * verifier and protected resource metadata for the MCP server next to it.
 */

import type { ErrorRequestHandler, Request, RequestHandler, Router as RouterType } from 'express';
import { Router, json, urlencoded } from 'express';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/server';
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthMetadataRouter,
} from '@modelcontextprotocol/express';
import { createMcpCorsMiddleware } from '../express/cors.js';
import type { AuthRelayOptions, UpstreamMetadata } from '../types.js';
import { createConsoleLogger, type Logger } from '../utils/logger.js';
import { createAuthorizeHandlers, wrap, type PendingRecord } from './authorize.js';
import { ClientRegistry } from './clients.js';
import { ConsentStore, deriveConsentSecret } from './consent.js';
import { OAuthRequestError, sendOAuthError } from './errors.js';
import { renderConsentPage } from './html.js';
import { RELAY_ROUTES, buildRelayMetadata, type OAuthMetadata } from './metadata.js';
import { STORAGE_NAMESPACES, namespacedStore } from './storage.js';
import { createTokenHandler } from './token.js';
import { Upstream } from './upstream.js';
import { createVerifier } from './verifier.js';

/** Default lifetime of a remembered consent decision: 30 days. */
export const DEFAULT_CONSENT_TTL = 30 * 24 * 60 * 60 * 1000;
/** Default name of the consent cookie. */
export const DEFAULT_CONSENT_COOKIE_NAME = 'mcp_relay_consent';
/** Default path the identity provider redirects back to. */
export const DEFAULT_CALLBACK_PATH = '/oauth/callback';
/** Default MCP endpoint path. */
export const DEFAULT_MCP_ENDPOINT_PATH = '/mcp';

const BODY_LIMIT = '64kb';

/** What `createAuthRelay` returns. */
export interface AuthRelay {
  /**
   * Express router with the authorization server (`/.well-known/oauth-authorization-server`,
   * `/register`, `/authorize`, `/token`, the identity provider callback), the
   * protected resource metadata for the MCP endpoint and CORS for it.
   * Mount it at the root of the app that serves `baseUrl`: `app.use(relay.router)`.
   */
  router: RouterType;

  /**
   * Token verifier for `requireBearerAuth` from `@modelcontextprotocol/express`.
   * Accepts the identity provider's access tokens for the configured audience
   * and reports `resource` as the MCP endpoint, so `expectedResource: relay.resource`
   * works. `req.auth.extra` carries `sub`, `claims` and `customData`.
   */
  verifier: OAuthTokenVerifier;

  /** The MCP endpoint URL: the RFC 8707 resource identifier. */
  resource: URL;

  /** URL of the protected resource metadata document, for `requireBearerAuth`. */
  resourceMetadataUrl: string;

  /** The authorization server metadata the relay publishes. */
  metadata: OAuthMetadata;

  /**
   * Discover the identity provider's metadata now instead of on the first
   * request. Optional; useful as a startup check.
   */
  discoverUpstream(): Promise<UpstreamMetadata>;
}

/** Normalise and check `baseUrl`. */
function parseIssuer(baseUrl: string): string {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new TypeError(`baseUrl must be an absolute URL, got "${baseUrl}"`);
  }
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new TypeError(
      `baseUrl must be an origin without a path, query or fragment (the relay router is mounted at the root), got "${baseUrl}"`
    );
  }
  return url.origin;
}

/** Permissive CORS for the endpoints browser-based public clients call directly. */
const publicCors: RequestHandler = (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, mcp-protocol-version'
  );
  res.setHeader('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
};

function createErrorHandler(logger: Logger): ErrorRequestHandler {
  return (error: unknown, _req: Request, res, next) => {
    if (res.headersSent) {
      next(error);
      return;
    }
    const status = (error as { status?: unknown }).status;
    if (typeof status === 'number' && status >= 400 && status < 500) {
      // Body parser errors: malformed JSON or form, payload too large
      sendOAuthError(
        res,
        new OAuthRequestError('invalid_request', 'Malformed request body', status)
      );
      return;
    }
    logger.error('Unhandled error in auth relay', error);
    sendOAuthError(res, new OAuthRequestError('server_error', 'An unexpected error occurred', 500));
  };
}

/**
 * Create the auth relay.
 *
 * @example
 * ```typescript
 * import { createMcpExpressApp, requireBearerAuth } from '@modelcontextprotocol/express';
 * import { Keyv } from 'keyv';
 * import { createAuthRelay } from 'mcp-oidc-provider';
 *
 * const relay = createAuthRelay({
 *   baseUrl: 'https://mcp.example.com',
 *   upstream: {
 *     issuer: 'https://your-tenant.auth0.com',
 *     clientId: process.env.OIDC_CLIENT_ID!,
 *     clientSecret: process.env.OIDC_CLIENT_SECRET!,
 *     audience: 'https://api.example.com',
 *   },
 *   store: new Keyv(),
 * });
 *
 * const app = createMcpExpressApp({ host: '0.0.0.0', allowedHosts: ['mcp.example.com'] });
 * app.use(relay.router);
 * app.post(
 *   '/mcp',
 *   requireBearerAuth({
 *     verifier: relay.verifier,
 *     resourceMetadataUrl: relay.resourceMetadataUrl,
 *     expectedResource: relay.resource,
 *   }),
 *   mcpHandler
 * );
 * ```
 */
export function createAuthRelay(options: AuthRelayOptions): AuthRelay {
  const issuer = parseIssuer(options.baseUrl);
  const logger = options.logger ?? createConsoleLogger();
  const fetchImpl: typeof fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const callbackPath = options.callbackPath ?? DEFAULT_CALLBACK_PATH;

  const upstream = new Upstream(options.upstream, {
    fetch: fetchImpl,
    logger,
    jwksCacheOptions: options.jwksCacheOptions,
  });
  const clients = new ClientRegistry(options.store, options.clients ?? {}, {
    fetch: fetchImpl,
    logger,
  });
  const pending = namespacedStore<PendingRecord>(options.store, STORAGE_NAMESPACES.PENDING);

  const resource = new URL(`${issuer}${options.mcpEndpointPath ?? DEFAULT_MCP_ENDPOINT_PATH}`);
  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resource);
  const scopesSupported = options.scopesSupported ?? upstream.scopes;
  const metadata = buildRelayMetadata({
    issuer,
    scopesSupported,
    dynamicRegistration: clients.allowDynamicRegistration,
    clientIdMetadataDocuments: clients.allowClientIdMetadataDocuments,
  });

  const consentEnabled = options.consent?.enabled ?? true;
  const consent = consentEnabled
    ? new ConsentStore({
        cookieName: options.consent?.cookieName ?? DEFAULT_CONSENT_COOKIE_NAME,
        secret: options.consent?.secret ?? deriveConsentSecret(options.upstream.clientSecret),
        ttl: options.consent?.ttl ?? DEFAULT_CONSENT_TTL,
        secure: options.secureCookies ?? issuer.startsWith('https:'),
      })
    : undefined;
  if (!consentEnabled) {
    logger.warn(
      'Consent page disabled: every registered client is forwarded to the identity provider without asking the user'
    );
  }

  const verifier = createVerifier({
    upstream,
    audience: options.upstream.audience,
    resource,
    resourceMetadataUrl,
    customData: options.customData,
    onVerifyError: options.onVerifyError,
    logger,
  });

  const {
    authorize,
    consent: consentDecision,
    callback,
  } = createAuthorizeHandlers({
    issuer,
    callbackPath,
    upstream,
    clients,
    consent,
    renderConsent: options.consent?.render ?? renderConsentPage,
    pending,
    resource,
    resourceName: options.resourceName,
    upstreamAudience: options.upstream.audience,
    upstreamAuthorizationParams: options.upstream.authorizationParams ?? {},
    logger,
  });
  const token = createTokenHandler({
    issuer,
    callbackPath,
    upstream,
    clients,
    pending,
    upstreamAudience: options.upstream.audience,
    onTokenResponse: options.onTokenResponse,
    logger,
  });

  const router = Router();

  // Discovery documents from the MCP SDK (each with its own permissive CORS):
  // the relay's authorization server metadata and the protected resource
  // metadata for the MCP endpoint
  router.use(
    mcpAuthMetadataRouter({
      oauthMetadata: metadata,
      resourceServerUrl: resource,
      scopesSupported,
      ...(options.resourceName ? { resourceName: options.resourceName } : {}),
    })
  );

  // Token and registration endpoints are called from browsers by public clients
  router.use([RELAY_ROUTES.token, RELAY_ROUTES.registration], publicCors);
  // CORS for the MCP endpoint (includes the MCP Inspector origin by default)
  router.use(
    createMcpCorsMiddleware({ baseUrl: issuer, additionalOrigins: options.additionalCorsOrigins })
  );

  if (clients.allowDynamicRegistration) {
    router.post(
      RELAY_ROUTES.registration,
      json({ limit: BODY_LIMIT, type: () => true }),
      wrap(async (req, res) => {
        try {
          const registration = await clients.register(req.body);
          res.setHeader('Cache-Control', 'no-store');
          res.status(201).json(registration);
        } catch (error) {
          if (error instanceof OAuthRequestError) {
            sendOAuthError(res, error);
            return;
          }
          throw error;
        }
      })
    );
  }
  router.get(RELAY_ROUTES.authorization, authorize);
  router.post(
    RELAY_ROUTES.consent,
    urlencoded({ extended: false, limit: BODY_LIMIT }),
    consentDecision
  );
  router.get(callbackPath, callback);
  router.post(RELAY_ROUTES.token, urlencoded({ extended: false, limit: BODY_LIMIT }), token);
  router.use(createErrorHandler(logger));

  return {
    router,
    verifier,
    resource,
    resourceMetadataUrl,
    metadata,
    discoverUpstream: () => upstream.metadata(),
  };
}
