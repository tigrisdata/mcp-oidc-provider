import Provider, {
  type Configuration,
  type InteractionResults,
  type KoaContextWithOIDC,
  type Client,
} from 'oidc-provider';
import { randomUUID } from 'node:crypto';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { Keyv } from 'keyv';

import type {
  OidcProviderConfig,
  OidcProvider,
  TokenValidationResult,
  AuthenticatedUser,
} from '../types/provider.js';
import type { HttpContext } from '../types/http.js';
import type { UserSession, InteractionSession } from '../types/session.js';
import type { KeyValueStore } from '../types/storage.js';
import { createOidcAdapterFactory } from './oidc-adapter.js';
import { createExtendedSessionStore, type ExtendedSessionStore } from './session-store.js';
import { createConsoleLogger, type Logger } from '../utils/logger.js';
import { generateDevJwks } from '../utils/jwks.js';
import {
  DEFAULT_ACCESS_TOKEN_TTL,
  DEFAULT_AUTHORIZATION_CODE_TTL,
  DEFAULT_REFRESH_TOKEN_TTL,
  DEFAULT_SCOPES,
  DEFAULT_CLAIMS,
  DEFAULT_ROUTES,
  DEFAULT_ALLOWED_CLIENT_PROTOCOLS,
  DEFAULT_INTERACTION_SESSION_TTL_MS,
  DEFAULT_USER_SESSION_TTL_MS,
  DEFAULT_INTERACTION_TTL,
  DEFAULT_GRANT_TTL,
  DEFAULT_SESSION_TTL,
} from './config.js';

/**
 * Create a KeyValueStore wrapper around a Keyv instance.
 */
function createKeyvStore<T>(keyv: Keyv): KeyValueStore<T> {
  return {
    get: (key: string) => keyv.get(key) as Promise<T | undefined>,
    set: (key: string, value: T, ttl?: number) => keyv.set(key, value, ttl),
    delete: (key: string) => keyv.delete(key),
    clear: () => keyv.clear(),
  };
}

/**
 * Create an OIDC provider instance.
 *
 * @param config - Provider configuration
 * @returns OidcProvider instance
 *
 * @example
 * ```typescript
 * import { Keyv } from 'keyv';
 * import { createOidcProvider } from 'mcp-oidc-provider';
 * import { Auth0Client } from 'mcp-oidc-provider/auth0';
 *
 * const provider = createOidcProvider({
 *   issuer: 'https://your-server.com',
 *   idpClient: new Auth0Client({ ... }),
 *   store: new Keyv(),
 *   cookieSecrets: ['your-secret'],
 * });
 * ```
 */
export function createOidcProvider(config: OidcProviderConfig): OidcProvider {
  const logger = config.logger ?? createConsoleLogger();
  const scopes = config.scopes ?? DEFAULT_SCOPES;
  const allowedProtocols = config.allowedClientProtocols ?? DEFAULT_ALLOWED_CLIENT_PROTOCOLS;

  // Get the underlying store from the Keyv instance
  const underlyingStore = config.store.opts?.store;

  // Create namespaced Keyv instances for different data types
  const userSessionKeyv = new Keyv({
    store: underlyingStore,
    namespace: 'user-sessions',
    ttl: DEFAULT_USER_SESSION_TTL_MS,
  });
  const interactionSessionKeyv = new Keyv({
    store: underlyingStore,
    namespace: 'interaction-sessions',
    ttl: DEFAULT_INTERACTION_SESSION_TTL_MS,
  });

  // Create stores
  const userSessionStore = createKeyvStore<UserSession>(userSessionKeyv);
  const interactionSessionStore = createKeyvStore<InteractionSession>(interactionSessionKeyv);

  // Create session store with extended methods
  const sessionStore = createExtendedSessionStore(userSessionStore);

  // Use provided JWKS or generate development keys
  const jwks = config.jwks ?? generateDevJwks();
  if (!config.jwks) {
    logger.warn(
      'No JWKS provided - using generated development keys. ' +
        'For production, generate keys using generateJwks() and provide them in the config.'
    );
  }

  // Create the oidc-provider configuration
  const providerConfig = createProviderConfiguration(config, sessionStore, scopes, jwks, logger);

  // Create the provider
  const provider = new Provider(config.issuer, providerConfig);

  // Enable proxy trust for correct URL generation behind reverse proxies
  provider.proxy = true;

  // Override redirect_uri validation for MCP client protocols
  overrideRedirectUriValidation(provider, allowedProtocols, logger);

  // Create the JWKS for token verification
  const JWKS = createRemoteJWKSet(new URL(`${config.issuer}/jwks`));

  return {
    provider,
    sessionStore,

    async handleInteraction(ctx: HttpContext): Promise<void> {
      await handleInteraction(ctx, provider, config, sessionStore, interactionSessionStore, logger);
    },

    async handleCallback(ctx: HttpContext): Promise<void> {
      await handleCallback(ctx, config, sessionStore, interactionSessionStore, logger);
    },

    async validateToken(token: string): Promise<TokenValidationResult> {
      return validateAccessToken(token, provider, config, JWKS, sessionStore, logger);
    },

    async refreshIdpTokens(accountId: string): Promise<boolean> {
      return refreshIdpTokensForSession(accountId, config, sessionStore, logger);
    },
  };
}

/**
 * Create the oidc-provider configuration.
 */
function createProviderConfiguration(
  config: OidcProviderConfig,
  sessionStore: ExtendedSessionStore,
  scopes: string[],
  jwks: { keys: Array<{ kty: string; [key: string]: unknown }> },
  logger: Logger
): Configuration {
  const ttl = {
    AccessToken: config.ttl?.accessToken ?? DEFAULT_ACCESS_TOKEN_TTL,
    AuthorizationCode: config.ttl?.authorizationCode ?? DEFAULT_AUTHORIZATION_CODE_TTL,
    IdToken: config.ttl?.idToken ?? DEFAULT_ACCESS_TOKEN_TTL,
    RefreshToken: config.ttl?.refreshToken ?? DEFAULT_REFRESH_TOKEN_TTL,
    Interaction: config.ttl?.interaction ?? DEFAULT_INTERACTION_TTL,
    Grant: config.ttl?.grant ?? DEFAULT_GRANT_TTL,
    Session: config.ttl?.session ?? DEFAULT_SESSION_TTL,
  };

  return {
    routes: DEFAULT_ROUTES,

    jwks,

    adapter: createOidcAdapterFactory(config.store, logger),

    clients: [],

    pkce: {
      required: () => true,
    },

    conformIdTokenClaims: false,

    features: {
      devInteractions: { enabled: false },
      deviceFlow: { enabled: false },
      clientCredentials: { enabled: false },
      introspection: { enabled: true },
      revocation: { enabled: true },
      registration: { enabled: true },
      resourceIndicators: {
        enabled: true,
        getResourceServerInfo: (
          _ctx: KoaContextWithOIDC,
          resourceIndicator: string,
          _client: Client
        ) => {
          // Use custom handler if provided
          if (config.getResourceServerInfo) {
            const info = config.getResourceServerInfo(resourceIndicator);
            if (info) return info;
          }

          // Default: allow any resource (MCP servers can be at any path)
          // Common patterns: /mcp, /, /api, etc.
          return {
            scope: scopes.join(' '),
            audience: resourceIndicator,
            accessTokenTTL: ttl.AccessToken,
            accessTokenFormat: 'jwt' as const,
          };
        },
      },
    },

    ttl,

    interactions: {
      url: (_ctx: KoaContextWithOIDC, interaction: { uid: string }) => {
        return `/oauth/interaction/${interaction.uid}`;
      },
    },

    claims: config.claims ?? DEFAULT_CLAIMS,

    findAccount: async (_ctx: unknown, sub: string) => {
      const userSession = await sessionStore.get(sub);

      if (!userSession) {
        return {
          accountId: sub,
          claims() {
            return { sub };
          },
        };
      }

      return {
        accountId: sub,
        claims() {
          return {
            sub,
            email: userSession.claims['email'] as string | undefined,
            email_verified: userSession.claims['email_verified'] as boolean | undefined,
            name: userSession.claims['name'] as string | undefined,
            nickname: userSession.claims['nickname'] as string | undefined,
            picture: userSession.claims['picture'] as string | undefined,
            updated_at: userSession.claims['updated_at'] as number | undefined,
          };
        },
      };
    },

    cookies: {
      keys: config.cookieSecrets,
      long: {
        signed: true,
        sameSite: config.isProduction ? 'none' : 'lax',
        secure: config.isProduction ?? false,
      },
      short: {
        signed: true,
        sameSite: config.isProduction ? 'none' : 'lax',
        secure: config.isProduction ?? false,
      },
    },

    responseTypes: ['code'],

    scopes,

    extraClientMetadata: {
      properties: ['logo_uri', 'client_name', 'client_uri'],
    },

    clientBasedCORS: () => true,

    issueRefreshToken(_ctx: KoaContextWithOIDC, client: Client, _code: unknown) {
      return client.grantTypeAllowed('refresh_token');
    },
  };
}

/**
 * Override redirect_uri validation to allow custom MCP client protocols.
 */
function overrideRedirectUriValidation(
  provider: Provider,
  allowedProtocols: string[],
  logger: Logger
): void {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ClientSchema = (provider as any).Client?.Schema;
  if (ClientSchema?.prototype) {
    const originalInvalidate = ClientSchema.prototype.invalidate;
    ClientSchema.prototype.invalidate = function (message: string, code?: string) {
      if (
        message.includes('redirect_uris') &&
        (message.includes('must only contain web uris') ||
          message.includes('reverse domain name based scheme'))
      ) {
        const redirectUris: string[] = this.redirect_uris ?? [];
        const hasKnownProtocol = redirectUris.some((uri) =>
          allowedProtocols.some((protocol) => uri.startsWith(protocol))
        );

        if (hasKnownProtocol) {
          logger.warn('Allowing non-standard redirect_uri for known MCP client', {
            validation_error: message,
            redirect_uris: redirectUris,
          });
          return;
        }
      }
      return originalInvalidate.call(this, message, code);
    };
  }
}

/**
 * Handle the interaction endpoint (login/consent flow).
 */
async function handleInteraction(
  ctx: HttpContext,
  provider: Provider,
  config: OidcProviderConfig,
  sessionStore: ExtendedSessionStore,
  interactionStore: KeyValueStore<InteractionSession>,
  logger: Logger
): Promise<void> {
  const uid = ctx.request.params['uid'];

  if (!uid) {
    ctx.response.status(400).send('Missing interaction UID');
    return;
  }

  try {
    // Get interaction details from oidc-provider
    // Use raw framework objects for oidc-provider compatibility
    if (!ctx.rawRequest || !ctx.rawResponse) {
      logger.error('Raw request/response objects not available in context');
      ctx.response.status(500).send('Internal server error: missing raw request/response');
      return;
    }

    const interaction = await provider.interactionDetails(
      ctx.rawRequest as Parameters<typeof provider.interactionDetails>[0],
      ctx.rawResponse as Parameters<typeof provider.interactionDetails>[1]
    );

    // Check if user is already authenticated
    const userSessionId = ctx.request.session?.get<string>('userSessionId');
    const userSession = userSessionId ? await sessionStore.get(userSessionId) : undefined;

    if (!userSession) {
      // User not authenticated - redirect to IdP
      if (userSessionId) {
        logger.info('Stale session detected, regenerating', {
          oldUserSessionId: userSessionId,
          interactionUid: uid,
        });
        await ctx.request.session?.regenerate();
      }

      const idpScopes = config.idpScopes ?? 'openid email profile offline_access';
      const { authorizationUrl, state, nonce, codeVerifier } =
        await config.idpClient.createAuthorizationUrl(idpScopes);

      // Store interaction data
      const sessionId = randomUUID();
      await interactionStore.set(sessionId, {
        interactionUid: uid,
        idpState: state,
        idpNonce: nonce,
        codeVerifier,
      });

      // Store session ID in cookie/session
      ctx.request.session?.set('interactionSessionId', sessionId);
      await ctx.request.session?.save();

      // Redirect to IdP
      ctx.response.redirect(authorizationUrl);
      return;
    }

    // User is authenticated - grant consent automatically
    // userSessionId is guaranteed to exist since userSession exists
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const accountId = userSessionId!;
    const grant = new provider.Grant({
      accountId,
      clientId: interaction.params['client_id'] as string,
    });

    const scopeParam = interaction.params['scope'] as string | undefined;
    const resourceParam = interaction.params['resource'] as string | undefined;

    const requestedScopes = scopeParam ? scopeParam.split(' ') : ['openid'];
    const scopesToGrant = new Set(requestedScopes);
    scopesToGrant.add('offline_access');

    const finalScope = Array.from(scopesToGrant).join(' ');
    grant.addOIDCScope(finalScope);

    if (resourceParam) {
      grant.addResourceScope(resourceParam, finalScope);
    }

    const grantId = await grant.save();

    const result: InteractionResults = {
      consent: { grantId },
      login: { accountId },
    };

    await provider.interactionFinished(
      ctx.rawRequest as Parameters<typeof provider.interactionFinished>[0],
      ctx.rawResponse as Parameters<typeof provider.interactionFinished>[1],
      result,
      { mergeWithLastSubmission: true }
    );
  } catch (error) {
    logger.error('Interaction error', error);
    ctx.response.status(500).send('Internal server error');
  }
}

/**
 * Handle the IdP callback after user authenticates.
 */
async function handleCallback(
  ctx: HttpContext,
  config: OidcProviderConfig,
  sessionStore: ExtendedSessionStore,
  interactionStore: KeyValueStore<InteractionSession>,
  logger: Logger
): Promise<void> {
  logger.info('IdP callback received', {
    url: ctx.request.originalUrl,
    hasSession: !!ctx.request.session,
  });

  try {
    const code = ctx.request.query['code'] as string | undefined;
    const state = ctx.request.query['state'] as string | undefined;

    if (!code || !state) {
      ctx.response.status(400).send('Missing code or state parameter');
      return;
    }

    // Retrieve interaction session
    const interactionSessionId = ctx.request.session?.get<string>('interactionSessionId');
    if (!interactionSessionId) {
      logger.error('No interaction session ID found in session');
      ctx.response.status(400).send('Invalid session - session cookie not found or expired');
      return;
    }

    const interactionSession = await interactionStore.get(interactionSessionId);
    if (!interactionSession) {
      ctx.response.status(400).send('Invalid interaction session');
      return;
    }

    // Verify state
    if (state !== interactionSession.idpState) {
      ctx.response.status(400).send('State mismatch');
      return;
    }

    // Build the full callback URL
    const callbackUrl = ctx.getFullUrl();

    // Exchange code for tokens
    const tokenSet = await config.idpClient.exchangeCode(
      callbackUrl,
      interactionSession.codeVerifier,
      state,
      interactionSession.idpNonce
    );

    // Parse ID token to get user claims
    const claims = config.idpClient.parseIdToken(tokenSet.idToken ?? '');

    // Extract custom data if the IdP client supports it
    const customData = config.idpClient.extractCustomData?.(claims);

    // Create user session
    const userSessionId = randomUUID();
    const userSession: UserSession = {
      userId: claims.sub,
      claims: claims as UserSession['claims'],
      tokenSet: {
        accessToken: tokenSet.accessToken ?? '',
        idToken: tokenSet.idToken ?? '',
        refreshToken: tokenSet.refreshToken ?? '',
        expiresAt: tokenSet.expiresIn ? Date.now() + tokenSet.expiresIn * 1000 : undefined,
      },
      customData,
    };

    await sessionStore.set(userSessionId, userSession);

    logger.info('User session created', {
      sessionId: userSessionId,
      email: claims.email,
    });

    // Store user session ID in framework session
    ctx.request.session?.set('userSessionId', userSessionId);
    await ctx.request.session?.save();

    // Clean up interaction session
    await interactionStore.delete(interactionSessionId);

    // Redirect back to interaction
    ctx.response.redirect(`/oauth/interaction/${interactionSession.interactionUid}`);
  } catch (error) {
    logger.error('IdP callback error', error);
    ctx.response
      .status(500)
      .send(`Authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Validate an access token and return the authenticated user.
 * Automatically refreshes IdP tokens if they are expired or about to expire.
 */
async function validateAccessToken(
  token: string,
  provider: Provider,
  config: OidcProviderConfig,
  JWKS: ReturnType<typeof createRemoteJWKSet>,
  sessionStore: ExtendedSessionStore,
  logger: Logger
): Promise<TokenValidationResult> {
  try {
    const isJWT = token.startsWith('eyJ');
    let accountId: string;

    if (isJWT) {
      // JWT token - verify and decode
      try {
        const { payload } = await jwtVerify(token, JWKS, {
          issuer: config.issuer,
          typ: 'at+jwt',
        });
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        accountId = payload.sub!;
      } catch (jwtError) {
        logger.error('JWT verification failed', jwtError);
        return { valid: false, error: 'Invalid or expired JWT token' };
      }
    } else {
      // Opaque token - look it up in storage
      try {
        const accessTokens = provider.AccessToken;
        const tokenData = await accessTokens.find(token);

        if (!tokenData) {
          return { valid: false, error: 'Token not found or expired' };
        }

        accountId = tokenData.accountId;
      } catch (error) {
        logger.error('Token lookup error', error);
        return { valid: false, error: 'Failed to validate access token' };
      }
    }

    // Get the user session
    let userSession = await sessionStore.get(accountId);
    if (!userSession) {
      return { valid: false, error: 'User session not found' };
    }

    // Check if IdP tokens need refreshing and refresh them automatically
    if (isIdpTokenExpired(userSession)) {
      logger.info('IdP tokens expired, attempting automatic refresh', { accountId });
      const refreshed = await refreshIdpTokensForSession(accountId, config, sessionStore, logger);
      if (refreshed) {
        // Re-fetch the session to get the updated tokens
        userSession = (await sessionStore.get(accountId)) ?? userSession;
      } else {
        logger.warn('IdP token refresh failed, returning stale tokens', { accountId });
      }
    }

    const user: AuthenticatedUser = {
      accountId,
      userId: userSession.userId,
      claims: userSession.claims as Record<string, unknown>,
      tokenSet: userSession.tokenSet,
      customData: userSession.customData,
    };

    return { valid: true, user };
  } catch (error) {
    logger.error('Token validation error', error);
    return { valid: false, error: 'Token validation failed' };
  }
}

/** Refresh buffer - refresh tokens 60 seconds before expiry */
const TOKEN_REFRESH_BUFFER_MS = 60 * 1000;

/**
 * Check if IdP tokens need refreshing.
 */
function isIdpTokenExpired(userSession: UserSession): boolean {
  const expiresAt = userSession.tokenSet.expiresAt;
  if (!expiresAt) {
    // No expiry info - assume valid
    return false;
  }
  // Refresh if expired or expiring within the buffer period
  return Date.now() >= expiresAt - TOKEN_REFRESH_BUFFER_MS;
}

/**
 * Refresh IdP tokens for a user session.
 */
async function refreshIdpTokensForSession(
  accountId: string,
  config: OidcProviderConfig,
  sessionStore: ExtendedSessionStore,
  logger: Logger
): Promise<boolean> {
  const userSession = await sessionStore.get(accountId);
  if (!userSession) {
    return false;
  }

  try {
    const newTokenSet = await config.idpClient.refreshToken(userSession.tokenSet.refreshToken);

    await sessionStore.updateTokenSet(accountId, {
      accessToken: newTokenSet.accessToken,
      idToken: newTokenSet.idToken ?? userSession.tokenSet.idToken,
      refreshToken: newTokenSet.refreshToken ?? userSession.tokenSet.refreshToken,
      expiresAt: newTokenSet.expiresIn ? Date.now() + newTokenSet.expiresIn * 1000 : undefined,
    });

    logger.info('IdP tokens refreshed successfully', { accountId });
    return true;
  } catch (error) {
    logger.error('IdP token refresh failed', { error, accountId });
    return false;
  }
}
