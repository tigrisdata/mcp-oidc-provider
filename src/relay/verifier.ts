/**
 * Token verifier for the MCP SDK: validates the identity provider's access
 * tokens (signature, issuer, audience, expiry) and derives `req.auth`.
 * @internal
 */

import type { JWTPayload } from 'jose';
import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';
import type { CustomDataFn } from '../types.js';
import type { Logger } from '../utils/logger.js';
import { sha256 } from './storage.js';
import type { Upstream } from './upstream.js';

export interface VerifierOptions {
  upstream: Upstream;
  /** Required `aud` of every accepted token. */
  audience: string;
  /** Resource identifier reported in `AuthInfo.resource` for accepted tokens. */
  resource: URL;
  resourceMetadataUrl: string;
  customData?: CustomDataFn;
  onVerifyError?: (error: unknown) => void;
  logger: Logger;
}

/** UserInfo results are cached per token for at most this long. */
const USERINFO_CACHE_MAX_MS = 60 * 60 * 1000;
const USERINFO_CACHE_MAX_ENTRIES = 1000;

interface CacheEntry {
  expiresAt: number;
  value: Promise<Record<string, unknown>>;
}

/** Scopes from a `scope` string (RFC 8693/9068) or an `scp` array (Okta, Entra). */
export function scopesFromClaims(payload: JWTPayload): string[] {
  const scope = payload['scope'];
  if (typeof scope === 'string') return scope.split(' ').filter(Boolean);
  const scp = payload['scp'];
  if (Array.isArray(scp)) return scp.filter((value): value is string => typeof value === 'string');
  return [];
}

/** The OAuth client the token was issued to (`azp` for OpenID providers, `client_id` per RFC 9068). */
export function clientIdFromClaims(payload: JWTPayload): string {
  const azp = payload['azp'];
  if (typeof azp === 'string') return azp;
  const clientId = payload['client_id'];
  return typeof clientId === 'string' ? clientId : '';
}

export function createVerifier(options: VerifierOptions): OAuthTokenVerifier {
  const { upstream, audience, resource, resourceMetadataUrl, customData, onVerifyError, logger } =
    options;
  const userinfoCache = new Map<string, CacheEntry>();

  const cachedUserinfo = (
    token: string,
    exp: number | undefined
  ): Promise<Record<string, unknown>> => {
    const key = sha256(token);
    const now = Date.now();
    const cached = userinfoCache.get(key);
    if (cached && cached.expiresAt > now) return cached.value;

    const tokenExpiry = exp !== undefined ? exp * 1000 : now + USERINFO_CACHE_MAX_MS;
    const expiresAt = Math.min(tokenExpiry, now + USERINFO_CACHE_MAX_MS);
    const value = upstream.userinfo(token);
    value.catch(() => userinfoCache.delete(key));
    for (const [existingKey, entry] of userinfoCache) {
      if (entry.expiresAt <= now) userinfoCache.delete(existingKey);
    }
    if (userinfoCache.size >= USERINFO_CACHE_MAX_ENTRIES) {
      const oldest = userinfoCache.keys().next().value;
      if (oldest !== undefined) userinfoCache.delete(oldest);
    }
    userinfoCache.set(key, { expiresAt, value });
    return value;
  };

  return {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
      try {
        const payload = await upstream.verifyToken(token, { audience, requiredClaims: ['exp'] });

        const extra: Record<string, unknown> = { sub: payload.sub, claims: payload };
        if (customData) {
          extra['customData'] = await customData({
            claims: payload,
            token,
            userinfo: () => cachedUserinfo(token, payload.exp),
          });
        }

        return {
          token,
          clientId: clientIdFromClaims(payload),
          scopes: scopesFromClaims(payload),
          expiresAt: payload.exp,
          resource,
          resourceMetadataUrl,
          extra,
        };
      } catch (error) {
        onVerifyError?.(error);
        logger.debug('Rejected access token', {
          error: error instanceof Error ? error.message : String(error),
        });
        // The SDK maps OAuthError(invalid_token) to a 401 with a WWW-Authenticate challenge
        throw new OAuthError(OAuthErrorCode.InvalidToken, 'Invalid or expired token');
      }
    },
  };
}
