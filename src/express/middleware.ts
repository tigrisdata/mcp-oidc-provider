import type { Request, Response, NextFunction } from 'express';
import { decodeJwt } from 'jose';
import type { OidcProvider } from '../core/types.js';
import type { Logger } from '../utils/logger.js';
import { createConsoleLogger } from '../utils/logger.js';

/**
 * Options for the Express auth middleware.
 */
export interface ExpressAuthMiddlewareOptions {
  /** Logger instance */
  logger?: Logger;
  /**
   * Whether to automatically refresh IdP tokens when they're close to expiration.
   * Default: true
   */
  autoRefresh?: boolean;
  /**
   * Buffer time in seconds before token expiration to trigger refresh.
   * Default: 300 (5 minutes)
   */
  refreshBufferSeconds?: number;
  /**
   * Base URL of the server for constructing WWW-Authenticate header.
   * Required for MCP clients to discover OAuth metadata.
   * If not provided, will be inferred from the request.
   */
  baseUrl?: string;
  /**
   * Path to the protected resource (MCP endpoint).
   * Default: '/mcp'
   */
  resourcePath?: string;
}

/**
 * Create an Express middleware for authenticating requests using the OIDC provider.
 *
 * This middleware:
 * 1. Extracts the Bearer token from the Authorization header
 * 2. Validates the JWT signature using JWKS
 * 3. Loads the user session
 * 4. Automatically refreshes IdP tokens if they're close to expiration
 * 5. Attaches the authenticated user to `req.user`
 *
 * @param provider - The OIDC provider instance
 * @param options - Middleware options
 * @returns Express middleware function
 *
 * @internal This is an internal utility used by setupMcpExpress.
 *
 * @example
 * ```typescript
 * const authMiddleware = createExpressAuthMiddleware(oidcProvider);
 * app.use('/api', authMiddleware, apiRoutes);
 * ```
 */
export function createExpressAuthMiddleware(
  provider: OidcProvider,
  options?: ExpressAuthMiddlewareOptions
): (req: Request, res: Response, next: NextFunction) => Promise<void> {
  const logger = options?.logger ?? createConsoleLogger();
  const autoRefresh = options?.autoRefresh ?? true;
  const refreshBufferSeconds = options?.refreshBufferSeconds ?? 300;
  const configuredBaseUrl = options?.baseUrl;

  // Helper to get base URL from request or config
  const getBaseUrl = (req: Request): string => {
    if (configuredBaseUrl) return configuredBaseUrl;
    const protocol = req.protocol;
    const host = req.get('host') ?? 'localhost';
    return `${protocol}://${host}`;
  };

  // Helper to set WWW-Authenticate header for OAuth discovery (RFC 9728)
  const setWwwAuthenticate = (req: Request, res: Response): void => {
    const baseUrl = getBaseUrl(req);
    const resourceMetadataUrl = `${baseUrl}/.well-known/oauth-protected-resource`;
    res.setHeader('WWW-Authenticate', `Bearer resource_metadata="${resourceMetadataUrl}"`);
  };

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Extract bearer token from Authorization header
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        // Include WWW-Authenticate header to help MCP clients discover OAuth
        setWwwAuthenticate(req, res);
        res.status(401).json({
          error: 'unauthorized',
          message:
            'Missing or invalid Authorization header. Expected: Authorization: Bearer <token>',
        });
        return;
      }

      const accessToken = authHeader.slice(7); // Remove 'Bearer ' prefix

      // Validate the token
      const result = await provider.validateToken(accessToken);

      if (!result.valid || !result.user) {
        setWwwAuthenticate(req, res);
        res.status(401).json({
          error: 'invalid_token',
          message: result.error ?? 'Invalid or expired token',
        });
        return;
      }

      // Check if IdP access token needs refresh
      if (autoRefresh) {
        const needsRefresh = isIdpTokenExpiringSoon(
          result.user.tokenSet.accessToken,
          refreshBufferSeconds
        );

        if (needsRefresh) {
          logger.info('IdP access token expiring soon, attempting refresh', {
            accountId: result.user.accountId,
          });

          const refreshed = await provider.refreshIdpTokens(result.user.accountId);

          if (refreshed) {
            // Re-fetch the session to get updated tokens
            const updatedResult = await provider.validateToken(accessToken);
            if (updatedResult.valid && updatedResult.user) {
              result.user = updatedResult.user;
            }
            logger.info('IdP tokens refreshed successfully', {
              accountId: result.user.accountId,
            });
          } else {
            logger.warn('IdP token refresh failed', {
              accountId: result.user.accountId,
            });
            // Continue with existing token - it's still valid
          }
        }
      }

      // Attach user info to request
      req.user = result.user;

      next();
    } catch (error) {
      logger.error('Auth middleware error', error);
      res.status(500).json({
        error: 'internal_server_error',
        message: 'Authentication failed',
      });
    }
  };
}

/**
 * Check if an IdP access token is expiring soon.
 *
 * @param accessToken - The JWT access token to check
 * @param bufferSeconds - Number of seconds before expiration to consider "expiring soon"
 * @returns true if token expires within buffer time, false otherwise
 *
 * @remarks
 * - If the token cannot be decoded (invalid format), returns false to avoid
 *   unnecessary refresh attempts on opaque tokens.
 * - If the token has no `exp` claim, returns false since we cannot determine expiration.
 */
function isIdpTokenExpiringSoon(accessToken: string, bufferSeconds: number): boolean {
  try {
    // Use jose library for consistent JWT decoding across the codebase
    const payload = decodeJwt(accessToken);
    const exp = payload.exp;

    // If no expiration claim, assume token doesn't expire (opaque tokens, etc.)
    if (!exp) return false;

    // Check if token expires within the buffer time
    const now = Math.floor(Date.now() / 1000);
    return exp <= now + bufferSeconds;
  } catch {
    // If we can't decode it (e.g., opaque token), assume it doesn't need refresh
    return false;
  }
}
