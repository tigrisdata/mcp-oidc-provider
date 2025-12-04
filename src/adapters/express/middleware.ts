import type { Request, Response, NextFunction } from 'express';
import type { OidcProvider, AuthenticatedUser } from '../../types/provider.js';
import type { Logger } from '../../utils/logger.js';
import { createConsoleLogger } from '../../utils/logger.js';

// Extend Express Request type to include user
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}

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
}

/**
 * Create an Express middleware for authenticating requests using the OIDC provider.
 *
 * This middleware:
 * 1. Extracts the Bearer token from the Authorization header
 * 2. Validates the token (JWT or opaque)
 * 3. Loads the user session
 * 4. Optionally refreshes IdP tokens if they're close to expiration
 * 5. Attaches the authenticated user to `req.user`
 *
 * @param provider - The OIDC provider instance
 * @param options - Middleware options
 * @returns Express middleware function
 *
 * @example
 * ```typescript
 * import { createExpressAuthMiddleware } from 'mcp-oidc-provider/express';
 *
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

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Extract bearer token from Authorization header
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
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
 */
function isIdpTokenExpiringSoon(accessToken: string, bufferSeconds: number): boolean {
  try {
    // Decode the JWT to check expiration (without verification)
    const parts = accessToken.split('.');
    if (parts.length !== 3) return true;

    const payload = JSON.parse(Buffer.from(parts[1] ?? '', 'base64').toString());
    const exp = payload.exp;
    if (!exp) return false;

    // Check if token expires within the buffer time
    const now = Math.floor(Date.now() / 1000);
    return exp <= now + bufferSeconds;
  } catch {
    // If we can't decode it, assume it doesn't need refresh
    return false;
  }
}

/**
 * Create an Express middleware that requires authentication but doesn't fail on invalid tokens.
 * Instead, it sets `req.user` to undefined if authentication fails.
 *
 * Useful for endpoints that have different behavior for authenticated vs anonymous users.
 *
 * @param provider - The OIDC provider instance
 * @param options - Middleware options
 * @returns Express middleware function
 */
export function createOptionalAuthMiddleware(
  provider: OidcProvider,
  options?: ExpressAuthMiddlewareOptions
): (req: Request, res: Response, next: NextFunction) => Promise<void> {
  const logger = options?.logger ?? createConsoleLogger();

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        // No token - continue without user
        req.user = undefined;
        next();
        return;
      }

      const accessToken = authHeader.slice(7);
      const result = await provider.validateToken(accessToken);

      if (result.valid && result.user) {
        req.user = result.user;
      } else {
        req.user = undefined;
      }

      next();
    } catch (error) {
      logger.error('Optional auth middleware error', error);
      // Don't fail - just continue without user
      req.user = undefined;
      next();
    }
  };
}
