/**
 * MCP integration module for mcp-oidc-provider.
 *
 * This module provides:
 * - Integrated MCP server setup with built-in OIDC authentication
 * - Helpers for integrating with the MCP SDK's auth system
 */

import type { AuthenticatedUser } from '../types.js';

// Extend Express Request type to include user
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /**
       * Authenticated user attached by setupMcpExpress auth middleware.
       * Available on POST requests to /mcp after token validation.
       * Undefined for GET/DELETE requests (stateless session handling).
       */
      user?: AuthenticatedUser;
    }
  }
}

// Re-export AuthenticatedUser for convenience
export type { AuthenticatedUser } from '../types.js';

// Integrated MCP + OIDC Express setup
export { setupMcpExpress } from './setup.js';
export type { McpExpressSetupOptions, McpExpressSetupResult, McpRequestHandler } from './setup.js';

// MCP auth provider for standalone OIDC servers
export {
  createMcpAuthProvider,
  getIdpTokens,
  InvalidTokenError,
  type McpAuthProviderOptions,
  type McpAuthProviderResult,
  type ProxyOAuthServerProviderConfig,
  type ClientInfo,
  type AuthInfo,
  type IdpTokenSet,
} from './auth-provider.js';
