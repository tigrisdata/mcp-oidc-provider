/**
 * Internal Express utilities for mcp-oidc-provider.
 * @internal
 *
 * This module is not exported to end users.
 * Use the high-level APIs instead:
 * - `mcp-oidc-provider/oidc` for the OIDC server
 * - `mcp-oidc-provider/mcp` for the MCP resource server side (MCP SDK v2)
 */

// Re-export for internal use only
export { createExpressAdapter, isOidcProviderRoute } from './adapter.js';
export { KeyvSessionStore } from './session-store.js';
export { createMcpCorsMiddleware } from './cors.js';
