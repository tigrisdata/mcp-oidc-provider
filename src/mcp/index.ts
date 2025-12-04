/**
 * MCP integration module for mcp-oidc-provider.
 *
 * This module provides helpers for integrating with the MCP SDK's auth system.
 */

export {
  createMcpAuthProvider,
  InvalidTokenError,
  type McpAuthProviderOptions,
  type McpAuthProviderResult,
  type ProxyOAuthServerProviderConfig,
  type ClientInfo,
  type AuthInfo,
} from './auth-provider.js';
