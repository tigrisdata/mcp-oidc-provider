/**
 * MCP integration module for mcp-oidc-provider.
 *
 * Connects a standalone mcp-oidc-provider OIDC server to an MCP resource
 * server built on the MCP TypeScript SDK v2: a token verifier for
 * `requireBearerAuth` from `@modelcontextprotocol/express` plus the OAuth
 * metadata routes the MCP server must expose.
 */

export {
  createMcpAuthProvider,
  getIdpTokens,
  type McpAuthProviderOptions,
  type McpAuthProviderResult,
  type IdpTokenSet,
} from './auth-provider.js';
