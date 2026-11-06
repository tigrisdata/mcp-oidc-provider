---
'mcp-oidc-provider': major
---

Target the MCP TypeScript SDK v2 (`@modelcontextprotocol/server`, `@modelcontextprotocol/express`, `@modelcontextprotocol/node`) and drop the integrated Express setup in favour of the SDK's own Express helpers.

**Removed**

- `setupMcpExpress`, `McpExpressSetupOptions`, `McpExpressSetupResult`, `McpRequestHandler` and the `req.user` request augmentation. Compose with the SDK instead: `createMcpExpressApp` and `requireBearerAuth` from `@modelcontextprotocol/express` on the MCP server, `createOidcServer` for the OIDC server. The `mcp-integrated-oidc` example is removed; the `standalone-oidc` example shows the composition.
- The IdP token auto-refresh that the integrated auth middleware performed. The verifier returns the stored IdP token set as is (`getIdpTokens(req.auth)` includes `refreshToken` and `expiresAt`).
- `proxyOAuthServerProviderConfig`, `ClientInfo` and `ProxyOAuthServerProviderConfig` (SDK v2 removed `ProxyOAuthServerProvider` and `mcpAuthRouter`), `InvalidTokenError`, and the `/health` route from `mcpRoutes`.
- `getIdpTokens` accepts the SDK `AuthInfo` only.

**Changed**

- `@modelcontextprotocol/server` and `@modelcontextprotocol/express` (`>=2.0.0`) are required peer dependencies of `mcp-oidc-provider/mcp`.
- `createMcpAuthProvider` is async: it fetches the OIDC server's authorization server metadata once at startup (start the OIDC server first) and returns `{ verifier, mcpRoutes, resourceMetadataUrl }`. `verifier` is an SDK `OAuthTokenVerifier` that rejects with `OAuthError` (`invalid_token`); its `AuthInfo` carries `expiresAt`, `resource` (from the token `aud` claim) and `resourceMetadataUrl`, so `requireBearerAuth`'s expiry, `expectedResource` (RFC 8707 audience binding) and `requiredScopes` checks work out of the box.
- `mcpRoutes` serves the discovery documents through the SDK's `mcpAuthMetadataRouter`: protected resource metadata at the path-based `/.well-known/oauth-protected-resource/<mcp path>` (RFC 9728; the root document is no longer served for a non-root MCP endpoint) and the OIDC server's `/.well-known/oauth-authorization-server` verbatim. `resourceMetadataUrl` is the path-based URL. The SDK rejects a non-HTTPS issuer other than `localhost` unless `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL=true` is set.
