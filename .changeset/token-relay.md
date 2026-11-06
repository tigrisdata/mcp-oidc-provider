---
'mcp-oidc-provider': major
---

The package is now an OAuth relay in front of your identity provider instead of an OIDC provider of its own. MCP clients still register, authorize and get tokens from your MCP server's origin, but every token is minted by the identity provider: the relay forwards the authorization code and refresh token grants with its single confidential client, passes the MCP client's PKCE challenge and verifier through unchanged, and verifies the provider's access tokens at the MCP endpoint. Nothing that can be replayed later is stored any more: no signing key, no session secret, no user tokens. The Keyv store holds client registrations, cached client metadata documents and authorization requests in flight (minutes).

**Removed**

- `createOidcServer`, `createOidcProvider`, `OidcClient`, `IOidcClient`, the session stores, the Express adapter, `generateJwks` and the `mcp-oidc-provider` CLI, and the `mcp-oidc-provider/oidc` and `mcp-oidc-provider/mcp` entry points. `oidc-provider`, `openid-client` and `express-session` are no longer dependencies.
- `createMcpAuthProvider` and `getIdpTokens`. The access token the MCP client presents is the identity provider's token; read it from `req.auth.token`.
- The `secret` and `jwks` options and the `SESSION_SECRET` / `JWKS` configuration they required.

**Added**

- `createAuthRelay(options)` returns `{ router, verifier, resource, resourceMetadataUrl, metadata, discoverUpstream }`. Mount `router` at the root of your MCP app; it serves `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource/<mcp path>`, `/register`, `/authorize`, `/token` and the identity provider callback (`/oauth/callback` by default, the same path as before). Pass `verifier`, `resourceMetadataUrl` and `expectedResource: resource` to `requireBearerAuth` from `@modelcontextprotocol/express`.
- Client ID Metadata Documents (MCP 2025-11-25): an `https` URL may be used as `client_id`; the relay fetches, validates and caches the document (`client_id_metadata_document_supported: true`). Dynamic Client Registration stays available for other clients.
- A consent page (on by default) that names the MCP client and the redirect URI before the user is sent to the identity provider, the MCP specification's confused-deputy mitigation for proxies with a static upstream client. Decisions are remembered per client and redirect URI in a signed cookie; the page can be replaced with `consent.render`.
- `customData` receives the verified access token claims plus a cached `userinfo()` lookup, so application data no longer depends on a stored session.
- `onTokenResponse` receives the verified ID token and access token claims of every token response the relay passes on (never the tokens), so data that only the ID token carries can be stored by `sub` for `customData` to use.

**Migration**

```ts
// before
const oidcServer = createOidcServer({ idpClient: new OidcClient({ issuer, clientId, clientSecret, redirectUri }), store, secret, jwks, baseUrl });
const { verifier, mcpRoutes, resourceMetadataUrl } = await createMcpAuthProvider({ oidcBaseUrl, store, mcpServerBaseUrl });

// after
const relay = createAuthRelay({
  baseUrl: 'https://mcp.example.com',
  upstream: { issuer, clientId, clientSecret, audience: 'https://api.example.com' },
  store,
});
app.use(relay.router);
app.post('/mcp', requireBearerAuth({ verifier: relay.verifier, resourceMetadataUrl: relay.resourceMetadataUrl, expectedResource: relay.resource }), handler);
```

Your identity provider must issue JWT access tokens for `upstream.audience` (for Auth0, register an API with that identifier). Users and MCP clients re-authenticate once after the upgrade; previously stored sessions are not read.
