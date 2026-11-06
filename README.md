# mcp-oidc-provider

OAuth for MCP servers, relayed to the identity provider you already have.

[![npm version](https://img.shields.io/npm/v/mcp-oidc-provider.svg)](https://www.npmjs.com/package/mcp-oidc-provider)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`mcp-oidc-provider` gives an Express-based [MCP](https://modelcontextprotocol.io) server everything the [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) asks for: protected resource metadata, an authorization server with Dynamic Client Registration and Client ID Metadata Documents, PKCE, a consent page and bearer token verification. It does not mint tokens. Every authorization code and refresh token grant is relayed to your OpenID Connect provider (Auth0, Okta, Keycloak, Microsoft Entra ID, ...), which issues the tokens, and the MCP endpoint verifies them against the provider's keys.

## Why a relay

MCP clients such as Claude, Cursor, VS Code, ChatGPT or the MCP Inspector have no prior relationship with your server. They discover its authorization server and register themselves, either with Dynamic Client Registration (RFC 7591) or by presenting a Client ID Metadata Document. Most identity providers do not offer that to arbitrary public clients, or create a new application for every registration.

Putting a complete OAuth provider in front of the identity provider solves the client side but needs its own signing key and a store of every user's upstream tokens. Whoever compromises the MCP server gets both.

The relay keeps the client-facing surface and drops the secrets:

- no signing key, no session secret, no stored user tokens;
- the Keyv store holds client registrations and authorization requests in flight (minutes);
- PKCE runs end to end between the MCP client and the identity provider: the relay forwards the client's `code_challenge` and `code_verifier` unchanged;
- a compromised server exposes only the tokens that pass through it while it is compromised, bounded by the identity provider's token lifetimes.

## How it works

```
MCP client                      Your MCP server (relay mounted)              Identity provider
    |                                      |                                        |
    |-- POST /mcp (no token) ------------->|                                        |
    |<- 401, resource_metadata URL --------|                                        |
    |-- GET /.well-known/... ------------->|  resource + authorization server docs  |
    |-- POST /register (or metadata URL) ->|  client stored in Keyv                 |
    |                                      |                                        |
    |-- GET /authorize (PKCE challenge) -->|  validate client + redirect URI        |
    |<- consent page ----------------------|  user approves this client             |
    |<- 302 ------------------------------>|-- /authorize (same challenge, --------->|  user signs in
    |                                      |   relay's client id, audience)         |
    |                                      |<- /oauth/callback?code ----------------|
    |<- 302 redirect_uri?code=relay-code --|  code bound to the client in Keyv      |
    |                                      |                                        |
    |-- POST /token (code + verifier) ---->|-- /token (upstream code + verifier ---->|  PKCE checked here
    |<- provider's token response ---------|<- access, refresh, id token -----------|
    |                                      |                                        |
    |-- POST /mcp, Bearer <access token> ->|  verify signature (JWKS), iss, aud, exp|
```

## Installation

```bash
npm install mcp-oidc-provider keyv express @modelcontextprotocol/server @modelcontextprotocol/express
```

Requires Node.js 18 or later. `express` (4 or 5), `keyv` and the two MCP SDK packages (2.x) are peer dependencies.

## Quick start

```typescript
import { createMcpExpressApp, requireBearerAuth } from '@modelcontextprotocol/express';
import { Keyv } from 'keyv';
import { createAuthRelay } from 'mcp-oidc-provider';

const relay = createAuthRelay({
  // Public origin of this server; the relay's endpoints live on it
  baseUrl: 'https://mcp.example.com',
  upstream: {
    issuer: 'https://your-tenant.auth0.com',
    clientId: process.env.OIDC_CLIENT_ID!,
    clientSecret: process.env.OIDC_CLIENT_SECRET!,
    // The provider must issue JWT access tokens for this audience
    audience: 'https://api.example.com',
  },
  // Any Keyv adapter: Redis, Postgres, Tigris, in-memory for development, ...
  store: new Keyv(),
});

// Host validation and JSON parsing from the MCP SDK
const app = createMcpExpressApp({ host: '0.0.0.0', allowedHosts: ['mcp.example.com'] });

// /.well-known/*, /register, /authorize, /token, /oauth/callback and CORS for /mcp
app.use(relay.router);

app.post(
  '/mcp',
  requireBearerAuth({
    verifier: relay.verifier,
    resourceMetadataUrl: relay.resourceMetadataUrl,
    expectedResource: relay.resource,
  }),
  async (req, res) => {
    // req.auth.token is the provider's access token; req.auth.extra has sub, claims, customData
  }
);

app.listen(3000);
```

See [`example/relay`](example/relay) for a complete server with an MCP tool, and [`ARCHITECTURE.md`](ARCHITECTURE.md) for the flows in detail.

## Setting up the identity provider

The relay is one confidential OAuth client at your provider. Create a web application and configure it as follows.

| Setting | Value |
| --- | --- |
| Callback / redirect URL | `<baseUrl>/oauth/callback` (change with `callbackPath`) |
| Grant types | Authorization code with PKCE, refresh token |
| Refresh tokens | Allowed (`offline_access`); turn on rotation with reuse detection if offered |
| Client credentials grant | Disabled: the relay's secret must not be able to obtain tokens on its own |
| Access tokens | JWTs for `upstream.audience`, short-lived |

How access tokens get an audience depends on the provider. The relay sends `audience=<upstream.audience>` with every authorization request; providers that do not know the parameter ignore it, and `upstream.authorizationParams` and `upstream.scopes` let you send what yours needs.

| Provider | Typical configuration |
| --- | --- |
| Auth0 | Create an API; its identifier is `audience`. The `audience` parameter selects it. |
| Okta | Use a custom authorization server; its audience is `audience`. |
| Keycloak | Add an audience mapper to the relay's client; `audience` is the mapped client ID. |
| Microsoft Entra ID | Expose an API scope and request it: `scopes: ['openid', 'profile', 'email', 'offline_access', 'api://<app-id>/.default']`; `audience` is the application ID URI. |

Consult your provider's documentation; the requirement is only that the access token is a JWT whose `aud` contains `upstream.audience`.

## Using the token in your MCP server

After `requireBearerAuth`, `req.auth` is the MCP SDK's `AuthInfo`:

| Field | Value |
| --- | --- |
| `token` | The identity provider's access token |
| `clientId` | The `azp` / `client_id` claim: the relay's client at the provider |
| `scopes` | From the `scope` (or `scp`) claim |
| `expiresAt` | The `exp` claim |
| `resource` | `relay.resource`, the MCP endpoint URL |
| `extra.sub` | The `sub` claim |
| `extra.claims` | All verified claims |
| `extra.customData` | Whatever your `customData` function returned |

`customData` runs on every verified token with the claims, the token and a `userinfo()` function that fetches the provider's UserInfo once per token (cached until the token expires):

```typescript
createAuthRelay({
  // ...
  customData: async ({ claims, userinfo }) => {
    const groups = claims['https://example.com/groups'];
    const profile = await userinfo();
    return { groups, email: profile['email'] };
  },
});
```

**Data that only the ID token carries.** The MCP server never sees the ID token: it goes to the MCP client, which does not send it on. If your application needs claims the provider only puts there (profile, organizations, roles), capture them when the relay passes the token response on and store them by `sub` for `customData` to read later:

```typescript
const profiles = new Keyv({ store: store.opts.store, namespace: 'profiles' });

createAuthRelay({
  // ...
  onTokenResponse: async ({ idTokenClaims }) => {
    if (!idTokenClaims?.sub) return;
    await profiles.set(idTokenClaims.sub, { groups: idTokenClaims['groups'] }, 30 * 24 * 3600 * 1000);
  },
  customData: ({ claims }) => profiles.get(claims.sub as string),
});
```

The hook receives `grantType`, the MCP `clientId`, `idTokenClaims` and `accessTokenClaims` (both verified; absent when a token is missing or does not verify), `expiresAt` and `scope`. It never receives the tokens themselves. It runs before the response is sent, and a rejection is logged rather than failing the token request. Refresh responses that include a new ID token fire it too, so stored data stays current.

**Calling other APIs.** The token in `req.auth.token` was issued for `upstream.audience`. If your MCP server forwards it to another API that accepts the same audience, that API cannot tell the request was mediated by the MCP server; the MCP specification calls this token passthrough and forbids it. Prefer an audience dedicated to the MCP server and obtain separate credentials for downstream APIs (token exchange, or a service credential of the MCP server itself).

## Options

### `createAuthRelay(options)`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `baseUrl` | `string` | required | Public origin of the server the router is mounted on. It is the relay's issuer, so no path. |
| `upstream` | `UpstreamOptions` | required | The identity provider, see below. |
| `store` | Keyv instance | required | Client registrations, cached client metadata documents and authorization requests in flight. |
| `mcpEndpointPath` | `string` | `'/mcp'` | Path of the MCP endpoint; with `baseUrl` it forms the resource identifier (RFC 8707). |
| `scopesSupported` | `string[]` | `upstream.scopes` | Advertised as `scopes_supported`. |
| `resourceName` | `string` | | Shown on the consent page and as `resource_name` in the resource metadata. |
| `callbackPath` | `string` | `'/oauth/callback'` | Where the identity provider redirects back to. |
| `clients` | `ClientOptions` | | How MCP clients identify themselves, see below. |
| `consent` | `ConsentOptions` | | The consent page, see below. |
| `customData` | `CustomDataFn` | | Derive application data from each verified token. |
| `onTokenResponse` | `TokenResponseHook` | | Called with the verified ID and access token claims of every token response the relay passes on; see below. |
| `jwksCacheOptions` | `{ cooldownDuration?, cacheMaxAge? }` | 30 s / 10 min | Cache for the provider's JWKS. |
| `additionalCorsOrigins` | `string[]` | | Extra browser origins allowed to call the MCP endpoint (the MCP Inspector origin is always allowed). |
| `secureCookies` | `boolean` | `true` for `https` base URLs | Mark the consent cookie `Secure`. |
| `onVerifyError` | `(error) => void` | | Called with the underlying error for every rejected token. |
| `logger` | `Logger` | console, `info` | Logging. Tokens, codes and secrets are never logged. |
| `fetch` | `typeof fetch` | global `fetch` | Used for all requests to the provider and for client metadata documents. |

### `upstream`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `issuer` | `string` | required | Issuer URL. Metadata is discovered at `/.well-known/openid-configuration` (or RFC 8414) on first use. |
| `clientId`, `clientSecret` | `string` | required | The relay's credentials at the provider. |
| `audience` | `string` | required | Sent as `audience` in authorization requests and required in the `aud` of accepted tokens. |
| `scopes` | `string[]` | `openid profile email offline_access` | Requested from the provider. |
| `authorizationParams` | `Record<string, string>` | | Extra parameters for every upstream authorization request. |
| `tokenEndpointAuthMethod` | `'client_secret_basic' \| 'client_secret_post'` | `client_secret_basic` | How the relay authenticates at the provider's token endpoint. |
| `metadata` | `Partial<UpstreamMetadata>` | | Endpoints to use instead of, or merged over, discovery. |
| `displayName` | `string` | issuer hostname | Provider name shown on the consent page. |

### `clients`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `allowDynamicRegistration` | `boolean` | `true` | Serve `POST /register` (RFC 7591). |
| `registrationTtl` | `number` (ms) | 30 days | How long a dynamic registration is kept. |
| `allowClientIdMetadataDocuments` | `boolean` | `true` | Accept an `https` URL as `client_id` and fetch its document. |
| `cimdAllowedHosts` | `string[]` | any public host | Restrict metadata document URLs to these hostnames. |
| `cimdCacheTtl` | `number` (ms) | 1 hour | Upper bound for caching a metadata document (`Cache-Control: max-age` is honoured within it). |
| `isAllowedRedirectUri` | `(uri: URL) => boolean` | see below | Replace the redirect URI policy. |

The default redirect URI policy accepts `https` URLs, `http` URLs on `localhost`, `127.0.0.1` and `[::1]`, and private-use schemes such as `cursor://` or `vscode://`. Redirect URIs must match a registered one exactly; loopback IP literals may use any port (OAuth 2.1).

### `consent`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | `boolean` | `true` | Ask the user before forwarding a client to the provider. |
| `ttl` | `number` (ms) | 30 days | How long an approval is remembered. |
| `cookieName` | `string` | `mcp_relay_consent` | Cookie that remembers approvals. |
| `secret` | `string` | derived from `upstream.clientSecret` | Key that signs the cookie; must be identical on every instance. |
| `render` | `(view: ConsentView) => string` | built-in page | Your own consent page; the hidden `fields` must be posted to `action` with `decision=approve` or `deny`. |

### Result

| Property | Description |
| --- | --- |
| `router` | Express router; mount at the root of the app serving `baseUrl`. |
| `verifier` | `OAuthTokenVerifier` for `requireBearerAuth`. |
| `resource` | The MCP endpoint URL (`URL`), for `expectedResource`. |
| `resourceMetadataUrl` | Protected resource metadata URL, for `requireBearerAuth`. |
| `metadata` | The authorization server metadata document the relay publishes. |
| `discoverUpstream()` | Discover the provider's metadata now (optional startup check). |

## Endpoints

All paths are relative to `baseUrl`.

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| `GET /.well-known/oauth-protected-resource<mcpEndpointPath>` | Protected resource metadata (RFC 9728) |
| `POST /register` | Dynamic Client Registration |
| `GET /authorize` | Authorization endpoint; renders the consent page or redirects to the provider |
| `POST /authorize/consent` | Consent decision |
| `GET /oauth/callback` | Provider callback; redirects to the MCP client with a relay code |
| `POST /token` | Token endpoint; `authorization_code` and `refresh_token` grants are relayed, everything else is `unsupported_grant_type` |

Clients get `error` responses in the formats OAuth defines: JSON bodies from `/token` and `/register`, redirects with `error`, `error_description`, `state` and `iss` from `/authorize`, and an HTML error page when the client or redirect URI itself is invalid.

## Security notes

- **Consent.** The relay uses one static client at the provider for every MCP client, so the provider's own consent cannot tell MCP clients apart. The relay's consent page names the client and the exact redirect URI and remembers approvals per client and redirect URI. Disable it only for deployments where every registered client is trusted.
- **Client ID Metadata Documents.** The relay fetches a URL supplied by an unauthenticated party. It requires `https` and a path, refuses IP literals, loopback and single-label hosts, resolves the hostname and refuses private addresses, does not follow redirects, caps documents at 64 KB and caches them for at most `cimdCacheTtl`. Set `cimdAllowedHosts` to limit fetches to known clients, or disable the feature.
- **What is stored.** Client registrations (with a hash of the client secret for confidential clients), cached metadata documents, consent interactions and authorization states for ten minutes, relay authorization codes for five. No tokens, keys or sessions.
- **HTTPS.** Serve `baseUrl` over HTTPS in production. The MCP SDK refuses a non-HTTPS issuer other than `localhost` unless `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL=true` is set.
- **Rate limiting** is not included. Put your usual limiter in front of `/register` and `/token`.
- **Refresh tokens** are the provider's and are all issued to the relay's client. The relay checks that the MCP client presenting one may use the grant but cannot tell which MCP client a refresh token was issued to; enable rotation with reuse detection at the provider.

## Migrating from 2.x

Version 3 replaces the OIDC provider with the relay. The MCP client-facing URLs are unchanged, so existing connectors keep working after re-authenticating once. See [CHANGELOG.md](CHANGELOG.md) for the full list; in short:

- `createOidcServer` + `createMcpAuthProvider` become one `createAuthRelay` call and `app.use(relay.router)` on the MCP app.
- Remove `JWKS` and `SESSION_SECRET`; keep the identity provider client ID and secret; add `audience`.
- Read the provider's access token from `req.auth.token` instead of `getIdpTokens(...)`; move anything that lived in the stored session to `customData` (claims or UserInfo).

## Development

```bash
npm install
npm test               # Vitest, with a fake identity provider
npm run test:coverage
npm run lint
npm run type-check
npm run build
```

Releases use [changesets](https://github.com/changesets/changesets): add one with `npx changeset` in every PR that changes published behaviour.

## License

MIT
