# mcp-oidc-provider

![GitHub License](https://img.shields.io/github/license/tigrisdata/mcp-oidc-provider)
[![NPM Version](https://img.shields.io/npm/v/mcp-oidc-provider 'NPM Version ')](https://www.npmjs.com/package/mcp-oidc-provider)
[![CI](https://github.com/tigrisdata/mcp-oidc-provider/actions/workflows/ci.yml/badge.svg)](https://github.com/tigrisdata/mcp-oidc-provider/actions/workflows/ci.yml)
![NPM Downloads](https://img.shields.io/npm/dm/mcp-oidc-provider)

## Overview

`mcp-oidc-provider` is an Express middleware that acts as an OIDC provider for MCP (Model Context Protocol) servers with support for any OIDC-compliant identity provider as its backend.

Implementing a [remote hosted MCP server](https://support.claude.com/en/articles/11503834-building-custom-connectors-via-remote-mcp-servers) requires [implementing MCP Authorization Protocol](https://modelcontextprotocol.io/specification/draft/basic/authorization). In theory, this is straightforward because modern applications either implement OAuth specs themselves or use an OAuth-compliant IdP like Auth0, Clerk, Okta, or Keycloak. [Long story short](https://www.tigrisdata.com/blog/mcp-oauth/), using your own IdP as-is imposes many limitations.

This package takes care of those limitations for you so you can focus on implementing your tools, resources, and prompts instead of spending hours investigating why your implementation doesn't work with Cursor or logs you out from Claude every few hours.

The OIDC server runs as its own Express app. Your MCP server stays a plain OAuth resource server built with the [MCP TypeScript SDK v2](https://github.com/modelcontextprotocol/typescript-sdk): it verifies the tokens the OIDC server issues, so it can live in any stack. It works with any OIDC-compliant identity provider like Auth0, Clerk, Okta, Keycloak, Azure AD, Google, and more.

It uses different packages under the hood to glue everything together:

| Package           | Purpose                                                                                                                          |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `oidc-provider`   | Core OIDC/OAuth 2.0 server implementation. Handles authorization, token issuance, JWKS, client registration, and all OAuth flows |
| `openid-client`   | OAuth 2.0/OIDC client library. Used by OidcClient to communicate with upstream identity providers via OIDC Discovery             |
| `jose`            | JWT signing/verification and JWKS generation. Used for access tokens and ID tokens                                               |
| `keyv`            | Universal key-value storage abstraction. Used for sessions, tokens, grants, and OIDC adapter data                                |
| `express`         | Web framework for the Express adapter. Provides routing, middleware, and HTTP handling                                           |
| `express-session` | Session management for Express. Stores login state during OAuth flows                                                            |
| `@modelcontextprotocol/server` | MCP TypeScript SDK v2 (peer dependency of `mcp-oidc-provider/mcp`). `createMcpAuthProvider` returns an `OAuthTokenVerifier` for the SDK's `requireBearerAuth` |
| `@modelcontextprotocol/express` | MCP SDK v2 Express helpers (peer dependency of `mcp-oidc-provider/mcp`). `createMcpAuthProvider` serves the OAuth discovery documents with its `mcpAuthMetadataRouter` |

## Installation

```bash
npm install mcp-oidc-provider keyv
```

`mcp-oidc-provider/mcp` builds on the MCP TypeScript SDK v2 (`@modelcontextprotocol/server` and `@modelcontextprotocol/express` are peer dependencies), so your MCP server also needs the SDK packages:

```bash
npm install @modelcontextprotocol/server @modelcontextprotocol/express @modelcontextprotocol/node
```

## JWKS (Signing Keys)

JWKS (JSON Web Key Set) contains the keys used to sign access tokens.

**For development:** No configuration needed. The package auto-generates keys on startup. Note that tokens become invalid after server restart.

**For production:** Generate and persist signing keys:

```bash
npx mcp-oidc-provider --pretty
```

<details>
<summary>Example output</summary>

```json
{
  "keys": [
    {
      "kty": "RSA",
      "n": "[truncated]",
      "e": "AQAB",
      "d": "[truncated]",
      "p": "[truncated]",
      "q": "[truncated]",
      "dp": "[truncated]",
      "dq": "[truncated]",
      "qi": "[truncated]",
      "alg": "RS256",
      "use": "sig",
      "kid": "52B-rPqOCIyK0Kcsin8GYQ"
    }
  ]
}
```

</details>

Store the output securely and provide it via the `jwks` option or `JWKS` environment variable. This ensures:

- Tokens remain valid across server restarts
- All instances in a distributed deployment use the same keys

If you are loading the JWKS from an environment variable, we suggest _not_ using the `--pretty` flag when generating your keys as different application runtimes are known to have strange behaviour when newlines are placed in the contents of environment variables.

## Quick Start

The setup has two parts that share one persistent Keyv store (e.g., Tigris, Redis):

1. **OIDC server** (`createOidcServer`) - what MCP clients talk to: Dynamic Client Registration, authorization, tokens and JWKS. It logs users in at your IdP.
2. **MCP server** - your MCP implementation. It advertises the OIDC server through protected resource metadata and verifies the tokens it issued with the MCP SDK's `requireBearerAuth`; `createMcpAuthProvider` supplies the verifier and the metadata routes.

Run them as two processes or two ports of one process. See the [standalone-oidc example](./example/standalone-oidc).

**auth.ts** - OIDC Server (port 4001)

<details>
<summary>TypeScript code</summary>

```typescript
import { Keyv } from 'keyv';
import { KeyvTigris } from '@tigrisdata/keyv-tigris';
import { createOidcServer, OidcClient } from 'mcp-oidc-provider/oidc';
import { type JWKS } from 'mcp-oidc-provider';

const OIDC_PORT = 4001;
const OIDC_BASE_URL = process.env.OIDC_BASE_URL ?? `http://localhost:${OIDC_PORT}`;

// Use a persistent store so both servers can access the same data
const store = new Keyv({ store: new KeyvTigris() });

// Parse JWKS from environment variable (required for production)
const jwks: JWKS | undefined = process.env.JWKS ? JSON.parse(process.env.JWKS) : undefined;

const oidcServer = createOidcServer({
  idpClient: new OidcClient({
    issuer: 'https://your-tenant.auth0.com', // or any OIDC issuer
    clientId: process.env.OIDC_CLIENT_ID!,
    clientSecret: process.env.OIDC_CLIENT_SECRET!,
    redirectUri: `${OIDC_BASE_URL}/oauth/callback`,
  }),
  store,
  secret: process.env.SESSION_SECRET!,
  port: OIDC_PORT,
  baseUrl: OIDC_BASE_URL,
  jwks,
});

await oidcServer.start();
```

</details>

**mcp.ts** - MCP Server (port 3001)

<details>
<summary>TypeScript code</summary>

```typescript
import { Keyv } from 'keyv';
import { KeyvTigris } from '@tigrisdata/keyv-tigris';
import { createMcpExpressApp, requireBearerAuth } from '@modelcontextprotocol/express';
import { createMcpAuthProvider } from 'mcp-oidc-provider/mcp';

const OIDC_BASE_URL = process.env.OIDC_BASE_URL ?? 'http://localhost:4001';
const MCP_PORT = 3001;
const MCP_BASE_URL = process.env.MCP_BASE_URL ?? `http://localhost:${MCP_PORT}`;

// Same persistent store as the OIDC server
const store = new Keyv({ store: new KeyvTigris() });

// Token verifier for the MCP SDK plus the OAuth metadata routes. Fetches the
// OIDC server's metadata once, so start the OIDC server first.
const { verifier, mcpRoutes, resourceMetadataUrl } = await createMcpAuthProvider({
  oidcBaseUrl: OIDC_BASE_URL,
  store,
  mcpServerBaseUrl: MCP_BASE_URL,
});

// Express app from the MCP SDK: JSON body parsing and DNS rebinding protection
const mcpApp = createMcpExpressApp({
  host: '0.0.0.0',
  allowedHosts: [new URL(MCP_BASE_URL).hostname],
});

// OAuth discovery documents (/.well-known/oauth-protected-resource/mcp and the
// OIDC server's /.well-known/oauth-authorization-server) plus CORS for /mcp
mcpApp.use(mcpRoutes);

mcpApp.post(
  '/mcp',
  requireBearerAuth({
    verifier,
    resourceMetadataUrl,
    expectedResource: new URL(`${MCP_BASE_URL}/mcp`), // only accept tokens issued for this server
  }),
  async (req, res) => {
    // req.auth holds the verified token info; your MCP handler here
  }
);

mcpApp.listen(MCP_PORT);
```

</details>

## Configuration

### Environment Variables

mcp-oidc-provider will read from the following environment variables by default:

| Variable       | Type                    | Description                             |
| -------------- | ----------------------- | --------------------------------------- |
| SESSION_SECRET | High-entropy string     | Secret for signing cookies/sessions     |
| JWKS           | JSON Web Key Set (JSON) | Pre-generated signing keys (production) |

### OidcClientConfig

The `OidcClient` works with any OIDC-compliant identity provider. It uses [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) to automatically configure endpoints.

| Option                 | Type                                                           | Required | Description                                                       |
| ---------------------- | -------------------------------------------------------------- | -------- | ----------------------------------------------------------------- |
| `issuer`               | `string`                                                       | Yes      | OIDC issuer URL (e.g., `https://your-tenant.auth0.com`)           |
| `clientId`             | `string`                                                       | Yes      | OAuth client ID                                                   |
| `clientSecret`         | `string`                                                       | Yes      | OAuth client secret                                               |
| `redirectUri`          | `string`                                                       | Yes      | OAuth callback URL                                                |
| `scopes`               | `string`                                                       | No       | OAuth scopes (default: `openid email profile`)                    |
| `additionalAuthParams` | `Record<string, string>`                                       | No       | Additional authorization parameters (e.g., `{ audience: '...' }`) |
| `extractCustomData`    | `(claims: UserClaims) => Record<string, unknown> \| undefined` | No       | Extract provider-specific data from ID token claims               |

#### Provider Examples

```typescript
// Auth0
new OidcClient({
  issuer: 'https://your-tenant.auth0.com',
  clientId: process.env.AUTH0_CLIENT_ID!,
  clientSecret: process.env.AUTH0_CLIENT_SECRET!,
  redirectUri: 'https://your-app.com/oauth/callback',
  scopes: 'openid email profile offline_access',
  additionalAuthParams: { audience: 'https://your-api.com' },
});

// Clerk (note: doesn't support offline_access)
new OidcClient({
  issuer: 'https://your-app.clerk.accounts.dev',
  clientId: process.env.CLERK_CLIENT_ID!,
  clientSecret: process.env.CLERK_CLIENT_SECRET!,
  redirectUri: 'https://your-app.com/oauth/callback',
  extractCustomData: (claims) => {
    if (claims['org_id']) {
      return {
        organization: {
          id: claims['org_id'],
          slug: claims['org_slug'],
          role: claims['org_role'],
        },
      };
    }
  },
});

// Okta
new OidcClient({
  issuer: 'https://your-domain.okta.com',
  clientId: process.env.OKTA_CLIENT_ID!,
  clientSecret: process.env.OKTA_CLIENT_SECRET!,
  redirectUri: 'https://your-app.com/oauth/callback',
  extractCustomData: (claims) => {
    if (claims['groups']) {
      return { groups: claims['groups'] };
    }
  },
});

// Keycloak
new OidcClient({
  issuer: 'https://keycloak.example.com/realms/my-realm',
  clientId: process.env.KEYCLOAK_CLIENT_ID!,
  clientSecret: process.env.KEYCLOAK_CLIENT_SECRET!,
  redirectUri: 'https://your-app.com/oauth/callback',
});

// Microsoft Azure AD
new OidcClient({
  issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
  clientId: process.env.AZURE_CLIENT_ID!,
  clientSecret: process.env.AZURE_CLIENT_SECRET!,
  redirectUri: 'https://your-app.com/oauth/callback',
});

// Google
new OidcClient({
  issuer: 'https://accounts.google.com',
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  redirectUri: 'https://your-app.com/oauth/callback',
});
```

### createOidcServer Options (from `mcp-oidc-provider/oidc`)

| Option                  | Type          | Required | Description                              |
| ----------------------- | ------------- | -------- | ---------------------------------------- |
| `idpClient`             | `IOidcClient` | Yes      | OIDC client instance                     |
| `store`                 | `Keyv`        | Yes      | Keyv instance for storage                |
| `secret`                | `string`      | Yes      | Secret for signing cookies/sessions      |
| `port`                  | `number`      | Yes      | Port to listen on                        |
| `baseUrl`               | `string`      | Yes      | Base URL of the OIDC server              |
| `jwks`                  | `JWKS`        | No       | Custom JWKS for signing tokens           |
| `isProduction`          | `boolean`     | No       | Production mode flag                     |
| `sessionMaxAge`         | `number`      | No       | Session max age in ms (default: 30 days) |
| `additionalCorsOrigins` | `string[]`    | No       | Additional origins to allow for CORS     |
| `onListen`              | `function`    | No       | Callback when server starts              |

### createMcpAuthProvider Options (from `mcp-oidc-provider/mcp`)

Returns a promise of `{ verifier, mcpRoutes, resourceMetadataUrl }`: pass `verifier` and `resourceMetadataUrl` to the MCP SDK's `requireBearerAuth` (add `expectedResource` to bind tokens to your MCP URL and `requiredScopes` for scope checks), and mount `mcpRoutes` on your MCP server. Requires `@modelcontextprotocol/server` and `@modelcontextprotocol/express`.

`mcpRoutes` serves the OAuth discovery documents through the MCP SDK's `mcpAuthMetadataRouter`, plus CORS for the MCP endpoint:

- `/.well-known/oauth-protected-resource<mcpEndpointPath>` - protected resource metadata (RFC 9728). This is the URL `requireBearerAuth` advertises in its `WWW-Authenticate` challenges, and the one MCP clients derive from the MCP endpoint URL. The root document is not served for a non-root MCP endpoint.
- `/.well-known/oauth-authorization-server` - the OIDC server's authorization server metadata, for clients that probe the MCP server origin. It is fetched once when the provider is created, so start the OIDC server before the MCP server.

The MCP SDK only accepts an HTTPS issuer (or `localhost`/`127.0.0.1`). For another HTTP issuer in development, set `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL=true`.

| Option             | Type               | Required | Description                                                 |
| ------------------ | ------------------ | -------- | ----------------------------------------------------------- |
| `oidcBaseUrl`      | `string`           | Yes      | Base URL of the OIDC server (e.g., `http://localhost:4001`) |
| `store`            | `Keyv`             | Yes      | Same Keyv instance used by OIDC server                      |
| `mcpServerBaseUrl` | `string`           | Yes      | Base URL of your MCP server                                 |
| `mcpEndpointPath`  | `string`           | No       | MCP endpoint path (default: `/mcp`)                         |
| `scopesSupported`  | `string[]`         | No       | Supported OAuth scopes                                      |
| `jwksCacheOptions` | `JwksCacheOptions` | No       | JWKS cache settings (default: 30s cooldown, 10min cache)    |
| `onVerifyError`    | `function`         | No       | Called with the underlying error when a token is rejected   |

## Accessing IdP Tokens

When you need to call upstream APIs, read the IdP token set from the verified token info (`req.auth`) with the `getIdpTokens` helper:

```typescript
import { getIdpTokens } from 'mcp-oidc-provider/mcp';

app.post('/mcp', requireBearerAuth({ verifier, resourceMetadataUrl }), async (req, res) => {
  const tokens = getIdpTokens(req.auth);
  if (tokens) {
    const userInfo = await fetch('https://my-api.com/api/userInfo', {
      headers: { Authorization: `Bearer ${tokens.accessToken}` },
    });
  }
});
```

The `IdpTokenSet` interface:

```typescript
interface IdpTokenSet {
  accessToken: string; // Access token for calling IdP APIs
  idToken: string; // ID token containing user identity
  refreshToken: string; // Refresh token for obtaining new access tokens
  expiresAt?: number; // Unix timestamp when access token expires
}
```

The same data is available directly as `req.auth.extra.idpTokens`, next to `req.auth.extra.claims` (ID token claims) and `req.auth.extra.customData` (from `extractCustomData`).

## Custom Identity Provider

For advanced use cases, you can implement the `IOidcClient` interface directly:

```typescript
import type { IOidcClient, AuthorizationParams, TokenSet, UserClaims } from 'mcp-oidc-provider';

class MyOidcClient implements IOidcClient {
  async createAuthorizationUrl(): Promise<AuthorizationParams> {
    // Generate authorization URL with PKCE, state, and nonce
  }

  async exchangeCode(
    callbackUrl: string,
    codeVerifier: string,
    expectedState: string,
    expectedNonce?: string
  ): Promise<TokenSet> {
    // Exchange authorization code for tokens
  }

  async refreshToken(refreshToken: string): Promise<TokenSet> {
    // Refresh access token
  }

  parseIdToken(idToken: string): UserClaims {
    // Decode ID token claims
  }

  // Optional: Extract custom data from claims
  extractCustomData?(claims: UserClaims): Record<string, unknown> | undefined {
    // Return any custom data you want stored in the user session
  }
}
```

## Storage Backends

The package uses [Keyv](https://keyv.org/) for storage abstraction. The store is used to persist:

- **OAuth Clients** - Dynamically registered client applications (via DCR)
- **Authorization Codes** - Short-lived codes exchanged for tokens
- **Access Tokens** - Tokens used to authenticate API requests
- **Refresh Tokens** - Long-lived tokens used to obtain new access tokens
- **User Sessions** - Authenticated user information and IdP tokens
- **Interaction Sessions** - OAuth flow state (PKCE, nonce, redirect URIs)
- **Grants** - User consent records for client applications

You can use any Keyv-compatible backend. For production, use a persistent store like Tigris or Redis.

### In-Memory (Development Only)

```typescript
import { Keyv } from 'keyv';
const store = new Keyv();
```

> **Warning**: In-memory storage loses all data on restart and is not shared across server instances. Do not use in production or distributed deployments.

### [Tigris](https://www.npmjs.com/package/keyv-tigris) (Recommended for Production)

We suggest storing data in a durable globally distributed object storage system like [Tigris](https://tigrisdata.com) for production usecases. This will make your data usable globally, making it trivial for you to scale your MCP server without fear of high latency to your storage backend.

```typescript
import { Keyv } from 'keyv';
import { KeyvTigris } from 'keyv-tigris';

const store = new Keyv({
  store: new KeyvTigris(),
});
```

## OIDC Endpoints

When using `createOidcServer`, the following endpoints are available:

| Endpoint                                | Description                 |
| --------------------------------------- | --------------------------- |
| `GET /authorize`                        | Authorization endpoint      |
| `POST /token`                           | Token endpoint              |
| `POST /token/revocation`                | Token revocation endpoint   |
| `POST /register`                        | Dynamic Client Registration |
| `GET /jwks`                             | JSON Web Key Set            |
| `GET /.well-known/openid-configuration` | OIDC Discovery              |
| `GET /oauth/callback`                   | IdP callback handler        |
| `GET /health`                           | Health check                |

## MCP Client Support

The provider automatically handles Dynamic Client Registration for MCP clients, including support for custom protocol URIs:

- `cursor://` - Cursor IDE
- `vscode://` - VS Code
- `windsurf://` - Windsurf

## Feedback & Support

If you encounter any issues, have questions, or want to request features, please [file an issue on GitHub](https://github.com/tigrisdata/mcp-oidc-provider/issues).

## Further Reading

To better understand the full auth flow when building an MCP server, challenges encountered, and solutions we implemented, take a look at the following detailed blog posts.

- [The man-in-the-middle pattern for MCP server OAuth](https://www.tigrisdata.com/blog/mcp-oauth/)
- [Open sourcing our MCP OIDC Provider](https://www.tigrisdata.com/blog/mcp-oidc-provider/)

## License

MIT
